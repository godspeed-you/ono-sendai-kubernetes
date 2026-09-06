//! Running a kubeconfig's credential plugin, through the host and under a grant.
//!
//! Specification §8.2 and §8.3. `ono-provider-kubernetes`'s `exec` module decides *whether* a
//! helper may run, *what* it would be run with and *what* its output means; this module is the
//! twenty lines that actually ask the host to run it. The split is §8.2's own:
//!
//! > Execution MUST occur only through an explicit KUANG/11 process-execution capability.
//!
//! So the capability is declared **optional** in the manifest and the grant is checked before the
//! program name is even assembled. Without it, a context that authenticates this way is refused by
//! name — which is what this package did for every such context until now, and is still what it
//! does for an operator who did not grant `process.exec`. A refusal is not a regression from a
//! wrong identity: an anonymous request to a cluster that expected `alice` fails as a permission
//! problem, and an operator spends an afternoon on their RBAC.
//!
//! **Nothing here spawns a process.** Neither crate's `src/` names the standard library's process
//! API at all, and `should_carry_no_subprocess_on_any_path_that_reaches_a_cluster` walks both
//! trees to say so — a scan strict enough that this paragraph had to be written around it, which
//! is the correct outcome for a rule about a literal. The host owns the confinement, the
//! environment and the stdio; this package owns the decision and the parse.

use ono_kuang_sdk::Ctx;
use ono_kuang_sdk::protocol::{WireError, method};
use ono_provider_kubernetes::exec::{ExecCredential, ExecPlugin};
use ono_provider_kubernetes::kubeconfig::Secret;
use ono_provider_kubernetes::transport::{Clock as _, SystemClock};
use serde_json::{Value as Json, json};

use crate::audit;
use crate::query::{UNSUPPORTED, UNSUPPORTED_CODE, failure};

/// The capability a credential plugin runs under (§8.2, §51.4).
pub(crate) const PROCESS_EXEC: &str = "process.exec";

/// How many stream reads a helper is given before this package stops waiting.
///
/// A credential plugin prints one JSON document and exits. A helper that has written nothing after
/// this many reads is one that is waiting for something — a prompt this package cannot answer, a
/// network call to an identity provider that is not coming back — and the bound is what turns that
/// into an answer rather than a hang (§50.1).
const READS: usize = 64;

/// What a credential plugin returned, or a refusal naming what stopped it.
///
/// The material never becomes a `String` on the way through: it arrives inside an
/// [`ExecCredential`], which holds it as a [`Secret`], and the only value that leaves here is the
/// token or the certificate pair a caller already had to be trusted with (§8.1).
pub(crate) struct Ran {
    /// The bearer token, where the plugin returned one.
    pub(crate) token: Option<Secret>,
    /// The client certificate and its key, where the plugin returned that form instead.
    pub(crate) client_certificate: Option<(Secret, Secret)>,
}

/// Runs `plugin` through the host and reads what it printed (§8.2, §8.3).
///
/// # Errors
///
/// A refusal where the grant is missing, where §8.2's interaction mode forbids the run, where the
/// host would not start the program, or where the output is not a credential this provider can
/// use. Each names which of those it is, because they have four different fixes.
pub(crate) fn run(
    ctx: &mut Ctx<'_>,
    plugin: &ExecPlugin,
    context: &str,
    instance: &str,
) -> Result<Ran, WireError> {
    // The grant first, before the program name is assembled, so a package without it never even
    // composes the request. §21.4 of the generic contract: this is a *local* block and not
    // anything the cluster said, and the message says so.
    if !matches!(
        ctx.check_capability(PROCESS_EXEC),
        Ok(ono_kuang_sdk::protocol::CheckAnswer::Granted)
    ) {
        audit::refused_locally(ctx, instance, PROCESS_EXEC, "credential plugin");
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "context `{context}` authenticates through the credential plugin `{}`, and this \
                 package was not granted `{PROCESS_EXEC}`",
                plugin.command()
            ),
            "§8.2 requires an explicit process-execution capability for a credential plugin. \
             Grant it — `load plugin io.github.godspeed-you.kubernetes --grant process.exec` — or \
             use a context with a token or a client certificate. Nothing was run and no request \
             reached the cluster.",
        ));
    }

    // §8.2's interaction mode. A package invoked from a pipeline has no terminal to lend, and
    // this package never claims one: `interactive` is false because there is no path by which it
    // could be true, and saying so is the difference between a refusal and a helper blocking on a
    // prompt nobody can see.
    plugin.may_run(false).map_err(|refusal| {
        failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("the credential plugin of context `{context}` was not run: {refusal}"),
            "A plugin declaring `interactiveMode: Always` needs a terminal, and a provider \
             invocation has none. Run its login flow yourself and use the credential it leaves \
             behind, or use a context with a token.",
        )
    })?;

    let environment: serde_json::Map<String, Json> = plugin
        .env()
        .iter()
        .map(|(name, value)| (name.clone(), json!(value)))
        .collect();
    audit::ran_credential_plugin(ctx, instance, context, plugin.command());
    let opened = ctx.host_call(
        method::PROCESS_EXEC,
        json!({
            "program": plugin.command(),
            "arguments": plugin.args(),
            "stdin": null,
            "environment": environment,
        }),
    )?;
    let handle = opened.get("handle").and_then(Json::as_u64).ok_or_else(|| {
        failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "the host started `{}` and named no stream",
                plugin.command()
            ),
            "This is a defect in the host rather than in the kubeconfig.",
        )
    })?;

    let printed = read_stdout(ctx, handle, plugin.command())?;
    let credential = ExecCredential::parse(&printed).map_err(|refusal| {
        failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "the credential plugin `{}` of context `{context}` did not answer with a \
                 credential: {refusal}",
                plugin.command()
            ),
            "§8.3: a credential plugin's output is the Kubernetes `ExecCredential` contract. What \
             it printed is not read as anything else, because a token taken out of an error \
             message would be sent to an API server as an identity.",
        )
    })?;
    // §8.3: "credential expiry MUST be honored." A helper whose cache is stale returns a token
    // that produces a `401` — which an operator reads as *their* credentials being wrong.
    credential
        .check_expiry(SystemClock.now())
        .map_err(|refusal| {
            failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!(
                    "the credential plugin `{}` of context `{context}` returned an expired \
                     credential: {refusal}",
                    plugin.command()
                ),
                "Nothing was sent to the cluster. The plugin's own cache is stale; running its \
                 refresh or clearing that cache is the fix, and sending the credential anyway \
                 would produce a `401` that reads as a permission problem.",
            )
        })?;

    Ok(Ran {
        token: credential.token().cloned(),
        client_certificate: credential
            .client_certificate()
            .map(|(certificate, key)| (certificate.clone(), key.clone())),
    })
}

/// Everything the helper wrote to stdout, bounded.
///
/// stderr is read and dropped on purpose. §8.1 forbids credential bytes reaching a log or a crash
/// diagnostic, a helper that fails often prints a message containing the identity it was trying to
/// assume, and this package has no way to tell one line from the other — so what a failing helper
/// said is *not* quoted back. What is quoted instead is that it wrote nothing usable, which is the
/// fact an operator can act on without this package having decided what is safe to repeat.
fn read_stdout(ctx: &mut Ctx<'_>, handle: u64, command: &str) -> Result<String, WireError> {
    let mut stdout = String::new();
    for _ in 0_usize..READS {
        if ctx.cancelled() {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("the credential plugin `{command}` was cancelled"),
                "Nothing reached the cluster.",
            ));
        }
        let answer = ctx.host_call(method::STREAMS_NEXT, json!({"handle": handle, "max": 8}))?;
        for value in answer
            .get("values")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            if value.get("stream").and_then(Json::as_str) == Some("stdout")
                && let Some(line) = value.get("line").and_then(Json::as_str)
            {
                stdout.push_str(line);
                stdout.push('\n');
            }
        }
        if answer.get("complete").and_then(Json::as_bool) == Some(true) {
            return Ok(stdout);
        }
    }
    Err(failure(
        UNSUPPORTED_CODE,
        UNSUPPORTED,
        format!("the credential plugin `{command}` did not finish"),
        "A credential plugin prints one document and exits. One that has not after sixty-four \
         reads is waiting for something this package cannot give it — a prompt, or an identity \
         provider that is not answering. Nothing reached the cluster.",
    ))
}

//! Credential plugins: what a kubeconfig asks to be run, and what it must say back.
//!
//! Specification §8.2 and §8.3. Nothing here runs a subprocess and nothing here can: the module
//! under test decides *whether* a helper may run, *what* it would be run with and *what* its
//! output means, and the running is a host call in the package under an explicit `process.exec`
//! grant. That separation is what makes every rule below assertable as a decision about a value.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::exec::{ExecCredential, ExecPlugin, ExecRefusal, InteractiveMode};
use ono_provider_kubernetes::transport::ObservedAt;

/// An `exec` block as a managed-service kubeconfig writes one.
const BLOCK: &str = r#"
apiVersion: client.authentication.k8s.io/v1beta1
command: cloud-cli
args: ["token", "--cluster", "prod"]
env:
  - name: CLOUD_PROFILE
    value: operations
interactiveMode: IfAvailable
provideClusterInfo: true
"#;

fn block(yaml: &str) -> serde_yaml_ng::Value {
    serde_yaml_ng::from_str(yaml).expect("the fixture is YAML")
}

#[test]
fn should_read_what_a_kubeconfig_asks_to_be_run() {
    // §8.2. The block is the whole of what the provider knows about the helper: which program,
    // which arguments, which environment, and whether it needs a terminal.
    let plugin = ExecPlugin::parse(&block(BLOCK)).expect("the block reads");

    assert_eq!(plugin.command(), "cloud-cli");
    assert_eq!(plugin.args(), ["token", "--cluster", "prod"]);
    assert_eq!(
        plugin.env().get("CLOUD_PROFILE").map(String::as_str),
        Some("operations")
    );
    assert_eq!(plugin.interactive_mode(), InteractiveMode::IfAvailable);
    assert!(plugin.provides_cluster_info());
}

#[test]
fn should_refuse_an_exec_contract_this_provider_does_not_speak() {
    // §8.3: the output is "the Kubernetes `ExecCredential` contract, not arbitrary CLI text". A
    // block claiming a different contract is asking for an exchange this provider cannot hold, and
    // running the helper anyway to see what comes out is exactly the "arbitrary CLI text" reading
    // the section forbids.
    let refused = ExecPlugin::parse(&block("apiVersion: example.io/v1\ncommand: cloud-cli\n"))
        .expect_err("an unknown contract is refused");

    assert_eq!(
        refused,
        ExecRefusal::UnknownContract("example.io/v1".to_owned())
    );
}

#[test]
fn should_refuse_an_interaction_mode_it_does_not_know_rather_than_assume_the_permissive_one() {
    // The subtle one. `Never` is the *permissive* value here — it is the one that lets the helper
    // run without a terminal — so defaulting an unrecognised mode to it is how a future spelling
    // of "this needs a terminal" would come to run without one. An absent `interactiveMode` is
    // `Never` because the kubeconfig contract says so; a present word this provider does not know
    // is a statement whose content is unavailable.
    let refused = ExecPlugin::parse(&block(
        "apiVersion: client.authentication.k8s.io/v1\ncommand: cloud-cli\ninteractiveMode: Maybe\n",
    ))
    .expect_err("an unknown mode is refused");
    assert_eq!(refused, ExecRefusal::UnknownMode("Maybe".to_owned()));

    let absent = ExecPlugin::parse(&block(
        "apiVersion: client.authentication.k8s.io/v1\ncommand: cloud-cli\n",
    ))
    .expect("a block with no mode reads");
    assert_eq!(absent.interactive_mode(), InteractiveMode::Never);
}

#[test]
fn should_refuse_to_run_a_plugin_that_needs_a_terminal_where_there_is_none() {
    // §8.2's last rule: "a provider operating in a non-interactive context MUST NOT fake
    // interactive stdin availability." A browser-based login flow declares `Always`, and running
    // it without a terminal does not fail cleanly — it blocks on a prompt nobody can see, which
    // an operator experiences as the shell hanging.
    let always = ExecPlugin::parse(&block(
        "apiVersion: client.authentication.k8s.io/v1\ncommand: login\ninteractiveMode: Always\n",
    ))
    .expect("the block reads");

    assert_eq!(always.may_run(false), Err(ExecRefusal::NeedsTerminal));
    assert_eq!(always.may_run(true), Ok(()));

    // The other two run either way, which is what their words mean.
    for word in ["Never", "IfAvailable"] {
        let plugin = ExecPlugin::parse(&block(&format!(
            "apiVersion: client.authentication.k8s.io/v1\ncommand: token\ninteractiveMode: {word}\n"
        )))
        .expect("the block reads");
        assert_eq!(plugin.may_run(false), Ok(()), "`{word}` runs without one");
        assert_eq!(plugin.may_run(true), Ok(()), "`{word}` runs with one");
    }
}

#[test]
fn should_read_a_token_a_credential_plugin_returned() {
    // §8.3, the ordinary case: a helper prints an `ExecCredential` and the token inside it is what
    // reaches the API server.
    let credential = ExecCredential::parse(
        r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1",
            "status":{"token":"k8s-aws-v1.abc","expirationTimestamp":"2026-09-07T12:00:00Z"}}"#,
    )
    .expect("the document reads");

    assert_eq!(
        credential.token().map(|token| token.expose().to_owned()),
        Some("k8s-aws-v1.abc".to_owned())
    );
    assert_eq!(credential.expires_at(), Some("2026-09-07T12:00:00Z"));
    assert!(credential.client_certificate().is_none());

    // §8.1: the material never reaches a rendering by accident.
    let rendered = format!("{credential:?}");
    assert!(
        !rendered.contains("k8s-aws-v1.abc"),
        "a credential's `Debug` does not print it: {rendered}"
    );
}

#[test]
fn should_read_a_client_certificate_a_credential_plugin_returned() {
    // The other form §8.3 allows, and the reason `client_certificate()` returns a *pair*: a
    // certificate without its key proves nothing, and offering one alone would be a credential a
    // caller could not use and would have to check for.
    let credential = ExecCredential::parse(
        r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1",
            "status":{"clientCertificateData":"-----BEGIN CERTIFICATE-----",
                      "clientKeyData":"-----BEGIN PRIVATE KEY-----"}}"#,
    )
    .expect("the document reads");

    let (certificate, key) = credential
        .client_certificate()
        .expect("both halves arrived together");
    assert!(certificate.expose().starts_with("-----BEGIN CERTIFICATE"));
    assert!(key.expose().starts_with("-----BEGIN PRIVATE KEY"));
    assert!(credential.token().is_none());
}

#[test]
fn should_refuse_output_that_is_not_an_exec_credential() {
    // §8.3's `MUST`, and the shape of the mistake it forbids: a helper that prints a bare token,
    // or a usage message, or an error. Reading any of those as a credential is the "arbitrary CLI
    // text" parsing the section rules out, and a token taken from a usage message would be sent to
    // an API server as an identity.
    for output in [
        "k8s-aws-v1.abc",
        "usage: cloud-cli token [--cluster NAME]",
        r#"{"kind":"Status","apiVersion":"v1","status":"Failure"}"#,
    ] {
        let refused = ExecCredential::parse(output)
            .expect_err("output that is not an `ExecCredential` is refused");
        assert!(
            matches!(refused, ExecRefusal::NotACredential(_)),
            "`{output}` is refused as not a credential, and was {refused:?}"
        );
    }
}

#[test]
fn should_refuse_a_credential_that_carries_neither_form() {
    // An `ExecCredential` whose status is empty, or which carries half a certificate. Both are
    // well-formed documents that authenticate nobody, and both would otherwise arrive as a
    // "successful" credential whose failure the API server reports as a `401` — which reads as
    // *the operator's* identity being wrong rather than as the helper having answered with
    // nothing.
    for output in [
        r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1","status":{}}"#,
        r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1",
            "status":{"clientCertificateData":"-----BEGIN CERTIFICATE-----"}}"#,
    ] {
        assert_eq!(
            ExecCredential::parse(output).expect_err("a credential with nothing in it is refused"),
            ExecRefusal::NoCredential
        );
    }
}

#[test]
fn should_refuse_a_credential_that_had_already_expired_when_it_arrived() {
    // §8.3: "credential expiry MUST be honored." A helper that returns a stale token is a helper
    // whose cache is wrong, and sending it produces a `401` an operator reads as their own
    // credentials being bad. The refusal names the instant the helper itself stated.
    let credential = ExecCredential::parse(
        r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1",
            "status":{"token":"stale","expirationTimestamp":"2026-09-07T10:00:00Z"}}"#,
    )
    .expect("the document reads");

    // 2026-09-07T10:00:01Z, one second past the stated expiry.
    let after = ObservedAt::from_unix_millis(1_788_775_201_000);
    assert_eq!(
        credential.check_expiry(after),
        Err(ExecRefusal::Expired {
            at: "2026-09-07T10:00:00Z".to_owned()
        })
    );

    // One second before it, the same credential is good.
    let before = ObservedAt::from_unix_millis(1_788_775_199_000);
    assert_eq!(credential.check_expiry(before), Ok(()));
}

#[test]
fn should_not_invent_an_expiry_for_a_credential_that_states_none() {
    // §21.4 applied to a credential: a helper that states no `expirationTimestamp` has said
    // nothing about expiry, which is not the same as saying it never expires. The API server's
    // `401` is what a stale one produces, and reporting an expiry this provider cannot see would
    // be the inference §4 forbids — it would refuse a credential that is perfectly good.
    let credential = ExecCredential::parse(
        r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1",
            "status":{"token":"forever"}}"#,
    )
    .expect("the document reads");

    assert_eq!(credential.expires_at(), None);
    assert_eq!(
        credential.check_expiry(ObservedAt::from_unix_millis(u64::MAX / 2)),
        Ok(())
    );

    // And an `expirationTimestamp` this provider cannot parse is treated the same way, for the
    // same reason: an unparsed instant is not an expired one, and refusing on it would refuse a
    // credential on the strength of a format nobody promised.
    let odd = ExecCredential::parse(
        r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1",
            "status":{"token":"t","expirationTimestamp":"2026-09-07T10:00:00+02:00"}}"#,
    )
    .expect("the document reads");
    assert_eq!(odd.check_expiry(ObservedAt::from_unix_millis(0)), Ok(()));
}

#[test]
fn should_carry_only_the_environment_the_block_declares() {
    // §51.3's least authority, applied to a subprocess. A helper is given the block's own `env`
    // and nothing inherited — which is a deviation from `kubectl`, whose helpers see the whole
    // operator environment, and it is the safe direction: a helper given an environment it did not
    // ask for is a helper acting as somebody the operator did not choose.
    let plugin = ExecPlugin::parse(&block(BLOCK)).expect("the block reads");

    assert_eq!(
        plugin.env().len(),
        1,
        "one entry, and it is the declared one"
    );
    assert!(!plugin.env().contains_key("PATH"));
    assert!(!plugin.env().contains_key("HOME"));
}

# ADR-0054: A credential plugin is a program the operator lets run, and a contract the provider reads

- Status: accepted
- Date: 2026-09-07
- Spec refs: §8.1, §8.2, §8.3, §21.4, §50.1, §51.3, §51.4, §51.6; §31.16 of core's specification;
  ADR-0002, ADR-0018, ADR-0024
- Decided by: agent (autonomous)

## Context

§8.2 opens with a `SHOULD` that is worth more than most `MUST`s:

> The provider SHOULD support kubeconfig `exec` authentication because managed Kubernetes services
> commonly rely on it.

EKS, GKE and AKS kubeconfigs authenticate through a helper. A provider that runs none connects to
none of them, which is not a missing convenience — it is most of the world's clusters. Until now
this package refused every such context by name, which was the correct refusal and left the
`SHOULD` unmet.

The rest of §8.2 and all of §8.3 are the conditions:

> Execution MUST occur only through an explicit KUANG/11 process-execution capability.
>
> The provider/host MUST honor the declared exec plugin interaction mode: `Never`, `IfAvailable`,
> `Always`. A provider operating in a non-interactive context MUST NOT fake interactive stdin
> availability.
>
> Exec credential output MUST be parsed as the Kubernetes `ExecCredential` contract, not as
> arbitrary CLI text. Credential expiry MUST be honored.

## Decision

**The decisions are in the domain crate, the twenty lines that ask the host to run something are
in the package, and `process.exec` is optional in the manifest.**

`exec.rs` decides *whether* a helper may run, *what* it would be run with and *what* its output
means. It runs nothing and cannot: no process API is named in either crate's `src/`, and the scan
that says so is strict enough that this ADR's sibling module had to write its own doc comment
around the literal. `credentials.rs` is the host call.

That split is what makes every rule below a decision about a value, testable without a subprocess:

- **The grant is checked before the program name is assembled.** Not "compose the request and let
  the broker refuse it" — that would rely on the broker to enforce a rule §8.2 puts on the
  provider, and the difference shows on a host whose policy is `Ask`. A package without the grant
  refuses by name and runs nothing, which is exactly what it did before the capability existed.
- **`Always` without a terminal is a refusal.** A provider invocation has no terminal and never
  claims one, so `may_run(false)` is what is asked. Running the helper anyway is what "faking
  interactive stdin availability" means in practice, and its failure mode is a helper blocking on
  a prompt nobody can see, which an operator experiences as the shell hanging.
- **An interaction mode this provider does not know is refused, not defaulted.** `Never` is the
  *permissive* value — it is the one that lets a helper run without a terminal — so defaulting an
  unrecognised word to it is how a future spelling of "this needs a terminal" would come to run
  without one. An absent mode is `Never` because the kubeconfig contract says so; a present
  unknown one is a statement whose content is unavailable.
- **The output is an `ExecCredential` or it is nothing.** A bare token, a usage message and a
  `Status` are all refused. §8.3's "not as arbitrary CLI text" is a rule about the worst case: a
  token scraped out of an error message would be sent to an API server as an identity.
- **An expired credential is refused before anything is sent**, naming the instant the helper
  itself stated. A helper with a stale cache otherwise produces a `401` that an operator reads as
  *their* credentials being wrong. A credential stating no expiry, or one whose timestamp this
  provider cannot parse, is *not* treated as expired — that would refuse a credential that is
  perfectly good, on an inference §4 forbids.

**The helper gets the block's `env` and nothing inherited.** §51.3's least authority applied to a
subprocess. This is a deliberate deviation from `kubectl`, whose helpers see the operator's whole
environment, and it is the safe direction: a helper given an environment it did not ask for is a
helper acting as somebody the operator did not choose. It will surprise someone whose helper reads
a profile variable from their shell, and the surprise is a refusal rather than a wrong identity.

**stderr is read and dropped.** A failing helper often prints a message containing the identity it
was trying to assume, and this package cannot tell that line from any other — so what a failing
helper *said* is not quoted back. What is reported is that it wrote nothing usable, which is the
fact an operator can act on without this package having decided what is safe to repeat (§8.1).

**The scope is the operator's.** `programs`, `executables` and `argv_policy` are the scope keys
`process.exec` carries, and none is pinned in the manifest: the program is whatever the operator's
own kubeconfig names, and a path glob written here would be either wrong for their cloud or wide
enough to mean nothing. Setting `programs` on the grant is what turns "run a helper" into "run
*this* one", and it is the operator who knows which.

**§51.6's fourth audit record exists now**, and it is the one with the sharpest reason: running a
helper is this package causing a *program* to execute under an operator's identity, and it is the
only thing it does that the capability broker cannot see for what it is — the broker checked a
program name and does not know a credential was the point. The record carries the context and the
command, and never the output or the environment: the first is a credential and the second is
where a credential is most often put.

## Consequences

A managed-cloud kubeconfig connects, under a grant the operator makes deliberately and can scope
to one program. One that authenticates any other way is unaffected and pays nothing — no helper is
composed for a context that carries a token.

The refusal path is unchanged for an operator who does not grant `process.exec`, and it is now the
*tested* path rather than the only one:
`should_refuse_to_run_a_credential_plugin_without_the_capability_that_governs_it` asserts that
nothing was run and that no request reached either cluster, which is the half a test that only
checked the error message would miss.

What is still not done is §8.3's *refresh*: a credential is fetched once per endpoint resolution
and a long invocation whose credential expires mid-flight gets the API server's `401` rather than
a second run of the helper. §8.3 makes refresh a `SHOULD` "before a request when the credential is
expired", and doing it properly means the credential outliving the resolution that fetched it —
which is a session question, not a credential one.

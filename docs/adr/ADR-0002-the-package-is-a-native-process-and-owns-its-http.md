# ADR-0002: The package is a native process and owns its HTTP

- Status: accepted
- Date: 2026-09-05
- Spec refs: §8.1, §8.2, §8.4, §27, §58.2, §58.5; core spec §31.10, §31.21; core ADR-0573
- Decided by: agent (autonomous)

## Context

A KUANG/11 package declares a runtime kind, and the choice decides what the package can reach and
what confines it. Core's spec §31.10 names four trust tiers and says the default for third-party
code *should* be `T2 isolated-component` — a WASM component — where the required host APIs can be
expressed safely. This package is first-party rather than third-party, but the reasoning applies
to it in the same way, and picking the weaker tier without stating why would be picking it by
default rather than on purpose.

The question is decided by how the package reaches an API server, and that was settled elsewhere.
Core's **ADR-0573** records that `network.request` is not the host's to serve: "a request is a
protocol — HTTP today, whatever else tomorrow — spoken over a connection the host brokers", the
operator's trust decision is the `hosts` and `ports` scope of `network.connect`, and "the host
carries no HTTP client for a protocol it does not speak". That ADR names the consequence for
package authors plainly: "A package author who needs HTTP writes it over the brokered connection.
That is more work."

So no tier gives this package an HTTP client. Whichever it picks, it owes itself TLS and HTTP/1.1
over a byte stream.

## Decision

**`runtime.kind: native-process`.**

A WASM component would carry the same obligation — TLS and HTTP over brokered bytes — and would
carry it under WASI's additional restrictions, with a `rustls` build for `wasm32-wasip2` and a
dependency surface this package has not yet grown. The isolation gained is real: for the WASM
tier the host's WASI context preopens nothing and allows no address, so filesystem and network
confinement are structural rather than brokered. It is not yet worth what it costs, because the
package's whole network path goes through the broker either way, and its filesystem access is one
path-scoped read of a kubeconfig.

**This is recorded as revisitable, not settled forever.** The condition to revisit is concrete:
once the transport exists and its dependency surface is known, the question becomes whether those
dependencies build for `wasm32-wasip2`, and if they do, the tier should move. Nothing in the
domain layer or the transport may assume a native process — §58.5 already forbids Kubernetes SDK
types escaping the provider boundary, and the same discipline keeps the tier a packaging decision
rather than an architectural one.

**The package owns its TLS.** Because the host brokers bytes and not requests, §8.4's "TLS
certificate validation MUST be enabled by default" is this package's obligation to keep, not
something it inherits. The kubeconfig's `certificate-authority-data`, its
`insecure-skip-tls-verify` and the system trust store are already modelled in `kubeconfig.rs` for
that reason, and the insecure state is answerable rather than inferable so that a diagnostic can
say so prominently.

## Consequences

Easy: the transport can be written against ordinary synchronous byte I/O and tested against
recorded bytes, with no async runtime and no live socket, which is what §59.1's "no production
cluster requirement" needs.

Hard: this package carries an HTTP/1.1 implementation and, later, a TLS stack. Both are code that
a host-served `network.request` would have made unnecessary, and both are now this project's to
keep correct. Chunked transfer decoding in particular is not optional, because watch streams use
it.

Watch: `native-confined` gives `Confinement::Broker` rather than `Confinement::Kernel` for
filesystem and network. Core's own word for that is honest — a native-process package "can still
open any file its user can" — so the confinement this package runs under is weaker than the
manifest's capability list suggests to a casual reader. The capability scopes are still enforced
at the brokered calls; what is missing is a kernel boundary behind them. Anyone reading this
package's `filesystem.read` scope should know it constrains the brokered call and not the process.

## Alternatives considered

**`wasm-component` now.** Rejected on cost rather than on principle: the same HTTP and TLS work,
plus a `wasm32-wasip2` build of a TLS stack, before the package can make one request. The tier is
the thing to change once the transport exists, and this ADR names that condition rather than
leaving it to preference.

**Ask core to serve `network.request` after all.** Rejected: ADR-0573 is a decision the user and
an agent took together, with a stated reason that does not depend on this package's convenience.
Reversing it would need evidence that the brokered-connection path cannot work, and this package
has not tried it yet. If the transport proves it genuinely cannot, that evidence belongs in an ADR
in core, not in a workaround here.

**Shell out to `kubectl`.** Rejected, and it is worth writing down because it is the cheap answer.
§62.13 requires core conformance on a machine where `kubectl` is absent, the generic provider
contract's §41.1 names "CLI subprocess wrapper as provider" as an anti-pattern, and §4 invariant 1
puts the API server at the authority — a `kubectl` wrapper would put a human-formatted rendering
there instead.

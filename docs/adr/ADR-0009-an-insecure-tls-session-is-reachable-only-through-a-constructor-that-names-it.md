# ADR-0009: An insecure TLS session is reachable only through a constructor that names it, and a context is resolved rather than guessed

- Status: accepted
- Date: 2026-09-05
- Spec refs: §7.1, §7.3, §7.4, §7.5, §8.1, §8.2, §8.4, §27.3 (generic provider contract); ADR-0002 here; core ADR-0573, ADR-0353
- Decided by: agent (autonomous)

## Context

`ADR-0002` records that this package owns its TLS: KUANG/11 brokers a byte connection and serves
no `network.request`, so §8.4's "TLS certificate validation MUST be enabled by default" has
nowhere else to live. Until this change the package spoke plain HTTP/1.1 over the brokered bytes,
which reaches an API server through `kubectl proxy` and nothing else, and `kubeconfig.rs` was
written and unused: the endpoint came from query options.

Three questions had to be answered together, because the answer to each constrains the others.

**Where does an insecure session become possible?** §8.4 allows one "only when explicitly
configured". The usual shape — a `verify: bool` argument, or a `Trust` that maps straight onto a
configuration — makes the insecure state reachable from any call site that happens to pass the
wrong value, and the failure is silent: an unverified session looks exactly like a verified one
until somebody intercepts it.

**Who reads the files a kubeconfig names?** A kubeconfig may put its certificate authority, its
client certificate and its client key at *paths*. Reading them needs the host's `filesystem.read`
capability, and §27.3 of the generic provider contract forbids blanket filesystem access to read
provider configuration. A TLS module that opened those files itself would take a capability
decision inside a constructor, where no reviewer looks for one.

**What names a cluster?** §7.4 requires the selected context to be visible in the provider
instance identity, and the existing query options carried `host`, `port` and `context` with no
default host — deliberately, because an invented endpoint is a cluster the operator never chose.

## Decision

**Verification is disabled in exactly one function, and its name says so.**
`tls::Anchors::for_trust` maps `kubeconfig::Trust` onto trust anchors and *refuses*
`Trust::Insecure` with an error naming `TlsSettings::without_certificate_verification`, which is
the only constructor that builds an unverified session. There is no boolean anywhere in `tls.rs`
that turns verification off. A caller that wants one writes the name, and every such call site is
one `grep` away — the same discipline `Secret::expose` uses for credential bytes (§8.1).

**A certificate authority that does not read is fatal, not a fall back.** `Anchors::pinned`
refuses a bundle that is not PEM, holds no certificate, or holds one `rustls` rejects. Falling
back to the platform store there would verify the server against something the kubeconfig never
named, and nothing in the session would say so. That silent downgrade is pinned by its own test.

**`tls.rs` performs no I/O.** `Anchors` carries certificates and never paths; `Trust::Certificate
AuthorityFile` is refused by `Anchors::for_trust` with the path in the error, so the caller reads
it — `query.rs` does, through `Ctx::host_call(filesystem.read)`, and a denial there is reported as
a capability decision distinct from "no such context".

**A query names a context or an endpoint, and naming neither is refused.** `context` alone
resolves through `~/.kube/config`: the server URL, the default namespace (§7.5) and the trust
anchors come from the file, and the instance is `kubernetes:<context>` (§7.4, §6.2). An explicit
`host` is §7.3's explicit configuration for automation and the test host; it outranks a context
name, reads no kubeconfig, and speaks plain HTTP/1.1. Neither is refused with a message naming
both.

**An explicit `host` never gets TLS, and there is no option to ask for it.** An endpoint given
without a kubeconfig has no trust anchors, and verifying it against the platform store would be a
trust decision taken here rather than by the operator.

**`exec` credential plugins are refused, not approximated.** §8.2 requires an explicit
process-execution capability and the `Never` / `IfAvailable` / `Always` interaction modes. This
package declares neither, so a context that authenticates that way answers `provider.unsupported`
naming what is missing. Connecting anonymously instead would fail on the cluster as a permission
problem, and the operator would debug RBAC for a request that never carried an identity.

## Consequences

Easy: a context that a `kubectl` user already has works — `https://`, a pinned authority, a
bearer token or an inline client certificate — and the end-to-end test proves it against a real
`rustls` server reached through the host's broker, with no cluster and no socket.

Hard: `rustls` is declared with `default-features = false` and `["ring", "std", "logging"]`, which
leaves **TLS 1.2 disabled**. Every current Kubernetes API server negotiates TLS 1.3, so this is a
bound rather than a gap today; a cluster that offers only TLS 1.2 is unreachable until the
`tls12` feature is added, and it will fail at the handshake with a protocol-version error rather
than obscurely.

Hard: a handshake failure consumes the brokered stream, so the package cannot ask whether the host
still holds the connection and does not close the handle. Closing one the host has already retired
is a protocol violation that quarantines the package, which is the worse of the two; the handle is
reclaimed when the invocation ends.

Watch: the manifest scopes `filesystem.read` to `~/.kube/config` and `~/.kube/*.yaml`. A
kubeconfig whose certificate authority or client key sits at `/etc/kubernetes/pki/...` is
therefore denied by the broker, with a message naming the path and the scope. That is the
operator's decision to widen, and it is deliberately not this package's to widen for them.

## Alternatives considered

**A `verify: bool` on the ordinary constructor.** Rejected: it makes the insecure state reachable
by a typo, and §8.4's "only when explicitly configured" is a property of the *call site*, not of
the kubeconfig alone.

**Letting `tls.rs` read the paths a kubeconfig names.** Rejected: it would put a capability
decision inside a TLS constructor and make the module untestable without a filesystem. The split
costs one error variant and buys a module that is a pure function of bytes.

**Falling back to the platform trust store when a pinned authority does not parse.** Rejected as
a silent downgrade — the operator asked for one thing and would get another.

**Reading `current-context` when a query names none.** Rejected for now: §7.4 forbids a command
silently operating on a different context because `current-context` changed on disk, and a
default taken at query time is exactly that shape. A context is named.

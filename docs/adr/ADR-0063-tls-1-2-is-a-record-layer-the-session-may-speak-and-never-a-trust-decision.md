# ADR-0063: TLS 1.2 is a record layer the session may speak, and never a trust decision

- Status: accepted
- Date: 2026-09-07
- Spec refs: §5.1, §5.2, §7.1, §8.4, §61.1; ADR-0002, ADR-0009
- Decided by: agent (autonomous)

## Context

`ADR-0009` declared `rustls` with `default-features = false` and `["ring", "std", "logging"]`,
and recorded the consequence in its own words: TLS 1.2 was disabled, "a cluster that offers only
TLS 1.2 is unreachable until the `tls12` feature is added, and it will fail at the handshake with
a protocol-version error rather than obscurely". That was a bound accepted knowingly rather than a
gap, because every current API server negotiates TLS 1.3.

It is still a bound against the specification. §5.1's support window is a matter of *what the
cluster serves*, and §5.2 makes discovery — not this package's build — the authority on that. An
API server whose operator pinned `--tls-min-version=VersionTLS12` together with a cipher list
that excludes 1.3, a bastion terminating TLS with an older stack, or a managed control plane
behind a load balancer that speaks 1.2 to the client are all clusters an operator holds a valid
kubeconfig for. §61.1's K0 is "connection and discovery", and a handshake that refuses a valid
cluster over a protocol version this package chose not to compile fails K0 for a reason the
specification never states.

The question worth an ADR is not whether to enable 1.2 — `rustls` offers nothing older, and
`with_safe_default_protocol_versions` covers exactly 1.2 and 1.3 once the feature is on — but
whether enabling it weakens §8.4's "TLS certificate validation MUST be enabled by default". The
worry is a real one in general: a second protocol version is a second code path, and the history
of TLS downgrade attacks is the history of a client agreeing to less than it could have had.

## Decision

**The `tls12` feature is enabled in the workspace's `rustls` declaration, and the protocol
version is treated as a property of the record layer with no bearing on trust.** Concretely:

- **The trust decision is unchanged in every path.** `TlsSettings::verifying` builds the
  verifier from `Anchors`, and `Anchors` still has no variant that means "check nothing"
  (ADR-0009). A TLS 1.2 handshake is verified against the same pinned or platform anchors and
  the same server name as a 1.3 handshake; `rustls` runs the same `ServerCertVerifier` for both
  and the version never reaches it as an argument. `AcceptAnyServer` — the verifier behind
  `without_certificate_verification` — already implemented `verify_tls12_signature` because
  the trait requires it, and still answers only from that one named constructor.
- **No obsolete version is enabled.** `rustls` 0.23 has no SSL 3, TLS 1.0 or TLS 1.1 to turn
  on, and this package names its provider and its version list explicitly rather than inheriting
  a process-wide default, so nothing an embedding shell configures can widen the set.
- **Downgrade is the server's choice, not an attacker's.** `rustls` implements the TLS 1.3
  downgrade sentinel: a 1.3-capable server that is negotiated down to 1.2 by a tampered
  `ClientHello` marks its `ServerHello.random`, and the client refuses the handshake. A server
  that genuinely offers only 1.2 is what gets 1.2, which is the case this change exists for.
- **Every refusal is proven on both versions.** Unknown issuer, name mismatch and the
  insecure-only-through-the-named-constructor rule each have a test over a TLS 1.2-only
  `rustls` server beside the existing TLS 1.3 ones, and client certificate authentication (§7.1)
  is proven over both, because 1.2 sends the client certificate in a different flight and a
  session that carried it on 1.3 alone would have proven §7.1 for one version.

## Consequences

- A cluster pinned to TLS 1.2 is reachable with certificate verification on. A cluster offering
  both still negotiates 1.3, which the 1.3-only test pins.
- `tests/tls.rs` gains `should_negotiate_tls_1_3_with_a_server_that_offers_only_tls_1_3`,
  `should_negotiate_tls_1_2_with_a_server_that_offers_only_tls_1_2`,
  `should_refuse_an_unknown_issuer_over_tls_1_2_exactly_as_over_tls_1_3`,
  `should_refuse_a_name_mismatch_over_tls_1_2`,
  `should_reach_an_unverifiable_tls_1_2_server_only_through_the_named_insecure_constructor` and
  `should_present_the_client_certificate_over_tls_1_2_and_over_tls_1_3`. Every existing refusal
  test holds unchanged.
- ADR-0009's "Hard" consequence about TLS 1.2 has expired. Its decision — one named constructor
  for the insecure state, no I/O in `tls.rs`, a pinned authority that does not read is fatal —
  is untouched.
- The compiled TLS surface grows by the 1.2 handshake and cipher suites `rustls` ships as safe
  defaults (ECDHE with AES-GCM and ChaCha20-Poly1305; no RSA key exchange, no CBC). Nothing here
  chooses cipher suites by hand, so a suite `rustls` retires disappears from this package with
  the next dependency update rather than surviving in a list nobody re-reads.

## Alternatives considered

**Leave 1.2 off and document the bound.** Rejected: the bound was already documented, and the
specification's support statement is about what a cluster serves. An operator with a valid
kubeconfig for a 1.2-only control plane gets a handshake error that names a version they did
not choose and cannot change.

**Enable 1.2 only behind a kubeconfig or query option.** Rejected: a knob would imply that 1.2
is a weaker trust posture the operator has to consent to, and it is not — the certificate check
is identical. §8.4 has one knob for weaker trust, and it is `insecure-skip-tls-verify`.

**Enable 1.2 only in the insecure constructor.** Rejected as backwards: the constructor that
checks nothing would speak more versions than the one that checks everything, and a verified
1.2-only cluster would be reachable only by turning verification off.

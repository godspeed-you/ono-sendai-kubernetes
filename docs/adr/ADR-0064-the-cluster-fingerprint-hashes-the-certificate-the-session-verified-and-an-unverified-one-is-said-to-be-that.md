# ADR-0064: The cluster fingerprint hashes the certificate the session verified, and an unverified one is said to be that

- Status: accepted
- Date: 2026-09-07
- Spec refs: §8.1, §8.4, §10.2, §10.3, §10.4, §21.4; ADR-0009, ADR-0011, ADR-0063
- Decided by: agent (autonomous)

## Context

`ADR-0011` modelled §10.2's cluster fingerprint as three named signals and implemented two of
them. The third — a SHA-256 over the server certificate's `SubjectPublicKeyInfo` — had its hash
function written and tested (`diagnostics::public_key_fingerprint`) and nothing to hash: the
package's `TlsStream` completed a handshake and then kept the verified certificate to itself, so
`get k8s-cluster` reported the signal as `not queried`. ADR-0011 left "one accessor on `tls.rs`"
for the change that owned that file.

Three things had to be decided together.

**Which certificate.** A `rustls` session holds the chain the peer presented, end entity first.
The end entity is the certificate the verifier checked against the anchors and the server name;
an intermediate is whatever the server chose to send along, and a root is often not sent at all.
Only the end entity is *the server's* key.

**What an insecure session's certificate is.** `TlsSettings::without_certificate_verification`
(ADR-0009) accepts any certificate. The peer still presents one, and `rustls` still holds it, so
the bytes are available — but nothing vouched for them. Anything able to route the connection
can present any certificate it likes, and hashing that key into the fingerprint would let an
interception decide which cluster the operator believes they are talking to. §10.2's signal is
"server certificate public-key fingerprint", and a certificate nobody verified is not known to
be the server's.

**Where the bytes come from.** The temptation, for a kubeconfig that names a
`certificate-authority` file, is to parse that file and hash it. That is the *authority's* key,
which is a different fact — several clusters routinely share an authority — and it is a file on
disk rather than something observed on the wire. The signal has to come from the session the
diagnostic's own requests travel over, or it is not a fingerprint of the cluster that answered.

## Decision

**`TlsStream::peer_certificate` returns the end-entity certificate of the session it was called
on, and says whether that session verified it.** `PeerCertificate` carries the DER bytes and a
`verified` flag captured from the `TlsSettings` the session was built with — not inferred from
the certificate, which cannot tell, and not from a kubeconfig, which says what was asked for
rather than what was done. There is no accessor for the intermediates.

**`Known<T>` gains a third state, `Unverified(T)`: the value was presented and nothing vouched
for it.** It is neither `Obtained` — `obtained()` answers `None`, `digest()` composes without it,
`compare()` does not count it as agreement or disagreement — nor `Unavailable`, because "the
provider could not learn it" is a different sentence from "the provider was shown it and could
not trust it". `ClusterDiagnostic::unknowns()` lists it with a reason of its own, so
`get k8s-cluster` on an insecure session reports `server_key_fingerprint: null` beside
`tls: insecure-skip-verify` and an unknown that says the key was presented and not verified. The
unverified hash is deliberately not a field of the record: a value in a table gets copied into a
comparison, and the whole point of the state is that this one must not be.

**The plugin hashes the certificate of the session it is about to use, before the first request
goes over it.** `cluster::observe` asks the `TlsStream` for its peer certificate at the moment
the handshake completes and hands the hash to the fingerprint the interrogation starts from. A
plain-HTTP session (an explicit `host`, ADR-0009) presents no certificate and the signal stays
`not queried`, which is the honest state for a connection that has no key to fingerprint.

**The public key, not the certificate, is what is hashed** — unchanged from ADR-0011, and it is
what keeps an ordinary certificate renewal from being reported as §10.4's cluster replacement.

## Consequences

- §10.2 runs on all three of its signals over a verifying TLS session, and
  `Signal::ServerPublicKey` is decisive in `Fingerprint::compare` as ADR-0011 already declared
  it, so two contexts that reach one control plane through two addresses now agree on a signal
  that a bastion or port-forward cannot change.
- §10.4's `MUST` — invalidate cached identity on changed fingerprint evidence — now has the
  evidence it was written for: a cluster rebuilt behind the same address changes its serving key,
  and `Session::observed_fingerprint` sees the disagreement.
- `Unknown::outcome()` becomes `Option<Outcome>`, because an unverified value has no §21.4
  outcome; `describe()` is what every caller used and its shape is unchanged for every existing
  reason.
- Proven in `crates/ono-kubernetes-plugin/tests/cluster.rs` end to end, over the real binary and
  a recorded API server that speaks TLS with a certificate the test's own authority issued, so
  the expected hash is computed in the test from the certificate the server was configured with:
  `should_fingerprint_the_public_key_of_the_certificate_the_session_verified` and
  `should_not_present_an_unverified_certificate_as_the_cluster_fingerprint`. The stream-level
  accessor and the `Known::Unverified` semantics are proven in `tests/tls.rs` and
  `tests/diagnostics.rs`.

## Alternatives considered

**Hash the unverified certificate into the fingerprint with a warning elsewhere.** Rejected: it
is the interception deciding the cluster identity, and a warning in another field is exactly the
inference-as-assertion §4 invariant 20 forbids in a different shape.

**Report the unverified hash in its own record field.** Rejected for now: a field is a value a
reader compares, and there is nothing this value may honestly be compared with. The state is
reported; the hash is not, until somebody names a use for it that is not a comparison.

**Read the kubeconfig's `certificate-authority` and hash that.** Rejected: it is a different key
(the issuer's), it is a file rather than an observation, and it is the same across every cluster
the authority signs for.

**Expose the whole chain.** Rejected: the intermediates are not the server's key and nothing
here has a use for them; an accessor that exists gets used.

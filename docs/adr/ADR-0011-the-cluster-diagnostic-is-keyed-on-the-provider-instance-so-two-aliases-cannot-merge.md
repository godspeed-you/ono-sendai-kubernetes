# ADR-0011: The cluster diagnostic is keyed on the provider instance, and its fingerprint is a set of named signals rather than a value

- Status: accepted
- Date: 2026-09-05
- Spec refs: §8.4, §8.5, §8.6, §10.1, §10.2, §10.3, §10.4, §11.1, §21.4, §34.3, §61.1; ADR-0004 here
- Decided by: agent (autonomous)

## Context

§61.1's last unmet requirement is a provider health and identity diagnostic: which cluster is
this, can it be reached, and who am I to it. Four things about it had to be decided together,
because each constrains the others.

**What identifies the record.** Every other schema this package contributes is keyed on
`metadata.uid`, because a Kubernetes name is a label a human reuses (§16.1). The diagnostic
describes no Kubernetes object, so it has no `metadata.uid` to key on. The obvious candidate is
the cluster fingerprint — and it is the wrong one. §10.3 says two instances that appear to point
at one upstream cluster MAY be *reported* as an alias and **MUST NOT** have their identities
merged, because their credentials and effective permissions differ. A record keyed on the
fingerprint merges exactly those two instances, in the host's object store, silently.

**What a fingerprint is.** §10.2 lists the evidence — normalised origin, server certificate
public key, `kube-system` namespace UID — and then says in one sentence that no single optional
signal may be treated as universally available. A fingerprint modelled as `Option<String>` cannot
express that: a cluster whose `kube-system` namespace the caller may not read comes back
indistinguishable from one nobody asked about.

**What "I could not determine that" is called.** `coverage::Outcome` already names the eight ways
to come back with nothing, and §21.4 requires "the API server refused it", "the API server does
not serve it" and "nobody asked" to stay apart. A diagnostic with its own words for the same
distinctions would let the two vocabularies drift.

**Whether a missing identity is an error.** §8.6 says failure to obtain the effective identity
MUST NOT block ordinary read operations. The same reasoning covers the rest of the diagnostic:
an observation that cannot be made is a stated unknown.

## Decision

**The diagnostic record's identity is the provider instance, `kubernetes:<context>`** — §10.1's
stable local identity, the one thing in the record that does not come from the cluster. Two
contexts pointed at one cluster produce two records with different `uid` and the same
`fingerprint`. The alias is therefore *visible* — the field that would merge them is not the field
that identifies them — and no code path merges anything.

**The fingerprint is a set of named signals, each obtained or unavailable for a stated reason.**
`diagnostics::Fingerprint` holds one `Known<String>` per `Signal`, `digest()` composes only the
signals that were obtained, and `obtained_signals()` reports which those were — so a fingerprint
built from one signal is visibly weaker than one built from three, rather than being absent.
`digest()` is `None` when nothing was obtained, because a hash of the empty composition is a
stable value every unidentifiable cluster would share.

**Comparison is per signal, and the verdict names its evidence.** `Fingerprint::compare` returns
an `AliasVerdict` carrying the signals that agreed and the signals that disagreed.
`Signal::is_decisive` marks the `kube-system` UID and the server public key as decisive and the
origin as not: a bastion, a load balancer or a `port-forward` changes the address without changing
the cluster, so an origin that differs refutes nothing while an origin that matches is still the
accidental-aliasing case §10.2 is about. **There is no operation that merges two fingerprints or
two instances.** §10.3's prohibition is a function nobody can call rather than a comment.

**`Known<T>` carries `coverage::Outcome` as its reason, and nothing in the module returns an
error.** A refused `SelfSubjectReview` is `Known::Unavailable(Outcome::ReadDenied)`; a cluster
that does not serve the review is `Outcome::TypeNotServed`; a signal this build cannot obtain is
`Outcome::NotQueried`. `ClusterDiagnostic::unknowns()` derives the list from those observations
rather than accumulating it beside them, so the list cannot drift from the fields it describes.

**An unreachable cluster gets a record, not a failed invocation.** `get k8s-cluster` has to work
precisely when the cluster does not. The only failures this target reports are a query that named
no API server and a capability the operator did not grant — neither of which is an observation
about a cluster. This is the opposite trade from `ADR-0004`, and for the opposite reason: an
incomplete *listing* fails because the value stream has nowhere to carry the coverage, while the
diagnostic's whole payload *is* the coverage, and it fits in the record.

**The credential identity and the effective identity are two fields even though nothing sets
impersonation.** §8.5 requires them to be impossible to confuse. With no impersonation configured
one `SelfSubjectReview` answers both, and they carry the same subject; with impersonation, the
credential identity is what a review issued *without* the impersonation headers reports and the
effective identity is what one issued *with* them reports. A single field today would silently
change meaning the day the second one appears, and every existing reader of it would change
meaning with it.

**Discovery decides whether the review is even attempted.** The provider asks `/apis` whether
`authentication.k8s.io` is served, reads its resource list, and checks that `SelfSubjectReview`
accepts `create` before posting one (§11.1). A `404` walked into is not the same answer as a
group the cluster does not serve.

## Consequences

- K0's health and identity requirement is met by a contributed target, `k8s-cluster`, answering
  one record — the shape the package already uses, so the shell needs no Kubernetes-specific
  concept to render it (§0.4).
- **The server public-key signal is modelled, implemented and not obtained.**
  `diagnostics::public_key_fingerprint` extracts a certificate's `SubjectPublicKeyInfo` and
  hashes it, with tests over certificates generated in the test; the provider's own `TlsStream`
  does not expose the certificate it verified, so the plugin has no bytes to give it. The signal
  reports `not queried`, which is exactly the state §21.4 keeps apart from absence, and one
  accessor on `tls.rs` promotes it. That accessor is left for the change that owns `tls.rs`.
- The public key rather than the whole certificate is what gets hashed, so an ordinary renewal is
  not reported as the cluster replacement of §10.4.
- The diagnostic makes up to seven requests, each recorded with its source and latency (§34.3).
  That is more round trips than any other target here; it runs when an operator asks, never on a
  path that reads objects.
- §10.4's cache invalidation on changed fingerprint evidence is *not* implemented, because nothing
  in this package caches object identities across invocations yet. The fingerprint that would
  trigger it now exists.
- Alias detection compares two fingerprints and is not persisted: a shell that holds two
  diagnostics can call `compare`, and nothing here remembers a cluster between invocations.
  `state.persist` is declared in the manifest and unused.
- `ring` becomes a declared dependency of `ono-provider-kubernetes`. It was already in the tree
  beneath `rustls`, so this widens the declaration and not the supply chain.

## Alternatives considered

**Key the record on the cluster fingerprint.** Rejected: it is the merge §10.3 forbids, performed
by the host rather than by this package, which makes it harder to see rather than impossible.

**Make the fingerprint one opaque string, absent when incomplete.** Rejected: it collapses "the
caller may not read `kube-system`" into "this cluster cannot be identified", and §10.2's closing
sentence exists to prevent exactly that.

**Report the reason for a missing signal in the field itself** — `kube_system_uid: "read
denied"`. Rejected: a renderer cannot tell that from a UID, and an operator reading a table would
take the second for a value. The value is null and the reason is in `unknowns`.

**Fail the invocation when the cluster cannot be reached.** Rejected: the question the target
answers includes "can it be reached", and an error is a worse rendering of "no" than a record
saying no.

**A contributed command rather than a target.** Rejected: a command returns whatever it likes,
with no declared schema, no identity and no provenance — the same reason `ADR-0582 (core)` was
needed for `get pod`.

**Attempt `SelfSubjectAccessReview` and `SelfSubjectRulesReview` too** (§21.2, §21.3). Deferred:
both are advisory, §21.3 says a rules summary MUST NOT be treated as a complete authorization
oracle, and neither answers "which cluster is this". They belong with the capability UI of §21.6.

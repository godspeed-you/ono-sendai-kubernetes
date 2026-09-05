# ADR-0005: Five schemas rather than nineteen, because a declared schema is a promise

- Status: accepted
- Date: 2026-09-05
- Spec refs: §14.4, §15.1, §15.2, §15.5, §16.1, §22, §33.1, §61.2 (K1); core spec §31.23, §31.68
- Decided by: agent (autonomous)

## Context

A KUANG/11 package states what it contributes twice. Once statically, in
`package/contributions/*.yaml`, which the host reads without starting anything, so that a target
word, its help page and its completion answer on a shell that has never loaded the package
(core §31.68). Once across the handshake, when the instance actually loads (core §31.23) — and
there the host registers the schema before it will accept a record carrying it.

`package/contributions/targets.yaml` declares nineteen nouns: the Tier 1 operational set of
§15.2, the resources everyday workload troubleshooting crosses. Declaring all nineteen statically
is what makes the package worth loading on first use rather than on every start.

The question is what the *schemas* document declares. The tempting answer is nineteen, so that
the two documents look symmetric. But a contributed schema is not a description of a Kubernetes
kind — it is a claim that this package will emit records of that shape, with those fields,
non-null where the schema says required. Nothing emits a `KubernetesService` record today. A
schema for one would be a promise with no code behind it, and §15.5 forbids exactly this class of
overstatement: documentation MUST state *separately* what is readable dynamically, what is
semantically curated, what is relationship enriched, what is watch capable and what is mutation
capable, because "a resource being discoverable does not imply that Ono understands every field or
relationship".

## Decision

**Nineteen target words are declared statically. Five carry a schema and a handler.**

`package/contributions/schemas.yaml` declares five schemas; `contributions::TARGETS` wires the
same five to query handlers; and `contributions::target()` returns `None` for the other fourteen,
so the package does not claim to answer a word it cannot answer. A single static table in
`contributions.rs` derives both the handshake contributions and — checked by
`tests/contributions.rs` against the YAML — the static documents, so the two halves of the
declaration cannot drift apart about what the package contributes.

Each of the five earns its place by proving something the others do not:

- **`k8s-namespace`** is the scope dimension itself (§9.2). Without it the shell can enter no
  scope this provider defines.
- **`k8s-node`** is cluster-scoped, so both scope shapes are exercised for real: the query path
  must derive the collection URL from discovery's scope rather than interleaving a namespace into
  everything, and §9.2's fake namespace never gets invented.
- **`k8s-pod`** is the noun the Cloud-Native Validation Gate names, and the one every relationship
  in §25 to §28 eventually lands on.
- **`k8s-deployment`** carries the desired-versus-observed pair of §14.4 — `generation` beside
  `observedGeneration`, `desired_replicas` beside `ready_replicas` — which is where a status
  flattening would be visible if one had been made. It is also the only one in a non-core API
  group, so the group-versus-core discovery path is exercised rather than assumed.
- **`k8s-secret`** is where §22's redaction boundary is demonstrated rather than asserted: the
  schema exposes `keys` and no payload, and an end-to-end test asserts the payload bytes appear
  nowhere in what the host received.

**What the other fourteen wait on** is not typing effort. Three things, in order:

1. **A field projection worth declaring.** Every schema is a set of §15.5 claims about which
   fields this package understands. `k8s-service` without `spec.type`, its ports and its selector
   would be metadata with a Kubernetes kind on it, and the selector is only meaningful once §26.1
   selection is answered rather than displayed.
2. **A query that reads more than one collection.** `k8s-endpointslice`, `k8s-ingress` and
   `k8s-serviceaccount` are interesting because of what they connect, and the traversal exists in
   the domain layer (`workload.rs`, `redaction::secret_references`) while the query path lists one
   GVR per invocation. Those nouns land with K2's operational graph, not before.
3. **`k8s-persistentvolume`, `k8s-storageclass`, `k8s-networkpolicy`** wait on the same, and on
   §31.3's honesty about policy effectiveness, which is a claim this package is not yet in a
   position to make.

**The fourteen are not the real gap, and this ADR says so rather than implying that finishing
them completes K1.** §15.1 asks for baseline dynamic support for *every discovered readable
resource*, which no static list can express: a CRD invented after this package was built cannot
appear in a document written before it. The mechanism for that is a separate open question —
`schema.rs` already projects an arbitrary object against an arbitrary OpenAPI schema, and what is
missing is a target shape that names a kind at runtime. Fourteen more static schemas would not
move that question one step.

## Consequences

Easy: every schema the package declares is one that something emits, so a schema mismatch is a bug
in this package rather than an unimplemented promise. Help and completion still answer for all
nineteen nouns, so the shell's discoverability does not depend on how much of the package is
finished. Adding a target is one table entry plus its field arms, and the tests hold the two
documents together.

Hard: `get k8s-service` is a word the shell will offer and this package will not answer. That is a
worse experience than not offering it at all *if* the refusal is unclear, and it is a better one
if the refusal names the reason — which is the shape §15.5 asks for and which the board tracks
until the noun is real.

Watch: it is not verified here what a host does with a static placeholder naming a schema id that
no schema document declares. The handshake path is checked — `tests/contributions.rs` asserts the
contributed schemas and the declared schemas are the same five — but the fourteen placeholders in
`targets.yaml` name schema ids that `schemas.yaml` does not contain, and whether core validates
that pairing at registration is an open question rather than a settled one. If it does, either
those entries lose their `schema` key or the placeholders shrink to five. That is on the board.

Watch also: the five were chosen for what they prove, not for what an operator most often types.
When the sixth is added the question to ask is which distinct claim it makes checkable, not which
kind is next alphabetically in §15.2.

## Alternatives considered

**Declare all nineteen schemas now and let fourteen of them return nothing.** Rejected: a
contributed schema is a promise the package cannot keep, and the failure mode is the worst
available — a target that answers with a well-formed empty result looks exactly like a cluster
with no Services, which is the §21.4 confusion this provider exists to remove.

**Declare only the five nouns statically as well, and add target words as they are implemented.**
Rejected: §31.68's placeholders are what let the shell offer help and completion for a package it
has not started, and the Tier 1 set is the honest statement of what this provider is *for*.
Shrinking the vocabulary to the finished part would make the package look smaller than its
intent and would churn the static document on every increment.

**One document per schema instead of one document with five.** Rejected: these five are one
decision about how a Kubernetes object becomes a record — the same metadata projection, the same
`uid` identity, the same unknown-is-null rule — and separate files would let them drift apart a
field at a time.

**Share the common metadata fields by composition rather than repeating them per schema.**
Rejected because the wire shape has no notion of a mixin: `SchemaContribution` carries a flat
field list, so a reader of one schema should see all of it in one place, and the repetition is
generated from one constant rather than typed out.

**Wait for the dynamic mechanism of §15.1 and contribute no static schemas at all.** Rejected: it
would leave the package with nothing runnable and nothing to test the whole chain with, and the
five that exist are what proved the brokered transport, the discovery path and the redaction
boundary end to end.

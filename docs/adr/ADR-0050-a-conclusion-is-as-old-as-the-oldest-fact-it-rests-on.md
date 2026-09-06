# ADR-0050: A conclusion is as old as the oldest fact it rests on

- Status: accepted
- Date: 2026-09-06
- Spec refs: §17.1, §20.2, §20.3, §23.1, §23.3, §23.6, §21.4, §4 invariants 8 and 20;
  Appendix C.2; ADR-0007
- Decided by: agent (autonomous)

## Context

§23.6 is one sentence:

> A derived edge's freshness is bounded by the freshness of every source fact used to derive it.

Every edge this provider emitted carried the freshness of the *subject's* read. For an owner
reference that is exactly right — the edge is a field of the object, and nothing else was read to
find it. For a `selects` edge it is wrong in the direction that matters: the edge is this
provider's conclusion from a Service read at one instant and a Pod collection read at another, and
stamping it with the subject's `observed_at` dates a conclusion by the freshest thing that went
into it. That is the arithmetic that makes a stale answer look current, and it is the same
substitution §4 invariant 20 forbids in the evidence field — reported as a fact something that was
inferred.

Appendix C.2 shows what a selector edge is supposed to carry, and the field had no counterpart in
the record:

```text
observed_resource_versions:
  service: "..."
  pod: "..."
```

## Decision

**`Freshness::bounded_by` in the domain layer, applied to exactly the edges this provider
concluded, with each source's `resourceVersion` published beside it.**

Three parts:

1. **The arithmetic lives in `Freshness`, not in the relations handler.** It is a rule about what a
   read is worth, and it belongs where every other such rule already is. It takes the oldest
   `observed_at`; a non-direct `Origin` among the sources wins, because a conclusion resting on a
   cache hit is not a direct observation whatever its other half was (§20.2); and a
   `watch_synced: false` source qualifies everything derived from it (§20.3).

2. **The `resourceVersion` is dropped rather than reconciled.** A `resourceVersion` names a point
   in *one* object's continuity (§4 invariant 8). There is no such point for a conclusion drawn
   from two, and offering one of the sources' tokens would hand a reader a continuity they cannot
   resume the edge from — a token that looks resumable and is not is worse than none.

3. **`observed_resource_versions` says which reads they were**, so §23.6 is checkable rather than
   merely asserted. The subject is always in it. A collection is in it *only* for an edge this
   provider concluded: naming a Pod list beside an owner reference would cite a source that had no
   part in the conclusion, which is the same class of mistake as citing evidence that does not
   exist — and it is the mistake a single shared map of "everything this invocation read" would
   make automatically.

Which edges are bounded is decided by `Evidence::is_asserted_by_provider`, the same fact the record
already publishes as `asserted`. That is deliberate: the rule a reader is told about and the rule
the code applies are one thing rather than two that can drift apart.

The bound is taken over *every* collection the invocation read rather than over the ones the
particular rule used. That is conservative — an edge is dated no fresher than any source, and never
fresher than the truth. Tracking per-rule provenance would be more precise and would put a second
bookkeeping structure between a rule and its output, for an improvement measured in the
milliseconds between two reads in one invocation. The conservative bound is the one that cannot be
wrong in the dangerous direction.

## Consequences

`get k8s-relation --kind Service --name api` now dates its `selects` edges by the older of the two
reads behind them, and each such record names both `resourceVersion`s. An `owned-by` edge is
unchanged and names only the subject, which is the whole of its evidence.

A source whose read carried no `resourceVersion` is left out of the map rather than entered as
empty text: the point of the field is that a reader can check the edge against the cluster, and a
key with nothing behind it is a check nobody can make (§21.4). The recorded Service fixture gained
a `resourceVersion` for that reason — every object a real API server returns has one, and a fixture
that omitted it was quietly testing a cluster that does not exist.

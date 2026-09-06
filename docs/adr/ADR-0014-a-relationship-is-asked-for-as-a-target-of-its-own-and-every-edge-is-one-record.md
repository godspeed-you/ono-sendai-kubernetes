# ADR-0014: A relationship is asked for as a target of its own, and every edge is one record

- Status: accepted
- Date: 2026-09-06
- Spec refs: §9.2, §9.6, §11.5, §16.1, §21.4, §23, §24, §25, §26, §27, §28, §29, §32, §33.1,
  §35.4, §35.7, §36.1, §36.2, §60.5, §62.4 (Gate D); §4 invariants 13 and 20
- Decided by: agent (autonomous)
- Builds on ADR-0004, ADR-0007, ADR-0008, ADR-0010, ADR-0012, ADR-0013

## Context

`relationship.rs` and `workload.rs` derive the whole `Ingress -> Service -> EndpointSlice -> Pod
-> Node` path with the evidence classes §23 defines, and `place.rs` addresses both ends of an
edge. None of it had an importer: the package read nine of the domain modules and never these.
Gate D (§62.4) — *every curated relationship can reveal whether it came from a native field, an
ownerReference, a selector, a well-known convention, an adapter derivation or an inference, and
the source fields used* — was true inside a unit test and unreachable from a prompt.

Routing it raises one question the specification does not answer, because it is a question about
Ono's shape rather than about Kubernetes.

**How does a user ask for a relationship?** A relationship is not a resource. It has no
`metadata.uid`, there is no collection to fetch it from, and half of the edges do not exist until
this provider derives them from two objects. Every other noun this package answers for maps onto
"read a collection, project each object"; this one does not.

Three shapes were on the table.

**A. A target of its own** — `get k8s-relation --kind Pod --name api-7d9f-abc`, one record per
edge.

**B. An option on each object target** — `get k8s-pod --name … --relations`, folding the edges
into the object's record as a list field.

**C. A host relation contribution** — pushing edges into core's relation store through
`relations.contribute`, and letting core's own traversal answer.

## Decision

**A: `k8s-relation` is a contributed target of its own, and it answers one record per edge.**

**Why not B.** An edge folded into a Pod's record is one opaque list field. It inherits the
object's identity, so a Pod's six relationships become one thing six times and no pipeline can
filter, sort or group them; contributions are static (ADR-0010), so the field would have to be
added to all nineteen schemas, each of which would then declare a shape it fills only sometimes;
and ADR-0013's rule — one field name means one thing everywhere — would be carrying a list whose
element structure the schema vocabulary cannot express. A record per edge is a value stream, and
a value stream is what the rest of the shell already knows how to work with.

**Why not C.** `relations.contribute` writes into a store, and this provider's reads are
side-effect free by §6's constraint. It is also the wrong direction for the first increment: the
edges have to be *derivable and inspectable* before it is worth deciding who caches them. C stays
open and is not foreclosed by A — a later session can feed the same edges into the host store,
and the schema below is what it would feed.

**The question is asked about one named object.** `kind` (or `resource`) and `name`, resolved
against discovery by the same code `k8s-resource` uses — so a CRD's owner references are reachable
without recompiling anything (§33.1) — and refused when `name` is absent. A relationship is a fact
about one object; deriving the edges of a whole collection would read every object in it to answer
a question about none of them. The resolution needs `get` rather than `list`, because §11.5's
resource that offers one without the other still has relationships and §60.5's Pod is readable by
name in a namespace nobody may enumerate (ADR-0012).

**No compound `--of pod/checkout-7f9d`.** It would be a second grammar for something the package
already spells with `kind` and `name`, and §35.1 and §4 invariant 22 forbid a hidden Kubernetes
mini-shell. The existing options also carry `group` and `version`, which a slash-separated
argument would have to grow a syntax for the day two groups serve one kind (§13.5, §35.8).

**An edge's identity is four fields: `uid`, `relation`, `target`, `evidence_path`.** It is the
only schema in this package not keyed on `metadata.uid`, for the plain reason that an edge has
none. Each component earns its place by what merges without it: `owned-by` and `controlled-by`
are one fact at two strengths (§24.3) and would collapse without `relation`; one object's two
owner references differ only in the far end; a Pod naming one ConfigMap from two containers
differs only in the pointer. `uid` keeps its meaning from every other schema here — the object the
record is a fact *about* — which is what lets `records::field_value` project the source's metadata
unchanged (ADR-0013).

**The record carries the evidence in four fields, and none of them is optional.**

| field | what it settles |
|---|---|
| `evidence_class` | Gate D's six-way choice, as a closed enum; `inference` is declared and never emitted |
| `evidence` | what was read and what it held, in one line |
| `evidence_path` | the JSON pointer, where the class cites one; null where the proof is not one field |
| `asserted` | whether the API server states the relationship, or this provider derived it (§23.3) |

`supporting` carries what qualifies an edge without deciding it — the host, path and port §27.1
requires to stay attached, the adapter that read a custom resource (§33.8) — each entry naming its
own class, so a supporting fact is checkable on the same terms as a deciding one.

`evidence_path` is null for a selector evaluation on purpose. The proof there is two objects, and
reporting a pointer would name a field as the proof when the proof is somewhere else; `evidence`
still says which selector matched which labels, which is what §23.3 asks for.

**Both ends are places, built by `place.rs`.** `source` and `target` are `k8s://` addresses in the
grammar of ADR-0008, so a cluster-scoped target has no namespace slot to fill and cannot acquire
the source's (§9.2, §24.2). The target's address is present even where the object was never read,
because §24.1 keeps a dangling edge an edge; `target_resolved` says which of the two it is, and
`target_uid` carries whatever the reference itself stated. `target_roles` is §36.2's overlay,
beside the native `target_kind` rather than instead of it (§36.1).

**A derivation that could not read is a gap, never an absence.** The derived classes need a second
reading — a Service's `selects` needs the Pods of its namespace, its `represented-by` needs the
EndpointSlices. When that listing is denied, unserved, or short, the rule is not evaluated at all
(ADR-0007: an unevaluated selector says so rather than returning the subset it could evaluate),
the edges that *were* derived are emitted because they are true, and the invocation then fails
naming §21.4's outcome — because a value stream of one schema has nowhere to put a coverage
report (ADR-0004, §4 invariant 13).

**The ownership reversal names kinds, and that is deliberate.** An owner reference lives on the
child, so answering "what does this Deployment own" means knowing which collection to look in. A
six-entry table in `relations.rs` maps §25's chain — Deployment to ReplicaSet, ReplicaSet,
StatefulSet, DaemonSet and Job to Pod, CronJob to Job — and a kind that is not in it yields the
edges it states about itself and no reversal. It is a curated-tier table (§15.2) beside the
curated-tier rules in `workload.rs`, and it is not a claim about which kinds exist: the dynamic
route resolves the *source* against discovery whatever kind it is, and an owner reference on a CRD
is read the same way as one on a Pod.

## Consequences

- Gate D is provable end to end. `tests/query.rs` drives the real binary against a recorded API
  server and asserts that a Pod's six edges reach a user naming their class and cited fields, that
  a Service's `selects` edge says it was derived and names the selector and the matched labels,
  that an owner reference states `controller: true`, that an edge whose target was never read is
  still an edge, and that nothing anywhere emits `inference`.
- `follow` has a vocabulary to traverse: `relation` narrows an answer to one of §35.7's words, and
  a word nobody defines is refused with the list of the ones somebody does, because answering
  nothing would say the object has no such edges.
- The evidence classes cannot blur by accident. A record that lost `evidence_class`, `evidence` or
  `asserted` would not decode: they are required fields of a contributed schema, so the host
  refuses the record rather than rendering a guess as an assertion.
- A relationship query costs more round trips than a listing — discovery, a resource list per
  group, the object, and a collection per derivation — and there is no session to amortise them
  (gap 2 of `docs/coverage.md`). That is a cost, not a correctness problem, and it shrinks to
  nothing the day discovery is cached.
- What is still unrouted, and named so nobody has to rediscover it: `Workload::selector_matches`
  (its `NotEvaluated` answer is not an edge and needs a shape of its own — ADR-0007),
  `Workload::volume_claim_templates` and `job_history` (intent and bounds, both non-edges),
  NetworkPolicy's `selects` (§31.1 — the domain layer has no rule reading `spec.podSelector`), and
  `condition.rs` beyond the `reconciliation` map the object schemas already carry. `near`, `up`
  and the `Neighbourhood` of `place.rs` remain unreachable: they are navigation rather than a
  value stream, and they need a verb this package does not yet answer.

## Alternatives considered

- **An option on each object target (B).** Rejected above: it makes an edge un-filterable, gives
  a Pod's six relationships one identity, and adds a field to nineteen schemas that most of them
  fill with nothing.
- **A schema per relationship kind** — `KubernetesOwnership`, `KubernetesRouting`. It would let
  each carry its own qualifiers as typed fields rather than as `supporting` strings. Rejected for
  ADR-0010's reason turned around: relationship *names* are open (a curated adapter may add one),
  so a schema per kind would be a static document trying to name something a later adapter
  invents, and a reader who wanted "everything this Pod touches" would have to union several
  streams.
- **One record per object carrying all its edges as a `map`.** Same identity problem as B, and it
  would make the natural question — "show me every `owned-by` edge in this namespace" — a
  client-side unnesting rather than a filter.
- **Deriving edges for a whole collection when `name` is absent.** Rejected: it turns one question
  into a read of every object in the namespace plus a derivation listing per object, and the
  operator who typed it asked about none of them in particular. If a fan-out is ever wanted, it
  should be an explicit word rather than the meaning of an omission.
- **Emitting an `inference` edge for anything.** Not implemented and not implementable through
  this route: no rule this module calls produces the class, and §23.5 reserves it for a
  cross-system resolver under an explicit confidence model.

# ADR-0058: A rule's selector is pushed down as upstream spells it, and an index answers only while its watch is live

- Status: accepted
- Date: 2026-09-07
- Spec refs: §17.3, §17.6, §19.7, §20.2, §20.3, §23.3, §23.6, §24.1, §25.1, §26.1, §26.2, §31.1,
  §50.4, §60.3; §30.5 of the generic provider contract in core; ADR-0007, ADR-0026, ADR-0044,
  ADR-0049, ADR-0050
- Decided by: agent (autonomous)

## Context

Every derived edge this provider answered was evaluated against a whole namespace. `get
k8s-relation --kind Service --name api` listed every Pod of the namespace at five hundred a page
and applied `spec.selector` locally; a Deployment listed every ReplicaSet; a NetworkPolicy listed
every Pod. On a two-Pod fixture that is one request. On a namespace of a hundred thousand Pods it
is two hundred requests to evaluate a selector the API server indexes, and `Budget::interactive`
refuses the sixteenth page — so the question was not slow there, it was unanswerable.

Two sections say what to do and one says what not to:

> The provider SHOULD push supported label selectors and field selectors … when Ono query
> semantics map exactly. It MUST NOT push a filter when the translation changes semantics.
> — §17.3
>
> Selector and owner-reference relationships MAY use indexes maintained over active caches.
> Indexes MUST track cache sync/freshness. An incomplete index MUST not return an unqualified
> complete-looking graph. — §50.4
>
> Providers MAY maintain indexes for relationship traversal, but index size and invalidation
> MUST be bounded and observable. — §30.5 (core)

ADR-0049 settled the *caller's* selector by refusing to translate it at all, and that decision
stands untouched. What §17.3 leaves open is the *rule's* selector — the one `relations.rs` reads
from the object it was asked about — and whether a translation of that one can be exact.

A second thing was in the way. A `k8s-change` invocation held its session's lock for its whole
life (ADR-0026: "two invocations of the same instance take turns"), which is the right rule for a
listing and a strange one for a watch: every other question about the same cluster waited for the
operator to stop watching. §50.4's cache "maintained over active caches" was therefore a cache no
relationship query could ever reach, because the invocation keeping it active was the one keeping
the session shut.

## Decision

### 1. The rule's selector is pushed down, and the translation is upstream's own

`crate::index::LabelSelector` reads a `metav1.LabelSelector` — `matchLabels` and the four
`matchExpressions` operators — and renders it exactly as `LabelSelectorAsSelector` in
`apimachinery` does: equalities as `key=value`, then `key in (a,b)`, `key notin (a,b)`, `key`,
`!key`. The same type evaluates the same expression locally. `tests/relationships.rs` pins every
operator in both directions, including the two upstream defines against intuition (`notin` and
`DoesNotExist` are satisfied by an object that lacks the key).

That is what makes the pushdown *exact* rather than *close*: the string the API server receives
is the one a client-go controller would have sent it, evaluated by the same server-side code that
decides what that controller sees. There is no Ono-side predicate language on the wire and no
translation of anything an operator typed — ADR-0049's argument, applied to a selector this
provider reads out of an object with its own code.

Which rule pushes what:

| Rule | Selector pushed | Why it is exact |
|---|---|---|
| Service → `selects` Pod (§26.1) | `spec.selector` as equalities | an equality map has one meaning in every evaluator; an empty one selects nothing and reads nothing |
| Service → `represented-by` EndpointSlice (§26.2) | `kubernetes.io/service-name=<name>` | one label, one value |
| NetworkPolicy → `selects` Pod (§31.1) | `spec.podSelector.matchLabels` as equalities | an empty `podSelector` is every Pod of the namespace, which is no `labelSelector` at all; a selector carrying expressions is refused *before* any Pod is read (ADR-0007) |
| controller → `owns` child (§25) | `spec.selector` as upstream reads it, as a **pre-filter** | see below |
| Pod → `selected-by`, `protected-by`; Service → `routed-from` | nothing | the selector lives on the far object, and no field of a Service says what it selects in a form the server filters on |

A selector this provider cannot read as upstream reads it — an operator it does not define,
`In` with no values — is not pushed at all. The fallback is the unfiltered listing, never an
approximation of the selector.

### 2. The owner pre-filter keeps the evidence class, and its one lag is stated

A Deployment's ReplicaSets are proven by `metadata.ownerReferences` (§24.1); the class on the
edge stays `owner-reference` and `Workload::owns` still reads every candidate's references. The
controller's `spec.selector` only decides *which candidates are fetched*.

That is exact because of how upstream controllers behave: the `ControllerRefManager` adopts an
orphan only if the selector matches it, and on every sync it *releases* a child it owns whose
labels no longer match — removing its own owner reference. A child that carries the reference and
fails the selector is therefore a child the controller is about to release, and it exists for
exactly the interval between a label change and the controller's next sync. In that interval
this provider answers what the controller is about to make true rather than what it has just
stopped being; the edge that disappears is one the cluster is in the act of removing. Every other
child the reference proves matches the selector, because that is the only way it acquired the
reference. A CronJob states no selector, so its Jobs are listed unfiltered.

### 3. An index lives with its watch, answers only while absence is conclusive, and is bounded

`crate::index::RelationshipIndex` holds three tables — label postings per namespace, children per
owner UID, objects per namespace — and no others: each is consumed by a derivation that exists,
and a UID, Node or StorageClass table would be maintained for a rule nobody has written. It is
owned by the session's `Watched` entry beside the stream, rebuilt by `Session::synchronise` and
updated by every event `Session::observe_event` applies. It is dropped with the stream, so every
invalidation the session already performs on a watch — `410`, a write to the collection
(§20.5), a cluster replacement (§10.4), a released view — invalidates the index by construction.

`Session::indexed` answers only while `WatchStream::absence_is_conclusive` — the same rule
`Session::lookup` reads by — and returns a named `IndexMiss` otherwise: not watched, not synced
in one of §41.4's words, or over capacity. `relations.rs` and `spatial.rs` treat every miss as a
reason to read the API server with the pushdown above, never as a reason to answer less.

The bound is `INDEX_CAPACITY` (fifty thousand objects), and crossing it *empties* the index
rather than truncating it: a truncated index would answer a selector with a subset that looks
whole, which is the sentence §50.4 forbids. `Session::index_state` and `Indexed::state` expose
size, bound, sync state and continuity, and the session's `Debug` prints them.

An answer from the index carries `Freshness::cached` — the stream's last observation instant,
the collection's continuity token, `origin=cache`, `watch_synced` — and ADR-0050's bound dates
every edge concluded from it accordingly. The record's provenance says `origin=cache`.

### 4. One listing per collection, scope and selector, per invocation

`Derived::listings` memoises every collection read by `(GVR, scope, labelSelector)`, so two rules
wanting the same listing read it once and a rule wanting a differently filtered one does not
inherit a wider read (§17.6's grouping, with the scope preserved on every gap). `spatial.rs`'s
neighbour inventory reads through `Session::indexed` first for the same reason, so a neighbour
drawn by `near` and an edge read by `get k8s-relation` come from one cache where one exists.

### 5. A watch borrows the session per step and never holds it for its life

`changes.rs` reaches the session through `Held::with` — a `Sessions::with` per step — for the
acquisition, for each event it applies, for each state it reads, and for the release at the end.
Between steps, where a watch spends its life blocked on a quiet socket, the session is free. The
record is built inside the borrow and emitted outside it, because emission blocks on the
consumer's credit and a session locked while a reader is slow is a session nobody else can reach.

ADR-0026's rule is unchanged: two invocations of one instance still take turns *inside* the
session. What changed is the length of a turn.

## Consequences

Measured in `crates/ono-kubernetes-plugin/tests/performance.rs`, over a four-page namespace of
which one Pod per page carries the selected label:

| Traversal | Before | After |
|---|---|---|
| Service (`selects`, `represented-by`, `routed-from`) | 13 requests: 6 discovery, the Service, 4 unfiltered Pod pages, the slices, the Ingresses | **10**: one Pod request carrying `labelSelector=app=api`, one slice request carrying `kubernetes.io/service-name=api` |
| Deployment (`owns`) | 8, ReplicaSets unfiltered | **8**, ReplicaSets carrying the Deployment's selector, and no Pod read |
| Pod (`selected-by`, `protected-by`) | 9 | **9**, and provably no Pod listing |
| NetworkPolicy (`selects`) | 11: 4 unfiltered Pod pages | **8**: one filtered Pod request |
| Service, with a synced watch open on the namespace's Pods | a Pod listing per query | **0** Pod requests; every `selects` edge says `origin=cache` |

The "before" column is derived from the previous code path against the same fixture; the
fixture did not exist before this change, so the numbers are arithmetic rather than a recording.

The watch no longer starves its instance. `tests/performance.rs` proves a relationship query
answering *while* a `k8s-change` invocation of the same instance is open, and §60.3's scenario
is now composable at the provider boundary.

**What this does not fix, and is written down so nobody reads it as fixed.** `Session::close_view`
keeps a stream whose state is `Live` after the view behind it has ended (ADR-0037's reading of
§19.7), and nothing feeds it afterwards. `Session::lookup` already answers from such a stream
with `origin=cache` and `watch_synced=true`, and the index now does the same, by the same rule:
the instruction is to reuse the session's watch where its absence is conclusive, and that is the
predicate. It is a truthfulness hazard — a name created after the view closed reads as
`ConfirmedAbsent`, and an edge derived then rests on a cache nobody is keeping true — and it
belongs to the owner of the close-view contract rather than to this decision. It is reported on
the board.

`Indexed` borrows the session for the length of one derivation; a derivation that needs both the
index and a mutable session must take the objects out first, which `Reads::collection` does.

## Alternatives considered

**Evaluate `matchExpressions` locally and drop ADR-0007's `NotEvaluated`.** The translation now
exists, so `Workload::selector_matches` could apply it. Refused for this change: it alters a
relationship's answer rather than its cost, belongs in its own increment with its own tests, and
ADR-0007 asked for exactly that separation.

**Push the caller's `--selector` through the same translation.** Refused; ADR-0049's argument is
that the safest translation of somebody else's question is none, and nothing here touches it.

**Index every watched collection into a session-wide graph keyed by UID.** The tables §50.4
lists are the ones a derivation asks for; a graph nobody queries is memory spent on a promise.
The three tables here are the ones `relations.rs` consumes, and the module says a fourth is added
when a fourth consumer is.

**Shed the oldest postings past the bound.** The obvious bound, and the one that produces an
index that answers `app=api` with the Pods it happened to keep. §50.4's `MUST` is about that
exact shape.

**Mark a closed view's stream `Reconnecting` so its cache stops answering.** The honest state,
and the one that would change what `should_release_a_closed_view_s_watch_only_when_its_cache_can_no_longer_answer`
pins. It is the right next decision and the wrong one to fold into this increment; it is recorded
above as a finding rather than taken here.

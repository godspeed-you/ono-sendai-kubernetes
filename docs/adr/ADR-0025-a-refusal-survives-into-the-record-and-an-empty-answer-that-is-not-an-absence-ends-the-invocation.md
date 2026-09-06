# ADR-0025: A refusal survives into the record, and an empty answer that is not an absence ends the invocation

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 13, 20, 22, §14.1, §14.7, §16.1, §21.4, §23.3, §23.4, §28.3, §28.4, §28.5, §35.1, §37.1, §37.2, §37.3, §37.5, §38.1, §38.2, §38.3, §38.4, §38.5, §38.6, §39.1, §39.2, §39.3, §39.4, §40.1, §40.4, §40.5, §42.1, §42.2, §47.1, §47.2, §47.7, §62.11, §63.6
- Decided by: agent (autonomous)

## Context

Six domain modules were built, tested and unreachable: `events.rs` (§38), `evidence.rs` (§28.3 to
§28.5 and §47), `logs.rs` (§42), `temporal.rs` (§39), `causal.rs` (§40), and the part of
`condition.rs` beyond the `reconciliation` map that five object schemas already carry (§37.1).
Between them they hold most of what makes this provider's claim different from a wrapper over the
upstream command-line client, and none of it could be asked for.

They also share a property that made routing them the hard part rather than the mechanical part.
**Each module's central content is a refusal**, and the refusal lives in the *shape* of its types:

- `Observations` offers no sort and `Occurrences` offers no `expand`, so a set of Events cannot
  become a history and an aggregated count cannot become a list of occurrences (§38.1, §38.4);
- `Found::NotObserved` carries an `Outcome` that can never be `Absent`, at any input (§38.6);
- `NodeEvidence` has no constructor that turns a value into a relationship, and no scheme has a
  match arm anywhere in it (§47.1, §28.5, Gate K);
- `Retrieved::bounds()` is never empty and there is no accessor whose name means "everything it
  printed" (§42.1);
- `Stamp` implements no comparison trait, so `sort()` does not compile, and `Basis::Observed` is
  reachable only through a watch event (§39.2);
- `Claim` has five members and none of them says that one thing brought about another (§40).

A boundary can lose every one of those without a single wrong value crossing it. A `Vec` of
records has no `sort` either, and the shell it is handed to does; a `timestamp` field is a column a
consumer orders by; an empty stream of records is read as absence by every consumer that has ever
been written; and a field *name* is what a reader reads first — `cause` above a correlation is a
lie told by a column heading with a true value under it.

So the question this decision answers is not "how are these six routed". It is: **what does a
boundary have to do so that a refusal expressed as a Rust type is still a refusal after it has
become a record?**

## Decision

### 1. Six contributed targets, and no new verb

`k8s-event`, `k8s-evidence`, `k8s-log`, `k8s-timeline`, `k8s-why` and `k8s-condition` are added to
`contributions::TARGETS` and to both contribution documents. Each is a *target word plus options*
and the package still contributes zero verbs, which is §35.1 and §4 invariant 22 unchanged:

```
get k8s-event     --kind Pod --name api-7d9f-abc
get k8s-evidence  --name node-a
get k8s-log       --name api-7d9f-abc --container api --tail-lines 200
get k8s-timeline  --kind Pod --name api-7d9f-abc
get k8s-why       --kind Pod --name api-7d9f-abc --within-ms 60000
get k8s-condition --kind Deployment --name checkout
```

`why` is the one that looks like a verb and is not: it is a noun this package answers `get` for,
and the alternative — a `why` verb in core — is a Kubernetes-shaped exception in a shell that must
not have one (§0.4). Five of the six take the object they are about as `kind` and `name`, resolved
against the cluster's own discovery exactly as `k8s-resource` and `k8s-relation` resolve one, so a
custom resource's Events, times, conditions and findings are reachable without recompiling
anything (§33.1). `k8s-evidence` names its kind in the table, because the pointers and the
published keys of `evidence.rs` are a Node's and reading a Pod through them would answer an empty
evidence set that renders as a machine with nothing to say rather than as the wrong question.

Each new `Reads` variant is a variant of its own rather than a shared "about one object" case, so
that `query::read`'s match and the handler dispatch in `lib.rs` cannot let a seventh reading fall
through to a wrong one.

### 2. An empty answer that is not evidence of absence ends the invocation

**Where a module's empty case is a statement about the search rather than about the cluster, the
invocation fails with that statement instead of completing with an empty record stream.**

Two targets are in that position, and both for a reason their own module already argues:

- `k8s-event`, where no Event regards the subject. Retention is minutes to hours, delivery is
  best-effort, and the read was never a complete query of anything, so what is not there may have
  been reported and discarded or never reported at all (§38.6, §63.6);
- `k8s-log`, where a retrieval produced no lines. The runtime rotated the log away, or the
  requested tail did not reach back to it, or the process writes to a file (§42.1, §63.6).

This is `ADR-0004`'s rule applied to a second kind of unrepresentable truth. `ADR-0004` failed an
invocation whose *coverage* the value stream had nowhere to carry; this fails one whose
*qualification of emptiness* it has nowhere to carry. The values that did arrive still cross
first, and the refusal names what an empty answer would have meant.

The boundary of the rule matters as much as the rule. An empty answer is a **completion** wherever
emptiness is a fact about the cluster:

- a named object that is not there — §21.4's `absent`, the one outcome that is evidence of
  absence — has no Events, no log, no conditions, no times and no findings, and answers with
  nothing;
- an object whose `status` carries no `conditions` states none, and `k8s-condition` completes;
- a Node with nothing to say still produces a record per unread key, so the case does not arise.

### 3. A time another clock wrote is a string beside a `clock`, never a `timestamp`

No schema added here carries an `eventTime`, a `lastTransitionTime`, a log timestamp prefix or a
temporal `stamp` as a `timestamp` field. Each is a `string`, and each arrives beside a required
`clock` field naming the machine that wrote it — `api-server`, `reported-by/<controller>`,
`node/<name>`, `unattributed`, or `provider`.

A `timestamp` column is one a shell sorts. Sorting five machines' clocks into one column produces
something that reads as a history of the cluster and is a picture of the skew between those
machines, which is exactly §39.2's prohibition arriving through a rendering rather than through
code. The one timestamp field in the six is `k8s-timeline`'s `window_opened` / `window_latest`,
because both ends of that window come from the only clock this machine owns.

`tests/contributions.rs` holds the pairing: every time field named above is declared `string`, and
every schema carrying one declares a `clock` beside it.

### 4. A field name is part of the refusal, and is tested as one

A field whose name implies more than its module allows is a regression even when its value is
right. Three prohibitions are therefore asserted against the *declared schemas* rather than left
to review:

- `k8s-why` carries no `cause`, `caused_by`, `because`, `root_cause`, `explanation`, `effect`,
  `impact`, `trigger` or `responsible`. What it carries is `claim` — one of §40's five words
  verbatim — `claim_means`, which states where the word stops, and `strongest_claim`, which is on
  every record because a reader who filters to one finding must still see the ceiling;
- `k8s-evidence` carries no `match`, `link`, `resolved`, `foreign_id` or `external_id`. It carries
  the value, the pointer it was read at, its `evidence_class`, its `strength` and `lookup_key` —
  and `lookup_key` documents in as many words that it says nothing about whether anything matches
  (§47.1, `ADR-0016`);
- `k8s-condition` carries no `healthy`, `ready`, `converged` or `success`. `observed_generation`
  and `generation` are two plain numbers, and the only derived state is the `reconciliation` map
  whose `verified_convergence` key is false for a matching generation alone (§37.3).

`k8s-event` gets the same treatment structurally: an aggregated Event is **one** record carrying
`recorded_count` and `aggregate`, and there is no field and no route by which 47 becomes 47
records.

### 5. The window and both kinds of hole are on every timeline record

`k8s-timeline` carries `window_opened`, `window_latest`, `continuous`, `gaps` and `not_observed`
on every record rather than on a summary. A stream of observations whose window lives elsewhere is
a stream a reader takes for a complete history, and §19.4's rule about a reader who has to look
for a marker being a reader who will miss it applies here exactly as it does to `k8s-change`.
`gaps` is the stretches observation could not cover; `not_observed` is the scopes that were never
readable, because a continuous window over a denied namespace is not a complete answer.

Everything this route produces is `Basis::Reported`. It opens no watch, and only a watch event
witnesses a change — so a Pod created at 08:00 and first read at 14:00 cannot be filed here as six
hours of history (§39.2, §39.4).

## Consequences

- Twelve sections of the specification stop being "built and unreachable": §37.1, §38, §39, §40,
  §42.1, §42.2, §47.7 and §28.3 to §28.5 now have a route to a user, and §47.7's `MUST` — that
  exported evidence be inspectable — is met at the boundary rather than in a Rust test.
- `get k8s-event` on a healthy object **fails**. This is intended and it is the most arguable
  consequence of this decision: an operator who asks a healthy Pod for its Events sees a refusal
  rather than a quiet nothing. The refusal names §38.6 and is a complete sentence about what was
  and was not established. A shell that wants "no news" as a soft answer can catch it on
  `provider.unavailable`; a pipeline that treated the empty case as "nothing went wrong" cannot be
  written by accident, which is §63.6's whole point.
- The two refusals reuse `provider.unavailable` (`Ono-Sendai-E0401`) rather than a new code. A
  code no registry explains is worse than a slightly wide one, and the KUANG taxonomy has no
  entry for "the answer is empty and its emptiness proves nothing". If core ever publishes one,
  these two call sites change and nothing else does.
- Six schemas and six field-name prohibitions are now promises this package keeps (`ADR-0005`).
  Every declared schema is emitted by a handler, and `tests/contributions.rs` fails if either half
  drifts.
- `k8s-log` deliberately offers no `follow`. A followed log is a live stream with exactly
  `k8s-change`'s shape — emit while the body is open, end when the operator ends it — and offering
  the word without that machinery would answer a followed request by closing at once, which a
  reader takes for a container that just stopped. `LogRequest::following()` exists in the domain
  layer and `logs::answer` never calls it.
- `k8s-why` reads no second object: its dependency-path rung is reachable in `causal.rs` and no
  finding here produces one, because a path needs the traversal `k8s-relation` performs and doing
  it twice would be a second set of rules that could disagree with the first. The
  `DEPENDENCY_PATH_EXISTS` rung therefore does not appear in an answer yet, and the ladder is
  still declared whole because a schema that could not express a rung would be the wrong place to
  record the gap.
- Nothing in the domain layer was changed. Two functions in `query.rs` were generalised —
  `curated` is now `pub(crate)`, and `subject`, `served`, `scope_for`, `hold`, `deliver`, `built`
  and `unnamed` are shared by the new handlers — so that six routes cannot disagree about which
  namespace an object was read in.

## Alternatives considered

**Complete with an empty stream and put the qualification in provenance.** Rejected. Provenance
travels on a record, and the case under discussion is the one with no records. A consumer that has
to notice the absence of provenance is a consumer that will not.

**Emit one "nothing was observed" record of the target's schema.** Rejected for `k8s-event`: a
record of `KubernetesEvent` that is not an Event would have to leave every required field null or
invented, and a schema that can describe both an Event and the absence of one is a schema whose
consumers must check which they have — which is the same forgotten check, moved.

**A second schema per target for the empty case.** Rejected on `ADR-0014`'s reasoning about gaps:
a consumer that has to join two streams to notice something is a consumer that will forget to.

**A `why` verb, or `explain`.** Rejected under §4 invariant 22 and §0.4. §53.6's example spells
evidence inspection as `explain`; this provider answers the same question as a contributed noun,
and a verb would either be a Kubernetes-specific word in this package's grammar or a change to
core's — and core's belongs in an ADR in core.

**Parsing timestamps into instants and marking the clock in a separate column anyway.** Rejected.
The marking would be advisory and the column would be sortable, and the whole point of §39.2 is
that the wrong answer must not be *available*, not that it must be discouraged.

**Expanding an aggregated Event into one record per occurrence, marked as reconstructed.**
Rejected outright. §38.4 is explicit, and a "reconstructed" flag is a field consumers drop.

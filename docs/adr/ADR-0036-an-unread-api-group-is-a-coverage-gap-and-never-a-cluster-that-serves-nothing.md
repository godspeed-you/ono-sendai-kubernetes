# ADR-0036: An unread API group is a coverage gap, and never a cluster that serves nothing

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 13, 16, §9.3, §11.1, §11.5, §21.4, §34.2, §34.3, §35.8, §48.2, §48.6, Appendix D.3; core §3 invariants 5, 11, §4.11, §19.3, §29.4
- Decided by: agent (autonomous)

## Context

`k8s-resource` and `k8s-relation` resolve the kind a query names against the cluster's own
discovery. A query that does not name a `group` therefore reads the resource list of **every
preferred group-version the server lists** — that is what makes a kind nobody compiled in
reachable by name alone (§15.1, §33.1), and what makes §35.8's ambiguity a real possibility.

Until this decision, one of those reads not answering ended the query. `query::document` returned
`Err(provider.unavailable)` for any non-`200` on a discovery path, and `resolve_in`, the
un-grouped catalogue search and `relations::catalogue` propagated it with `?`. So a single
`APIService` answering `503` — `metrics.k8s.io`, a webhook-backed aggregate whose backend is down,
an ordinary Tuesday in a real cluster — made `get k8s-resource --kind Pod`, `get k8s-relation` and
every catalogue query fail, while the core API server answered every request put to it.

That is the situation §34.2 legislates for, in two sentences:

> An unavailable aggregated API group MUST NOT make the entire Kubernetes provider unavailable if
> the core API server remains usable.
>
> Coverage SHOULD report the failed group/version separately.

§4 invariant 16 is the reason it is not a special case — "Aggregated APIs are normal discovered
APIs" — and §48.6 says what the answer may look like: "If an all-resource view spans several GVRs
and one API group is unavailable, successful resources MAY remain visible with explicit incomplete
coverage." The inherited generic contract asks for the same shape twice: §29.4, "If an upstream
API lacks one optional capability, the provider SHOULD degrade that capability rather than
rejecting the whole provider when safe", and §19.3, "The provider MAY emit the valid values and an
explicit gap/partial coverage marker rather than discarding everything. The user MUST be able to
tell that the result is incomplete."

The reason it had not been done is on the board under *Deferred / blocked*, and it is the whole
difficulty of the change:

> That is deliberate — an incomplete search resolving to one candidate is indistinguishable from
> an unambiguous one, and §35.8 is not worth trading for convenience.

§35.8 requires that a name several types share "MUST prompt/require disambiguation rather than
choosing by an arbitrary type priority". A search that skipped a group and found exactly one
candidate has not established that only one type has the name — the second candidate may be
sitting in the group that did not answer. Skipping quietly would convert §35.8's refusal into a
confident wrong answer. §21.4 and §4 invariant 13 say the same thing one level up: "resource type
not served" is one of eight distinct states, and a kind missing from a search that could not read
every group has not been shown to be unserved.

So the requirement is not "continue past the failure". It is **continue past the failure while
saying, in the answer, exactly which part of the search space was not covered** — and never let
any claim be made that only a complete search could support.

## Decision

**1. A group-version's resource list fails soft; `/api` and `/apis` do not.**

`query::group_document` reads one group-version's resource list and returns either the document or
a coverage outcome. A non-`200` becomes an outcome (`403` → `read denied`, `404`/`410` →
`not served`, `502`/`503`/`504` → `unavailable`, anything else → `request failed`), and a document
that does not parse as an `APIResourceList` becomes `request failed` — a fact about that group
rather than about the cluster (§34.3). A **transport** failure remains an error: that is the
connection under every remaining request breaking, not one group declining to answer over a
connection that works.

`/api` and `/apis` keep `query::document` and keep failing the query. They are not one group among
many: they are how the provider learns what is served at all (§11.1), and a cluster that will not
answer them cannot be read. §34.2's isolation is for the groups *behind* them.

**2. The failed group/version is a coverage gap, in a scope dimension of its own.**

`coverage::Outcome` gains a ninth word beside §21.4's eight — `unavailable`, "an API group's own
server did not answer while the core API server did" — because §48.2 keeps `service_unavailable`
apart from a request that merely errored and §34.3 forbids attributing every failure generically
to "the cluster". `coverage::Scope` gains `in_group_version`, the dimension §9.3 already calls a
scope, so `Gap::describe()` renders Appendix D.3's row verbatim:

```text
custom.metrics.k8s.io/v1beta1: unavailable
```

**3. A search carries what it could not read, and the two cannot drift apart.**

`query::search` returns a `Searched` — the assembled `Discovery` and the gaps together. Nothing
can consume the first without holding the second. `Searched::resolve` resolves through
`dynamic::resolve_for` as before and maps the failure through `query::unresolved_over`, which is
weaker than the complete-search refusal by exactly one case: **`NotServed` over an incomplete
search is not `provider.unsupported`.** It becomes `provider.unavailable` naming the group-versions
that were not searched, because the kind may live in precisely the group that did not answer.
Every other refusal survives with the unread groups appended to its help, so an ambiguity refusal
and an un-grouped catalogue both say that the space they describe is partial (§15.5).

**4. An answer over an incomplete search is never a complete answer.**

This is where §35.8 is kept. Three outcomes change on the `k8s-resource` and `k8s-relation`
routes, and all three keep the values:

- a **listing** merges the search gaps into the listing's own coverage, emits every record, and
  ends the invocation as incomplete — the same channel a denied namespace already uses, and the
  message now names both holes;
- a **direct read by name** emits the object and then says the search that chose which resource to
  read it from could not read every group;
- an **absence** (`404` at the object's own endpoint) stops being an absence. `absent` is the one
  outcome in §21.4's vocabulary that is evidence about the cluster rather than about the query, and
  a search that skipped a group has not earned it.

**5. A caller that cannot carry coverage gets the refusal.**

`resolve_in` keeps its signature and now fails when the search was incomplete, with a message that
says why: one candidate found among the groups that answered is not proof that only one type has
this name. A `Resource` has nowhere to record that the search behind it skipped a group, so the
honest thing a `Result<Resource, _>` can return is the refusal. `changes.rs` and `planning.rs`
reach discovery through it and are unchanged in behaviour — a query that names `group` never
fans out and never meets this at all.

## Consequences

- One broken aggregated API server no longer makes the Kubernetes provider unreadable. `get
  k8s-resource --kind Pod` against a cluster whose `metrics.example` group answers `503` delivers
  the Pods and reports `metrics.example/v1beta1: unavailable`
  (`should_answer_from_the_groups_that_answered_when_an_aggregated_group_does_not`).
- §35.8's property survives, and is now checked rather than assumed. A search that found exactly
  one candidate while a group was unreadable does not present itself as unambiguous
  (`should_not_present_a_search_that_could_not_read_every_group_as_unambiguous`), and a kind only
  the failed group could have served does not come back as "not served"
  (`should_not_report_a_kind_only_an_unreadable_group_could_serve_as_not_served`).
- **The user still sees a failed invocation for an incomplete answer**, with the records
  delivered first. That is this package's existing convention for partial coverage — the value
  stream of a contributed target carries records of one schema and has nowhere to put a coverage
  report — and it is unchanged here. What §34.2 asked for and what changed is that the values now
  arrive and the failed group/version is named; §34.2 is about the provider staying usable, not
  about the shape of the report. A contributed target that could emit a coverage record beside its
  values would let this become a complete answer with a coverage row, and that remains open.
- `discovery::Builder::add_resources` exists beside `resources` so that one group's unreadable
  document cannot consume the builder holding the groups that answered.
- Third-party consumers of `coverage::Outcome` see a ninth variant. §21.4's eight are untouched
  and `should_distinguish_the_eight_ways_a_query_can_come_back_without_objects` still holds.

## Alternatives considered

**Skip the unreadable group silently.** The smallest change, and the one the board refused for a
year. It converts §35.8's disambiguation into an arbitrary answer whenever the second candidate
happens to live in the group that is down, and it makes a kind that exists look unserved — §4
invariant 13's failure, dressed as availability. Rejected.

**Keep failing the whole query.** Honest, and what the code did. It is also exactly what §34.2's
first sentence forbids, and it makes the provider's availability the *minimum* of every registered
`APIService` rather than the availability of the API server the operator is talking to.

**Report the gap only when the resolved kind was ambiguous.** Tempting, and unsound: whether the
skipped group would have produced a second candidate is unknowable without reading it. The
condition would have to be evaluated against the very document that did not arrive.

**Fail soft on `/api` and `/apis` too, reporting them as gaps.** This would turn a cluster that
cannot be reached at all into a cheerful short answer with a footnote, which is core §3 invariant
5 — "Permission denial, API failure, scope exclusion and pagination failure MUST NOT be rendered
as an empty successful result". §11.1 makes discovery mandatory; a provider with no discovery has
nothing to be partial about.

**A `partial_result` error code of its own.** §48.2's taxonomy names one, and core's
`docs/contracts/errors.yaml` publishes no code for it. Inventing one here would put a code on the
wire that no registry explains — the reason `UNAVAILABLE_CODE` is spelled out in this package in
the first place. Registering one is a change in core, not here.

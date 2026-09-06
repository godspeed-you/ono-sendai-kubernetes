# ADR-0032: A permission check is a question the API server answers, and only an explicit denial stops a change

- Status: accepted
- Date: 2026-09-06
- Spec refs: §21.1, §21.2, §21.3, §21.4, §21.6, §43.1, §46.2, §61.5, §5.2, §5.3, §11.5, §13.1, Appendix E
- Decided by: agent (autonomous)

## Context

K4 — "bounded safe actions" — lists seven requirements in §61.5 and the first of them is
`authorization preflight support`. Six were met. This one was not, and its absence was recorded
rather than hidden: `plan::Preflight` had three members and nothing anywhere built or sent a
`SelfSubjectAccessReview`, so `should_not_report_permission_as_granted_when_no_preflight_ran` kept
the slot honest and every plan a user could see carried `Caveat::PermissionNotVerified`.

That was truthful and it cost a line of Appendix E. The specification's own worked example of a
prospective change has a block this provider could not produce:

```text
AUTHORIZATION
  patch deployments: allowed (preflight)
  authoritative check occurs on apply
```

§46.2 asks a plan for `permission preflight result` in the same list as `current resourceVersion`
and `known destructive effects`, and §21.6 gives the answer three words:

> Ono MAY hide or de-emphasize actions known to be unauthorized, but `explain` SHOULD state
> whether an action is:
>
> ```text
> allowed by preflight check
> denied by preflight check
> unknown / unchecked
> ```

The permission this rests on is §21.2's, and it is a `MAY` with a warning attached:

> For a specific action, the provider MAY use `SelfSubjectAccessReview` to ask whether the current
> identity can perform the relevant request.
>
> Such a check is advisory for UX and planning. The actual API request remains authoritative
> because authorization can change between check and execution.

And the constraint over all of it is §21.1, one sentence long:

> Ono MUST NOT implement its own RBAC evaluator as a substitute for the Kubernetes authorizer.

Three things made this harder than "send a request and put the boolean on the record".

**A `SelfSubjectAccessReview` is a create.** It is a `POST` to a collection, and `get k8s-plan` is
a read-only target whose test asserted that every request it made was a `GET`. Reads do not mutate
(§43.1); a plan that ran a dry-run `PATCH` was rejected for exactly this reason in ADR-0024,
because a dry run executes admission webhooks.

**The upstream status has two booleans, not one.** `SubjectAccessReviewStatus` carries `allowed`,
`denied`, `reason` and `evaluationError`. `allowed: false` with `denied: false` is not a refusal;
it means no authorizer expressed an opinion. Reading it as a refusal would be this provider
deciding an authorization question the API server declined to decide — §21.1 in the smallest space
it fits into.

**A denied preflight raises a question §21.1 does not settle.** If the check says no, does the
mutation refuse, or does it send the write and let the API server refuse?

## Decision

### 1. The review is resolved through discovery, and a cluster that does not serve it is `not queried`

`authorization.k8s.io` is looked up in the discovery snapshot the plan already built, its preferred
version is whatever the cluster prefers (§5.3), the kind is found by `by_kind` and the collection
comes from the resolved `Gvr` (§13.1: `selfsubjectaccessreviews`, never the kind), and `create` is
checked against the verbs discovery published for it (§11.5). No group, no kind, no `create` verb,
an unreadable resource list, a review the server refused, an unparseable answer — every one is
`Preflight::NotAnswered(reason)`, which is §21.4's `not queried` and §21.6's `unknown / unchecked`.

None of them is a denial and none of them is a grant. A provider that turned "I could not ask" into
"you may not" would have made its own unavailability into an authorization verdict.

### 2. `Preflight` has four members for §21.6's three words

```rust
pub enum Preflight {
    NotChecked,           // nobody asked
    NotAnswered(String),  // asked, no usable answer, and what stopped it
    Allowed,
    Denied(String),       // and the reason the API server gave
}
```

`Display` is §21.6's vocabulary and nothing else — `allowed by preflight check`,
`denied by preflight check: <reason>`, `unknown / unchecked`, `unknown / unchecked: <reason>`. The
reason follows the words rather than replacing them, because §46.2 asks for the *result* and a user
reading a denial needs to know which grant to ask for. A fourth word ("unavailable", "error") would
make a reader decide the safety of a state on their own, so there is none.

`Preflight::from_review` maps `allowed: true` to `Allowed`, `denied: true` to `Denied`, and
**everything else to `NotAnswered`** — including `allowed: false, denied: false` and any
`evaluationError`. The aggregate Kubernetes authorizer defaults to deny, so a no-opinion answer
usually *would* be refused; "usually" is not a word a plan may put where an answer goes.

### 3. Both plans and mutations carry the check, because a mutation is a plan that was carried out

`preflight_for` runs at the end of `plan_on`, which `get k8s-plan`, `set k8s-resource` and
`remove k8s-resource` all share. One path from arguments to a plan means one place the review is
built, and the review asks about the action the plan turned out to describe.

The verb it asks about is the API server's, not this package's. `Action::api_verb` answers `patch`
for an apply and `delete` for a deletion; a review asking about `apply` would be asking about a verb
no Kubernetes authorizer has an opinion on, and would come back unanswered while looking like a
check.

### 4. This is the one write a read-only path makes, and it is written down where it is made

A `SelfSubjectAccessReview` is a create by the REST verb and a question by its semantics: the API
server computes the answer, returns it in `status`, and stores no object. So `get k8s-plan` stays
side-effect free while gaining Appendix E's `AUTHORIZATION` line. That sentence is in
`transport::create_request`'s doc comment, in `planning::preflight_for`'s, in the `planning` module
header, and in the assertion of
`should_answer_what_a_change_would_do_without_making_it`, which now permits exactly one non-`GET`
request and names it.

### 5. Every plan carries an authorization caveat, including an allowed one

§21.2 says the check is advisory. A plan that reported `allowed` and dropped the subject would read
as a guarantee, so `Caveat` gained two members beside the existing `PermissionNotVerified`:

- `PermissionCheckIsAdvisory` — on an allowed plan: *authorization can change between the check and
  the request, and the API server decides on the request itself*;
- `PermissionDeniedByPreflight(reason)` — on a denied plan, naming the reason and stating that the
  API server remains the authority.

`NotChecked` and `NotAnswered` keep `PermissionNotVerified`. Every one of the four states says
something, and the one most easily mistaken for a guarantee is the one that carries a caveat rather
than the one that loses it. `Plan::describe` now opens that with `authorization: …`, which is
Appendix E's block in one line.

### 6. A denied preflight refuses the mutation; a denied preflight is still a plan

`set k8s-resource` and `remove k8s-resource` stop on `Preflight::Denied` **before the write**, with
`contribution.refused` (`Ono-Sendai-K11901`) — this package's own code for its own safety rules —
carrying the reason the API server gave. `get k8s-plan` describes the change exactly as before and
puts `denied by preflight check: <reason>` on the record.

This does not violate §21.1, and the distinction is worth stating precisely. §21.1 forbids an *RBAC
evaluator* as a *substitute* for the Kubernetes authorizer. Nothing here evaluates a rule: the
refusal relays an answer the API server gave seconds earlier, about exactly this verb on exactly
this object, and the refusal code says it is this package refusing rather than the cluster — a
denial code would claim the cluster refused a write it never received.

Four properties make the refusal safe rather than merely convenient:

- **Only an explicit `denied: true` stops anything.** No opinion, no review API, no answer: all go
  to the API server to be decided.
- **Nothing is cached.** The review runs on every invocation, so a grant that lands makes the same
  command work on the next attempt. There is no stale "no" to clear.
- **The plan is still answerable.** A user who is refused can see the change and the reason, which
  is what they need to ask for the right grant.
- **The write would have been refused anyway.** The alternative is a `403` that costs a round trip
  and reads, to a user, exactly like the sentence we already have.

There is deliberately no flag to override it. A `--force`-shaped escape here would be the shortest
path to a write on the day somebody is in a hurry, and it would buy only the case where a webhook
authorizer answers reviews differently from the request path — a cluster misconfiguration this
provider should surface rather than route around.

### 7. §21.3's `SelfSubjectRulesReview` is not implemented, and that is the decision

§21.3 is a `MAY` with a prohibition attached:

> `SelfSubjectRulesReview` MAY be used to improve discoverability of likely available actions within
> a namespace.
>
> Its result MUST NOT be treated as a complete authorization oracle. Upstream explicitly permits
> incomplete rule summaries depending on authorizer behavior.

It is not implemented, for three reasons.

- **There is no surface it would fill.** §21.6's capability UI in this package is one field on one
  record, and that field is answered exactly by a per-action review: the question is always "may I
  do *this*", never "what might I be able to do". A rules summary answers a question nobody asks.
- **Its only plausible use is the one §21.3 forbids.** A summary is worth having to hide or offer
  actions in bulk. Hiding on an incomplete summary hides actions a user is permitted, offering on
  one offers actions they are not, and both are the summary being treated as an oracle. A per-action
  `SelfSubjectAccessReview` at the moment of the question has neither failure mode.
- **It would cost a request per plan for a fact nothing reads.** §50.2 asks for discovery cost to be
  bounded; a second write-shaped request whose result is displayed nowhere is not.

If a future capability UI needs it — an `explain` that lists what could be done in a namespace — it
arrives with that UI, and with the incompleteness on the record beside every entry.

## Consequences

- **K4's seventh requirement is met**, and §61.5 is complete for the first time: authorization
  preflight, prospective plan, server dry run, conflict and precondition handling, asynchronous
  verification, scoped recovery, deletion and finalizer semantics. Whether the level is *claimed*
  is a separate matter tied to the acceptance gates (§0.1).
- **Appendix E's `AUTHORIZATION` block is producible.** Of the two lines the example showed that
  this provider could not, one — `HPA target` — remains, because no HorizontalPodAutoscaler code
  exists.
- **`get k8s-plan` makes one more request, and it is not a `GET`.** A reader auditing the write
  surface of the read path will find a `POST` there. It is `selfsubjectaccessreviews`, it persists
  nothing, and the four places named in §4 above say so. This is the least comfortable consequence
  of the decision and it is the reason it is written down four times.
- **A user can be refused a write by this package rather than by the cluster.** The refusal names
  the API server as its source and the grant as its subject; the plan remains answerable; the check
  re-runs every invocation. The residual risk is a cluster whose authorizer answers reviews
  differently from requests, and in that cluster this package refuses a write that would have been
  accepted. That is a real cost, accepted knowingly, and the mitigation is that only an explicit
  denial has this effect.
- **No new argument and no new schema field.** §21.6's three words are the value of the `preflight`
  field the `k8s-plan` schema already declares — the record needed a better *answer*, not another
  column. `contributions.rs`, `targets.yaml` and `commands.yaml` are untouched, and the two
  declaration tests that guard them stay quiet for the right reason.
- **`package/contributions/schemas.yaml` describes the `preflight` field as defaulting to
  "not checked".** The rendered default is now `unknown / unchecked`; the field's `doc` string is
  stale by one phrase. No test reads it and no contract depends on it. It is left for the owner of
  that document rather than edited from here.
- **`Preflight` gained a fourth member and `Caveat` gained two.** Both are `pub` enums of the
  provider crate; a downstream exhaustive `match` would need a new arm. There is no downstream
  outside this repository.

## Alternatives considered

**Let a denied preflight proceed and have the API server refuse it.** The strictest reading of
§21.1: the check is advisory, so it advises and never decides. Rejected because it makes a user
issue a write to learn something this package already knows, and because "advisory" in §21.2 is
about *authority* — the API server decides — rather than about whether a client may act on the
advice. What §21.1 forbids is a substitute evaluator, and relaying an answer is not evaluating one.
The refusal is scoped to explicit denials and re-checked every invocation precisely so that it never
becomes a cached verdict of this package's own.

**Add an `--ignore-preflight` escape hatch.** Would cover the misconfigured-authorizer case. Rejected
for the reason ADR-0024 rejected a `force` boolean: the shortest path to a green write must not be
flipping a flag, and the case it buys is a cluster defect that should be visible rather than
bypassed. A user who genuinely needs the write can still make it — through any other client, which
is the honest place for "I do not believe this cluster's own answer".

**Model the preflight as `Option<bool>` and derive the words at the boundary.** Smaller type.
Rejected because it collapses `denied: true` and `allowed: false, denied: false` into one `Some(false)`,
which is exactly the conflation §21.1 forbids, and because it leaves the reason — the only part of
the answer a user can act on — with nowhere to live.

**Run the review only on the mutation path and leave `get k8s-plan` a pure read.** Would preserve
the "every request is a `GET`" property. Rejected because §46.2 lists the preflight result as plan
content and Appendix E puts it on the plan: a plan whose authorization line is always
`unknown / unchecked` is the state this ADR exists to end. The `POST` that persists nothing is a
smaller compromise than a plan that cannot answer the question it is asked to answer.

**Add a second field for §21.6's words beside the existing `preflight` field.** Considered so the
raw result and the vocabulary could both appear. Rejected: two fields where one answer exists is two
things to keep in agreement, and the second would have been a projection of the first. The three
words *are* the result.

**Implement `SelfSubjectRulesReview` behind a caveat.** §21.3 permits it and the caveat would be
truthful. Rejected under §4's own test for scope: a summary this provider displays nowhere is code
with no reader, and the first reader it acquires will be tempted to use it as the oracle §21.3
forbids. It arrives with the UI that needs it, or not at all.

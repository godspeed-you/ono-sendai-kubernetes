# ADR-0019: A mutation carries its preconditions or it is refused, and an acceptance is never an outcome

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 4, 5, 13, 18; §16.3, §20.4, §24.4, §37.5, §43, §44, §45, §46, §48.2,
  §54.1, §56, §59.1, §61.5, §62.7 (Gate G), §62.8 (Gate H), §63; generic contract §19.2, §19.4
- Decided by: agent (autonomous)

## Context

This is the first increment in which the provider writes to a cluster, and the
[specification](../architecture/kubernetes-provider.md) asks for more care here than anywhere else.
Four sections were empty (§43, §44, §45, §46) and one was vacuous (§56: nothing mutated, so nothing
had preconditions). Two acceptance gates sit on this tranche, and both describe a *rendering* that
must not happen rather than a feature that must exist:

- **Gate G (§62.7):** a successful Deployment spec update cannot be rendered as a successful
  rollout until verification evidence arrives.
- **Gate H (§62.8):** deletion accepted with finalizers remains terminating, not deleted.

Read together with §4 invariant 18 — a mutation result is not proof the intended outcome occurred —
the shape of the risk is clear, and none of it looks like a bug in review. An accepted `PATCH`
returns `200 OK` with the new spec on the object; rendering that as "rolled out" is one sentence,
and the sentence is *true about the API server*. A `DELETE` that returns `Status: Success` on an
object with a `pvc-protection` finalizer is a deletion that has started and may never finish; the
word "deleted" is right there in the verb. A server-side apply that conflicts with another manager
fails, and the change that makes it stop failing is `force=true`.

The other half is §56, which is written entirely in SHOULDs. `resourceVersion` preconditions
prevent lost updates; UID preconditions stop a stale plan deleting a same-name object that was
recreated in between (§16.3). Both are optional in the sense that a request without them is
well-formed and usually works. They are the difference between a mutation aimed at an object and a
mutation aimed at a name.

## Decision

### Two modules, split on prospective versus actual

`plan.rs` holds §46 and §56: a change described before it is made. `mutation.rs` holds §43, §44 and
§45: the request it becomes, the answer that comes back, and what a later observation establishes.
Verification lives in `mutation.rs` even though it is §46's, because a verdict is made *from a
response and an observation* while a rule is chosen *before either exists* — so `VerificationRule`
is a plan field and `Verdict` is not.

Neither module does I/O, both are pure functions of recorded bytes and injected time, and no
`async` appears in either. Every awkward case §60 lists — an apply conflict, a finalizer deletion,
a recreated object under a planned name — is an ordinary test rather than a cluster somebody has to
break on purpose (§59.1).

### The guarded plan is the short one; the unguarded plan is a sentence somebody wrote

`Plan::of(&Object, action)` derives the `resourceVersion` and UID preconditions from the object that
was read. It is the constructor that takes the fewest arguments and knows the most, so the safe
form is also the convenient one.

`Plan::targeting(target, action)` — a target assembled from a typed name — **refuses**:
`PlanRefusal::MissingPrecondition(ResourceVersion)` for an update (§56.1),
`MissingPrecondition(Uid)` for a deletion (§56.3). The refusal names the missing precondition and
what it would have prevented, rather than saying "invalid".

§43.4 permits an expert escape hatch, so there is one: `Plan::unguarded(target, action, reason)`.
It takes a reason, marks the plan for the rest of its life
(`Caveat::NoPreconditionGuardsTheTarget`), and `is_precondition_guarded()` answers false. **This is
a deliberate strengthening of a SHOULD into a refusal with a named way past it.** A SHOULD that is
enforced only by review is a SHOULD that decays at four in the afternoon, and the failure mode —
a mutation that lands on a different object lifetime — is silent, permanent and indistinguishable
from success in the response.

`Plan::staleness(&Object)` (§56.2) compares the UID **before** the `resourceVersion`, because a
different UID is not a stale plan: it is a plan whose target no longer exists (§16.3). Calling that
staleness would invite the fix staleness gets, which is to re-read and apply. `Staleness::Fresh` is
the only variant that permits an apply; `Unverifiable` does not, because a comparison that could
not be made is not a comparison that passed.

### Reversibility is three questions, and a plan answers all three

§46.5 separates reapplying a previous spec from getting back what the change consumed. So every
`Effect` carries its own `Reversibility`, the plan reports the **weakest** of them, and `Recovery`
is two lists — what reapplying restores and what it does not — instead of a verdict.

A container image change therefore reports `ConfigurationChanged (configuration reapplicable)`,
`PodsReplaced (irreversible)` and `TrafficDisrupted (irreversible)`; the plan's own reversibility is
irreversible, and `Recovery::describe()` says in as many words that this is not a rollback. A
deletion reports `ObjectRemoved (irreversible)` — recreating the name produces a new UID and no
history — plus dependents removed or orphaned by policy, persistent data at risk for the storage
kinds, and external side effects as `Unknown`, which §45.5 and §46.5 both require and which no API
response can settle.

The other §46.2 fields are there and refuse to flatter themselves: `Preflight::NotChecked` is the
default and is not a permission; the dependent preview is owner-reference evidence only (§23.2,
§24.1) with a `Coverage` beside it that starts at `NotQueried`; a deletion says its propagation
policy and that ownership edges are impact evidence rather than an order of removal (§24.4); and
the field managers already on the object are named before the apply rather than at the conflict
(§44.3, §54.1).

### Force is a sentence with a reason in it

`ApplyOptions::new(manager)` does not force and produces a request with no `force` parameter. The
only way to force is `force_conflicts_because(reason)`. There is no `force: bool` anywhere, because
the shortest path to a green apply must not be flipping a flag (§44.3, §44.4).

A `409` carrying `FieldManagerConflict` causes becomes a `Conflict` that keeps the owning manager
and the field path, `Conflict::is_automatically_resolvable()` is false, and `Resolution` has exactly
one member: `ExplicitChoiceRequired`. A resolution enum with a `Force` member would put the
forbidden answer one match arm away from being taken automatically.

A `409` that carries no such causes is classified from the message — the API server offers no
structured discriminator between "somebody wrote first" and "your UID precondition failed" — and a
`409` matching neither phrase is **not** called a precondition failure. An unrecognised refusal
reported as a recognised one is worse than one reported as unknown.

### An acceptance reaches one rung of the ladder and no further

`MutationOutcome::established_stage()` returns `Some(Stage::ApiAccepted)` for a persisted write and
`None` for everything else, including a successful dry run — nothing was written, so not even the
first claim holds (§44.5). There is no method on `MutationOutcome` that says converged, rolled out
or healthy. `condition.rs`'s existing ladder is reused rather than reimplemented, so Gate G is held
by the same `Stage` and `Reconciliation` types that already hold §20.4 and §37.5.

`Verification::of(plan, observation, deadline, now)` answers with a four-member `Verdict`, and the
fourth is the one §46.4 insists on. `Inconclusive` is not a failure and not a success: both
`is_success()` and `is_failure()` are false, and `describe()` says "verification incomplete… not
evidence that the change failed, and not evidence that it succeeded". A verification whose target
could not be read (`Observation::Unobservable(Outcome::ReadDenied)`) is inconclusive whatever the
clock says, because §21.4's distinction between denial and absence does not stop applying once a
mutation is involved.

### Deletion has states, not a boolean

`DeletionState` is `Accepted` / `Terminating { finalizers, since }` / `Absent`, and there is
deliberately **no method called `is_deleted`**. `is_object_absent()` answers what this provider can
observe — the object being gone from the API — and only a read that established absence advances
the state. `Deletion::observe_absence(Outcome)` accepts only `Outcome::Absent`; a `403` on the
follow-up read is recorded as a note and leaves the state where it was, because reading a
permission boundary as a completed deletion is §4 invariant 13 lost where it costs the most.
`describe()` always ends by saying that effects outside the API server are unknown either way.

### Nothing is wired to a user

Neither module is imported by `ono-kubernetes-plugin`, no target performs a mutation, and no route
reaches one. **K4 reaching a user is a separate decision that needs its own risk classification and
host capability**, and it is not taken here: this increment builds the shape and the refusals while
getting them wrong is still cheap. `budget.rs` is also untouched, so `Idempotent` still has exactly
three constructors and no mutation can be automatically retried — the fourth constructor that
`ADR-0017` describes has deliberately not been added.

## Consequences

- §43, §44, §45, §46 and §56 have code and tests for the first time; §61.5's seven K4 requirements
  are addressed in the library except the authorization preflight *call*, which is a plan field
  (`Preflight`) with no `SelfSubjectAccessReview` behind it yet.
- Gate G and Gate H have executable tests. `should_not_report_an_accepted_deployment_update_as_a_completed_rollout`
  and `should_report_a_deletion_with_a_finalizer_as_terminating_rather_than_deleted` are the two
  that would fail first if either invariant were softened.
- **`plan.rs` and `mutation.rs` join the modules `docs/coverage.md` counts as built and
  unreachable.** That is the honest entry, and for this tranche it is also the safe one.
- An apply document is built from JSON pointers, and a pointer that indexes into a list is
  **refused** unless the change also sets that entry's `name` (`MutationError::UnkeyedListEntry`).
  Server-side apply merges list entries by key rather than by position, so an index without its key
  would merge against whichever entry the server chose. This covers `name`-keyed lists —
  containers, volumes, env — and refuses everything else rather than guessing a merge key.
- `Deletion::read` returns `Result<Self, Box<MutationOutcome>>`. The refusal is the interesting case
  for §56.3 and it is larger than the success, so it is boxed.
- The dependent preview needs a lister that does not exist yet, so in practice a delete plan carries
  `Caveat::DependentPreviewIncomplete` until a caller supplies one. That is the true state of the
  evidence, and it is better than a preview that looks complete because nobody looked.

## Alternatives considered

**Preconditions as optional fields with a warning.** The obvious design: build the plan, attach a
warning where a precondition is missing, let the caller decide. Rejected because the warning is
carried by the value that is easiest to ignore, and because it makes the unguarded mutation the
shorter sentence to write. The current shape inverts that: the guarded plan takes one argument and
the unguarded one takes a reason.

**One `Mutation` module rather than two.** Fewer files, and the plan and the request would sit
beside each other. Rejected because it hides the property that matters: a plan is a value that can
exist, be shown and be argued with while nothing has happened, and a module that also holds the
request builder invites a `Plan::execute` that closes the gap.

**A `reversible: bool` on the plan.** Every reviewer asks for it. It is exactly the claim §46.5
forbids, and whichever way it defaulted would be wrong: `true` promises a rollback that does not
exist, `false` makes the field useless. Two lists and a weakest-effect answer say more and promise
less.

**Automatic retry with `force` after a conflict, behind a confirmation.** Rejected on §44.3, which
does not qualify: Ono MUST NOT automatically force ownership merely to make the action succeed. A
confirmation prompt is still automatic from the code's point of view — the decision has already
been shaped as "yes or no" rather than "who should own this field".

**Verification with three verdicts (confirmed, refuted, pending).** Simpler, and it is what most
tooling does. It has no answer for a deadline that passed without decisive evidence, so that case
lands in one of the other three — "refuted" blames a change that may have worked, "pending" waits
forever, "confirmed" is unthinkable. §46.4 names the fourth answer explicitly, so it is a variant.

**`is_deleted()` on `Deletion`, defined as "absent".** Convenient for a renderer and one refactor
away from being true of `Accepted` as well. The method is named for what was observed instead, and
the type has no vocabulary for a claim about the volume behind the claim.

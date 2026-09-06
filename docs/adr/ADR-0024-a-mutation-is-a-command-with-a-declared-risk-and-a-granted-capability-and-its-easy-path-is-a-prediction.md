# ADR-0024: A mutation is a command with a declared risk and a granted capability, and its easy path is a prediction

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 13, 18, 22; §11.5, §16.1, §16.3, §21.4, §22, §35.1, §37.5, §43.3, §43.4,
  §44, §45, §46, §51.2, §56, §61.5 (K4), §62.7 (Gate G), §62.8 (Gate H); generic contract §18.4,
  §21.1–§21.6, §22, §27.2, §27.6; core spec §31.5, §31.16–§31.19, §31.22, §31.23, §31.68, §31.75
- Decided by: agent (autonomous)
- Supersedes nothing; completes the deferral recorded in ADR-0019 ("Nothing is wired to a user")

## Context

[ADR-0019](ADR-0019-a-mutation-carries-its-preconditions-or-it-is-refused-and-an-acceptance-is-never-an-outcome.md)
built `plan.rs` and `mutation.rs` and deliberately wired neither to anything, saying that reaching
a user "needs its own risk classification and host capability, and it is not taken here". This is
that decision. It is the first increment in which a user's own sentence writes to a cluster.

Four questions had to be answered at once, and each of them has a wrong answer that looks fine in
review.

**Which word.** `get` is a read verb (§4 invariant 22, generic contract §21.2), and this package's
whole contribution surface until now has been targets — nouns that `provider.query` answers. The
easy thing is another target: `get k8s-apply --set ...` needs no new machinery at all.

**Under which grant.** The manifest declares five capabilities and none of them is about writing.
The KUANG/11 model has twenty-nine families and a package may not invent a thirtieth — an unknown
id makes the manifest `package.invalid` at load, so this is a closed vocabulary rather than a
convention.

**What the default does.** §44.5 asks for a server-side dry run as the mutation preview. A dry run
that has to be asked for is a dry run nobody uses at four in the afternoon.

**What the answer says.** Gate G and Gate H are both about a *rendering* that must not happen, and
the record this package emits is the rendering.

## Decision

### The mutation is a command; the plan is a target

Two contributions, and the split follows from what the two wire shapes can carry.

A `TargetContribution` is a name, a schema, a summary and an identity note. It has nowhere to
state a risk and nowhere to state a capability, because everything a target answers is a read. A
`CommandContribution` states both, and — this is the part that made the decision — the supervisor
checks the declared capabilities **at every invocation, against the plugin's grants, before the
package's code is reached at all**. So:

- `get k8s-plan` is a **target**. Building a plan is read-only: discovery, one `GET` of the object
  the change is aimed at, and this provider's own rules. It is safe to point at anything.
- `set k8s-resource` and `remove k8s-resource` are **commands**, with `risk: mutate` and
  `risk: destructive`, and `capabilities: [network.connect]`.

The verbs are core's own (`docs/contracts/verbs.yaml`): `set` is "modify properties or
configuration" and `remove` is "delete a resource or a membership", which are §43.3's bounded
field change and its deletion exactly. §31.22 asks a package to reuse an existing verb wherever
the semantics allow, and here they do; a `k8s-apply` would have been the first word of the
Kubernetes mini-shell §35.1 forbids. The noun is `k8s-resource`, the one `get` already reads, so
one word is read by one verb and written by another.

`destructive` rather than `mutate` for the deletion is not decoration: §45.1 and §45.5 are a list
of the ways a deletion reaches things this provider cannot get back, and core's `risk_levels`
defines `destructive` as "may cause irreversible loss". The host applies its own confirmation
policy to that descriptor (generic contract §21.5); this package prompts for nothing of its own.

### A mutation is prevented from being reachable by accident four times over

1. **It is not a `get`.** `provider.query` resolves against contributed targets, and neither
   command is one — `plugin.query(SET, ...)` is `resolve.target_not_found` before any byte moves.
2. **It needs a grant.** The host checks `network.connect` at invocation; without it the
   invocation fails with `capability.denied` and the recorded cluster sees no request at all.
3. **Its default writes nothing.** `dry_run` defaults to **true**, so the shortest sentence a user
   can write asks the API server to run admission and defaulting and persist nothing.
4. **Its preconditions are not typeable.** There is no `resource_version` and no `uid` argument.
   The only source is the object that was read, so §56 travels rather than being described, and a
   target that cannot supply one is refused by `Plan::of` rather than sent.

There is also no `force` flag anywhere. `force_because` takes the sentence a reviewer will read.

### The dry run is the default, and it is labelled as a prediction

`set k8s-resource --kind Deployment --name api --set '{"/spec/replicas": 2}'` sends
`PATCH …?dryRun=All`. The record says `dry_run: true`, `acceptance: "dry run"`, `stage: null` —
nothing was written, so not even the first rung of §20.4's ladder holds — and `prediction`
carries the label generic contract §21.4 requires: **provider-native dry run**, which "predicts
API acceptance, not what controllers do afterwards". The plan record carries the other label,
**static provider metadata**, because a plan is derived from one read and this provider's rules
and is a much weaker claim than a dry run's.

Writing is `dry_run false`. That is one argument, and it is the only place in the design where the
user is asked to be explicit about which of the two they meant.

**The plan target does not dry-run.** A dry-run `PATCH` is a write-shaped request that runs
admission webhooks, and a word a user may point at anything must not do that. The plan says so —
`Caveat::AdmissionEffectsNotPreviewed` — rather than leaving the omission to be inferred.

### An acceptance is kept from reading as an outcome by what the schema does not have

The mutation schema has `acceptance` (what the API server did with the request), `stage` (how far
up §20.4's ladder that reaches: `ApiAccepted` for a write, null for a dry run or a refusal), and
`verdict` (what one later observation established). It has no `succeeded`, no `rolled_out`, no
`healthy` — and `tests/contributions.rs` fails if one is ever added.

After a persisted write, the handler looks at the target **once, immediately**, with a deadline of
`Duration::ZERO`. That is a decision rather than a placeholder: this invocation is not waiting for
anything, so evidence that is not decisive at that moment never became decisive within the window
there was, which §46.4 calls `Inconclusive` — "not evidence that the change failed, and not
evidence that it succeeded". Reporting it as `Pending` would promise a second look nobody is going
to take. For the Deployment of Gate G the follow-up read shows `generation` ahead of
`observedGeneration`, so the record says `stage: API accepted desired-state change`,
`verdict: inconclusive`, and a `reconciliation` map carrying the rule and the fields it read.

For a deletion the same look feeds `Deletion::observe` / `observe_absence`, and only
`Outcome::Absent` advances the state — a `403` on the follow-up read is recorded as a note and
leaves the state where it was. A finalizer-held claim therefore reports
`terminating; deletion is pending` with its finalizers beside it, and the word "deleted" is not
something `DeletionState` can produce (Gate H).

### A plan is keyed on four things, because it is not an object

`uid`, `resource_version`, `action`, `changes`. One object may have several prospective changes
aimed at it, so `uid` alone would collapse a scale-down and an image change into one record. The
`resource_version` component is the *precondition* — the point in the object's continuity the
change is aimed at — never what came back. A mutation record shares the key, and the argument is
§56.1's own: a write **consumes** its precondition, so a second attempt asserting the same token
is refused by the API server rather than being a second record under the same key.

## Findings about core, which are the part of this worth more than the code

### 1. There is no capability family for "change state in the external system a provider fronts"

The commands declare `network.connect`, and that is the only honest choice available.

Everything these commands do to a cluster travels as bytes through the network broker, whose scope
— `hosts` and `ports` — is the operator's decision about which cluster this package may reach at
all (§51.2, generic contract §27.2). It is enforced, it is true, and it is the capability the work
actually consumes. What it cannot do is separate a read from a write: the broker sees a byte
stream, not an HTTP request, so one grant covers `GET` and `PATCH` alike. **An operator who grants
this package the ability to read a cluster has, in the same act, granted it the ability to write to
one.** The `risk` descriptor and the dry-run default are what stand in the gap, and neither is a
security boundary.

The two families whose names come closest belong to other domains, and their scope keys say so:
`service.mutate` is scoped to `units` (service-manager units) and `remote.mutate` to `links` (Ono
remote-execution links, core §31.40, where the far side is another Ono enforcing its own policy).
Claiming either would put a scope on an operator's grant screen that nothing checks, which
§31.16 forbids in as many words: "A scope that cannot be enforced reliably MUST NOT be offered as
if it were a security boundary." Inventing a thirtieth family is not open either — an unknown
capability id makes the manifest `package.invalid`.

What is missing is a family in the shape of `provider.mutate`, scoped by provider instance and
resource class, whose scope the *package* declares at the call site and the broker checks the way
it checks `filesystem.read`'s paths. That needs a host call for a provider mutation to be checked
against, which is the second finding.

### 2. The KUANG/11 provider role has one method, and it is a read

`protocol.v1.yaml` gives the provider role `provider.query` and nothing else. A mutating provider
action must therefore be delivered as `command.invoke`, which is why the risk and the capability
live on a command contribution and not on a target one. That is a coherent design and this ADR
works with it rather than around it — but it means a provider mutation is, from the host's point
of view, an opaque command rather than a typed operation on a target. Generic contract §21.1 asks
an action to declare "accepted target type(s)", a "parameter schema" and "known idempotency
semantics", and a `CommandContribution` has fields for none of the three: `target` is one string,
and the options a command takes are documentation.

### 3. A contributed command cannot declare its options, so they are prose

`CommandContribution` carries `id`, `verb`, `target`, `summary`, `input`, `output`,
`capabilities`, `argument_mode`, `risk` and `examples`. Core's own command contracts
(`docs/contracts/commands/*.yaml`) additionally carry `selectors` and `options`, and
`contributions.v1.yaml` says a contributed command uses "the same metadata schema core commands
use" — but the wire type does not carry them and is `deny_unknown_fields`. So `dry_run`,
`set`, `unset`, `force_because` and `propagation` are documented in
`package/contributions/commands.yaml` and in each summary, and a shell can complete none of them.
This is the same gap `contributions/targets.yaml` already records for targets; it is worse for a
command, because `dry_run` is the argument that decides whether a cluster changes.

### 4. The error registry has no code for a refusal by a provider's own safety rule

A plan refused for a missing precondition is reported as `safety.policy_denied`
(`Ono-Sendai-E0702`). The `kind` is right — "a safety policy or confirmation requirement stopped
the operation" — but the summary says *configured* policy, and nothing was configured: the rule is
this provider's, from ADR-0019. The two nearer-looking codes are worse. `provider.unsupported`
says the provider cannot do the thing, which is false: it can, and it declines.
`provider.unavailable` says the cluster did not answer, and it did.

### 5. `audit.event` has no observable channel in the test host

Generic contract §27.6 asks a security-sensitive provider operation to emit an audit record
carrying the package, the instance, the action category, the scope, the capability used, the
target identity and the result. The host call exists (`audit.event`), needs no capability, and the
supervisor stores what it receives in `Shared::plugin_events` — which has no public accessor, so a
test cannot assert that the record was emitted or what it contained. Under this repository's "no
test, no code" rule the emission is therefore **not implemented**, and this is the reason.

## Consequences

- §61.5's K4 is reachable by a user for the first time: a prospective plan, a server dry run, a
  bounded write, conflict and precondition handling, deletion and finalizer semantics, a scoped
  recovery statement, and a verification that is asynchronous in the sense that matters (it is
  made from a *later observation* rather than from the write's own response). The one K4
  requirement still unreached is the **authorization preflight call**: `Preflight` is a plan field
  and there is still no `SelfSubjectAccessReview` behind it, so every plan carries
  `Caveat::PermissionNotVerified` and the API server remains the only authority (§21.1, generic
  contract §18.4).
- `plan.rs` and `mutation.rs` leave the "built and unreachable" list in `docs/coverage.md`. That
  file is another agent's this session and is not edited here.
- Gate G and Gate H now have end-to-end tests against the real binary, not only library ones:
  `should_not_report_an_accepted_deployment_update_as_a_completed_rollout` and
  `should_report_a_deletion_with_a_finalizer_as_terminating_rather_than_deleted`.
- `mutation.rs` gained one function and changed no behaviour: `admission_differences_of` takes the
  returned object as an argument, so the boundary can pass a `redaction::Guarded` one. Comparing
  against `MutationOutcome::returned` directly would report an admission-rewritten Secret payload
  verbatim, which is the one way a mutation could disclose what a read may not (§22, Gate I).
- A change to a list entry still needs its merge key: `apply_document` refuses
  `/spec/template/spec/containers/0/image` unless the change also sets that entry's `name`. That
  reaches a user now, as a refusal naming the change rather than a merge against whichever entry
  the server chose (§44.1).
- Two schemas are contributed that no target answers for, which is new for this package. The
  contributions test now matches schemas by id rather than by position, because two documents
  grown at their ends cannot promise an order.

## Alternatives considered

**The plan as a `explain k8s-resource` command rather than a `k8s-plan` target.** `explain` is
core's verb for "show the resolution and plan without executing" and it is not mutating, so the
semantics fit. Rejected because a command's output is a stream a user consumes and a target's
output is a *noun a user can ask for, filter, sort and keep* — and §46's whole model is that a
plan is a value that can exist, be shown and be argued with while nothing has happened. Making it
a target is what lets `get k8s-plan ... | where reversibility == "irreversible"` be a sentence.

**`remote.mutate` as the capability.** It is the only family whose summary is "perform mutations
across a remote system", and it would give the operator a *separate* switch for writing, which
`network.connect` does not. Rejected on its scope key: `links` names Ono remote-execution links
(§31.40), a Kubernetes API server is not one, and a grant scoped `links: ["kubernetes:prod"]`
would be checked against nothing because this package makes no host call under that family. A
switch that is real but named after the wrong thing, carrying a scope that is never evaluated, is
worse than an honest report that the switch does not exist.

**A `force: bool` argument.** Every reviewer asks for it, and `ApplyOptions` already refuses to
offer it. Rejected for the reason ADR-0019 gives: the shortest path to a green apply must not be
flipping a flag. `force_because` costs a sentence, and the sentence is the artefact §44.4 wants.

**`dry_run` defaulting to false, with the dry run behind an argument.** The conventional shape,
and what `kubectl` does. Rejected because §44.5 asks for the dry run to be the mutation *preview*,
and a preview that must be asked for is a preview that is skipped exactly when it matters. The
cost is real and is accepted: a user who means to write types four more characters, and every
example in `commands.yaml` shows both spellings so the difference is visible before the first use.

**Verifying from the write's own response.** The API server returns the mutated object on a
successful apply, so a verification could be run against it with no extra request. Rejected
because it is the Gate G trap in its purest form: the returned object carries the new spec by
construction, so a `FieldObserved` rule would report `Confirmed` for every accepted write, and
"the field is set" would have become "it worked" through a saving of one round trip.

**Reporting a single immediate observation as `Pending`.** Gentler, and it is what a reader
expects from a verification that has just started. Rejected because nothing is going to look
again: this invocation ends, and `Pending` would describe a wait that is not happening. §46.4
provides the fourth answer precisely so that "we looked and could not tell" does not have to
borrow one of the other three.

**Emitting the plan and the outcome as two records from the mutating command.** Tempting, because
a user who writes without planning first would then see both. Rejected because the two carry
different schemas and a command declares one output type — and because the honest fix is the
other direction: the plan is a word of its own, and `get k8s-plan` is the sentence to write first.

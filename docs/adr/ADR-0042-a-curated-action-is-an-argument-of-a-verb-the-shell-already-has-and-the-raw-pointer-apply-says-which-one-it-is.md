# ADR-0042: A curated action is an argument of a verb the shell already has, and the raw pointer apply says which one it is

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 13, 18, 22, §11.1, §13.4, §14.3, §14.5, §14.7, §18.1, §18.4, §21.4, §23.4, §24.3, §33.5, §33.6, §33.8, §35.1, §43.3, §43.4, §44.1, §45.4, §45.5, §46.1, §46.2, §46.3, §50.2, §52, §54.1, §54.2, §54.3, §55.2, §55.4, §62.7
- Decided by: agent (autonomous)

## Context

The mutation surface met every `MUST` it was measured against and four `SHOULD`s of the same
sections were unmet. They are one decision each, and three of them share a root cause: the
provider had exactly two shapes of change — a JSON-pointer apply and a delete — and *everything*
was expressed through them, including the things §43.3 asks to be expressed as themselves.

**§43.3 lists seven candidate bounded actions.** Scale a workload, restart a rollout through an
explicit supported mechanism, set an image, apply a bounded field change, delete, annotate/label,
cordon/uncordon a node. Every one of them reduces to the bounded field change that already
existed — scaling is `/spec/replicas`, cordoning is `/spec/unschedulable`, a rollout restart is an
annotation on the pod template. Reducing them is not the same as offering them. The question §43.3
actually poses is whether a user has to know the pointer, and §52 poses the same question again as
discoverability: an action surface nobody can find is not a bounded action surface.

**§43.4 says the raw escape hatch "MUST be explicitly low-level" and "MUST NOT become the default
UX simply because it is easy to implement".** The JSON-pointer apply was simultaneously §43.3's
bounded change and the only apply there was, and nothing in the summary, the help line, the plan or
the record said which of the two a reader was looking at. Planning and confirmation integration —
the other two clauses of §43.4 — were already met.

**§33.6 asks a provider to preserve desired/observed semantics *and* mutation boundaries.** The
read half was met: `schema.rs` keeps `Intent::Desired` and `Intent::Observed` apart. The mutation
half was absent. `--set '{"/status/phase": "Running"}'` was assembled into the object document like
any other field, sent to the object endpoint, and neither routed to `/status` nor refused.

**§54.1 lists five sources of competing desired-state writers and §54.2 asks for a warning.**
`grep HorizontalPodAutoscaler crates/` was empty. One source existed — `Caveat::OtherFieldManagers`
from `managedFields` — and a plan that scaled a Deployment an HPA governs said nothing about the
autoscaler that would write the count back. §54.2's `MUST NOT` half already held, through
`Verdict::Inconclusive` and Gate G.

**§55.2 says deleting a Namespace "MUST receive enhanced prospective analysis" and lists six
things the plan should contain.** A Namespace deletion plan was indistinguishable from a
ConfigMap's but for two generic flags: `runs_workload` and `storage_bearing` both happen to be
true of `Namespace`.

## Decision

### 1. §43.3's seven actions are arguments of `set`, and there is still no third command

`Action` gains a third member, `Action::Curated(Curated, Vec<FieldChange>)`, beside the raw
`Apply` and the `Delete`. `Curated` has seven members and they are §43.3's list:

```
Scale  SetImage  RestartRollout  Cordon  Uncordon  Label  Annotate
```

A user reaches them as **named arguments of `set k8s-resource`**, the command that already exists:

```
set k8s-resource --kind Deployment --name api --replicas 2
set k8s-resource --kind Deployment --name api --image web=registry.example/web:1.4.0
set k8s-resource --kind Deployment --name api --restart_rollout true
set k8s-resource --kind Node       --name node-7 --schedulable false
set k8s-resource --kind Deployment --name api --label tier=edge
set k8s-resource --kind Deployment --name api --annotation owner=payments
remove k8s-resource --kind ConfigMap --name stale
```

**This is the whole of how it avoids a mini-shell.** The package contributes the same two commands
it contributed before, on the same two core verbs, `set` and `remove` — zero new words in the
shell's grammar (§4 invariant 22, §35.1, §31.22). `restart`, `enable` and `disable` are in core's
`docs/contracts/verbs.yaml` and a `restart k8s-resource` / `disable k8s-node` pair was the obvious
alternative; it is rejected below. Each curated action is discoverable in `help set k8s-resource`,
each has a completion candidate and a one-line doc, and the invocation is shorter than the pointer
form it replaces — which is what §52 is asking for.

**Exactly one curated action per invocation.** §46.3 gives one verification rule per action and
§46.2 one set of effects, so a plan carrying two transitions would have a rule belonging to one of
them and effects belonging to both. `--replicas 2 --restart_rollout true` is a refusal that names
both arguments.

**Each action carries what §46.2 asks, and the verification rules are four rather than one.**
`VerificationRule` gains three members, taken from §46.3's own worked examples:

| action | rule | reads |
|---|---|---|
| scale | `ControllerConvergence` | generation advanced, controller observed it, replicas satisfy policy |
| set image, restart rollout | `RolloutObserved` | pod template changed, new ReplicaSet observed, new pods ready, old one scales down |
| cordon, uncordon | `SchedulabilityObserved` | `spec.unschedulable` holds the requested value — and nothing about the pods already there |
| label, annotate | `MetadataObserved` | the keys are read back — and nothing about what selects on them |
| raw pointer apply | `FieldObserved` | the requested fields are read back |

`EffectKind` gains `SchedulingStopped` and `SchedulingRestored` for the same reason: `unschedulable:
true` reads as an ordinary boolean and what it does is take a node out of scheduling *without
moving anything already on it*, which a field list cannot show and an operator who confuses cordon
with drain very much needs.

**Two mechanisms are decided here rather than left to a caller.**

*Set image names the container.* `--image web=…` is resolved against the object's own container
list to an index, and the change carries `containers/N/name` beside `containers/N/image` because
§44.1 merges list entries by key rather than by position. A container name that matches nothing is
a refusal that lists the containers there are, rather than an apply document that adds one.

*A rollout restart is a pod-template annotation whose value is the `resourceVersion` the restart
was planned against.* `ono-sendai.io/restarted-from-resource-version: "4711"`. Changing the pod
template is §43.3's "explicit supported mechanism" — it is what makes a controller roll, and the
API server and the controller both already understand it; deleting pods would be a second
mechanism this provider invented, with no plan and no verification rule behind it. The *value* is
the object's `resourceVersion` rather than a wall-clock timestamp because this module has no clock
and should not acquire one for a marker: the token is opaque, is used as an opaque token and never
as a time or a sort key (§14.3), it changes on every write so a second restart is a second change,
and it records *which observation* the restart was made from, which a timestamp does not.

**The scale subresource (§33.5) is deliberately not used.** `schema.rs`'s `has_scale` is discovered
and still has no caller. Scaling goes through `/spec/replicas` on the object, as a server-side
apply, because §44.1's field ownership is the property this provider's whole mutation surface rests
on: `/scale` is a `PUT` of a different object and does not participate in the ownership tracking
that makes `Caveat::OtherFieldManagers` and §44.3's conflicts mean anything. A `Scale` written
through the subresource would be a change no `fieldManager` owned.

### 2. The raw apply says it is the escape hatch, in all four places a user meets it

`Action::is_low_level()` is true for `Apply` and false for `Curated` and `Delete` — a deletion is
one of §43.3's own candidate actions and says exactly what it does; what is low-level is a field
list aimed by pointer at a schema the caller is expected to know. From it:

- **`Caveat::LowLevelChange`** on every raw-apply plan, naming the curated transitions to prefer.
  It reaches both records — the plan's `caveats` and the mutation's — and `Plan::describe`;
- **the command summary** now leads with the curated actions and calls `--set`/`--unset` the
  low-level escape hatch, in `contributions.rs` and `package/contributions/commands.yaml`;
- **the option help lines** for `set` and `unset` open with `LOW-LEVEL EXPERT PATH (specification
  section 43.4)`, which is what `help` and completion show;
- **`Action::Display`** renders it as `apply N low-level field change(s) named by JSON pointer
  (§43.4)`.

### 3. A write to `/status` is refused, not routed

**Refused.** `check_pointer` in `planning.rs` refuses `/status` and anything under it before
discovery and before any request; `mutation.rs::apply_document` refuses it again as the library
backstop, with `MutationError::ObservedStateNotWritable`.

The reasoning is that both alternatives are worse and one of them is worse quietly. Sent to the
**object endpoint**, a status field is dropped by the API server wherever the subresource is
served, and the request still answers `200` — a change that reports success for having done
nothing, which is the failure mode this repository exists to make impossible. Sent to the
**subresource**, it succeeds, and Ono has written observed state: a value whose entire meaning is
"what a controller reports having seen" now says what somebody typed. That is the desired/observed
collapse Gate G (§62.7) is about, arriving through the write path instead of the read path. §33.6
asks for the *boundary* to be preserved, and a boundary a provider crosses on request is not one.

The refusal is uniform rather than conditional on discovery reporting a `status` subresource. Where
the subresource exists the write is out of bounds; where it does not, `status` is still a
controller's report and writing it is still Ono answering "what did the controller observe" with
"what somebody typed". Making the refusal conditional would mean the same sentence is refused on a
Deployment and accepted on a CRD that has not declared its subresource yet — a difference in
Ono's honesty produced by a CRD author's omission. The boundary is the `status` tree and nothing
wider: `/spec/statusPage` and a CRD field called `statusCheck` are ordinary desired state and are
untouched.

Reading observed state is unaffected and is where the answer belongs: `get k8s-resource` and
`k8s-condition` already keep desired and observed apart (§37).

### 4. §54.1's sources are one list with a coverage, and §54.2's warning is derived from the change

`CompetingWriter` carries a name, the source that named it (`WriterEvidence`), what it writes and a
detail. Three of §54.1's five sources produce one:

- **`managedFields`** — every manager the object already records, which was previously only a
  caveat and is now in the same list as the rest;
- **owner references** — the *controller* owner only (§24.3): a ReplicaSet's Deployment writes its
  spec back, and a non-controller owner is ownership for garbage collection;
- **HPA targets** — a `HorizontalPodAutoscaler` whose `spec.scaleTargetRef` names this object by
  kind, group *and* name in the same namespace. Matching on less would make every autoscaler in a
  busy namespace a warning, and a warning that fires on everything is read as noise.

**What the warning says**, when a change writes `/spec/replicas` on a workload an HPA governs:

> a HorizontalPodAutoscaler named `api` targets this workload and writes `/spec/replicas` itself.
> A direct replica change may be reconciled back within the autoscaler's next interval, and the API
> server accepting `spec.replicas` is not evidence of a durable effect (§54.2)

and the writer entry beside it adds `it keeps the count between 2 and 10`. The caveat is derived
from the field the change touches rather than pushed by whoever ran the search, so it cannot be
attached to a change that does not write the count.

**The autoscaler search runs only for a change that writes `/spec/replicas`** (§54.2 is about a
*direct replica change*), and it costs at most one resource-list read and one list page. Every way
it can come up empty — no `autoscaling` group served, a resource list that would not read, a
listing the authorizer refused — is a coverage gap and `Caveat::CompetingWriterEvidenceIncomplete`,
because an empty list from a group that would not answer is not an absence of autoscalers (§21.4,
§4 invariant 13). A plan where nobody looked carries the same caveat.

§54.3's GitOps evidence is **not** implemented. It is a `MAY` conditioned on curated adapters, and
the adapter registry §33.8 describes does not exist in this package yet; inventing an annotation
allow-list here would be the curated knowledge §33.8 says belongs in an adapter.

### 5. A Namespace deletion enumerates what it would remove, and says what it could not list

For a destructive plan whose target is a `Namespace`, `plan_on` enumerates the preferred version of
every group the cluster serves, lists every namespaced collection in that namespace, and attaches
`Contained` counts by GVR plus the coverage of the enumeration. §55.2's six bullets:

| bullet | where it is |
|---|---|
| contained resource counts by GVR | `contained`, a `list<map>` of `{gvr, count, at_least}` |
| resource types that could not be listed | `contained_coverage` plus `Caveat::ContainedInventoryIncomplete` |
| namespace finalizers | `Caveat::FinalizersMustBeRemoved`, which already existed |
| known PVC/PV implications | `Caveat::NamespaceHoldsPersistentVolumeClaims(n)`, named rather than left as one more count |
| admission/authorization state | the `preflight` field every plan carries (§21.2, §46.2) |
| external side effects may outlive it | `Caveat::ExternalEffectsMayOutliveTheNamespace`, in as many words |

Three properties are the point rather than the list.

**A collection that would not list gets no entry at all.** Not a count of zero — that is the single
most dangerous number a namespace-deletion plan could print, and §55.4 and §45.4 both say the same
thing in different words: what could not be listed is reported as *not listed*. The gap names the
GVR and the outcome (`list denied`, `unavailable`, `request failed`), one at a time.

**A page that did not end is a floor.** `Contained::at_least` renders as `apps/v1/deployments: at
least 500`. One page per collection is asked for, because §55.2 wants counts at the moment somebody
is waiting to decide and walking every collection to its end is an unbounded number of requests
(§50.2, §18.4).

**A Namespace deletion that nobody enumerated says so.** `Caveat::ContainedInventoryNotEnumerated`
fires when `contents` is absent on a Namespace deletion, so a plan that skipped §55.2's analysis is
distinguishable from one that ran it and found nothing (§4 invariant 13).

The enumeration is over *preferred* versions only, because §55.2 asks for counts by GVR and the
same objects served at two versions would be counted twice (§13.4).

### 6. Two supporting corrections

`set_at` in `mutation.rs` now unescapes RFC 6901 pointer segments (`~1` → `/`, `~0` → `~`, in that
order). Without it, `--label app.kubernetes.io/name=checkout` would have created a field called
`app.kubernetes.io~1name` beside the labels and the request would have succeeded. The label
convention §23.4 names is exactly the case that breaks.

`PLAN_FIELDS` gains `competing_writers`, `competing_writer_coverage`, `contained` and
`contained_coverage`; `MUTATION_FIELDS` gains those four and `caveats`. The mutation record carries
them because §46.1 makes a mutation a plan that was then carried out, and a §54.2 warning that only
`get k8s-plan` showed would be one that `set k8s-resource --dry_run true` — the shortest sentence a
user writes — never printed. `contained` is nullable and null for every change that is not a
Namespace deletion; `competing_writers` is required and empty-with-coverage, because every change
has writers to report or a statement about the looking.

## Consequences

- The curated actions are on `set k8s-resource` only. The `k8s-plan` *target* keeps `--action`,
  `--set`, `--unset` and `--propagation`, because a target's options are declared in
  `package/contributions/targets.yaml` and that document is outside this change. Two consequences
  follow, and neither is a hole in a `MUST`. A curated action is still plannable without writing:
  `dry_run` defaults to true (§44.5), so `set k8s-resource --replicas 2` predicts and the record
  carries the whole plan, its effects and its verification rule. And `get k8s-plan --set …` still
  produces `Caveat::LowLevelChange` on its record, so §43.4's labelling reaches a user there too —
  what is missing is only the `LOW-LEVEL EXPERT PATH` prefix on that target's own help line.
  Adding the curated arguments and the help prefix to `k8s-plan` is a follow-up, and it is a
  document edit plus four lines.
- `Action` is a three-member enum where it was two, so every match over it in the domain layer had
  to answer for the curated case. That is deliberate: a fourth shape of change cannot be added
  without deciding its verb, its effects and its verification rule.
- `has_scale` (§33.5) remains discovered with no plugin caller, for the reason in decision 1. A
  generic scalable-workload capability over CRDs — §33.5's actual offer — would use it, and that
  is a capability-reporting change (§57.1) rather than a mutation one.
- A Namespace deletion plan is now the most expensive read this package makes: one resource list
  per group plus one list page per namespaced collection. It is bounded, it is paid only for a
  Namespace deletion, and §55.2 is a `MUST`.
- Nothing about confirmation changed. The host applies its policy to the declared `risk`, and this
  package still prompts for nothing (§21.5 of the generic provider contract).

## Alternatives considered

**`restart k8s-resource`, `disable k8s-node`, `enable k8s-node` — new commands on core's existing
verbs.** This was the first design and it is the one the verb vocabulary invites: `restart`,
`enable` and `disable` are all in core's `docs/contracts/verbs.yaml`, and `disable k8s-node` reads
better than `set k8s-resource --schedulable false`. Rejected on §35.1. A package that grows one
command per Kubernetes state transition is a Kubernetes mini-shell that grew by *verb* instead of
by noun — seven words today, and the next seven are whatever the next §43.3 revision lists. Each
would have to declare the same risk and the same capability for the same change to the same object,
and `contributions.rs` would hold seven near-identical `Command` entries whose only difference is
which argument they read. The existing test `should_write_only_through_a_verb_that_says_so` asserts
that this package's verbs are exactly `["set", "remove"]`, and keeping that assertion true is a
better property than a slightly shorter invocation.

**A single `--action scale` argument taking the transition by name.** Rejected: it is the pointer
problem with an extra layer. `--action scale --value 2` needs a second argument whose meaning
changes with the first, and completion cannot offer `--value`'s type until `--action` is written.
A named argument per transition is what makes `help` and completion useful.

**Routing `/status` writes to the subresource where discovery says one is served.** Rejected in
decision 3. It is technically the "correct" Kubernetes operation and that is the problem: it makes
Ono a controller, and a value that says what a controller observed would say what a user typed.

**Refusing `/status` only where the subresource is served.** Rejected: the same sentence would be
refused on a Deployment and accepted on a CRD that had not declared its subresource, which makes
Ono's honesty a function of a CRD author's omission.

**A `reversible: bool` or a `will_be_overwritten: bool` for the HPA case.** Rejected for the reason
§46.5 rejects the first: a boolean is a claim, and what §54.2 asks for is a warning naming the
writer and what it does. `may be reconciled back` is the strongest true sentence available.

**Counting a namespace's contents by walking every collection to the end.** Rejected under §50.2
and §18.4. A floor that says it is a floor is more useful than an exact count that arrives after
the operator has stopped reading, and `at_least` is not a rounding — it is the shape of a bounded
count.

**Listing a namespace's contents through `remainingItemCount` alone.** Rejected: it is optional,
the API server may omit it, and a plan whose numbers appear and disappear depending on the server's
mood is worse than one that says `at least N` every time it stopped early.

**A per-source caveat for each of §54.1's five sources that was not consulted.** Rejected: it would
fire on every plan forever, which is how an operator learns to skip the caveat list. The coverage
field carries what the search reached, and §54.3's absence is recorded here rather than repeated at
every invocation.

# ADR-0013: One field name means one thing across nineteen schemas

- Status: accepted
- Date: 2026-09-05
- Spec refs: §14, §15.2, §15.5, §21.4, §25, §26, §27, §29, §30, §31, §32, §37.2, §37.3, §37.5
- Decided by: agent (autonomous)
- Supersedes the deferral recorded in ADR-0005, not its rule

## Context

ADR-0005 declared five schemas rather than nineteen, because a contributed schema is a promise
the package will emit records of that shape and nothing emitted a `KubernetesService`. It named
what the other fourteen were waiting on: a field projection worth declaring, and — for the
relationship-shaped nouns — evidence rather than a display.

Both are now available. `workload.rs` derives the Service, EndpointSlice, Ingress and StatefulSet
relationships with their evidence classes; `condition.rs` derives a reconciliation state with the
rule and the citations §37.5 requires; `object.rs` projects §14's metadata for every kind from one
code path; `redaction.rs` destroys a payload at the boundary. Wiring the remaining fourteen is
therefore a question about *schemas* rather than about Kubernetes.

Three questions had to be answered before the first field was written.

**How is a field resolved?** `records::field_value` matches on the field's *name* and nothing
else — no target, no kind. That is deliberate (it keeps the schema table, the field list and the
projection readable side by side) and it has a consequence: a field name is global vocabulary, not
a per-schema label. Nineteen schemas written independently would collide within a week —
`ready` as a Node's condition status and as a DaemonSet's count of ready nodes, `capacity` as a
volume's size and as a claim's bound size, `reclaim_policy` under `spec` on one kind and at the
top level on another.

**How much of a kind does a schema describe?** §15.5 forbids the all-or-nothing claim: a resource
being discoverable does not imply Ono understands every field of it. A schema listing every field
of a Service would be claiming exactly that.

**What does a derived state look like?** §37.2 requires reconciliation rules to be kind-specific,
§37.5 requires the derived state to arrive with the fields it rests on, and §37.3 says a matching
`observedGeneration` is not health.

## Decision

**All nineteen of §15.2's Tier 1 set are declared and wired**, in §15.2's own order, in
`package/contributions/schemas.yaml` and `contributions::TARGETS`. `tests/contributions.rs` fails
if a declared target has no handler, if a declared schema has no target, or if the two documents
disagree about a field.

**One field name means one thing, everywhere.** The rule is enforced by reading rather than by a
type, so it is written down here and asserted by the tests that pin each kind's projection:

- `phase` is `status.phase` on a Namespace, a Pod, a claim and a volume;
- `desired_replicas` is `spec.replicas`; `current_replicas`, `ready_replicas`,
  `updated_replicas` and `available_replicas` are the matching `status` counts, on every kind that
  has them;
- a DaemonSet counts **nodes**, so its fields are `desired_scheduled`, `current_scheduled`,
  `ready_scheduled`, `updated_scheduled`, `available_scheduled` and `misscheduled` — never
  `replicas`, because the number means something different;
- a claim's `bound_capacity` is `status.capacity.storage` and a volume's `capacity` is
  `spec.capacity.storage`: asked-for and got are two claims, and the claim carries both
  (`requested_storage` beside `bound_capacity`);
- `reclaim_policy` reads `spec.persistentVolumeReclaimPolicy` or the top-level `reclaimPolicy`,
  because it is one question — what happens to the storage on release (§30.5) — and no object
  carries both pointers;
- `ports` reads `spec.ports` or the top-level `ports`, for the same reason;
- `keys` is a Secret's key names through the redaction guard, and a ConfigMap's `data` keys
  otherwise. A ConfigMap is not sensitive; a schema whose *shape* depended on whether the payload
  is sensitive would make redaction a per-kind decision instead of a boundary (ADR-0003).

**A schema carries what an operator troubleshoots with.** Between four and twelve fields beyond
§14's shared metadata, chosen so that the field that explains the usual failure is present: a
CronJob's `suspend`, a claim's null `volume_name`, a DaemonSet's `misscheduled`, a StatefulSet's
`update_revision` beside its `current_revision`, a Job's `failure_reason`. What is left out stays
reachable through `k8s-resource`, which projects the whole object, so leaving a field out costs a
more verbose spelling rather than access.

**A reconciliation is one map field, on the four workload controllers and Job.** It carries
`state` in §37.5's own wording, `rule` naming the derivation, `evidence` listing every field the
rule read and what it held, `verified_convergence`, and `stage` — §20.4's ladder, null where the
evidence establishes nothing and never `workload externally healthy`. `verified_convergence` is a
separate key precisely because §37.3 says `observedGeneration` alone is not health: a renderer
that wants one green word has to ask that question rather than treat "not failed" as success.
Kinds with no controller reconciling them towards anything — ConfigMap, Service, Namespace,
Secret — carry no such field, on §37.2's rule; a state derived for symmetry would be a claim with
no rule behind it.

**Nothing is summarised that a specification says must not be.** A NetworkPolicy's `rules` are
`spec.ingress` and `spec.egress` verbatim, because §31.2 forbids reducing peers that combine
namespace selectors, pod selectors and IP blocks to a boolean, and §31.3 forbids implying the
installed network plugin enforces the policy — so no field is named `enforced`. A Service's
`ports` stay a structured map for §31.4. A selector-less Service's `selector` is null, because
§26.1 requires it to produce no guessed Pod edges. An EndpointSlice endpoint with no `targetRef`
contributes an address and no target, because §26.4 keeps it an endpoint fact.

**Relationship-shaped fields come from the domain layer.** `services`, `tls_secrets` and
`ingress_class` are read off `Workload::ingress_edges`; `service_name` off
`Workload::governing_service`; `claim_templates` off `Workload::volume_claim_templates`;
`targets` and the endpoint counts off `Workload::endpoints`; `controller` off the owner reference
marked `controller: true`. The evidence *class* stays visible in the schema documentation, so an
EndpointSlice's `service_name` — a label, which an operator can change — is documented as
convention evidence while a StatefulSet's is documented as a native field (§23, Gate D).

## Consequences

Easy: `get k8s-service`, `get k8s-ingress`, `get k8s-networkpolicy` and sixteen more answer
records with declared schemas, host provenance and UID identity, over the same discovery, the same
`--name` lookup and the same redaction boundary as the original five. The Tier 1 half of §15.2 is
delivered rather than declared. Adding a kind is one table entry, one schema block and the field
arms it needs.

Hard: the global field vocabulary is a convention a compiler cannot check. A twentieth schema
that declares `ready` meaning something new will silently take the Node's condition status. The
mitigation is that every kind's projection is pinned by an end-to-end test asserting specific
values, so a collision shows up as a wrong value rather than as a missing one — but the first
line of defence is this document.

Watch: five of the nineteen — Service selection, EndpointSlice endpoints, Ingress routing,
NetworkPolicy selection, ServiceAccount use — are *relationships* in §26 to §32, and this session
delivers their record fields rather than their edges. A record says which Services an Ingress
routes to; it does not say which host and path led to each, and the evidence that would answer
that lives on `Workload::ingress_edges` with no route to the shell. That is K2's relationship
work, and none of it is blocked by the schemas above.

Watch also: `k8s-pod` still carries no `service_account`, `configmap` or `volume` reference, so
§29.1 and §30.1's Pod-side dependencies are the one part of Tier 1 that is reachable only through
`k8s-resource` today.

## Alternatives considered

**Resolve a field by target and name, so each schema owns its vocabulary.** Rejected for now: it
would remove the collision hazard and add a second axis to every projection, and the field arms
would stop being readable as one list. The hazard is real and the mitigation is tests plus this
record; if a third collision has to be worked around, that is the signal to revisit.

**One `status` string per kind instead of a `reconciliation` map.** Rejected: it is exactly the
"invent a status word" §37 exists to prevent. A word with no rule and no citations is a verdict
nobody can check, and §37.3 shows how easily one becomes a false claim of health.

**Summarise a NetworkPolicy into `allows_ingress_from` lists.** Rejected outright: §31.2 names
this as the anti-pattern, and a summary that is true only under complete coverage of every policy
in the namespace is a summary this provider cannot honestly produce.

**Give each kind's counts the same names (`ready`, `desired`, `updated`).** Rejected: a
DaemonSet's numbers are nodes and a Deployment's are pods, and one name for both would make a
fleet-wide rollout and a replica rollout look like the same measurement.

**Wait for the relationship layer, and ship the schemas with it.** Rejected: the record fields are
useful on their own — a suspended CronJob and an unbound claim are answered today — and holding
them back would repeat ADR-0005's deferral for a reason ADR-0005 has already discharged.

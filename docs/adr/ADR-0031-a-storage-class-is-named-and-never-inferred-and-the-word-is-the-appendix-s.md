# ADR-0031: A storage class is named and never inferred, and the word is the appendix's

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariant 20, §9.2, §23.1, §23.5, §30.1, §30.2, §30.3, §30.5, §35.5, §35.7,
  §61.3 (K2), §62.4 (Gate D), Appendix B; ADR-0008, ADR-0014, ADR-0027, ADR-0029
- Decided by: agent (autonomous)

## Context

ADR-0029 closed §30.2's `PVC → bound-to → PV` and deliberately left §30.1's third line open:

```text
PV -> provisioned-by / storage-class -> StorageClass
```

It left it open because the word had to be decided and the decision reached `place.rs`, which was
outside that change's scope. Two things were unsettled.

**The vocabulary conflicts with itself.** §30.1 spells the edge `provisioned-by / storage-class`.
Appendix B's canonical vocabulary spells it `uses-storage-class` and does not list either of
§30.1's spellings. Appendix B's own preamble says its names "are provider-facing candidates and
SHOULD be reconciled with the project's global relationship registry before ABI freeze", so it is
the list that is *meant* to be the vocabulary.

**The field has three states and only one of them is an edge.** `spec.storageClassName` may name a
class, may be the empty string, or may be absent — and Kubernetes gives all three different
meanings.

## Decision

### The word is `uses-storage-class`

Appendix B's, for three reasons that agree:

1. **It is the reconciled list.** §30.1's line is prose in a paragraph about mapping volumes;
   Appendix B is the vocabulary section, and it names the one word.
2. **`uses-*` is the shape this provider already has** for every "this object names that one"
   edge: `uses-service`, `uses-tls-secret`, `uses-ingress-class`, `uses-gateway-class`,
   `uses-secret`, `uses-image-pull-secret`. A seventh in the same shape needs no explanation;
   `provisioned-by` would be the only edge here reading in the passive.
3. **`provisioned-by` would assert something the field does not say.** It claims the provisioning
   happened. `spec.storageClassName` on a `Pending` claim says only which class was *asked for*,
   and §4 invariant 20 forbids a claim arriving in a shape stronger than its evidence.

Both ends carry it: `PVC → uses-storage-class → StorageClass` as well as §30.1's
`PV → uses-storage-class → StorageClass`, from the same field name, because §30.3 wants the class
reachable "for change/risk reasoning" and an operator planning a deletion (§30.5) is holding
whichever of the two the plan named.

### Three states, one edge

- **A name** is the class, and the edge is `Evidence::NativeField` citing `/spec/storageClassName`.
- **The empty string is not.** `storageClassName: ""` is Kubernetes' way of saying *no class, do
  not provision dynamically*. An edge there would address a StorageClass whose name is the empty
  string, which is not a thing.
- **Absent is not either.** It means the cluster's default class applies. *Which* class that is, is
  a fact about the cluster — the `storageclass.kubernetes.io/is-default-class` annotation on some
  other object — and reading it from here would be §23.5's inference wearing §23.1's clothes. A
  claim that took the default has no `uses-storage-class` edge, and the cluster's default classes
  are reachable as StorageClass records with their annotations.

A StorageClass is cluster-scoped, so the target carries no namespace (§9.2), and the target's
`apiVersion` is `storage.k8s.io/v1` rather than the `v1` `reference_edge` hard-codes — which is
why the edge is built inline, as `bound-to` and `scheduled-on` are.

## Consequences

- `get k8s-relation --kind PersistentVolumeClaim --name data --relation uses-storage-class`
  answers, and so does the same question of a PersistentVolume. That is §30.1's third line and the
  last unmet piece of K2's *config/storage relations* requirement.
- The word is `follow`-able: `Waypoint::UsesStorageClass` joins `place.rs` at `Proximity::Dependency`,
  beside `bound-to` and `mounts`, and the two shapes are declared in `package/manifest.yaml`, so
  `near` on a claim ranks its class with its volume.
- A claim that named no class has no edge and says nothing. A reader who wants to know which class
  it will get asks the cluster for its StorageClasses; this provider does not answer a question
  about the cluster by reading a field of one object.
- §30.4's PV/CSIDriver/CSINode/VolumeAttachment relationships remain untaken. They are a `MAY`, and
  the CSI identifiers a Node and a volume state are already exported as cross-system evidence
  (§47.5, ADR-0016) rather than resolved here.

## Alternatives considered

**`provisioned-by`, as §30.1 spells it first.** Rejected above: it asserts the provisioning
happened, and a `Pending` claim naming a class disproves that in the commonest case an operator
looks at.

**Both words, as synonyms.** Rejected. Two words for one edge doubles what a user has to know and
halves what a filter finds; §23 is explicit that one vocabulary is the point.

**Read the cluster's default class when the field is absent.** Rejected as the clearest case of
§23.5 there is. It is a correlation across two objects, it changes when an administrator moves the
default annotation, and it would arrive under `Evidence::NativeField` on a field that is not there.

**An edge for the empty string, marked as "explicitly none".** Rejected. An edge whose target does
not exist is not an edge; the fact that a claim refused dynamic provisioning is a *field* of the
claim, and `records.rs` already projects `storage_class`.

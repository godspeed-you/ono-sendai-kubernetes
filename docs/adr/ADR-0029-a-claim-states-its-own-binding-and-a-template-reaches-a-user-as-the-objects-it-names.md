# ADR-0029: A claim states its own binding, and a template reaches a user as the objects it names

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 13, 20, §9.2, §13.5, §22.4, §23.1, §23.5, §24.1, §24.2, §25.1, §25.3, §28.1, §29.1, §29.2, §29.3, §29.4, §30.1, §30.2, §32.1, §35.7, §62.4, Appendix B
- Decided by: agent (autonomous)

## Context

K2 — the operational graph (§61.3) — had three holes that a user meets as an empty answer rather
than as a refusal, which is the failure mode §21.4 exists to prevent.

**`bound-to` was a word with no producer.** `Relation::BoundTo` is in the vocabulary, in
`relations::RELATIONS`, in `place::Waypoint`, in `spatial::SHAPES` and in the manifest's declared
relations — and nothing anywhere constructed one. `--relation bound-to` therefore answered
`Completed` with no records, which reads as "this claim is bound to nothing" for every claim in
every cluster. §30.2 names the field that decides it (`PVC.spec.volumeName`) and the one case that
must not be guessed (a Pending claim with no volume name).

**`uses-template` had no code and no possible shape.** §25.1 asks for
`Deployment -> uses-template -> PodTemplate semantics`. A PodTemplate has no name, no `uid` and no
collection: `Place::of_target` cannot build an address for one, and `workload.rs` already states
the rule this comes from — a template is not an object (§25.3). The word is also absent from
Appendix B's vocabulary, so nothing downstream was waiting for it.

**A Pod's dependencies were read from one container list and one volume shape.** `pod_edges`
scanned `/spec/containers` and three volume sources. `initContainers`, `ephemeralContainers`, the
projected volume sources §29.1 names explicitly, and `spec.imagePullSecrets` produced nothing, so
a Pod that cannot start because an init container's ConfigMap is missing was reported as a Pod
that references no configuration. §29.3's `optional` flag had nowhere to ride at all, and
`Evidence` has no field for it.

There is also a vocabulary conflict to settle: §30.1 spells the StorageClass edge
`provisioned-by / storage-class` and Appendix B spells it `uses-storage-class`.

## Decision

**1. A claim's binding is an edge the claim itself states, produced in `Graph::edges_of`.**
`claim_edges` reads `/spec/volumeName`, filters the empty string, and builds the target inline —
`PersistentVolume`, `apiVersion: v1`, **no namespace**, because a PersistentVolume is
cluster-scoped and a namespace copied onto it would name an address nobody can look up (§9.2,
§24.2). `/status/phase` rides as *supporting* evidence: §30.2 calls the status fields "relevant"
and they are, but the spec field is what decides, so a claim whose spec names a volume the control
plane has not yet confirmed still says which volume and still says `Pending`.

It lives in `Graph::edges_of` rather than in `relations::stated_edges` because it is the same
class of fact as `spec.nodeName` on a Pod: one object, one of its own fields, no second reading.
`edges_of` is the single door every consumer already walks through — `stated_edges`, the spatial
contribution and `redaction::secret_references` all call it — so routing it there makes the edge
reachable by `get k8s-relation`, by `near` and by `follow` without a second copy of the rule. The
`is(object, …)` guards in `stated_edges` exist for the *curated* rules in `workload.rs`, which
read field **shapes** a custom resource could coincidentally share; this rule is guarded the same
way but at its own door, by group **and** kind.

**2. `uses-template` is not emitted. A controller's template reaches a user as the reference edges
the template states**, through `Workload::template_dependencies`, routed in
`relations::stated_edges`. A pod template names ConfigMaps, Secrets, claims, pull Secrets and a
ServiceAccount, and every one of those *is* an addressable object with a lifetime. So
`Deployment -> references-config -> ConfigMap` with evidence
`/spec/template/spec/volumes/0/configMap/name` answers the operator's question ("what does this
Deployment depend on") in the vocabulary §29 to §32 already use, with a pointer a reader can check
(Gate D). The kind table is per kind and includes the pointer, because a CronJob templates a Job
that templates a Pod and `/spec/template` finds nothing there.

**Placement is deliberately excluded.** `spec.nodeName` inside a template asks where Pods should
go; `scheduled-on` says where a Pod *is* (§28.1). A Deployment is scheduled nowhere, and
`pod_edges` therefore keeps the node edge to itself instead of taking it from the shared
`pod_spec_edges`.

**3. Every container list and every typed volume source is scanned, from one rule.**
`pod_spec_edges(source, namespace, spec, base)` takes the pointer the spec was read at and builds
every evidence path from it, so `containers`, `initContainers` and `ephemeralContainers` are one
loop over a list of field names rather than three copies, and a Pod at `/spec` and a template at
`/spec/template/spec` are the same rule at two addresses. Added: `projected.sources[].configMap`
and `projected.sources[].secret` (which carries `name`, not `secretName`), and Pod-level
`spec.imagePullSecrets` as `uses-image-pull-secret`. A `serviceAccountToken` projection emits
nothing: the API server mints that token and there is no object to point at.

**4. `optional` rides as supporting evidence, and only when the object stated it.** §29.3 asks
that the edge preserve the fact; `Evidence` has no field for it and adding one would put an
`Option<bool>` on selector and owner-reference evidence that can never carry it. So the flag is a
second `Evidence::NativeField` in `Edge::with_supporting`, citing `…/optional` and the value read.
That is the same split §27.1 already uses for a route's host and path: the flag does not make the
reference exist, and it changes what a missing target means. When the field is absent the
supporting list is empty — the default is not something the API server said. The record already
carries `supporting`, so this reaches a user through `k8s-relation` with no schema change.

**5. The StorageClass edge is `uses-storage-class`, and it is not implemented here.**
Appendix B's spelling wins over §30.1's `provisioned-by / storage-class`: Appendix B is the
vocabulary list, its preamble marks these as the names to reconcile with the global registry, and
§30.1's slash is a description of the relationship rather than a word a user types after `follow`.
Implementing it needs a new `Relation` variant, which needs a new `Waypoint` word in `place.rs`
(`Waypoint::from_relation` is total by design) and two new contributed shapes in `spatial.rs` and
the manifest. `place.rs` is outside the file scope of this change, and a `Relation` variant added
without its `Waypoint` does not compile. The name is decided here so the next change spells it
once; the edge is not claimed anywhere until it is produced.

**6. §29.4's immutable flags are already exposed for ConfigMap and not for Secret.**
`records.rs` projects `/immutable` and `contributions.rs` declares it in `CONFIGMAP_FIELDS`.
`SECRET_FIELDS` has no such field, and a Secret carries `immutable` in exactly the same way. That
is a *record* field rather than an edge, it belongs to `records.rs` and `contributions.rs`, and
those files are outside this change. It is recorded here so it is not rediscovered as new.

## Spec deviation

**§25.1**, which says curated relationships for a Deployment SHOULD include:

> ```text
> Deployment -> uses-template -> PodTemplate semantics
> ```

This provider emits no `uses-template` edge. The rule that replaces it: **the semantics of a pod
template are exposed as the controller's own reference edges to the objects the template names,
each citing its pointer inside the template.** The reasons are §25.3's own — a template is not an
object, so it has no `uid`, no address and no lifetime — and §24.1's, which requires an edge's far
end to stay addressable even when it was never read. An edge to a synthetic `PodTemplate` place
would fail `Place::of_target` at emission or, worse, succeed against a name no `get` can resolve.
`uses-template` is also absent from Appendix B's vocabulary, so no relationship registry is left
with a dangling word.

## Consequences

- `--relation bound-to` answers, and `pvc -> pv` becomes the first *filled* member of a shape the
  manifest has declared since the spatial contribution was written.
- A Deployment, ReplicaSet, StatefulSet, DaemonSet, Job and CronJob now answer with reference
  edges they did not answer with before. They are edges of the *controller*, and the evidence path
  says so — a reader who wants the running Pods' references still asks the Pods.
- No new contributed shape is declared for those controller edges, so they reach a user through
  `get k8s-relation` and do not become spatial exits. `spatial::emit` drops any pair no shape
  declares, so this is a bounded omission rather than a silent one; declaring
  `deployment->configmap` and its neighbours is a later decision with a cost in the manifest.
- `Graph::edges_of` now matches on group **and** kind. A custom resource of another group whose
  kind is spelled `Pod` no longer has `spec.nodeName` read as a scheduling fact (§13.5). This is a
  behaviour change, and it is the correct one; it has its own regression test.
- Every new Secret edge flows into `redaction::secret_references`, which filters `edges_of` for
  `ReferencesSecret` edges with a path — so the projected and container-list Secret references
  join the redaction path automatically. The Pod's `uses-image-pull-secret` edge does **not**, and
  must not: `stated_edges` adds `secret_references` filtered to the two `uses-*` words on top of
  `edges_of`, and an edge produced by both would reach a user twice. A test holds that line.

## Alternatives considered

- **A `uses-template` edge with a synthetic target** (`Target::new("PodTemplate", "checkout")`).
  Rejected: it invents an address that resolves to nothing. `enter` on it fails, `follow` arrives
  nowhere, and §24.1's "unresolved target" — which means *nobody looked yet* — becomes
  indistinguishable from "there is nothing to look at".
- **A `PodTemplate` intent value in the shape of `ClaimTemplate`.** Honest, and unreachable: an
  intent value becomes visible only as a record field, which is `records.rs` and
  `contributions.rs`. It would have been a typed answer nobody could ask for, which is exactly the
  state ADR-0025 was written to end.
- **Reading the template through `Graph::edges_of` beside the Pod arm.** Rejected: the pointer
  differs per kind and the table is §25's knowledge, which is `workload.rs`. `edges_of` keeps the
  core `v1` objects whose reference fields are their own, and the controller chain stays where
  §25 to §27 already live.
- **An `optional: bool` field on `Evidence::NativeField`.** Rejected: it puts a Kubernetes
  configuration concept on the evidence type every class shares, and `Evidence::Selector` can
  never carry it. `supporting` already means "qualifies without deciding".
- **Emitting `optional: false` where the field is absent.** Rejected: the default is Kubernetes'
  and not the API server's statement, and Gate D's pointer would cite a field the object does not
  hold.
- **§30.1's `provisioned-by` as the StorageClass word.** Rejected in favour of Appendix B's
  `uses-storage-class`: the appendix is the vocabulary, §30.1 is prose, and `uses-*` is the shape
  the rest of this provider's words already take (`uses-service`, `uses-tls-secret`,
  `uses-ingress-class`, `uses-secret`, `uses-image-pull-secret`).

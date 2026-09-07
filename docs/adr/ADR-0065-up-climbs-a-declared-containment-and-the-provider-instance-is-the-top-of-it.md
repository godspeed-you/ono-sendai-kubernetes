# ADR-0065: `up` climbs a declared containment, and the provider instance is the top of it

- Status: accepted
- Date: 2026-09-07
- Spec refs: §9.1, §9.2, §10.1, §35.2, §35.3, §35.4, §35.6, §36.1, §36.2, §53.1–§53.3; `ADR-0596 (core)`,
  `ADR-0597 (core)`; ADR-0011, ADR-0027
- Decided by: agent (autonomous)

## Context

`up` from a Kubernetes place refused. The namespace was reachable as a *relation* — `follow
…pod_to_namespace` landed on it, and ADR-0027's board entry recorded that this package could make
the spatial parent reachable but not make `up` land on it — because a contributed target had no
way to say which kind of place is above it, and the space above a namespace was an aggregate no
package could declare (`ADR-0584 (core)`).

`ADR-0597 (core)` closed that generically: a target declares `parent`, the schema of the kind
above it, and `up` follows the contributed relation the manifest declares for the pair. And
`ADR-0596 (core)` gave a target `roles`, so that `find place --role workload` has something to
plan by. Both are declarations this package now has to make — and the hierarchy it declares is
the one §35.2, §35.3 and §35.6 describe: provider instance, namespace, resource, with ownership
kept somewhere else entirely.

## Decision

**Every target whose kind has a containment shape declares that shape's far end as its
`parent`; the containment shapes reach the provider instance; and `up` climbs them.**

1. A namespaced kind's parent is the namespace, along the `in-namespace` shape `spatial.rs`
   already declared for fourteen kinds. A namespace's parent, and a cluster-scoped kind's — Node,
   PersistentVolume, StorageClass — is the **cluster**, along four new `in-cluster` shapes whose
   far end is `k8s-cluster`. `Target::parent` is read off `SHAPES` rather than restated, so a
   parent without a shape cannot be declared here and is refused by the host on disk anyway.
2. The cluster is a place of this package's own, keyed on the provider instance of §10.1
   (ADR-0011) and never on a fingerprint. An `in-cluster` edge's far end is therefore the
   instance id the standing endpoint resolved to, and the host binds it by re-reading
   `k8s-cluster` — whose `uid` is that id. Two instances reaching one cluster remain two places.
3. `up` from the cluster refuses: it is the top of what this package contributes, and a cluster
   is not filed under a domain of the laptop the shell runs on (§2.17 of v0.4).
4. Ownership is untouched. `pod_to_replicaset` still carries `owned-by, controlled-by` and
   `follow` still walks it; `up` never does. The two shapes are two questions (§35.6).
5. Every target declares the roles `place.rs`'s `ROLE_OVERLAY` gives its kind, so the role a
   Deployment carries on a `k8s-relation` record and the role its place is found by are one
   table; the native schema, `uid` and `canonical_ref` are unchanged beside them (§36.1, §36.3).

**Tier 2 kinds declare no parent yet, and that is the cost boundary.** Every shape costs one
listing per contributed-edge merge — `near` and `up` pay for it — and the four cluster shapes
were chosen because their kinds are already listed for other shapes. Declaring `in-namespace`
for the eight namespaced Tier 2 kinds would add eight listings to every `near`. `up` from one of
them refuses naming the missing declaration, which is the honest state until the merge can be
narrowed to the standing place (`ADR-0585 (core)` §4 records why it cannot be today).

## Consequences

`get k8s-pod … | enter; up` lands on the namespace, `up` again on the cluster, `up` again
refuses as the top; `back` walks the same steps in reverse. `get k8s-cluster … | enter; near`
lists the cluster's namespaces and nodes as exits. `find place --role workload` answers with
the Pods and controllers the cluster holds and never with a Service, each place carrying
`roles: [workload]` beside its unchanged native type. The on-disk `targets.yaml` declares the
same roles and parents the handshake does, and a test holds the two together.

Tests, `crates/ono-kubernetes-plugin/tests/spatial_shell.rs`, over the real `ono` binary:

- `should_go_up_from_a_pod_to_its_namespace_and_from_there_to_the_cluster` (replaces the
  refusal test `should_say_why_up_has_nowhere_to_go_from_a_kubernetes_place`, whose reason no
  longer exists);
- `should_enter_the_cluster_and_find_its_namespaces_and_nodes_among_the_exits`;
- `should_find_workloads_by_role_across_the_kinds_that_carry_it`;

and `tests/contributions.rs`: `should_declare_the_same_roles_and_parents_in_the_document_and_across_the_handshake`,
with `should_relate_only_kinds_the_contribution_actually_reads` now naming the cluster as the
one endpoint that reads no kind.

## Alternatives considered

**Make the namespace the top.** Rejected: §35.2 makes the cluster the provider root scope, and a
hierarchy whose top is a namespace would leave `enter k8s-cluster` a place with nothing below it.

**Key the cluster's end of the edge on `kube-system`'s uid.** Rejected: that is the fingerprint,
and keying a place on it merges the two instances §10.3 forbids merging (ADR-0011).

**Declare parents for every Tier 2 kind now.** Rejected for the cost stated above; the decision
expires when a contributed-edge merge can be asked about one place rather than the whole cluster.

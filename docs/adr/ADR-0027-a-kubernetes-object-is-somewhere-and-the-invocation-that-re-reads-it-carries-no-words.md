# ADR-0027: A Kubernetes object is somewhere, and the invocation that re-reads it carries no words

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 4, 5, 13, 22, §7.1, §7.3, §7.4, §7.5, §9.2, §16.1, §16.5, §21.4,
  §23.1–§23.3, §24.1, §26.1, §26.2, §28.1, §31.1, §32.1, §35.1–§35.8, §36.1–§36.4, §53.1–§53.3,
  §61.1 (K1, K2), §62.1 (Gate A), §65.2, §69;
  `ADR-0584 (core)`, `ADR-0585 (core)`, `ADR-0194 (core)`; ADR-0008, ADR-0010, ADR-0014, ADR-0024
- Decided by: agent (autonomous)

## Context

`place.rs` has known how to address a Kubernetes object since ADR-0008. It builds a place URI with
a grammar of its own in which a cluster-scoped resource has no namespace slot (§9.2); it binds the
lifetime identity rather than the name (§35.4); it knows that a namespace is a Pod's spatial parent
even though a ReplicaSet owns it (§35.6); and `Neighbourhood::ranked` holds §35.5's prioritisation
— for a Service, its selected Pods, then its EndpointSlices, then its routes. All of it was built,
tested, and reachable only as **strings on a record**. `get k8s-relation` printed two place URIs
under every edge and a user could not stand on either of them.

The reason had been core's, and it stopped being core's on 2026-09-05:

- **`ADR-0584 (core)`** makes every schema a package declares a target for a kind of place, keyed
  on the schema id. That needed no line here at all — this package already declared thirty targets
  with `uid` identity, and the moment the host carried the change, `find place --type
  KubernetesPod` and `get k8s-pod | enter` worked. It was verified before anything below was
  written, and the sixty-three types the shell offers after `load plugin` now include thirty of
  this package's.
- **`ADR-0585 (core)`** runs a relation between two such kinds, declared in the manifest as
  `<from>-><to>` where each endpoint is the id of a schema one of *this package's own* targets
  declares, validated against the documents on disk before the runtime is spawned.

So what was owed here was the declaration, the edges, and one thing neither ADR anticipated.

**The shell asks a package for a place with no words at all.** `PluginProvider::snapshot` invokes
`provider.query` with an empty argument map, and it is what runs when the shell re-reads a place
(§33.2 of the generic provider contract) and when it resolves either end of a contributed edge.
This package refused such a query outright — "the query named neither a kubeconfig `context` nor a
`host`, and this provider does not guess an API server" — which was a defensible reading of §7 when
every query came from a person. It is not defensible now. Measured against the real `ono` binary
before any change, entering a Pod worked and `look` on the place that followed reported it
**`removed`, with a tombstone**, about a Pod the recorded cluster was still serving; and no
contributed edge could have resolved either of its ends.

## Decision

### 1. An invocation that names no cluster stands where the last one stood, and then falls back to `current-context`

Three ways in, in this order:

1. an explicit `host` (§7.3), unchanged;
2. a named `context` resolved through the kubeconfig (§7.4), unchanged;
3. **neither** — the *standing query*, and then the kubeconfig's `current-context`.

The standing query is the endpoint options of the most recent invocation **in this process** that
named a cluster: `host`, `port`, `context`, `kubeconfig`, `namespace`, `all_namespaces`,
`max_pages`, and — because `k8s-resource` names its collection in the selector rather than in a
table — `kind`, `group`, `version` and `resource`. Only what an operator typed is remembered.
Nothing the cluster answered is, and no credential is: replaying re-reads the kubeconfig and
re-resolves the credential from scratch, so §8.1's boundary is untouched and a rotated token takes
effect on the next call exactly as it does on the named path.

This is a replay of the operator's own words rather than a guess, which is what keeps §7.4 —
"context switching MUST remain explicit". An invocation that names an endpoint of its own keeps it
and becomes the new standing one; every record carries
`provider_instance=kubernetes:<context>` in its provenance, so which cluster answered is visible
rather than implied.

`current-context` behind it is §7.1's own list: "current context as an optional default" is among
the elements a provider MUST support. A kubeconfig that elects no context is refused with the
contexts it does define, and a kubeconfig that could not be read at all — denied, absent — is
refused as "nothing named an API server" **with the read failure named in the help**, because §4
invariant 13 does not let a denial disappear into an absence.

### 2. Thirty-three shapes, declared in the manifest and in one table

`package/manifest.yaml`'s `contributions.relations` and `spatial::SHAPES` are one declaration
written twice, in the same order, and `tests/contributions.rs` fails if they disagree. Every
endpoint is the id of a schema `package/contributions/targets.yaml` declares a target for, which is
what a host checks at load; the same check is made here against the same two files, so a wrong
declaration is a test failure rather than a `package.invalid` somebody discovers on installation.

The shapes are grouped by §35.5's own order — what a place selects, what carries its addresses,
what routes to it, where it runs, its lineage, what it needs in order to run — and then §35.6's
namespace. A shape is declared only where this package actually derives an edge for it: a relation
nothing ever fills is a word a user can `follow` into silence.

**A shape carries no word of its own.** `ADR-0585 (core)` derives the relation id from the shape's
text, so `…pod/1->…node/1` registers `io.github.godspeed-you.kubernetes.pod_to_node` and every
Kubernetes relationship between one pair of kinds arrives under one relation, saying which it is in
the edge's `relation` field. `follow io.github.godspeed-you.kubernetes.pod_to_node` is what a user
types; `scheduled-on` is what travels on the edge.

### 3. `up` is spatial, and it is a separate shape from ownership — and it still is not `up`

§35.6 is explicit that a namespace is a Pod's spatial parent *even though a ReplicaSet owns it*,
and the two are two shapes here for exactly that reason: `…pod_to_namespace` carries `in-namespace`
and `…pod_to_replicaset` carries `controlled-by`. Routing containment through ownership would land
the spatial parent on whichever controller happened to create the object.

**`up` itself still refuses**, and this ADR does not claim otherwise. Landing `up` on a place needs
the plugin-defined aggregate space of §36.4 — id, label, parent domain, membership query, supported
relations, cost, permissions — and `docs/contracts/kuang/contributions.v1.yaml` gives a package no
way to declare one. `ADR-0584 (core)` says so in its own Consequences and refuses with
`spatial.no_parent` naming the missing declaration, which is the honest sentence. What this package
can do is make the spatial parent *reachable* and keep it distinct from ownership; what it cannot
do is make `up` land on it.

`in-namespace` is a word of this contribution's and deliberately not one of
`place.rs::Waypoint`'s. `shares-namespace` is that vocabulary's word for co-tenancy and its
documentation says in as many words that it is not a relationship; using it for containment would
make one word mean two things. It is a field on a record and not a verb, so §35.1's `MUST NOT`
against a Kubernetes mini-shell is untouched: this package still contributes zero verbs.

### 4. Both ends are a lifetime identity, or there is no edge

Every schema this package declares is keyed on `uid`, so the host resolves an end by asking the
target that answers for the schema for `uid == <the key the record carried>`. An `ownerReference`
already carries one. `spec.nodeName`, a volume's `configMap.name` and an Ingress backend's service
name do not — they are names — so the pass resolves them against the objects it read and, where it
read none, **contributes no edge at all**. §35.4 will not let a place be bound to a word two
resource lifetimes can share, and §24.1's unresolved far end stays visible where it belongs: on the
`k8s-relation` record, in the `target_resolved` field.

### 5. Nothing about *which* edges or *in what order* is decided at this boundary

Which edges exist is `relations::stated_edges` — lifted out of the `k8s-relation` handler rather
than copied, so a relationship a user reads and one they walk are the same relationship decided
once — plus `Graph::selects` and `Workload::endpoint_slices` over the objects the same pass read.
How near a neighbour is, and in what order, is `Neighbourhood::ranked`. The test that holds this is
not the Service one, which would pass either way: it is the Pod, where `Graph::edges_of` produces
owner references before `spec.nodeName` and §35.5 ranks placement above lineage, so a boundary
emitting edges in the order it built them puts `controlled-by` first and `ranked` puts
`scheduled-on` first.

Semantic roles stay an overlay (§36.1, §36.3). `Place::roles` is beside `Place::gvk` and never
instead of it; nothing here reads a role, and a Deployment is a `KubernetesDeployment` in the
shell's type vocabulary rather than a workload-shaped anything.

### 6. The contribution is a command, gated on `relation.write`, and it is never granted by default

§36.1 has a package contribute a relationship provider by answering for the shell's own
`spatial-relation` target. It is a **command** rather than a target for ADR-0024's reason read from
the other side: a contributed target declares no capability and a contributed command declares one
the host checks before any of this package's code runs, which is where §35.5 wants the filter.

`relation.write` is in `capabilities.optional` and is never granted by default (§31.19). Without
it, core drops the shapes before the merge and the package is never asked; with it,
`get k8s-pod … | enter; near` answers. What a user must grant, in full:

```
load plugin io.github.godspeed-you.kubernetes \
  --grant network.connect --grant clock.read --grant relation.write
```

### 7. The cost, stated rather than hidden

A merge is one invocation with no arguments, so the pass reads one bounded page of each kind the
shapes name — seventeen listings in the standing scope — and derives every edge from what it read.
Discovery is free after the first (§50.2's session). This is expensive, and `ADR-0585 (core)`
records why it cannot be declared: a contributed relation has no field for a cost class. What can
be done is done: a kind no shape names is not read, a kind the cluster does not serve or does not
let this caller list is skipped rather than failing the pass (§21.4), and the page budget of the
standing query applies.

## Consequences

**Of Gate A's five verbs — installed, discovered, queried, entered, watched — all five are now
reachable**, for a CRD invented after this package was built. `tests/spatial_shell.rs` proves
"entered" over the real `ono` binary, and the CRD case was verified by hand against a recorded
server offering `menagerie.example/v1 Sprocket`: `get k8s-resource --kind <invented> | enter`
gives a place with `identity: {uid: …}`, `identity_tier: lifetime`, and a `look` that reports it
present rather than gone.

**Of §69's eleven verbs, `enter`, `near` and `follow` now reach Kubernetes and `up` and `map` do
not.** `up` is §36.4 above. `map` was not exercised and is not claimed.

**`enter` binds identity and not a name.** Two Pods called `checkout` are two places with two
`spatial_id`s and the two `uid`s their records carried; a shell that bound a place to a name would
answer with one.

What is refused, and how clearly:

- **Invoking the contribution without `relation.write`** is `capability.denied` naming the
  capability, checked by the host before this package runs.
- **`near` at a Kubernetes place without `relation.write`** answers with nothing, and the shell
  says nothing about why. This is the one refusal that is not clear, and it is not this package's
  to fix: §35.5's filter-before-merge means a package without the grant is never asked, so there is
  nobody to produce a message. Recorded on the board as a finding for core.

What still cannot be done:

- **`up` has nowhere to land** — §36.4, above.
- **A contributed relation has no short word.** `follow io.github.godspeed-you.kubernetes.pod_to_node`
  is a mouthful. `ADR-0585 (core)` explains why the host will not invent a shorter one and names
  the declaration that would let a package supply it.
- **One process remembers one standing query.** A place of a kind older than the last
  `k8s-resource` question is re-read against the newer kind and answers as absent. The shell has no
  way to tell a package which place it is re-reading, so this is the shape of the gap rather than a
  choice taken here.
- **`~/.kube/config` is unreachable through a real host.** The supervisor sets the package's `HOME`
  to its sandbox working directory, and the host matches a `filesystem.read` grant against a
  canonicalised absolute path — so the manifest's declared scope `~/.kube/config` matches nothing a
  package can ask for, whether it expands the tilde or not. An operator must pass `kubeconfig` with
  an absolute path, or name the endpoint. Found on the way; on the board, not fixed here.

Which tests encode it:

`crates/ono-kubernetes-plugin/tests/spatial_shell.rs`, over the real `ono` binary, against a
recorded API server on a real socket:

- `should_enter_a_kubernetes_object_as_a_place_bound_to_its_lifetime`
- `should_keep_two_pods_of_one_name_apart_as_two_places`
- `should_answer_near_with_the_neighbours_this_package_contributes` — the Node, the ReplicaSet, the
  account, the Service that selects it and the namespace, each with the package on the edge as
  provider, provenance and evidence origin, and a confidence the host did not raise to `exact`
- `should_follow_a_contributed_relation_to_the_node_a_pod_runs_on`
- `should_reach_the_namespace_a_pod_is_in_without_routing_it_through_the_owner`
- `should_say_why_up_has_nowhere_to_go_from_a_kubernetes_place`
- `should_open_no_exit_from_a_kubernetes_place_without_the_relation_write_grant`

`crates/ono-kubernetes-plugin/tests/query.rs`, under the deterministic test host:

- `should_assert_an_edge_between_two_kinds_of_place_this_package_contributes`
- `should_key_both_ends_of_a_contributed_edge_on_a_lifetime_and_never_on_a_name`
- `should_offer_a_service_its_selected_pods_before_its_slices_and_its_routes` — and the Pod, where
  ranked order and derivation order differ
- `should_relate_a_pod_to_its_namespace_and_to_its_owner_as_two_different_relations`
- `should_assert_no_edge_whose_far_end_this_pass_could_not_bind_to_a_lifetime`
- `should_contribute_no_edge_without_the_relation_write_grant`
- `should_stand_where_the_last_named_endpoint_stood_when_a_query_names_none`
- `should_let_a_query_that_names_an_endpoint_replace_the_standing_one`
- `should_stand_on_the_collection_a_resource_query_named_as_well_as_on_its_endpoint`
- `should_take_the_kubeconfig_s_current_context_when_a_query_names_no_endpoint`
- `should_refuse_a_query_naming_no_endpoint_when_the_kubeconfig_names_no_current_context`

`crates/ono-kubernetes-plugin/tests/contributions.rs`, against the documents on disk:

- `should_declare_the_same_relation_shapes_in_the_manifest_and_in_the_table`
- `should_name_only_schemas_this_package_declares_a_target_for_at_both_ends_of_every_shape`
- `should_relate_only_kinds_the_contribution_actually_reads`
- `should_request_the_capability_that_gates_every_contributed_relation`
- `should_name_the_relations_a_host_would_register_for_these_shapes`
- `should_answer_for_the_core_spatial_relation_target_and_declare_its_capability`

Five mutations were run to confirm the tests bite: keying an edge on the object's name, emitting
containment first, routing containment through the owner, emitting neighbours in derivation order
rather than `ranked` order, and skipping the far-end resolution. Each turned exactly the expected
tests red.

## Alternatives considered

**Leave the argument-less invocation refused, and accept that a Kubernetes place is reported gone
one statement after it is entered.** Rejected: it makes `enter` a word that appears to work and
lies immediately afterwards, and it makes `near` and `follow` unreachable in principle rather than
unimplemented. The refusal was a reading of §7 written when every query came from a person, and
§7.1 lists `current-context` as an element a provider MUST support.

**Take the kubeconfig's `current-context` and nothing else.** Rejected as insufficient rather than
wrong, and it is kept as the third step. The host sets a package's `HOME` to its sandbox working
directory and matches a `filesystem.read` grant against canonicalised absolute paths, so
`~/.kube/config` reaches nothing through a real host; and an operator who named `--host` for
automation or a test never had a kubeconfig in play at all. The standing query answers both cases
and is a replay of what the operator typed rather than a file's opinion.

**Cache the resolved `Endpoint`, credential and all, instead of the options.** Rejected on §8.1: a
credential's material does not travel into anything that outlives one call, and a process-global
holding a bearer token is the thing that boundary exists to prevent. Replaying the *options* costs
one kubeconfig read per invocation and keeps a rotated token honest.

**Declare a relation shape between every pair of Tier 1 kinds.** Rejected: a shape nothing fills is
a relation a user can `follow` into silence, and the load-time check `ADR-0585 (core)` added exists
precisely to keep that from happening. Every shape here has an edge behind it.

**Give the spatial parent no shape at all, on the grounds that `up` is the verb for it and `up`
refuses.** Rejected: §35.6 is a statement about where a Kubernetes object *is*, and the fact that
one verb cannot land on it is not a reason to make the answer unreachable by any means. What is
refused is `up`, clearly and with its reason; what is available is the parent, under a relation
that says it is containment and not ownership.

**Use `Waypoint::SharesNamespace` for the containment edge.** Rejected: its own documentation says
it is not a relationship and that it exists to keep arbitrary namespace co-tenants out of the front
of `near`. Two meanings for one word, in the vocabulary whose whole job is that a word means one
thing.

**Contribute the edges as a target rather than a command.** Rejected for ADR-0024's reason: a
target contribution has nowhere to declare a capability, and §35.5 wants the capability checked
before anything is merged. A command declares it and the host checks it at every invocation.

**Re-sort the neighbours at the boundary, so that `near` gets exactly §35.5's list.**
Rejected — and it would have been three lines. `Neighbourhood::ranked` *is* §35.5's list, with the
two tie-breaks the specification implies underneath it, and a second ordering at the boundary would
be a second answer to a question the domain layer already answers. What the boundary does is emit
in that order.

# ADR-0040: A policy edge is intent read from both ends, evidence has four subjects, and a word nothing answers is refused

- Status: accepted
- Date: 2026-09-06
- Spec refs: §9.5, §13.5, §21.4, §23.3, §23.5, §24.2, §26.1, §27.1, §31.1, §31.2, §31.3, §32.2, §32.3, §35.5, §35.7, §47.1, §47.3, §47.4, §47.6, §47.7, Appendix A, Appendix B, Appendix C.3
- Decided by: agent (autonomous)

## Context

Three `SHOULD`s of the specification left named vocabulary with nothing behind it.

**§31.1 had no code at all.** `NetworkPolicy` reached a user as a schema, a handful of record
fields and a `SemanticRole::Policy` overlay, and it had no relationship: `Graph::selects` reads
`/spec/selector`, which is a Service's shape, and a policy states `/spec/podSelector`. So the one
object an operator names during a connectivity outage was reachable from nothing and reached
nothing. Appendix B listed `protected-by`, and nothing produced it. `Waypoint::ConstrainedBy`
existed as a followable word whose `relation()` returned `None` — a word a user could type into
silence, which is exactly what ADR-0031 and `docs/STATE.md` say is worse than a refusal.

**§47.3 and §47.4 were unexported.** `evidence.rs` published ten keys, all `kubernetes.node.*`,
and `get k8s-evidence` read a Node. A Pod's `status.containerStatuses[]` carries the two
identifiers a future container-runtime provider would resolve on, and a Service's and an
Ingress's `status.loadBalancer.ingress[]` carries the addresses a cloud resolver would. Neither
left this provider. §47.6 also puts a trap in the middle of the second one: `image: nginx:1.25`
and `imageID: …@sha256:…` are two claims of different strength about one container, and the
section forbids confusing tag equality with digest identity.

**Six Appendix B words had no producer**: `selected-by`, `routed-from`, `uses`, `binds`,
`grants-to`, `has-address`. Appendix B says its names "SHOULD be reconciled with the project's
global relationship registry", which is a decision to *make*, not a list to implement.

## Decision

### 1. A policy's reach is one derivation, produced from either end

`Graph::policy_selects(policy, pods)` produces §31.1's own example — `NetworkPolicy -> selects ->
Pod` — and `Graph::protected_by(pod, policies)` produces Appendix B's word for the far end of the
same fact. Both return `SelectorMatch`, so ADR-0007 holds unchanged: a `matchExpressions`
selector is `NotEvaluated` rather than answered by its `matchLabels` subset, which matches *more*
than the selector does.

The word from the Pod's end is `protected-by` and not `selected-by`. They are the reverses of two
different edges: a Service's selector decides where traffic goes, a policy's decides which rules
are written for a Pod, and one word for both ends of both would put a firewall rule in the routing
vocabulary. `Waypoint::ConstrainedBy` is replaced by `Waypoint::ProtectedBy`, which has a relation
behind it.

Two things ride on every policy edge, and they are §31.1's `MUST` and §31.3's:

- the **namespace**, as `Evidence::NativeField` at `/metadata/namespace`, beside the selector and
  the labels that satisfied it. A policy is namespace-local, and an edge that dropped the
  namespace would read as a cluster-wide claim;
- the **intent**, as supporting evidence saying that the API server states this policy and that
  *whether the installed networking implementation enforces it is not observed*. §31.3 draws that
  line and the word `protected-by` alone would blur it — a cluster running no policy controller
  would otherwise read as protected.

An **empty `spec.podSelector` is not an empty selector**. For a Service, empty selects nothing
(§26.1); for a NetworkPolicy the API defines it as every Pod in the namespace, which is how a
default-deny policy is written. Reading the two the same way would report the strictest policy in
a cluster as governing nothing, so the empty case matches namespace-wide and says so in a second
piece of supporting evidence.

**Peers produce nothing.** §31.2 requires ingress and egress peers to keep their native
structure, so no edge is derived from them: an edge to a CIDR block is §31.2's misleading boolean
in a different shape.

### 2. Evidence has four subjects, and the query names which

`NodeEvidence` becomes `SubjectEvidence` with four rules: `of_node` (§47.2, unchanged),
`of_pod` (§47.3, §47.6), `of_load_balancer` for a Service or an Ingress (§47.4), and `of` which
dispatches on GVK and refuses a kind with no rule. Four new keys join the ten:

```text
kubernetes.pod.container-id        distinguishing   qualified by the container
kubernetes.pod.image-id            distinguishing   qualified by the container
kubernetes.pod.image               correlating      qualified by the container
kubernetes.load-balancer.address   correlating      qualified by IP or Hostname
```

`ProviderId` is renamed `SchemedId` — with `ProviderId` kept as an alias for Appendix C.3's name
— and is the one parser for every identifier another system minted. §47.3's `MUST` (preserve the
runtime scheme) is therefore the same code as §28.4's, and `containerd://ab12` and an invented
`quantum-runtime://ab12` come out identically because there is no arm for either. The
decomposition now travels on the item rather than being recomputed per key at the boundary, so an
address is never decomposed into a URI nobody stated.

§47.6's ranking is the third and fourth rows above: an `imageID` names content and is a lookup
key, an `image` is a tag somebody may move tonight and is not.

`get k8s-evidence` takes a **`kind` option defaulting to `Node`**, and namespace joins its
options because three of the four subjects are namespaced. It is deliberately *not*
`k8s-resource`'s resolution over every group the cluster serves: there is no generic evidence
rule — every rule is a set of pointers into one kind's own fields — so a kind resolved through
discovery would be fetched and then refused. Refusing by name, before a cluster is reached, is the
same answer without the read, and it can name the four kinds that do have a rule.

### 3. Four of Appendix B's six words are produced; three are refused by name

| word | decision |
|---|---|
| `selected-by` | **Produced.** §26.1 from the Pod's end, by the same evaluation as `selects`, with the reversal stated as supporting evidence. |
| `routed-from` | **Produced.** §27.1 and §27.3 from the backend's end, by re-reading the router through `ingress_edges` / `gateway_edges` so the two directions cannot disagree. Host, path and port evidence survives the reversal. |
| `protected-by` | **Produced.** §31.1 from the Pod's end (decision 1). |
| `binds` | **Produced.** §32.2's `roleRef` is a native field, and a Role is namespace-local while a ClusterRole is cluster-scoped, so only the first carries the binding's namespace onto the target (§9.5, §24.2). |
| `uses` | **Refused.** This provider has specific words for every dependency it derives — `uses-service`, `uses-secret`, `uses-storage-class`, `mounts`, `references-config`, `runs-as` — and a generic `uses` would blur §29 to §32's classes into one word whose evidence a reader cannot predict. |
| `grants-to` | **Refused.** §32.3: a User and a Group are not stored Kubernetes API objects and the provider MUST NOT imply that a corresponding object exists. A `grants-to` that answered for the ServiceAccount subject and was silent about the User and the Group would read as a binding that grants to one subject — a worse falsehood than the missing word. The subjects stay visible as the binding's own fields. |
| `has-address` | **Refused as a relationship, produced as evidence.** See the deviation below. |

A refused word is not offerable: none of the three parses as a `Waypoint` or appears in
`relations.rs`'s `RELATIONS`, so `get k8s-relation --relation uses` is refused by name with the
words that do answer, rather than completing with nothing.

### 4. A reverse edge is derived on request, and is not registered as a shape

`selected-by` and `routed-from` are answered by `get k8s-relation`, which derives edges from the
one object a query names. They are **not** added to `contributions.relations`: the host registers
a contributed edge once and renders it from both of its ends — `tests/spatial_shell.rs` proves it,
a Pod's `near` already shows the Service that `selects` it — so a registered reverse would put the
same neighbour in `near` twice under two words.

The policy edge *is* new to that graph, so one shape is added:
`networkpolicy/1 -> pod/1`, from the policy's end only.

## Spec deviation

§27.1 lists among the curated relationships an Ingress SHOULD expose:

> `Ingress -> has-address -> status load-balancer address`

**This provider does not emit `has-address` as a relationship.** The far end is not an object: it
has no `metadata.uid`, no collection, and no place in the URI grammar ADR-0008 fixes, so
`Place::of_target` would mint an address that resolves to nothing and a user could `enter` it and
be refused. ADR-0016's rule already covers what to do with such a value — *a value this provider
cannot verify is exported as evidence, never as a link* — and decision 2 exports exactly this
value, from exactly this field, under `kubernetes.load-balancer.address` with its type, its
pointer and `lookup_key: false`. §47.4 says the same thing about the same field in the other
direction: an IP or hostname match alone remains resolver evidence, not a Kubernetes-verified
foreign relationship.

The rule that replaces it: **an Ingress's or a Service's load-balancer address reaches a user as
identity evidence with `get k8s-evidence --kind Ingress`, and never as an edge.** If a later
version of Ono gives a foreign address a place of its own, the edge becomes buildable and this
decision is revisited.

## Consequences

- A NetworkPolicy is reachable and traversable for the first time: `get k8s-relation --kind
  NetworkPolicy --name default-deny` answers with the Pods it is written for, the same query on a
  Pod answers `protected-by`, and `near` on either shows the other.
- A Pod's relationship query now reads two more collections (Services and NetworkPolicies) and a
  Service's reads one more (Ingresses). Each is a `collection` call that records a gap where it
  cannot read, so a cluster that serves no `networking.k8s.io` makes a Pod's relationship query
  *fail naming what was missing* rather than answer a Pod that no policy governs. That is the
  existing rule for the existing derivations (§21.4, ADR-0004), applied consistently — and it is
  the most arguable consequence of this decision.
- `Derived` gains an `unevaluated` list beside its coverage, because "this scope did not answer"
  and "this selector is one this provider does not evaluate" are different sentences and only the
  first is about the cluster. Either one ends the invocation.
- The `k8s-evidence` schema is unchanged: every new key fits the fields §47.7 already required —
  `key`, `qualifier`, `value`, `source`, `strength`, `evidence_class`, `lookup_key`, `uri_scheme`,
  `uri_path`. Only the prose changed, in both the table and the on-disk document.
- `NodeEvidence::of` is now `SubjectEvidence::of_node`, and `evidence_record` no longer takes the
  evidence set — a caller passes one exported item, and the item knows its own decomposition.
- Gate K is unchanged and still checked: no cloud vendor is named in `src/evidence.rs` or in the
  plugin's boundary module, and no runtime is named either.

## Alternatives considered

**`NetworkPolicy -> constrained-by -> Pod`, keeping the existing waypoint.** Rejected.
`constrained-by` is not Appendix B's word, and the reason it existed — that §35.5 names policies
as something to navigate to while nothing derived them — stops being true with decision 1.

**One word, `selects`, for both ends of both the Service edge and the policy edge.** Rejected: the
Pod's end of a Service and the Pod's end of a policy are different facts, and Appendix B gives
them different words for that reason.

**Producing `selects` for a policy with `matchExpressions` from its `matchLabels`.** Rejected by
ADR-0007, which this decision reuses rather than re-argues.

**Answering `protected-by` with the policies whose selectors happened to be evaluable.** Rejected.
"Which policies govern this Pod" is one question; a subset of it presented as the whole is the
claim that no other policy applies. One unevaluated selector makes the whole answer
`NotEvaluated`.

**A `kind` option on `k8s-evidence` that resolves through discovery like `k8s-resource`.**
Rejected: it promises an answer for any kind and then refuses everything but four, after a read.

**One evidence key per subject kind for the load balancer** (`kubernetes.service.load-balancer`
and `kubernetes.ingress.load-balancer`). Rejected: it is the same field stating the same thing,
and a resolver matching an address against an inventory does not care which kind published it.

**Emitting `grants-to` for ServiceAccount subjects only.** Rejected above: a partial answer to
"who does this binding grant to" is more dangerous than no answer, because the missing subjects
are exactly the human ones.

**Emitting `has-address` with a synthetic place for the address.** Rejected: a place a user can
enter and that resolves to nothing is a worse promise than a value they can read.

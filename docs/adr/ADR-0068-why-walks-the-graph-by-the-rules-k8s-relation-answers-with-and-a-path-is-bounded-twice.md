# ADR-0068: `why` walks the graph by the rules `k8s-relation` answers with, and a path is bounded twice

- Status: accepted
- Date: 2026-09-07
- Spec refs: §4 invariants 13, 20; §17.1, §18.3, §21.4, §23, §23.3, §23.4, §35.8, §40.1, §40.3,
  §40.4, §40.5, §49.1, §50.1; §23.4 of the generic provider contract; §11.3 of the Cloud-Native
  Vision; ADR-0007, ADR-0014, ADR-0020, ADR-0025, ADR-0058
- Decided by: agent (autonomous)

## Context

`causal.rs` has had five rungs since ADR-0020, and one of them — `DEPENDENCY_PATH_EXISTS`, "a
relationship path connects them, so influence was possible" — was declared in the schema, listed in
`claim`'s enum, documented in `claim_means`, and produced by nothing a user could invoke. ADR-0025
recorded why at the time: `k8s-why` read no second object, "because a path needs the traversal
`k8s-relation` performs and doing it twice would be a second set of rules that could disagree with
the first." That reasoning was right about the risk and wrong to stop there. A rung that is
declared and unreachable is a public claim the provider cannot make, and §40.3's whole example —
a Service that selects Pods whose EndpointSlices carry no ready endpoint — is a path through the
graph joined to what was observed along it.

The concern ADR-0025 named is real. `relations.rs` decides which edges an object has: what it
states about itself (§23.1, §23.2), and what needs a second reading — a selector evaluated against
a listing, the children an owner's `ownerReferences` prove, the Ingress in front of a Service. A
second traversal written for `why` would be a second place for those rules to live, and the two
would disagree the first time one of them was changed.

Two further things needed deciding before a walk could be honest. A relationship graph has cycles
— a ReplicaSet owns the Pod whose owner reference names it — so a walk that follows every edge
never ends. And every hop beyond the first is a read of somebody else's object, which §49.1 says a
provider must bound rather than take as far as the graph goes.

## Decision

**`k8s-why` derives the subject's edges through `relations::derive`, the one function that
answers `get k8s-relation`, and walks outward from them through `causal::Walk`, which is bounded
in hops and in reads, visits every object once, and reports each edge on the rung it earned.**

The rules, each pinned by a test:

- **One derivation, two routes.** `relations::derive` is the whole of what `Related::run` did
  after resolving its object — the stated edges, then the two-sided ones with their listings
  cached per invocation — lifted out so that `why` calls it for the subject and for every object
  the walk reads. A path `why` shows whole is a path `k8s-relation` would show one hop at a time,
  by construction rather than by review.
- **The rung is the evidence class.** At the first hop, an edge the API server asserts — an owner
  reference, a native field — is reported as `ASSERTED_BY_KUBERNETES` and not also as a weaker
  path beside it: one fact, one finding. An edge this provider derived — a selector it evaluated,
  a convention, an adapter's rule — is `DEPENDENCY_PATH_EXISTS`. Every path beyond the first hop is
  `DEPENDENCY_PATH_EXISTS` whatever its hops rest on, because a path is as strong as its weakest
  hop, and every hop names its class in the sentence so a reader can see which one that is.
- **Bounded twice.** `depth` is the question — how many hops, 1 by default, at most 3, refused
  above that rather than clamped. The read bound is the cost — how many far ends the walk may
  fetch to learn the next hop — and a walk it stops is a coverage gap (`not queried`, in the
  scope of each far end left unread) with `more_available` set, never a shorter answer that looks
  complete (§18.3).
- **Every object once, in a fixed order.** The walk is breadth-first over edges sorted by
  relation, kind, namespace, name and evidence, so an answer does not depend on the order a
  listing came back in. An object reached twice — the subject again through a cycle, a
  Deployment through both `owned-by` and `controlled-by` — is reported along the first path found
  and never read twice.
- **A far end is read as `get k8s-resource --name` reads it**: resolved against discovery by kind
  and, where the reference carries one, group — a kind two groups share with no `apiVersion` on
  the reference is refused as ambiguous rather than picked (§35.8) — and fetched at its own
  endpoint (§17.1), across the redaction boundary before anything derives from it. An absent far
  end is an answer and the edge stands; a denied or unserved one is a gap on the answer; a broken
  connection ends the invocation.
- **A selector this provider does not evaluate is a refusal of its own.** ADR-0007 at a far end:
  the paths that were found are not all of them, and `Unproven::NotEvaluated` says so once.
- **A finding is made once.** `Why::add` refuses a finding equal to one already made. Two Pod
  conditions that each carry no `observedGeneration` are one fact about the object, and counting
  it twice is the summation `strongest_claim` refuses, arriving by another door.

## Consequences

- `DEPENDENCY_PATH_EXISTS` is reachable from a prompt: `get k8s-why --kind Pod --name api` reports
  the Service whose selector the Pod satisfies as a path, and `--depth 2` reports the Deployment
  behind its ReplicaSet as a two-hop path with both owner references on it. Proven at the domain
  (`tests/causal.rs`, nine walk tests), at the provider boundary against a recorded server
  (`tests/query.rs`, three), and against a live cluster whose ReplicaSet a controller made
  (`live_cluster.rs::should_walk_a_pod_to_its_deployment_as_a_dependency_path_over_objects_a_control_plane_produced`).
- `k8s-why` gained one option, `depth`, declared in `contributions/targets.yaml` and read by the
  handler. `timeline::Observed`, the conversation `why` used to share, is gone; `why` has a
  conversation of its own because it reads more than the timeline does.
- The cost of the default answer is unchanged in kind: one hop is what `k8s-relation` already
  spends on the same object. Each further hop is one `GET` per reached object plus whatever
  listings its rules need, read once per invocation across every object the walk touches.
- Nothing is a cause. The walk adds a rung's worth of reach and no vocabulary: the ladder still
  has five words, `should_have_no_vocabulary_for_causation_in_the_module_itself` still reads the
  source, and `strongest_claim` is still a maximum.
- ADR-0025's statement that the rung "does not appear in an answer yet" is superseded by this
  record.

## Alternatives considered

**Remove the rung from the public contract.** Rejected. §40.3 expects the graph to inform `why`,
§11.3 of the Cloud-Native Vision names the word as one of the four Ono should be valuable for
being able to say, and the mechanism it needed — one derivation both routes share — was a
refactor rather than a feature.

**Emit a path finding for every edge, asserted ones included.** Rejected: an owner reference
would then appear twice, once as the assertion and once as a one-hop path, and a reader counting
findings would count one fact twice.

**One path per route to an object.** Rejected: the Deployment behind a ReplicaSet is reachable
along `owned-by` and `controlled-by` at each of two hops, and four sentences about one object say
less than one.

**Clamp `depth` to the bound.** Rejected: an answer for a shallower depth than was asked is a
wrong answer that looks right. Refuse and say what the bound is.

**Bound reads through the transport ledger alone.** Rejected as insufficient: the ledger bounds
requests for the whole invocation and would stop a walk mid-hop with a `partial_result` error,
where §18.3 asks for a stated incomplete answer. The walk's own read bound stops *before* the read
and records the gap; the ledger stays underneath as the invocation's ceiling.

# STATE

The work board for the Ono-Sendai Kubernetes provider. Read it first, update it last, every
session (AGENTS.md §9).

This is not the backlog. The backlog is the
[issue tracker](https://github.com/godspeed-you/ono-sendai-kubernetes/issues); one problem is one
issue, with the evidence that closes it in the issue body. A problem found on the way goes below
under *Found, not yet filed*, and the user triages it into an issue.

---

## Where the project is

**The package runs, speaks TLS, resolves the cluster it talks to from a kubeconfig context, reads
every one of §15.2's nineteen kinds and every kind the cluster serves besides, answers a direct
lookup by name, and says what one object is related to with the evidence under each edge.** A
contributed target answers from an API server over the host's brokered connection, over a session
whose certificate it verified against the authority the context pinned.

The honest counterweight sits beside that sentence: **eleven of the twenty-four domain modules —
10,356 lines and 239 tests — cannot be reached from a prompt.** The library grew faster than the
boundary did this session, and the watch, the session, the live view, the Events, the logs, the
budget, the plan, the mutation, the temporal vocabulary and the causal ladder are all finished,
proven and unreachable.

| | |
|---|---|
| Specification | `docs/architecture/kubernetes-provider.md` — canonical here, immutable, checksummed |
| Domain layer | `crates/ono-provider-kubernetes`, twenty-four modules, no host and no cluster |
| Package | `crates/ono-kubernetes-plugin`, the `ono-kubernetes` binary: contributions, broker, query, dynamic, cluster, records, relations |
| Tests | 584 across the workspace, all green, no live cluster and no network |
| Transport | HTTP/1.1 over a `rustls` session over the host's brokered `network.connect` |
| Conformance level reached | **none claimed.** K0's six requirements are all met and §0.1 binds a claim to the gates; see below |
| Licence | Apache-2.0 (core is MIT) |

The gate has grown to core's shape: `cargo fmt --check`, `cargo clippy -D warnings`, the test
suite and `cargo doc -D warnings` now run beside the specification checksum, the link check, the
ADR check and the instructions check. None of the document checks was dropped (AGENTS.md §10).

| Module | Specification | What it settles |
|---|---|---|
| `kubeconfig` | §7, §8 | a context becomes a connection; a credential cannot reach a `Debug` |
| `discovery` | §11, §13 | what the server serves; `Gvk` and `Gvr` are separate types |
| `object` | §14, §16 | UID is lifetime identity, a name is not (Gate C) |
| `relationship` | §23–§32 | every edge names the evidence it rests on (Gate D) |
| `coverage` | §18, §21 | eight ways to come back with nothing (Gate E) |
| `transport` | §17–§18, §21, §48 | HTTP/1.1 over a byte-stream trait; pagination, coverage, continuity, the whole error taxonomy |
| `watch` | §19, §20 | the `410 Gone` state machine, and the decoder that reads one out of a `200 OK` stream (Gate F) |
| `schema` | §12, §33 | an unknown CRD types fully through a path that names no kind (Gates A, B) |
| `workload` | §25–§27, §30 | `Ingress -> Service -> EndpointSlice -> Pod -> Node`, one edge per hop |
| `condition` | §37 | every derived reconciliation state cites the fields it rests on (Gate G) |
| `redaction` | §22, §29.2 | Secret payload destroyed at the boundary, not filtered at the edge (Gate I) |
| `place` | §9, §35, §36 | addresses that round-trip; cluster and namespace scope are two grammars |
| `diagnostics` | §8.5, §8.6, §10, §34.3 | which cluster this is, whether it answers, as whom, and what is unknown |
| `session` | §6.3, §10.4, §12.4, §19.6, §20 | what one provider instance holds between two invocations, and what empties it |
| `evidence` | §28.3–§28.5, §47 | what a Node states about the machine under it, for someone else to resolve (Gate K) |
| `events` | §38 | best-effort observations, and every reading of them that is not available |
| `live` | §41 | a bounded view of a watch, and the states it may honestly show |
| `logs` | §42 | container logs as observations, and the three remote sessions this cannot open |
| `budget` | §49, §50 | what a query may cost, what it says when it stops, and which verbs may be retried |
| `plan` | §46, §56, §45 | a change described before it is made, and what it refuses to claim |
| `mutation` | §43–§45, §46.3 | what a change is sent as, what came back, and what that still does not prove |
| `temporal` | §39 | when something was observed, by whose clock, and why five clocks are not a timeline |
| `causal` | §40 | what `why` may say about two facts, and the sentence it has no way to construct |
| `tls` | §8.4 | a `rustls` session that is itself a `ByteStream`, below HTTP |

**Section by section, with the evidence for each verdict: [`coverage.md`](coverage.md).** It is the
only place the untouched sections are counted, and it holds the §4 invariant checklist. This board
says what the last session did; that document says where the whole surface stands.

The package reaches the API server through the host's brokered `network.connect` — a real
`ByteStream` over `streams.emit` and `streams.next`, with no fixture fallback — and end-to-end
tests drive the real binary under `ono_kuang_testhost::TestHost` against recorded API bytes. The
whole chain is exercised: handshake, capability broker, connection, HTTP/1.1, discovery, list, get
by name, relationship derivation, redaction boundary, and the host's own stamp on the provenance of
every record it accepts. No cluster is contacted (§59.1).

**All nineteen Tier 1 kinds of §15.2 now carry a schema and a handler**, and the fourteen §31.68
placeholders ADR-0005 held back are gone: `tests/contributions.rs` fails if the static document,
the handshake and the wiring table ever disagree again, and
[ADR-0013](adr/ADR-0013-one-field-name-means-one-thing-across-nineteen-schemas.md) records the rule
that kept the field vocabulary from drifting — one field name means one thing across all of them.

Three further nouns answer beside them.
`k8s-resource` reaches every kind the cluster serves —
[ADR-0010](adr/ADR-0010-a-generic-noun-reaches-every-kind-because-a-static-document-cannot-name-one-invented-later.md).
`k8s-relation` answers what one object is related to, one record per edge, each carrying the
relationship word, both ends as place URIs, the target's roles and four evidence fields that cannot
be dropped —
[ADR-0014](adr/ADR-0014-a-relationship-is-asked-for-as-a-target-of-its-own-and-every-edge-is-one-record.md).
`k8s-cluster` says which cluster this is and who the provider is to it —
[ADR-0011](adr/ADR-0011-the-cluster-diagnostic-is-keyed-on-the-provider-instance-so-two-aliases-cannot-merge.md).

### Conformance, stated honestly

No level is claimed. §0.1 is the reason the assessment is done this way: "any implementation
claiming conformance to a capability or maturity level in this document MUST satisfy the
corresponding acceptance gates." So a level whose requirements are met is still not claimed while
its gate is unproven, and each table below says which of the two is missing.

**K0 — connection and discovery (§61.1): all six requirements met, not claimed.**

| K0 requirement | State |
|---|---|
| kubeconfig / explicit connection | **yes.** A named `context` resolves through `~/.kube/config` — server, default namespace, trust anchors, bearer token, inline client certificate — read under the host's `filesystem.read` capability. An explicit `host` remains §7.3's explicit configuration, and naming neither is refused: no host is ever defaulted. `exec` credential plugins are refused rather than approximated (§8.2) |
| secure TLS defaults | **yes.** `tls.rs` is a `rustls` session below the `ByteStream` trait; verification is on unless `insecure-skip-tls-verify` is set, a certificate authority that does not parse is fatal rather than a fall back to the platform store, and the insecure path is reachable only through a constructor that names it ([ADR-0009](adr/ADR-0009-an-insecure-tls-session-is-reachable-only-through-a-constructor-that-names-it.md)). TLS 1.2 is disabled by the crate's feature set |
| provider instance isolation | **yes**, and this is what changed. `tests/isolation.rs` drives two kubeconfig contexts through one loaded instance and checks each of §6.5's five prohibitions against the decrypted wire transcript: alpha's token never reaches beta's server, beta's namespace never appears in alpha's request path, the two records carry two provider instances, the two diagnostics carry two identities and two fingerprints, and alpha answers identically before and after beta ran. Nothing is shared between queries, so nothing can cross over — and the demonstration now exists rather than the argument |
| dynamic API discovery | **yes.** `/api`, `/apis` and the resource list are read on every query. Version, GVR, namespaced-ness and `list` support come from the server; a cluster serving no `apps` group gets `provider.unsupported` rather than a guessed path |
| cluster / namespace scopes | **yes.** A namespace is a deliberate request, `all_namespaces` is explicit (§9.4), and a cluster-scoped kind gets no namespace segment (§9.2) |
| provider health / identity diagnostics | **yes.** `get k8s-cluster` answers one record for the provider instance: the normalised API server origin, the `kube-system` namespace UID where readable, and the digest they compose, saying which signals it holds (§10.2); the server version and every request's source and latency (§34.3); the TLS posture (§8.4); the effective identity from `SelfSubjectReview` where the cluster serves it (§8.6); and `unknowns`, naming each thing it could not determine with one of §21.4's outcomes |

**What holds K0 back is its gate, not its requirements.** §62.10 asks for two contexts queried
*concurrently*, and the KUANG/11 SDK serves one request at a time: `Plugin::run_io` reads an
envelope, answers it, and reads the next, so opening a second `provider.query` before the first is
drained quarantines the instance with `runtime.protocol_violation`. That was tried and measured
rather than assumed, and the test says so in a comment instead of pinning the violation as the
contract. Two queries in one session, sequentially, is the strongest form of §62.10 this protocol
allows. Whether the gate's word is achievable at all is a question for core; it is filed below.

**K1 — dynamic read model (§61.2): six of seven, not claimed.**

| K1 requirement | State |
|---|---|
| arbitrary discovered readable resources | **yes.** `k8s-resource` resolves whatever the query names against the cluster's own discovery, over the preferred version of every group the server lists. A kind two groups both serve is refused with the candidates (§35.8, §13.5), and *not served*, *not listable*, *ambiguous* and *empty* are four different answers (§11.5, §21.4) |
| dynamic schema / unstructured fallback | **yes.** The API server's OpenAPI v3 document for the resolved group-version types the resource; the component is found by what it declares in `x-kubernetes-group-version-kind` (§13.2). A server that publishes none leaves the typing absent, and every field still projects with its precision saying so (§12.3, §12.5) |
| UID identity | **yes.** Every record's identity field is `metadata.uid`, for a custom resource exactly as for a Pod (§16.1), across all 22 schemas |
| metadata projection | **no, and it is the one that is unmet.** §14.1 names twelve fields; the boundary carries nine. `annotations`, `finalizers`, `ownerReferences` and `managedFields` are projected by `object.rs`, declared by no contributed schema, and excluded from `k8s-resource`'s `other` map because `dynamic::content` filters `metadata` out by design — so no route reaches them. §14.5's and §14.6's `MUST`s are therefore unmet at the boundary, and §14.1's "MUST not pretend the data is absent" is the sentence that bites. Owner references are partly compensated as `k8s-relation` edges and as `controller`/`controller_kind`; annotations and finalizers are not compensated at all |
| get / list / pagination | **yes.** §17.1's direct lookup by name is wired and proven by four end-to-end tests that separate it from the listing: the canonical object endpoint, a `get` that succeeds where `list` is denied, a `404` that is absence rather than an unserved API, and a `403` that is a refused read ([ADR-0012](adr/ADR-0012-a-direct-lookup-by-name-is-its-own-request-and-its-absence-is-an-answer.md)). `list` carries pages and a budget |
| partial coverage and RBAC truth | **yes**, as a failed invocation carrying what was missing ([ADR-0004](adr/ADR-0004-an-incomplete-read-fails-the-invocation-because-a-value-stream-cannot-carry-coverage.md)), and now with a `403` list denial pinned end to end rather than read |
| CRD support | **yes.** A CRD invented after this package was built is discoverable, queryable and returns typed records without recompiling anything, no source file of the plugin crate names the kind the test uses, and its owner references are reachable through the same resolution |

**The board previously rounded metadata projection up and `coverage.md`'s §14 row did not.** The
two disagreed; this is the correction, in the direction the §14 row already pointed. `get` — the
requirement K1 was blocked on yesterday — is met. What replaced it is four field arms in
`records.rs` and four schema entries, which is a smaller gap and a more embarrassing one.

**K2 — operational graph (§61.3): five of seven, not claimed.**

| K2 requirement | State |
|---|---|
| owner references | **yes.** `owned-by`, `controlled-by` and the reversal `owns`/`controls`, the last with `supporting` saying the direction was reversed. An edge whose far end nobody read stays an edge and says so through `target_resolved` (§24.1) |
| core curated workload relations | **yes** for Deployment → ReplicaSet → Pod, StatefulSet and DaemonSet → Pod, CronJob → Job → Pod, and StatefulSet's governing Service. §25.1's `uses-template` edge has no code |
| Service / EndpointSlice relations | **yes.** `selects` derived from the selector against observed labels with the selector-less refusal, `represented-by` through the service-name label with the convention kept as evidence, `endpoint-for` where `targetRef` resolves, and an endpoint without one staying an endpoint fact |
| scheduling relations | **yes.** `scheduled-on` from `spec.nodeName`, and no guess for an unscheduled Pod |
| config / storage relations | partial. `references-config`, `references-secret`, `uses-secret`, `uses-image-pull-secret` and `mounts` are all routed. **§30.2's `PVC → bound-to → PV` has no producer**: `spec.volumeName` is read as a field and never as an edge, so `bound-to` is a word a query may filter on that nothing emits. §29.1's projected volume sources, `initContainers` and `ephemeralContainers` are never scanned |
| spatial integration | **no.** Both ends of every edge are a `place.rs` URI bound to the lifetime identity, which is §35.4 — and they are *strings on a record*, not places in Ono's graph. The package declares no `contributions.relations` and holds no `relation.write` grant, and core's provider trait has no place or relation method, so `enter`, `near`, `up` and `map` do not reach Kubernetes |
| relationship evidence inspection | **yes.** `evidence_class`, `evidence`, `evidence_path`, `asserted` and `supporting` on every edge record, and `should_never_present_an_inference_as_a_relationship` end to end |

**K3 — live Kubernetes (§61.4): all six built, none routed, not claimed.**

| K3 requirement | State |
|---|---|
| list/watch continuity | built. `watch.rs`, and now the decoder that turns a chunked `200 OK` body into `WatchEvent`s, holding a frame split across two chunks |
| reconnect | built. Resume from a checkpoint without recording a gap; a stream that never listed refuses to reconnect |
| 410 gap handling | built. A `410` arriving as an error frame *inside* a successful stream is read as an expiry rather than a generic failure; pre-gap and post-gap are never stitched |
| live-view integration | built. `live.rs`: six states each with its own word, no plain `rows` accessor, and a `stale` state that takes the clock as a parameter |
| cache sync/freshness state | built. `session.rs` synchronises a cache from a listing, refuses to seed one from a partial listing, refuses to read absence from an unsynchronised cache, and stops answering from one whose continuity broke |
| Events as supplemental observations | built. `events.rs`, both representations, counts and series preserved, no ordering, no reason branching |

**Nothing here is reachable.** `ono-kubernetes-plugin` imports none of `watch`, `session`, `live`
or `events`, and no code path anywhere opens a watch. K3 is a routing problem, not a knowledge
problem.

**K4 — bounded safe actions (§61.5): six of seven built, none routed, not claimed — and the
routing is deliberate.**

| K4 requirement | State |
|---|---|
| authorization preflight support | **absent.** `plan::Preflight` has a slot for a `SelfSubjectAccessReview` result and nothing anywhere builds or sends one. `should_not_report_permission_as_granted_when_no_preflight_ran` keeps the slot honest rather than filling it |
| prospective plan | built. `Plan::of` derives §56's preconditions from the object that was read; a plan assembled without them is refused, and `Plan::unguarded` takes a reason and marks the plan for life |
| server dry-run where applicable | built. A dry run is marked as one, is never read as a persisted change, and reports the fields admission changed while excluding the five server-owned metadata pointers |
| conflict / precondition handling | built. A conflict names the manager that owns the field and resolves to `ExplicitChoiceRequired`; the only way to force takes a reason. A `resourceVersion` failure is a lost update and a UID failure is a different object lifetime |
| asynchronous verification | built. `Verdict` has four members and `Inconclusive` is neither success nor failure; a timeout means verification is incomplete rather than that the change failed |
| scoped recovery statement | built. §46.5's two questions kept apart: `Recovery` states in two lists what reapplying would and would not restore, and recreation is never offered as recovery for a deletion |
| deletion / finalizer semantics | built. Propagation policy and UID precondition on the request; a deletion accepted with a finalizer is terminating rather than deleted; a deletion is confirmed only by absence or by a new lifetime under the name |

`plan.rs` and `mutation.rs` are 2,924 lines with 48 tests and are **deliberately not wired**: §43.1
puts read usefulness first, and wiring a write path before the live view is routed would invert
§64's order further than it already is
([ADR-0019](adr/ADR-0019-a-mutation-carries-its-preconditions-or-it-is-refused-and-an-acceptance-is-never-an-outcome.md)).

**K5 — temporal / cross-system enrichment (§61.6): two of five, not claimed.**

| K5 requirement | State |
|---|---|
| explicit observation coverage | built. `coverage.rs`'s eight outcomes and `budget.rs`'s stated overrun; four outcomes are pinned end to end |
| resource snapshot / watch temporal integration | built, unreachable. `temporal.rs` names the clock behind every stamp, refuses to order two written by different clocks, and keeps a timestamp read off current state from becoming an observed change; a `Stamp` implements no comparison trait, so the forbidden sort does not compile. `watch.rs`'s segments and gaps are §39.3. There is no snapshot diff (§39.4 is an untaken `MAY`), and nothing imports either module |
| causal evidence discipline | partial. §40.1's posture reaches a user — every edge states its evidence class, every reconciliation cites its fields, nothing produces a narrative — and §40.5's answer is literally `reconciliation.state == "unknown due to insufficient evidence"`. `causal.rs` is the full five-rung ladder, none of whose rungs says one thing caused another, and it is unrouted. **There is no `why` surface**, so the ladder has no verb to be climbed by |
| exported cross-system identity evidence | built, unreachable. `evidence.rs` exports `spec.providerID`, addresses by type, `systemUUID`, `machineID` and the topology labels, each with a source pointer and one of three ranked strengths, and there is no constructor that turns any of it into a relationship ([ADR-0016](adr/ADR-0016-a-value-this-provider-cannot-verify-is-exported-as-evidence-never-as-a-link-or-a-history.md)). §47.7 says it MUST be inspectable before a foreign provider is connected, and no user can inspect it |
| first verified external resolver path | **absent.** §60.8 step 3 — a synthetic resolver mapping the exported evidence — has no test and no code anywhere |

### Acceptance gates (§62), one row each

A gate is *claimed* only when it is provable end to end through the shell. The column says which
of the three states each is in, and never rounds one up.

| Gate | State | Why |
|---|---|---|
| A — unknown CRD | **partial** | §62.1 names five verbs: installed, discovered, queried, entered and watched. Discovery and query are proven end to end against a recorded server offering an invented group, kind, plural, short name and field set, with a test asserting none of those words appears in any source file of the plugin crate. **Entered and watched are unreachable.** The previous board said "proven end to end"; it was reading three of the five verbs |
| B — no raw-JSON collapse | **end to end** | Proven in both directions in one pair of tests: with a published schema `format: date-time` becomes an instant and `untyped` is empty; without one the same date stays text, every field survives, and each undescribed pointer is named |
| C — UID lifetime | library only | `should_treat_a_recreated_object_as_a_second_lifetime` and `should_read_a_recreated_object_as_an_arrival_rather_than_a_change`. Nothing deletes, so the delete/recreate sequence cannot be driven through the binary |
| D — relationship evidence | **end to end** | Every `k8s-relation` record carries the evidence class, the description, the deciding field where there is one, and whether the API server states it or this provider derived it. All six of §62.4's classes are `Evidence` variants; the sixth, inference, has no producer and a test proves it never appears |
| E — namespace truth | **end to end** | A `403` list denial fails the invocation naming `list denied`, and a `403` on one object is a refused read rather than an absence. A derived edge set that could not enumerate is a gap, not an empty answer |
| F — watch gap truth | library only | The 410 state machine, the gap model and now the decoder that reads a `410` error frame out of a `200 OK` stream. No watch is opened anywhere |
| G — desired/observed separation | **partial** | The read half is end to end: `reconciliation` carries the state, the rule and the fields it rests on, and `verified_convergence` is a key of its own so a matching `observedGeneration` cannot read as health. The gate's own scenario is a Deployment *spec update*, which needs mutation — `should_not_report_an_accepted_deployment_update_as_a_completed_rollout` is library only |
| H — finalizer truth | **partial** | `terminating` is asserted end to end for an object carrying a deletion timestamp. Nothing deletes, so the gate's premise — deletion accepted with finalizers — is reached only in `mutation.rs`'s tests |
| I — secret safety | **end to end** | §62.9 is about the default list, detail and navigation paths, and all three now exist and all three take a `Guarded` — there is no other door into the emission path ([ADR-0003](adr/ADR-0003-secret-payload-is-destroyed-at-the-boundary-rather-than-filtered-on-the-way-out.md)). The list path and the dynamic path each assert the payload appears nowhere in anything the host accepted; the navigation path is guarded by the type and has no payload assertion of its own |
| J — context isolation | **not satisfiable as worded** | The crossover half is proven end to end for credentials, namespaces, identities, fingerprints and record provenance. The gate says *concurrently*, and the SDK serves one request at a time — a second `provider.query` opened before the first is drained quarantines the instance. Filed below as a finding for core |
| K — cross-system decoupling | library only | `spec.providerID` is exported with its source pointer and its strength, no cloud vendor is named anywhere in `evidence.rs` (a test reads the source), and the package links no cloud SDK (a test reads the dependency graph). No user can see any of it |
| L — cancellation | **partial** | The list path has an end-to-end cancellation test. Log follow stops delivering lines when cancelled and a retry stops the moment the caller stops waiting, both library only; watch cancellation has no path at all because nothing opens a watch |
| M — no `kubectl` dependency | unblocked, unproven | The package reaches an `https://` API server named by a kubeconfig context with no `kubectl` and no proxy in the path, and `grep Command::new` over `crates/` is empty. Claiming it wants a run against a real cluster, which nothing in this repository does yet |
| N — current support matrix | untouched | `.github/workflows/ci.yml` has one `ubuntu-latest` job and no Kubernetes version axis |

## The next milestone

The **Cloud-Native Validation Gate** — `docs/strategy/cncf-readiness.md` §2 in core. It is not a
feature; it is the architectural experiment that decides whether the cloud-native direction is
earned, and it is allowed to fail.

The implementation order is the specification's §64, and it is not negotiable by convenience —
each phase is what makes the next one verifiable:

```
Phase 1  connection foundation      provider instance, kubeconfig, TLS/auth, discovery,
                                    navigation root. No mutations.
Phase 2  dynamic resource model     GVK/GVR registry, OpenAPI schema loading, unstructured
                                    conversion, metadata projection, UID identity, get/list/
                                    pagination, CRD fixtures. Proves Kubernetes needs no static
                                    core model.
Phase 3  curated operational graph  semantic adapters and relationships for the Tier 1 set.
Phase 4  live observation           list/watch continuity, reconnect, 410 gaps, freshness.
```

**Phase 1 is closed.** TLS, the kubeconfig wiring, the health/identity diagnostic and provider
instance isolation are all done and driven end to end.

**Phase 2 owes one thing**, and it is not the one it owed yesterday. `get` (§17.1) landed; the
schema cache exists and has an owner in `session.rs` that the plugin does not hold. What is
actually missing is the last third of §14's metadata projection — `annotations`, `finalizers`,
`ownerReferences` and `managedFields` reach no user — and that is the single requirement standing
between here and K1.

**Phase 3 is delivered as records.** Every Tier 1 adapter is wired, and `k8s-relation` routes the
whole `Ingress -> Service -> EndpointSlice -> Pod -> Node` path with the evidence under each hop.
What phase 3 still owes is `near` and `follow` as *verbs*: the semantics are reachable, the
spatial integration is not, because a Kubernetes place is a string on a record rather than a place
in Ono's graph.

**Phase 4 is built and unrouted, and so are phases 5 through 8 in part.** The order was not kept:
`mutation.rs`, `plan.rs` and `logs.rs` are phase 7 and phase 8 work that landed in the library
before phase 4 reached a user. Eleven domain modules — 10,356 lines, 239 tests — cannot be
reached from a prompt. Wiring the session and then the watch is what turns the largest part of
that back into product, and it needs a route rather than new Kubernetes knowledge.

## Proven from a prompt (2026-09-05)

The chain runs end to end against a live HTTP API server, typed at an ordinary shell prompt:

```text
> grant capability network.connect --plugin io.github.godspeed-you.kubernetes
> get k8s-pod --host 127.0.0.1 --port 18002 | to json

[{"uid":"pod-uid-1","name":"checkout-7f9d","namespace":"shop","api_version":"v1","kind":"Pod",
  "resource_version":"884213","created":"2026-09-05T10:00:00Z","labels":{"app":"checkout"},
  "terminating":false,"phase":"Running","node":"ip-10-42-2-19","pod_ip":null,
  "containers":["app"],"restarts":2}]
```

`inspect` on the same record answers what matters more than the fields:

```text
schema      io.github.godspeed-you.kubernetes.pod/1
identity    {"uid": "pod-uid-1"}
provider    plugin:io.github.godspeed-you.kubernetes
```

Identity is the UID and not the name, the schema is the one the target declared, and the
provenance is stamped by the host rather than claimed by the package. `pod_ip` is null because
the fixture's Pod has no address — unknown, never fabricated. The record composes:
`| where phase == "Running" | select name node restarts` filters and projects it like any other.

What the run traverses, in order: the command registry's placeholder for the contributed target,
core's `provider.query` route, the plugin process, the host's brokered `network.connect` with the
operator's grant checked at the call, HTTP/1.1 written by this package, the API server, discovery,
the list, the typed projection, and back through the pipeline.

Three refusals were observed on the way to it, each correct and each worth keeping:

- without a grant, `capability.denied` naming `network.connect`;
- without a context or host, `provider.unavailable` saying this provider does not guess an API
  server;
- against an HTTP/1.0 server that closes each response, a protocol error whose help names TLS as
  the usual cause.

**This is not a claimed conformance level.** It is one target, against one recorded shape, over
plain HTTP. What it establishes is that the route exists and the contracts hold along it.

## In progress

Nothing is half-written. What is next, in the order the phases make each other verifiable:

- **The session, wired (§6.3, §50.2, §12.4, §10.4, §20.2).** `session.rs` holds everything §6.3
  names and the plugin does not import it, so every query still pays for discovery and the
  OpenAPI document again. It is the precondition for the watch and it needs no new Kubernetes
  knowledge — the state type exists and 21 tests pin it.
- **Four metadata fields at the boundary (§14.5, §14.6).** `annotations`, `finalizers`,
  `ownerReferences` and `managedFields`. Four field arms in `records.rs`, four schema entries, and
  K1 turns on it.
- **A watch that is actually opened (§19, §41, K3, Gate F).** The decoder, the state machine, the
  view and the registry all exist; nothing calls them. Needs the session to have somewhere to live.

## The transport decision, and what it costs

The provider reaches the API server over the KUANG/11 brokered connection, and it must speak
HTTPS itself. That is settled, not open: **ADR-0573 in core** decided on 2026-09-03 that
`network.request` is not the host's to serve — "a request is a protocol, HTTP today, whatever
else tomorrow, spoken over a connection the host brokers", and the host carries no client for a
protocol it does not speak. The call stays declared and answers `provider.unavailable` naming the
brokered path, so a package that reaches for it is told where the door is.

The consequence for this provider is written into that ADR: "A package author who needs HTTP
writes it over the brokered connection. That is more work." Concretely, `network.connect` yields
bytes in and bytes out, so the plugin needs TLS and an HTTP/1.1 client of its own before a single
Kubernetes request can be made. §8.4's "TLS validation is on by default" then belongs to this
package rather than to the host.

Both halves are written, tested and driven end to end through the host's broker: the end-to-end
test hands the recorded cluster a `rustls` server identity, and the package handshakes against it
with the authority its kubeconfig pinned. Why the package is a native process, and why it owns
both halves:
[ADR-0002](adr/ADR-0002-the-package-is-a-native-process-and-owns-its-http.md).

## Found, not yet filed

- **The isolation flake was a fixture defect, and the answer is worth keeping (2026-09-06).**
  Diagnosed and fixed, recorded here because the *method* matters more than the fix. The cause was
  not TLS and not the transport: `Fixture::build` named its temporary directory from pid and
  clock, but the three tests run in one process and this host's clock advances in 100 ns steps, so
  two fixtures collided, overwrote each other's kubeconfig, and the loser pinned the winner's
  certificate authority. Because the authority is named after its server, the issuer name matched
  while the key did not — which is why it surfaced as `BadSignature` rather than `UnknownIssuer`,
  and why three earlier readings of the symptom were wrong.

  **The product was cleared by measurement rather than by argument**: with both ends traced on a
  failing run, all seven fixture connections matched a broker connection byte for byte, with zero
  content mismatches, zero chunk-boundary differences and zero swallowed TLS errors. That was the
  question that mattered — a byte stream reordering under load would have corrupted a real cluster
  too — and it was answered with bytes, not reasoning. Fixed with a process-wide counter that
  cannot tie, `create_dir` so a collision fails loudly instead of sharing silently, and a
  regression test verified red without the counter. 12 consecutive clean workspace runs here, 20
  plus a 200-run stress batch by the agent that found it.

- **`get pod` needs core's contributed-target route, which landed on 2026-09-05.** ADR-0582 in
  core wires a contributed *target* to `provider.query`; before it, a package could only answer
  `get` through a contributed *command*, which returns whatever it likes with no declared schema,
  no identity and no provenance. This provider therefore requires a core at or after that commit,
  and the compatibility table in `README.md` must say so once a version of core carries it.
- **~~A contributed target is invoked with no options.~~ Closed in core, verified here
  (2026-09-06).** It was the single largest thing between this package and a claimed gate. Against
  the pinned core checkout, `ono-cli`'s `invoke_contributed` now delegates to `invoke`, which
  turns `--name value` and `--name=value` into the JSON arguments of the plugin protocol; the
  `Map::new()` on the `.target.` branch is gone. `get k8s-pod --context prod` and
  `get k8s-resource --kind Widget` reach the package. Kept rather than deleted, because a finding
  list that quietly loses its largest entry teaches a reader nothing about what moved.
- **Gate J's word cannot be honoured from this side, and that is a question for core.** §62.10
  asks for two contexts queried *concurrently*. The KUANG/11 SDK serves one request at a time —
  `Plugin::run_io` reads an envelope, answers it, reads the next — so a second `provider.query`
  opened before the first is drained arrives where the package is waiting for the response to one
  of its own host calls, and the supervisor quarantines the instance with
  `runtime.protocol_violation`. That was tried and measured. Two queries in one session,
  sequentially, is the strongest form of §62.10 this protocol allows, and it is what
  `tests/isolation.rs` proves; the test records the finding in a comment rather than pinning the
  violation, because a test that asserted it would make it the contract. Either the gate's word
  needs a concurrent invocation path in core, or it needs rewording there.
- **Core registers an invocable target only from the on-disk document, never from the
  handshake.** `ono-kuang-supervisor`'s `load()` validates a handshake target contribution and
  mounts a `PluginProvider` for it; the thing that makes `get <word>` resolve is
  `ono-cli`'s `plugin_registry::target_declarations()`, which reads `contributions/targets.yaml`
  and synthesises one `ContributedCommand` per entry. A handshake-only target name therefore
  yields a provider entry nothing can spell, and it is accepted silently — the reverse
  disagreement (on disk, not answered at handshake) *is* refused, with a good message. This is
  why a discovered CRD cannot earn a name today (ADR-0010), and the asymmetry is worth reporting
  on its own.
- **A target contribution has nowhere to declare its options, so `--kind` cannot be completed or
  helped.** `docs/contracts/kuang/contributions.v1.yaml` gives a target `name`, `schema`,
  `summary` and `identity_doc` and nothing else; the wire type matches and `TargetDocument` is
  `deny_unknown_fields`, so adding an `options:` key is a hard parse failure. Contributed
  *commands* have an `options` key in the contract and core drops it anyway
  (`contract.rs`: "A contribution declares no selectors or options"). `k8s-resource --kind` is
  therefore discoverable only through its `summary` line and this document.
- **A target's declared schema id is not checked against the package's contributed schemas at
  load — and there are no longer any placeholders to be caught by it.** All 22 targets now declare
  a schema the package contributes, and `tests/contributions.rs` holds the document, the handshake
  and the wiring table to each other. The core finding stands and is now only latent: the
  supervisor checks a contributed target's schema id for a package-or-core *prefix*, never against
  the package's contributed schemas. The check that bites is per record — a record whose schema id is
  not in the handshake registry does not decode, and one that decodes but does not match the
  target's declared schema is a `runtime.schema_violation`. So a target with an undeclared schema
  would load happily and fail at its first emit, at runtime rather than at load.
- **§18.4's "more may exist" does not reach the user.** A listing stopped by a page budget is
  coverage-complete by design, so the invocation completes and the `may_have_more` flag the domain
  layer sets is dropped. The value stream has nowhere to carry it, which is the same protocol
  constraint ADR-0004 records for coverage.
- **The plugin's partial-coverage failure path has no end-to-end test.** It is proven at the
  domain level (`tests/transport.rs` keeps the pages that arrived and attaches the error) and the
  mapping from partial coverage to a failed invocation is read rather than run.
- **TLS 1.2 is disabled.** The workspace declares `rustls` with `default-features = false` and
  `["ring", "std", "logging"]`, which leaves out `tls12`. Every current API server negotiates
  TLS 1.3, so this is a bound rather than a gap — and a cluster that offers only TLS 1.2 fails at
  the handshake until the feature is added.
- **A failed handshake does not close its brokered handle.** `TlsStream::connect` consumes the
  stream, so the package cannot ask whether the host still holds the connection; closing one the
  host has already retired is a protocol violation, which is worse. The handle is reclaimed when
  the invocation ends.
- **A kubeconfig `server` with a path prefix is refused.** Rancher-style endpoints
  (`https://host/k8s/clusters/c-xxx`) name one, and this build does not prepend it to its
  requests. Refusing is deliberate: dropping the prefix silently would query a different cluster.
- **The server certificate's public key is modelled and not obtained.** `diagnostics.rs`
  extracts a certificate's `SubjectPublicKeyInfo` and hashes it, with tests over certificates
  generated in the test — and `tls::TlsStream` does not expose the certificate it verified, so
  the plugin has no bytes to hand it. The signal reports `not queried`, which §21.4 keeps apart
  from absence. One accessor on `tls.rs` promotes it from a stated unknown to §10.2's second
  signal, and it was left to the change that owns that module (ADR-0011).
- **§10.4's cache invalidation is written and has no caller.** `Session::observed_fingerprint`
  returns a `ClusterChange` and empties identities, schemas, watches and negotiated capabilities on
  decisive disagreement, keeps them where the evidence still agrees, and does neither where the
  evidence decides nothing — three tests. The plugin holds no session, so nothing at runtime ever
  observes a second fingerprint and the rule has nothing to bite on.
- **Alias detection is a comparison and a memory, and neither survives an invocation.**
  `Fingerprint::compare` answers whether two instances may be one cluster and `Session` now
  remembers one between calls — inside one process, for as long as somebody holds the value.
  Nothing persists it across invocations; `state.persist` is declared in the manifest and unused.
- **Eleven domain modules cannot be reached from a prompt.** `session`, `watch`, `evidence`,
  `events`, `live`, `logs`, `budget`, `mutation`, `plan`, `temporal` and `causal`: 10,356 lines,
  239 tests, zero importers in `ono-kubernetes-plugin`. Two of them are unwired deliberately
  (§43.1 puts read usefulness first). The other nine are finished work waiting on a route, and
  `k8s-relation` is the evidence that adding one is a day's work rather than a phase.
- **`Relation::BoundTo` is a word nothing emits.** A `k8s-relation` query may narrow to
  `bound-to` and will always come back empty, because §30.2's `PVC → bound-to → PV` has no
  producer: `spec.volumeName` is read as a record field and never as an edge. A relation word that
  can be asked for and never answered is worse than one that is refused.
- **§47.7's `MUST` is unmet although the evidence exists.** "Cross-system evidence MUST be
  inspectable even before a foreign provider is connected." `evidence.rs` builds exactly what
  Appendix C.3 spells, with 17 tests, and no target exposes it — so the one requirement the
  section makes about *inspection* is the one thing missing.
- **`current-context` is not taken as a default.** §7.1 offers it as an optional default and §7.4
  forbids a command silently following it when it changes on disk. A context is named; whether a
  deliberate opt-in default is worth adding is open.

## Deferred / blocked

- **A discovered CRD earning a *name* is still open**, and needs a change in core. `k8s-resource`
  is the floor: every kind is reachable, spelled as options. The nicer shape — a discovered
  `Sprocket` becoming its own word with its own help and completion — needs core to register a
  target contributed at handshake time, which it does not do (see the finding below).
  [ADR-0010](adr/ADR-0010-a-generic-noun-reaches-every-kind-because-a-static-document-cannot-name-one-invented-later.md)
  is shaped so that adding it later takes nothing away.
- **§34.2's failure isolation is not honoured on the dynamic search.** A query naming no `group`
  reads the resource list of every group the server lists, and one that does not answer fails the
  query rather than being skipped. That is deliberate — an incomplete search resolving to one
  candidate is indistinguishable from an unambiguous one, and §35.8 is not worth trading for
  convenience — but it means one broken aggregated API server makes an unqualified `--kind` search
  fail. Naming `group` keeps it out of the search. What §34.2 wants instead is the search
  continuing while *saying* which groups it could not read.
- **§12.4's schema cache has an owner the plugin does not hold.** `Session` keeps a
  `SchemaCache` and applies all four of §12.4's invalidation rules — a CRD change, a served
  version set that changed, a withdrawn group, a replaced cluster. Each query still fetches the
  OpenAPI document for the resolved group-version again, because the plugin does not import
  `session`. The two halves now exist and are still not joined, which is §50.2 and §6.3 and §20.2
  all being one absent line of wiring.
- **`docs/contracts/` does not exist.** Whether this provider needs machine-readable contracts of
  its own, or registers everything through core's, is still open. The package's contributions live
  in `package/contributions/*.yaml` and are checked against the handshake by
  `tests/contributions.rs`, which has answered the question in practice without deciding it.
- **No `MAINTAINERS.md`.** Neither here nor in core. It is required before any CNCF Sandbox
  application; inventing one earlier would be the honorary-maintainer anti-pattern the readiness
  document names.

## Session records

### 2026-09-05 — repository established

The Kubernetes Provider Specification moved here from outside any repository, as the single
canonical copy. Core deliberately does not have one: `docs/strategy/cloud-native-vision.md` and
`docs/architecture/external-system-provider.md` stay canonical there and are referenced rather
than duplicated.

Three lines of the specification were changed and no others — its header and inheritance list
named their companions by the filenames they were generated under, which are not the paths those
documents have inside core. Normative content untouched; `docs/architecture/spec.sha256` records
the state from here on.

Added: README, CONTRIBUTING, SECURITY, then the meta framework — `AGENTS.md` inheriting core's
development contract by reference, `CLAUDE.md`, this board, `docs/adr/`, and `scripts/gate.sh`.
The gate was checked against the four regressions it exists to catch: an edited specification, a
specification missing from the path the manifest names, instructions that stop naming the
specification, and a broken relative link. All four turn it red.

`implementation` was created from `main` and pushed, both pointing at the same commit, mirroring
core. It was missing at first: `AGENTS.md` §11 required the branch, the gate refused to run on
`main` and named it as the way out, and CI triggered on it — while the branch did not exist. That
still "worked", because `git switch --create` makes one on the spot, but a branch the policy
depends on should exist deliberately rather than appear as a side effect of the first agent who
reads the refusal.

### 2026-09-05 — the domain layer

Five modules, 63 tests, written test-first, no network and no live cluster. The order was chosen
so that nothing waited on the transport: configuration, then discovery, then identity, then
relationships, then coverage.

Two findings about core came out of it, and both changed the plan rather than the code here:

1. **A contributed target had no route.** `provider.query` was protocol-complete and
   conformance-tested with no call site in the shell, so a package could only answer `get` through
   a command — which returns untyped values. Fixed in core, ADR-0582.
2. **`network.request` is deliberately unserved** (core ADR-0573). The transport is this
   package's own HTTPS over brokered bytes. Recorded above.

### 2026-09-05 — the transport, the package, and the records that were owed

Seven more domain modules — transport, watch, schema, workload, redaction, condition, place — and
then the binary that makes a contributed target real. 243 tests across the workspace. The brokered
connection reached a `ByteStream` with no fixture fallback, and the end-to-end test drives the
real binary under `TestHost` against recorded API bytes.

The vocabulary was merged on the way: `Edge` and `Target` had grown parallel copies in three
modules, and `Edge::new` now takes its evidence as a *constructor argument*, so there is no moment
at which an edge exists without saying where it came from. Gate D in the type rather than in a
review.

Six decisions had been taken during that work and never written down. They are records now, and
the reasoning in the module documentation is where each came from:

| | |
|---|---|
| [ADR-0003](adr/ADR-0003-secret-payload-is-destroyed-at-the-boundary-rather-than-filtered-on-the-way-out.md) | Secret payload is destroyed at the boundary rather than filtered on the way out — including the `last-applied-configuration` annotation, and every kind named `Secret` in every group |
| [ADR-0004](adr/ADR-0004-an-incomplete-read-fails-the-invocation-because-a-value-stream-cannot-carry-coverage.md) | An incomplete read fails the invocation, because a value stream cannot carry coverage. Carries a `Spec deviation` for §18.3 |
| [ADR-0005](adr/ADR-0005-five-schemas-rather-than-nineteen-because-a-declared-schema-is-a-promise.md) | Five schemas rather than nineteen, because a declared schema is a promise |
| [ADR-0006](adr/ADR-0006-resource-version-carries-no-ordering-so-the-forbidden-comparison-does-not-compile.md) | `ResourceVersion` carries no ordering, so the comparison §14.3 forbids does not compile |
| [ADR-0007](adr/ADR-0007-an-unevaluated-selector-says-so-rather-than-returning-the-subset-it-could-evaluate.md) | An unevaluated selector says so rather than returning the subset it could evaluate |
| [ADR-0008](adr/ADR-0008-a-place-uri-has-its-own-grammar-in-which-a-cluster-scoped-object-has-no-namespace-slot.md) | A place URI has its own grammar, in which a cluster-scoped object has no namespace slot |

The board's conformance line was wrong in both directions before this session: it said the domain
layer was under construction, which had stopped being true, and it said no level was reached,
which is still true and for reasons worth naming. K0 is now assessed requirement by requirement
above. Two of its six were unmet at the time this was written — TLS and a health/identity
diagnostic — so the level stayed unclaimed, and the `kubectl proxy` dependency that the missing
TLS created was filed as the thing blocking Gate M.

The next record supersedes half of that: TLS and the kubeconfig wiring landed the same day, which
is why the requirement table above no longer matches this paragraph. The table is the current
assessment; this is what it looked like a few hours earlier.

### 2026-09-05 — TLS, and a context that resolves to a cluster

`tls.rs`: a `rustls` session that is itself a `ByteStream`, so `HttpConnection` never sees a
certificate and the whole request path above it stayed unchanged. 18 tests, of which five run a
real handshake against a `rustls` server on the other end of an in-memory byte stream — an unknown
issuer and a name mismatch are refused, the same server is reachable only once verification was
explicitly disabled, and a server that demands a client certificate is shown one.

The shape that mattered most was making the insecure state hard to reach rather than merely
documented. `Anchors::for_trust` refuses `Trust::Insecure` and names the one constructor that
builds an unverified session, and a certificate authority that does not parse is fatal instead of
falling back to the platform store — a fallback that would verify the server against something the
kubeconfig never named. Both are pinned by tests that were watched to fail first.

`kubeconfig.rs` stopped being unused. A query that names a `context` now reads `~/.kube/config`
through the host's `filesystem.read`, and takes the server, the default namespace, the trust
anchors and the credential from it; a denied read says so distinctly from a context that is not in
the file. `exec` credential plugins are refused with what §8.2 would require, because a wrong
identity reads as an RBAC problem on the cluster and sends the operator to debug something that
was never sent. `Connection` grew the two accessors the connection path needed and nothing more:
the inline client certificate, and the paths a context names for one it does not carry.

The end-to-end test is the one worth keeping: the recorded cluster was given a `rustls` server
identity, and the real binary — under `TestHost`, through `network.connect` — resolved a context,
pinned its authority, handshaked, and put the context's bearer token on every request including
discovery. 270 tests. [ADR-0009](adr/ADR-0009-an-insecure-tls-session-is-reachable-only-through-a-constructor-that-names-it.md)
records the decisions.

Next: the health / identity diagnostic, which is the last thing K0 waits on.

### 2026-09-05 — which cluster is this, and who am I to it

`diagnostics.rs` and the `k8s-cluster` target. 19 domain tests and 6 end-to-end ones through the
real binary under `TestHost`, against a recorded API server that answers `/version`, discovery,
the `kube-system` namespace and a `SelfSubjectReview`.

The shape that mattered was refusing to let one value stand for a cluster. A fingerprint is a set
of *named* signals, each obtained or unavailable for a reason in `coverage::Outcome`'s vocabulary,
because §10.2 says in one sentence that no single signal may be treated as universally available.
So a cluster whose `kube-system` namespace the caller may not read still has a fingerprint — a
weaker one, and `fingerprint_signals` says so — rather than none. The comparison that detects an
alias runs signal by signal and names its evidence, and there is no operation anywhere that merges
two of them: §10.3's prohibition is a function nobody can call.

Three tests were watched to fail first, and one mutation was run to confirm the suite bites: a
`403` on the review mapped to `not served` instead of `read denied` turns the partial-identity
test red, which is the distinction §21.4 exists for.

The credential identity and the effective identity are two fields although nothing sets
impersonation. With none configured one review answers both and they agree; with one, they cannot.
A single field would change meaning the day the second appeared, and so would every reader of it.

[ADR-0011](adr/ADR-0011-the-cluster-diagnostic-is-keyed-on-the-provider-instance-so-two-aliases-cannot-merge.md)
records why the record is keyed on the provider instance rather than on the cluster, and why an
unreachable cluster answers a record rather than failing — the opposite trade from ADR-0004, for
the opposite reason: there, the coverage had nowhere to go in a value stream; here, the coverage
*is* the value.

### 2026-09-05 — a kind the package has never heard of

The two requirements K1 waited on are met: §15.1's arbitrary discovered readable resources, and
CRD support. `schema.rs` had done the hard part since the previous session and nothing routed to
it; this session is the route, and almost none of it is new Kubernetes knowledge.

The decision it needed first was where a CRD's *name* comes from, and the honest answer was found
by reading core rather than by preferring a shape. Two things were checked in a checkout of core
before anything was written. A target contributed across the handshake never becomes an invocable
word — only `plugin_registry::target_declarations()`, reading the on-disk document, does that.
And the SDK fixes a `Plugin`'s contributions before `run()` opens the host session, so a package
cannot know a cluster's CRDs at the moment it declares what it contributes. Handshake-time
contribution is therefore not merely unregistered; it is unreachable. That settled it:
**one static generic noun**, `k8s-resource`, whose kind is a query option.
[ADR-0010](adr/ADR-0010-a-generic-noun-reaches-every-kind-because-a-static-document-cannot-name-one-invented-later.md).

The subtlest part was the schema id, and it has a cost worth naming twice. A record may only
claim a schema its package contributed, the contributions are fixed before any cluster is reached,
and the host enforces this at two points — an unregistered schema id does not decode at all, and
one that decodes but does not match the target's declaration is a `runtime.schema_violation`. So
every dynamically read object, of every kind there will ever be, carries
`io.github.godspeed-you.kubernetes.resource/1`. The Ono schema no longer distinguishes a
`Sprocket` from a `Widget`; §13.2's canonical host type does, from inside the record —
`api_group`, `kind`, `resource_name`, `scope`. A consumer that wants one kind filters on those.

What the route does, and where each part comes from:

| | |
|---|---|
| which resource | `dynamic::resolve` against the preferred version of every group the server lists. A kind two groups share is `resolve.ambiguous` with the candidates and the spelling that picks each — §35.8, never a type priority. Kinds exactly, plurals and short names case-insensitively (§13.5) |
| which fields | the API server's own `/openapi/v3/...` for the resolved group-version, and the component that *declares* the GVK (§13.2). One request types a built-in and a CRD identically, so no permission on `customresourcedefinitions` is needed to understand a custom resource |
| when nothing describes it | `Schema::absent()`. Every field still projects; `schema_source`, `precision` and `untyped` say what nothing vouches for (§12.3, §12.5) |
| four ways to come back with nothing | not served, not listable, ambiguous, and a query that named no kind at all — which is answered with the cluster's own catalogue (§11.5, §21.4) |

Gate A is proven by driving the real binary against a recorded server offering an invented group,
kind, plural, short name and field set, with a test asserting that no source file of the plugin
crate contains any of those words. Gate B is proven in both directions in one pair of tests: with
the schema, `format: date-time` becomes an instant and `untyped` is empty; without it the same
date stays text, every field survives, and each undescribed pointer is named. Three mutations were
run to confirm the tests bite — preferring the first ambiguous candidate, always typing as absent,
and dropping the non-`spec` payload — and each turned exactly the expected test red.

320 tests. `discovery.rs` gained one accessor, `groups()`, because a query that names a kind and
no group has to ask the server which groups it serves; nothing else in the domain layer changed.

Three findings about core came out of the reading, and the first is the largest thing between this
package and a claimed gate: **a contributed target is invoked with no options at all**, so
`--kind` and `--context` alike never reach the package from a shell prompt. Core ADR-0582 names it
as a deliberate later increment. Everything here is proven through `provider.query`, which is the
call core will make once the options half lands.


### 2026-09-06 — a session, a watch that decodes, relationships that reach a user, and the invariant that did not hold

Five increments in one run, and the shape of the repository changed rather than its size. Where
the previous session left a domain library nine of whose fifteen modules the plugin imported, this
one left twenty-four modules of which the plugin imports thirteen — and moved four of the six
things the provider thesis promises onto the far side of the boundary. 584 tests, all green.

**`session.rs` (§6.3, §10.4, §12.4, §19.6, §20).** The one deliberately stateful thing in a crate
where everything else is a function of bytes already received. It holds all nine components §6.3
names across a call, and it does no I/O: a caller reads bytes with `transport` and hands the
results here. That is what makes the awkward sequences ordinary tests — a cluster replaced behind
an unchanged configuration name, an expiry mid-stream, a partial listing that must not become a
cache. §10.4's `MUST` finally has a cache to invalidate, and it empties identities, schemas,
watches and negotiated capabilities on decisive fingerprint evidence and on nothing weaker
([ADR-0015](adr/ADR-0015-a-session-owns-what-outlives-one-call-and-decisive-fingerprint-evidence-empties-it.md)).
**It is not wired to the plugin**, which is the largest single thing this board now owes.

**Watch frames decode (§19).** The gap the previous coverage map named third was "there is no wire
driver: nothing decodes a watch frame into a `WatchEvent`". `WatchDecoder` does, off a real
chunked `200 OK` body read through `HttpConnection`, holding a frame split across two chunks and
refusing a truncated final one. The case that mattered is the `410` that arrives as an *error
frame inside a successful stream* — the watch was opened hours earlier, so `410 Gone` is never a
response code — and it is read as an expiry rather than as a generic failure. §59.2's watch-stream
fixture class stopped being the one built in Rust.

**`evidence.rs` (§28.3–§28.5, §47, Gate K) repaired the one invariant of §4 that did not hold.**
`spec.providerID` is exported with its source pointer, decomposed no further than
`<scheme>://<path>`, ranked above an address, and there is no constructor anywhere that turns
evidence into a relationship. Two tests guard it by reading rather than trusting: one fails if a
cloud vendor is named anywhere in the module including in an example, the other fails if the
package links a cloud SDK
([ADR-0016](adr/ADR-0016-a-value-this-provider-cannot-verify-is-exported-as-evidence-never-as-a-link-or-a-history.md)).
Invariant 20 holds — in the library, and nowhere a user can see it, which is why §47.7's `MUST`
is now the sharpest single unmet sentence in the specification.

**`events.rs` (§38) and `live.rs` / `logs.rs` (§41, §42).** Three sections that had no code. Each
expresses its section's refusals in the shape of its types rather than in a warning: a set of
Events has no sort and no latest, a count has no expand, a search's empty case cannot be absence,
a live view has no plain `rows` accessor, a retrieved log has no accessor meaning "everything it
printed", and a remote session's success type is uninhabited so no caller can hold one
([ADR-0018](adr/ADR-0018-a-remote-session-that-cannot-be-opened-is-a-refusal-that-names-what-is-missing.md)).

**`budget.rs` and the error taxonomy (§48, §49, §50).** §48.2's seventeen classes are complete and
held by a test, because the way a taxonomy decays is one locally reasonable merge at a time; §48.1
now keeps `details.group`, `causes` and `retryAfterSeconds`. `budget.rs` counts the six quantities
a host budget may bound and refuses; an exceeded budget writes a *stated* incomplete result rather
than returning a shorter list. §49.3 is a type rather than a rule: a `RetryPolicy` is constructed
from an `Idempotent`, which has three constructors named after the three read verbs and no other
way in, so the first mutation that wants a retry has to add one and say what makes it replayable
([ADR-0017](adr/ADR-0017-a-refusal-is-classified-on-its-reason-and-a-retry-is-built-from-the-verb.md)).

**`plan.rs` and `mutation.rs` (§43–§46, §56, K4), deliberately not wired.** A plan built from the
object that was read carries §56's preconditions; one assembled by hand without them is refused,
and the way out takes a reason and marks the plan for life. An acceptance can never reach a rung
above `ApiAccepted`, force takes a reason or does not compile, and an inconclusive verification is
its own answer rather than a failure
([ADR-0019](adr/ADR-0019-a-mutation-carries-its-preconditions-or-it-is-refused-and-an-acceptance-is-never-an-outcome.md)).
Nothing sends anything, and §43.1 is the reason that is the right order.

**In the plugin: nineteen kinds, a name, a relationship, and a proof of isolation.** All nineteen
Tier 1 nouns of §15.2 now carry a schema and a handler; ADR-0005's fourteen placeholders are gone
and [ADR-0013](adr/ADR-0013-one-field-name-means-one-thing-across-nineteen-schemas.md) records what
kept the field vocabulary from drifting. §17.1's `get` is a request of its own, with its `404`
meaning absence where a collection's means the API is not served
([ADR-0012](adr/ADR-0012-a-direct-lookup-by-name-is-its-own-request-and-its-absence-is-an-answer.md)).
`k8s-relation` is the route `relationship.rs`, `workload.rs` and `place.rs` had been waiting for:
one object in, one record per edge out, both ends as place URIs, the target's roles beside its
native kind, and four evidence fields that cannot be dropped
([ADR-0014](adr/ADR-0014-a-relationship-is-asked-for-as-a-target-of-its-own-and-every-edge-is-one-record.md)).
`tests/isolation.rs` proves §6.5 against the decrypted wire transcript rather than by argument.

**What the re-derivation found that the previous board had rounded up.** Two corrections, both in
the same direction. Gate A names five verbs and only three of them are reachable — "entered" and
"watched" are not, so the gate is partial rather than proven. And K1's unmet requirement is no
longer `get`, which landed, but **metadata projection**: `annotations`, `finalizers`,
`ownerReferences` and `managedFields` are projected by `object.rs`, declared by no schema, and
filtered out of `k8s-resource`'s payload by design, so no route reaches them and §14.5's and
§14.6's `MUST`s are unmet at the boundary. `coverage.md`'s §14 row had said so all along and the
conformance table had not; the table is the thing that changed.

**`temporal.rs` and `causal.rs` (§39, §40) landed last, and the discipline is in the types.** A
`Stamp` implements no comparison trait, so the cross-clock sort §39.2 forbids does not compile, and
`Stamp::relate` answers `Order::Unordered` where a comparison operator has no room for an answer;
`Basis::Observed` is reachable only through `Observation::watched`, so a Pod created at 08:00 and
first seen at 14:00 cannot be filed as six hours of history. `causal.rs` is a five-rung ladder
whose top rung is `ASSERTED_BY_KUBERNETES` and none of whose rungs says one thing caused another —
`Finding::proximity` cannot be made to return anything stronger than `CORRELATED_WITH` whatever
window it is given, two clocks yield `ClocksDisagree` rather than a number, and a test fails if a
word for causation appears in the module at all
([ADR-0020](adr/ADR-0020-a-timestamp-carries-the-clock-that-wrote-it-and-why-has-no-word-for-cause.md)).
Both are unrouted, which is why §39 stays domain only and §40 stays split across the boundary.

Next, in the order the phases make each other verifiable: wire the session, add the four metadata
fields, then open a watch.

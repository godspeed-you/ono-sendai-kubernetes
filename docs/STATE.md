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
lookup by name, says what one object is related to with the evidence under each edge, holds a
session across invocations, watches a collection live and says which periods it could not observe,
and — under a declared risk and a granted capability — predicts or makes one bounded change.**

The counterweight is much smaller than it was this morning: **two of the twenty-four domain
modules — `live` and `budget`, 1,474 lines and 40 tests — cannot be reached from a prompt.** It
was eleven modules, 10,356 lines and 239 tests. The plugin now imports twenty-two of the
twenty-four.

| | |
|---|---|
| Specification | `docs/architecture/kubernetes-provider.md` — canonical here, immutable, checksummed |
| Domain layer | `crates/ono-provider-kubernetes`, twenty-four modules, no host and no cluster |
| Package | `crates/ono-kubernetes-plugin`, the `ono-kubernetes` binary: contributions, broker, sessions, query, dynamic, changes, cluster, records, relations, events, evidence, logs, timeline, why, conditions, planning, mutations |
| Contributions | 30 targets, 2 commands, 31 schemas, **zero verbs of this package's own** |
| Tests | 642 across the workspace — 498 domain, 144 package — all green, no live cluster and no network |
| Transport | HTTP/1.1 over a `rustls` session over the host's brokered `network.connect` |
| Conformance level reached | **none claimed.** K0 and K1 are met requirement by requirement and §0.1 binds a claim to the gates; see below |
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

**Eleven further nouns answer beside them**, and every one is a noun plus options — the package
contributes no verb of its own (§35.1, §4 invariant 22):

| Word | What it answers |
|---|---|
| `k8s-resource` | every kind the cluster serves, including one invented after this package was built ([ADR-0010](adr/ADR-0010-a-generic-noun-reaches-every-kind-because-a-static-document-cannot-name-one-invented-later.md)) |
| `k8s-relation` | one record per edge, both ends as place URIs, the target's roles, and four evidence fields that cannot be dropped ([ADR-0014](adr/ADR-0014-a-relationship-is-asked-for-as-a-target-of-its-own-and-every-edge-is-one-record.md)) |
| `k8s-cluster` | which cluster this is, whether it answers, as whom, and what is unknown ([ADR-0011](adr/ADR-0011-the-cluster-diagnostic-is-keyed-on-the-provider-instance-so-two-aliases-cannot-merge.md)) |
| `k8s-change` | a live watch: one record per observation, and a `gap` record for each period it could not observe ([ADR-0022](adr/ADR-0022-a-watch-answers-with-a-bounded-observation-and-the-period-it-could-not-observe-is-a-record.md), [ADR-0023](adr/ADR-0023-a-brokered-connection-borrows-the-invocation-for-one-read-so-a-watch-can-answer-while-it-is-still-watching.md)) |
| `k8s-event` | the Events regarding one object, aggregation kept as a count, and a refusal where nothing was observed |
| `k8s-evidence` | what a Node states about the machine under it, exported for someone else to resolve (§47.7) |
| `k8s-log` | one container's log, as lines that carry the bounds of the read |
| `k8s-timeline` | what is known to have happened to one object, and by whose clock |
| `k8s-why` | what may be said about the state an object is in, and the rung above which it may not climb |
| `k8s-condition` | one record per condition, with the reason, the message and the transition time |
| `k8s-plan` | one prospective change, described before anything is sent — read-only, safe to point anywhere |

The six observation nouns and their refusals:
[ADR-0025](adr/ADR-0025-a-refusal-survives-into-the-record-and-an-empty-answer-that-is-not-an-absence-ends-the-invocation.md).

**Two words write, and they are commands rather than targets**, because a target contribution has
nowhere to state a risk or a capability and a command contribution states both — and the host
checks the capability at every invocation before any of this package's code runs
([ADR-0024](adr/ADR-0024-a-mutation-is-a-command-with-a-declared-risk-and-a-granted-capability-and-its-easy-path-is-a-prediction.md)):

```text
set k8s-resource      risk: mutate        capabilities: [network.connect]
remove k8s-resource   risk: destructive   capabilities: [network.connect]
```

Both verbs are core's own. `dry_run` defaults to **true**, so the shortest sentence a user can
write asks the API server to run admission and persist nothing; writing costs one more argument.

### Conformance, stated honestly

No level is claimed. §0.1 is the reason the assessment is done this way: "any implementation
claiming conformance to a capability or maturity level in this document MUST satisfy the
corresponding acceptance gates." So a level whose requirements are met is still not claimed while
its gate is unproven, and each table below says which of the two is missing.

**Two levels are now met requirement by requirement and neither is claimed**, which is the shape
§0.1 exists to produce: K0 waits on Gate J and K1 waits on Gate A, and both gates are about
something this package could do and does not.

**K0 — connection and discovery (§61.1): all six requirements met, not claimed.**

| K0 requirement | State |
|---|---|
| kubeconfig / explicit connection | **yes.** A named `context` resolves through `~/.kube/config` — server, default namespace, trust anchors, bearer token, inline client certificate — read under the host's `filesystem.read` capability. An explicit `host` remains §7.3's explicit configuration, and naming neither is refused: no host is ever defaulted. `exec` credential plugins are refused rather than approximated (§8.2) |
| secure TLS defaults | **yes.** `tls.rs` is a `rustls` session below the `ByteStream` trait; verification is on unless `insecure-skip-tls-verify` is set, a certificate authority that does not parse is fatal rather than a fall back to the platform store, and the insecure path is reachable only through a constructor that names it ([ADR-0009](adr/ADR-0009-an-insecure-tls-session-is-reachable-only-through-a-constructor-that-names-it.md)). TLS 1.2 is disabled by the crate's feature set |
| provider instance isolation | **yes**, and the proof does more work than it did. `tests/isolation.rs` drives two kubeconfig contexts through one loaded instance and checks each of §6.5's five prohibitions against the decrypted wire transcript. Something is now shared between two queries — the session registry — so `should_hold_one_session_per_context_and_nothing_between_two` asserts that alpha discovers once across two queries, that beta discovers its own cluster rather than inheriting alpha's snapshot, and that *every* request each server saw carries its own context's credential, which is how the transcript proves the credential is resolved again rather than taken from state. The session key is the provider instance, the resolved endpoint and the transport posture, and a component may only ever split two invocations, never merge two ([ADR-0021](adr/ADR-0021-a-session-lives-in-the-process-and-is-keyed-on-what-the-operator-configured-never-on-what-the-cluster-said.md)) |
| dynamic API discovery | **yes.** `/api`, `/apis` and the resource list come from the server, and are now read **once per session** rather than once per query — `should_not_run_discovery_again_for_a_second_query_in_one_session` counts the request heads the recorded server saw. A cluster serving no `apps` group gets `provider.unsupported` rather than a guessed path |
| cluster / namespace scopes | **yes.** A namespace is a deliberate request, `all_namespaces` is explicit (§9.4), and a cluster-scoped kind gets no namespace segment (§9.2) |
| provider health / identity diagnostics | **yes.** `get k8s-cluster` answers one record for the provider instance: the normalised API server origin, the `kube-system` namespace UID where readable, and the digest they compose, saying which signals it holds (§10.2); the server version and every request's source and latency (§34.3); the TLS posture (§8.4); the effective identity from `SelfSubjectReview` where the cluster serves it (§8.6); and `unknowns`, naming each thing it could not determine with one of §21.4's outcomes |

**What holds K0 back is its gate, and the gate stopped being someone else's problem.** §62.10
asks for two contexts queried *concurrently*. Until this morning that was unreachable: the SDK
served one request at a time, and a second `provider.query` opened before the first was drained
quarantined the instance with `runtime.protocol_violation`. **`ADR-0586` in core changed that** —
a package may now have several invocations open at once, one worker each, under a ceiling declared
in code by the author (`Plugin::concurrent_invocations`) and in the manifest by the operator
(`runtime.max_concurrent_invocations`), with the smaller of the two winning and a refusal rather
than a quarantine beyond it. That ADR names this provider's Gate J as one of the two pieces of work
that found the bug.

**This provider does not use it, for three independent and checkable reasons:**

1. `Cargo.lock` pins the SDK at core `879d390`, which predates the change — `concurrent_invocations`
   does not exist in the revision this workspace builds against;
2. `sessions::Sessions` is an `Rc<RefCell<BTreeMap<Key, Session>>>`, and the new SDK's handler
   bound is `Fn(&mut Ctx) -> Outcome + Send + Sync`. `Rc` and `RefCell` were chosen deliberately
   because a lock would have suggested a concurrency the protocol did not have (ADR-0021 §1); that
   reason has expired;
3. neither `package/manifest.yaml` nor `plugin()` declares a ceiling, and `tests/isolation.rs`
   still queries the two contexts sequentially — its header still says the SDK serves one request
   at a time, which is true of the pinned revision and no longer true of core.

So Gate J is not "not satisfiable as worded" any more. It is **work owed here**, and it is the one
thing between K0's six met requirements and a claimed level.

**K1 — dynamic read model (§61.2): all seven requirements met, not claimed.**

| K1 requirement | State |
|---|---|
| arbitrary discovered readable resources | **yes.** `k8s-resource` resolves whatever the query names against the cluster's own discovery, over the preferred version of every group the server lists. A kind two groups both serve is refused with the candidates (§35.8, §13.5), and *not served*, *not listable*, *ambiguous* and *empty* are four different answers (§11.5, §21.4) |
| dynamic schema / unstructured fallback | **yes.** The API server's OpenAPI v3 document for the resolved group-version types the resource; the component is found by what it declares in `x-kubernetes-group-version-kind` (§13.2). A server that publishes none leaves the typing absent, and every field still projects with its precision saying so (§12.3, §12.5) |
| UID identity | **yes.** Every record's identity field is `metadata.uid`, for a custom resource exactly as for a Pod (§16.1). All 31 contributed schemas declare an identity and every one names `uid` as a component |
| metadata projection | **yes**, and this is what changed. `annotations` is a map beside `labels` (§14.5); `finalizers` is a list beside `terminating`, which is §14.6 asked twice; `owner_references` is a `list<map>` carrying `controller` and `blockOwnerDeletion`, because a list of names drops the two flags that make a reference more than a name; `field_managers` is §14.7's summary. All four join the shared metadata block, so a discovered CRD reaches them by exactly the route a Pod does — pinned by `should_carry_every_metadata_field_the_projection_names_for_a_curated_kind` and `…_for_a_kind_nobody_compiled_in`. One field is summarised rather than carried: `deletionTimestamp` is the boolean `terminating` on an object record, and its instant reaches a user through `k8s-timeline` as a string beside the clock that wrote it |
| get / list / pagination | **yes.** §17.1's direct lookup by name is wired and proven by four end-to-end tests that separate it from the listing: the canonical object endpoint, a `get` that succeeds where `list` is denied, a `404` that is absence rather than an unserved API, and a `403` that is a refused read ([ADR-0012](adr/ADR-0012-a-direct-lookup-by-name-is-its-own-request-and-its-absence-is-an-answer.md)). `list` carries pages and a budget |
| partial coverage and RBAC truth | **yes**, as a failed invocation carrying what was missing ([ADR-0004](adr/ADR-0004-an-incomplete-read-fails-the-invocation-because-a-value-stream-cannot-carry-coverage.md)), and now with a `403` list denial pinned end to end rather than read |
| CRD support | **yes.** A CRD invented after this package was built is discoverable, queryable and returns typed records without recompiling anything, no source file of the plugin crate names the kind the test uses, and its owner references are reachable through the same resolution |

**K1's requirements are complete and the level is not claimed, because Gate A is not.** §62.1
names five verbs — installed, discovered, queried, entered and watched — and *entered* is
unreachable: nothing in Kubernetes is a place. The correction this board made this morning, that
metadata projection rather than `get` was K1's open requirement, held for exactly one session and
is now closed.

**K2 — operational graph (§61.3): five of seven, not claimed.**

| K2 requirement | State |
|---|---|
| owner references | **yes.** `owned-by`, `controlled-by` and the reversal `owns`/`controls`, the last with `supporting` saying the direction was reversed. An edge whose far end nobody read stays an edge and says so through `target_resolved` (§24.1) |
| core curated workload relations | **yes** for Deployment → ReplicaSet → Pod, StatefulSet and DaemonSet → Pod, CronJob → Job → Pod, and StatefulSet's governing Service. §25.1's `uses-template` edge has no code |
| Service / EndpointSlice relations | **yes.** `selects` derived from the selector against observed labels with the selector-less refusal, `represented-by` through the service-name label with the convention kept as evidence, `endpoint-for` where `targetRef` resolves, and an endpoint without one staying an endpoint fact |
| scheduling relations | **yes.** `scheduled-on` from `spec.nodeName`, and no guess for an unscheduled Pod |
| config / storage relations | partial. `references-config`, `references-secret`, `uses-secret`, `uses-image-pull-secret` and `mounts` are all routed. **§30.2's `PVC → bound-to → PV` has no producer**: `spec.volumeName` is read as a field and never as an edge, so `bound-to` is a word a query may filter on that nothing emits. §29.1's projected volume sources, `initContainers` and `ephemeralContainers` are never scanned |
| spatial integration | **no, and the reason changed.** Both ends of every edge are a `place.rs` URI bound to the lifetime identity, which is §35.4 — and they are *strings on a record*, not places in Ono's graph. It used to be that core's spatial vocabulary was closed to a package. It is not any more: `ADR-0584` in core makes a contributed target a kind of place and `ADR-0585` runs a contributed relation between two contributed kinds. This package declares no contributed kinds of place, no `contributions.relations` and holds no `relation.write` grant, so `enter`, `near`, `up` and `map` still do not reach Kubernetes — and that is now work owed here |
| relationship evidence inspection | **yes.** `evidence_class`, `evidence`, `evidence_path`, `asserted` and `supporting` on every edge record, and `should_never_present_an_inference_as_a_relationship` end to end |

**K3 — live Kubernetes (§61.4): five of six, not claimed.**

| K3 requirement | State |
|---|---|
| list/watch continuity | **yes.** `k8s-change` lists, feeds the listing to `Session::synchronise` — which refuses one that lost a page, because a cache seeded from it would afterwards read every refused object as absent — and opens the watch from the version *that listing* returned. Never from "now" (§19.1) |
| reconnect | **yes.** The server's own watch timeout closes the stream, the checkpoint is still good, and the next request opens at it. A round that delivered nothing is paced by a bounded backoff (50 ms doubling to 1 s, reset by any round that delivered a record) |
| 410 gap handling | **yes.** A `410` arriving as an error frame *inside* a successful `200 OK` stream is read as an expiry rather than a generic failure — which is how a real expiry arrives — and the break is a **record**: `gap`, with both edges, after which `segment` increments and `continuous` is false and never resets. `should_go_on_watching_after_a_gap_rather_than_ending_at_the_break` sees `listed(1) modified(1) gap(1) listed(2) listed(2) added(2)` |
| live-view integration | **no, and it is the one that is unmet.** §41.1's `MUST` is to use the inherited Ono live-view contract. This package opens no host view; what it hands back is a value stream that happens to be live. `live.rs` — the module written for §41 — has no importer, and `stale`, the one of §41.4's six states that belongs to a view rather than to a stream, reaches nobody. The other five reach a user as `sync_state` on every record |
| cache sync/freshness state | **yes.** A cache is refused a partial listing, refuses to read absence before sync, and stops answering when continuity broke; `should_answer_a_watched_object_from_the_cache_and_say_that_is_where_it_came_from` reads a named object out of the session cache with `origin=cache` on its provenance and the object endpoint never asked |
| Events as supplemental observations | **yes.** `get k8s-event`: both representations, counts and series preserved, no ordering, no reason branching, and an unobserved search that *fails* rather than answering empty |

**K3 stopped being a routing problem and became one requirement.** The gate it needs, Gate F, is
now end to end.

**K4 — bounded safe actions (§61.5): six of seven, not claimed.**

| K4 requirement | State |
|---|---|
| authorization preflight support | **absent, and it is the one that is unmet.** `plan::Preflight` has a slot for a `SelfSubjectAccessReview` result and nothing anywhere builds or sends one. `should_not_report_permission_as_granted_when_no_preflight_ran` keeps the slot honest rather than filling it, and every plan a user sees carries `Caveat::PermissionNotVerified` — so the API server remains the only authority, which is §21.1, at the cost of the `AUTHORIZATION` line Appendix E spells |
| prospective plan | **yes.** `get k8s-plan` is a read-only target: discovery, one `GET`, and this provider's rules. It does not dry-run — a dry-run `PATCH` runs admission webhooks, and a word a user may point at anything must not do that — and says `Caveat::AdmissionEffectsNotPreviewed` rather than leaving the omission to be inferred |
| server dry-run where applicable | **yes**, and it is the default. `dry_run` is true unless the caller says otherwise, so the shortest sentence a user can write predicts; the record says `dry_run: true`, `acceptance: "dry run"`, `stage: null`, and carries the label the generic contract §21.4 requires — *provider-native dry run*, which predicts API acceptance and not what controllers do afterwards |
| conflict / precondition handling | **yes.** `should_name_the_owning_manager_on_a_conflict_and_never_force` and `should_force_only_when_a_reason_was_given` run through the real binary. There is no `force` flag anywhere; `force_because` takes the sentence a reviewer will read |
| asynchronous verification | **yes**, in the sense that matters: the verdict is made from a *later observation* rather than from the write's own response. One immediate look with a deadline of `Duration::ZERO`, and what is not decisive at that moment is `Inconclusive` — not `Pending`, because nothing is going to look again |
| scoped recovery statement | **yes.** §46.5's two questions kept apart: `Recovery` states in two lists what reapplying would and would not restore, and recreation is never offered as recovery for a deletion |
| deletion / finalizer semantics | **yes.** `remove k8s-resource` carries the propagation policy and the UID precondition on the request — asserted against the recorded server's body — and a deletion accepted with a finalizer reports `terminating; deletion is pending` with the finalizers beside it. The word "deleted" is not something `DeletionState` can produce |

The deferral `ADR-0019` recorded — "nothing is wired to a user" — is discharged by
[ADR-0024](adr/ADR-0024-a-mutation-is-a-command-with-a-declared-risk-and-a-granted-capability-and-its-easy-path-is-a-prediction.md).
§43.1's ordering was kept: read usefulness reached a user across two sessions before any write did.

**K5 — temporal / cross-system enrichment (§61.6): three of five met, one partial, one absent —
not claimed.**

| K5 requirement | State |
|---|---|
| explicit observation coverage | **yes.** `coverage.rs`'s eight outcomes, five of them pinned end to end; `gaps` and `not_observed` on every timeline record; `segment` and `continuous` on every change record |
| resource snapshot / watch temporal integration | **partial.** The watch half reaches a user: `k8s-change` carries §39.3's segments and gaps. The temporal half reaches a user: `k8s-timeline` names the clock behind every stamp, and because it opens no watch, everything it produces is `Basis::Reported` — a Pod created at 08:00 and first read at 14:00 cannot be filed as six hours of history. **The two do not compose**: no route joins an object's timeline to the watch history of its collection, and there is no snapshot at all (§39.4 is an untaken `MAY`), so §39.3's history is observable and not retrievable |
| causal evidence discipline | **yes.** `get k8s-why` answers one record per finding, each carrying `claim` — one of §40's five words verbatim — `claim_means`, which states where the word stops, and `strongest_claim` on *every* record so a reader who filters to one finding still sees the ceiling, and never a sum. Two clocks yield `CAUSALITY_NOT_PROVEN` with "different clocks wrote the two timestamps" rather than a number. §40.5's required answer is reachable and cheap. The declared schema carries no `cause`, `because`, `root_cause`, `explanation`, `impact` or `trigger`, and `tests/query.rs` reads the field names and fails if one appears. What it cannot yet produce is the `DEPENDENCY_PATH_EXISTS` rung, because a path needs `k8s-relation`'s traversal and doing it twice would be a second set of rules |
| exported cross-system identity evidence | **yes**, and §47.7 with it. `get k8s-evidence --name <node>` renders `spec.providerID`, addresses by type, `systemUUID`, `machineID` and the topology labels before any foreign provider is connected — one record per key, each with its source pointer, its `evidence_class`, its ranked `strength` and a `lookup_key` that documents in as many words that it says nothing about whether anything matches. No constructor turns any of it into a relationship, no cloud vendor is named on the route, and the package links no cloud SDK ([ADR-0016](adr/ADR-0016-a-value-this-provider-cannot-verify-is-exported-as-evidence-never-as-a-link-or-a-history.md)) |
| first verified external resolver path | **absent.** §60.8 step 3 — a synthetic resolver mapping the exported evidence — has no test and no code anywhere. The point of that test is that writing one should require no change here, and nothing has been written |

### Acceptance gates (§62), one row each

A gate is *claimed* only when it is provable end to end through the shell. The column says which
state each is in, and never rounds one up. **Eight of the fourteen are end to end**, up from four.

| Gate | State | Why |
|---|---|---|
| A — unknown CRD | **partial** | §62.1 names five verbs: installed, discovered, queried, entered and watched. Installed, discovered and queried are proven end to end against a recorded server offering an invented group, kind, plural, short name and field set, with a test asserting none of those words appears in any source file of the plugin crate. **Watched is now reachable and unpinned**: `k8s-change` resolves its collection for `Verb::Watch` through the same discovery route `k8s-resource` uses, so a CRD invented later is watchable by construction — and the watch tests use Pods, so nothing asserts it. **Entered is unreachable**, and that is the whole of what blocks K1 |
| B — no raw-JSON collapse | **end to end** | Proven in both directions in one pair of tests: with a published schema `format: date-time` becomes an instant and `untyped` is empty; without one the same date stays text, every field survives, and each undescribed pointer is named |
| C — UID lifetime | **partial** | Three end-to-end tests bite on a reused name from three directions: an Event is refused a later lifetime of the same name, ownership is matched by UID, and every delete carries a UID precondition that the recorded server's request body is asserted against (§56.3). Was *library only*; a delete can now be driven. **The gate's own sequence — delete, recreate under the same name, observe two lifetimes — is still not driven through the binary**, so this is three consequences proven and the premise assumed |
| D — relationship evidence | **end to end** | Every `k8s-relation` record carries the evidence class, the description, the deciding field where there is one, and whether the API server states it or this provider derived it. All six of §62.4's classes are `Evidence` variants; the sixth, inference, has no producer and a test proves it never appears |
| E — namespace truth | **end to end** | A `403` list denial fails the invocation naming `list denied`, and a `403` on one object is a refused read rather than an absence. A derived edge set that could not enumerate is a gap, not an empty answer. Two more shapes joined it: a denied Event scope is a `not_observed` entry on a timeline record, and a denied evidence key is answered as unread rather than omitted |
| F — watch gap truth | **end to end** | `should_make_a_watch_gap_visible_rather_than_stitching_a_history_over_it`, and then the harder one: `should_go_on_watching_after_a_gap_rather_than_ending_at_the_break` sees `listed(1) modified(1) gap(1) listed(2) listed(2) added(2)` and four reads of the collection — the acquisition, the watch that broke, the re-acquisition, and the watch that replaced it. `should_report_the_gap_even_where_the_query_refused_to_pay_for_a_re_acquisition` proves what `reacquire: false` buys back is the second listing and never the gap |
| G — desired/observed separation | **end to end** | The gate's own scenario is a Deployment *spec update*, and it is now driven through the real binary: `should_not_report_an_accepted_deployment_update_as_a_completed_rollout`. The follow-up read shows `generation` ahead of `observedGeneration`, so the record says `stage: API accepted desired-state change`, `verdict: inconclusive`, and a `reconciliation` map carrying the rule and the fields it read. The schema has no `succeeded`, no `rolled_out` and no `healthy`, and `tests/contributions.rs` fails if one is added |
| H — finalizer truth | **end to end** | `should_report_a_deletion_with_a_finalizer_as_terminating_rather_than_deleted` drives `remove k8s-resource` against a server that accepts the deletion and answers with the object: `deletion_state` is `terminating; deletion is pending`, the finalizers are beside it, and the test asserts the word "deleted" appears nowhere in the statement |
| I — secret safety | **end to end** | §62.9's three paths all take a `Guarded`, and so do the three emission paths added since — Events, logs and the mutation answer, whose admission diff is computed against a guarded object so an admission-rewritten Secret cannot be reported verbatim ([ADR-0003](adr/ADR-0003-secret-payload-is-destroyed-at-the-boundary-rather-than-filtered-on-the-way-out.md)). The routes that carry no object payload at all — evidence, timeline, why, condition — are safe by having nothing to leak, which is a weaker guarantee than the type and is recorded as one |
| J — context isolation | **unproven, and now this repository's work** | The crossover half is proven end to end for credentials, namespaces, identities, fingerprints, record provenance and — since the session landed — for discovery not being inherited between two contexts. The gate says *concurrently*, and that is reachable in core since `ADR-0586`. It is not reached here: the SDK is pinned at `879d390`, `Sessions` is `Rc<RefCell<…>>` against a `Send + Sync` handler bound, no ceiling is declared, and `tests/isolation.rs` queries sequentially. This is the only gate whose reason moved *toward* this repository this session |
| K — cross-system decoupling | **end to end** | Was *library only*. `get k8s-evidence` exports `spec.providerID` with its source pointer and its strength through the real binary (`should_export_a_node_s_machine_evidence_with_its_pointer_class_and_strength`); `should_name_no_cloud_vendor_on_the_route_that_exports_machine_evidence` reads the source of the whole route, and a second test reads the dependency graph for a cloud SDK |
| L — cancellation | **partial** | Three of the four operations §62.12 names are end to end: a large list, a watch on an open body (`should_stop_a_live_watch_promptly_when_the_host_cancels_it`, which then answers the next query from the same instance — which is what says the brokered connection was given back), and a verification, which is one immediate observation and has nothing to cancel. **Log follow has no route at all**: `k8s-log` deliberately offers no `follow`, and `LogRequest::following()` is never called, so its cancellation is library only |
| M — no `kubectl` dependency | unblocked, unproven | The package reaches an `https://` API server named by a kubeconfig context with no `kubectl` and no proxy in the path, and `grep Command::new` over `crates/` is empty. Claiming it wants a run against a real cluster, which nothing in this repository does yet |
| N — current support matrix | untouched | `.github/workflows/ci.yml` has one `ubuntu-latest` job and no Kubernetes version axis. `README.md` now states §15.5's five support axes, which is a claim about shape; a matrix is a claim about versions, and only a CI run against two of them supports it |

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

**Phase 2 is closed.** The last thing it owed — §14's metadata projection — landed as four fields
on the shared metadata block, and the schema cache found its owner when the session was wired.
All seven of K1's requirements are met.

**Phase 3 is delivered as records and owes the spatial half.** Every Tier 1 adapter is wired, and
`k8s-relation` routes the whole `Ingress -> Service -> EndpointSlice -> Pod -> Node` path with the
evidence under each hop. What it still owes is `near`, `enter` and `follow` as *verbs*: a
Kubernetes place is a string on a record rather than a place in Ono's graph. The reason changed
this session — core's spatial vocabulary is open to a package now (`ADR-0584`, `ADR-0585`) — so
this is work here rather than a door held shut elsewhere, and it is the largest single item on
the board.

**Phase 4 is closed but for one requirement.** A watch is opened, answers while the body is open,
continues past a gap and stops promptly when the operator does. What is missing is a live *view*:
§41.1's inherited live-view contract is not used and `live.rs` has no importer.

**Phases 5 through 8 landed out of order, and the cost is now visible rather than theoretical.**
Events, temporal, causal, logs, plan and mutation all reach a user. Because phase 7's write landed
in the same session as phase 4's watch, `set k8s-resource`'s answer is verified by one immediate
observation — there is no watch to verify it against, and §46.4's `Inconclusive` is doing work
that a live view would otherwise do.

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

Nothing is half-written. The three items this section carried are all done. What is next, in the
order the phases make each other verifiable — and the first two are the only two things standing
between here and a claimed level:

- **Two invocations at once (Gate J, §6.5, §62.10, K0).** Bump the pinned core past `ADR-0586`,
  make `sessions::Sessions` `Send + Sync` — `Arc` and a lock where `Rc` and `RefCell` are today,
  and the reason the ADR gave for the latter has expired — declare
  `Plugin::concurrent_invocations(n)` and `runtime.max_concurrent_invocations`, and rewrite
  `tests/isolation.rs` so the two contexts overlap. Nothing about this is Kubernetes knowledge,
  and it is the last thing K0 waits on.
- ~~**A Kubernetes object that is somewhere (Gate A, K1, K2, §35.2, §35.3, §35.5, §35.6,
  §53.1–3).**~~ **Done, but for `up` and `map`.** `package/manifest.yaml` declares thirty-three
  `contributions.relations` shapes between the schemas its targets already declare, and
  `spatial.rs` answers for the shell's own `spatial-relation` target under a `relation.write`
  grant. `enter`, `near` and `follow` reach a cluster over the real `ono` binary
  (`tests/spatial_shell.rs`), and **Gate A's five verbs are all reachable**, "entered" included,
  for a CRD invented after the build. `up` refuses with `spatial.no_parent` because §36.4's
  aggregate space is not a package's to declare, and the spatial parent is reachable instead as
  the `…_to_namespace` relation, distinct from `…_to_replicaset` because §35.6 is explicit that
  where a Pod *is* and what owns it are two questions. `map` is untried and unclaimed. ADR-0027.
- **A live view rather than a live stream (§41.1, K3).** The one unmet K3 requirement. `live.rs`
  is written, tested and unimported, and `stale` is the state that reaches nobody.
- **A `SelfSubjectAccessReview` (§21.2, §46.2, K4).** The one unmet K4 requirement, and the
  `AUTHORIZATION` line of Appendix E. `plan::Preflight` has the slot.

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

- **A package cannot read `~/.kube/config` through a real host.** The supervisor sets a package's
  `HOME` to its sandbox working directory (`sandbox.rs`), and the host matches a `filesystem.read`
  grant against a *canonicalised absolute* path — so the scope this package's manifest declares,
  `~/.kube/config`, matches nothing a package can ask for, whether the package expands the tilde
  itself or passes it through. An operator must pass `kubeconfig` with an absolute path, or name
  the endpoint with `host`/`port`. Found while making the argument-less invocation answer
  (ADR-0027); it is core's boundary rather than this package's, and it is why the standing query
  rather than `current-context` is the first fallback.
- **`near` without `relation.write` is indistinguishable from a place with no neighbours.** §35.5
  has the host filter before the merge, and `ADR-0585 (core)` implements it by dropping a
  package's shapes at load — so a package without the grant is never asked and there is nobody to
  say why the answer is empty. This package refuses clearly where it can: invoking its
  contribution directly is `capability.denied` naming the capability. A shell-side hint — "one
  loaded package would contribute exits here and holds no `relation.write`" — is core's to add.

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
- **~~Gate J's word cannot be honoured from this side.~~ Answered in core; now owed here
  (2026-09-06).** The finding was that the KUANG/11 SDK served one request at a time, so a second
  `provider.query` opened before the first was drained quarantined the instance with
  `runtime.protocol_violation`. **`ADR-0586` in core fixed exactly that**, and names this
  provider's Gate J as one of the two pieces of work that found it: `run_io` no longer runs
  package code, an invocation gets a worker of its own, responses are routed by `seq`, and beyond
  a declared ceiling the answer is `runtime.concurrency_limit` rather than a quarantine. The
  ceiling is split deliberately — the author declares thread-safety in code with
  `Plugin::concurrent_invocations(n)`, the operator declares a budget in the manifest with
  `runtime.max_concurrent_invocations`, and the smaller wins — because no manifest can assert
  thread-safety and no package may declare its way past a resource budget.

  **Nothing here uses it yet**, and the three reasons are independent: `Cargo.lock` pins the SDK
  at core `879d390`, which predates the change; `sessions::Sessions` is `Rc<RefCell<…>>` and the
  new handler bound is `Fn(&mut Ctx) -> Outcome + Send + Sync`; and no ceiling is declared in
  either place. `tests/isolation.rs` still queries sequentially and its header still explains why,
  in words that were true this morning. Kept rather than deleted, because a finding that moves
  from "the protocol cannot" to "we have not" is the most useful kind to keep visible.
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
- **A contributed command cannot declare its options either, and there it is worse.**
  `CommandContribution` carries `id`, `verb`, `target`, `summary`, `input`, `output`,
  `capabilities`, `argument_mode`, `risk` and `examples`. Core's own command contracts additionally
  carry `selectors` and `options`, and `contributions.v1.yaml` says a contributed command uses "the
  same metadata schema core commands use" — but the wire type does not carry them and is
  `deny_unknown_fields`. So `dry_run`, `set`, `unset`, `force_because` and `propagation` are
  documented in `package/contributions/commands.yaml` and in each summary, and a shell can complete
  none of them. `dry_run` is the argument that decides whether a cluster changes (ADR-0024).
- **The KUANG/11 provider role has one method, and it is a read.** `protocol.v1.yaml` gives the
  provider role `provider.query` and nothing else, so a mutating provider action must be delivered
  as `command.invoke` — which is why the risk and the capability live on a command contribution.
  Generic contract §21.1 asks an action to declare accepted target types, a parameter schema and
  known idempotency semantics, and a `CommandContribution` has fields for none of the three.
- **There is no capability family for "change state in the external system a provider fronts".**
  The two mutating commands declare `network.connect`, which is the only honest choice: everything
  they do travels as bytes through the network broker, and the broker cannot tell a `GET` from a
  `PATCH`. **An operator who grants this package the ability to read a cluster has, in the same
  act, granted it the ability to write to one.** `service.mutate` and `remote.mutate` carry scope
  keys belonging to other domains, and an unknown capability id makes the manifest
  `package.invalid`, so neither claiming one nor inventing a thirtieth is open. What is missing is
  a `provider.mutate` family scoped by provider instance and resource class (ADR-0024).
- **`audit.event` has no observable channel in the test host.** Generic contract §27.6 asks a
  security-sensitive provider operation to emit an audit record. The host call exists and needs no
  capability, and `Shared::plugin_events` in the supervisor has no public accessor — so a test
  cannot assert that a record was emitted or what it contained, and under "no test, no code" the
  emission was not written. §51.6 is unmet for that reason and no other.
- **The error registry has no code for a refusal by a provider's own safety rule.** A plan refused
  for a missing precondition reports `safety.policy_denied`, whose summary says *configured*
  policy; nothing was configured, the rule is this provider's. The two nearer codes are worse:
  `provider.unsupported` says it cannot, and it can and declines; `provider.unavailable` says the
  cluster did not answer, and it did. The same taxonomy has no entry for "the answer is empty and
  its emptiness proves nothing", which is why `k8s-event` and `k8s-log` reuse
  `provider.unavailable` for their refusals (ADR-0025).
- **A target's declared schema id is not checked against the package's contributed schemas at
  load — and there are no longer any placeholders to be caught by it.** All 30 targets now declare
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
- **~~§10.4's cache invalidation is written and has no caller.~~ It has one, and only one.**
  `cluster::answer` hands the fingerprint it just observed to `Session::observed_fingerprint`,
  which empties discovery documents, schemas, watches, identity and capabilities on decisive
  disagreement. A fingerprint costs a read of `kube-system` and is not something §50.2 will pay
  for on every list, so this is the one moment the package has the evidence — and it means a
  cluster replaced behind an unchanged context name is caught by `get k8s-cluster` and by nothing
  cheaper. `Session::crd_updated` and `group_version_changed` are the two that still have no
  runtime caller, which is §33.2 and the other half of §11.4.
- **Alias detection is a comparison and a memory, and neither survives an invocation.**
  `Fingerprint::compare` answers whether two instances may be one cluster and `Session` now
  remembers one between calls — inside one process, for as long as somebody holds the value.
  Nothing persists it across invocations; `state.persist` is declared in the manifest and unused.
- **~~Eleven domain modules cannot be reached from a prompt.~~ Two can not: `live` and
  `budget`.** 1,474 lines, 40 tests, zero importers in `ono-kubernetes-plugin`, down from eleven
  modules, 10,356 lines and 239 tests. `live.rs` is §41.1's live view and is the one unmet K3
  requirement; `budget.rs` is §49.2's `Retry-After` and §49.5's throttling, and nothing anywhere
  retries anything, so a rate-limited response is classified correctly and waited on never.
- **`Relation::BoundTo` is a word nothing emits.** A `k8s-relation` query may narrow to
  `bound-to` and will always come back empty, because §30.2's `PVC → bound-to → PV` has no
  producer: `spec.volumeName` is read as a record field and never as an edge. A relation word that
  can be asked for and never answered is worse than one that is refused.
- **~~§47.7's `MUST` is unmet although the evidence exists.~~ Met.** `get k8s-evidence` renders
  what Appendix C.3 spells, before any foreign provider is connected, one record per key.
- **`get k8s-event` on a healthy object fails, and that is the most arguable thing here.** An
  operator who asks a healthy Pod for its Events sees a refusal rather than a quiet nothing,
  because an empty Event search is a statement about retention rather than about the cluster
  (§38.6, §63.6). The refusal names the section and is a complete sentence about what was and was
  not established; a pipeline that treated empty as "nothing went wrong" cannot be written by
  accident. `k8s-log` does the same for a retrieval that produced no lines. ADR-0025 records the
  reasoning and the alternatives, and this is the entry to revisit if the shape proves wrong in
  use.
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
- **A Kubernetes object is not a place, and core is no longer the reason.** `ADR-0584` in core
  makes a contributed target a kind of place and `ADR-0585` runs a contributed relation between
  two contributed kinds — the two closures that used to shut `enter`, `near`, `up` and `map` out
  of Kubernetes. This package declares neither, and `place.rs` already builds every address the
  contributions would carry. Deferred rather than blocked, and it is the largest item on the board
  because Gate A, K1's claim and K2's spatial requirement all turn on it.
- **§34.2's failure isolation is not honoured on the dynamic search.** A query naming no `group`
  reads the resource list of every group the server lists, and one that does not answer fails the
  query rather than being skipped. That is deliberate — an incomplete search resolving to one
  candidate is indistinguishable from an unambiguous one, and §35.8 is not worth trading for
  convenience — but it means one broken aggregated API server makes an unqualified `--kind` search
  fail. Naming `group` keeps it out of the search. What §34.2 wants instead is the search
  continuing while *saying* which groups it could not read.
- **~~§12.4's schema cache has an owner the plugin does not hold.~~ Joined.** The package holds
  the session, the OpenAPI document for a resolved group-version is fetched once, and an *absent*
  schema is cached too, because "this server publishes none" is an answer about this cluster and
  re-asking pays §50.2's cost for a document that will not be there next time either.
  `should_read_the_published_schema_once_for_two_queries_of_one_kind`.
- **A stale snapshot is possible within one process, and nothing detects it.** A session caches
  discovery *documents* rather than the assembled snapshot — because §35.8's ambiguity is a
  property of the search space and an answer that depended on what an earlier query happened to
  fetch would not be the same answer twice — and they are invalidated only by a decisive
  fingerprint disagreement or a new process. A CRD installed while a session is live is therefore
  invisible until one of those. §11.4 and §33.2 ask for more; what exists is the place to put it.
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

### 2026-09-06 — the boundary caught up with the library, and one gate changed owner

This record covers five commits (`e37fd85`..`ad03456`) and a re-derivation of
[`coverage.md`](coverage.md) against the tree rather than against the announcement. The shape of
the repository changed rather than its size: where the morning left twenty-four domain modules of
which the plugin imported thirteen, this leaves **twenty-two of twenty-four imported**, 30
contributed targets, 2 contributed commands and 642 green tests.

**The session is wired (§6.3, §50.2, §12.4, §10.4, §20.2).** `sessions::Sessions` is built once in
`plugin()` and handed to every handler by `Rc`, keyed on the provider instance, the resolved
endpoint and the transport posture — a key whose rule is one-directional: a component may only
split two invocations that would otherwise have shared a session, never merge two that would not.
The cluster fingerprint is deliberately *not* in it, because §10.3 says two instances that reach
one cluster are never merged and keying on what the cluster says about itself is exactly how they
would be. It is not `state.persist`: a snapshot restored from disk arrives with no evidence that
it is still about the same cluster, so it is either trusted (and a rebuilt cluster answers from
the previous one's cache, which is §10.4's failure) or re-verified (and the round trips it saved
are spent verifying it)
([ADR-0021](adr/ADR-0021-a-session-lives-in-the-process-and-is-keyed-on-what-the-operator-configured-never-on-what-the-cluster-said.md)).
§50.2 is measured rather than argued, by counting the request heads a recorded server saw.

**§14's last four fields reached the boundary**, so K1's seven requirements are complete. That is
the correction this board made in the morning, closed the same day.

**A watch is opened, and then it stopped being bounded.** `ADR-0022` routed one and recorded, in
its §5, that a *live* watch would need one of three things from core, because `BrokeredStream`
held `&mut Ctx` for as long as the connection lived and `Ctx::emit` needs the same reference.
`ADR-0023` found that reading wrong: nothing in the protocol forced the borrow. `broker::Lease`
owns the reference for the length of one handler and lends it out one caller at a time, so a
handler reads a chunk, releases the context, emits what that chunk decoded to, and reads the next
— with the body open throughout. `ByteStream` was left untouched, because a context parameter on
the trait would have threaded a host concept through `TlsStream`, `HttpConnection`, `Client` and
every domain module that is written against it, to serve one implementation.
`should_emit_a_record_as_each_change_arrives_rather_than_when_the_stream_ends` drives a server
that puts each frame on the wire only when the test releases it, so a record cannot exist unless
the package emitted it while still watching. Gate F is end to end; Gate L holds for a query that
never ends by itself.

**K4 reached a user, and the shape was the decision rather than the code.** `get k8s-plan` is a
target because a plan is a *value* a user can filter, sort and argue with while nothing has
happened; `set k8s-resource` and `remove k8s-resource` are commands because only a command
contribution can declare a `risk` and a capability, and the host checks the capability at every
invocation before this package's code runs. Both verbs are core's own — a `k8s-apply` would have
been the first word of the mini-shell §35.1 forbids. `dry_run` defaults to true, there is no
`force` flag and no `resource_version` or `uid` argument, and the mutation schema has no
`succeeded`, `rolled_out` or `healthy` field, checked by a test. Gates G and H are end to end
([ADR-0024](adr/ADR-0024-a-mutation-is-a-command-with-a-declared-risk-and-a-granted-capability-and-its-easy-path-is-a-prediction.md)).

**Six nouns took the last of the unreachable work across, and the hard part was the refusals.**
Each of `events`, `evidence`, `logs`, `temporal`, `causal` and the rest of `condition` expresses
its section's refusal in the *shape* of a Rust type — no sort, no expand, no accessor meaning
"everything it printed", no comparison trait, no word for cause — and a boundary can lose every
one of those without a wrong value crossing it. So: a time another clock wrote is a `string`
beside a required `clock` and never a `timestamp` a shell could sort; three schemas are checked
against a list of field names they may not carry; an aggregated Event is one record with a count
and there is no route by which 47 becomes 47 records; and where an empty answer is a statement
about the search rather than about the cluster — an Event search that observed nothing, a log
retrieval that produced no lines — the invocation *fails* with that statement rather than
completing empty
([ADR-0025](adr/ADR-0025-a-refusal-survives-into-the-record-and-an-empty-answer-that-is-not-an-absence-ends-the-invocation.md)).
§47.7's `MUST` — the sharpest unmet sentence in the specification that morning — is met.

**What the re-derivation found, and it is the part worth keeping.** Two claims were withdrawn,
both because core moved and this repository did not:

- **Gate J stopped being unsatisfiable.** `ADR-0586` in core gives a package a worker per
  invocation and a ceiling declared twice — by the author in code, by the operator in the
  manifest, smaller wins — and it names this provider's Gate J as one of the two pieces of work
  that found the bug. This package pins the SDK at core `879d390`, which predates it; holds its
  sessions in `Rc<RefCell<…>>` against a handler bound that is now `Send + Sync`; and declares no
  ceiling. So K0's six met requirements wait on work here rather than on a question for core.
- **K2's spatial requirement stopped being core's fault too.** `ADR-0584` and `ADR-0585` make a
  contributed target a kind of place and a contributed relation an edge between two of them. This
  package declares neither, so Gate A's "entered" is still unreachable — and it is the only thing
  standing between K1's complete requirement set and a claimed level.

Both are now the top two items under *In progress*, and neither needs new Kubernetes knowledge.

Counts, so that the next re-derivation has something to disagree with: 13 sections implemented, 53
partial, **0 domain-only and 0 not started**, 4 advisory; 6 appendices partial and 1 advisory; 21
of §4's 22 invariants hold and the twenty-second is aggregated-API failure isolation; 8 of 14
gates end to end.

Next: two invocations at once, then a Kubernetes object that is somewhere.

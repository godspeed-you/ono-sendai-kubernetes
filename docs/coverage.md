# Coverage

What of [the specification](architecture/kubernetes-provider.md) is built, section by section, with the
evidence for each verdict. Written to be argued with: every row names a module, a test, or the
thing that is missing.

This is not [`STATE.md`](STATE.md). The board says what the last session did and what the next one
should do. This document says where the whole surface stands, including the parts nobody has
started, and it is the only place the untouched sections are counted.

Read as a **snapshot taken on 2026-09-05** against `implementation`. One row was already moving
while it was written: §17.1's `get` route appeared in `query.rs` between the reading and the
writing, and the row says what was there when it was read and what has since appeared. A coverage
map that does not date itself is the second way to be dishonest about state.

---

## The headline

Of the **70 numbered sections**, 6 are implemented, 33 are partial, 17 are built and tested in the
domain library with no route to a user, 10 have no code, and 4 are advisory with nothing to
implement. Of the **7 appendices**, 4 are partial, 2 have no code, and 1 is informative. Of the
**22 core invariants of §4**, 12 hold, 3 hold partly, 4 hold only inside the library, 2 are vacuous
because the feature they constrain does not exist, and 1 does not hold.

The number that matters more than any of those: **`ono-kubernetes-plugin` imports nine of the
fifteen domain modules.** It never imports `relationship`, `workload`, `place`, `watch` or
`condition`. Those five modules are 4,410 lines with 112 tests, and no user can reach a single
line of them. Relationships, places, watch continuity and reconciliation state — four of the six
things the provider thesis promises — are built, proven and unreachable.

---

## How a section was classified

| Class | Means |
|---|---|
| **implemented** | The requirements are met and tests pin them. |
| **partial** | Some requirements met; the row names the ones that are not. |
| **domain only** | Built and tested in `ono-provider-kubernetes`, with nothing in `ono-kubernetes-plugin` routing it to a user. Where such a section is *also* incomplete in the library, the row says so — the class is decided by reachability first, because an unreachable capability is not a capability. |
| **not started** | No code. |
| **advisory** | Thesis, open questions or informative notes: there is no requirement to implement. Named as its own class rather than filed under "not started", because a section nobody was asked to build is not a gap. |

A `MAY` nobody took is noted as such and is not counted against the section. A doc comment citing
a section number was treated as a pointer, never as proof: every row below was checked by reading
the code the citation leads to.

---

## The sections

| § | Title | Class | Evidence, or what is missing |
|---|---|---|---|
| 0 | Document Status and Authority | implemented | §0.4 holds: nothing Kubernetes-specific sits in core. The two core changes this package needed (ADR-0573, ADR-0582 in core) are generic provider mechanics. §0.1 holds as discipline — no conformance level is claimed anywhere. |
| 1 | Provider Thesis | advisory | Narrative. Measured against §69 below. |
| 2 | Goals | partial | 2.1, 2.2 and 2.6 are routed. 2.3 (relationships), 2.4 (spatial), 2.5 (live) are domain only. 2.8 (cross-system anchors) has no code. 2.7 is conditional on mutation, which does not exist and is not required yet. |
| 3 | Non-Goals | implemented | Every `MUST NOT` holds: no `kubectl` subprocess anywhere (`grep Command::new` over `crates/` is empty), no Helm/GitOps/metrics dependency, no daemon, and §3.7 is enforced by `redaction.rs` rather than asserted. |
| 4 | Core Invariants | partial | Itemised in [the invariant checklist](#the-22-core-invariants-of-4) below. |
| 5 | Upstream Compatibility Policy | partial | §5.2–§5.4 hold: `diagnostics::ServerVersion` keeps `gitVersion` uninterpreted (`should_keep_the_version_string_the_server_wrote`), every path comes from discovery. **§5.1's `MUST` — a tested compatibility matrix — does not exist**, and `.github/workflows/ci.yml` has one `ubuntu-latest` job with no Kubernetes version axis, so §5.5 is untaken too. |
| 6 | Provider Package, Instance and Session | partial | §6.1, §6.2, §6.4 and §6.5 hold (`kubeconfig::Connection::instance_id`, `should_keep_two_contexts_apart_even_when_they_share_a_server`; `startup: lazy`). **There is no session.** No `Session` type exists in either crate; every invocation re-resolves the endpoint, re-runs discovery and re-fetches the schema, so seven of §6.3's nine components are not held between calls. |
| 7 | kubeconfig and Connection Configuration | partial | §7.1 met for server, CA, users, contexts, current-context-as-default, namespace default, client certificates and bearer tokens — 16 tests in `tests/kubeconfig.rs`. §7.3, §7.4, §7.5 met. **`KUBECONFIG` multi-file merge is absent** (a conditional `SHOULD`); its attached `MUST` — surface the deviation in diagnostics — is unmet, as the `k8s-cluster` record has no field for it. |
| 8 | Authentication and Credential Handling | partial | §8.1, §8.4 and §8.6 implemented and routed ([ADR-0009](adr/ADR-0009-an-insecure-tls-session-is-reachable-only-through-a-constructor-that-names-it.md); `should_refuse_a_malformed_certificate_authority_rather_than_falling_back_to_the_platform_store`; `should_answer_a_partial_identity_when_the_cluster_refuses_a_self_subject_review`). §8.5 is a `MAY`, deliberately untaken with the two-field shape already in place. **§8.2/§8.3 have no code**: an `exec` context is detected and refused, and no `ExecCredential` is parsed, no `interactiveMode` honoured, no expiry handled. EKS, GKE and AKS kubeconfigs do not connect. |
| 9 | Scope Model | partial | §9.2 and §9.4 are enforced at both layers and pinned at the boundary (`§9.2` assertion in `tests/query.rs`; `scope_of` requires an explicit `all_namespaces`). §9.1, §9.3, §9.5 and §9.6 live in `place.rs` with 29 tests and no importer — no record carries a place URI. |
| 10 | Cluster Identity | partial | §10.1 and §10.3 hold, and §10.3's prohibition is a function nobody can call ([ADR-0011](adr/ADR-0011-the-cluster-diagnostic-is-keyed-on-the-provider-instance-so-two-aliases-cannot-merge.md)). §10.2 runs on two of its three signals: `cluster::fingerprint_of` hard-codes the server public key as `NotQueried` because `tls.rs` does not surrender the peer certificate. **§10.4's `MUST` is unmet** — nothing compares a stored fingerprint against a new one, and there is no object cache or watch registry to invalidate. |
| 11 | API Discovery | partial | §11.1 met (`tests/discovery.rs`, 11 tests, including subresources and unmodelled verbs); §11.4 met trivially because discovery is refetched every query; §11.5 met (`should_say_a_kind_is_not_served_rather_than_answer_with_nothing`). **§11.3's `MUST` is unmet**: `discovery::Discovery` holds resources and versions and carries no `provider_instance`, `observed_at`, `api_server`, `coverage` or source-mechanism field. §11.2's aggregated Discovery API is untaken, at the cost of one round trip per group. |
| 12 | OpenAPI and Schema Discovery | implemented | §12.1–§12.3 and §12.5 proven end to end: `should_type_an_unknown_kind_from_the_schema_the_cluster_publishes` and `should_keep_every_field_of_an_unknown_kind_the_cluster_describes_nowhere` are the two directions. §12.4's caching is a `MAY`; `schema::SchemaCache` implements all four invalidation rules and is used only by `tests/schema.rs`. |
| 13 | Kubernetes Type Identity | implemented | `Gvk` and `Gvr` are separate types (`should_not_confuse_the_kind_with_the_rest_resource`); §13.2's five fields are all on `…resource/1` and asserted by `should_answer_for_a_resource_whose_kind_only_the_query_knows`; §13.5 refuses rather than ranks (`should_refuse_an_ambiguous_kind_and_name_the_candidates`). |
| 14 | Common Object Metadata Projection | partial | `object.rs` projects every field §14.1 names, with §14.2–§14.7 each pinned (`should_refuse_to_treat_resource_version_as_a_number_or_a_time`, `should_summarise_managed_fields_rather_than_dropping_them`). **The boundary carries nine fields and drops four**: no contributed schema has `annotations`, `finalizers`, `owner_references` or `managed_fields`, so §14.5's and §14.6's `MUST`s are not reachable by a user. |
| 15 | Resource Inventory and Implementation Tiers | partial | §15.1 is delivered and is the strongest thing in the repository (`should_read_a_kind_this_package_has_never_heard_of`). §15.2: 19 Tier 1 nouns declared, **5 wired** — the rest are §31.68 placeholders reachable through `k8s-resource` ([ADR-0005](adr/ADR-0005-five-schemas-rather-than-nineteen-because-a-declared-schema-is-a-promise.md)). §15.3 untaken. §15.4 has one Gateway adapter, domain only. **§15.5's `MUST` is unmet**: no document states the five support axes separately — this one is a start, not a discharge. |
| 16 | Resource Identity and Lifetime | partial | §16.1, §16.2 and §16.5 hold and are routed (`should_identify_every_kubernetes_object_by_uid_rather_than_by_name`). §16.4 is an untaken `MAY`. **§16.3 is unclear**: the code guarantees two lifetimes never merge, but nothing *emits* a discontinuity — there is no such type and no signal crosses the boundary. Whether "make derivable and never hide" satisfies "MUST emit" is a reading, not a fact. |
| 17 | Read Operations | partial | §17.2 implemented and routed: `Client::list_page` keeps collection `resourceVersion`, `continue` and `remainingItemCount`. **§17.1 `get` had no route when this was read**, and one appeared in `query.rs` while it was being written — a `name` option reaching `client.get(resource.gvr(), scope, name)`. That change does not yet pass `cargo fmt` or `clippy`, so it is reported as arriving rather than as arrived. The domain half was never the gap: `Client::get` carries all six facts §17.1 requires and its path builder is pinned by `should_address_a_single_object_below_its_collection`. §17.3–§17.5 exist in `ListOptions` and are never set by the plugin. §17.6 has no code (`SHOULD`). |
| 18 | Pagination and Large Collections | partial | §18.1–§18.3 implemented and routed, including the snapshot break and the partial-page failure ([ADR-0004](adr/ADR-0004-an-incomplete-read-fails-the-invocation-because-a-value-stream-cannot-carry-coverage.md)); `should_return_the_pages_that_arrived_with_partial_coverage_when_a_later_one_fails`. §18.4 is honoured in `Coverage` but its "more may exist" flag reaches no user. **§18.5 is unmet**: `Client::list` accumulates every page before anything is emitted, which is the opposite of streaming. No plugin test exercises multi-page continuation. |
| 19 | Watch Model | domain only | §19.1, §19.3, §19.4 and §19.5's backoff are complete and pinned by 26 tests, including `should_never_join_pre_gap_and_post_gap_changes_into_one_history`. **It is also unwired inside the library**: `transport::watch_request` has one caller, a test, and nothing anywhere decodes a watch frame into a `WatchEvent` — the state machine is only ever fed by hand. §19.2, §19.6 and §19.7 have no code. |
| 20 | Cache, Freshness and Consistency | domain only | §20.1 is a `MAY` and one of its six caches exists. `Freshness` models `observed_at`, `resourceVersion`, `Origin` and `watch_synced`, and `as_cached` is called only from `should_distinguish_a_cached_observation_from_a_direct_read`. §20.2's `MUST` — the user can tell a cached observation from a direct read — is unreachable twice over: nothing caches, and records carry no freshness field. §20.3 and §20.4 are in `watch.rs` and `condition.rs`, unimported. §20.5 is vacuous. |
| 21 | Authorization and RBAC Truth | partial | §21.1 holds by construction — there is no RBAC evaluator. §21.4's eight outcomes are complete (`should_distinguish_the_eight_ways_a_query_can_come_back_without_objects`) and two branches are routed with plugin tests; **no plugin test pins a 403 list denial reaching a user**. §21.5 is a type invariant, not observed behaviour: `query.rs` issues one request against one scope. §21.2/§21.3 are untaken `MAY`s. §21.6's `explain` surface does not exist. |
| 22 | Secret Handling | implemented | Payload is destroyed at the boundary, not filtered at the edge ([ADR-0003](adr/ADR-0003-secret-payload-is-destroyed-at-the-boundary-rather-than-filtered-on-the-way-out.md)); `records.rs` takes a `Guarded` and never an `Object`. Proven end to end by `should_answer_a_secret_query_with_key_names_and_no_payload_anywhere` and `should_keep_the_redaction_boundary_on_the_dynamic_route`. §22.4's reference edges are domain only. |
| 23 | Relationship Model Overview | domain only | The six evidence classes §62.4 names are the six variants of `Evidence`, and `Edge::new` takes evidence as a constructor argument, so no edge can exist without it (`should_never_produce_an_edge_without_evidence`). §23.5 holds by construction — `Evidence::Inferred` has no producer. **§23.6 is missing**: `Edge` has no freshness field, so nothing bounds a derived edge by its sources. |
| 24 | Ownership Graph | domain only | §24.1–§24.3 met: `Graph::edges_of` emits `owned-by` and, where the flag is set, `controlled-by`, keeping the dangling target inspectable (`should_keep_an_owner_edge_whose_target_cannot_be_read`, `should_distinguish_the_controller_from_a_plain_owner`). §24.4 needs destructive-change planning, which does not exist. |
| 25 | Workload Controller Relationships | domain only | Every owner edge the section names is built and tested in `workload.rs`, including §25.3's claim-templates-as-intent and §25.5's refusal to claim a complete Job history (`should_not_claim_a_complete_job_history_for_a_cronjob`). Only §25.1's `uses-template` edge has no code. |
| 26 | Service and Endpoint Relationships | domain only | §26.1's `MUST`, including the selector-less refusal, and §26.3/§26.4 are pinned (`should_not_invent_selection_for_a_selectorless_service`, `should_keep_every_slice_first_class_rather_than_merging_them`). `exposes-address` is a value rather than an edge, and §26.5's curated Service type does not exist. |
| 27 | Ingress, Gateway and Routing | domain only | `routes-to`, `uses-tls-secret` and `uses-ingress-class` carry host, path, pathType and port as supporting evidence. §27.3's Gateway adapter is version-gated (`should_not_read_an_unrecognised_gateway_api_version_as_if_the_schema_were_known`). **`has-address` from `status.loadBalancer` is not built** — `ingress_edges` reads only `/spec`. |
| 28 | Scheduling and Node Relationships | domain only | §28.1/§28.2 met (`should_not_guess_a_node_for_an_unscheduled_pod`). **§28.4 has no code at all**: `spec.providerID` is read nowhere in `crates/` — it appears only as inert JSON in two fixtures. §28.3 is served only by the raw `labels` map; §28.5 exposes `internal_ip` alone. |
| 29 | Configuration Dependencies | domain only | `envFrom`, `env.valueFrom`, `volumes[].configMap` and `volumes[].secret` produce edges. Missing: projected volume sources (which §29.1 names), `initContainers` and `ephemeralContainers` are never scanned, §29.3's `optional` flag is never read, and §29.4's `immutable` has no code. |
| 30 | Storage Relationships | domain only | Only `Pod → mounts → PVC` is derived. **§30.2's `PVC → bound-to → PV` has no producer**: `Relation::BoundTo` exists in the vocabulary and `spec.volumeName` is never read. §30.3 and §30.4 are reachable only through the generic projection. §30.5 is half met — finalizers are projected, reclaim policy is not typed. |
| 31 | NetworkPolicy and Network Relationships | not started | No code evaluates a NetworkPolicy selector; `Graph::selects` reads `/spec/selector`, which is the Service shape, not `/spec/podSelector`. What exists is vocabulary: a `Waypoint::ConstrainedBy` whose `relation()` deliberately returns `None`, a proximity slot, and a role row. The one test that shows a policy neighbour supplies it by hand. |
| 32 | Identity and RBAC Resources | domain only | §32.1 fully met, namespace-local: `Pod → runs-as → ServiceAccount` and the image-pull-secret reference. §32.2's `binds`/`grants-to` have no `Relation` variant and no code; Role rule sets are not typed. §32.3 is an untaken `MAY`. |
| 33 | CRDs and Arbitrary Custom Resources | partial | §33.1's `MUST` is genuinely delivered end to end, and `should_name_the_invented_kind_nowhere_in_the_implementation` fails the day anyone special-cases a kind ([ADR-0010](adr/ADR-0010-a-generic-noun-reaches-every-kind-because-a-static-document-cannot-name-one-invented-later.md)). §33.3–§33.7 implemented and tested. **§33.2 is a mechanism with no caller** — `SchemaCache::invalidate*` and `CrdVersion::is_served` run only in tests, and no CRD add, delete or storage-version change is detected at runtime. §33.8 has no adapter registry; the sole adapter is hard-coded. |
| 34 | Aggregated API Servers | partial | §34.1 holds structurally. **§34.2's `MUST` is violated in the plugin**: a query naming no group reads the resource list of every served group, and `document()` turns any non-200 into a whole-query `UNAVAILABLE` — one broken aggregated APIService fails the whole provider, and no per-group failure is reported. No test covers it. §34.3 is met (`should_name_the_source_and_the_latency_of_every_request_it_made`). |
| 35 | Spatial Mapping | domain only | All four place shapes round-trip, `up` refuses the owner shortcut, §35.5's ranking and §35.7's five words are implemented, and §35.8's `MUST` is met by `NameEntry::Ambiguous` — 29 tests, no importer ([ADR-0008](adr/ADR-0008-a-place-uri-has-its-own-grammar-in-which-a-cluster-scoped-object-has-no-namespace-slot.md)). The one §35.8-shaped rule a user meets is a separate implementation for *kind* ambiguity in `dynamic.rs`. |
| 36 | Semantic Roles | domain only | `ROLE_OVERLAY` maps about 28 kinds onto the nine candidate roles, matched on group *and* kind, with §36.1 and §36.3 pinned (`should_not_equate_two_places_that_share_a_role`). §36.2 is a `MAY`. No record or target exposes a role. |
| 37 | Conditions and Desired/Observed State | partial | `condition.rs` is complete: structured conditions, verbatim unknown statuses, `should_not_call_an_observed_generation_healthy`, and §37.5's `MUST` that every derived state cite its fields. **The boundary routes a sliver and duplicates it**: `records.rs` does not import `condition` and re-implements a private `Ready` check into one boolean, and no record carries a conditions list or a container reason. `k8s-deployment` does carry `generation` beside `observed_generation`. |
| 38 | Kubernetes Events | not started | No `k8s-event` target, and no `events.k8s.io`, `involvedObject`, `regarding`, `series` or `count` anywhere in `crates/`. |
| 39 | Temporal Integration | domain only | §39.3 is exactly the `Segment`/`WatchGap` model in `watch.rs`, with the canonical scenario tested. §39.4 is an untaken `MAY`; §39.5 is out of the base provider by the spec's own words. Unreachable, because no watch is opened. |
| 40 | `why` and Causal Discipline | domain only | §40.5's required answer exists literally as `ReconciliationState::UnknownInsufficientEvidence`; §40.1's evidence-over-narrative posture is the `Evidence` enum. There is no `why` surface, and §40.2's Event evidence source does not exist. |
| 41 | Live Views | domain only | §41.4's five states are named verbatim in `watch::SyncState` and pinned by `should_give_every_live_view_state_its_own_word`; `Reception::Discarded` prevents the frozen-but-live table. §41.1–§41.3 have no code because the plugin never opens a watch. |
| 42 | Logs, Exec, Attach and Port Forward | not started | No subresource handling of any kind. §42.6's "no hidden `kubectl` subprocess" holds vacuously: the manifest declares no process capability and nothing spawns a process. All of §42 is conditional in the spec and deferred to phase 8 by §64. |
| 43 | Mutation Principles | not started | No PUT, PATCH or DELETE is issued anywhere; the one POST is the `SelfSubjectReview`. §43.1 is the section's only `MUST` and it says read usefulness comes first, so this is the ordering the spec asks for rather than a gap. |
| 44 | Server-Side Apply and Field Ownership | not started | No `fieldManager` on any request, no `dryRun`, no conflict or force handling. `object.rs::field_managers` reads `metadata.managedFields`, which is §14.7's read projection, not §44.2's write-side manager. |
| 45 | Delete, Finalizers and Garbage Collection | not started | Two of §45.1's six distinctions are carried passively — `deletionTimestamp` and `finalizers` are projected and `terminating` reaches the user. There is no DELETE, no propagation policy, no dependent preview. |
| 46 | Prospective Change and Verification | not started | No plan, no dry-run, no change-plan type. The nearest artefact is `ReconciliationStage::ladder()`, which is §46.3's verification vocabulary written for §20.4 and unreachable from the plugin. |
| 47 | Cross-System Identity Evidence | not started | §47.1's *separation* is designed for — `Evidence::Inferred` is documented as never produced here so a resolver has an honest place to put a correlation. **Nothing is exported.** `providerID`, `containerID`, `imageID`, `volumeHandle` and `status.loadBalancer` are read nowhere; the only node evidence emitted is `internal_ip` and `kubelet_version`. |
| 48 | Error Mapping and Partial Failure | partial | `ApiError` splits denial, absence, continuity expiry, rate limiting and protocol failure; `Status` keeps `code`, `reason`, `message`, `details.kind` and `details.name`; §48.3's 404 ambiguity is resolved by the operation that asked. Missing from §48.2's taxonomy: `unauthenticated`, `conflict`, `invalid` and `service_unavailable` all collapse into `Failed { code }`. §48.1's `details.group`, `causes` and `retryAfterSeconds` are unparsed. |
| 49 | API Priority, Fairness, Rate Limits and Retries | partial | §49.2 met — `RateLimited { status, retry_after }` keeps the server's advice verbatim rather than guessing. §49.4's bounded backoff is implemented and tested. **Nothing retries**: `transport.rs` is synchronous with no retry executor, so `Retry-After` is preserved and never waited on. §49.5's configurable QPS/burst/concurrency has no code. §49.3 is moot without mutation. |
| 50 | Performance Requirements | partial | §50.1 met: the package is a separate process and cancellation is checked before the query and between every record (`should_stop_promptly_when_the_host_cancels_a_query`). §50.5/§50.6 met through `Intent`, `default_view.columns` and a page budget. **§50.2 is unmet**: `/api`, `/apis`, the resource list and the OpenAPI document are fetched on every single query. §50.4's relationship indexes do not exist. |
| 51 | Security and KUANG/11 Isolation | partial | §51.1, §51.3 and §51.4 are strong: the manifest declares five capabilities and no process capability, `filesystem.read` is pinned to two kubeconfig paths, and `exec` plugins are refused rather than approximated. §51.2 is brokered but the host set is deliberately unpinned, for a reason the manifest states. §51.5 met via `Guarded`. **§51.6 is unmet** — no audit record is ever emitted. |
| 52 | Presentation and Discoverability | partial | §52.1/§52.2 met: every `default_view` column is a typed field and `restarts` is `null` rather than `0` when the status is silent. §52.3 is partly served by `Intent`'s spec/status/other/untyped split, with no relationships, events or permissions sections to organise. §52.4 has no code; §52.5 is host-side. |
| 53 | Native Ono Interaction Examples | domain only | Three of nine have their semantics in the library and no route: §53.4 (`near` ranking), §53.5 (`follow`), §53.6 (relation evidence). **Six have no code at all**: §53.1, §53.2, §53.3, §53.7, §53.8, §53.9. Nothing here is typeable at a prompt today. |
| 54 | Autoscaling and Controller Interaction | not started | No `HorizontalPodAutoscaler` reference anywhere. §54.1's evidence source is half-present — `field_managers()` returns the distinct managers — and it is exposed in no schema, so no competing-writer warning can be shown. |
| 55 | Namespace Semantics and Bulk Operations | partial | §55.1 implemented and routed: `scope_of` defaults to the context namespace and requires an explicit `all_namespaces`, and a cluster-scoped kind gets no namespace segment. §55.2, §55.3 and §55.4 need a delete and a bulk path, neither of which exists. |
| 56 | API Object Mutation Preconditions | not started | Nothing mutates, so nothing has preconditions. The raw materials are in place and unused: `ResourceVersion` is deliberately non-orderable ([ADR-0006](adr/ADR-0006-resource-version-carries-no-ordering-so-the-forbidden-comparison-does-not-compile.md)) and §56.3's UID precondition is exactly the identity `object.rs` already enforces. |
| 57 | Provider Manifest Requirements | partial | `package/manifest.yaml` declares identity, compatibility, runtime, role, KUANG capabilities and contributions. It declares none of §57's illustrative `capabilities:` map and no `security:` block — **though whether it can is genuinely unclear**: §57 defers to the generic contract, which here is `kuang-package/1`, and the KUANG capability list encodes the same security facts in its own vocabulary. **§57.1 is this section's `MUST` and has no code**: nothing distinguishes manifest-declared potential capability from session-effective capability. |
| 58 | Implementation Architecture Guidance | partial | §58.1's layering is followed and §58.3/§58.5 are met — the dynamic path is the primary one and no Kubernetes type crosses into core. §58.2's `SHOULD` (a mature client library) is deliberately not taken; the transport is this package's own ([ADR-0002](adr/ADR-0002-the-package-is-a-native-process-and-owns-its-http.md)). **§58.4's adapter registry does not exist** — the one adapter is a hard-coded branch in `workload.rs`. |
| 59 | Deterministic Test Strategy | partial | §59.1 and §59.5 hold absolutely: nothing in the suite contacts a cluster or a cloud. Of §59.2's twelve fixture classes, seven are real byte fixtures — discovery, OpenAPI, pagination, 410 expiry, RBAC denial, `Status` errors, connection reset. **Watch streams are not**: every watch test constructs a `WatchEvent` in Rust, because nothing deserialises a watch frame. **CRD removal, aggregated API failure, mutation dry-run, concurrent conflict and finalizer deletion have no fixture at all.** §59.3 and §59.4 have no CI. |
| 60 | Canonical Test Scenarios | partial | §60.2 and §60.4 are walked end to end in the domain (`should_treat_a_recreated_object_as_a_second_lifetime`, `should_survive_the_canonical_watch_expiry_scenario`). §60.1 covers steps 1 and 6 and misses 2, 4, 5 and 7. §60.5's model is tested and its premise is unrealisable, because there is no `get`. §60.6 covers step 3 only. **§60.3, §60.7 and §60.8 have no test at all** — §60.3 in particular is the one place watch and relationships would have to compose, and they never meet. |
| 61 | Conformance Levels | partial | K0 is five of six — provider instance isolation is the unmet one. K1 is six of seven — `get` is the unmet one, and its route arrived while this was written. **No level is claimed**, which is correct under §0.1. K2 fails on routing, K3 on watch, K4 on mutation, K5 on cross-system evidence. |
| 62 | Acceptance Gates | partial | A and B are proven end to end through the package's protocol surface. C, D, E, F, G and I are proven in the domain only. L has an end-to-end cancellation test. M is unblocked — the package reaches an `https://` API server with no `kubectl` in the path — and unproven against a real cluster. H is partial — `tests/query.rs` asserts `terminating == true` end to end for an object with a deletion timestamp, and nothing deletes anything, so the gate's premise is never reached. **J, K and N have no proof**: J's closest test runs its two contexts *sequentially* and the gate says "concurrently", K needs `providerID`, N needs a version matrix in CI. |
| 63 | Anti-Patterns | implemented | Each is avoided, several by a type rather than a review: 63.1 (no subprocess), 63.3 (JSON in, typed out), 63.4 (`should_not_promote_a_selector_match_to_ownership`), 63.5 (`condition.rs` refuses the synthetic string), 63.7 (`scope_of` requires the explicit flag), 63.8 ([ADR-0003](adr/ADR-0003-secret-payload-is-destroyed-at-the-boundary-rather-than-filtered-on-the-way-out.md)), 63.11 (`should_never_join_pre_gap_and_post_gap_changes_into_one_history`). 63.6, 63.9 and 63.10 are vacuous — no Events, no mutation. |
| 64 | Recommended Implementation Sequence | partial | Phase 1 is nearly closed, phase 2 is largely delivered and owes the schema cache, with `get` arriving, phase 3 is built and unrouted, phase 4 is built and unwired. Phases 5 through 9 have no code. The order was kept. |
| 65 | Definition of Useful v1 Capability | partial | Five of twelve hold: 1 (connect), 3 (discover built-in and custom), 4 (typed desired and observed fields), 10 (empty vs denied vs incomplete, as a failed invocation) and 12 (no `kubectl`). **2, 5, 6, 7, 8, 9 and 11 do not** — item 2 is a `--namespace` option rather than `enter`, and there is no traversal, no Events, no live view and no `providerID`. |
| 66 | Maintainer and Contribution Boundaries | partial | `CONTRIBUTING.md` names §66.1's ten surfaces verbatim, states §66.4's domain-expertise rule and §66.3's fixture-first rule, and `README.md` records honestly that no `MAINTAINERS.md` exists. **§66.2 is not yet structural**: there is no public adapter extension point, so adding a CRD ecosystem means editing `workload.rs` inside the crate. |
| 67 | CNCF-Relevant Design Qualities | advisory | Qualities rather than requirements. §67.1, §67.2 and §67.5 are supported by what is built; §67.3 has the shape and no external contributor; §67.4 is untested against a real cluster. |
| 68 | Open Questions | advisory | Reserved by the spec. §68.7 is actively honoured — `schema.rs` refuses to guess a reference from a field name (`should_not_guess_a_relationship_from_a_field_name`). §68.1's global URI grammar stays open, and `place.rs` froze a repo-local one under [ADR-0008](adr/ADR-0008-a-place-uri-has-its-own-grammar-in-which-a-cluster-scoped-object-has-no-namespace-slot.md), which is a decision here rather than there. |
| 69 | Final Provider Thesis | advisory | Its own measure: of the eleven verbs it names, `find`, `inspect` and a pipeline over `get` work. `enter`, `near`, `follow`, `trace`, `past`, `diff`, `why`, `plan` and `apply` do not reach Kubernetes. |

### Appendices

| App. | Title | Class | Evidence, or what is missing |
|---|---|---|---|
| A | Initial Curated Resource Matrix | partial | "Dynamic read: MUST" is met for every profile, including Arbitrary CRD, through `k8s-resource`. "Curated relations" is domain only where it exists. **"Watch: MUST" is met for nothing** — no watch is ever opened. |
| B | Canonical Relationship Vocabulary | partial | 14 of the 23 candidate names exist as `Relation` variants. Missing: `selected-by`, `routed-from`, `uses`, `uses-storage-class`, `protected-by`, `binds`, `grants-to`, `has-address`. `bound-to` exists as a name with no producer. `provider-hosted-by` is resolver output and correctly absent. |
| C | Relationship Evidence Examples | partial | C.1 and C.2 are realised, C.2 without `observed_resource_versions` because `Edge` carries no freshness (§23.6). **C.3 is not started** — it is the `providerID` evidence nothing reads. |
| D | Coverage Examples | partial | D.2 and D.4 are realised in `coverage.rs` and `watch.rs`. D.1 is partial — `Coverage` records scopes and gaps and carries neither the type nor the `resourceVersion`, which live in `transport.rs`. **D.3 is not built**: a `Coverage` has one requested scope, so a per-type aggregate has nowhere to go — the same hole as §34.2. |
| E | Prospective Change - Scale Deployment | not started | Needs the whole of §43–§46, §54 and §56. |
| F | Prospective Change - Delete Namespace | not started | Needs the above plus §45 and §55.2. |
| G | Upstream Behavior Notes | advisory | Informative by its own last sentence. |

---

## The 22 core invariants of §4

These are the promises the product makes. Twelve hold, three hold partly, four hold only inside
the library, two are vacuous, and one does not hold.

| # | Invariant | Status | Evidence |
|---|---|---|---|
| 1 | The API server is the authority | holds | No local store and no synthesis. Every invocation reads the server; there is nothing that could answer from anywhere else. |
| 2 | Discovery is authoritative for what is served | holds | `Gvr::path()` builds every REST path from the discovered resource; no endpoint is compiled in. `should_report_an_unserved_api_rather_than_guess_its_collection_path`. |
| 3 | Native Kubernetes identity remains inspectable | holds | `api_group`, `api_version`, `kind`, `resource_name` and `scope` on every dynamic record, asserted field by field. |
| 4 | `metadata.uid` is the canonical lifetime identity | holds | Every contributed schema declares `identity: [uid]`; `should_identify_every_kubernetes_object_by_uid_rather_than_by_name`. |
| 5 | A name is not a lifetime identity | holds | `Locator` is a separate type from `Identity`; `should_treat_a_recreated_object_as_a_second_lifetime`. |
| 6 | `resourceVersion` is a continuity token, not a clock | holds | `ResourceVersion` derives no ordering, so the comparison does not compile ([ADR-0006](adr/ADR-0006-resource-version-carries-no-ordering-so-the-forbidden-comparison-does-not-compile.md)). |
| 7 | `generation` and `resourceVersion` are not conflated | holds | `should_not_conflate_generation_with_resource_version`; both are separate fields on `k8s-deployment`. |
| 8 | Desired and observed state stay distinguishable | holds partly | `schema::Intent` and `condition.rs` keep them apart in the library. At the boundary only `k8s-deployment` carries the pair; every other record flattens or omits it. |
| 9 | Conditions are structured observations, not one string | holds in the library only | `condition.rs` is complete and tested. **The boundary does the thing the invariant forbids in miniature**: `records.rs` re-implements a private `Ready` lookup as one boolean on `k8s-node`, and no record carries a conditions list. |
| 10 | Owner references beat label-name heuristics | holds in the library only | `should_not_promote_a_selector_match_to_ownership`, `should_not_own_a_child_that_names_the_same_owner_name_with_a_different_uid`. No edge reaches a user. |
| 11 | Selectors imply membership, not ownership | holds in the library only | `Relation::Selects` and `SelectorMatches` are separate words, and `Evidence::Selector::is_asserted_by_provider()` is false. Unrouted. |
| 12 | Events are best-effort, not audit history | vacuous | There is no Event support at all, so nothing can violate it and nothing keeps it. |
| 13 | Missing permission is not absence | holds | `coverage::Outcome`'s eight states, with "not served" and "not listable" pinned at the boundary. Thin: no plugin test covers a 403 list denial. |
| 14 | An expired watch is a continuity break | holds in the library only | `should_never_join_pre_gap_and_post_gap_changes_into_one_history` — and no watch is ever opened, in the plugin or in the library. |
| 15 | CRDs are normal resources | holds | Proven end to end against an invented group, kind, plural and short name, with a test asserting none of those words appears in the plugin's source. |
| 16 | Aggregated APIs are normal discovered APIs | holds partly | Discovery treats them identically (§34.1). §34.2 is violated: one unavailable aggregated group fails the whole query. |
| 17 | Unknown fields remain preservable | holds | `should_keep_every_field_of_an_unknown_kind_the_cluster_describes_nowhere`, with `precision`, `schema_source` and `untyped` saying what nothing vouches for. |
| 18 | A mutation result is not proof of reconciliation | vacuous | Nothing mutates. The five-rung ladder exists in `watch.rs` and is unreachable. |
| 19 | Finalizers and deletion propagation are visible in destructive reasoning | holds partly | `finalizers` and `deletionTimestamp` are projected and `terminating` reaches a user. There is no destructive reasoning for them to be visible in, and no propagation policy. |
| 20 | Cross-system relationships are evidence-driven and resolved outside Kubernetes logic | **does not hold** | The second half holds — no cloud SDK, and `Evidence::Inferred` is reserved and never produced. The first half has no code: **no evidence is exported at all**, because `spec.providerID` is read nowhere. |
| 21 | Secret payloads are protected by default | holds | Destroyed at the boundary ([ADR-0003](adr/ADR-0003-secret-payload-is-destroyed-at-the-boundary-rather-than-filtered-on-the-way-out.md)); the end-to-end test asserts the payload appears nowhere in anything the host accepted. |
| 22 | No hidden Kubernetes mini-shell | holds | The package contributes nouns and no commands. `package/contributions/targets.yaml` declares 21 targets and zero verbs; every operation is an existing Ono verb. |

---

## The largest gaps, in the order they block each other

**1. ~~A contributed target is invoked with no options.~~ Closed in core the same day this
document was written.** It was read here as the largest gap and it was, until core commit
`1e85a84` made `provider.query` carry the invocation's words through the same parser the command
route already used. The proof is in `docs/STATE.md`: `get k8s-pod --host 127.0.0.1 --port 18002`
answers from a prompt with a typed record, which it could not have done while the option map was
empty. Left in place rather than deleted, because a gap list that quietly loses its top entry
teaches a reader nothing about what moved.

**2. There is no session.** Each invocation re-resolves the endpoint, re-runs discovery and
re-fetches the OpenAPI document. That single absence is the direct cause of five separate rows
above: §12.4's schema cache is written and unused, §50.2's discovery cost is paid every query,
§10.4's `MUST` has no cache to invalidate, §20.2's "cached or direct?" cannot be answered because
nothing is cached, and Gate J has nothing to prove because nothing is shared. A connection that
outlives one query is also the precondition for the next gap.

**3. The watch is never opened, and cannot be.** `watch.rs` is the most complete module in the
repository — the 410 state machine, the gap model, the five live-view states, the reconnect
backoff, 26 tests — and there is no wire driver: nothing decodes a watch frame into a
`WatchEvent`, and the plugin does not import the module. That blocks K3 entirely, Gate F's
end-to-end claim, §39's temporal history, §41's live views, §20.3's sync state, and Appendix A's
watch `MUST` for every profile in the matrix. It needs the session from gap 2 to have somewhere to
live.

**4. No relationship, place or role reaches a user.** `relationship.rs`, `workload.rs`,
`place.rs` and `condition.rs` are 3,565 lines with 86 tests and no importer. That blocks K2,
Gate D's end-to-end claim, `near`, `follow`, `up`, six of §53's nine examples, and items 5, 6, 7
and 8 of §65's twelve. It is independent of gaps 2 and 3 — it needs a route, not a connection —
which makes it the largest amount of finished work standing closest to being useful.

**5. Nothing is exported for a cross-system resolver.** `spec.providerID` is read nowhere. That
one field read is all that stands between the present state and §47.2, Gate K, §60.8, Appendix C.3
and the only invariant of §4 that does not hold. It has no prerequisite and it is the cheapest
item on this list, which is why it is worth naming beside the four large ones.

Two smaller things are worth keeping in sight because they are near-complete rather than absent.
**`get` (§17.1)** was the last unmet K1 requirement and its route landed in `query.rs` during the
writing of this document; the domain half in `transport.rs` was complete throughout. Once it is
green, K1 turns on one row rather than on a body of work. **§34.2's failure isolation** is a known deliberate trade recorded on the board,
and it currently means one broken aggregated APIService takes the whole provider down.

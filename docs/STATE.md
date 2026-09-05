# STATE

The work board for the Ono-Sendai Kubernetes provider. Read it first, update it last, every
session (AGENTS.md §9).

This is not the backlog. The backlog is the
[issue tracker](https://github.com/godspeed-you/ono-sendai-kubernetes/issues); one problem is one
issue, with the evidence that closes it in the issue body. A problem found on the way goes below
under *Found, not yet filed*, and the user triages it into an issue.

---

## Where the project is

**The package runs, speaks TLS, resolves the cluster it talks to from a kubeconfig context, and
can say which cluster that is and who it is to it.** A contributed target answers from an API
server over the host's brokered connection, over a session whose certificate it verified against
the authority the context pinned.

| | |
|---|---|
| Specification | `docs/architecture/kubernetes-provider.md` — canonical here, immutable, checksummed |
| Domain layer | `crates/ono-provider-kubernetes`, thirteen modules, no host and no cluster |
| Package | `crates/ono-kubernetes-plugin`, the `ono-kubernetes` binary: contributions, broker, query, dynamic, cluster, records |
| Tests | 320 across the workspace, all green, no live cluster and no network |
| Transport | HTTP/1.1 over a `rustls` session over the host's brokered `network.connect` |
| Conformance level reached | **none claimed.** K0 is partly met; see below |
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
| `transport` | §17–§18, §21 | HTTP/1.1 over a byte-stream trait; pagination, coverage, continuity |
| `watch` | §19, §20 | the `410 Gone` state machine; pre-gap and post-gap never stitched (Gate F) |
| `schema` | §12, §33 | an unknown CRD types fully through a path that names no kind (Gates A, B) |
| `workload` | §25–§27, §30 | `Ingress -> Service -> EndpointSlice -> Pod -> Node`, one edge per hop |
| `condition` | §37 | every derived reconciliation state cites the fields it rests on (Gate G) |
| `redaction` | §22, §29.2 | Secret payload destroyed at the boundary, not filtered at the edge (Gate I) |
| `place` | §9, §35, §36 | addresses that round-trip; cluster and namespace scope are two grammars |
| `diagnostics` | §8.5, §8.6, §10, §34.3 | which cluster this is, whether it answers, as whom, and what is unknown |

The package reaches the API server through the host's brokered `network.connect` — a real
`ByteStream` over `streams.emit` and `streams.next`, with no fixture fallback — and an end-to-end
test drives the real binary under `ono_kuang_testhost::TestHost` against recorded API bytes. The
whole chain is exercised: handshake, capability broker, connection, HTTP/1.1, discovery, list,
redaction boundary, and the host's own stamp on the provenance of every record it accepts. No
cluster is contacted (§59.1).

Five of the declared targets carry a kind-specific schema and a handler: `k8s-namespace`,
`k8s-node`, `k8s-pod`, `k8s-deployment`, `k8s-secret`. Fourteen more are §31.68 placeholders with
help and completion and no claim to answer — [ADR-0005](adr/ADR-0005-five-schemas-rather-than-nineteen-because-a-declared-schema-is-a-promise.md).

**`k8s-resource` answers for everything else the cluster serves.**
`get k8s-resource --kind Sprocket --group menagerie.example` resolves the kind against the
cluster's own discovery, types it from the OpenAPI document the server publishes for that
group-version, and emits records of one statically declared schema —
[ADR-0010](adr/ADR-0010-a-generic-noun-reaches-every-kind-because-a-static-document-cannot-name-one-invented-later.md).
A document written before the package runs cannot name a kind invented after it, so the noun
names the *shape of the question* instead of the answer. That is what makes §15.1 and §33.1
reachable from a word §31.68 can register statically, and it costs the operator a more verbose
spelling than a curated noun.

### Conformance, stated honestly

**K0 — connection and discovery (§61.1): partly met, and not claimed.** Six things are required.

| K0 requirement | State |
|---|---|
| kubeconfig / explicit connection | **yes.** A named `context` resolves through `~/.kube/config` — server, default namespace, trust anchors, bearer token, inline client certificate — read under the host's `filesystem.read` capability. An explicit `host` remains §7.3's explicit configuration, and naming neither is refused: no host is ever defaulted. `exec` credential plugins are refused rather than approximated (§8.2) |
| secure TLS defaults | **yes.** `tls.rs` is a `rustls` session below the `ByteStream` trait; verification is on unless `insecure-skip-tls-verify` is set, a certificate authority that does not parse is fatal rather than a fall back to the platform store, and the insecure path is reachable only through a constructor that names it ([ADR-0009](adr/ADR-0009-an-insecure-tls-session-is-reachable-only-through-a-constructor-that-names-it.md)). TLS 1.2 is disabled by the crate's feature set, so a cluster that offers only 1.2 is out of reach |
| provider instance isolation | partial. Every record carries `kubernetes:<context>` as provenance, and each query opens its own connection. Nothing is shared between queries yet, so there is nothing to cross over — and nothing that proves Gate J either |
| dynamic API discovery | **yes.** `/api`, `/apis` and the resource list are read on every query. Version, GVR, namespaced-ness and `list` support come from the server; a cluster serving no `apps` group gets `provider.unsupported` rather than a guessed path |
| cluster / namespace scopes | **yes.** A namespace is a deliberate request, `all_namespaces` is explicit (§9.4), and a cluster-scoped kind gets no namespace segment (§9.2) |
| provider health / identity diagnostics | **yes.** `get k8s-cluster` answers one record for the provider instance: the normalised API server origin, the `kube-system` namespace UID where readable, and the digest they compose, saying which signals it holds (§10.2); the server version and every request's source and latency (§34.3); the TLS posture, including an active insecure session (§8.4); the effective identity from `SelfSubjectReview` where the cluster serves it (§8.6); and `unknowns`, naming each thing it could not determine with one of §21.4's outcomes. Unreachable is an answer rather than a failure, and a refused review never blocks a read ([ADR-0011](adr/ADR-0011-the-cluster-diagnostic-is-keyed-on-the-provider-instance-so-two-aliases-cannot-merge.md)) |

Five of the six are met. **Provider instance isolation is the one that is not**, so K0 is still
not claimed: every record carries `kubernetes:<context>` and each query opens its own connection,
which means nothing is shared and therefore nothing crosses over — and equally that nothing proves
Gate J. What is missing is named rather than rounded up.

The diagnostic makes the two identities of §10.3 visible without merging them: a record is keyed
on the *provider instance*, so two contexts reaching one cluster produce two records with two
identities and one fingerprint. The field that would merge them is deliberately not the field that
identifies them.

**K1 — dynamic read model (§61.2): six of seven, and not claimed.** Seven things are required.

| K1 requirement | State |
|---|---|
| arbitrary discovered readable resources | **yes.** `k8s-resource` resolves whatever the query names against the cluster's own discovery, over the preferred version of every group the server lists, and lists it. A kind two groups both serve is refused with the candidates rather than resolved by an arbitrary type priority (§35.8, §13.5), and *not served*, *not listable*, *ambiguous* and *empty* are four different answers (§11.5, §21.4) |
| dynamic schema / unstructured fallback | **yes.** The API server's OpenAPI v3 document for the resolved group-version types the resource; the component is found by what it declares in `x-kubernetes-group-version-kind` (§13.2) rather than by a naming convention. A server that publishes none leaves the typing absent, and every field still projects with its precision saying so (§12.3, §12.5) |
| UID identity | **yes.** Every record's identity field is `metadata.uid`, for a custom resource exactly as for a Pod (§16.1) |
| metadata projection | **yes.** §14's common projection fills the same nine fields for every kind, curated or discovered, from one code path |
| get / list / pagination | partial. `list` is wired, with pages and a budget; **`get` is not.** §17.1's direct lookup by name has no route |
| partial coverage and RBAC truth | **yes**, as a failed invocation carrying what was missing ([ADR-0004](adr/ADR-0004-an-incomplete-read-fails-the-invocation-because-a-value-stream-cannot-carry-coverage.md)) |
| CRD support | **yes.** A CRD invented after this package was built is discoverable, queryable and returns typed records without recompiling anything, and no source file of the plugin crate names the kind the test uses ([ADR-0010](adr/ADR-0010-a-generic-noun-reaches-every-kind-because-a-static-document-cannot-name-one-invented-later.md)) |

**`get` is the one that is unmet**, so K1 is not claimed. The two requirements this session set out
to close — §15.1's arbitrary discovered readable resources, and CRD support — are met, and are the
two the level was previously blocked on. `get` is a smaller, well-understood gap: §17.1's direct
lookup by the canonical REST endpoint, over the same discovery and the same redaction boundary.

One caveat belongs beside that table and not inside it. Everything above is proven through
`provider.query` — the protocol call a contributed target is answered by — under the real
supervisor and the real binary. It is **not** reachable by typing `get k8s-resource --kind …` in a
shell today, because core issues `provider.query` for a contributed target with an empty options
map (core ADR-0582 says so, and the finding is recorded below). That blocks `--kind` exactly as it
already blocks `--context` for `get k8s-pod`, so it bounds every target this package has rather
than this one.

**Acceptance gates.** A and B are now proven end to end through the package's protocol surface:
`tests/query.rs` drives the real binary under `TestHost` against a recorded server offering an
invented API group, kind, plural, short name and field set, and a test asserts that none of those
words appears in any source file of the plugin crate — so the kind is reached because it is data
and the test fails the day anyone special-cases it. Gate B is proven in both directions: with a
published schema the record is structural typed values, and without one every field survives with
its own shape while `precision`, `schema_source` and `untyped` say what nothing vouches for.
Neither is *claimed*, on the same rule as the others: a gate is claimed when it is provable
through the shell, and the empty-options finding below is what stands between the two.

C, D, E, F, G and I are addressed at the domain level with tests that were
each verified to bite. None is claimed, because a gate is claimed when it is provable end to end
through the shell. Gate I comes closest — the end-to-end query test asserts the Secret payload
appears nowhere in anything the host accepted — and it still waits, because §62.9 is about the
default *list, detail and navigation* paths and only the list path exists. Gate L has an
end-to-end cancellation test. **Gate M (§62.13, no `kubectl` dependency) is no longer blocked**:
the package reaches an `https://` API server named by a kubeconfig context, with no `kubectl` and
no proxy in the path. Claiming it wants a run against a real cluster, which nothing in this
repository does yet.

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

Phase 1 is nearly closed: TLS, the kubeconfig wiring and the health/identity diagnostic are done,
and provider instance isolation — a test that proves Gate J — is the one thing left before K0.
**Phase 2 is largely delivered ahead of it**, because the two K1 requirements the level waits on
are the dynamic ones: the GVK/GVR registry, OpenAPI schema loading, unstructured conversion,
metadata projection, UID identity and the CRD fixtures are all in place and driven end to end.
What Phase 2 still owes is `get` (§17.1) and the schema cache (§12.4).

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

- **Provider instance isolation (Gate J, §62.10).** Nothing is shared between queries, so nothing
  can cross over; what is missing is the demonstration that two instances against two clusters
  stay apart. The cluster diagnostic is what makes such a test writable: two instances now have
  two identities and a fingerprint each.
- **`get` (§17.1).** The last unmet K1 requirement: a direct lookup by name against the canonical
  REST endpoint discovery resolved, over the same redaction boundary as the listing. Not started.

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

- **`get pod` needs core's contributed-target route, which landed on 2026-09-05.** ADR-0582 in
  core wires a contributed *target* to `provider.query`; before it, a package could only answer
  `get` through a contributed *command*, which returns whatever it likes with no declared schema,
  no identity and no provenance. This provider therefore requires a core at or after that commit,
  and the compatibility table in `README.md` must say so once a version of core carries it.
- **A contributed target is invoked with no options, so nothing a query says reaches the
  package.** `ono-cli`'s `invoke_contributed` issues `plugin.query(target, Map::new())` on the
  `.target.` branch, dropping the invocation's words entirely — while the command branch does
  turn `--name value` into JSON. Core ADR-0582 names this as a deliberate later increment: "the
  query is issued with no options … That needs the options half of `provider.query`, which is a
  separate increment." The consequence here is that **no target this package contributes is usable
  from a shell prompt yet**: `get k8s-pod` cannot receive `--context`, and `get k8s-resource`
  cannot receive `--kind`. Everything is proven through `provider.query` itself, which is the same
  call core will make once it fills the options in. This is the single largest thing standing
  between this package and a claimed gate.
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
- **Fourteen static placeholders name schema ids that no schema document declares — and core does
  not check the pairing at load.** The question ADR-0005 left open is answered: the supervisor
  checks a contributed target's schema id only for a package-or-core *prefix*, never against the
  package's contributed schemas. The check that bites is per record — a record whose schema id is
  not in the handshake registry does not decode, and one that decodes but does not match the
  target's declared schema is a `runtime.schema_violation`. So a placeholder naming an undeclared
  schema loads happily and fails at its first emit, which it never reaches because nothing wires
  it. The placeholders can stay; what would be caught is a *wired* target with an undeclared
  schema, at runtime rather than at load.
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
- **§10.4's cache invalidation has no cache to invalidate.** Strong fingerprint evidence that
  changes must invalidate cached object identities and watches before data is presented as
  current. Nothing here caches across invocations yet, so the rule has nothing to bite on — and
  the fingerprint that would trigger it now exists.
- **Alias detection is a comparison, not a memory.** `Fingerprint::compare` answers whether two
  instances may be one cluster; nothing persists a fingerprint between invocations, so the shell
  is the only place two of them meet. `state.persist` is declared in the manifest and unused.
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
- **§12.4's schema cache is not used.** Each query fetches the OpenAPI document for the resolved
  group-version again, because nothing is shared between queries yet — the same reason provider
  instance isolation is unproven. `schema.rs` has a `SchemaCache` keyed on a cluster fingerprint,
  and the diagnostic now produces such a fingerprint, so the two halves exist and are not joined.
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

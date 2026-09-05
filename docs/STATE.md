# STATE

The work board for the Ono-Sendai Kubernetes provider. Read it first, update it last, every
session (AGENTS.md §9).

This is not the backlog. The backlog is the
[issue tracker](https://github.com/godspeed-you/ono-sendai-kubernetes/issues); one problem is one
issue, with the evidence that closes it in the issue body. A problem found on the way goes below
under *Found, not yet filed*, and the user triages it into an issue.

---

## Where the project is

**The package runs, speaks TLS, and resolves the cluster it talks to from a kubeconfig context.**
A contributed target answers from an API server over the host's brokered connection, over a
session whose certificate it verified against the authority the context pinned.

| | |
|---|---|
| Specification | `docs/architecture/kubernetes-provider.md` — canonical here, immutable, checksummed |
| Domain layer | `crates/ono-provider-kubernetes`, twelve modules, no host and no cluster |
| Package | `crates/ono-kubernetes-plugin`, the `ono-kubernetes` binary: contributions, broker, query, records |
| Tests | 270 across the workspace, all green, no live cluster and no network |
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

The package reaches the API server through the host's brokered `network.connect` — a real
`ByteStream` over `streams.emit` and `streams.next`, with no fixture fallback — and an end-to-end
test drives the real binary under `ono_kuang_testhost::TestHost` against recorded API bytes. The
whole chain is exercised: handshake, capability broker, connection, HTTP/1.1, discovery, list,
redaction boundary, and the host's own stamp on the provenance of every record it accepts. No
cluster is contacted (§59.1).

Five of the nineteen declared targets carry a schema and a handler: `k8s-namespace`, `k8s-node`,
`k8s-pod`, `k8s-deployment`, `k8s-secret`. The other fourteen are §31.68 placeholders with help
and completion and no claim to answer — [ADR-0005](adr/ADR-0005-five-schemas-rather-than-nineteen-because-a-declared-schema-is-a-promise.md).

### Conformance, stated honestly

**K0 — connection and discovery (§61.1): partly met, and not claimed.** Six things are required.

| K0 requirement | State |
|---|---|
| kubeconfig / explicit connection | **yes.** A named `context` resolves through `~/.kube/config` — server, default namespace, trust anchors, bearer token, inline client certificate — read under the host's `filesystem.read` capability. An explicit `host` remains §7.3's explicit configuration, and naming neither is refused: no host is ever defaulted. `exec` credential plugins are refused rather than approximated (§8.2) |
| secure TLS defaults | **yes.** `tls.rs` is a `rustls` session below the `ByteStream` trait; verification is on unless `insecure-skip-tls-verify` is set, a certificate authority that does not parse is fatal rather than a fall back to the platform store, and the insecure path is reachable only through a constructor that names it ([ADR-0009](adr/ADR-0009-an-insecure-tls-session-is-reachable-only-through-a-constructor-that-names-it.md)). TLS 1.2 is disabled by the crate's feature set, so a cluster that offers only 1.2 is out of reach |
| provider instance isolation | partial. Every record carries `kubernetes:<context>` as provenance, and each query opens its own connection. Nothing is shared between queries yet, so there is nothing to cross over — and nothing that proves Gate J either |
| dynamic API discovery | **yes.** `/api`, `/apis` and the resource list are read on every query. Version, GVR, namespaced-ness and `list` support come from the server; a cluster serving no `apps` group gets `provider.unsupported` rather than a guessed path |
| cluster / namespace scopes | **yes.** A namespace is a deliberate request, `all_namespaces` is explicit (§9.4), and a cluster-scoped kind gets no namespace segment (§9.2) |
| provider health / identity diagnostics | **no.** Nothing answers "which cluster is this, and can it be reached". There is no diagnostic surface at all |

One of the six is unmet outright — there is no health or identity diagnostic — so **K0 is not
reached.** What is missing is named rather than rounded up.

**K1 — dynamic read model (§61.2): not reached.** UID identity, metadata projection and
pagination are real; `list` is wired and `get` is not; partial coverage and RBAC truth are modelled
and do reach the user, as a failed invocation
([ADR-0004](adr/ADR-0004-an-incomplete-read-fails-the-invocation-because-a-value-stream-cannot-carry-coverage.md)).
The two requirements that decide the level are the two that are absent from the shell: §15.1's
*arbitrary discovered readable resources* and CRD support. `schema.rs` projects an unknown CRD
fully, with tests, and no target routes to it — a static list of nouns cannot name a kind invented
after the package was built. That is the open question below, not a matter of adding more entries.

**Acceptance gates.** C, D, E, F, G and I are addressed at the domain level with tests that were
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

Phase 1 is the one in flight. TLS and the kubeconfig wiring are done; a health/identity diagnostic
is what now stands between the package and K0.

## In progress

- **A health / identity diagnostic**: which cluster is this, can it be reached, and who am I to it
  (§8.6, §10.2). The last unmet K0 requirement. Not started.

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
- **Fourteen static placeholders name schema ids that no schema document declares.**
  `package/contributions/targets.yaml` declares nineteen nouns and `schemas.yaml` declares five.
  Whether a host validates that pairing when it registers the static contributions is unverified —
  the handshake half is tested and this half is not. If core does validate it, either those
  entries lose their `schema` key or the placeholder list shrinks (ADR-0005).
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
- **`current-context` is not taken as a default.** §7.1 offers it as an optional default and §7.4
  forbids a command silently following it when it changes on disk. A context is named; whether a
  deliberate opt-in default is worth adding is open.

## Deferred / blocked

- **How a CRD becomes a typeable noun is open.** §31.68's static placeholders are written before
  the package runs; §33.1's custom resources are discovered while it runs, and a document written
  first cannot name a kind invented later. `schema.rs` already projects an arbitrary object
  against an arbitrary OpenAPI schema; what is missing is a target shape that names a kind at
  runtime. This is what K1 waits on, and it wants an ADR before it wants code.
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

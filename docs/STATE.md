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
every one of §15.2's nineteen kinds and §15.3's seventeen besides — and every kind the cluster
serves that nobody compiled in — answers a direct lookup by name, pushes a label selector to the
API server, says what one object is related to with the evidence and the source reads under each
edge, holds a session across invocations, watches a collection live and says which periods it
could not observe, exports cross-system identity evidence for four subject families, and — under a
declared risk and a granted capability — predicts or makes one bounded change, then says what a
follow-up read established about it.**

Every one of the twenty-four domain modules is now imported by the package. `live` and `budget`,
the last two that were not, reach a reader through `changes.rs` and `query.rs`.

| | |
|---|---|
| Specification | `docs/architecture/kubernetes-provider.md` — canonical here, immutable, checksummed |
| Domain layer | `crates/ono-provider-kubernetes`, twenty-four modules, no host and no cluster |
| Package | `crates/ono-kubernetes-plugin`, the `ono-kubernetes` binary: contributions, broker, sessions, query, dynamic, changes, cluster, records, relations, events, evidence, logs, timeline, why, conditions, planning, mutations, audit, spatial |
| Core revision | **`5e49ee75cd32255ca9d16700ee1701d86e663f08`** — the one every `Cargo.toml`, `Cargo.lock` and `.github/workflows/ci.yml` resolves to, carrying `ADR-0582 (core)` through `ADR-0605 (core)` — the KUANG/11 permission layer among them; `should_build_the_shell_from_the_revision_this_package_is_built_against` fails if any of them diverge |
| Contributions | 47 targets, 2 commands, 48 schemas, 64 relation shapes, **zero verbs of this package's own** |
| Tests | 1072 across the workspace, all green; 29 announce a skip without a cluster or an `ono` binary, and every one of them is declared in `docs/contracts/expected_test_skips.yaml`, checked in both directions |
| Live proof | 18 tests in `live_cluster.rs` against real `kind` clusters at all three declared versions — v1.35.8, v1.36.4 and v1.37.0 — with no `kubectl` on the machine. Seventeen announce a skip without one; the eighteenth is a static source scan that never does |
| Transport | HTTP/1.1 over a `rustls` session over the host's brokered `network.connect` |
| Conformance level reached | **none claimed.** §0.1 binds a claim to the gates; see `docs/coverage.md` for the requirement-by-requirement map |
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
| `coverage` | §18, §21 | nine ways to come back with nothing (Gate E) |
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
set k8s-resource      risk: mutate        capabilities: [network.connect, provider.mutate]
remove k8s-resource   risk: destructive   capabilities: [network.connect, provider.mutate]
```

Both verbs are core's own. `dry_run` defaults to **true**, so the shortest sentence a user can
write asks the API server to run admission and persist nothing; writing costs one more argument.

### Conformance and the acceptance gates

**These live in [`coverage.md`](coverage.md), not here.** They were duplicated on this board for
two sessions and drifted from the map both times, which is the argument for one owner: the board
says what the last session did and what the next should do, and the map says where the whole
surface stands. Requirement by requirement, gate by gate, with the evidence for each verdict, is
that document.

The summary, as of 2026-09-07: **K0 6/6, K1 7/7, K2 7/7, K3 6/6, K4 7/7, K5 5/5, and all fourteen
acceptance gates of §62 met** — the live half of the evidence run against `kind` at v1.35.8,
v1.36.4 and v1.37.0 with no `kubectl` on the machine.

**No level is claimed.** §0.1 binds a claim to the gates and the gates are met, so what remains is
judgement rather than evidence: a level is a promise to a user about a provider nobody has yet run
against a production cluster. Making that promise is not a decision this board takes on its own.


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

**Phase 3 is closed, in both halves.** Every Tier 1 adapter is wired, `k8s-relation` routes the
whole `Ingress -> Service -> EndpointSlice -> Pod -> Node` path with the evidence under each hop,
and §15.3's seventeen Tier 2 kinds are curated beside them (ADR-0052). The spatial half it used to
owe is delivered: `enter`, `near` and `follow` reach a cluster through the real `ono` binary, and
a CRD invented after the build is entered as a place keyed on the cluster's own `uid` — Gate A's
fifth verb, proven live.

**Phase 4 is closed.** A watch is opened, answers while the body is open, continues past a gap and
stops promptly when the operator does, and §41's live view is wired into `changes.rs` — a row that
goes stale says so rather than staying there looking current.

**Phases 5 through 8 landed out of order, and the cost that used to remain is closed.** Events,
temporal, causal, logs, plan and mutation all reach a user, and `set k8s-resource` now verifies a
change by watching the controller converge rather than by one immediate read (ADR-0060); §46.4's
`Inconclusive` is the honest answer where the watch times out, not a stand-in for a live view.

## Proven from a prompt (2026-09-05)

The chain runs end to end against a live HTTP API server, typed at an ordinary shell prompt:

```text
> install plugin kubernetes            # since 2026-09-08; the line below was a `grant capability` then
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

Nothing. The last session moved the package to the KUANG/11 permission contract (below), and
before it the completion pass closed the last wiring gap — the dependency-path causal finding — and
made `trace`/`diff`'s absence an explicit out-of-scope boundary rather than an ambiguous one.
**All fourteen acceptance gates of §62 are met**, and the live suite — now 18 tests — was run
against `kind` at v1.35.8, v1.36.4 and v1.37.0 on a machine with no `kubectl`. The workspace is
**1072 tests, all green**.

### v0.2.1, and the version a tag names (2026-09-08)

**The package is `0.2.1`**, which is what the payload directory, the wrapper asset names and the
manifest all say. The first attempt at the release found the reason to bump it: the tag was pushed
as `v0.2.1` while every version in the tree still read `0.2.0`, so `cargo deb` wrote a file the
publish step was not looking for and nothing was attached. The workflow now reads the manifest and
refuses a tag that disagrees with it, before it builds anything, so that mismatch costs seconds
rather than a whole build. `tests/packaging.rs` already tied the three versions together; nothing
tied them to the tag.

### Signed by nobody's key (2026-09-08)

**The wrappers are released from a workflow that holds no secret** (`ADR-0609 (core)`, ADR-0071).
The payload's signature was ed25519 with a private key somebody had to keep, which is why v0.2.0
shipped as a source release: this project has no such key and does not want one. Core now verifies
a keyless signature, so `.github/workflows/release.yml` signs the payload against a certificate
issued to the run, verifies the bundle it just made against the identity a reader will check, and
publishes the `.deb`, the `.rpm` and the `.kuang` archive. `scripts/package.sh --keyless` is that
path, `--key` remains for a local build, and `tests/packaging.rs` holds the workflow to using no
repository secret. An operator trusts it by enrolling the workflow identity, which the README
gives verbatim.

### The distribution wrapper (2026-09-08)

**`ono-plugin-kubernetes` is a source, never an installer** (ADR-0071; K11A §22). The plugin crate
carries `cargo deb` and `cargo generate-rpm` metadata placing the signed payload — manifest,
contributions, runtime, signature — under `/usr/lib/ono-sendai/plugin-sources/<id>/0.2.0/` with
the `kuang-system-origin/1` sidecar beside it, no maintainer script, nothing in `/usr/bin`, and a
lower bound of `ono (>= 0.4.3)`. `scripts/package.sh --key …` builds both and prints the content
digest a catalog entry states; `tests/packaging.rs` holds the metadata to K11A §11.3 and §17. The
workspace version is `0.2.0`, what the manifest has declared since ADR-0070.

### The permission contract (2026-09-08)

**`install plugin kubernetes` is the whole ceremony, and the six `grant capability` lines are
gone from the normal path.** Core implemented the KUANG/11 plugin installation, resolution and
permission specification (K11P; `ADR-0600 (core)` through `ADR-0605 (core)`), naming this provider
as the reference, and this package is now the worked example (ADR-0070):

- `package/manifest.yaml` is `kuang-package/2`, version `0.2.0`, `kuang_api ">=11.2 <12"`, with the
  seven permissions and three profiles of K11P §26.1. `recommended` reads and never writes;
  `spatial-relations` and `plugin-state` are automatic; `credential-helper` is asked for at first
  use; `cluster-mutation` is in `operate` only, and no manifest could put it elsewhere.
- `credentials.rs` reads `capabilities.check`'s `ask` as "proceed and let the host ask", refuses a
  `denied` before the program name is assembled, and names `set permission kubernetes
  credential-helper …` as the remedy. Nothing runs without a decision, under every answer.
- The live and spatial suites install the package the way an operator does — one `install plugin
  path:… --confirm`, `--access operate` where a test writes — and grant nothing by hand.
  `isolation.rs` holds the three shapes of the helper decision under `ScriptedConsent`.
- `scripts/demo.sh` and the README lead with the install; `grant capability` is documented as the
  raw mechanism underneath.

### The completion pass

Two things were wired that the map had recorded as short:

1. **`DEPENDENCY_PATH_EXISTS` is reachable.** `get k8s-why` derives the object's edges through the
   one rule set that answers `k8s-relation` (`relations::derive`, lifted out for the purpose) and
   walks outward through `causal::Walk` — bounded in hops (`depth`, at most 3) and in reads,
   visiting every object once so a cycle is a path that stops, reporting an asserted edge as the
   assertion and a derived one as a path. Proven at the domain, at the boundary and against a live
   cluster whose ReplicaSet a controller made (ADR-0068).
2. **`trace` and `diff` are an out-of-scope boundary, not a gap.** `trace` is the shell's
   relationship verb, bound to core targets and not opened to contributed relations by
   `ADR-0585 (core)`; `diff` is core's unbuilt v0.5 snapshot comparison. Both wait on a generic
   core increment, `near`/`follow`/`k8s-relation`/`k8s-why` reach the same graph, and a test pins
   the shape of `trace`'s refusal so it cannot become an empty graph (ADR-0069).

**One defect the walk found and fixed.** Against a real cluster's *aggregated* discovery, each
resource's `responseKind` leaves `group`/`version` empty to mean "the enclosing group-version".
The reader fell back to the enclosing version but not the enclosing group, so a Deployment read
over aggregated discovery was stored under the core group — and `k8s-resource --kind Deployment
--group apps`, and the walk's far-end reads, resolved to nothing. The fixture had filled the
field, so a hundred green tests never disagreed with it. Fixed in `discovery.rs`, with the
fixtures rewritten to match what a real API server writes (a fixture written from the same belief
as the code cannot disagree with it).

### The follow-up completion pass (2026-09-07)

Nine generic deficiencies were fixed in Ono core, because each was a boundary an external-system
provider needed and none carries a Kubernetes concept — `ADR-0591 (core)` through
`ADR-0599 (core)`: load-time schema-reference validation, the provider error taxonomy
(`provider.inconclusive`, `provider.authentication_failed`, `provider.authorization_denied`,
`provider.rate_limited`), host-resolved `~` in a path scope, the `provider.mutate` capability
family, the provider-action contract, semantic roles on a place, a contributed place's `up`, the
handshake-only-target report, and the remote-session assessment. The provider's pinned core
revision moved with them, and its final value for this pass is `864602a` — the child of `e207b9a`
that adds only a core README refresh, and the one every manifest, `Cargo.lock` and the CI matrix
resolve to (`chore: repin core to 864602a`).

Twelve provider-local decisions, ADR-0055 through ADR-0067, took the matching `SHOULD`s: credential
lifecycle and refresh, `KUBECONFIG` merge, the server path prefix, the relationship index and
selector pushdown, watch-capability negotiation, mutation convergence through the watch, schema
freshness, the semantic adapter registry with the Gateway API as its first member, TLS 1.2, the
verified peer-certificate fingerprint, spatial `up` to the cluster root, the `provider.mutate`
migration with the action contract, and the error-code migration.

### What is left, and why each is left

Two things, each a reservation with a reason rather than a backlog position, and both in
[`coverage.md`](coverage.md)'s "What is left":

1. **The three remote sessions (§42.3–§42.5).** Exec, attach and port-forward stay refusals that
   name what is missing (ADR-0018). `ADR-0599 (core)` records the assessment: a provider
   remote-session capability must integrate with core's v0.8 terminal-ownership and job-control
   contract, which is specified and not yet implemented, and building it now would either invent
   that contract (forbidden by §0.4) or bypass terminal ownership (forbidden by v0.8 §14.1). This
   is a conditional non-capability in §42's own "if supported" terms — the exact missing generic
   pieces are named in the ADR — not unfinished code. It becomes an implementation when core's v0.8
   lands.
2. **§15.4's Tier 3 ecosystems.** This provider curates no ecosystem's semantics, because a wrong
   claim about another controller's fields is the fabrication §4 forbids (ADR-0053). §33.8's
   registry now exists (ADR-0062, Gateway API as its first member), so the reservation is "no
   member yet" rather than "no mechanism"; it expires when a maintainer with that expertise
   contributes an adapter.
3. **`trace` and `diff` reaching Kubernetes (ADR-0069).** `trace` is the shell's relationship
   verb, bound to core targets; `ADR-0585 (core)` opened `near`/`follow`/`map` to contributed
   relations and not `trace`, so `trace k8s-pod` refuses by name and the same graph is reached
   through `near`, `follow`, `get k8s-relation` and `get k8s-why`. `diff` is core's unbuilt v0.5
   snapshot comparison. Both wait on a generic core increment, not on this provider, and a test
   pins the shape of `trace`'s refusal so it cannot become an empty graph.

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

**The 2026-09-07 completion pass closed most of what stood here.** The following findings below
are now resolved and are kept struck-through-in-prose for the record rather than deleted, because
a finding list that silently loses its entries teaches a later reader nothing: the `~/.kube/config`
real-host boundary (`ADR-0593 (core)`); the missing `provider.mutate` capability family
(`ADR-0594 (core)`, ADR-0066); the error registry having no code for an empty-not-absence answer
or a credential refusal (`ADR-0592 (core)`, ADR-0067); a target's schema id unchecked at load
(`ADR-0591 (core)`); the plugin partial-coverage path having no end-to-end test (now driven through
the boundary); TLS 1.2 disabled (ADR-0063); a kubeconfig `server` path prefix refused (ADR-0057);
the peer certificate modelled and not obtained (ADR-0064); and the `KUBECONFIG` single-file limit
(ADR-0056). What remains open below is process rather than code: the `docs/contracts/` scope and
the `MAINTAINERS.md` question. The capability findings — `provider.mutate`, the error codes, TLS
1.2, the peer fingerprint, the server prefix, credential refresh — are all closed and struck
through for the record.

- **~~A package cannot read `~/.kube/config` through a real host.~~ Closed in core
  (`ADR-0593 (core)`).** The host resolves a leading `~/` against the operator's home before the
  canonical scope check, so the manifest's declared `~/.kube/config` scope reaches the operator's
  kubeconfig with no absolute path — proven by the demo connecting with no `--kubeconfig`.
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
  and the compatibility table in `README.md` says so.
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

  **This is used now.** The pinned core carries `ADR-0586 (core)`, `lib.rs` declares
  `CONCURRENT_INVOCATIONS = 3` beside the manifest's `runtime.max_concurrent_invocations: 3`, and
  `tests/isolation.rs` holds one context open on stream credit while another's whole conversation
  runs — Gate J, genuinely concurrent. Kept rather than deleted, because a finding that moved from
  "the protocol cannot" to "done" is worth keeping visible.
- **Core registers an invocable target only from the on-disk document, never from the
  handshake — and now says so.** `get <word>` resolves from `contributions/targets.yaml`, so a
  handshake-only target name yields a provider entry nothing can spell; `ADR-0598 (core)` made the
  host name such a target at load for what it is rather than accept it silently. This is still why
  a discovered CRD cannot earn a *word* of its own today (ADR-0010) — every kind is reachable
  through `k8s-resource`'s options — and earning the word remains a core increment.
- **~~A target contribution has nowhere to declare its options.~~ Closed in core, taken here.**
  `ADR-0587 (core)` gave a contribution an `options` key that reaches the registry, and every
  target and command in this package declares every argument its handler reads —
  `should_declare_only_arguments_a_handler_actually_reads` fails on a declared option nothing
  consumes, and `should_reach_the_registry_with_every_argument_this_package_declares` drives the
  real binary. **The lesson that cost the most**: `map` is not a `DeclaredType`, and declaring one
  made `set k8s-resource` stop resolving in the shell while every test stayed green.
- **~~A contributed command cannot declare its options either.~~ Closed with the above.**
  `dry_run`, `set`, `unset`, `force_because` and `propagation` are declared and reach the
  registry, so the argument that decides whether a cluster changes is one a shell can complete.
- **~~The KUANG/11 provider role has one method, and it is a read.~~ Closed in core, taken here.**
  A mutating action is still a `command.invoke`, but `ADR-0595 (core)` gave a command contribution
  an `action:` block that declares accepted target types, that it mutates, its idempotency and its
  verification, read by the host before the first invocation (ADR-0066). Generic contract §21.1's
  three fields are all declared.
- **~~There is no capability family for "change state in the external system a provider fronts".~~ Closed in core, taken here.**
  `ADR-0594 (core)` added the `provider.mutate` family, scoped by provider instance and resource
  class, and both mutating commands now declare it beside `network.connect` (ADR-0066). The host
  checks both before any code runs, so a read-only grant of `network.connect` can no longer write.
  ADR-0024 recorded the finding this closes.
- **~~`audit.event` has no observable channel in the test host.~~ Closed in core, taken here.**
  `ADR-0589 (core)` found that `audit.event` pushed a package's records onto a vector nothing read
  — not `LoadedPlugin::audit()`, not `get audit`, not the persisted trail — and joined them to the
  trail the broker writes, under host attribution and a host clock so a package cannot forge
  either. §51.6 is met: `audit.rs` records connect, denial and mutation, and no function in it
  takes an `Object` ([ADR-0047](adr/ADR-0047-what-the-broker-cannot-see-is-what-is-worth-recording.md)).
- **~~The empty-not-absence refusal borrowed the wrong code.~~ Closed (ADR-0067).** `k8s-event`'s
  unobserved search and `k8s-log`'s empty read are `provider.inconclusive` now (`ADR-0592 (core)`),
  the code that means "the answer is empty and its emptiness proves nothing". A plan refused for a
  missing precondition is `contribution.refused` — this provider's own rule declining — which is a
  different statement kept apart from the inconclusive one on purpose (ADR-0025, ADR-0028).
- **~~A target's declared schema id is not checked at load.~~ Closed in core
  (`ADR-0591 (core)`).** A contribution naming a schema the package does not contribute is refused
  at load rather than at the first record. `tests/contributions.rs` holds the document, the
  handshake and the wiring table to each other besides.
- **~~§18.4's "more may exist" does not reach the user.~~ Closed.** It reaches twice over:
  `upstream=more-available` on each record's provenance, and `max_pages` as a declared option so a
  caller who bounded the answer can see that they did.
- **~~The plugin's partial-coverage failure path has no end-to-end test.~~ Closed.** It is driven
  through the boundary now: `should_keep_the_records_of_a_page_that_crossed_when_a_later_page_is_refused`
  emits the pages that crossed and then fails the invocation naming the gap.
- **~~TLS 1.2 is disabled.~~ Closed (ADR-0063).** The `tls12` feature is enabled beside 1.3, so an
  API server pinned to TLS 1.2 is a reachable cluster rather than a handshake failure — with the
  same anchors, the same name check and the same named insecure constructor as 1.3.
- **A failed handshake does not close its brokered handle.** `TlsStream::connect` consumes the
  stream, so the package cannot ask whether the host still holds the connection; closing one the
  host has already retired is a protocol violation, which is worse. The handle is reclaimed when
  the invocation ends.
- **~~A kubeconfig `server` with a path prefix is refused.~~ Closed (ADR-0057).** A Rancher-style
  endpoint (`https://host/k8s/clusters/c-xxx`) has its prefix carried on every request.
- **~~The server certificate's public key is modelled and not obtained.~~ Closed (ADR-0064).**
  `tls::TlsStream` exposes the peer certificate the session verified, and §10.2's second signal is
  the SPKI hash of *that* certificate — `should_fingerprint_the_public_key_of_the_certificate_the_session_verified`.
- **~~§10.4's cache invalidation is written and has no caller.~~ It has one, and only one.**
  `cluster::answer` hands the fingerprint it just observed to `Session::observed_fingerprint`,
  which empties discovery documents, schemas, watches, identity and capabilities on decisive
  disagreement. A fingerprint costs a read of `kube-system` and is not something §50.2 will pay
  for on every list, so this is the one moment the package has the evidence — and it means a
  cluster replaced behind an unchanged context name is caught by `get k8s-cluster` and by nothing
  cheaper. `Session::crd_updated` and `group_version_changed` now have a runtime caller too: a
  refreshed discovery document diffed against its predecessor fires both, so a CRD installed
  mid-session is discovered within the 30 s validity window (ADR-0061), which is §33.2 and the
  other half of §11.4.
- **Alias detection is a comparison and a memory, and neither survives an invocation.**
  `Fingerprint::compare` answers whether two instances may be one cluster and `Session` now
  remembers one between calls — inside one process, for as long as somebody holds the value.
  Nothing persists it across invocations; `state.persist` is declared in the manifest and unused.
- **~~Eleven domain modules cannot be reached from a prompt.~~ Closed: all twenty-four are
  imported.** `live.rs` reaches a reader through `changes.rs` (§41.1's live view, K3), and
  `budget.rs` through `query.rs` — `RetryPolicy::plan` waits on a `Retry-After` in sliced naps
  checking cancellation, and a query declares `max_requests`, `max_scopes` and `budget_ms`.
- **~~`Relation::BoundTo` is a word nothing emits.~~ Closed (ADR-0031).** §30.2's
  `PVC → bound-to → PV` has a producer: `claim_edges` reads `/spec/volumeName` with `/status/phase`
  as supporting evidence, and an empty name is not an edge
  (`should_bind_a_claim_to_the_volume_it_names`).
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
- **~~`current-context` is not taken as a default.~~ Closed.** An invocation naming no endpoint
  takes the kubeconfig's `current-context`, and one where the kubeconfig names none is refused
  rather than guessed (`should_take_the_kubeconfig_s_current_context_when_a_query_names_no_endpoint`,
  `should_refuse_a_query_naming_no_endpoint_when_the_kubeconfig_names_no_current_context`). §7.4's
  rule against silently following a changed context on disk still holds: the standing query, not a
  re-read of `current-context`, is what a wordless follow-up uses (ADR-0027).

## Deferred / blocked

- **~~The session's shell died on a full `/tmp`.~~ Cleared 2026-09-06, and the increment is
  committed.** `/tmp` on this machine is a 30.4 GB tmpfs mounted `usrquota`, uid 1000 reached its
  quota, and every write under it returned `EDQUOT` — which killed the agent harness, because it
  stages each shell command there. The user cleared it. **The lesson worth keeping**:
  `scripts/acceptance.sh` builds with the repository root as the docker context, and `target/` in
  this tree and in core's is 56 GB of it. A `.dockerignore` naming `target/` would have prevented
  the whole failure, and it belongs in core beside the Dockerfile.

- **A discovered CRD earning a *name* is still open**, and needs a change in core. `k8s-resource`
  is the floor: every kind is reachable, spelled as options. The nicer shape — a discovered
  `Sprocket` becoming its own word with its own help and completion — needs core to register a
  target contributed at handshake time, which it does not do (see the finding below).
  [ADR-0010](adr/ADR-0010-a-generic-noun-reaches-every-kind-because-a-static-document-cannot-name-one-invented-later.md)
  is shaped so that adding it later takes nothing away.
- **~~A Kubernetes object is not a place.~~ Closed.** `ADR-0584` and `ADR-0585` in core opened the
  vocabulary; this package declares both, and `enter`, `near` and `follow` reach a cluster through
  the real `ono` binary. A CRD invented after the build is entered as a place keyed on the
  cluster's own `uid` — Gate A's fifth verb, proven against a live cluster
  (`should_enter_a_custom_kind_the_cluster_learned_after_this_package_was_built`). `up` climbs
  the declared containment to the cluster root now, and refuses only above it (ADR-0065).
- **~~§34.2's failure isolation is not honoured on the dynamic search.~~ Closed.** The search now
  fails soft per group-version and `Searched` makes it impossible to hand on the groups that
  answered without the ones that did not, so one broken aggregated API server no longer fails an
  unqualified `--kind` search — it narrows it and says which groups it could not read. Four tests
  pin it, and it is what closed §4 invariant 16.
- **~~§12.4's schema cache has an owner the plugin does not hold.~~ Joined.** The package holds
  the session, the OpenAPI document for a resolved group-version is fetched once, and an *absent*
  schema is cached too, because "this server publishes none" is an answer about this cluster and
  re-asking pays §50.2's cost for a document that will not be there next time either.
  `should_read_the_published_schema_once_for_two_queries_of_one_kind`.
- **A discovery document goes stale only after its validity window.** A session caches discovery
  *documents* rather than the assembled snapshot, and a document older than 30 s is re-read and
  diffed against its predecessor, firing `crd_updated`, `group_version_changed` and
  `group_withdrawn` (ADR-0061). So a CRD installed while a session is live is discovered within the
  window rather than at the next process. What is still not detected is a structural schema change
  whose discovery footprint is byte-identical, because `SchemaCache` has no window of its own.
- **`docs/contracts/` holds one contract, the skip register.** Whether this provider needs further machine-readable contracts of
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

### 2026-09-07 — the gaps closed, and two defects only running could find

This record covers `76125cd`..`96ebabb` and a re-derivation of [`coverage.md`](coverage.md). The
headline is that **all fourteen acceptance gates of §62 are met**, proven against real `kind`
clusters at all three declared versions, and that the last two were closed by finding bugs rather
than by writing features.

**The gaps the previous coverage map named are closed.** §11.3's discovery snapshot carries its
five fields and `k8s-cluster` publishes them, because a provider fact nothing can read is not one
([ADR-0048](adr/ADR-0048-a-served-surface-that-cannot-say-when-it-was-observed-is-a-lookup-table.md)).
§17.3–§17.5's selectors are pushed to the API server *verbatim*, which is what keeps all three of
the section's prohibitions: there is no translation, so nothing for a translation to change
([ADR-0049](adr/ADR-0049-the-way-to-keep-a-selector-translation-from-changing-meaning-is-to-have-no-translation.md)).
§23.6 dates a derived edge by the oldest read that went into it and publishes Appendix C.2's
`observed_resource_versions`
([ADR-0050](adr/ADR-0050-a-conclusion-is-as-old-as-the-oldest-fact-it-rests-on.md)). §47.5 exports
a CSI handle and its driver as two items rather than one, because joining them would be a decision
about whose namespace the handle lives in
([ADR-0051](adr/ADR-0051-a-volume-handle-is-a-name-the-storage-system-gave-and-this-provider-does-not-know-whose.md)).
And §15.3's seventeen Tier 2 kinds are curated, proven against a recorded server and against a
live cluster, because a fixture written from the same table as the code cannot disagree with it
([ADR-0052](adr/ADR-0052-a-curated-noun-earns-its-place-by-its-projection.md)).

**§33.8's registry is a decision rather than code**, and the guard that came with it found a real
defect. §55.2's Namespace deletion analysis read `resource.kind() == "Namespace"` with no group
beside it, so a custom resource called `Namespace` in another group would have had a cluster's
namespaced inventory counted as its contents and attached to its deletion plan. §13.5 is the rule
it broke. The registry itself is declined with reasons in
[ADR-0053](adr/ADR-0053-there-is-no-curated-crd-knowledge-to-register-and-inventing-some-would-be-worse.md):
it governs curated *CRD* knowledge, this provider curates none, and inventing an ecosystem's
semantics would be a claim about what somebody else's controller means by its fields.

**The part worth keeping is the two defects, because neither could have been found by a test in
this repository.**

- **`get k8s-log` had never once worked against a real API server.** The request asked for
  `Accept: text/plain` — what a log body *is*, and not a media type Kubernetes' content
  negotiation offers — so every real cluster answered `406 Not Acceptable`. The recorded fixture
  answered whatever it was asked and never looked at the header. A fixture written from the same
  belief as the code cannot disagree with it, and a hundred green tests proved only that the
  fixture was agreeable. It now answers `406` to a media type the API server would refuse, which
  turns eight tests red on the old spelling, and a live test reads CoreDNS's startup lines.

- **The host was converting every refusal from an unbounded target into a clean empty answer.**
  `plugin_provider::stream_of` in core returned on the end of the output stream without reading
  the invocation result, so a handler that refused before emitting anything looked exactly like
  one that finished with nothing to say. That is §21.4 of the provider contract violated *by the
  host* — invisible to every test a provider can write, and it is what had been hiding the log
  defect through every layer of green beneath it. Fixed as `ADR-0590 (core)` with acceptance case
  `129-kuang-unbounded-target`, and this package now pins the revision that carries it.

Both were found by running `scripts/demo.sh` and reading its output. Nothing else in this session
was.

**Gate N is tested rather than asserted.** §5.1 asks for "a tested compatibility matrix, not a
parser guard", and the window lived in four places that could drift apart — the specification, the
workflow's three legs, the README's compatibility row and `scripts/cluster.sh`'s default.
`should_test_the_support_matrix_the_specification_declares_and_the_readme_claims` makes them one
claim. A sibling pins the core revision CI builds the shell from against *every* manifest, after a
bump that touched only the workspace left two revisions of `ono-kuang-protocol` in one graph.

Counts, so the next re-derivation has something to disagree with: 1055 tests, 47 targets, 2
commands, 48 schemas, 24 of 24 domain modules imported, 22 declared skips, 54 ADRs, 31 sections
implemented and 35 partial, 22 of 22 invariants, **14 of 14 gates**.

Later the same day, §8.2 and §8.3 landed too — a managed cloud's kubeconfig connects, under a
`process.exec` grant an operator makes deliberately (ADR-0054) — and an independent skeptical
review of this document and the coverage map found nine things overstated, every one of which is
corrected in the commits above. Two of its findings were tests weaker than the rows citing them,
including one that had no failing input at all.

What came next, in the completion passes recorded above under *In progress*: §8.3's credential
refresh landed as a session-keyed credential store with a bounded 401 retry (ADR-0055), the rest
of the `SHOULD` band closed (ADR-0055 through ADR-0067), and the dependency-path causal finding was
wired (ADR-0068). This is the last of the dated session records; the current state is at the top of
this document, not here.

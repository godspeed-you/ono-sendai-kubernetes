# STATE

The work board for the Ono-Sendai Kubernetes provider. Read it first, update it last, every
session (AGENTS.md §9).

This is not the backlog. The backlog is the
[issue tracker](https://github.com/godspeed-you/ono-sendai-kubernetes/issues); one problem is one
issue, with the evidence that closes it in the issue body. A problem found on the way goes below
under *Found, not yet filed*, and the user triages it into an issue.

---

## Where the project is

**Domain layer under construction. Nothing runs in the shell yet.**

| | |
|---|---|
| Specification | `docs/architecture/kubernetes-provider.md` — canonical here, immutable, checksummed |
| Implementation | `crates/ono-provider-kubernetes`, five modules, no I/O yet |
| Tests | 63, all green, no live cluster and no network |
| Conformance level reached | **none yet.** K0 needs a connection, and there is no transport |
| Licence | Apache-2.0 (core is MIT) |

What exists is the part that can be built and proved without a socket: configuration resolution,
discovery, object identity, relationships and the coverage model. Each was written test-first and
each answers to a numbered section of the specification.

| Module | Specification | What it settles |
|---|---|---|
| `kubeconfig` | §7, §8 | a context becomes a connection; a credential cannot reach a `Debug` |
| `discovery` | §11, §13 | what the server serves; `Gvk` and `Gvr` are separate types |
| `object` | §14, §16 | UID is lifetime identity, a name is not (Gate C) |
| `relationship` | §23–§32 | every edge names the evidence it rests on (Gate D) |
| `coverage` | §18, §21 | eight ways to come back with nothing (Gate E) |

Three acceptance gates are addressed at the domain level: **C** (delete and recreate is two
lifetimes), **D** (evidence class and source fields on every edge), **E** (denied never renders
as empty). None is *claimed* until it is provable end to end through the shell.

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

Nothing beyond Phase 1 can be claimed before Phase 1 exists.

## In progress

Nothing claimed. The next increment is the transport, and it is the one the rest waits on.

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

Nothing in the domain layer depends on how bytes are moved, which is why it was built first.

## Found, not yet filed

- **`get pod` needs core's contributed-target route, which landed on 2026-09-05.** ADR-0582 in
  core wires a contributed *target* to `provider.query`; before it, a package could only answer
  `get` through a contributed *command*, which returns whatever it likes with no declared schema,
  no identity and no provenance. This provider therefore requires a core at or after that commit,
  and the compatibility table in `README.md` must say so once a version of core carries it.

## Deferred / blocked

- **The gate has no compile, lint or test step**, because there is nothing to compile. It checks
  the specification checksum, link resolution, ADR form and that the instructions name the
  specification. When the first crate lands, the gate grows to core's shape and these checks stay
  (AGENTS.md §10).
- **`docs/contracts/` does not exist.** Whether this provider needs machine-readable contracts of
  its own, or registers everything through core's, is an open question for the first
  implementation increment and wants an ADR.
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

Next: the transport, then the plugin binary, then K0.

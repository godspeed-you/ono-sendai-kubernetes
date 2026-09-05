# STATE

The work board for the Ono-Sendai Kubernetes provider. Read it first, update it last, every
session (AGENTS.md §9).

This is not the backlog. The backlog is the
[issue tracker](https://github.com/godspeed-you/ono-sendai-kubernetes/issues); one problem is one
issue, with the evidence that closes it in the issue body. A problem found on the way goes below
under *Found, not yet filed*, and the user triages it into an issue.

---

## Where the project is

**Specification stage. No implementation exists.**

| | |
|---|---|
| Specification | `docs/architecture/kubernetes-provider.md` — canonical here, immutable, checksummed |
| Implementation | none |
| Tests / fixtures | none |
| Conformance level reached | none — K0 is not started |
| Licence | Apache-2.0 (core is MIT) |

The repository was created 2026-09-05 and holds the specification, the documents around it and
the gate that keeps them honest.

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

Nothing.

## Found, not yet filed

Nothing yet.

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

Next: nothing is claimed. Phase 1 of §64 is the work, and it needs a decision about where the
implementation lives — a crate in this repository, or a KUANG/11 package — which is `ADR-0002`.

# ono-sendai-kubernetes

The Kubernetes provider for [Ono-Sendai](https://github.com/godspeed-you/ono-sendai) — the
reference KUANG/11 external-system provider.

> Kubernetes is not a command namespace inside Ono. It is a system Ono can understand.

**Nothing is installable from this repository yet, and no Kubernetes version is supported.** The
package declares its nouns and the domain layer is under construction; there is no transport, so
nothing has reached a cluster. `docs/STATE.md` says precisely how far it goes.

| | |
|---|---|
| [`docs/architecture/kubernetes-provider.md`](docs/architecture/kubernetes-provider.md) | the canonical Kubernetes Provider Specification — immutable, checksummed |
| [`crates/ono-provider-kubernetes/`](crates/ono-provider-kubernetes/) | the domain layer: configuration, discovery, identity, relationships, coverage |
| [`package/`](package/) | the KUANG/11 package: manifest and contributed targets |
| [`AGENTS.md`](AGENTS.md) | the development contract, for humans and AI agents alike |
| [`docs/STATE.md`](docs/STATE.md) | the work board: what is in progress, found, or deferred |
| [`docs/adr/`](docs/adr/) | decisions recorded in this repository |
| [`scripts/gate.sh`](scripts/gate.sh) | the quality gate every change must pass |

## What the provider is for

A cloud-native troubleshooting path crosses `Ingress → Service → EndpointSlice → Pod → Node →
cloud instance → host → process → socket`. The Kubernetes API already holds the structure needed to
walk the upper half of that path. Today an operator reassembles it by hand, across tool
boundaries, translating identifiers between outputs.

The provider exists to preserve that structure instead of flattening it into terminal text: native
Kubernetes objects as typed Ono values, relationships as first-class edges carrying their
evidence, clusters and namespaces as places in the same world Ono already navigates, and RBAC
denial, stale caches and broken watches as facts rather than as empty results.

It is not a `kubectl` wrapper, a dashboard, a Helm implementation, a GitOps controller or a
metrics backend — the specification's §3 says so normatively.

## Why a separate repository

Kubernetes domain logic must not accumulate inside Ono core. A dedicated repository keeps the
generic KUANG/11 external-system contract testable as a real extension boundary, lets provider
release cadence differ from core cadence, and gives Kubernetes expertise a place to own work
without first understanding the shell's parser, job control or renderer.

A separate Git repository does not make this a separate project. Whether the CNCF ecosystem would
one day treat provider repositories as subprojects or simply as further repositories of
Ono-Sendai is an open governance question, and Ono-Sendai is not a CNCF project.

## Relationship to Ono-Sendai

This repository is authoritative for Kubernetes API integration, resource mapping,
Kubernetes-local relationships, CRD handling, watch/cache behaviour, Kubernetes compatibility
policy, its own tests and fixtures, and the Kubernetes Provider Specification.

The [Ono-Sendai repository](https://github.com/godspeed-you/ono-sendai) remains authoritative for
the shell language and pipeline semantics, the generic systems model, the KUANG/11 host and
runtime contracts, the generic external-system provider architecture, cross-provider policy and
project-wide governance. Two documents there govern this one:

- [`docs/architecture/external-system-provider.md`](https://github.com/godspeed-you/ono-sendai/blob/main/docs/architecture/external-system-provider.md)
  — the generic contract this provider conforms to;
- [`docs/strategy/cloud-native-vision.md`](https://github.com/godspeed-you/ono-sendai/blob/main/docs/strategy/cloud-native-vision.md)
  — why the cloud-native direction is being taken at all.

Both are canonical in that repository and are deliberately not copied here.

## Compatibility

| | |
|---|---|
| KUANG/11 package format | `kuang-package/1`, `kuang_api >=11.1 <12` |
| Ono-Sendai core | **at or after ADR-0582.** Before it, a contributed target could only be answered through a contributed command, which returns values carrying no declared schema, no identity and no provenance |
| Kubernetes versions | the specification was written against the API model of 2026-09-03 and targets the then-supported v1.35 – v1.37 (§0.5, §5.1). This is a specification target, not a support claim |
| Supported versions of this provider | none — there is no release |

The provider is specified to be discovery-first: it learns what the connected API server actually
serves rather than assuming a compiled-in version (§5.2). A tested compatibility matrix replaces
this table once an implementation exists.

## Maturity levels

The specification defines six conformance levels (§61), and a provider may sit at different
levels for different resource families rather than claiming one flag:

```text
K0  connection and discovery
K1  dynamic read model, including CRDs
K2  operational graph — relationships and navigation
K3  live Kubernetes — watch continuity, gaps, freshness
K4  bounded safe actions
K5  temporal and cross-system enrichment
```

Read-only usefulness comes first. Mutation support is never required to call the provider
production-ready for its declared scope.

## Status and roadmap

The provider is at the specification stage. The first implementation milestone is the
Cloud-Native Validation Gate described in
[`docs/strategy/cncf-readiness.md`](https://github.com/godspeed-you/ono-sendai/blob/main/docs/strategy/cncf-readiness.md) in the core repository: a proof-of-concept that demonstrates Ono's existing concepts becoming *more* useful
against Kubernetes without creating a Kubernetes-specific second shell. That gate is allowed to
fail, and failing it is evidence worth having.

The specification's §64 sets the implementation order: connection foundation, then the dynamic
resource model, then the curated operational graph, then live observation.

## Ownership

This repository is part of the Ono-Sendai project and is maintained by it. There is **no separate
maintainer list yet** — neither here nor in core, where `MAINTAINERS.md` is recorded as required
before any CNCF Sandbox application and does not exist. Nobody is listed as a maintainer of this
provider who is not actually maintaining it.

Project-wide governance is inherited from Ono-Sendai by reference rather than duplicated here.
Repository-specific ownership can be added when a provider community develops; the specification
already names the surfaces that ownership would be divided along (§66.1).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Kubernetes domain expertise is valued independently
from Ono core expertise (§66.4), and contribution surfaces are deliberately bounded — discovery
and schema, workload relationships, network relationships, storage, RBAC and identity,
watch and cache, events, mutation and verification, CRD adapters, fixtures and version
compatibility (§66.1).

## Security

See [`SECURITY.md`](SECURITY.md). A Kubernetes provider handles cluster credentials and can reach
production infrastructure, so report privately.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

Note that the Ono-Sendai core repository is MIT-licensed at the time of writing; its own
Apache-2.0 transition is a separate decision recorded in `docs/strategy/cncf-readiness.md` §3 and
has not been executed.

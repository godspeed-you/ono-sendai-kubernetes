# ono-sendai-kubernetes

The Kubernetes provider for [Ono-Sendai](https://github.com/godspeed-you/ono-sendai) — the
reference KUANG/11 external-system provider.

> Kubernetes is not a command namespace inside Ono. It is a system Ono can understand.

**There is no release, and no Kubernetes version is supported.** What exists is a KUANG/11
package that builds from this repository and runs: it speaks HTTPS to an API server over the
host's brokered connection, reads any kind the cluster serves, walks relationships with the
evidence under each edge, watches a collection live, and — under a declared risk and an operator's
grant — predicts or makes one bounded change. It is proven against recorded API bytes and has
never been run against a production cluster.
[`docs/coverage.md`](docs/coverage.md) says section by section how far it goes, and
[`docs/STATE.md`](docs/STATE.md) says what is next.

| | |
|---|---|
| [`docs/architecture/kubernetes-provider.md`](docs/architecture/kubernetes-provider.md) | the canonical Kubernetes Provider Specification — immutable, checksummed |
| [`crates/ono-provider-kubernetes/`](crates/ono-provider-kubernetes/) | the domain layer: twenty-four modules, no host and no cluster |
| [`crates/ono-kubernetes-plugin/`](crates/ono-kubernetes-plugin/) | the `ono-kubernetes` binary: the KUANG/11 boundary |
| [`package/`](package/) | the KUANG/11 package: manifest, targets, commands and schemas |
| [`AGENTS.md`](AGENTS.md) | the development contract, for humans and AI agents alike |
| [`docs/coverage.md`](docs/coverage.md) | what of the specification is built, with the evidence for each verdict |
| [`docs/STATE.md`](docs/STATE.md) | the work board: what is in progress, found, or deferred |
| [`docs/adr/`](docs/adr/) | decisions recorded in this repository |
| [`scripts/gate.sh`](scripts/gate.sh) | the quality gate every change must pass |

## What you can type today

The package contributes **30 targets, 2 commands and no verb of its own**: every operation is an
Ono verb that already existed. Reading is `get`; the two words that write are core's own `set` and
`remove`, aimed at the same noun `get` reads.

```text
> grant capability network.connect --plugin io.github.godspeed-you.kubernetes

> get k8s-pod --context prod --namespace shop | where phase == "Running"
> get k8s-resource --context prod --kind Sprocket        # any kind the cluster serves, CRDs included
> get k8s-relation --context prod --kind Pod --name api-7d9f --relation scheduled-on
> get k8s-change --context prod --kind Pod               # live, until you stop it; gaps are records
> get k8s-event    --context prod --kind Pod --name api-7d9f
> get k8s-condition --context prod --kind Deployment --name checkout
> get k8s-timeline --context prod --kind Pod --name api-7d9f
> get k8s-why      --context prod --kind Pod --name api-7d9f
> get k8s-log      --context prod --name api-7d9f --container api --tail-lines 200
> get k8s-evidence --context prod --name node-a          # what a Node says about the machine under it
> get k8s-cluster  --context prod                        # which cluster, reachable, as whom
> get k8s-plan     --context prod --kind Deployment --name api --set '{"/spec/replicas": 2}'
> set k8s-resource --context prod --kind Deployment --name api --set '{"/spec/replicas": 2}'
> remove k8s-resource --context prod --kind Pod --name api-7d9f
```

**What needs a granted capability.** Nothing reaches a cluster without
`network.connect`; without the grant the invocation fails with `capability.denied` and the server
sees no request at all. Reading a kubeconfig needs `filesystem.read`, declared in the manifest and
pinned to `~/.kube/config` and `~/.kube/*.yaml` rather than to the filesystem. `set k8s-resource`
declares `risk: mutate` and `remove k8s-resource` declares `risk: destructive`, and the host
applies its own confirmation policy to those descriptors — this package prompts for nothing of its
own. **`dry_run` defaults to `true`**, so the shortest sentence you can write asks the API server
to run admission and persist nothing; `--dry-run false` is the one place you are asked to be
explicit about which of the two you meant.

Two honest limits on that grant. KUANG/11 has no capability family for changing state in the
system a provider fronts, so both commands declare `network.connect` — which means **an operator
who grants this package the ability to read a cluster has, in the same act, granted it the ability
to write to one.** And a contributed target or command has nowhere to declare its options, so none
of the flags above can be completed or helped by the shell; they are documented in
[`package/contributions/`](package/contributions/) and in each summary.

**What you cannot type.** `enter`, `near`, `up`, `map`, `trace` and `diff` do not reach Kubernetes:
an object carries an address as a *string on a record* and is not yet a place in Ono's graph.
`--follow` on a log, a live *view* as opposed to a live stream, a permission preflight, and a
`labelSelector` or `fieldSelector` pushed to the server are all absent and named in
[`docs/coverage.md`](docs/coverage.md).

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
| Ono-Sendai core, to build | the SDK revision `Cargo.lock` pins. It predates `ADR-0586 (core)`, so this package answers **one invocation at a time** and cannot yet prove §62.10's *concurrent* two-context isolation |
| Ono-Sendai core, to run | **at or after `ADR-0582 (core)`.** Before it, a contributed target could only be answered through a contributed command, which returns values carrying no declared schema, no identity and no provenance |
| Kubernetes versions | **none is supported.** The specification was written against the API model of 2026-09-03 and targets the then-supported v1.35 – v1.37 (§0.5, §5.1); that is a specification target, not a support claim, and no CI job runs against any Kubernetes version (§5.5, Gate N) |
| Kubernetes versions actually exercised | none. Every test runs against recorded API bytes; nothing in this repository has contacted a cluster (§59.1) |
| Releases of this provider | none |

The provider is discovery-first by construction: every REST path is built from what the connected
API server says it serves, and no endpoint is compiled in (§5.2). A tested compatibility matrix
replaces this table when there is CI to support one.

## What is supported, along five axes

§15.5 forbids an all-or-nothing support claim and requires these five to be stated separately.
"Curated" means a hand-written schema with named fields; every kind is readable dynamically
whether or not it is curated. Section-by-section evidence is in
[`docs/coverage.md`](docs/coverage.md).

| Resource family | Readable dynamically | Semantically curated | Relationship enriched | Watch capable | Mutation capable |
|---|---|---|---|---|---|
| Workloads (Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob, Pod) | yes | yes | yes | yes | yes, bounded |
| Service, EndpointSlice | yes | yes | yes | yes | yes, bounded |
| Ingress, Gateway API | yes | yes | yes, except `has-address` | yes | yes, bounded |
| Node, Namespace | yes | yes | yes | yes | yes, bounded |
| ConfigMap, Secret, ServiceAccount | yes | yes | yes | yes | yes, bounded |
| PersistentVolumeClaim, PersistentVolume, StorageClass | yes | yes | **no `bound-to` edge** (§30.2) | yes | yes, bounded |
| NetworkPolicy | yes | yes | **no selector evaluation** (§31.1) | yes | yes, bounded |
| RBAC (Role, RoleBinding, ClusterRole, ClusterRoleBinding) | yes | no | no (§32.2) | yes | yes, bounded |
| HPA, PDB, quotas, admission, CSI, leases (§15.3 Tier 2) | yes | no | no | yes | yes, bounded |
| Custom resources of any CRD | yes | no, and none is needed | yes, through owner references and generic rules | yes | yes, bounded |

"Mutation capable" means one bounded field change or one deletion, of one object named by the
caller, with the preconditions taken from the object that was read — never a bulk operation and
never a scale, restart or cordon action of its own (§43.3 is not fully served). "Watch capable"
means `get k8s-change` resolves the collection through discovery, so a kind invented after this
package was built is watchable; the watch tests exercise Pods.

## Maturity levels

The specification defines six conformance levels (§61), and a provider may sit at different
levels for different resource families rather than claiming one flag:

```text
K0  connection and discovery                            requirements met — not claimed
K1  dynamic read model, including CRDs                   requirements met — not claimed
K2  operational graph — relationships and navigation     five of seven
K3  live Kubernetes — watch continuity, gaps, freshness  five of six
K4  bounded safe actions                                 six of seven
K5  temporal and cross-system enrichment                 three of five, one partial
```

**No level is claimed, including the two whose requirements are met.** §0.1 binds a conformance
claim to the corresponding acceptance gates: K0 waits on Gate J, which asks for two kubeconfig
contexts queried *concurrently*, and K1 waits on Gate A, which asks for an unknown CRD to be
*entered* as well as discovered and queried. Both are things this package could do and does not,
and both are the first two items on [`docs/STATE.md`](docs/STATE.md). Requirement by requirement,
and gate by gate, is in that document.

Read-only usefulness comes first. Mutation support is never required to call the provider
production-ready for its declared scope, and it landed here before a live *view* did — which is
out of the order §64 sets, and is recorded as such rather than presented as a plan.

## Status and roadmap

The next milestone is the Cloud-Native Validation Gate described in
[`docs/strategy/cncf-readiness.md`](https://github.com/godspeed-you/ono-sendai/blob/main/docs/strategy/cncf-readiness.md) in the core repository: a proof-of-concept that demonstrates Ono's existing concepts becoming *more* useful
against Kubernetes without creating a Kubernetes-specific second shell. That gate is allowed to
fail, and failing it is evidence worth having.

Of the things it asks for, direct API interaction with no dependency on `kubectl`, UID-aware
identity, useful behaviour for kinds unknown at compile time, relationships with inspectable
evidence, honest handling of RBAC denial and watch discontinuity, no Kubernetes-specific parser or
core exception, and deterministic tests needing no live cluster are all built and tested here.
**Navigation through the existing spatial model is not**, and it is the largest open item: a
Kubernetes object carries an address and is not yet somewhere you can be.

The specification's §64 sets the implementation order: connection foundation, then the dynamic
resource model, then the curated operational graph, then live observation. Phases 1, 2 and 4 are
closed, phase 3 owes its spatial half, and parts of phases 5 through 8 arrived early.

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

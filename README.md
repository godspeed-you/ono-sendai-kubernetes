# ono-sendai-kubernetes

The Kubernetes provider for [Ono-Sendai](https://github.com/godspeed-you/ono-sendai) — the
reference KUANG/11 external-system provider.

> Kubernetes is not a command namespace inside Ono. It is a system Ono can understand.

**v0.2.1 ships the package as a `.deb` and an `.rpm`, signed by nobody's key**: the release
workflow keeps no secret, proves its identity with a short-lived token, and a reader checks which
workflow on which tag signed. v0.2.0 moved the package to the KUANG/11 permission contract:
`install plugin kubernetes` is the whole ceremony, what it may do is decided in a person's words,
and the credential helper of a managed cloud is asked for at first use rather than granted blind.
v0.1.0 was the first release.
It is a KUANG/11 package that builds from this repository and runs: it speaks HTTPS to an API server over the host's brokered connection, reads any kind the
cluster serves, walks relationships with the evidence under each edge, watches a collection live
at a terminal, and — under a declared risk and an operator's grant — predicts or makes one bounded
change. Most of it is proven against recorded API bytes, and a suite of integration tests runs the
real `ono` binary against ephemeral `kind` clusters across the declared supported Kubernetes minor
versions, on a machine with no `kubectl` installed. It has not been run against a production
cluster. [`docs/coverage.md`](docs/coverage.md) says section by section how far it goes, and
[`docs/STATE.md`](docs/STATE.md) says where the whole surface stands.

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

The package contributes **47 targets, 2 commands and no verb of its own**: every operation is an
Ono verb that already existed. Reading is `get`; the two words that write are core's own `set` and
`remove`, aimed at the same noun `get` reads.

```text
> install plugin kubernetes                              # one prompt: the recommended access
> get k8s-pod --context prod --namespace shop | where phase == "Running"
> get k8s-pod --context prod --namespace shop --selector 'app=api,tier!=cache'   # pushed to the server
> get k8s-pod --context prod --namespace shop | take 1 | enter; look             # an object is a place
> near                                                  # its neighbours, with `relation.write` granted
> get k8s-resource --context prod --kind Sprocket        # any kind the cluster serves, CRDs included
> get k8s-relation --context prod --kind Pod --name api-7d9f --relation scheduled-on
> get k8s-change --context prod --kind Pod               # live, until you stop it; gaps are records
> get k8s-event    --context prod --kind Pod --name api-7d9f
> get k8s-condition --context prod --kind Deployment --name checkout
> get k8s-timeline --context prod --kind Pod --name api-7d9f
> get k8s-why      --context prod --kind Pod --name api-7d9f
> get k8s-why      --context prod --kind Pod --name api-7d9f --depth 2   # dependency paths, never a cause
> get k8s-log      --context prod --name api-7d9f --container api --tail_lines 200
> get k8s-evidence --context prod --name node-a          # what a Node says about the machine under it
> get k8s-cluster  --context prod                        # which cluster, reachable, as whom
> get k8s-plan     --context prod --kind Deployment --name api --set '{"/spec/replicas": 2}'
> set k8s-resource --context prod --kind Deployment --name api --set '{"/spec/replicas": 2}'
> remove k8s-resource --context prod --kind Pod --name api-7d9f
```

**What you are asked, and what it means.** `install plugin kubernetes` shows the recommended
access in plain words and installs on `Y`:

```text
Recommended access:
  - Connect to Kubernetes clusters
  - Read Kubernetes configuration (paths ~/.kube/config, ~/.kube/*.yaml)
  - Use Kubernetes credentials
  - Add Kubernetes relationships to Ono
  - Keep plugin state and read the clock

Asked only when needed:
  - Run an external login helper

Not granted:
  - Change Kubernetes resources

Install with recommended access? [Y/n/details]
```

Each line is a **permission** of `package/manifest.yaml` — a user-facing statement that resolves
to exact KUANG/11 capabilities the host grants on its behalf: `network.connect`, `filesystem.read`
pinned to `~/.kube/config` and `~/.kube/*.yaml` rather than to the filesystem, `secret.use`, a
`relation.write` bounded to this package's own relation shapes, `state.persist` and `clock.read`.
`details` shows every one of them with its scope, enforcement and duration, and
`get permission kubernetes` shows the same afterwards. The host classifies each capability and
this package cannot lower the class: nothing that changes a cluster can sit in a recommended
profile, and a manifest that tried would be refused before any of its code ran. The design is
`ADR-0600 (core)` through `ADR-0605 (core)`, and ADR-0070 here; the contract is
`docs/contracts/kuang/permissions.v1.yaml` in the core repository.

Nothing reaches a cluster without *Connect to Kubernetes clusters*; with it denied the invocation
fails with `capability.denied` and the server sees no request at all. `set k8s-resource` declares
`risk: mutate` and `remove k8s-resource` declares `risk: destructive`, and the host applies its own
confirmation policy to those descriptors — this package prompts for nothing of its own.
**`dry_run` defaults to `true`**, so the shortest sentence you can write asks the API server to run
admission and persist nothing; `--dry_run false` is the one place you are asked to be explicit
about which of the two you meant.

Reading a cluster and changing one are two decisions. **`provider.mutate` is the authority to
change state in the cluster**, declared by `set k8s-resource` and `remove k8s-resource` and checked
by the host at every invocation before any of this package's code runs — and it is in no
recommended profile. The recommended install is a read-only provider that cannot send a write;
`set permission kubernetes --profile operate` (or `… cluster-mutation --decision allow`) is the
deliberate step that enables it, with its own confirmation, and until then a mutation fails with
`permission.denied` naming that step. The `risk` descriptor and the dry-run default sit on top of
that boundary rather than in place of it. A script names the profile: `install plugin kubernetes
--access operate --confirm`.

Every flag above is declared and reaches the registry, so `help get k8s-pod` and
`help set k8s-resource` list them with their types and defaults — including `--dry_run`, which is
the argument that decides whether a cluster changes.

**What you cannot type.** `exec`, `attach` and `port-forward` are refusals that say what is missing
rather than sessions (§42.3–§42.5), waiting on a terminal-ownership contract core has specified and
not built (`ADR-0599 (core)`). `trace` and `diff` reach no Kubernetes noun: `trace` is the shell's
relationship verb, bound to core targets, so a Kubernetes object's graph is walked with `near`,
`follow`, `get k8s-relation` and `get k8s-why` instead; `diff` is core's unbuilt v0.5 snapshot
comparison. Both wait on a generic core increment rather than on this provider. Each limit is named
with its reason in [`docs/coverage.md`](docs/coverage.md).

**What is asked for later.** A kubeconfig authenticating through an `exec` credential plugin —
which is how EKS, GKE and AKS are usually configured — runs that plugin under `process.exec`, and
under nothing less: §8.2 requires an explicit process-execution capability. You were not asked for
it at install. The first context that needs a helper is the moment you are asked, for that one
program:

```text
Kubernetes needs to run an external program to authenticate to the selected context:
  /usr/local/bin/aws
Allow this helper? [o] once  [s] this session  [a] always for this program  [n] deny  [d] details
```

`always` is a grant scoped to exactly that program, kept across sessions and visible under
`get permission kubernetes`. A script cannot be asked and gets `permission.required` with the line
that would allow it — `set permission kubernetes credential-helper --decision allow --scope
programs=/usr/local/bin/aws`. Either way the helper gets the environment your kubeconfig declares
and nothing inherited.

`grant capability` and `revoke capability` still exist, as the raw administrative mechanism under
all of this; `get permission kubernetes --all` shows how each permission maps onto them.

**From your distribution's package manager.** The same signed payload ships as a `.deb` and an
`.rpm` named `ono-plugin-kubernetes` (K11A §22, ADR-0071). Installing one places the payload
under `/usr/lib/ono-sendai/plugin-sources/io.github.godspeed-you.kubernetes/<version>/` and
nothing else — no maintainer script, no activation, no trust, no permission. Ono then does what
it does for any source:

```text
$ sudo apt install ono-plugin-kubernetes         # or: sudo dnf install ono-plugin-kubernetes
$ ono
> install plugin kubernetes
Source: system package (ono-plugin-kubernetes)
…
Install with recommended access? [Y/n/details]
```

**Who signed it, and how to trust them.** The payload is signed without a key: the release
workflow proves its identity with a short-lived token, a certificate is issued to it for about ten
minutes, and the public transparency log records that it was used (`ADR-0609 (core)`, ADR-0071).
Nothing in this repository holds a private key, and there is no secret to leak. Ono verifies that
offline; to trust it, enrol the identity once:

```yaml
# ~/.config/ono/kuang/trust.yaml
format: kuang-trust/1
identities:
  - publisher: io.github.godspeed-you
    issuer: https://token.actions.githubusercontent.com
    identity: https://github.com/godspeed-you/ono-sendai-kubernetes/.github/workflows/release.yml@refs/tags/*
    trust: trusted
```

Until you do, `verify plugin kubernetes` answers `signature: valid` and `trust: unknown`, which
are two different questions and stay two answers.

The package manager grants Ono nothing; the prompt is the same one, and the payload is copied
into Ono's own store, so `apt upgrade` under the root makes a new candidate and never touches the
running plugin until you run `install plugin kubernetes` again. `remove plugin kubernetes`
removes Ono's copy and tells you the system source remains; `apt remove ono-plugin-kubernetes`
removes that. `scripts/package.sh --keyless` is what the release runs, and
`scripts/package.sh --key <signing key>` builds both wrappers locally and prints the content
digest a catalog entry states; the generic contract is core's
`docs/specs/kuang11/kuang11-plugin-package-acquisition-system-distribution.md`.

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
| KUANG/11 package format | `kuang-package/2` — `/1` plus the `permissions` section — and `kuang_api >=11.2 <12`, the host API that answers `capabilities.check` with `ask` and holds a `process.exec` call on a person's consent (`ADR-0600 (core)`, `ADR-0603 (core)`) |
| Ono-Sendai core, to build | the revision `Cargo.toml` pins, which carries `ADR-0588 (core)` — a contributed target declares whether its answer ends, which is what lets a watch reach the shell as a live stream rather than as a table that never arrives |
| Ono-Sendai core, to run | **at or after `ADR-0590 (core)`**, which is the revision every manifest here pins and CI builds the shell from. `ADR-0588 (core)` is what makes `get k8s-change` and `get k8s-log --follow` stream rather than be collected; `ADR-0590 (core)` is what makes a refusal from either of them *reach you*, and a host between the two answers an empty table where this provider refused |
| Kubernetes versions | **v1.35 – v1.37**, which is what upstream maintained on the specification's snapshot date (§0.5, §5.1). The claim is a tested matrix rather than a parser guard: nothing in the provider inspects `gitVersion`, and a cluster outside the window may work perfectly (§5.2) |
| Kubernetes versions actually exercised | **v1.35.8, v1.36.4 and v1.37.0** — the declared oldest, the one between and the newest — on ephemeral `kind` clusters in CI and on demand through `scripts/cluster.sh` (§5.5, §59.3, Gate N) |
| Releases of this provider | **v0.2.1** — the signed `.deb` and `.rpm` wrappers, needing `ono >= 0.4.4`; v0.2.0 brought the KUANG/11 permission contract; v0.1.0 was the first, built from this repository as a KUANG/11 package |

The provider is discovery-first by construction: every REST path is built from what the connected
API server says it serves, and no endpoint is compiled in (§5.2). The matrix above is what CI
runs, not what the code permits.

## Seeing it work

```bash
scripts/demo.sh              # or --version v1.35.8, or --keep to poke at the cluster afterwards
```

Builds an ephemeral `kind` cluster, installs the package the way an operator installs one, and
runs §65's whole "useful Kubernetes provider" list at an ordinary `ono` prompt: connect, enter,
discover a CRD invented minutes ago, inspect the fields the schema does not describe, walk
`Deployment → ReplicaSet → Pod → Node` and `Service → EndpointSlice → Pod` with the evidence under
each hop, watch a collection live, meet a denial that is not an emptiness, export a Node's machine
identity, plan a change, hit a field-manager conflict, take ownership with a written reason, and
read a log — with `kubectl` nowhere in the path. It narrates; the assertions are in
`crates/ono-kubernetes-plugin/tests/live_cluster.rs`.

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
| PersistentVolumeClaim, PersistentVolume, StorageClass | yes | yes | yes, including `bound-to` and `uses-storage-class` | yes | yes, bounded |
| NetworkPolicy | yes | yes | yes, from both ends (§31.1) | yes | yes, bounded |
| RBAC (Role, RoleBinding, ClusterRole, ClusterRoleBinding) | yes | yes | yes, `binds` (§32.2) | yes | yes, bounded |
| HPA, PDB, quotas, admission, CSI, leases (§15.3 Tier 2) | yes | yes | no | yes | yes, bounded |
| Custom resources of any CRD | yes | no, and none is needed | yes, through owner references and generic rules | yes | yes, bounded |

"Mutation capable" means one bounded field change or one deletion, of one object named by the
caller, with the preconditions taken from the object that was read — never a bulk operation. §43.3's seven curated actions are served as *arguments* of those two
verbs — `--replicas`, `--restart_rollout`, `--schedulable` and the rest — rather than as words of
this package's own, which is where the pressure toward a mini-shell was and where it was refused. "Watch capable"
means `get k8s-change` resolves the collection through discovery, so a kind invented after this
package was built is watchable — proven against a real cluster on a CRD created while the watch was
open.

## Maturity levels

The specification defines six conformance levels (§61), and a provider may sit at different
levels for different resource families rather than claiming one flag:

```text
K0  connection and discovery                            6 of 6
K1  dynamic read model, including CRDs                   7 of 7
K2  operational graph — relationships and navigation     7 of 7
K3  live Kubernetes — watch continuity, gaps, freshness  6 of 6
K4  bounded safe actions                                 7 of 7
K5  temporal and cross-system enrichment                 5 of 5
```

**No level is claimed, and the reason is no longer evidence.** §0.1 binds a conformance claim to
the corresponding acceptance gates, and all fourteen are met — the live half of that evidence run
against `kind` at v1.35.8, v1.36.4 and v1.37.0. What is left is judgement: a level is a promise to
a user about a provider nobody has yet run against a production cluster, and the place to assemble
the evidence for one is [`docs/coverage.md`](docs/coverage.md) rather than this table.

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
Navigation through the existing spatial model is built too: an object is a place, `near` answers
in §35.5's order under a `relation.write` grant, and a CRD invented after the build is entered.
What the gate asks for that is *not* here is a provider it has been run against in anger.

The specification's §64 sets the implementation order: connection foundation, then the dynamic
resource model, then the curated operational graph, then live observation. All four are closed,
and parts of phases 5 through 8 arrived early. The one cost that used to remain — a mutation
verified by an immediate read rather than against a watch — is closed: `set k8s-resource` watches
the controller converge before it reports (§46.3).

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

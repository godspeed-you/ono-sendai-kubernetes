# Ono-Sendai Kubernetes

**Kubernetes as typed objects, relationships and places — inside the shell you already have.**

> Kubernetes is not a command namespace inside Ono. It is a system Ono can understand.
> — [the Kubernetes Provider Specification](docs/architecture/kubernetes-provider.md), §1

This is the reference KUANG/11 external-system provider for
[Ono-Sendai](https://github.com/godspeed-you/ono-sendai): a package that speaks HTTPS to an API
server, reads any kind a cluster serves, walks relationships with the evidence under each edge,
navigates the shell's spatial model, and — under a grant an operator gives deliberately — makes
one bounded change. No Kubernetes concept lives in core.

[**Install**](#installing-it) · [**Quick start**](#quick-start) ·
[**Specification**](docs/architecture/kubernetes-provider.md) ·
[**Coverage**](docs/coverage.md) ·
[**Releases**](https://github.com/godspeed-you/ono-sendai-kubernetes/releases)

---

## The problem

A cloud-native question crosses `Ingress → Service → EndpointSlice → Pod → Node → cloud instance
→ host → process → socket`. The API server holds the upper half of that path as structure: UIDs,
owner references, selectors, endpoints, conditions. Then `kubectl` prints columns, and an operator
reassembles the structure by hand — `-o json | jq`, a name copied from one output into the next
command, an identifier translated across a tool boundary because the two tools disagree about what
a column is.

The flattening costs more than typing. An RBAC denial, a stale cache and a watch that dropped its
connection all render as the same thing at a terminal: nothing. A `Pod` name is reused the moment
its predecessor dies. A relationship the cluster asserts and one an operator guesses look alike
once both are text.

## What it feels like

Objects keep their shape all the way down the pipe:

```text
local://~ > get k8s-pod --context prod --namespace shop | select name phase node restarts

NAME                  PHASE    NODE           RESTARTS
api-7d9f-4kx2t        Running  prod-worker-1  0
api-7d9f-9wlmz        Running  prod-worker-3  2
checkout-6b4d8-xq7vp  Running  prod-worker-1  0
```

That table is a rendering. What flows through the pipe is `Stream<KubernetesPod>` — `restarts` is
a number, `created` is a timestamp, `labels` is a map with keys in it, and `uid` is the identity a
reused name cannot forge — so the next stage addresses objects rather than columns:

```text
local://~ > get k8s-pod --context prod --namespace shop | take 1 | enter
local://~ > near
```

An object is a place. `near` answers with the neighbours the cluster itself asserts, and an edge
says where it came from — `evidence_class` names whether it was an owner reference, an evaluated
selector, a label convention or an inference, and `evidence_path` names the field it was read
from:

```text
local://~ > get k8s-relation --context prod --kind Deployment --name checkout
```

A selector goes to the API server and is answered there, and a kind invented minutes ago reads
exactly like one that shipped with Kubernetes:

```text
local://~ > get k8s-pod --context prod --namespace shop --selector 'app=api,tier!=cache'
local://~ > get k8s-resource --context prod --kind Sprocket
```

And a refusal stays a refusal. A namespace you may not list comes back as a coverage gap carrying
its own word — denied, not served, unavailable, a page that failed — beside the records that did
arrive; a watch that lost its connection says which period it could not observe. Neither one
becomes an empty table.

## Why this provider

- **Typed by discovery, never by a compiled-in table.** Every REST path is built from what the
  connected server says it serves, so CRDs, aggregated APIs and kinds newer than this build all
  read through the same path (§5.2, §13).
- **Relationships carry their evidence.** `owner-reference`, `selects`, `scheduled-on`,
  `bound-to`, `binds` and the rest name the field they were read from and how strong that reading
  is, so an edge can be argued with.
- **A cluster is a place.** Contexts, namespaces and objects sit in the spatial model Ono already
  has: `enter`, `look`, `near`, `back`, and `get k8s-why` for the dependency paths behind a state.
- **Identity outlives the name.** UIDs are the identity and names are locators, so a recreated
  `Pod` is a different object from its predecessor, whatever the two share (§16).
- **Denial, staleness and gaps are facts.** Each is a value with a reason on it.
- **Reading and changing are two decisions.** The recommended install cannot send a write, and
  the authority to change a cluster sits in a separate profile you enable on purpose.
- **No verb of its own.** The package contributes 47 targets, 2 commands and zero new words:
  reading is `get`, and the two that write are core's `set` and `remove`, aimed at the noun `get`
  reads.

## Installing it

Requirements: Linux on x86_64, and `ono` 0.4.4 or newer.

Each [release](https://github.com/godspeed-you/ono-sendai-kubernetes/releases) carries a `.deb` and
an `.rpm` wrapper, beside the signed `.kuang` payload a catalog entry names:

```bash
sudo apt install ./ono-plugin-kubernetes_0.2.3_amd64.deb    # Debian, Ubuntu and relatives
sudo dnf install ./ono-plugin-kubernetes-0.2.3-1.x86_64.rpm # Fedora, RHEL and relatives
```

That places the payload under `/usr/lib/ono-sendai/plugin-sources/` and does nothing else — no
maintainer script, no activation, no trust, no permission. Ono decides the rest:

```text
$ ono
local://~ > install plugin kubernetes
Source: system package (ono-plugin-kubernetes)

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

Each line resolves to exact KUANG/11 capabilities the host grants on the package's behalf:
`network.connect`, a `filesystem.read` pinned to `~/.kube/config` and `~/.kube/*.yaml`,
`secret.use`, a `relation.write` bounded to this package's own relation shapes, `state.persist`
and `clock.read`. `details` shows every one with its scope, enforcement and duration;
`get permission kubernetes` shows the same afterwards. A script names its profile instead of being
asked: `install plugin kubernetes --access operate --confirm`.

`apt upgrade` changes a candidate under the system root and never the plugin you are running,
until `install plugin kubernetes` copies the new payload into Ono's own store.
`remove plugin kubernetes` removes Ono's copy and says the system source remains.

Or build it, with the Rust toolchain `rust-toolchain.toml` pins:

```bash
git clone https://github.com/godspeed-you/ono-sendai-kubernetes
cd ono-sendai-kubernetes
scripts/package.sh --key <signing key>   # runtime, payload, .deb and .rpm
```

That needs `kuang-sign` from core's `ono-kuang-sdk` — on your `PATH`, or in a sibling
`ono-sendai` checkout — and a key of your own, which `kuang-sign keygen --out <file>` writes. The
run prints the content digest a catalog entry would state.

## Verifying the package

The payload is signed without a key. The release workflow proves its identity with a short-lived
token, a certificate is issued to it for about ten minutes, and the public transparency log records
that it happened — so this repository holds no private key and there is no secret to leak
(`ADR-0609 (core)`, [ADR-0071](docs/adr/ADR-0071-a-distribution-package-is-a-source-of-the-plugin-and-never-its-installer.md)).

Ono verifies that offline. To trust the identity behind it, enrol it once:

```yaml
# ~/.config/ono/kuang/trust.yaml
format: kuang-trust/1
identities:
  - publisher: io.github.godspeed-you
    issuer: https://token.actions.githubusercontent.com
    identity: https://github.com/godspeed-you/ono-sendai-kubernetes/.github/workflows/release.yml@refs/tags/*
    trust: trusted
```

Until you do, `verify plugin kubernetes` answers `signature: valid` and `trust: unknown`. Those are
two questions, and they stay two answers.

## Quick start

Six things to try, roughly in the order they change your idea of what a cluster is:

```text
get k8s-cluster  --context prod                   which cluster, reachable, as whom
get k8s-pod      --context prod --namespace shop  a typed table, no jq in sight
get k8s-resource --context prod --kind Sprocket   any kind the server serves, CRDs included
get k8s-change   --context prod --kind Pod        live, until you stop it; gaps are records
get k8s-relation --context prod --kind Pod --name api-7d9f   the edges, and their evidence
get k8s-why      --context prod --kind Pod --name api-7d9f   dependency paths, never a cause
```

The rest of the surface: `k8s-event`, `k8s-condition`, `k8s-timeline`, `k8s-log`, `k8s-plan` for a
change you have not made, `k8s-evidence` for what a `Node` says about the machine under it, and
`set` / `remove k8s-resource` for the two operations that write. Every flag is declared and reaches
the registry, so `help get k8s-pod` and `help set k8s-resource` list them with their types and
defaults — `--depth` on `k8s-why`, `--selector` on a listing, `--dry_run` on a write.

## Changing a cluster

`provider.mutate` is the authority to change cluster state. `set k8s-resource` and
`remove k8s-resource` declare it, the host checks it at every invocation before any of this
package's code runs, and it belongs to no recommended profile. Enabling it is its own sentence,
with its own confirmation:

```text
local://~ > set permission kubernetes --profile operate
```

Until then a mutation fails with `permission.denied` naming that step. On top of that boundary sit
two more: `set k8s-resource` declares `risk: mutate` and `remove k8s-resource` declares
`risk: destructive`, which the host's own confirmation policy reads, and **`dry_run` defaults to
`true`** — the shortest sentence you can write asks the API server to run admission and persist
nothing. `--dry_run false` is where you say which of the two you meant.

A change is one field of one object named by the caller, with the preconditions taken from the
object that was read. §43.3's curated actions are arguments of those two verbs — `--replicas`,
`--image`, `--restart_rollout`, `--schedulable`, `--label`, `--annotation` — rather than words of
this package's own, and `--set` with a JSON pointer is the expert path underneath them. A real
write then watches the controller converge before it reports, so what you get back is what
happened and never only what was accepted (§46.3). A field-manager conflict is an answer, and
taking ownership costs a written reason: `--force_because '…'`.

**Credentials are asked for at the moment of use.** A kubeconfig that authenticates through an
`exec` credential plugin — how EKS, GKE and AKS are usually configured — needs `process.exec`, and
you were not asked for it at install. You are asked at the first context that needs one, about that
one program:

```text
Kubernetes needs to run an external program to authenticate to the selected context:
  /usr/local/bin/aws
Allow this helper? [o] once  [s] this session  [a] always for this program  [n] deny  [d] details
```

`always` is scoped to exactly that program and survives sessions. A script cannot be asked and gets
`permission.required` carrying the line that would allow it. Either way the helper gets the
environment your kubeconfig declares and nothing inherited.

## What it will not do

`exec`, `attach` and `port-forward` are refusals that say what is missing, waiting on a
terminal-ownership contract core has specified and has not built (§42.3–§42.5). `trace` and `diff`
reach no Kubernetes noun: `trace` is bound to core targets, so an object's graph is walked with
`near`, `follow`, `get k8s-relation` and `get k8s-why` instead, and `diff` is core's unbuilt
snapshot comparison. Both wait on a generic core increment rather than on this provider.

The specification's §3 rules out the rest normatively: this is no `kubectl` wrapper, dashboard,
Helm implementation, GitOps controller or metrics backend. Each limit is named with its reason in
[`docs/coverage.md`](docs/coverage.md).

## Seeing it work

```bash
scripts/demo.sh              # or --version v1.35.8, or --keep to poke at the cluster afterwards
```

Builds an ephemeral `kind` cluster, installs the package the way an operator installs one, and runs
§65's whole "useful Kubernetes provider" list at an ordinary `ono` prompt: connect, enter, discover
a CRD invented minutes ago, walk `Deployment → ReplicaSet → Pod → Node` and
`Service → EndpointSlice → Pod` with the evidence under each hop, watch a collection live, meet a
denial that stays a denial, export a Node's machine identity, plan a change, hit a field-manager
conflict, take ownership with a written reason, and read a log — with `kubectl` nowhere in the path.
It narrates; the assertions live in `crates/ono-kubernetes-plugin/tests/live_cluster.rs`.

## Compatibility

| | |
|---|---|
| Ono-Sendai core | **0.4.4 or newer** to run; to build, the core revision `Cargo.toml` pins, which CI builds the shell from |
| KUANG/11 package format | `kuang-package/2` and `kuang_api >=11.2 <12` — the host API that answers `capabilities.check` with `ask` and holds a `process.exec` call on a person's consent |
| Kubernetes versions | **v1.35 – v1.37**, what upstream maintained on the specification's snapshot date (§0.5, §5.1). Nothing inspects `gitVersion`, so a cluster outside the window may work perfectly (§5.2) |
| Versions actually exercised | **v1.35.8, v1.36.4 and v1.37.0** — the declared oldest, one between, the newest — on ephemeral `kind` clusters in CI and on demand through `scripts/cluster.sh` |
| Platforms | linux-amd64 and linux-arm64 in the manifest; releases publish amd64 wrappers |
| Releases | **v0.2.3**, the signed `.deb`, `.rpm` and `.kuang`. v0.2.2's `.kuang` was packed without its signature and should not be used; v0.2.0 brought the KUANG/11 permission contract; v0.1.0 was the first |

## Documentation

| | |
|---|---|
| [`docs/architecture/kubernetes-provider.md`](docs/architecture/kubernetes-provider.md) | the Kubernetes Provider Specification — canonical here, immutable, checksummed |
| [`docs/coverage.md`](docs/coverage.md) | what of it is built, section by section, with the evidence for each verdict |
| [`docs/STATE.md`](docs/STATE.md) | the work board: what is in progress, found, or deferred |
| [`docs/adapters.md`](docs/adapters.md) | the adapter registry, for a contributor teaching the provider a kind |
| [`docs/adr/`](docs/adr/) | decisions recorded in this repository |
| [`package/`](package/) | the KUANG/11 package: manifest, targets, commands and schemas |
| [`crates/ono-provider-kubernetes/`](crates/ono-provider-kubernetes/) | the domain layer: twenty-four modules, no host and no cluster |
| [`crates/ono-kubernetes-plugin/`](crates/ono-kubernetes-plugin/) | the `ono-kubernetes` binary: the KUANG/11 boundary |
| [`AGENTS.md`](AGENTS.md) | the development contract, for humans and AI agents alike |
| [`scripts/gate.sh`](scripts/gate.sh) | the quality gate every change must pass |

**Relationship to Ono-Sendai.** Kubernetes domain logic stays out of core, which is what keeps the
generic KUANG/11 contract testable as a real extension boundary and lets this repository release on
its own cadence. It is authoritative for Kubernetes API integration, resource mapping,
Kubernetes-local relationships, CRD handling, watch and cache behaviour, compatibility policy, and
its own specification. The [core repository](https://github.com/godspeed-you/ono-sendai) is
authoritative for the shell language, the generic systems model, the KUANG/11 host and runtime
contracts, and project-wide governance; two of its documents govern this one —
[`docs/architecture/external-system-provider.md`](https://github.com/godspeed-you/ono-sendai/blob/main/docs/architecture/external-system-provider.md),
the contract this provider conforms to, and
[`docs/strategy/cloud-native-vision.md`](https://github.com/godspeed-you/ono-sendai/blob/main/docs/strategy/cloud-native-vision.md),
why the direction is being taken at all. Both stay canonical there and are deliberately not copied
here. A separate Git repository does not make this a separate project.

## Project status

**Current release: v0.2.3.** All 22 core invariants of §4 hold and all fourteen acceptance gates of
§62 are met, the live half of that evidence run against `kind` at v1.35.8, v1.36.4 and v1.37.0 on a
machine with no `kubectl` installed. Most of the suite runs against recorded API bytes; the rest
runs the real `ono` binary against ephemeral clusters. **It has not been run against a production
cluster.**

The specification defines six conformance levels (§61), and every requirement of all six is met:

```text
K0  connection and discovery                             6 of 6
K1  dynamic read model, including CRDs                   7 of 7
K2  operational graph — relationships and navigation     7 of 7
K3  live Kubernetes — watch continuity, gaps, freshness  6 of 6
K4  bounded safe actions                                 7 of 7
K5  temporal and cross-system enrichment                 5 of 5
```

**No level is claimed**, and what stands in the way is judgement: a level is a promise to a user
about a provider nobody has yet run in anger, and the place to assemble the case for one is
[`docs/coverage.md`](docs/coverage.md).

The Cloud-Native Validation Gate in
[`docs/strategy/cncf-readiness.md`](https://github.com/godspeed-you/ono-sendai/blob/main/docs/strategy/cncf-readiness.md)
in core asks whether Ono's existing concepts become *more* useful against Kubernetes without
growing a second, Kubernetes-shaped shell. Everything it asks for is built and tested here — direct
API interaction with no `kubectl` in the path, UID-aware identity, kinds unknown at compile time,
evidence-carrying relationships, navigation through the existing spatial model, honest handling of
denial and watch discontinuity, deterministic tests needing no live cluster, and zero Kubernetes
special cases in core. What is missing is the one thing a repository cannot supply itself: a
production cluster somebody has depended on it against. Ono-Sendai is not a CNCF project.

→ [open issues](https://github.com/godspeed-you/ono-sendai-kubernetes/issues) ·
[`docs/STATE.md`](docs/STATE.md) · [`docs/coverage.md`](docs/coverage.md)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Kubernetes expertise is valued independently of Ono core
expertise (§66.4), and the contribution surfaces are bounded on purpose: discovery and schema,
workload relationships, network relationships, storage, RBAC and identity, watch and cache, events,
mutation and verification, CRD adapters, fixtures and version compatibility (§66.1).

```bash
scripts/gate.sh              # format, lint, test, documents, contracts — every change passes it
scripts/cluster.sh up        # an ephemeral kind cluster, for the live half
```

Development is specification-first and test-first, the specification is immutable and checksummed,
and anything architectural is recorded as an ADR in [`docs/adr/`](docs/adr/). There is **no
maintainer list yet**, here or in core; nobody is listed as maintaining this provider who is not.

## Security

See [`SECURITY.md`](SECURITY.md). This package handles cluster credentials and can reach production
infrastructure, so report a suspected vulnerability privately rather than in a public issue.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Core is MIT-licensed at the time of writing; its own
Apache-2.0 transition is a separate decision, recorded in core's `docs/strategy/cncf-readiness.md`
§3 and not executed.

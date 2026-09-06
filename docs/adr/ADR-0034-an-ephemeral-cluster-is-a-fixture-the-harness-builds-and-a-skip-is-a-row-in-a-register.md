# ADR-0034: An ephemeral cluster is a fixture the harness builds, and a skip is a row in a register

- Status: accepted
- Date: 2026-09-06
- Spec refs: §0.5, §4 invariants 1–2, 4–5, 13, §5.1, §5.2, §5.5, §7.1, §7.5, §8.4, §9.4, §12.2, §12.3, §12.5, §14.2, §14.6, §17.1, §19.1, §19.4, §21.4, §23, §24, §33.1, §51.4, §59.1, §59.2, §59.3, §59.4, §59.5, §62.1, §62.2, §62.3, §62.5, §62.8, §62.13, §62.14
- Decided by: agent (autonomous)

## Context

Twelve of the fourteen acceptance gates of §62 are provable from a recorded document, and this
repository proves them that way, because §59.1 requires it: *"All mandatory provider conformance
tests MUST run without production credentials."* Two are not, and one more is only half provable.

- **§62.14, Gate N**: *"Release CI passes against the declared oldest and newest supported
  Kubernetes minor versions."* A recording has no version. §5.1 states the window — *"At the time
  this specification was written, that means v1.35 through v1.37"* — and adds the sentence that
  decides the shape of the answer: *"The support statement MUST be expressed as a tested
  compatibility matrix, not as a parser guard that rejects other versions."* A matrix is a thing
  that runs, not a constant in a source file.
- **§62.13, Gate M**: *"Core conformance works on a machine where `kubectl` is absent."* Half of
  that is static and this repository already had it — no module that reaches a cluster spawns a
  subprocess (§51.4). The other half is a property of a *machine*, and no static check observes a
  machine.
- **§59.3**: *"CI SHOULD additionally run integration tests against disposable local Kubernetes
  clusters such as kind or an equivalent project-approved mechanism. These tests validate real API
  behavior not faithfully represented by fixtures."* §59.4 adds: *"Local integration SHOULD cover
  the provider's declared upstream support window at release qualification time."* And §5.5 asks
  CI for *"oldest actively supported Kubernetes minor release targeted by the provider"*, *"latest
  actively supported minor release"*, and *"one intermediate release when practical"*.

There was no cluster harness at all, so all three were unproven. §0.5's snapshot fixes the ends of
the window at v1.35 and v1.37; the `kindest/node` tags that exist for them are **v1.35.8** and
**v1.37.0**, verified against Docker Hub on 2026-09-06.

Three things made this harder than "run some tests against kind".

**The fixtures cannot be installed with `kubectl`.** A harness that reached for it would prove
Gate M on a machine that has the tool the gate is about. Every object has to go in over the
Kubernetes REST API.

**The provider deliberately creates nothing.** `plan_on` refuses a mutation whose target does not
exist — *"a change is aimed at an object that exists, and this provider creates nothing it was not
asked to change"* — which is right (§21.3 of the generic provider contract, ADR-0019) and means
Gate C's *recreate* half cannot be driven through `ono` at all.

**A skipped test reports as a pass.** The live suite must skip where there is no cluster, or
`scripts/gate.sh` would depend on one, which AGENTS.md §7 forbids. But `spatial_shell.rs` already
skipped with a bare `eprintln!("skipped: …")` and a silent `return`, and cargo reported those runs
as seven passes. Core met the same defect and closed it in `ADR-0513 (core)`: a skip carries one
of six categories and announces `SKIPPED <test>: <category>: <detail>`, and §38.2 of core's
specification requires the expected set to be declared as data.

## Decision

**The cluster is a fixture the harness builds, over the same REST API the provider speaks; and
every test that can skip is a row in a register the gate checks in both directions.**

### `scripts/cluster.sh` — an ephemeral cluster with no Kubernetes client

```text
scripts/cluster.sh up   [--version vX.Y.Z] [--name <cluster>]   # prints the kubeconfig path
scripts/cluster.sh down [--name <cluster>]
```

`kind` creates the cluster and `docker` runs its node; neither is a Kubernetes client. Everything
after that is `curl` against the API server, authenticated with the client certificate out of
`kind get kubeconfig` — `certificate-authority-data`, `client-certificate-data` and
`client-key-data` decoded to a mode-700 temporary directory that the exit trap removes.

`up` is idempotent (a cluster of the same name is replaced rather than reused, because a
half-installed fixture set is indistinguishable from a complete one until a test fails on it), and
it never leaves a cluster running when it fails: the trap deletes what the run created.

**The fixtures are the ones the gates name.** Two namespaces; three CRDs invented for the test — a
namespaced structural one, a cluster-scoped one, and one whose schema carries
`x-kubernetes-preserve-unknown-fields` — with custom resources of each; a Deployment, a Service, a
ConfigMap, a Secret, a ServiceAccount; a StorageClass, a PersistentVolume and a PersistentVolumeClaim
bound to it; a ConfigMap held by the finalizer `ono.test/hold`; a ConfigMap named `lifetime` for
Gate C to delete; and a restricted identity — a ServiceAccount with a Role granting `get`/`list`
in `ono-alpha` only, a `TokenRequest`-minted bound token, and a second kubeconfig context carrying
it.

**Derived objects are waited for, never assumed.** `up` polls, with a bounded timeout and a loud
failure, for each CRD to be `Established`, for the ReplicaSet, for a Pod that is both scheduled and
addressed, for an EndpointSlice whose endpoints carry a `targetRef`, and for the PVC to be `Bound`.
A Pod that has not been scheduled has no Node to be related to and no address to appear in a slice,
so a harness that returned early would hand the relationship tests a cluster that is still catching
up and call the resulting flake a bug in the provider.

**`ono-beta` holds objects.** This is the fixture decision Gate E rests on: a `403` over an empty
namespace and a `403` over a full one look the same to the provider, but only the second makes
"empty" a *wrong* answer rather than a coincidentally right one (§4 invariant 13, §21.4).

**The kubeconfig is written rather than patched**, with two contexts — `ono-admin` on the client
certificate and `ono-restricted` on the bound token, both defaulting to the `ono-alpha` namespace
(§7.5). Fixed names, because the tests read them and a name that changed per run would be a second
thing to pass between the script and the suite.

### `tests/live_cluster.rs` — eleven tests, driving the real binary

The harness is `tests/spatial_shell.rs`'s, extended: the package is laid out in a scratch plugin
home the way an operator installs one, the real manifest and contribution documents are used byte
for byte, and the kubeconfig is copied to `$HOME/.kube/config` inside that home. Two operator
decisions are part of the script rather than hidden in a test hook — the `filesystem.read` grant is
widened with `grant capability --scope 'paths=…/.kube/**'` (the supervisor matches a granted path
as a glob against the path the package asks for, and the manifest's declared `~/.kube/config` does
not expand), and `relation.write` is named on `load plugin` because §31.19 never grants it by
default.

What each test proves:

| test | proves |
|---|---|
| `should_reach_a_cluster_a_kubeconfig_context_names_and_report_the_version_it_serves` | §7.1, §8.4, §11.1 and Gate N: kubeconfig read under `filesystem.read`, TLS verified against the pinned authority, client certificate presented, and `server_version` compared with `ONO_K8S_EXPECT_VERSION` so a matrix leg proves which end of the window it ran against |
| `should_list_a_built_in_kind_and_read_one_object_at_its_own_endpoint` | K0/K1: a collection listed, then one object read at its own endpoint rather than filtered out of the collection (§17.1, ADR-0012) |
| `should_type_a_custom_kind_the_cluster_learned_after_this_package_was_built` | Gates A and B: `schema_source: openapi-v3`, `precision: structural` and an integer `spec.size` for the Widget; `scope: cluster` and a null namespace for the Constellation; `precision: unknown` and `/spec/pressure` among `untyped` for the Sketch (§12.2, §12.3, §12.5) |
| `should_keep_two_lifetimes_of_one_name_apart_across_a_delete_and_a_recreate` | Gate C: the uid read, the delete carrying it as a precondition, `verdict: confirmed`, and a second uid under the same name (§4 invariants 4–5, §56.3) |
| `should_report_a_denied_namespace_as_a_denial_rather_than_an_empty_result` | Gate E: the administrator sees objects in `ono-beta`, the restricted identity reads `ono-alpha`, and the same read of `ono-beta` ends the invocation naming the denial with no empty sequence anywhere |
| `should_report_a_deletion_held_by_a_finalizer_as_terminating_rather_than_deleted` | Gate H: `deletion_state` contains `terminating` and not `absent`, the finalizer is named, and a read afterwards still finds the object with `terminating: true` (§14.6) |
| `should_walk_a_deployment_to_the_node_over_objects_a_control_plane_produced` | Deployment → ReplicaSet → Pod → Node, each hop a separate read, with `owner-reference` and `native-field` kept apart and `/spec/nodeName` named as the field that decided the scheduling edge (§23) |
| `should_reach_the_pod_behind_a_service_through_the_endpointslice_the_cluster_wrote` | Service → EndpointSlice → Pod, with three evidence classes in one answer — `selector`, `convention`, `native-field` — and both routes arriving at the same Pod (§23, §24) |
| `should_observe_a_real_create_on_a_watch_of_a_kind_invented_for_the_test` | §19.1's list-then-watch as one sequence: `max_changes` at one more than the collection holds, an object created while the watch is open, and an `added` record carrying the uid the API server minted, `continuous` (§19.4) |
| `should_answer_a_live_read_on_a_machine_with_no_kubectl` | Gate M's live half: the test looks for `kubectl` on `PATH` itself and fails the run if it finds one, then does the read |
| `should_carry_no_subprocess_on_any_path_that_reaches_a_cluster` | Gate M's static half, repository-wide: no `Command::new` in any `crates/*/src` module (§51.4). The one test here that needs no cluster, and therefore the one that runs everywhere |

**The harness spawns `curl` and never `kubectl`.** Two tests need an object created while they
run, and the provider creates nothing, so the create is the harness's own work over the same REST
API with the same credential. `curl` is an HTTP client; `kubectl` is a Kubernetes client, and the
difference is what §62.13 is about.

### A skip is a row in a register, and the gate reads both directions

`docs/contracts/expected_test_skips.yaml` is the register — the first machine-readable contract
this repository has needed, in the directory AGENTS.md §2 reserves for exactly that. Seventeen
rows: ten live tests and the seven spatial outcome tests, whose ad-hoc `eprintln!("skipped: …")`
is replaced by the same marker.

A skip site is a call to `announce_skip("<test>", "<category>", …)` with both values as literals,
so the gate reads them without running anything. `scripts/gate.sh` gains a `skips` step that
fails when a skip site has no row, when a row's test no longer exists or no longer skips, when a
row's category disagrees with the marker, and when any test file still carries the ad-hoc form
outside a comment. Nothing already in the gate is reordered or weakened.

### CI runs the matrix at both declared ends

`.github/workflows/ci.yml` keeps the `gate` job unchanged and adds a `kubernetes` job over
`v1.35.8` and `v1.37.0`. It removes `kubectl` from the runner and proves it is gone, installs
`kind` pinned by version and sha256, checks core out at the revision `Cargo.toml` pins and builds
`ono` from it, creates the cluster with `scripts/cluster.sh up`, runs the live suite with
`ONO_K8S_EXPECT_VERSION` set to the leg's version, and deletes the cluster whatever happened.

Building core in CI is practical — it is one `cargo build -p ono-cli --bin ono` against a public
repository this workspace already fetches as a git dependency — so no part of §5.5 or Gate N is
faked. It is built once per matrix leg rather than passed between jobs as an artifact: sharing it
would add two more third-party actions to pin by digest for the sake of a few runner minutes.

## Consequences

- Gate M, Gate N and §59.3 are provable, and were proved: 11 of 11 live tests pass against
  `kindest/node:v1.35.8` and 11 of 11 against `kindest/node:v1.37.0`, on a machine with no
  `kubectl` installed, with the fixtures installed entirely over the REST API.
- `scripts/gate.sh` stays green **without** a cluster, and the ten live tests announce their skip
  instead of returning quietly. The register makes that visible rather than trusted.
- The suite is destructive on the fixtures it is given — it deletes `held` and deletes and
  recreates `lifetime`. That is the point of Gates C and H, and it is why the cluster is
  ephemeral: `scripts/cluster.sh up` is cheap (about 50 seconds with a warm node image) and is
  meant to be re-run rather than reused across days.
- A second external tool, `curl`, is now a prerequisite of the live suite. It is declared in the
  register with the rest, and the cluster cannot be created without it anyway.
- **`--dry_run false`, not `--dry-run false`.** The mutating commands' declared option is
  `dry_run`, and the shell takes it verbatim; the kebab spelling in `commands.yaml`'s examples is
  accepted silently and leaves the default in force, so a user following the example predicts when
  they meant to write. This is a finding about `package/contributions/commands.yaml`, which
  another worker owns — it is recorded here and not fixed here.
- The `map` option type on `set k8s-resource` is not in core's registry vocabulary, so every load
  of the package reports `(degraded)`. It does not affect anything above — the two mutating
  commands still run — and it belongs to whoever owns the contribution documents.
- kind's node images are pinned by patch version. When upstream's supported window moves, both
  the matrix and this ADR's reading of §5.1 move with it; nothing in the code carries a version.
- §5.5's *"one intermediate release when practical"* is not run. Two legs already double the
  Kubernetes CI cost, and the two ends are what Gate N names. `kindest/node:v1.36.4` exists, and
  adding a third row of the matrix is a one-line change if the cost is ever worth paying.

## Alternatives considered

**Install the fixtures with `kubectl` and assert its absence only in the test process.** Shorter
by a hundred lines, and it makes Gate M a claim about an environment variable rather than about a
machine. Rejected: the gate is *"core conformance works on a machine where `kubectl` is absent"*,
and a harness that needs it has not built that machine.

**Apply YAML manifests through `kind load` or a static bundle.** There is no such path that does
not go through a Kubernetes client. The REST API is the interface the provider itself uses, so
using it for the fixtures also means the harness and the subject agree about what the cluster is.

**Drive Gate C's recreate through `set k8s-resource`.** The apply path uses
`application/apply-patch+yaml`, which upstream *can* create with — but the plugin resolves and
reads its target first and refuses when it is absent, on purpose. Loosening that to make a test
convenient would trade a real invariant for a shorter harness. The harness creates the object
itself instead.

**Have `scripts/cluster.sh` pre-create both lifetimes and let the test compare two recorded uids.**
That proves the API server mints distinct uids, which nobody doubted. Gate C is about the
*provider* producing a lifecycle discontinuity, so the sequence has to run through `ono`.

**Detect an unannounced skip by scanning for a bare `return` in a test, as core does.** Core's
scanner is a real piece of software with escapes for closures, `async` blocks and blocks that
already asserted. Writing a second one in bash would guess, and a check that guesses is a check
people work around (`ADR-0428 (core)`). The register plus the literal-argument convention gets the
same guarantee for the skips that exist, and the convention is checkable exactly.

**Point the package at the kubeconfig where `scripts/cluster.sh` wrote it, under `target/`.**
It would need the same widened grant and would prove something about `target/`. Copying the file
into the scratch home puts it where §7.1 says an operator keeps one.

**Let the live tests fail rather than skip when there is no cluster.** It would make the register
unnecessary. It would also make `cargo test` in this repository require Docker, a network and two
minutes of cluster creation for anyone who wanted to change a parser — and §59.1 says the
mandatory path runs without any of that.

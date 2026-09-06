# Contributing to the Ono-Sendai Kubernetes provider

Contributions are welcome. This repository is developed **specification-first and test-first**,
the same way [Ono-Sendai](https://github.com/godspeed-you/ono-sendai) is.

[`AGENTS.md`](AGENTS.md) is the authoritative development contract for this repository, and it
applies to human contributors as well as to AI agents. It inherits Ono-Sendai's
[project-wide contract](https://github.com/godspeed-you/ono-sendai/blob/main/AGENTS.md) by
reference and states what differs here; neither file is a copy of the other. Read both before your
first change. This page is the short version.

## Where the project currently is

There is an implementation, and there is no release. The package connects to a cluster from a
kubeconfig context, reads any kind the cluster serves — including one invented after the build —
walks relationships with the evidence under each edge, watches a collection live at a terminal,
answers what it could not observe, and makes bounded changes under a declared risk and an
operator's grant. Most of it is proven against recorded API bytes; a live suite drives the real
`ono` binary against ephemeral `kind` clusters at the declared oldest, middle and newest supported
Kubernetes minor versions.

[`docs/coverage.md`](docs/coverage.md) is the section-by-section map of how far it goes and where
it stops, and it is the honest place to look for something to work on:

- a section it marks partial, with the gap named;
- a `SHOULD` nothing implements yet — §15.3's Tier 2 kinds are readable dynamically and none is
  curated, which is the largest well-defined piece of work on the board;
- a curated CRD ecosystem (§15.4), which is what the adapter surface exists for;
- the §68 open questions, which are explicitly reserved for later specifications or ADRs;
- reading [`docs/architecture/kubernetes-provider.md`](docs/architecture/kubernetes-provider.md)
  against real clusters you operate, and opening an issue where a requirement is wrong,
  unimplementable, or would produce a misleading answer.

`scripts/demo.sh` builds a cluster and runs the whole of §65's list at an `ono` prompt; it is the
fastest way to see what exists before deciding what to add. `scripts/cluster.sh up` gives you the
same cluster to work against.

## You do not need to know the shell

This is the point of the repository split. A contributor who knows Kubernetes deeply should be
able to extend resource mappings, relationship rules, CRD adapters or fixtures **without** reading
Ono's parser, job control, terminal rendering or shell startup (§2.9, §66.2). Review policy values
Kubernetes domain expertise independently from Ono core expertise (§66.4).

Bounded contribution surfaces (§66.1):

```text
discovery/schema          RBAC/identity            mutation/verification
workload relationships    watch/cache              CRD adapters
network relationships     Events/temporal          fixtures/version compatibility
storage relationships
```

## The rules that are not negotiable

These come from the specification and from the generic provider contract in core. A change that
breaks one of them is rejected regardless of how convenient it is.

- **Discovery is authoritative.** Learn what the API server actually serves; do not assume a
  compiled-in version, and do not reject a usable cluster because `gitVersion` is unfamiliar
  (§4 invariant 2, §5.2, §5.3).
- **CRDs are normal resources.** A change that gives built-in kinds typed behaviour while custom
  resources get raw JSON is non-conformant (§4 invariant 15, §33.1).
- **UID is lifetime identity; a name is not.** Same name, different UID is a different resource
  lifetime, and it must produce a lifecycle discontinuity rather than a merge (§4 invariant 4, §4 invariant 5, §16.3).
- **Missing permission is not absence.** `403`, an unserved API, an unqueried scope and an empty
  result are distinct states and must stay distinct (§4 invariant 13, §21.4).
- **A broken watch is a gap.** A `410 Gone` breaks continuity; pre-gap and post-gap events must
  never be stitched into a fake continuous history (§4 invariant 14, §19.4).
- **Evidence classes do not blur.** An owner reference, a selector evaluation, a well-known label
  convention and an inference are four different things, and each edge carries which one it is
  (§23). A guessed relationship must never render as a provider-proven one.
- **Secrets stay redacted, credentials never become values** (§4 invariant 21, §8.1, §22).
- **No Kubernetes special case in Ono core.** If a capability is broadly meaningful for external
  systems, extend the generic contract through an ADR in core; if it is Kubernetes-specific, it
  stays here (§0.4). The test: could an unrelated future provider ignore this concept without
  carrying Kubernetes baggage?
- **No hidden Kubernetes mini-shell.** Existing Ono verbs express these operations; a parallel
  `kubectl`-shaped vocabulary is not the interaction model (§4 invariant 22, §8.2 of the Cloud-Native
  Vision, §35.1).
- **Reads do not mutate.** Discovery, inspection, relationship traversal and rendering are
  side-effect free.

## Before you commit

```bash
scripts/gate.sh
```

It verifies that the specification is unmodified and present, that every relative markdown link
resolves, that ADRs match `ADR-NNNN-kebab-title.md` with the required headings, that the
instruction files still name the specification, and that every test which can announce a skip is
declared in `docs/contracts/expected_test_skips.yaml` — in both directions, so an undeclared skip
and a declaration whose test no longer skips both fail. Then `cargo fmt --check`, `cargo clippy
-D warnings`, the whole test suite and `cargo doc -D warnings`. It refuses to run on `main`,
because implementation belongs on `implementation` (`AGENTS.md` §11).

It takes about seven minutes and needs no cluster and no network: the live suite announces its
skips and the rest runs against recorded API bytes. To run the live half, `scripts/cluster.sh up`
and set `ONO_K8S_KUBECONFIG` to the path it prints.

## Tests

Provider tests must not contact live clusters by default. The specification requires a
deterministic test path that works without production credentials (§59), with fixtures able to
emulate pagination, RBAC denial, rate limiting, watch streams, `410 Gone`, connection reset and
version skew. All of those exist as recorded API bytes.

Beside them are three suites worth knowing about before you add to any of them:

- `tests/live_cluster.rs` drives the real `ono` binary against a real cluster and announces a
  declared skip when there is none, so the gate stays green without one;
- `tests/adversarial.rs` treats every value a cluster sends as attacker-chosen, because it is —
  anyone who can create an object names it. If you add a path that reads a name, a label, an
  annotation or a message, it belongs here too;
- `tests/performance.rs` asserts *counts*: how many requests a listing costs, how many objects are
  held at once, how many rows a view rebuilds. They are contracts, and a change that adds a
  request per object should fail one of them.

Relationship or API behaviour changes should arrive **with** their fixtures, not after them
(§66.3).

## Specification changes

The Kubernetes Provider Specification is canonical here and has exactly one copy. It is not
duplicated into the core repository, and it must not be.

Where it conflicts with an inherited safety or truthfulness invariant from core, **the inherited
invariant wins** unless an explicit ADR in core revises the generic contract for all providers
(§0.3). Changes that alter normative behaviour are recorded as decisions, not as silent edits.

## Commits and branches

Conventional Commits, English, one kind of change per commit, green tree. Do not push to `main`
directly, and do not open a pull request unless the work is finished and verified.

## Reporting security issues

Do not open a public issue for a vulnerability. See [`SECURITY.md`](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the Apache License 2.0, the
license of this repository. See [`LICENSE`](LICENSE).

# Contributing to the Ono-Sendai Kubernetes provider

Contributions are welcome. This repository is developed **specification-first and test-first**,
the same way [Ono-Sendai](https://github.com/godspeed-you/ono-sendai) is.

[`AGENTS.md`](AGENTS.md) is the authoritative development contract for this repository, and it
applies to human contributors as well as to AI agents. It inherits Ono-Sendai's
[project-wide contract](https://github.com/godspeed-you/ono-sendai/blob/main/AGENTS.md) by
reference and states what differs here; neither file is a copy of the other. Read both before your
first change. This page is the short version.

## Where the project currently is

There is **no implementation yet**. This repository holds the Kubernetes Provider Specification
and nothing else. That shapes what a useful contribution looks like right now:

- reading [`docs/architecture/kubernetes-provider.md`](docs/architecture/kubernetes-provider.md)
  against real clusters you operate, and opening an issue where a requirement is wrong,
  unimplementable, or would produce a misleading answer;
- the §68 open questions, which are explicitly reserved for later specifications or ADRs;
- deterministic fixtures for behaviour the specification already describes.

Implementation work follows the order in §64: connection foundation, dynamic resource model,
curated operational graph, live observation. Picking a later phase before an earlier one exists
produces work that cannot be verified.

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
resolves, that ADRs match `ADR-NNNN-kebab-title.md` with the required headings, and that the
instruction files still name the specification. It refuses to run on `main`, because
implementation belongs on `implementation` (`AGENTS.md` §11).

There is no compile, lint or test step yet, because there is nothing to compile. When the first
crate lands the gate grows to Ono-Sendai's shape and these checks stay.

## Tests

Provider tests must not contact live clusters by default. The specification requires a
deterministic test path that works without production credentials (§59), with fixtures able to
emulate pagination, RBAC denial, rate limiting, watch streams, `410 Gone`, connection reset and
version skew. Live integration tests may exist behind explicit credentials and CI gates.

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

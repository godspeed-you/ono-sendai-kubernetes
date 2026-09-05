# AGENTS.md — Operating Instructions for the Kubernetes Provider Repository

> This file is the **single source of truth** for how any AI agent (Codex, Claude Code, or any
> other) works in this repository. `CLAUDE.md` is a thin Claude-specific layer that points here.
> Read this file completely before your first action in a session.

---

## 0. This repository inherits a development contract

Ono-Sendai's [`AGENTS.md`](https://github.com/godspeed-you/ono-sendai/blob/main/AGENTS.md) is the
project-wide development contract, and it applies here **in full** unless this file says
otherwise. It is not copied into this repository: two authoritative copies of one contract is how
they start disagreeing.

Read it for: pragmatism and the separation of `feat`/`fix`/`refactor`/`perf`/`test` (§4), the TDD
loop (§7), the ADR format (§8), testing behaviour rather than structure (§11), commit conventions
(§12.2), and code style (§16).

This file states what is **different** here, and what is **additional** because the subject is
Kubernetes.

---

## 1. Prime Directive

Build the Kubernetes provider specified in `docs/architecture/kubernetes-provider.md` — the
reference KUANG/11 external-system provider for Ono-Sendai — **test-driven, autonomously, without
asking the user for input.**

**There is no implementation yet.** At the time of writing this repository holds a specification
and the documents around it. The first milestone is the Cloud-Native Validation Gate (§15), not a
feature.

The rules of core's §1 hold unchanged: do not block on the user, tests are the referee, no test
no code, be pragmatic, do not stop early, never write to `main` unless the user says so.

---

## 2. Repository Layout

```
ono-sendai-kubernetes/
├── AGENTS.md                     these instructions (authoritative here)
├── CLAUDE.md                     thin pointer + Claude-specific notes
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE                       Apache-2.0 (core is MIT — §3.4)
├── scripts/
│   └── gate.sh                   the quality gate (§10)
└── docs/
    ├── architecture/
    │   ├── kubernetes-provider.md    the specification (IMMUTABLE, read-only — §5.1)
    │   └── spec.sha256               its checksum, verified on every gate run
    ├── adr/ADR-*.md              decisions recorded in this repository (§8)
    └── STATE.md                  the work board (§9)
```

Directories that do not exist yet and what they are reserved for, so that nobody invents a second
name for them: `crates/` or `src/` for the implementation, `tests/` for integration tests,
`fixtures/` for the deterministic API fixtures §59 of the specification requires, and
`docs/contracts/` if this provider ever needs machine-readable contracts of its own.

The vocabulary is core's: a **specification** is a narrative document, a **contract** is a
machine-readable file. Do not reintroduce a directory that means both.

---

## 3. Naming

Core's §3 applies unchanged — the product is **Ono-Sendai**, the binary is **`ono`**, crates are
`ono-*`, and **KUANG/11** is the extension runtime rather than an old name for the shell.

Additions for this repository:

| Thing | Name |
|---|---|
| This repository / the component | the **Kubernetes provider** — not "the k8s plugin", not "kubectl support" |
| Crates, when they exist | `ono-provider-kubernetes*`, following core's `ono-*` convention |
| Provider identity | `kubernetes` (specification §6.1) |
| Provider instance | `kubernetes:<context>`, e.g. `kubernetes:prod-eu` (§6.2) |

Two Kubernetes concepts are **not** interchangeable and must never be spelled as one (§13.1):

- **GVK** — group, version, kind: object and schema identity;
- **GVR** — group, version, resource: REST collection identity.

Code that treats them as the same string is wrong even when it happens to work.

---

## 4. Authority Order (what wins when sources disagree)

```
0. Ono-Sendai's narrative specifications        docs/specs/ono_sendai_*spec_v*.md in core
                                                IMMUTABLE; they define the shell this plugs into
1. Ono-Sendai's generic provider contract       docs/architecture/external-system-provider.md
                                                in core — the boundary this provider conforms to
2. docs/architecture/kubernetes-provider.md     this repository's specification (IMMUTABLE)
3. Ono-Sendai's machine-readable contracts      docs/contracts/ in core
4. docs/adr/ADR-*.md                            decisions recorded here
5. tests/ + fixtures/                           executable behaviour contract
6. the implementation
```

Two consequences that are easy to get wrong:

- **An inherited safety or truthfulness invariant beats this repository's specification.** Where
  they conflict, the inherited invariant wins unless an explicit ADR **in core** revises the
  generic contract for all providers (specification §0.3). An ADR here cannot grant this provider
  an exemption from a rule that binds every provider.
- **Core's ADRs are not automatically binding here, and this repository's ADRs are never binding
  in core.** The two series are independent and both start at `ADR-0001`. Cite across repositories
  by name and repository, never by bare number: `ADR-0581 (core)`.

---

## 5. The specification is immutable

### 5.1 The rule

**`docs/architecture/kubernetes-provider.md` MUST NOT be edited, amended, reformatted, renamed,
regenerated or replaced.** Not to fix a typo, not to reflow a paragraph, not to correct something
you believe is wrong, not "while you are in there". This is core's §5.1 applied to this
repository's specification, for the same reason: it is the fixed reference every later artefact is
measured against, and it stops being that the moment anyone edits it.

Where the specification is ambiguous, silent, internally inconsistent, apparently wrong or out of
date with reality: **write an ADR** (§8), state the reading you chose and why, and implement your
decision. An ADR that departs from something the specification says carries a `Spec deviation`
heading naming the section, quoting the sentence, and stating the rule that replaces it — core's
§8 format, unchanged.

Only the user changes the specification, and only by replacing it deliberately.

### 5.2 The rule is checked, not trusted

`scripts/gate.sh` verifies `docs/architecture/spec.sha256` on every run. A written rule is easy
to forget halfway through a long session.

The checksum proves that a *discovered* specification was not edited. It cannot prove that a
specification is discovered at all, which is the failure mode that nearly went unnoticed in core
when the documents moved directories (`ADR-0581 (core)`). So the gate also fails when the
specification is **missing** from the path the manifest names, rather than passing over an empty
manifest.

If the user replaces the specification, they update the manifest:

```bash
( cd docs/architecture && sha256sum kubernetes-provider.md > spec.sha256 )
```

---

## 6. Non-Negotiable Constraints

Fixed by the specification and by the generic contract; not open for agent re-decision.

- **Discovery is authoritative.** Learn what the API server serves. No compile-time assumption
  about which APIs exist, and no rejection of a usable cluster because `gitVersion` is unfamiliar
  (§4 invariants 1–2, §5.2, §5.3).
- **CRDs are normal resources.** Typed behaviour for built-in kinds and raw JSON for custom ones
  is non-conformant (§4 invariant 15, §33.1).
- **`metadata.uid` is lifetime identity; a name is not.** Same name, different UID is a different
  resource lifetime and must produce a lifecycle discontinuity (§4 invariants 4–5, §16.3).
- **`resourceVersion` is an opaque continuity token.** Never a timestamp, never a cross-resource
  clock, never sorted as a timeline (§4 invariant 6, §14.3). It is not `generation` (§4 invariant 7).
- **Missing permission is not absence.** `403`, an unserved API, an unqueried scope, a failed page
  and an empty result are distinct states (§4 invariant 13, §21.4).
- **A broken watch is a gap.** `410 Gone` breaks continuity; pre-gap and post-gap events are never
  stitched into a continuous history (§4 invariant 14, §19.4).
- **Evidence classes do not blur.** Owner reference, selector evaluation, label convention and
  inference are four different things and every edge says which it is (§23). A guessed
  relationship must never render as a provider-proven one.
- **Secrets stay redacted; credentials never become values** (§4 invariants 21, §8.1, §22).
- **No Kubernetes special case in Ono core** (§0.4). The test: could an unrelated future provider
  ignore this concept without carrying Kubernetes baggage? If not, it does not belong in core.
- **No hidden Kubernetes mini-shell** (§4 invariant 22, §35.1). Existing Ono verbs express these
  operations.
- **Reads do not mutate.** Discovery, inspection, relationship traversal and rendering are
  side-effect free.
- **Unknown data is `null`**, never fabricated and never zero.
- Repository language is **English**: code, comments, tests, docs, commits, ADRs. Conversation
  with the user may be German.

---

## 7. Working Rhythm

Core's §7 TDD loop, unchanged: `SELECT → CONTRACT → RED → GREEN → REFACTOR → GATE → RECORD → LOOP`.

One addition that is specific to this subject: **fixtures come with the change, not after it**
(specification §66.3). A relationship rule or API behaviour without a deterministic fixture is a
claim no gate can check, and this provider's whole value is that its claims are checkable.

**Tests must not contact live clusters by default** (§59). The deterministic path emulates
pagination, RBAC denial, rate limiting, watch streams, `410 Gone`, connection reset and version
skew. Live integration tests may exist behind explicit credentials and CI gates, and are never
what the gate depends on.

---

## 8. ADRs

Core's §8 format, unchanged: `docs/adr/ADR-NNNN-kebab-title.md`, zero-padded, monotonic, with
`Context` / `Decision` / `Consequences` / `Alternatives considered`, plus `Spec deviation` where
the decision departs from something a specification says.

This repository's series starts at `ADR-0001` and is independent of core's (§4).

An ADR here may decide anything within this provider. It may **not** decide anything about Ono
core, the generic provider contract, or another provider — those need an ADR in core.

---

## 9. Task Selection and the Work Board

`docs/STATE.md` is the board: read it first, update it last, every session. It holds work in
flight, findings not yet filed, deferred work and session records.

The backlog is this repository's GitHub issue tracker. A problem found on the way goes on the
board under *Found, not yet filed*; the user triages it into an issue.

---

## 10. Quality Gate (Definition of Done)

```bash
scripts/gate.sh
```

It runs what is checkable in a repository of documents:

```
branch guard          refuses to run on `main` (ONO_ALLOW_MAIN=1 overrides)
specification         docs/architecture/spec.sha256 verifies, and the file it names exists
links                 every relative markdown link resolves
ADRs                  filenames, numbering and required headings
instructions          README, AGENTS.md and CLAUDE.md name the specification
```

**When an implementation exists, this gate grows to core's shape** — `cargo fmt --check`,
`cargo clippy -D warnings`, the test suite, and whatever contract check this provider needs — and
the additions above stay. Do not replace the gate; extend it. A gate that gets weaker as the
repository gets more serious is the wrong direction.

If a gate tool is missing, **create it** rather than skipping the gate.

---

## 11. Branch Policy and Commits

Core's §12 applies unchanged, and the two rules that matter most:

- **`main` is written to only when the user asks for it, in that request and no other.** A green
  gate makes work *promotable*; the user makes it promoted.
- **Implementation happens on `implementation`**, created from `main` and disposable by design.
  `scripts/gate.sh` refuses to run on `main`.

Conventional Commits, English, one kind of change per commit, green tree. Do not open pull
requests unless asked.

---

## 12. Stopping Rule

Core's stopping rule is `scripts/release-check.sh` printing that the shell is release-ready. This
repository has no such script yet, because it has nothing to release.

Until it does, the milestone that matters is the **Cloud-Native Validation Gate** described in
[`docs/strategy/cncf-readiness.md`](https://github.com/godspeed-you/ono-sendai/blob/main/docs/strategy/cncf-readiness.md)
§2 in core. It asks whether Ono's existing concepts become *more* useful against Kubernetes
without creating a Kubernetes-specific second shell, and it requires, among other things: direct
API interaction with no dependency on `kubectl`, UID-aware identity, useful behaviour for kinds
unknown at compile time, relationships with inspectable evidence, navigation through the existing
spatial model, honest handling of RBAC denial and watch discontinuity, no Kubernetes-specific
parser or core exception, and deterministic tests that need no live production cluster.

**That gate is allowed to fail.** A failed proof-of-concept is evidence worth having, and the
readiness document says so explicitly: if Kubernetes needs pervasive core exceptions or a second
grammar, the abstraction gets revised rather than the result being talked around.

---

## 13. Session Checklist

1. Read `docs/STATE.md`.
2. Confirm the branch before the first edit: `git rev-parse --abbrev-ref HEAD`.
3. Do the work in increments (§7).
4. `scripts/gate.sh` green before every commit.
5. ADR for anything architectural, cross-cutting or hard to reverse (§8).
6. Update `docs/STATE.md` last.

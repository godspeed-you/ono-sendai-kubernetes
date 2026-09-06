# CLAUDE.md — Ono-Sendai Kubernetes provider

@AGENTS.md

**`AGENTS.md` is the authoritative instruction set for this repository.** Read it in full before
your first action. This file adds only the Claude-Code-specific layer on top of it. Do not
duplicate rules here — if a rule needs to change, change it in `AGENTS.md`.

Ono-Sendai's project-wide contract,
[`AGENTS.md` in core](https://github.com/godspeed-you/ono-sendai/blob/main/AGENTS.md), applies
here too and is deliberately not copied into this repository.

---

## The short version (full rules in AGENTS.md)

- **Subject:** the Kubernetes provider for **Ono-Sendai** (binary: `ono`) — the reference KUANG/11
  external-system provider. Specification: `docs/architecture/kubernetes-provider.md`, normative
  MUST/SHOULD/MAY, **immutable** (AGENTS.md §5).
- **There is an implementation**, in two crates, with a live suite that drives the real `ono`
  binary against ephemeral `kind` clusters. `docs/coverage.md` is the section-by-section map;
  `docs/STATE.md` is the board (AGENTS.md §9, §12).
- **Naming:** the product is **Ono-Sendai**, the binary is **`ono`**, **KUANG/11** is the
  extension runtime. **GVK** (kind identity) and **GVR** (REST collection identity) are different
  things and never one string (AGENTS.md §3).
- **What core owns and what this repository owns:** core owns the shell, the generic provider
  contract and cross-provider policy; this repository owns Kubernetes API integration, resource
  mapping, Kubernetes-local relationships, CRD handling and watch/cache behaviour. An inherited
  safety invariant beats this repository's specification, and an ADR here cannot grant this
  provider an exemption from a rule binding every provider (AGENTS.md §4).
- **The specification is immutable.** Never edit, reformat, rename or regenerate it — not even a
  typo. Ambiguous, inconsistent or wrong? ADR with a `Spec deviation` heading, then implement your
  decision. `scripts/gate.sh` verifies its checksum on every run (AGENTS.md §5).
- **Method:** strict TDD, `RED → GREEN → REFACTOR → GATE → RECORD → LOOP`. Fixtures arrive with
  the change, not after it. Tests never contact live clusters by default (AGENTS.md §7).
- **Autonomy:** every decision not fixed by a specification is yours. Decide, write an ADR in
  `docs/adr/`, continue. Do not ask; do not idle. This series starts at `ADR-0001` and is
  independent of core's — cite across repositories as `ADR-0581 (core)` (AGENTS.md §8).
- **Branch:** implementation goes on `implementation`, never on `main`. `scripts/gate.sh` refuses
  to run on `main` (AGENTS.md §11).
- **State board:** `docs/STATE.md` — read first, update last, every session.
- **Repo language is English** (code, tests, docs, commits). Talk to the user in their language.

```bash
scripts/gate.sh            # branch guard, spec checksum, links, ADRs, instructions
```

---

## Claude-Code-specific guidance

**Plan mode.** For a multi-increment task, plan briefly, then execute. Do not use `ExitPlanMode`
to request permission for decisions AGENTS.md §8 already delegates to you.

**AskUserQuestion.** Effectively banned for this project. Architecture, library and design
questions are answered by you with an ADR. Use it only for the escalation cases in core's §8.

**Long specification.** `docs/architecture/kubernetes-provider.md` is ~3800 lines. Do not read it
whole; use `grep -n '^#'` for the section index, then `sed -n 'A,Bp'` for the sections you need,
and cite as `§N` in ADRs, tests and commit messages. Its §4 Core Invariants is a numbered list,
so cite those as `§4 invariant 13` rather than `§4.13`.

**Cross-repository work.** Ono-Sendai core is a separate repository and usually a separate
checkout. Do not assume it is present; do not edit it from here. A change that needs core is an
issue or an ADR in core, not a local workaround.

**Subagents.** Use them when they genuinely reduce context load or parallelise disjoint work —
`Explore` for locating sections in the long specification, `Plan` for decomposing a phase of §64
into increments. Do not spawn one for a single-file edit.

**Parallel tool calls.** Batch independent reads, greps and test runs into a single message.

**Commits.** Conventional Commits, one kind of change per commit, green tree only, trailer:
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
Never push or open a PR unless asked.

**Reporting.** End a session with: what was proven, by which tests, and the next task from
`docs/STATE.md` — not a narration of the steps taken.

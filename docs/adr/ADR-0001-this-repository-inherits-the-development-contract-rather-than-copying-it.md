# ADR-0001: This repository inherits the development contract rather than copying it

- Status: accepted
- Date: 2026-09-05
- Spec refs: §0.2, §0.3, §0.4, §2.9, §66; core AGENTS.md §2, §5, §12
- Decided by: agent (autonomous)

## Context

The Kubernetes provider was given its own repository so that Kubernetes domain logic stays out of
Ono core, the generic KUANG/11 extension boundary is exercised by a real consumer, and Kubernetes
expertise can own work without first understanding the shell (`ADR-0581 (core)`, and §1.2 of
core's readiness document).

A separate repository needs its own operating rules — an agent working here has to know what wins
when sources disagree, whether the specification may be edited, what the gate is, and which branch
to write on. Ono-Sendai already answers all of that in `AGENTS.md`, and it took 580 decisions to
arrive at those answers.

Two failure modes were available. Copying core's `AGENTS.md` produces a second authoritative copy
of one contract, which is the duplication anti-pattern core's own readiness document names, and
the copies begin disagreeing at the first amendment to either. Writing a fresh contract from
nothing discards rules that exist because something went wrong, and reproduces those failures here.

## Decision

`AGENTS.md` in this repository **inherits core's `AGENTS.md` by reference** and states only what
differs or is additional. It is not a copy, and core's file is not vendored.

What is inherited unchanged: the separation of change kinds, the TDD loop, the ADR format, testing
behaviour rather than structure, commit conventions, code style, and the branch policy under which
`main` is written to only when the user asks in that request.

What this repository states for itself:

- **An authority order that spans two repositories.** Core's narrative specifications and its
  generic provider contract sit *above* this repository's specification. An inherited safety or
  truthfulness invariant beats the Kubernetes specification where they conflict, and only an ADR
  *in core* can revise a rule that binds every provider (§0.3). An ADR here cannot grant this
  provider an exemption.
- **Two independent ADR series.** Both start at `ADR-0001`. Cross-repository citations carry the
  repository: `ADR-0581 (core)`. Merging the numbering would make every future core ADR a
  potential collision here.
- **The specification is immutable**, on core's §5.1 rule and for its reason: it is the fixed
  reference later artefacts are measured against. Deviations are ADRs with a `Spec deviation`
  heading; the document itself stays untouched.
- **Kubernetes-specific non-negotiables** that no general contract would state — discovery is
  authoritative, CRDs are normal resources, UID is lifetime identity and a name is not,
  `resourceVersion` is an opaque token, denied is not empty, a `410` is a gap, evidence classes do
  not blur, and GVK is not GVR.
- **A gate proportional to a repository of documents**, described below.

## Consequences

Easy: an agent that has read core's contract can start here immediately, and reads only the delta.
A rule that changes in core changes here at the same moment, with no second copy to forget.

Hard: this repository's instructions are not self-contained. An agent that cannot reach core's
`AGENTS.md` has an incomplete contract, and the file says so rather than pretending otherwise.
That trade is deliberate — a stale copy is worse than an absent one, because it is confidently
wrong.

Watch: the inheritance is by prose reference, and nothing verifies that core's §-numbers still say
what this file claims. If core renumbers its sections, the references here rot silently. The
mitigation available today is that this file cites section *titles* alongside numbers where the
reference carries weight; a real check would need cross-repository tooling that does not exist and
is not worth building for one consumer.

`scripts/gate.sh` checks what this repository can actually check: that the specification's
checksum verifies **and that the file it names exists**, that every relative markdown link
resolves, that ADRs match the required form and numbering, and that the instruction files name the
specification. It refuses to run on `main`.

The second of those exists because of a specific near-miss. A checksum manifest proves that a
*discovered* document was not edited; it cannot prove a document is discovered at all, and
`sha256sum --check` over a manifest naming a missing file reports a warning that is easy to lose.
In core, documents moving out from under their discovery root nearly left nine immutable
specifications unguarded behind a green gate (`ADR-0581 (core)`). The gate here was verified
against all four regressions it claims to catch, including that one.

The gate has no compile, lint or test step because there is nothing to compile. When the first
crate lands it grows to core's shape and these checks stay. A gate that gets weaker as the
repository gets more serious is the wrong direction, and `AGENTS.md` §10 says so where the next
agent will read it.

## Alternatives considered

**Copy core's `AGENTS.md` and edit it.** Rejected: two authoritative copies of one contract, which
is exactly the anti-pattern the split was made to avoid, and they diverge at the first amendment.

**Write a minimal contract from scratch.** Rejected: it discards rules that exist because
something failed, and the failures return.

**No `AGENTS.md` here at all, relying on core's.** Rejected: core's file cannot state this
repository's authority order, its immutability target, its gate or its Kubernetes non-negotiables,
and an agent would have to infer them.

**Continue core's ADR numbering from 0582.** Rejected: the series would collide the moment core
records its next decision, and neither repository could allocate a number without consulting the
other.

**Defer the gate until there is code.** Rejected: the specification is immutable *now*, and an
immutability rule nothing checks is a rule that gets forgotten halfway through a long session.
That is core's stated reason for checking rather than trusting, and it applies before the first
line of code, not after it.

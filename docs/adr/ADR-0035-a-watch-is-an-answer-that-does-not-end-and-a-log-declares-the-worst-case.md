# ADR-0035: A watch is an answer that does not end, and a log declares the worst case

- Status: accepted
- Date: 2026-09-06
- Spec refs: §19.1, §19.7, §41.1, §41.2, §42.1, §61.4 (K3), §62.12;
  shell specification §18.2, §18.3, §18.5 in core; `ADR-0588 (core)`, `ADR-0586 (core)`;
  ADR-0022, ADR-0023, ADR-0028, ADR-0030
- Decided by: agent (autonomous)

## Context

§41.1 is a `MUST`: *"The provider MUST use the inherited Ono live-view contract rather than
creating a Kubernetes-specific TUI subsystem."* The inherited contract is the shell's own — an
unbounded `ValueStream` reaching the last stage of a terminal pipeline, rendered in place by
`ono_cli::live` (shell specification §18.3).

This package could not reach it, and the reason was not in this repository. Every contributed
target's answer was **collected**: `plugins::query` did `invocation.collect().await`, because
nothing a package declared said whether its answer ends. `get k8s-change` therefore never returned
to a prompt at all — a defect no test here could see, because the package's own tests drive it
through the deterministic test host, which reads incrementally and never consults the shell.

`ADR-0588 (core)` closed it: a target declares `answer: bounded | unbounded`, and an unbounded one
becomes a stream with that boundedness rather than a table that never gets drawn. The pinned core
moves to `29edac7` to take it.

What remained was a decision this repository has to make, and it is sharper than it looks:
**boundedness is declared per target, and `k8s-log` is bounded until `follow` is written.**

## Decision

### Two words declare `unbounded`, and the rest declare `bounded`

`k8s-change` and `k8s-log`. Everything else — twenty-eight targets — ends by itself.

**`k8s-change` is unambiguous.** A watch has no natural end; §41 says the operator ends it, and
`max_changes` is an option a caller may write rather than a bound the answer has. There is no
bounded reading of it to fall back on.

**`k8s-log` declares the worst case**, and that is the substance of this ADR. A log read with no
`follow` ends when the body ends; with `follow` it runs until the operator stops it (ADR-0030).
The declaration is a property of the target, so one of the two has to lose.

It has to be the bounded one, because the two errors are not symmetrical:

- **An unbounded declaration over a bounded answer** is a stream that ends. Everything downstream
  works — `| to json`, `| count`, a redirect, `take` — and at a terminal it renders as a growing
  tail, which is how a log reads anyway (`ADR-0059 (core)`).
- **A bounded declaration over a followed log** is a shell that does not come back. The host
  collects, the package never stops emitting, and the prompt is gone. That is the defect this ADR
  exists to remove, reintroduced through the one word where it is easiest to miss.

The cost is narrow and it is a refusal rather than a wrong answer: a bare `get k8s-log` whose
output is neither a terminal nor a serializer is refused with *"a live stream needs a
representation when nobody is watching it"*, which names both ways out. `get k8s-log | to json`,
`get k8s-log > file`, `get k8s-log | count` and an interactive `get k8s-log` are all unaffected.

### The pair is named in a test rather than counted

`should_declare_the_same_boundedness_in_the_document_and_across_the_handshake` asserts the
document and the handshake agree for all thirty targets, *and* that exactly `k8s-change` and
`k8s-log` are the unbounded ones. A third is then a decision somebody takes on purpose rather than
a consequence of adding a `Reads` variant.

### The proof is the refusal, not the table

`should_hand_a_watch_to_the_shell_as_a_stream_rather_than_a_table` drives the real `ono` binary
against a recorded API server with output captured, and asserts the live-stream refusal. That is a
stronger proof than a table would be: a *bounded* declaration produces a table here and can never
produce this refusal, and the refusal arrives before any watch is drained, because boundedness is
known when the stream is built. The same test asserts that `get k8s-pod` is still tabulated, so
the declaration is discriminating rather than blanket.

## Consequences

- `get k8s-change --context prod --kind Pod` at a terminal is a live view: rows arriving as the
  cluster changes, `gap` records when continuity breaks, `sync_state` on every one. That is §41.1
  satisfied through the inherited contract, with no rendering code in this repository.
- `get k8s-log --follow` returns to the prompt when the operator stops it, instead of hanging the
  shell. It was written in ADR-0030 and, through the shell, unusable until now.
- A bare `get k8s-log` in a script that expected a table gets a refusal naming its two remedies.
  This is a breaking change to a pre-1.0 package with no released consumers, and the alternative
  is a hang.
- **§41.4's `stale` still reaches nobody.** Five of its six states ride on every change record as
  `sync_state`; the sixth belongs to a *view* and needs a clock and a staleness window, which is
  `live.rs`'s job and is not wired here. This ADR closes §41.1's routing; §41.4 remains open on
  the board.

## Alternatives considered

**Declare `k8s-log` bounded and refuse `follow` through the shell.** Rejected: the package cannot
tell which door an invocation came through, so the refusal would have to be unconditional, and it
would remove a capability §42.1 lists explicitly.

**A second target — `k8s-log-follow`.** Rejected under §4 invariant 22 and §35.1. Two nouns for
one read is the first word of a Kubernetes mini-shell, and the difference between them is an
argument, which is what arguments are for.

**Ask core for boundedness that depends on an argument.** The honest long-term answer is the
`watch` verb — `watch k8s-resource` — which core cannot yet route to a contributed target because
`is_watchable` requires a builtin `ono.<target>-event/1` schema. `ADR-0588 (core)` deferred that
deliberately. Conditional boundedness would be a second mechanism for the same question, decided
in the harder direction, for one target; the worst-case declaration costs one narrow refusal and
no new concept. Recorded on the board as the shape to revisit when the `watch` route opens.

**Leave `k8s-change` collected and let `max_changes` be mandatory.** Rejected. It makes the
specification's own live view unreachable, and a required bound on a watch is a table with extra
steps.

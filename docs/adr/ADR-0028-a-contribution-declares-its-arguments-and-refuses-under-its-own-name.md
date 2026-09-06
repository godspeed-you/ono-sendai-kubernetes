# ADR-0028: A contribution declares its arguments, and refuses under its own name

- Status: accepted
- Date: 2026-09-06
- Spec refs: §7.1, §7.3, §7.4, §7.5, §9.2, §9.4, §13.3, §17.1, §18.4, §19.4, §38.6, §40, §42.1,
  §43.3, §44.1, §44.2, §44.4, §44.5, §45.2, §55.3, §56, §63.6;
  `ADR-0587 (core)`, `ADR-0586 (core)`, `ADR-0585 (core)`, `ADR-0584 (core)`;
  ADR-0010, ADR-0019, ADR-0024, ADR-0025, ADR-0027
- Decided by: agent (autonomous)

## Context

Three findings this board carried were findings about core, and core closed all three in
`ADR-0587` on the same day: a contributed **command** could not declare its options, a contributed
**target** could not declare its options either, and there was no error code for a package
refusing under a safety rule of its own.

The cost of the first was concrete rather than cosmetic. `dry_run` decides whether a cluster is
changed. Undeclared, it had no help line, no type, no completion candidate and no default the host
could apply — so the safe value existed only as `unwrap_or(true)` inside one handler, and the two
documented examples told an operator to write `--dry-run false`, which produces the argument key
`dry-run`, which nothing reads. The example claimed to write and did not. It failed safe, and it
was still wrong in the direction that teaches an operator the wrong sentence.

The cost of the third was a false assertion in every refusal this provider makes on its own
authority. `safety.policy_denied` says a *configured* policy forbade the operation, and nothing
was configured. `provider.unavailable` — which ADR-0025 chose for `k8s-event` and `k8s-log`
because it was the least wrong of three — says the external system did not answer, and in both
cases it answered fully and the package declined to render the answer's emptiness as an absence.

## Decision

**The pinned core moves from `879d390` to `e1a44fd`, and this package consumes all three
closures.**

### 1. Every target and every command declares its arguments, from one table

`contributions::Parameter` is the declaration, and `Target::options()` and `Command::options()`
derive each contribution's list from what it *reads*. The lists are not restated in the on-disk
documents by hand: `package/contributions/targets.yaml` and `commands.yaml` carry them, and
`tests/contributions.rs` parses both through the host's own `TargetDocument` / `CommandDocument`
and fails when either disagrees with the handshake. A second reader written for the test could
have agreed with the table while the host disagreed with both.

A second test reads the package's own sources and fails when a declared argument's name appears
nowhere in `src/`. A declared option nothing consumes is the same failure as an undeclared one
something does: the shell offers a word, the user writes it, and nothing happens.

**`dry_run` declares `default: true`, and the handler keeps its fallback.** The declaration is
what makes the safe value visible in `help` and applied by the host before this package's code
runs. The fallback is what keeps the package correct when it is driven by something that is not
that host. A package whose safety depends on the host having done its job is a package with a
latent write in it.

**`namespace` is declared on every kind, including the cluster-scoped ones.** Whether a resource
is namespaced is discovery's answer (§4 invariants 1–2, §9.2), so this table does not carry a list
of which kinds have a namespace — that list is precisely the static model of Kubernetes §5.2
forbids. A namespace named for a cluster-scoped kind produces no namespace segment.

**`all_namespaces` is declared on the reads and on neither write.** §55.3 keeps bulk mutation out
of this action surface, and an option that fanned a change across every namespace the caller can
see is the shape that section forbids, arriving as an argument.

### 2. `contribution.refused` replaces two borrowed codes

`Ono-Sendai-K11901` carries all three refusals this provider makes on its own authority: a plan
whose precondition is missing (§56, ADR-0019), an Event search that observed nothing (§38.6), and
a log read that produced no lines (§63.6). Its published help is the sentence all three needed and
none of them could say: *the package's rule, not the host's policy and not the external system's
answer.*

Nothing else changes about those refusals. They still fail the invocation rather than completing
empty, still carry the bounds or the retention statement that says what the emptiness does not
prove, and are still the shape ADR-0025 argued for. Only the claim about *who refused* is now true.

## Consequences

- `help get k8s-pod` prints an `OPTIONS` block and `get k8s-pod --con<TAB>` completes, on a shell
  that has never loaded this package (§31.68 in core's specification). The declaration is read
  from disk before any of this package's code runs.
- A written word is coerced to the type it was declared as, so `--port 6443` arrives as an integer
  because it was declared one rather than because it happened to parse as one, and `--max_pages 3`
  can no longer arrive as the string `"3"` on one route and an integer on another.
- Three entries leave *Found, not yet filed* and one leaves the error-taxonomy finding. The board
  keeps them as closed entries rather than deleting them: a finding that moves from "the protocol
  cannot" to "we have" is the most useful kind to keep visible.
- The two mutating examples now read `--dry_run false`. An operator following the old ones was
  predicting when they believed they were writing.
- A consumer catching `provider.unavailable` around `get k8s-event` no longer catches it. That is
  the point, and it is a breaking change to a pre-1.0 package with no released consumers.

## Alternatives considered

**Keep the options as prose in the documents' comments.** Rejected. That was the state ADR-0587
was written to end, and the comments were already a manual index of names three files read: the
handlers, the summaries and the board. Two of the three were out of date.

**Declare only the arguments a user is likely to type.** Rejected. A partial declaration is the
worst of the three states, because the words that got a help line become the words that appear to
exist and the rest become words that appear not to. The set is derived from what each handler
reads, so it is complete by construction and a test enforces the other direction.

**Close the argument set — refuse an undeclared word.** Not this package's to decide, and core
decided against it in `ADR-0587`: a word a contribution did not declare still reaches it, because
nothing about declaring *some* arguments says a package accepts no others. This package refuses
nothing new.

**Keep `safety.policy_denied` for the plan refusal and use `contribution.refused` only for the two
empty answers.** Rejected. The plan refusal is the case `contribution.refused` was written for —
`ADR-0587` cites it by name — and a taxonomy where two codes mean "this package declined" is a
taxonomy a caller has to test twice.

**Invent a code for "the answer is empty and its emptiness proves nothing".** Rejected as a
distinction without a difference at the boundary: in both cases the package holds an answer and
declines to render it, under a rule of its own, and the message says which rule. A fourth code
would be this package legislating for a taxonomy that belongs to core.

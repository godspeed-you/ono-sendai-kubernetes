# ADR-0045: A continuation that does not continue is a broken snapshot, and a view pays for the change rather than the collection

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 6, 13, 14, 21, §14.3, §16.1, §16.2, §17.1, §18.1, §18.2, §18.3, §18.5,
  §19.4, §21.4, §22.2, §22.3, §34.2, §41.4, §42.2, §44.6, §48.1, §50.1, §50.5, §62.9 (Gate I);
  §12.3, §30.4 and §30.5 of `docs/architecture/external-system-provider.md`; ADR-0022, ADR-0038,
  ADR-0043, ADR-0044, ADR-0046
- Decided by: agent (autonomous)

## Context

The adversarial suite (ADR-0043) and the performance suite (ADR-0044) were written to find
defects rather than to fix them, and they left each one pinned: a `// FINDING:` comment naming the
defect and its owner, and an assertion that documented *today's* behaviour so the suite stayed
green and the gap stayed visible. Five of those findings live in modules this decision owns.

1. **`Client::walk` followed a `continue` token it had just sent.** §18.1 makes a token mean "the
   collection is incomplete" and says nothing about a server that answers a continuation with the
   token that asked for it — a proxy that rewrites list responses, an aggregated API server with a
   broken continuation (§34.2), or a hostile one. The loop re-sent whatever arrived with no
   comparison, so nothing but a page budget stopped it, and what a reader got was N copies of one
   page delivered as a complete listing. `Client::new` starts on `Budget::unlimited()`, so a
   caller other than the plugin inherited no bound at all.
2. **`Client::get` never checked it got what it asked for.** A `GET .../pods/checkout` in `shop`
   answered with a Secret named `somebody-else` in `kube-system` was reported under that identity,
   honestly labelled and completely unrelated to the question. It is the same defect `identify`
   has a page deeper (ADR-0046): trusting the response body about *which* object arrived is how a
   server chooses which §22 rule applies to the bytes it is sending.
3. **The submitted half of an admission difference was unredacted.** §44.6's diff has two halves.
   The returned one is guarded deliberately — `mutation::admission_differences_of` exists for
   that — and the requested one went into the record verbatim, so a `k8s-apply` of a Secret put
   its payload into the mutation record and from there into command history, against §22.3 and
   the sibling rule §42.2 states for logs.
4. **A `WatchStream`'s change log was unbounded.** One `ObservedChange` per event, never trimmed,
   for the lifetime of the session. The cache is bounded by the collection — ten thousand
   modifications of five hundred Pods are five hundred Pods — and nothing bounded the number of
   events that passed through it, which §18.5, §50.1 and the generic contract's §30.4 all forbid.
5. **`LiveView::refresh` was O(objects) and cloned up to `capacity` objects, and `changes.rs`
   called it once per emitted record.** A ten-thousand-object namespace under a busy controller
   therefore paid two thousand object clones and eight thousand identity clones *per change
   event*, for a table nothing in the package reads. §50.1's "MUST NOT freeze" is the requirement
   it strained.

Four of the five are the same shape of mistake: a value that arrived is trusted about a question
the *request* already answered. The fifth is a cost nobody had counted.

## Decision

### 1. A repeated `continue` token breaks continuity (§18.1, §18.2)

`BreakReason` gains `TokenRepeated`. When a page arrives carrying the token that asked for it,
`Client::walk` stops there with `Continuity::Broken(BreakReason::TokenRepeated)`, records a
coverage gap, and attaches an `ApiError::Malformed` naming the token — §18.3's rule that the error
travels *on* the collection rather than replacing it.

Two details are the decision rather than the mechanism:

- **The repeated page is refused, not delivered.** It is the copy the repetition produces, and
  core §12.3 asks a provider to "prevent duplicate emission where provider pagination semantics
  permit stable deduplication". A token identical to the one just sent is exactly that signal. A
  streaming reader cannot unsend a record, so the check happens before `Reader::page`.
- **Every page that crossed before it stands.** §18.3 is explicit that pages 1..N may stand as
  long as coverage is partial and the error is attached, and this is that case with N=1.

The bound is now a property of the loop rather than a policy somebody remembered to ask for: a
caller that legitimately raises `max_pages` for a large collection no longer raises the ceiling on
a loop, and a caller on `Budget::unlimited()` is no longer unbounded.

### 2. A `GET` answered with another object is malformed, never a substitution and never an absence

`Client::get` compares the answer against the locator that fetched it (§16.2): the name, the
namespace where both state one, and the group-version. A disagreement is `ApiError::Malformed`.

- **Not `NotFound`.** The object asked for may well exist; reporting absence would be a claim
  about the cluster manufactured out of a claim about the answer, which is precisely what §21.4
  and §4 invariant 13 keep apart.
- **The `kind` is not compared.** A GVR names a REST collection and a GVK names an object
  (AGENTS.md §3); deriving one from the other by a string rule is the mistake that section
  exists to prevent, and discovery is the authority for the mapping. The group-version *is*
  compared, because both sides spell it the same way.
- **Only a stated disagreement counts.** A body that says nothing about its namespace has not
  claimed to be somewhere else, and the request path already fixed the scope.

### 3. Both halves of an admission difference go through `redaction::Guarded`

`redaction::guarded_document` takes a *document* across the boundary `Guarded` takes an object
across, and `admission_differences_of` puts the submitted half through it before comparing. The
rule about which kinds bear a payload is therefore written once. A document that does not read
back as an object is redacted anyway: over-redaction costs a reader some detail and
under-redaction cannot be taken back (§3.7).

The consequence is that **no difference is reported over a Secret's payload at all**, because both
halves are `<redacted>` by the time they are compared and compare equal. That is the honest answer
to a question this provider is not allowed to hold the operands of, and it replaces something
worse than incomplete: the old behaviour reported `CIPHERTEXT -> <redacted>` as a rewrite whether
or not admission had touched anything, and carried the value that made it a disclosure. §44.6 asks
for admission's changes to be reported; §22.3 says the bytes may not be. Where they meet, the
inherited safety invariant wins (AGENTS.md §4), and everything that is not payload — a mutating
webhook's image registry rewrite, an injected default — still compares exactly as before.

### 4. A change log is bounded, and a trimmed log is a gap

`Segment` keeps the most recent `CHANGE_LOG_CAPACITY` (1 024) changes and drops the oldest in
blocks of a quarter of that. `Segment::trimmed` counts what left, so no event is ever unaccounted
for.

**What a trimmed log says is the decision.** A history that silently forgets its beginning is the
continuity lie §19.4 exists to prevent — an ordered list of changes that starts in the middle of
the period it claims to describe. So the trim is reported the way every other discontinuity in
this module is: `GapReason::ChangeLogTrimmed`, one `WatchGap` per period, carrying the version the
period began at and the version its retained record now begins at. `is_gap_free()` is false while
one exists and `describe_continuity()` names it, which are the two places a reader already looks.

It is deliberately *not* one of the other three reasons: this is not a period nobody watched. The
events were observed, applied to the cache and reported to whoever was reading at the time, and it
is the record of them that has a hole. The gap says which hole it is.

### 5. A refresh costs the change, and the rows are rebuilt on a cadence

Two changes, in the two places the multiplication had a factor:

- **`live.rs`.** `refresh` splits into taking the stream's state and rebuilding the rows. A row at
  the same lifetime and the same `resourceVersion` is the same observation (§14.3), so it is moved
  across rather than rebuilt from a clone of an object the view already holds; the withheld list
  is *compared* against the objects that did not fit, field by field and without allocating, and
  rebuilt only when it changed. `LiveView::rebuilt_rows` publishes how many rows the last refresh
  had to build — the observable half of the bound the generic contract's §30.5 asks for. The
  contract does not move: the same rows, the same withheld set, the same clock as a parameter.
- **`changes.rs`.** `LiveView::observe` is the new constant-time half, and the emitter calls it on
  every record: §41.4's state, gaps and staleness are always this event's. The rows are rebuilt on
  `VIEW_ROWS_EVERY` (250 ms). The only thing that can lag is the `withheld` count, which is a
  property of the view rather than a claim about the cluster.

Measured by `tests/performance.rs`'s `should_bound_a_live_view_at_its_capacity_and_name_everything_it_did_not_admit`,
ten thousand objects into a two-thousand-row view, debug build:

| | before | after |
|---|---|---|
| first refresh (nothing to keep) | 13.86 ms | 11.85 ms |
| refresh after one change — what a record cost | 20.62 ms | 6.17 ms |
| rows rebuilt by that refresh | 2 000 | 1 |
| per-record view cost in the package | 20.62 ms (a refresh) | 0.11 µs (an observation) |

The last row is the one the finding was about: ten thousand events over that collection cost about
206 seconds of view rebuilding before and about a millisecond of observing now, plus four row
rebuilds a second while records are flowing.

## Consequences

- **`k8s-change` can report a fourth gap reason.** `change_log_trimmed` is added to the
  `gap_reason` enum in `contributions.rs` and in `package/contributions/schemas.yaml`. A consumer
  matching on the three older words sees a value it does not know; the field is nullable and
  documented, and the alternative — reporting a trim under `restarted_without_checkpoint` — would
  merge two different holes into one word.
- **Six tests changed from documenting a defect to preventing it**, four of them by inversion:
  `should_break_continuity_when_a_continue_token_answers_with_itself` and
  `should_refuse_an_answer_that_is_a_different_object_than_the_one_that_was_asked_for` and
  `should_redact_both_halves_of_an_admission_difference_over_a_secret` in the provider's
  adversarial suite, `should_stop_a_collection_whose_continue_token_never_changes_at_the_repetition`,
  `should_apply_ten_thousand_watch_events_without_discarding_one` and
  `should_bound_a_live_view_at_its_capacity_and_name_everything_it_did_not_admit` in its
  performance suite, and `should_end_an_invocation_whose_server_never_stops_paginating` in the
  package's adversarial suite. `tests/watch.rs` gains
  `should_bound_the_change_log_and_report_a_trimmed_history_as_a_gap`, because a bound belongs in
  the module's own suite as well as in the one that measured it.
- **One fixture was advancing its tokens only by accident.** The hundred-thousand-object walk in
  the provider's adversarial suite repeated `page-1` on all fifty pages; it now numbers them. A
  fixture that repeats a token is now a test of finding (1) rather than a test of scale, which is
  the fix working on the first thing it was pointed at.
- **`temporal.rs` does not yet read the trim.** It builds an `ObservedPeriod` from
  `Segment::started_at`, and for a trimmed segment the observations inside it begin later than the
  period says. The trim is visible on the stream (`gaps()`, `describe_continuity()`) and on the
  segment (`trimmed()`, `retained_from()`); carrying it into a timeline's own vocabulary is a
  change to a module this decision does not own, and it is left as a finding.
- **A watch that repeats one token now fails an invocation two pages in** rather than sixteen. The
  message is the continuity one, which is the honest reason: the query was not stopped by a
  policy.
- The suites stay deterministic and cluster-free. The workspace runs 41 test binaries green,
  `clippy -D warnings` and `cargo doc` are clean, and the performance numbers above are printed by
  the test rather than asserted, because a shared runner varies by more than any regression worth
  catching (ADR-0044).

## Alternatives considered

**Follow a repeated token and deduplicate the objects.** Rejected. Deduplicating means holding
every identity the walk has seen, which is the retention §18.5 asks a streaming caller not to do,
and it would keep talking to a server that has told us it cannot continue its own snapshot.

**Stop on a repeated token without breaking continuity — report it as `more_available`.**
Rejected: §18.4's "more remains upstream" is what a *decision* leaves behind, and no decision was
made. A malformed answer and an operator's page budget must not print the same.

**Compare the returned `kind` in `Client::get` by pluralising the GVR's resource.** Rejected.
`pods -> Pod` works until `endpoints`, `NetworkPolicies` or any CRD whose plural is irregular, and
a rule that is right most of the time is worse here than no rule: it would refuse legitimate reads
of exactly the custom resources §33.1 makes ordinary. Discovery already answers this and a future
version of `get` may take a `Resource` rather than a `Gvr`.

**Report an admission difference over a Secret's payload as `<redacted> -> <redacted>`.** Rejected.
It reads as "admission rewrote this" and the provider cannot know whether it did — both operands
were destroyed at the boundary. Claiming a change nobody observed is the failure mode §4 invariant
20 is about, one field to the left.

**Redact the submitted half by filtering the rendered difference in `mutations.rs`.** Rejected for
the reason the module documentation of `redaction.rs` gives: redaction that has to be remembered
fails on the first path nobody reviewed. The document goes through the boundary, so every future
caller of `admission_differences_of` inherits it.

**Bound the change log by trimming silently.** Rejected — it is the finding's own trap. A log that
drops its oldest entries and says nothing is a history that reads as whole, and §19.4 exists
because a shorter true story and a story with a hole in it are different claims.

**Keep the change log unbounded and bound the session instead.** Rejected: the session already
bounds what it holds per collection, and a bound expressed as "the whole log until something
evicts the stream" is not a bound a reader can name. `CHANGE_LOG_CAPACITY` is a number in the
public API for the same reason `LiveView::capacity` is one.

**Give `LiveView` an incremental API — apply one change to the view.** Rejected for now. It would
be the fastest possible answer and it moves the capacity bound's semantics into the caller: an
object admitted as soon as room frees, and an exact withheld set, are properties of a rebuild
against the whole stream, and reproducing them incrementally is where a bounded view starts
showing a fraction of a namespace as if it were all of it. Keeping every unchanged row and
observing on every event gets the same answer at a cost the measurement above bounds.

**Refresh the rows on every record and accept the cost.** Rejected: it is the finding. Two hundred
seconds of rebuilding a table nothing reads, for ten thousand events, is the freeze §50.1 forbids
even though every individual refresh returns.

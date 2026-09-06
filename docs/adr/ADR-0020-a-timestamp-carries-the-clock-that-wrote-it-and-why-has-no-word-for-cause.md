# ADR-0020: A timestamp carries the clock that wrote it, and `why` has no word for cause

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariant 6, §14.3, §19.4, §21.4, §23, §23.3, §23.4, §37.1, §37.3, §38.3, §38.5, §39, §40, §42.1, §54, §55, §59.1, §61.6, §63.6
- Decided by: agent (autonomous)

## Context

K5 is the last untouched conformance level, and its two remaining requirements — temporal
integration and causal evidence discipline — are the two places where this provider is most likely
to produce a confident answer that is false.

**§39 hands out four kinds of timestamp and one clock.** An object's `creationTimestamp` and the
times in `managedFields` are written by the API server. An Event's `eventTime` is written by the
reporting component, on whichever machine that component runs. A condition's `lastTransitionTime`
is written by whichever controller wrote the status, and the object does not record which. A log
line prefix comes from a container runtime on a node (§42.1). Only `observed_at` is this machine's.
All five parse into milliseconds, all five sort, and the resulting sequence is a picture of the
skew between five machines presented as a history of a cluster. `logs.rs` already refuses the
conflation for node timestamps by keeping them as strings; nothing generalised that refusal.

**§14.3 makes `resourceVersion` an opaque continuity token** and §4 invariant 6 forbids sorting it
as a timeline. `ADR-0006` already made the comparison not compile. A temporal module is exactly
where that would be undone, because a watch gap is naturally described as "between version 9000 and
version 9600" and the difference between those two numbers looks like a duration.

**§40 is almost entirely refusals.** A provider contributes evidence rather than generating
authoritative explanations (§40.1); ownership indicates management responsibility rather than the
cause of any particular state change (§40.4); `why` must be allowed to conclude that the evidence is
insufficient, and that outcome is preferable to a plausible invention (§40.5). The generic
contract's §23.4 adds the sharp edge: a provider MUST NOT infer causality solely from timestamp
proximity.

The sentence at issue is one every operator says out loud during an incident: *the change at 14:21
broke the thing at 14:22*. It is sometimes true. It is never proven by the two timestamps, and a
provider that writes it down as a fact has laundered a hypothesis into evidence. `docs/coverage.md`
recorded both sections as "domain only" with no surface at all.

The question this record answers is where the refusals live. Both sections can be satisfied by
careful code, and careful code is what stops being careful in the fourth month.

## Decision

**One rule, applied twice: the strongest statement a type can make is the strongest statement the
evidence supports, so making a stronger one is a compile error rather than a review finding.**

`src/temporal.rs` — a timestamp never travels without its clock:

- `ClockSource` is part of every `Stamp`. Five writers, five words: the provider, the API server, a
  named `Reporter`, a named `Node`, and `Unattributed`. `is_comparable_with` is equality **minus**
  `Unattributed`, so two condition transition times are not ordered even against each other: "same
  field" is not "same clock" (§37.1).
- `Stamp` implements no ordering trait. `stamps.sort()` does not compile. The only comparison is
  `Stamp::relate`, whose fourth answer is `Order::Unordered(Undecidable)` — the answer an operator
  needs and a comparison operator has no room for. `apart_millis` returns `None` across clocks,
  because a distance between two machines is skew plus elapsed time with nothing separating the
  terms.
- `Basis::Observed` is reachable only through `Observation::watched`, which stamps with the
  acquisition clock. Everything read off state goes through `Observation::reported`, whose
  `ReportedSource` vocabulary has no variant for a watch event. A Pod created at 08:00 and first
  seen at 14:00 therefore cannot be filed as six hours of history (§39.2).
- `TemporalGap` keeps the two `resourceVersion`s the break lies between and, separately, the
  provider-clock instants at which it was noticed and resumed. `unobserved_millis()` comes from the
  second pair or is `None`. The tokens are positions; they never become a length (§14.3).
- `Timeline` states its window and both kinds of hole — watch gaps from `watch.rs`, scope gaps from
  `coverage.rs`. It has no method returning one merged sequence: `ordered_on` requires a clock to be
  named, so the cross-clock timeline has no entry point rather than a warning against it.
- An unreadable timestamp is `is_placeable() == false` and keeps its raw text. It is never coerced
  to the epoch, which would sort before everything real and read as the oldest fact in the cluster.

`src/causal.rs` — a ladder with five rungs and no sixth:

```text
CAUSALITY_NOT_PROVEN  <  CORRELATED_WITH  <  PRECEDED_BY  <  DEPENDENCY_PATH_EXISTS  <  ASSERTED_BY_KUBERNETES
```

- Every `Finding` constructor is bounded in what it may return. `Finding::proximity` yields
  `CorrelatedWith` or `CausalityNotProven` at any input and any window — §23.4 made structural.
  There is no `Finding::new(claim, support)`; a general constructor would let proximity be filed as
  an assertion and the type would guarantee nothing.
- `DEPENDENCY_PATH_EXISTS` is built from `relationship.rs`'s edges and means influence was
  *possible*. `Claim::means()` carries that limit in the vocabulary, because a bare token is read as
  strongly as its reader needs it to be.
- `ASSERTED_BY_KUBERNETES` is the §23.4 carve-out and is kept separable from correlation. It is
  reachable from an owner reference or native field (`Evidence::is_asserted_by_provider`), from an
  `observedGeneration` that has caught up with `metadata.generation` (§37.3, §40.4), and from an
  Event's `regarding` (§38.3). A selector this provider evaluated is `Unproven::NotAsserted`,
  however confident the match — §23.3's boundary, restated in the causal vocabulary. The Event's
  `reason` and `note` are not promoted with the `regarding` link (§38.5).
- `Why::strongest_claim` is the **maximum** of the ladder, never a sum. Three weak findings do not
  add up to a strong one, and a scoring function is how they would. Findings that establish nothing
  are kept, because a refusal is evidence about the search (§21.4, §4 invariant 13).
- `Why::describe` ends on the ceiling and its limit rather than on the strongest finding, so a
  reader who stops early stops on the qualification.

**Three things follow and are worth stating separately.**

*Both modules compose rather than duplicate.* Continuity comes from `watch.rs`'s `WatchGap` and
`GapReason`; scope truth from `coverage.rs`'s eight-way `Outcome`; edges and their evidence classes
from `relationship.rs`; conditions and `observedGeneration` from `condition.rs`; Event attachment
from `events.rs`'s `regards`, which already matches on UID before locator. Nothing re-derives a
relationship or re-reads an Event field, so there is no second place for the rules to drift.

*Time enters through `transport::Clock`.* Both modules are pure functions of recorded observations
and injected time — no network, no async, no wall clock (§59.1). Every assertion about a window, a
gap length or a correlation distance is deterministic under `FixedClock`.

*The absence of a causal word is asserted by reading the source.* `tests/causal.rs` fails if
`Caused`, `Causes`, `CAUSED_BY`, `root_cause` or `RootCause` appears in `src/causal.rs`, following
the precedent `tests/events.rs` set for Event reason literals. This rule dies by degrees — one
variant added "just for the case where it really is obvious" — and a test that reads the source is
the only kind that fails on the first degree. `tests/temporal.rs` proves the ordering ban the same
way, with a compile-time probe that fails if `Stamp` or `Observation` ever acquires `PartialOrd`.

## Consequences

Easy: §39 and §40 have implementations whose refusals a later author cannot forget, because
reaching for them does not compile into anything. A temporal answer states its window on the
provider's own clock, the watch gaps in it and the scopes it could not read. `why` can say that a
policy change preceded a readiness failure by sixty seconds on one clock, that a dependency path
made influence possible, and that Kubernetes asserts a controller relationship — and it cannot say
that any of them caused anything. §40.5's required conclusion is a normal return value.

Hard: neither module reaches a user. They join `relationship`, `workload`, `place`, `watch`,
`condition`, `evidence` and `events` as domain code the plugin does not import. §61.6's remaining
requirement — a verified external resolver path without provider-core coupling — is another
package's, and this work does not supply it. No conformance level is claimed.

Watch: `parse_rfc3339_millis` accepts only the UTC `Z` form that `metav1.Time` and
`metav1.MicroTime` marshal, and refuses offsets. If some aggregated API server ever serves an
offset form, its timestamps become unplaceable rather than wrong — the safe direction, and visible
in an answer rather than silent.

Watch also: the ladder's ordering is a judgement. Precedence sits above correlation because it
discharges more of the burden, and a dependency path above both because a structural connection
outlives a coincidence. Somebody may reasonably order those three differently. What is not a
judgement is the top of the ladder, and that is the property the tests assert.

## Alternatives considered

**Give `Stamp` a `PartialOrd` and document that cross-clock comparison is forbidden.** Rejected:
that is the comment-as-mechanism this repository keeps refusing. `stamps.sort()` would compile, read
naturally, produce a plausible sequence, and be wrong in a way no reviewer can see from the diff.

**Normalise every timestamp to the API server's clock using an observed offset.** Rejected: there is
no offset to observe. The provider never learns what a node or a controller thinks the time is,
only what it wrote, and a correction estimated from that is the fabrication both modules exist to
prevent. §13.4 of the generic contract requires the uncertainty to survive.

**Order a timeline by `resourceVersion` where timestamps disagree.** Rejected by §14.3 and §4
invariant 6, and by `ADR-0006` which already made the comparison not compile. It is also the most
tempting version of the mistake, because within one resource the tokens usually do increase.

**One `Source` enum with a public constructor for `Observation`.** Rejected: a `creationTimestamp`
could then be filed as a watch event by passing the wrong variant, and the result would be
indistinguishable from a change this provider saw. `ReportedSource` is a second, smaller vocabulary
with no word for it.

**A `Claim::Caused` variant, gated behind a strict evidence check.** Rejected as the whole point.
Every gate is a condition somebody can weaken later, and the weakening is always locally
defensible. A variant that does not exist cannot be reached by any argument.

**Let `Why` compute a confidence score across findings.** Rejected: a score is how three weak
findings become a strong conclusion, and it hides which finding carried the answer. The maximum of a
named ladder is legible and cannot be inflated by volume.

**Merge `TemporalGap` into `watch::WatchGap`.** Rejected for the reason `watch.rs` already gives for
keeping its gap apart from `coverage::Gap`: a watch gap is about continuity tokens, and a temporal
gap is about provider-clock instants. Folding them would cost one or the other, and the separation
is what keeps a `resourceVersion` from being read as a time.

**Take `§39.4` snapshot diffing as part of this work.** Not taken: it is an untaken `MAY`, and the
section itself says a difference between snapshots proves state difference rather than the sequence
of intermediate changes. `ReportedSource::ResourceSnapshot` exists so that a later diff has an
honest basis to record itself under.

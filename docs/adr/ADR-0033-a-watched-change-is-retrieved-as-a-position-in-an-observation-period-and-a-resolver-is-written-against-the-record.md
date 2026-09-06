# ADR-0033: A watched change is retrieved as a position in an observation period, and a resolver is written against the record

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 4, 5, 6, 13, 14, 20, §14.3, §19.4, §19.6, §20.2, §20.3, §21.4, §28.4, §28.5, §39.1, §39.2, §39.3, §39.4, §39.5, §41.4, §47.1, §47.2, §47.7, §60.8, §61.6, §62.11
- Decided by: agent (autonomous)

## Context

Two of K5's five requirements (§61.6) were open, and they are unrelated to each other except that
both are about this provider's edges: what it hands to somebody else, and what it can say about
time.

**§60.8 step 3 had no test and no code.** Steps 1, 2 and 4 were done — a Node states a
`providerID`, `get k8s-evidence` exports it with its JSON pointer, its evidence class and its
§47.2 strength, and two tests prove that no cloud vendor is named on the route and no cloud SDK is
in the dependency graph. Step 3 is "a synthetic cloud resolver maps it", and §61.6 spells what it
is for: *the first verified external resolver path without provider-core coupling*. The point of
that test is a negative one. If writing a resolver required so much as a field being added here,
the export would not be an export; it would be a plugin point, and §47.1's "a generic cross-system
resolver can consume" would be a description of an intention rather than of a fact.

**§39's two halves did not compose.** `docs/STATE.md` recorded it exactly: the watch half reaches
a user through `k8s-change`, which carries §39.3's segments and gaps; the temporal half reaches a
user through `k8s-timeline`, which names the clock behind every stamp and — because it opens no
watch — produces nothing but `Basis::Reported`. No route joined an object's timeline to the watch
history of its collection. So §39.3's history was *observable* and not *retrievable*: an operator
could watch a collection for ten minutes, see six changes go past, and then ask what is known to
have happened to one of those objects and be told only what its metadata says.

Joining them ran into a fact about `watch.rs` that turns out to be the whole design question.
`WatchStream` records **which** change arrived, to which lifetime identity, at which
`resourceVersion`, and in which order — and it records **no arrival time at all**. That is not an
oversight: a segment is a continuity structure keyed on the tokens the server hands out, and
`§14.3` and `§4 invariant 6` forbid those tokens from being read as a clock. The consequence is
that a change retrieved from a stream afterwards has an order and no instant, and the honest
options are to attach nothing, to attach something invented, or to widen `watch.rs` and the
session so that every event's acquisition instant is retained for the life of the session.

`temporal.rs` had already refused the middle option in words: `Timeline::absorb_continuity` takes
a stream's *gaps* and deliberately not its changes, because "stamping them all with the moment of
this call would invent acquisition times that look exactly like measured ones".

## Decision

### 1. A witnessed change carries a position and no instant, and no clock is named for it

`Timeline::include_watch(subject, stream, observed_at)` takes what a watch on the subject's
collection witnessed *of that subject* into the timeline. Each change becomes an `Observation`
with `Basis::Observed` and `Source::WatchEvent` — this provider did see it happen, which is
precisely what §39.2 separates from a timestamp read off state — and with `Stamp::unclocked()`:

```text
clock       unclocked
stamp       "" (there is no reading, and an empty string is not a fabricated one)
placeable   false
detail      "modified at position 9005, in observation period 1"
```

`ClockSource::Unclocked` is a new member of the clock vocabulary and it is not comparable with
anything, including itself, so `Stamp::relate` answers `Unordered(Unplaceable)` against every other
stamp and `Timeline::ordered_on(&ClockSource::Unclocked)` yields an empty sequence with every
candidate unplaceable. A witnessed change therefore cannot be sorted against this machine's real
readings, against the API server's timestamps, or against another witnessed change.

Seeing something happen and knowing when it happened are two claims. This provider makes the first
and declines the second, and the record shape is what keeps them apart: there is no timestamp field
on these records for a shell to order by, so the missing measurement cannot be recovered by a
consumer's optimism.

The position is a `resourceVersion` and it appears in `detail` as prose — "at position 9005" —
never in `stamp`. A continuity token in a field called `stamp` is §4 invariant 6's forbidden
reading arriving through a column heading.

### 2. A history is per observation period, and there is no call that concatenates two

Every witnessed change is filed under the unbroken `ObservedPeriod` it arrived in. A period carries
its ordinal, the `resourceVersion` it began at, the one it closed at where it closed, and how many
of the subject's changes were seen in it. `Timeline::witnessed(period)` requires a period to be
named — exactly as `Timeline::ordered_on(clock)` requires a clock to be named — so the
concatenation of two periods, which reads as a complete run while missing everything that happened
during the break between them, has no entry point rather than a warning against it (§4 invariant
14, §19.4). Each change's `detail` names its period too, so the separation survives into a record
even when a reader sees one row at a time.

The gaps between periods arrive as `TemporalGap`s on the same timeline, so `continuous` is false
and `gaps` is non-empty on every emitted record the moment a watch on this collection broke.

### 3. Three refusals travel with the composition

- **Only this subject's changes**, matched on the full `Identity`. A Pod rebuilt under the same
  name does not inherit the deleted one's history (§4 invariants 4 and 5).
- **Only what was witnessed.** The objects a stream's cache holds came from a list, and a list is
  one look at current state. Nothing in the cache becomes history (§39.2). A stream that listed and
  saw nothing change contributes a real, empty period.
- **A stream that observed nothing says so in the coverage.** `Syncing` records a
  `Outcome::NotQueried` gap and `Denied` records `Outcome::ListDenied`, because an empty history
  from an unsynchronised or refused stream is not a quiet object (§20.3, §21.4, §4 invariant 13).
  What was observed *before* a refusal is still carried; the refusal ends the period, it does not
  retract it.

### 4. The window widens to the moment the session last observed the collection, and no further

`Session::watch_observed_at(gvr, scope)` is added as a pure accessor of state the session already
keeps: the moment of the most recent observation of that stream — the listing that seeded the
cache, or the last event applied to it (§20.2). `include_watch` widens the timeline's `Window`
back to it.

This is the one provider-clock fact a retrieved stream has, and widening to it is a conservative
claim: the watch was demonstrably observing at that instant, and it was probably observing earlier.
Widening further would require an acquisition time nothing records. Without the widening, a
`k8s-timeline` record would report a window one read wide beside changes that happened before the
read — an answer that contradicts itself.

### 5. §39.4's `MAY` is declined

State snapshots are not taken. Three reasons, and the third is the one that matters:

- The provider already holds the only snapshot it needs. §20.3's informer-style cache *is* a
  synchronised snapshot with a known sync state, and `Freshness` already says whether an object
  came from it. A second, retained snapshot store would be a second copy of cluster state living
  across invocations under a different set of freshness rules, and §50.5 and §51.1 are about
  keeping this package's footprint small.
- What §39.4 offers is weaker than what §39.3 now delivers. The section says it plainly: "A
  difference between snapshots proves state difference, not the exact sequence of intermediate
  changes." The composition above delivers the sequence, within the period it was observed.
- Most importantly, **the gap §39.4 might have covered is closed rather than described.**
  `k8s-timeline` now retrieves §39.3's history: an operator who watched a collection with
  `k8s-change` and then asks what is known to have happened to one of its objects receives the
  changes this provider witnessed, with the coverage window they fall in and every break in it. The
  requirement was not "there is no snapshot"; it was that history was observable and not
  retrievable, and retrieval is what has been built.

The snapshot the route *does* record stays what it was: the read itself, as
`ReportedSource::ResourceSnapshot`, whose basis is `reported` even though its stamp is this
machine's own clock, because a snapshot proves that state was so at a moment and never the sequence
that reached it.

### 6. Per-event acquisition instants are deferred, deliberately and visibly

The honest way to give a witnessed change a measured instant is to record it as the event arrives,
which `Observation::from_change(change, at)` already exists for and which `k8s-change` could do —
and then to keep those instants in the session for the life of the watch. That is a change to
`watch.rs`'s segment structure and to the session's per-stream state, it costs memory proportional
to the number of events observed, and it needs a bound (§18.5, §50.5). It is a separate decision
and it belongs on the board, not smuggled in here. Until it is taken, the answer says `unclocked`
rather than guessing, which is the direction §39.2 and §13.4 of the generic contract both point.

### 7. The resolver of §60.8 step 3 is written against the record, and lives entirely in a test

`crates/ono-kubernetes-plugin/tests/resolver.rs` builds the records `get k8s-evidence` emits — the
same contribution table, the same schema, the same record builder — and hands them to a synthetic
cloud resolver defined in a module of that same file. The resolver's entire input is
`&[Arc<RecordValue>]`. It imports no type from `ono_provider_kubernetes`, sees no `Object`, no
`Gvr` and no `Place`, and reads the records by the field names the `k8s-evidence` schema declares.

Its vendor knowledge is one table with one row — the scheme `aws`, the foreign system it belongs
to, and the convention that this scheme writes a failure domain first and an instance identifier
last. That knowledge is entirely in the test, which is the point of §47.1: the decomposition this
package performs stops at `<scheme>://<path>` and labels no segment (§28.4).

The link the resolver draws states whose claim it is:

```text
claimed_by       synthetic-cloud-resolver
rests_on         aws:///eu-central-1a/i-0123456789abcdef0 stated at /spec/providerID
evidence_class   inference
```

`inference` and not `native-field`: the *field* is native and the API server states it, and the
identification of a machine in another system is a finding of something that has read both sides
(§4 invariant 20, ADR-0016). The exported record's own `evidence_class` stays `native-field`,
because it is a claim about the field.

A value the export marks `lookup_key: false` produces a *candidate* and never a link, however exact
it looks. The resolver reads the flag rather than judging the value, which is §47.2's ranking doing
the work it exists to do (§28.5).

**The decoupling is proven behaviourally rather than by grepping for vendor names.** The same
fixture is exported twice, once with an `aws://` identifier and once with an invented
`quantum-fabric://` one, and every field of the two records that is not the value itself is
identical — because this package has no arm for either. The resolver recognises one and refuses the
other by name. If anything here knew about a cloud, those two exports would differ.

### 8. `tests/resolver.rs` is where it lives, not `crates/ono-provider-kubernetes/tests/`

The alternative was to drive the domain layer and assert the emitted records separately. It was not
needed: `records::evidence_record`, `contributions::target`, `NodeEvidence::of`, `Place::of_object`
and `Freshness::direct_read` are all public, so the real emitted records can be built in a second
test binary without the `RecordedCluster` host machinery of `tests/query.rs` — which is a single
test binary's private scaffolding and not reachable from another one. What the resolver consumes is
therefore the record a pipeline receives, built by the code that builds it in production, and no
part of the emission path is stubbed.

## Consequences

- `k8s-timeline` answers `basis: observed` records for the first time. A consumer that assumed
  every record from this target was `reported` was reading a fact about the old implementation.
- Records with `clock: unclocked` and an empty `stamp` now exist on the `k8s-timeline` schema. No
  field was added and no field changed nullability: `stamp` is a required string and the absence of
  a reading is spelled as the empty string beside `placeable: false`, rather than as a fabricated
  instant. A renderer keying on `placeable` shows what it always showed.
- `ClockSource` has a sixth member. Nothing matches it exhaustively outside `temporal.rs`.
- `Undecidable` deliberately gained *no* member: an unclocked stamp comes back as
  `Unplaceable` — "names no instant" — which is true of it and keeps `causal.rs`'s mapping from
  refusal to `Unproven` exhaustive without a change there.
- `Session` gained one accessor and no state. The watch registry is unchanged.
- The `k8s-timeline` route now reads the session's watch registry. It opens no watch: a target that
  started one to answer a timeline would be watching on behalf of a query that has already ended
  (§19.6, §19.7).
- Because the composition depends on a watch having run *in this process*, the same
  `get k8s-timeline` answers differently before and after a `k8s-change` on the same collection.
  That is the truth of §39.2 rather than an inconsistency: what a provider knows about the past
  depends on whether it was looking.
- §60.8 is complete. K5's five requirements of §61.6 are met.

## Alternatives considered

**Stamp each witnessed change with the session's last observation instant.** One line, and it is
the invented history `temporal.rs` exists to prevent. Every change in a period would carry the same
placeable instant, `Stamp::relate` would call them `Simultaneous` — a positive claim that they
happened at the same moment — and they would sort convincingly against real readings. Rejected on
§39.2.

**Put the position in `stamp` and mark it unplaceable.** A `resourceVersion` in a field named
`stamp` is §4 invariant 6's forbidden reading delivered by a column heading, and the first consumer
to sort on it would produce a timeline out of opaque tokens. Rejected.

**Add `run` and `position` fields to the `k8s-timeline` schema.** Cleaner to read, and it would have
required editing `contributions.rs`, `package/contributions/targets.yaml` and `records.rs`. The
existing schema already declares `basis: observed`, `source: watch-event`, `clock`, `stamp`,
`placeable`, `detail`, `continuous` and `gaps` — it was designed for this — and everything the two
new fields would carry is carried by `detail` and by the gap list. Deferred rather than rejected: if
a renderer needs to group by period without parsing prose, that is a schema change worth making on
its own evidence.

**Widen `watch.rs` to retain a per-event acquisition instant.** The complete answer, and a change to
the continuity structure, to session state and to this package's memory profile. Deferred to the
board (decision 6).

**Take §39.4 and diff two snapshots.** Weaker than what was built, and a second copy of cluster
state to keep fresh. Declined in decision 5.

**Write the resolver against the domain types.** It would have passed and proven nothing: the
requirement is that a resolver can be written by somebody who has only the published record
document, and a resolver holding an `IdentityEvidence` is a resolver that must be compiled against
this repository.

**Assert the decoupling by grepping the resolver's source for Kubernetes names.** Brittle, and it
tests spelling rather than structure. The signature is the proof — the resolver's input is records
— and the behavioural test of decision 7 proves the other direction with a fixture instead of a
regular expression.

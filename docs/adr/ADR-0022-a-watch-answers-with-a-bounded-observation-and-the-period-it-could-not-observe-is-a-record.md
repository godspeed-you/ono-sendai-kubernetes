# ADR-0022: A watch answers with a bounded observation, and the period it could not observe is a record

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariant 13, §4 invariant 14, §9.2, §11.5, §13.1, §14.3, §18.2, §18.3, §19.1, §19.2, §19.3, §19.4, §19.5, §19.6, §19.7, §20.2, §20.3, §22, §39.3, §41.4, §50.1, §61.4, §62.6, §62.12
- Decided by: agent (autonomous)

## Context

`watch.rs` held the whole of §19 — the state machine, the segments, the gaps, the backoff, and
`WatchDecoder`, which turns a chunked `200 OK` body into events and reads a `410` arriving as an
error frame *inside* that successful stream as an expiry. `transport.rs` built the request and
streamed the chunks. `session.rs` held the registry. **Nothing opened a watch**: `watch_request`
had two callers and both were tests. That single missing route blocked all six K3 requirements
(§61.4), Gate F end to end, §41's live views, §39's temporal history, §20.3's sync state, and
Appendix A's watch `MUST` for every profile in the matrix.

Two things had to be decided, and only one of them is about Kubernetes.

**What shape does a watch take as a `provider.query`?** A watch is unbounded; a contributed target
answers with a value stream under credit. That part composes: `Ctx::emit` blocks for credit and
returns `EmitError::Cancelled` when the host cancels, which is exactly how core's own endless
target behaves — `count-forever` in the example package emits until it is cancelled and nothing
else. What does **not** compose is the borrow. `BrokeredStream` holds `&mut Ctx` for as long as the
connection lives, because every byte travels as a host call; `Ctx::emit` needs the same `&mut Ctx`.
So while a response body is open, nothing can be emitted. A live view would need either a second
context, a way to lend the context back between reads, or a non-borrowing connection handle, and
none of the three exists in the protocol as it stands.

**What must a user be able to see?** Not the streaming. §4 invariant 14 and §19.4 say pre-gap and
post-gap events are never stitched into a continuous history, and Gate F (§62.6) is that sentence
made checkable. A stream of change records with nothing in it to mark a break *is* that stitching:
the reader sees an ordered sequence and has no way to know that part of it was never observed. The
gap is the requirement; the liveness is a feature.

## Decision

### 1. `k8s-change` is a target of its own, and a gap is one of its records

One record per observation, of schema `io.github.godspeed-you.kubernetes.change/1`, with
`change` taking one of five words: `listed`, `added`, `modified`, `deleted`, `gap`. `listed` is an
object that was in the collection when observation began — a starting state rather than a change.
The other three are §19.3's classes verbatim. `gap` is a period this provider could not observe,
which is a fact about time rather than about an object, so its object fields are all null.

A gap could have been a second schema. It is not, because a consumer that has to join two streams
to notice a break is a consumer that will forget to, and because a gap *is* an observation — of a
period rather than of an object.

### 2. Continuity is carried on every record, not attached to the ones that broke

Three required fields, and they are required so that a reader cannot fail to be told:

- `segment` counts the unbroken observation periods. Everything before a `410` is segment 1 and
  everything after it is segment 2, so `group by segment` is the honest reading and concatenating
  the two is not something a consumer arrives at by accident (§39.3);
- `continuous` is false from the first gap onward and never resets — the one-bit form of the same
  fact, for a reader who filters rather than groups. Closing a gap says observation continues,
  never that the unobserved period was filled in;
- `sync_state` is §41.4's word for what a live view may honestly show: `syncing`, `live`,
  `reconnecting`, `gap detected`, `denied`. `live` is the only one of the five that entitles
  anybody to read an absence as an absence (§20.3).

The schema's identity is `resource`, `segment`, `change`, `uid`, `resource_version`. A change has
no `metadata.uid` of its own — the UID on the record is the object's — and the segment is in the
key because without it an object re-listed after a break would collapse onto the observation made
before it, which is §4 invariant 14 undone through the identity model rather than through the
record stream.

### 3. List, then watch from the collection's version — never from "now"

§19.1's sequence is the requirement rather than an optimisation: a watch opened without a
`resourceVersion` starts at the present moment and silently loses everything that already exists.
The listing goes to `Session::synchronise`, which refuses it when it is not a snapshot a cache may
stand on (§18.2, §18.3). A listing that lost a page is a fine answer to `get` and a terrible cache,
because every object it was refused would afterwards read as absent — §4 invariant 13 reached
through the back door.

The collection is resolved for `Verb::Watch` rather than `Verb::List`, through the same discovery
route `k8s-resource` uses, so a CRD invented after this package was built is watchable without
recompiling anything and a refusal names the grant that is actually missing (§11.5).

### 4. One invocation is a bounded observation, and says so in its own shape

This invocation acquires the collection, opens one watch, reads that response to its end or to
`max_changes`, and answers with what it carried — plus, where continuity broke, the gap record and
the re-acquired state on the far side of it (§19.4 step 4, which `reacquire` may switch off; the
gap record is emitted either way). Cancellation is checked before every emission (§62.12), and the
process boundary of §50.1 is unchanged.

It is a *bounded observation of a live stream* rather than a live view, and every record's
`sync_state` says which of §41.4's five states the stream was in when the answer was given. The
limitation is the protocol's rather than this provider's, and it is named in §5 below rather than
worked around.

### 5. What core would have to offer for a live view

A live `k8s-change` needs the invocation context to be reachable while a brokered connection is
open. Any one of these would do it, and none exists today:

- a `Ctx` that can lend itself back between reads of a connection it owns — i.e. a brokered stream
  that borrows for the duration of a read rather than for the duration of the connection;
- a non-borrowing connection handle, with `streams.next` callable through a value the package can
  hold beside `Ctx` rather than through `Ctx`;
- a host-side pump: `provider.query` answering from a stream the host drives, so that the package
  hands back a source rather than emitting from a loop it owns.

This is a finding about the KUANG/11 SDK, not a gap here, and it belongs in an ADR in core if it is
to be decided. It is the second such finding on this boundary: Gate J's word "concurrently" is not
reachable either, because the SDK serves one request at a time.

### 6. A `410` is read from wherever it arrives, and an unreadable frame is a break

An expiry may arrive as the *status* of the watch response, when the checkpoint names history the
server has already discarded, or as an `ERROR` frame inside a perfectly successful `200 OK` stream,
when it expires while the stream is open. The second is how a real expiry arrives, and an
implementation that classifies HTTP codes never sees it. Both become
`WatchEvent::Error(WatchFailure::Expired)` and go to the same state machine.

A frame that arrives whole and cannot be decoded is neither an expiry nor a protocol fault to
report as one. It suspends the stream, so the events after it are never filed inside the history
before it, and the re-acquisition that follows records the gap that leaves — a stream re-listed
rather than resumed did not observe what produced the new state.

### 7. A watched object crosses the boundary as a `Guarded`, like every other object

§22 and Gate I: a watched Secret is a Secret. There is one door into the emission path and a change
stream does not get a second one.

## Consequences

- **Gate F is end to end.**
  `should_make_a_watch_gap_visible_rather_than_stitching_a_history_over_it` drives the real binary
  against a recorded server that opens `200 OK` and closes the stream with a `410` error frame. The
  emitted sequence is `listed(1) modified(1) gap(1) listed(2) listed(2)`; the gap names
  `watch_expired_410` and the last version observed before it; and the object that appeared during
  the break is never reported as having arrived, because nobody observed it arriving.
- **K3's first three requirements are routed**, and the other three are reachable from the same
  route: `live.rs`'s view states are the `sync_state` word, the cache is the one `session.rs`
  synchronises, and `events.rs` needs a target rather than a mechanism.
- **§20.2 now has two origins from a user's seat.** A `get` by name in a session with a live watch
  is answered from the cache with `origin=cache`, and the object endpoint is never asked
  (`should_answer_a_watched_object_from_the_cache_and_say_that_is_where_it_came_from`). A listed
  object is `direct-read` and a pushed one is `watch-event`, so all three of §20.2's words are
  produced by something.
- **A watch does not stay open across invocations, and the checkpoint does.** The registry is the
  session's (§19.6, §19.7), so a second `k8s-change` in one session resumes from where the first
  stopped rather than re-listing. What does not survive is the connection.
- **`max_changes` bounds an unbounded thing, and the bound is visible.** An invocation that stops
  at its budget answers a prefix and says which segment it stopped in, rather than never returning.
- **§19.2's streaming lists remain a `Capability` slot nothing negotiates.** The fallback is the
  list/watch this record implements, which is the safe half of the pair.

## Alternatives considered

**A `--watch` flag on the existing nouns.** `get k8s-pod --watch` would emit Pod records as they
change. Rejected because a Pod record has nowhere to put a gap: the schema is a projection of an
object, and a period nobody observed is not an object. Adding `segment` and `continuous` to all
twenty object schemas would put a watch's vocabulary on every read that is not one.

**A gap as a failed invocation.** `Outcome::Failed` carrying the gap, as `query.rs` does for an
incomplete listing (ADR-0004). Rejected because a watch that hit a `410` and re-acquired has *not*
failed — it has a discontinuous history, and the records either side of the break are true. Failing
would discard the second segment, which is the part the operator wants most.

**A gap as a log line or a diagnostic field on `k8s-cluster`.** Rejected on §4 invariant 14: a gap
that is not in the stream is a gap a consumer of the stream cannot see, and the stream is where the
stitching would happen.

**Emitting the initial listing as `added` events.** Simpler, and false. Those objects did not
arrive; they were there. §19.1's snapshot and §19.3's classes are different claims, and `listed` is
the word that keeps them apart.

**Reopening the watch repeatedly within one invocation to approximate a live view**, emitting
between rounds. It works — §19.5's reconnect from a checkpoint is exactly this — and it trades a
new connection per batch for a lag of one batch. Rejected for now because it makes the invocation
unbounded again without making it live, and because the honest answer to "why is this not live" is
§5 above rather than a loop that nearly is.

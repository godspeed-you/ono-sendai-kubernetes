# ADR-0030: A followed log is a live stream that accumulates nothing, and a cancelled follow makes no claim

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariant 13, §19, §21.4, §41, §42.1, §42.2, §61.5, §62.12, §63.6
- Decided by: agent (autonomous)

## Context

Acceptance Gate L (§62.12) asks that "large list, watch, log-follow and verification operations
terminate promptly under Ono cancellation semantics". Three of the four were proven end to end.
The fourth had no route at all: `LogRequest::following()` existed, `LogFollow` existed, both were
tested in the domain layer, and nothing in the package ever called either. `k8s-log` deliberately
declared no `follow`, and the reason it gave was honest — a followed log is a live stream with the
same shape as `k8s-change`, and offering the word without that machinery would answer a followed
request by closing the body at once, which a reader takes for a container that has just stopped.

The machinery has existed since ADR-0023. A brokered connection borrows the invocation context for
the length of one read rather than for the length of the connection, so a handler holding a
`Lease` can read a chunk, release the context, emit, and read again with the body still open. That
is what made `k8s-change` a live watch, and it is all a followed log needs.

Three things were still open, and none of them is answered by copying `changes.rs`.

**§42.2 forbids a log becoming provider cache or temporal history.** The domain layer enforces
that in the shape of its types: `Retrieved` is deliberately not `Clone`, and `LogFollow` holds
counters, a state and a partial line, and no lines at all. A follow route that collected lines
into a `Vec` and built one `Retrieved` at the end would satisfy every test in this repository and
break the rule the whole module exists for, silently, in exactly the case where the collection is
unbounded by construction.

**A record needs a `Retrieved` and a follow has no end.** `records::log_record` reads the target,
the run, the bounds and the ending off a `Retrieved`. During a follow there is no ending yet, and
`bounds` still has to be on every record, because following a log does not make it complete: the
container runtime rotated and truncated it before anybody followed it.

**The empty-answer refusal was written for a bounded read.** §63.6 and ADR-0025 make a read that
produced no lines end the invocation with its bounds rather than complete with an empty stream,
because a reader who receives nothing concludes that the container printed nothing. A follow can
end empty for two very different reasons, and one of them is the operator.

## Decision

**1. `follow` is an option of `k8s-log`, declared in `contributions::LOG_OPTIONS` and in
`package/contributions/targets.yaml`, and it is the only one there that is not a bound.** Every
other option narrows the answer and adds an entry to the record's `bounds`; this one removes the
end of it. It is declared last for that reason. Splitting a `k8s-log-follow` target off was
rejected: the question is the same question, and the shell already has a word for "keep going".

**2. A followed log is a live invocation with `k8s-change`'s shape.** The handler takes the
`Lease` once, and runs two exchanges over it through `query::converse_on`: `Prepare` under the
ordinary read policy, and `Following` under `ReadPolicy::watch()`. The split is deliberate. A
request policy fails after three thirty-second idle windows, which is correct for an API server
that accepted a request and then said nothing, and wrong for a container that prints once an hour.
A watch policy waits a quarter of a second per read and never gives up, which is correct for the
body and wrong for the Pod read that precedes it. Cancellation is checked at the top of every
chunk iteration and in the read-error arm, and a cancellation that surfaced as a stream error is
answered as a cancellation.

**3. Nothing is accumulated: `LogFollow` is the type that carries the follow, and one `Retrieved`
is built per line and dropped with its record.** The per-line `Retrieved` is the record's
provenance — the target, the run, the bounds, the ending — and it is the smallest thing that can
carry it. There is no list anywhere in the package that grows as the container writes, which is
§42.2 held by construction rather than by remembering.

**4. A record emitted while the body is open says so.** `follow.ending()` is `Ending::StillOpen`
during the follow, so every record carries "the stream is still open" rather than a claim that the
stream ended. `bounds` is on a followed record exactly as it is on a read one.

**5. `follow` with `previous` is refused before the request is sent**, through the existing
`LogRequestError::FollowPrevious`, mapped to `provider.unsupported` in the one place both answers
build their HTTP request. The API server accepts the pair, ignores `follow` and closes the body
immediately, and a caller watching for more lines reads that as a container it has just seen stop.

**6. How a follow ends is three different sentences, and cancellation is not one of them.**

- The operator cancelled it: `Outcome::Cancelled`, and no refusal, whatever it delivered. A read
  somebody interrupted has made no claim about what the container did or did not print, and
  refusing on its behalf would invent one. This is the distinction ADR-0025's refusal cannot make.
- The stream failed: `provider.unavailable`, whatever it delivered first. Reporting `Completed`
  after a body that broke would present a truncated follow as a whole one.
- The body ended having delivered nothing: `contribution.refused`, in §63.6's spirit but not
  §63.6's words. The help text names the ending beside the bounds, because a body that ended is a
  fact about the connection rather than about the container — a proxy dropping an idle stream, a
  node rebooting and a process exiting are indistinguishable from here.
- The body ended having delivered lines: `Completed`.

**7. `LogFollow::finish()` is added to the domain layer.** A followed body that ends mid-line was
holding bytes in the decoder that nothing could reach, so the last thing the container wrote
disappeared — silently, and exactly where a reader is looking hardest. It is handed over as an
unterminated line, which is what `LogDecoder::finish` already does with the same bytes for a
bounded read.

## Consequences

- Gate L's fourth leg is closed. `should_stop_a_followed_log_promptly_when_the_host_cancels_it`
  cancels a follow against a body that never ends, asserts `Cancelled`, and then proves the
  provider instance survived — which is what says the brokered connection was given back rather
  than abandoned or closed twice.
- `should_emit_a_log_line_as_it_arrives_rather_than_when_the_stream_ends` asserts the live
  property the way the watch tests do: the recorded server answers with the head of a chunked body
  and nothing else, and each line goes on the wire only when the test releases it. A record cannot
  exist unless the package emitted it while still following.
- The bounded read is untouched behaviourally. Its conversation now shares `prepare` with the
  follow, so the two cannot drift on which cluster they discovered, which Pod they read, or which
  request they would have sent.
- A followed `k8s-log` holds a connection for as long as the operator watches it, and the host's
  credit is the backpressure: `Ctx::emit` blocks until the consumer has taken a record, so a
  chatty container stops being read from rather than being queued here.
- Two refusal sentences now exist for an empty log where there was one. They are deliberately
  close in wording — both say "this is not evidence that the container printed nothing" — and
  deliberately different in what follows it.

## Alternatives considered

**Buffer the follow and emit at the end.** It is what `k8s-log` did for a bounded read and it
would have needed no new machinery. Rejected twice over: it is the §42.2 violation this ADR is
mostly about, and against a body that never ends it does not merely emit late — it never emits.

**A separate `k8s-change`-style target, `k8s-log-follow`.** It would keep the bounded handler
untouched. Rejected: it is the same question about the same object, and a second noun for it is
the hidden Kubernetes mini-shell §4 invariant 22 forbids, one word at a time.

**Refuse an empty follow with ADR-0025's existing sentence.** Simpler, and one refusal instead of
two. Rejected because it makes a claim the follow has not earned: a read that looked and found
nothing and a stream that was open and carried nothing are different facts, and the second one is
about the connection.

**Treat a cancelled follow that delivered nothing as an empty answer and refuse it.** Rejected for
the same reason, more strongly: the operator ended the read. A refusal there would tell them
something about the container on the strength of their own keystroke.

**Let the follow reconnect when the body ends, as the watch does.** A watch reconnects because
`resourceVersion` names a position the server still holds, so nothing is missed. A log has no
such token — reopening would either replay from the start or start from now, and neither is the
continuation it would look like. The body ending ends the follow, and the record says so.

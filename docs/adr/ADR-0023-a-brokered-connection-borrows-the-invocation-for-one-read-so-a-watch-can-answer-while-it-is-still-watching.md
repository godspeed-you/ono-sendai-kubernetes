# ADR-0023: A brokered connection borrows the invocation for one read, so a watch can answer while it is still watching

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariant 13, §4 invariant 14, §19.1, §19.3, §19.4, §19.5, §20.2, §20.3, §22, §31.15, §41.4, §50.1, §61.4, §62.6, §62.12
- Supersedes: `ADR-0022` §4 (one invocation is a bounded observation) and the finding in its §5
- Decided by: agent (autonomous)

## Context

`ADR-0022` routed a watch and then said, in §5, what it could not do and why:

> A live `k8s-change` needs the invocation context to be reachable while a brokered connection is
> open. […] a brokered stream that borrows for the duration of a read rather than for the duration
> of the connection; a non-borrowing connection handle […]; a host-side pump.

The limitation was real and it was located in the wrong place. It was recorded as a finding about
the KUANG/11 SDK — something core would have to offer — and it is not. Nothing in the protocol
forces the borrow. `streams.next` is a host call like any other; the package holds no descriptor
either way. The borrow existed because `BrokeredStream` stored `&mut Ctx` in a field and therefore
held it for as long as the connection lived, and `Ctx::emit` needs the same `&mut Ctx`. Two
alternating uses of one exclusive reference were expressed as one long-lived one.

The cost was not a missing feature. It was a *false* answer to the question `k8s-change` exists to
answer. §19 and §41 describe observation that continues; a bounded observation of a live stream is
a different claim, and the sentence in `changes.rs` that explained why the shape was bounded was
explaining a property of a struct field as though it were a property of the protocol.

Three shapes could remove it, and the first two need a decision each rather than a preference.

## Decision

### 1. The context is leased, and the lease is what the connection holds

`broker::Lease` owns `&mut Ctx` for the length of one handler and hands it out one caller at a
time. `BrokeredStream` holds `&Lease` and a handle; it borrows the context inside `streams.next`
and `streams.emit` and has given it back before the call returns. What survives between two reads
is the handle and the bytes that arrived and were not consumed — state rather than a borrow.

So a handler reads a chunk, releases the context, emits the records that chunk decoded to, and
reads the next chunk, with the response body open throughout. That is `ADR-0022` §5's first shape,
and it needed no change in core.

**`ByteStream` is untouched, and that is the point.** The obvious alternative was to give the
trait's methods a context parameter, generic so that `FixtureStream` passes `()`. It was rejected
on what it would drag with it: `TlsStream` sits between the broker and HTTP and implements the
same trait, so it would carry the parameter too, and so would `HttpConnection`, `Client`, and
every `fn …<S: ByteStream>(client: &mut Client<S>)` in `logs.rs`, `mutation.rs`, `plan.rs`,
`discovery.rs` and `session.rs` — a parameter that is `()` in every domain test and every fixture,
threaded through a layer whose whole value is that it does not know a host exists. The borrow was
never a property of `ByteStream`; it was a property of one implementation, and that is where the
change belongs.

**The lease is checked rather than assumed.** It lends the context out one caller at a time and
refuses an overlap, naming it as a defect in this package. What the compiler can no longer prove
across an implementation of a trait that carries no context, the lease proves at the point of use:
a read *inside* an emission would be that overlap. It cannot be reached from the loop below —
reads and emissions alternate — and if a later change reaches it, it is a refusal with a sentence
on it rather than a second exclusive borrow or a panic.

### 2. A read policy belongs to the exchange, because silence means opposite things

A request whose response never comes is a broken server: three empty deadline windows and the
connection is called dead. A watch whose response never comes is a collection in which nothing
changed, which is the ordinary case. One constant cannot mean both, so `ReadPolicy` says which,
and a `Conversation` declares it.

The watch policy is a quarter-second window with no limit on empty ones, and the short window is
about cancellation rather than about latency. The host serves one call at a time, so an invocation
parked in a thirty-second read cannot be told the operator has stopped it until that read returns
— and a watch spends nearly all its life parked in a read. The window is therefore the resolution
of §62.12's "promptly", and an empty one is where `Ctx::cancelled` is asked. A cancelled read
comes back as a stream error, because a byte stream has no other vocabulary, and the loop above
asks the lease whether the invocation was cancelled before it calls anything a failure: reporting
the operator's own decision as a fault of the cluster would be a lie about the cluster.

### 3. `k8s-change` is live, and `max_changes` is how a caller asks for a prefix

The invocation acquires the collection, emits its state as `listed`, opens a watch from the
version that listing returned, and then emits one record per frame as each frame arrives, until
the operator cancels it. `ADR-0022` §4 said the opposite and its reason no longer exists, so this
supersedes it rather than adding a mode beside it.

The bounded observation survives as an option: `max_changes` now bounds *records emitted* rather
than events read, which is both the thing a caller can see and the thing a caller meant. Absent,
there is no bound, because a watch has no natural end and inventing one — five hundred changes,
say — is a number that would decide for the operator when they had seen enough.

A body that ends is not the end of the watch. §19.5's reconnect is now something this invocation
does rather than something the next invocation inherits: the server's own watch timeout closes the
stream, the checkpoint is still good, and the next request opens at it. A round that delivered
nothing and ended at once is the one shape that could spin, so it is paced by the bounded backoff
`watch.rs` already carried (50 ms doubling to 1 s), reset by any round that delivered a record.

### 4. Nothing is buffered between the cluster and the consumer

`Ctx::emit` blocks until the host has credit, and the credit is created by the consumer taking a
record (§31.15). Because a record is emitted as its frame is decoded, a watch that produces faster
than its reader stops reading the socket rather than growing a queue: the backpressure lands on
the API server's connection, where TCP already knows what to do with it. The alternative — decode
into a vector and emit later — is what the previous shape had to do, and it is unbounded in
exactly the case that matters, a busy collection nobody is reading quickly.

### 5. The gap is unchanged, and now it has a second side

Everything `ADR-0022` §1, §2, §6 and §7 decided stands: one record per observation, `gap` as one
of the five words, `segment`/`continuous`/`sync_state` required on every record, a `410` read from
wherever it arrives, and one redaction door. What changes is that observation *continues* past the
break. The gap record is emitted, state is re-acquired by listing, the re-listed objects carry
segment 2 and `continuous = false`, and the watch reopens — so the second segment is a period a
reader can go on watching rather than the last thing the invocation had to say before returning.

## Consequences

- **A live watch reaches a user.**
  `should_emit_a_record_as_each_change_arrives_rather_than_when_the_stream_ends` drives the real
  binary against a recorded server that opens the watch, never sends the terminating chunk, and
  puts each frame on the wire only when the test releases it. A record therefore cannot exist
  unless the package emitted it with the body open. Against that server the previous shape does
  not answer late; it does not answer at all.
- **Gate F holds inside a stream that does not stop.**
  `should_go_on_watching_after_a_gap_rather_than_ending_at_the_break` sees
  `listed(1) modified(1) gap(1) listed(2) listed(2) added(2)` — four requests to the collection
  endpoint: the acquisition, the watch that broke, the re-acquisition, and the watch that replaced
  it. `should_make_a_watch_gap_visible_rather_than_stitching_a_history_over_it` is unchanged and
  still passes, now under `max_changes`.
- **Gate L holds for a query that never ends by itself.**
  `should_stop_a_live_watch_promptly_when_the_host_cancels_it` cancels a watch on an open body,
  gets `Cancelled` rather than a stream that stops, and then answers the next query from the same
  instance — which is what says the brokered connection was given back. Closing a handle the host
  has already retired is a protocol violation that quarantines the package, so the release still
  goes through the `is_open` check `converse` has always made.
- **The option that skips the re-acquisition still reports the break.**
  `should_report_the_gap_even_where_the_query_refused_to_pay_for_a_re_acquisition` asks for
  `reacquire: false`, sees `listed(1) modified(1) gap(1)` and exactly two reads of the
  collection. What `reacquire` buys back is the second listing; it was never the gap.
- **`FixtureStream` and the domain layer did not move.** `transport.rs`, `watch.rs`, `tls.rs` and
  every test over them are untouched: the change is entirely in how the package's own
  implementation of `ByteStream` obtains a context. The 498 tests of `ono-provider-kubernetes`
  that prove the provider without a cluster prove exactly what they proved before.
- **Two costs, named.** An idle watch makes four host calls a second, which is the price of
  quarter-second cancellation and is a message on a pipe rather than anything on the network. And
  the alternation of read and emit is enforced dynamically rather than statically; §2 above says
  what that buys and how it fails if it is ever broken.
- **`ADR-0022` §5's finding is withdrawn for the first of its three shapes.** The other two remain
  true statements about the SDK and neither is needed. The unrelated finding in the same section —
  that Gate J's "concurrently" is unreachable because the SDK serves one request at a time — is
  untouched and still stands.

## Alternatives considered

**A context parameter on `ByteStream`.** Rejected in §1: it is the shape the task suggests first
and it is honest, but it puts a host concept into the trait every domain module and every fixture
is written against, to serve one implementation of it.

**Lending the context back through the stream — `Option<&mut Ctx>` with `take` and `restore`.**
Statically checkable, and the closest thing to a compiler-proven version of §1. Rejected because
the borrow has to be reached *through* the stack that owns it: the watch's byte source is
`TlsStream<BrokeredStream>` inside `HttpConnection` inside `Client`, so either `TlsStream` grows
an `inner_mut` and the lend becomes a four-deep reach, or the lend becomes a trait method and
every implementor carries it — which is the alternative above wearing a different hat.

**A response stream the caller pumps, holding no byte source.** `HttpConnection` taken apart into
`(stream, host, buffer)` between reads, so that ownership of the bytes is never held across an
emit. It works for the plain path and stops at TLS: a `rustls` session cannot be parked and
rebuilt over a fresh inner stream without `tls.rs` learning to do it, and the session state is
exactly the thing that must not be dropped between two reads of one connection.

**Reopening the watch between batches to approximate liveness**, which `ADR-0022` considered and
rejected. It is now not merely unattractive but unnecessary.

**Keeping the bounded invocation as the default and adding a `--follow` option.** Rejected because
it leaves the noun meaning the wrong thing: `get k8s-change --kind Pod` is a question about what is
happening, and answering it with a prefix of a stream, by default, is the same category error the
bounded shape was. A caller who wants a prefix says how long a one.

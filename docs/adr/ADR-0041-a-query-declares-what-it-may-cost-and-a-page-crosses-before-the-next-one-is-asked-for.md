# ADR-0041: A query declares what it may cost, and a page crosses before the next one is asked for

- Status: accepted
- Date: 2026-09-06
- Spec refs: §5.3, §11.2, §12.4, §17.6, §18.1, §18.2, §18.3, §18.4, §18.5, §19.7, §20.2, §20.3, §34.2, §48.6, §49.1, §49.2, §49.3, §49.4, §49.5, §50.1, §50.2, §50.6, §62.12
- Decided by: agent (autonomous)

## Context

Five `SHOULD`s of the read path were unmet, and three of them had the same cause: a module that
was written, tested and had no importer.

**`budget.rs` had no caller.** Eight hundred and seventy-one lines and twenty tests modelling
exactly what §49 and §50 ask for — the six quantities §20.4 of the generic contract names,
`Budget::interactive` with conservative defaults, `Ledger` counting them, `Overrun::record` writing
a stop into coverage, `Throttle::of` reading the API Priority and Fairness headers off a `429`,
`RetryPolicy` gated on an `Idempotent` that only three read verbs can construct, `Jitter` derived
from the provider instance, and `Decision::{Wait, Stop}` with cancellation checked first. Nothing
in `ono-kubernetes-plugin` imported any of it. The normative sentences it was built for read:

- §49.1: "Ono is an interactive shell, not a load generator. The provider MUST bound concurrency
  and SHOULD use efficient list/watch patterns."
- §49.2: "Rate-limited responses MUST be represented as rate limiting, not generic network
  failure. `Retry-After` or equivalent upstream retry guidance SHOULD be honored."
- §49.3: "Safe idempotent reads MAY be retried with bounded exponential backoff and jitter.
  Mutation retries MUST consider Kubernetes idempotency and preconditions. A timed-out mutation
  whose server outcome is unknown MUST NOT be blindly replayed if replay can duplicate side
  effects."
- §49.5: "The provider SHOULD expose configurable query concurrency/QPS/burst policy with
  conservative defaults aligned with interactive use."
- §17.6: "Before an expensive all-namespace/all-resource query, the provider SHOULD estimate or
  expose query breadth when possible."
- §50.1: "Connecting a large cluster MUST NOT freeze parser, prompt or unrelated local shell
  operations. All remote work MUST be asynchronous/cancellable according to Ono host semantics."

The `429` was classified correctly and waited on never. The breadth of an all-group search was
neither estimated nor exposed. No bound of any kind was configurable, and none was applied.

**`Coverage::may_have_more` reached no record.** §18.4 says a user-provided limit "is not provider
incompleteness if the pipeline intentionally stops consumption", and then: "The value stream SHOULD
still know that more upstream results may exist." `transport.rs` set the flag correctly on a page
budget and `may_have_more()` had no caller in the plugin, so `--max_pages 1` against a ten-page
collection completed with a page of Pods and said nothing. `docs/STATE.md` recorded the reason —
the value stream had nowhere to carry it, which is the protocol constraint ADR-0004 records for
coverage.

**`Client::list` buffered every page.** §18.5: "The provider SHOULD stream pages into the Ono
pipeline rather than buffering entire large clusters unless an operation explicitly requires a
complete set." Generic §12.4 says the same. The list loop accumulated every page into one `Vec` and
`query.rs` emitted after the walk was over; `Client::list_page` existed for a streaming caller and
had none. The watch and the log already streamed, and `broker::Lease` was already the mechanism
(ADR-0023) — the listing simply had not been moved onto it.

**Aggregated discovery was never negotiated.** §11.2: "The provider SHOULD use the stable
aggregated Discovery API when available because it provides an efficient cluster-wide resource
summary. It MUST have a compatible fallback for supported clusters where a required discovery form
is unavailable." Also §5.3: "Optional upstream capabilities such as streaming lists MUST be
negotiated or detected and MUST have a safe fallback." No `apidiscovery.k8s.io` negotiation existed
anywhere and `session::Capability::AggregatedDiscovery` was an unused enum variant. The fallback
was the only path, so the risk was nil and the win was one round trip instead of one per group.

**`Session::release_watch` had no caller.** §19.7: "Leaving a place or closing a live view SHOULD
release watches that no longer serve another active consumer." `changes.rs` registered a watch and
never released one. What leaked was a checkpoint and a cache entry rather than a connection.

## Decision

### 1. A listing is a walk with a reader, and the reader is the thing that holds objects

`Client::list` is re-expressed on top of a new `Client::walk`, which takes a `Reader`:

```rust
pub trait Reader {
    fn page(&mut self, page: Page) -> Walk;
    fn failed(&mut self, error: &ApiError) -> Walk { Walk::Stop }
}
```

The walk keeps what belongs to the *sequence* — the snapshot `resourceVersion` (§18.2), the
coverage (§18.3), the continuity break, the page budget (§18.4) — and holds no objects at all. The
`Listing` it returns comes back with an empty `objects`, because the reader has them.
`Client::list` is that trait implemented by a collector, so the buffering form still exists for the
callers §18.5 exempts: the listing that seeds a watched cache (§19.1), and a relationship
derivation that must evaluate a selector across a whole collection (§23.3).

`query.rs` implements `Reader` as `Streamed`, which holds the `Lease` and emits each page's records
before the walk asks for the next page. Nothing about `ByteStream` or the broker had to change:
ADR-0023 already made the invocation context something a connection borrows per call rather than
holds, and this is the second thing built on it.

`Reader::failed` is the seam §49.3 needs. A `Walk::Continue` re-sends **the same request** — the
same continue token into the same snapshot, which is the only repetition §18.2 permits without a
continuity break. The walk never restarts a sequence and never invents a delay.

### 2. What a partial listing means once a record has crossed

It means what §18.3 already said, with the choice about *when* removed.

ADR-0004 recorded the rule for a buffered answer: the values that are true are emitted, and the
*invocation* then fails with what was missing, because a contributed target's value stream carries
records of one schema and has nowhere to put a coverage report. It was a decision then — the
provider held the whole collection and could have withheld all of it.

Streaming removes that option. Page one is in the consumer's hands when page two is refused, and a
record cannot be unsent. So:

- **every record that crossed stays true and stays delivered.** It was read, it was redacted, it
  was stamped with its own freshness; nothing about page two makes page one false;
- **the invocation ends `Failed`**, naming the scope, the outcome in §21.4's vocabulary and — where
  a budget rather than the cluster stopped it — the bound. A short list that ends `Completed` is
  the one failure §18.3's "a default table MUST NOT look identical to a complete result" is about;
- **`Outcome::Completed` after records have crossed means the walk finished or a *user limit*
  stopped it.** §18.4's case, and only that one.

This is stricter than it was, not weaker: the failure is now the only place the incompleteness can
live, so it names the hole rather than saying "partial".

### 3. §18.4 rides on provenance, not on a schema field

A record of a listing stopped by `max_pages` carries `upstream=more-available` in its
`Provenance::source`, beside the `provider_instance`, `origin`, `scope`, `endpoint` and
`resource_version` that already live there. It is written **only when true**: a record that said
`upstream=consumed` would be asserting that the collection is exhausted, which a stream still
mid-walk does not know, and §18.4 asks only for the positive claim that more *may* exist.

Provenance rather than a field, for the reason `records.rs` already gives about origin and
freshness: **the record's fields are about the Kubernetes object**, and "there is more of this
collection upstream" is not a property of a Pod. The alternative was a field on the shared metadata
projection, which twenty-one schemas share — a relationship edge, an Event, a condition and a log
line would all have had to answer a question about a pagination none of them did.

The moment it is decided is inside `Reader::page`, and that is the only moment available: the page
carries the server's own `continue` token and the query carries its own `max_pages`, so the stream
knows *there and then* whether it is about to stop with results still upstream. Nothing later can
say it, because the records are about to cross.

### 4. §49.5's operator surface is three bounds, and it is a declared option

Three new options join `max_pages` on every target that lists anything:

```
max_requests   how many requests this query may send            (default 64)
max_scopes     how many namespaces / group-versions it may reach (default 32)
budget_ms      how long it may take                              (default 10000)
```

They are declared parameters — the established shape here (ADR-0028) — of type `int`, which is a
type the registry accepts. They start from `Budget::interactive()`, so **all six** of §20.4's
quantities are bounded for a query that names none of them: a default that leaves one dimension
open is an unbounded default, and the default is what every unconfigured query runs under.

Three of six are exposed, and the other three are decided rather than forgotten:

- **`max_pages` was already there and means something different.** §18.4 makes a page budget a
  *decision to stop consuming*, which is not incompleteness: the answer completes and the records
  say more exists upstream. Passing one of the three new bounds is the *provider* stopping short,
  which is a coverage gap recorded as `not queried`. Two words for two different events.
- **Concurrency is not exposed**, because it is structurally one. This package holds one brokered
  connection and sends one request at a time; a knob that cannot change what the API server sees at
  an instant would be a decoration, and §5.3's discipline about not claiming a capability applies to
  a provider's own surface as much as to an API server's. The bound is still counted, so the day a
  second connection exists the ledger already refuses.
- **The transferred-byte bound is not exposed**, because it is a safety property rather than a
  preference. §50.1 says connecting a large cluster must not freeze the shell; an operator who
  raised the byte bound to get an answer would have moved that risk onto the shell instead of
  narrowing the question. `max_pages` narrows it honestly and says so in coverage.

The ledger lives on the `Client` and is `Budget::unlimited()` until `Client::spend` is called, which
`query::read` does and nothing else does. **A bound belongs to a question, not to a connection**:
the same connection carries a watch, and a ten-second elapsed bound would end a healthy watch for
being healthy (§49.4 gives a watch its own bounded reconnect loop, which is a different rule).

### 5. §17.6 is asked before the fan-out, not discovered inside it

`search()` resolves the group-versions it has to cover, builds an `Estimate` of one request and one
scope per group-version, and asks `Budget::admits` before it sends anything. A refusal names the
breadth (`"12 requests across 12 scopes"`) and the bound it passed, and tells the operator the two
ways out: name a `group`, or raise `max_scopes`. Refusing halfway hands back a partial answer nobody
asked for; refusing up front with the breadth stated is the "estimate or expose" §17.6 asks for.

During the fan-out each group-version is entered as a `Scope` of its own (§9.3), which is what makes
breadth a counted quantity rather than a metaphor.

### 6. §49.2's wait is done by the caller, and it is cancellable

`budget.rs` owns no thread and starts nothing — its module documentation says so, and the reason is
that a library which decides when to sleep has taken a decision that was not its own. So
`RetryPolicy::plan` returns a `Duration` and `query.rs` waits. `RetryPolicy` is built from
`Idempotent::list()`, and `Idempotent` has three constructors named after the three read verbs and
no other way in: §49.3's `MUST` about never blindly replaying a mutation is a compile-time property
of this call site and no fourth constructor was added.

The wait is **sliced**. `nap` sleeps in twenty-five-millisecond steps and checks `Lease::cancelled`
between them, and `plan` checks cancellation before anything else. A retry that finished its backoff
before noticing that the operator had stopped the query would have made the shell unresponsive for
exactly as long as it was being polite to the API server, which is the failure §50.1 and Gate L are
about. The precedent for sleeping at all is `changes.rs`'s reconnect backoff; the floor (100 ms),
ceiling (2 s) and allowance (3) are shorter and smaller than a watch's, because a person is waiting
for this one.

`Retry-After` is a floor rather than a suggestion — `plan` already returns `ours.max(theirs)`. A
client that backed off for less than the API server asked for has decided it knows better than the
API server how loaded the API server is.

### 7. Aggregated discovery is negotiated on the request that was going to happen anyway

`/api` and `/apis` are requested with

```
Accept: application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,
        application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList,
        application/json
```

and the **reply's** `Content-Type` decides which form arrived. That is §5.3's "negotiated or
detected": a server that ignores the header answers `200` with the legacy document, so the request
proves nothing and only the answer does. Plain `application/json` closing the list is what keeps the
fallback a `200` rather than a `406`.

The stable `v2` is first because §11.2 asks for the *stable* aggregated API. `Discovery::aggregated`
reads everything §11.1 requires out of the one document — groups, versions, resources, scope, verbs,
kind identity from `responseKind` (§13.1) and subresources — so `search()` and `curated()` make no
per-group request at all where it answered. It is an error rather than an empty snapshot when the
document does not read: a permissive parse over an `APIGroupList` yields no items and therefore a
cluster that serves nothing, which is §4 invariant 13's collapse reached through content
negotiation.

`freshness: "Stale"` is kept rather than flattened. The aggregation layer marks a group-version whose
own API server did not answer, usually with an empty resource list beside it, and that is §34.2's
failure with the server's own word on it — recorded as the same `unavailable` coverage gap a `503`
on the group's resource list produces, one round trip earlier.

The two forms are cached under different keys (`/apis` and `/apis#aggregated`), because they are
different documents and a cache that let one answer for the other would hand an
`APIGroupDiscoveryList` to the legacy reader.

### 8. §19.7's "another active consumer" is the session's own cache

`Session::close_view` releases a watch when — and only when — the stream can no longer answer a read.
`changes.rs` calls it on every way out of the watch loop.

The qualifier is the whole rule. This provider has exactly one other consumer of a watch and it is
not a second stream: it is `Session::lookup`. §20.2 makes `origin=cache` a first-class answer a later
invocation may be given, and §20.3 lets a synchronised stream report an absence *as* an absence. A
stream that can still do either is serving a consumer; one past a `410`, or denied, is holding a
checkpoint the API server has already discarded and a set of objects nothing is keeping true.

So `close_view` asks exactly the question `lookup` asks (`WatchStream::absence_is_conclusive`), and
it asks it in `session.rs` rather than in the caller so the two cannot drift. Releasing every watch
on close would make §20.2's cache origin unreachable in practice; releasing none is
`release_watch` never being called, which is what this ADR is fixing.

## Consequences

- **A listing is bounded in memory and in cost.** Ten thousand Pods cross a page at a time and the
  process holds one page; the credit `Ctx::emit` blocks on is the backpressure, so the queue ends up
  on the API server's connection where TCP already knows what to do with it (§18.5, §50.1).
- **A short answer can no longer read as a whole one, in four different ways.** A denied page fails
  the invocation with the scope named; a budget stop fails it with the bound named; a page budget
  completes and marks the records; a stale aggregated group is a coverage gap. §18.3, §49.1, §18.4
  and §34.2 each keep their own word.
- **`Answer::Listed` is constructed nowhere and stays.** It is the arm six handlers write to say
  that a direct read answering with a collection is a defect; deleting the variant deletes that
  check from all six. It carries an `#[expect(dead_code)]` saying so.
- **A first query against a cluster that aggregates discovery costs two round trips instead of
  `2 + n`.** A cluster that does not is unchanged, and every existing test in `tests/query.rs` runs
  against a recorded server that ignores the negotiation — so the fallback is exercised by a hundred
  tests rather than by one.
- **The narrow invalidation of §12.4 and §33.2 is driven by the legacy documents.** A changed
  aggregated document drops the assembled snapshot wholesale rather than expiring one group's
  schemas. That is the conservative direction — more re-derivation, never a stale answer — and it is
  worth revisiting if aggregated discovery becomes the common path.
- **A watch that ends healthy still answers later reads from its cache; one that ends past a gap
  does not exist any more.** The integration test that reads a watched object from the session cache
  proves the first half at the boundary; the session test proves both halves directly.
- **The elapsed bound is on the wall clock even where a test fixes `Client`'s clock.** §50.1 is about
  how long a person waits, and a test that fixes time to make freshness assertable is not asking for
  a query that may run forever. Provider-crate clients start unbounded, so nothing there is affected.

## Alternatives considered

**A field on the object records for §18.4.** Rejected: the shared metadata projection is used by
twenty-one schemas, so a `more_available` field would appear on a relationship edge, an Event, a
condition and a log line — none of which paginated anything — and each would have to answer it with
something. Provenance is where this codebase already puts facts about the *observation* rather than
about the object, and it says so in `records.rs` in as many words.

**A trailing record.** Rejected: a record of the target's schema with every field null is a
fabricated object, and §4's "unknown data is null, never fabricated" is about exactly that shape.
`k8s-change` can carry a `notice` because its schema is *about* an observation; an object schema is
not.

**Failing the invocation when a page budget stops it.** Rejected by §18.4 in as many words: a
user-provided limit "is not provider incompleteness if the pipeline intentionally stops
consumption". Failing on `first 20` would cry wolf on the ordinary case and teach an operator to
ignore the one that matters.

**Withholding a streamed listing until it is known to be whole.** Rejected: it is the buffering
§18.5 asks the provider not to do, and it would make the first record of a large collection wait for
the last. ADR-0004's rule — values first, then the invocation says what was missing — already
covers the case and needs no exception.

**Enforcing the budget inside `HttpConnection::send`.** Rejected: it would need a new `ApiError`
variant, which would ripple through the §48.2 taxonomy and make "the query ran out of budget" look
like a class of transport failure. The `Client` is the right level: `Overrun::kind` is
`partial_result` precisely because nothing failed.

**Exposing all six bounds as options.** Rejected for concurrency and bytes, with the reasons under
Decision 4. A configurable knob that cannot change anything is worse than an absent one, because it
makes a reader believe something about the implementation that is not true.

**A second discovery endpoint instead of content negotiation.** Rejected because there is not one:
aggregated discovery is served at `/api` and `/apis`, and the form is chosen by `Accept`. Probing a
different path would have been an invented protocol with an extra round trip.

**Releasing every watch when a live view closes.** Rejected: it makes §20.2's cache origin
unreachable in practice, and §19.7 explicitly qualifies its rule with "no longer serve another
active consumer". A cache a later read may be answered from is such a consumer.

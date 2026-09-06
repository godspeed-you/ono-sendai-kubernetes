# ADR-0044: A performance requirement is a number a test can count, and the costs nothing bounds are written down

- Status: accepted
- Date: 2026-09-06
- Spec refs: §17.6, §18.1, §18.3, §18.4, §18.5, §19.3, §19.6, §19.7, §20.1, §20.3, §41.4, §48.2,
  §49.1, §49.5, §50.1, §50.2, §50.3, §50.5, §59.1, §62.12; and §30.1 to §30.5 of the generic
  provider contract in core
- Decided by: agent (autonomous)

## Context

Everything in this repository's suite proved *behaviour*. §50 is about **cost**, and a provider
that is correct and unusable against a real cluster has failed a requirement rather than a
preference. Nothing measured any of it, and the gap was not evenly distributed: the small-case
tests that exist — two Pods, two pages, two watch events — cannot distinguish a per-query round
trip from a per-object one, cannot tell a bounded cache from an unbounded one, and cannot tell a
cancellation observed between reads from one observed when a deadline expires. All three are the
same at n=2 and none of them is at n=100 000.

The specification's performance section is unusually testable if it is read as arithmetic rather
than as advice:

> **§50.2** "Discovery and OpenAPI loading SHOULD be cached and incrementally refreshed rather
> than downloaded before every query."
>
> **§18.5** "The provider SHOULD stream pages into the Ono pipeline rather than buffering entire
> large clusters unless an operation explicitly requires a complete set."
>
> **§62.12 (Gate L)** "Large list, watch, log-follow and verification operations terminate
> promptly under Ono cancellation semantics."
>
> **§30.4 (core)** "Enumeration and watch implementations MUST avoid retaining entire remote
> inventories when streaming semantics suffice."
>
> **§30.5 (core)** "Providers MAY maintain indexes for relationship traversal, but index size and
> invalidation MUST be bounded and observable."

Each of those is a *count*: requests on the wire, objects held at once, pages walked, milliseconds
between a cancellation and a termination. Counts can be regression-tested honestly. Wall-clock
throughput on whatever machine CI gave us cannot.

## Decision

### 1. Two suites, and the split follows what each one can see

`crates/ono-provider-kubernetes/tests/performance.rs` (12 tests, ~4.5 s) measures what the
*provider* retains, in process, over a `FixtureStream`. `crates/ono-kubernetes-plugin/tests/
performance.rs` (7 tests, ~60 s) measures what the *package* costs against a recorded API server
reached through the real test host: requests that actually travelled, and cancellations that are a
host concept with no meaning below the broker.

Neither can replace the other. A request count asserted inside the provider crate cannot see the
discovery the plugin does before it; a retention measured through the plugin cannot see anything,
because the objects are on the far side of a process boundary by the time a test can look.

### 2. Fixtures are generated, never checked in

A hundred thousand recorded Pods is twenty-five megabytes nobody reads and a diff nobody reviews.
Both files build their collections from a function of an index, so a fixture's *size* is an
argument (§59.1's determinism is unaffected: the same index produces the same bytes every run).

### 3. What is a contract, and what is an observation

A **contract** is asserted as an exact number and a change to it is a decision somebody has to
make on purpose. An **observation** is printed and asserted only against a ceiling loose enough
that only a change of asymptotic behaviour can reach it. Saying which is which in the test, and
here, is the point: a suite where every number is an assertion becomes a suite people delete.

**Contracts.**

| What | Number | Where | Which sentence |
|---|---|---|---|
| Requests for a 200-page, 100 000-object listing | **200** — one per page, none per object | provider | §18.1, §49.1 |
| Objects held at once while streaming that listing | **500** — one page; the walk retains **0** | provider | §18.5, §30.4 (core) |
| Requests when a reader stops on page one | **1** | provider | §18.4, §50.1 |
| Pages read under `max_pages 10` of 200 | **10** pages, **10** requests, **5 000** objects, coverage says more exists | provider | §18.4 |
| Pages read by an unconfigured interactive query of a 200-page collection | **16** — `Budget::interactive`'s bound — and the refusal names the bound rather than the cluster | both | §49.5, §48.2 |
| Discovery requests for two queries over 800 objects | **(1, 1, 1)** for `/api`, `/apis`, `/api/v1`; **11** requests in total | plugin | §50.2, §6.3 |
| Schema entries after reading one group-version's schema twice | **1** | provider | §12.4, §50.3 |
| Watch events applied out of 10 000, and events discarded | **10 000** and **0**; cache holds **500**, the collection's size, not the event count | provider | §19.3, §19.6 |
| Live-view rows over a 10 000-object stream at capacity 2 000 | **2 000** rows, **8 000** withheld, and the view is not `current` | provider | §18.5, §41.4 |
| `withheld` on the first record of a 2 100-object watched collection | **100** | plugin | §18.5, §41.4 |
| Objects that stand when page 51 of 200 is refused | **25 000**, coverage partial, error attached | provider | §18.3 |
| Cancellation of a listing while the server is answering | **Cancelled**, under 5 s (measured **1.1 ms**) | plugin | §62.12 |
| Cancellation of a live watch | **Cancelled**, under 5 s (measured **495 ms**) | plugin | §62.12 |
| Cancellation of a followed log | **Cancelled**, under 5 s (measured **253 ms**) | plugin | §62.12 |

**Observations** — printed by `cargo test … -- --nocapture`, asserted only against a ceiling:

| What | Measured |
|---|---|
| Bytes transferred for 100 000 Pods in 200 pages | 49 825 847 |
| Native JSON retained per ordinary Pod | **528 bytes** |
| A buffered 50 000-object listing | 26 400 000 bytes retained — just inside `Budget::interactive`'s 32 MiB transfer bound, and outside it at 60 000 objects |
| A 20 MB ConfigMap, streamed | 20 971 748 bytes transferred, **0** retained by the walk |
| The same object, buffered | 20 971 693 bytes retained |
| A 2 640 072-byte OpenAPI v3 document | parsed in 36 ms, held as one cache entry |
| A synchronised informer cache of 20 000 Pods | 20 000 objects, ~10 560 000 bytes |
| 10 000 watch events over 2 250 000 bytes | applied in 233 ms; change log grows to **10 000 entries** |
| One `LiveView::refresh` over 10 000 objects | 14.4 ms; the 8 000 withheld identities cost ~368 000 bytes of names alone |
| Cancelling a listing blocked on a server that has gone silent | **59.99 s** |

### 4. Wall-clock is asserted only for cancellation, and only in seconds

Three of the numbers above are latencies, and all three are cancellations. Their ceiling is five
seconds: loose enough that a loaded CI machine cannot reach it, tight enough to catch the only
regression that matters, which is a cancellation noticed at a read deadline rather than between
reads. Everything else that is timed is printed and bounded at ten or thirty seconds, which is a
guard against an accidental quadratic and nothing more.

### 5. Tests rather than benchmarks

No `[[bench]]` section and no `criterion` dev-dependency. `cargo bench` does not run in the gate,
so a benchmark is a number nobody sees regress; and every quantity worth guarding here turned out
to be a count rather than a duration, which a `#[test]` asserts better than a harness that reports
a distribution. The one place a bench harness would earn its keep — `LiveView::refresh` — is
recorded as an observation instead, because the finding about it is structural rather than
statistical.

## Consequences

- §50's requirements have numbers behind them for the first time, and the numbers are in this
  document so the next reader has a baseline to disagree with.
- **Four findings were left in place, documented with `// FINDING:` comments and not fixed**, per
  the working agreement that `src/` belongs to other workers this session:
  1. **A cancelled listing blocked on a silent server takes ~60 s** — two windows of
     `broker::REQUEST_DEADLINE_SECONDS`. `ReadPolicy::request` asks one constant to be both a
     liveness deadline and a cancellation window; `ReadPolicy::watch` already has the right shape
     at 0.25 s, which is why the watch and the followed log terminate in under half a second and
     the operation Gate L names *first* does not. In `broker.rs`.
  2. **`Client::walk` never notices a `continue` token it has already sent.** A server that
     repeats one token describes a collection §18.1's "until all required pages have been
     consumed" never finishes consuming. Today the only thing that stops it is the page bound —
     which is `Budget::interactive`'s default and therefore rises whenever an operator legitimately
     raises it for a large collection. `Continuity::Broken(BreakReason::SnapshotChanged)` is the
     existing shape for the neighbouring malformed-pagination case. In `transport.rs`.
  3. **A `WatchStream`'s change log is unbounded**: one `ObservedChange` per event, never trimmed,
     for the life of the session. §19.4's segment model needs the segment *boundaries*, not every
     change inside them, and core's §30.4 reads on this as much as on a listing. A bound with a
     reported `withheld`, the way `LiveView` bounds its rows, would keep §19.4 intact. In
     `watch.rs`.
  4. **`LiveView::refresh` is O(objects) and clones up to `capacity` objects, and `changes.rs`
     calls it once per emitted record.** A watched collection of ten thousand objects pays ten
     thousand object clones per change event. Nothing here is wrong per §41; §50.1's "MUST NOT
     freeze" is the requirement it strains. In `live.rs` and `changes.rs`.
- A fifth thing is worth knowing and is not a defect: **`VIEW_CAPACITY` is not the memory bound it
  reads as.** It bounds what a reader is shown. What the session holds is the whole watched
  collection, and the only thing between a shell and a hundred-thousand-Pod namespace is that
  `Budget::interactive` refuses the listing that would seed it — a bound on the transfer rather
  than on the cache.
- **Suite runtime: ~64 s** — 4.5 s for the provider suite, 60 s for the plugin suite, of which
  59.99 s is the single test that documents finding (1). The other six plugin tests finish in
  under a second between them. That one test is the most expensive thing this work adds to a
  seven-minute gate, and it becomes fast the moment finding (1) is fixed: its ceiling is a
  regression guard against "never terminates", not a floor that locks the latency in.
- The recorded server in the plugin suite is a second, much smaller one beside `query.rs`'s. That
  is duplication, and it is deliberate: `query.rs`'s server is 2 000 lines of layered fixtures
  whose sizes are fixed, and a performance suite needs a server whose collection size is an
  argument. Sharing one would mean editing a test file this session does not own.

## Alternatives considered

**Assert throughput — objects per second, milliseconds per page.** Rejected. It is the number
people ask for and the one that cannot be defended: a shared CI runner varies by more than any
regression worth catching, so the assertion is either so loose it proves nothing or so tight it
flakes, and a flaking performance test is deleted within a month. Counts do not have that problem.

**Sample process RSS to measure memory.** Rejected under the same reasoning and one more: RSS
depends on the allocator, on what else the test binary is doing and on when the OS felt like
returning pages. Counting retained objects and re-serialising their own `native()` JSON through
the types' accessors is deterministic, attributable to a specific structure, and can name *which*
cache is unbounded — which RSS never can.

**A `[[bench]]` target with `criterion`.** Rejected: `cargo bench` does not run in the gate, so a
regression in it is invisible until somebody goes looking. A benchmark nobody runs is worth less
here than a test that asserts a bound.

**Fix the four findings while measuring them.** Rejected on process rather than on merit: three of
the four are in files other workers hold this session, and a performance fix landed on top of
somebody else's in-flight change is how a measurement becomes a merge conflict. They are written
down, each with the shape of its fix, and left to the user to schedule.

**Drive the plugin suite through `query.rs`'s recorded cluster.** Rejected: it would mean editing a
test file this session does not own, and its fixtures are fixed at two Pods and two pages by
design — every other test in that file depends on them not changing.

**Skip the sixty-second cancellation test and report the finding in prose.** Considered seriously,
because sixty seconds is a sixth of the gate. Rejected: a finding without a test is a sentence in a
document, and this one is a Gate L requirement that is currently not met. The test asserts only
that the invocation terminates at all, so it keeps passing — faster — once the latency is fixed.

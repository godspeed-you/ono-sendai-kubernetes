# ADR-0026: Two invocations answer at once, and a session is locked by the one that claimed it

- Status: accepted
- Date: 2026-09-06
- Spec refs: §6.2, §6.3, §6.5, §8.1, §10.4, §19.6, §49.1, §49.5, §50.2, §61.1, §62.10;
  `ADR-0586 (core)`, ADR-0021, ADR-0022, ADR-0023
- Decided by: agent (autonomous)

## Context

K0 met all six of §61.1's requirements and could not be claimed, because §0.1 binds a level to its
gate and Gate J (§62.10) asks for two kubeconfig contexts to be queried **concurrently**. The word
was unreachable rather than unmet: a KUANG/11 package answered one invocation at a time, and a
second `provider.query` opened before the first was drained quarantined the instance with
`runtime.protocol_violation`. `tests/isolation.rs` therefore proved the strongest thing the
protocol allowed — two contexts, sequentially, in one session, with no crossover — and said so in
its own header.

`ADR-0586 (core)` removed the constraint. A package may now have several invocations open at once,
one worker each, under a ceiling declared in code by the author (`Plugin::concurrent_invocations`)
and in the manifest by the operator (`runtime.max_concurrent_invocations`), with the smaller of the
two winning and a refusal rather than a quarantine beyond it. That ADR names this provider's Gate J
as one of the two pieces of work that found the bug.

Three things stood between that and a proof here, and all three were local:

1. **The pinned SDK predated the change.** `Cargo.lock` pinned `ono-kuang-sdk` at core `879d390`,
   where `concurrent_invocations` does not exist.
2. **`sessions::Sessions` was an `Rc<RefCell<BTreeMap<Key, Session>>>`.** ADR-0021 chose `Rc` and
   `RefCell` deliberately — "the SDK serves one invocation at a time on one thread, and a lock
   would suggest a concurrency this protocol does not have" — and the new handler bound is
   `Fn(&mut Ctx) -> Outcome + Send + Sync + 'static`. The reason had expired and the type had not.
3. **No ceiling was declared anywhere**, so even a thread-safe package would have answered one
   invocation at a time and refused the second.

Under all of it sits the question the exercise is actually about. A shared store reached by two
threads is the shape §6.5 forbids — no shared identity, cache, watch checkpoint, credential or
namespace between two provider instances — and "we hold a lock" is an answer to a different
question. What has to be true is that two invocations running at the same time cannot see each
other's cache **and** that they genuinely run at the same time.

## Decision

### 1. The dependency names the revision that carries the change, rather than a branch

`Cargo.toml` pins all four core crates at `rev = 6167ba58…`, the commit of `ADR-0586 (core)`. It is
on core's `implementation` branch rather than on `main`, and the two obvious references are both
wrong for this repository: tracking `main` would silently undo this provider's concurrency the next
time the lock file were regenerated, and tracking `implementation` would let a disposable branch
decide what this repository builds against. One revision for all four, because they share
`ono-kuang-protocol` and two revisions of it in one tree are two incompatible copies of every type
that crosses the boundary.

What the bump moved, in this package: `run_io` takes `impl Read + Send` and `impl Write + Send`, a
handler is `Fn(&mut Ctx) -> Outcome + Send + Sync + 'static`, `Plugin::concurrent_invocations`
exists with a default of one, `runtime.max_concurrent_invocations` is a manifest field, and
`runtime.concurrency_limit` is a refusal an operator can read. Nothing in the domain layer moved:
`ono-provider-kubernetes` has no host and no `Ctx`.

### 2. Two locks, because a session and the registry answer different questions

`Sessions` is a `Mutex<BTreeMap<Key, Arc<Mutex<Option<Session>>>>>`, and the two locks are held for
deliberately different lengths of time:

- the **registry** lock is held for a lookup and an insertion, and released before the invocation
  uses what it found. A registry held for the length of an invocation would make two queries of two
  different clusters take turns, and the concurrency would compile, be declared, and not exist;
- a **session** lock is held for the length of the invocation that claimed it. That is what makes a
  session a coherent thing to read and write: §6.3's discovery documents, schema cache, fingerprint
  and watch registry stay consistent with each other because exactly one invocation is inside them
  at a time.

The isolation argument survives the move intact, because it never rested on there being one thread.
It rests on the key. `Sessions::with` is the only route to a session and it takes a `Key` — the
provider instance of §6.2, the resolved endpoint, and the transport posture — so a thread reaches
exactly the session its own key names. A lock arbitrates *who* uses a session; the key decides
*which* session that is. Two invocations at the same time can no more reach each other's cache than
two invocations one after the other, and ADR-0021's one-directional rule for the key is untouched:
a component may only ever split two invocations, never merge two.

The three things that were never in a session stay out of it: no credential material (§8.1, resolved
per invocation), no answered namespace (§7.5's default is configuration; the scope is resolved per
invocation), and no cluster fingerprint in the key (§10.3).

### 3. Two invocations of one provider instance take turns

The cost of §2 is stated rather than hidden: two invocations that resolve to one key serialise on
that session's lock, including across their round trips. This is the honest shape of the thing. A
session is one cluster reached one way, and interleaving two invocations inside one would produce a
state neither of them asked for — a discovery document cached by one query and read by another that
searched a different group-version, or §10.4's invalidation firing under an invocation that had
already read what it invalidated. Concurrency across *instances* is what §62.10 asks for and what a
provider fronting several clusters wants; concurrency *within* one instance is a queue of one
cluster's own work.

Two consequences follow, and both are visible in the tests: a query and a watch of the same context
do not overlap, and `tests/isolation.rs` reads the two cluster diagnostics one at a time because
two diagnostics of one instance would be two invocations of one session.

### 4. A poisoned session is discarded rather than recovered

A handler that panics is unwound by the SDK's `catch_unwind` and fails its own invocation
(`ADR-0586 (core)` §6). Whatever it half-wrote into a session is state with no evidence behind it,
so the next invocation to reach that key clears the poison, drops the session and seeds a new one:
discovery is paid for again, and nothing is answered from a cache that cannot be shown to still be
true. §10.4's discipline applied to a failure rather than to a fingerprint. The registry itself is
recovered rather than discarded, because it is a map of handles and refusing every later invocation
over one dead thread is the failure mode that ADR exists to prevent.

### 5. The ceiling is three, and it is declared twice because two people know two things

`CONCURRENT_INVOCATIONS` in `lib.rs` and `runtime.max_concurrent_invocations` in
`package/manifest.yaml` are both **3**, and they are two statements rather than one repeated:

- the **code's** number says the handlers are safe to run beside each other and how many of them
  this package is prepared to spawn. No manifest can assert that on the author's behalf, which is
  why an operator cannot raise it;
- the **manifest's** number is the operator's budget for one instance, capped by host policy — the
  host's own default is four, so declaring three is this package asking for less than it is
  offered.

Three is what this package's shapes of work need at once, rather than a round number. One slot is a
live watch: §19's `k8s-change` borrows its invocation for as long as the operator keeps watching
(ADR-0023), so it holds a slot for minutes rather than for a round trip. Two more are the two
contexts of §62.10, which is the case the specification asks to be possible while something else is
going on. A fourth slot would buy a second simultaneous watch and cost a fourth worker, a fourth
brokered connection and a fourth TLS session inside one instance's 256 MiB — and §49.1 requires this
provider to bound its concurrency, because Ono is an interactive shell rather than a load generator.
A bound that stops at the work it can name is a bound.

Both numbers are load-bearing and were checked by lowering each to one and watching Gate J's test
fail with the second invocation refused.

### 6. The overlap is held by the credit window, and a recorded server may not hold it

`should_answer_two_contexts_queried_at_the_same_time_without_crossover` runs under a credit window
of one value against clusters holding three Pods each. A handler that has emitted one record and
still owes two is stopped inside `emit` until the host grants demand, and demand is granted by
consumption — which the test controls. So alpha is held open *before* beta is asked anything, and
beta's entire conversation with its own API server happens inside alpha's invocation. The
transcript both recorded servers write to holds the line-by-line evidence, and every original
assertion of the sequential proof is still made against the decrypted wire: each server saw only its
own token on *every* request head, each was asked only about its own namespace, no object of one
appears anywhere in the other's answer, each record carries its own provider instance, and each
context answers the same afterwards.

**A recorded server that withheld its answer until both clusters had been asked was tried first and
is wrong here.** The supervisor fills a brokered read inside its own actor loop
(`host_streams_next` → `InboundStream::fill`), so a read nobody answers stalls every other
invocation's host calls with it: the package's two invocations were genuinely open and the host
could not serve the second one's `network.connect` until the first one's read returned. The credit
window holds an invocation open *without* holding a host call open, which is exactly the property
`ADR-0586 (core)` §1 was written to give. The finding about the host belongs to core and is
reported rather than worked around here (AGENTS.md §4).

## Consequences

- **Gate J is proven as worded.** Two contexts are answered concurrently by one loaded instance,
  with the overlap held by a mechanism the scheduler cannot fake, and the five prohibitions of §6.5
  are checked against the decrypted transcript of two real TLS sessions. With the ceiling lowered to
  one, the test fails immediately with the second invocation refused rather than hanging.
- **K0's six requirements now stand behind a proven gate.** Claiming the level is a separate
  decision for the board and for `docs/coverage.md`, which this ADR does not make.
- **A watch no longer blocks the package.** Before this, `k8s-change` occupied the only invocation
  there was for as long as it watched. It now occupies one of three, and a query of another cluster
  answers beside it.
- **Two invocations of one instance serialise**, including a query behind a watch of the same
  context. §3 states why this is the intended shape rather than a defect; if a future increment
  needs a watch and a query of one context at once, it needs a session that can lend out parts of
  itself, and that is a design, not a lock.
- **`Sessions::len` counts a key from the moment an invocation claims it**, whether or not that
  invocation has finished seeding its session. Nothing reads it but a caller asking how many
  instances this process holds state for.
- **A panicked invocation costs its instance its cached discovery** and nothing else. The next
  query re-reads `/api`, `/apis` and the resource list, which is §50.2's cost paid once more rather
  than an answer nobody can vouch for.
- **Invocations overlap; their host calls still take turns.** The supervisor fills a brokered read
  inside its own actor loop, so while one invocation is parked in a read of its API server the
  others wait for the host rather than for each other. `broker.rs` already keeps a watch's read
  window at a quarter of a second, and that constant now buys a second thing besides §62.12's
  prompt cancellation: it is the longest another invocation can be kept waiting by a watch. The
  overlap this ADR proves is therefore real and its throughput is the host's to widen — a finding
  for core, not a thing to work around here (AGENTS.md §4).
- **The dependency reference is now a commit rather than a branch**, so this repository stops
  tracking core's `main` and starts moving when somebody moves it deliberately. It moves back to a
  branch when the change is on one.
- **§49.5's configurable concurrency/QPS policy is still unimplemented.** What exists is a bound the
  operator can lower in the manifest, which §49.1 requires; a policy surface an operator can tune
  per query is not built and is not claimed.

## Alternatives considered

**One lock over the whole registry, held for the length of an invocation.** The smallest change from
`RefCell`: swap it for a `Mutex` and keep `with` as it was. Rejected because it produces exactly the
failure this exercise is about — two contexts declared concurrent, dispatched on two workers, and
serialised on a lock one of them holds across every round trip. Gate J's test would have deadlocked
against its own rendezvous or passed while proving nothing.

**A lock-free registry: one `OnceLock` per key, or an immutable map swapped under an atomic.**
Rejected as machinery bought for contention that does not exist. The registry is touched twice per
invocation, and invocations are coarse.

**`RwLock` on the registry.** Would let two lookups proceed together. Rejected for the same reason:
the write path is an insertion that happens once per instance per process, and a `Mutex` held for a
map lookup is not what any of this is waiting on.

**Keeping `Rc<RefCell<…>>` and declaring a ceiling of one.** It compiles under the new SDK only if
no handler captures the registry, which every handler does. It also leaves Gate J unprovable, which
is the whole point of the work.

**Recovering a poisoned session rather than discarding it.** Cheaper, and it keeps the discovery a
panicking invocation had already paid for. Rejected: a cache whose last writer died mid-write is
precisely the state §10.4 forbids presenting as current, and re-reading three discovery documents is
a smaller cost than an answer nobody can account for.

**Declaring the ceiling only in code, or only in the manifest.** Rejected in `ADR-0586 (core)` for
both directions, and the reasons hold here: a manifest that could raise the number would let an
operator assert thread-safety about somebody else's code, and a code declaration alone would take a
resource the operator never agreed to.

**Four, the host's default.** It is the number the host hands out when nobody says anything, so
declaring it says nothing. Three is the number of things this package can be doing at once and name.

**Proving the overlap with `tokio::join!` over two `collect()` calls.** What the conformance suite's
shape suggests at a glance. Rejected because it asks the scheduler nicely: the first invocation may
well complete before the second is dispatched, and the test would then pass for a package that
answers one invocation at a time — which is the exact defect Gate J exists to catch.

**Proving it with a recorded server that answers only once both clusters have asked.** The strongest
statement available on paper, and it deadlocks against the supervisor's actor loop (§6). Kept in the
test file as the reason the credit window is there, so that the next reader does not try it again.

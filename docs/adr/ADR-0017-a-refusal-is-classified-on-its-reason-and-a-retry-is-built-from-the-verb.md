# ADR-0017: A refusal is classified on its reason, and a retry is built from the verb rather than remembered as a rule

- Status: accepted
- Date: 2026-09-06
- Spec refs: §11.5, §17.6, §18.1, §18.3, §18.5, §19.4, §21.4, §48, §49, §50, §56, §59.2; generic
  contract §12.6, §19.1, §19.2, §19.3, §19.4, §20.2, §20.3, §20.4
- Decided by: agent (autonomous)

## Context

Three sections of the specification were untouched or half-built, and they turn out to be one
problem seen from three angles: **what a failure is**, **whether it may be repeated**, and **what
a query is allowed to spend before it stops**.

**§48** asks that upstream errors be mapped into a taxonomy of seventeen classes while the native
detail survives. What existed answered part of it. `ApiError` already kept a denial, an absence, a
`410` and a `429` apart, which is the distinction §21.4 and §4 invariant 13 rest on. But
`unauthenticated`, `conflict`, `invalid` and `service_unavailable` all arrived as one variant
carrying an HTTP code, and `details.group`, `causes` and `retryAfterSeconds` were parsed by nobody.
The gap matters because the API server usually says more than its code does: a `500` carrying
`reason: ServerTimeout` is an invitation to ask again, and the same `500` classified from its code
alone is a generic failure nobody retries. Two opposite pieces of advice out of one response.

**§49** asks that `429` be honoured with its `Retry-After`, that retries be bounded, cancellable
and un-synchronised, and — the sentence with teeth — that a mutation whose server outcome is
unknown never be blindly replayed. There are no mutations in this provider yet. That is exactly
when the shape gets decided, because the first mutation will be written by someone who is thinking
about the mutation.

**§50** reads like a performance section and mostly is not. §50.1 wants the shell not to freeze,
and §20.4 of the generic contract names the six quantities a host budget may bound: requests,
scopes, pages, elapsed time, transferred bytes and concurrent requests. That is a counting
problem, not a speed problem.

Two failure modes run through all three, and neither looks like a failure in review. A budget that
stops a fan-out and returns the values it had **looks exactly like a complete answer**. And a
retry loop around a request that turns out to be a `POST` **looks exactly like a retry loop**.

## Decision

### The taxonomy is a mapping over the native error, not a replacement for it

`transport::ErrorKind` holds §48.2's seventeen classes, and `ApiError::kind(Operation)` maps into
it. `ApiError` keeps its variants and its `Status` unchanged, so nothing that already reads a
denial has to be rewritten, and no caller has to choose between the class and the detail — both
are on the same value.

**The mapping is made on `reason` first and on the HTTP code second.** The reason is the
structured field §48.1 names, and it is the more precise of the two; the code is what remains when
a middlebox answered instead of an API server. §48.3's `404` ambiguity is resolved by the
operation that asked, the same way `outcome()` already resolves it: one object being absent is
`not_found`, a collection endpoint being absent is `api_not_served` (§11.5).

Five of the seventeen classes are never produced by `transport` — `tls_error`, `credential_error`,
`schema_error`, `partial_result`, `cancelled` come from elsewhere in the provider. They are named
in the same enum anyway. A provider whose error words differ by which file produced them has no
taxonomy.

`Status` now also parses `details.group`, `details.retryAfterSeconds` and `causes` (§48.1, §48.5),
and carries four values that arrived in the response head rather than in the body: the `Audit-Id`,
`Retry-After`, and the two API Priority and Fairness UIDs. They ride on the `Status` because the
head and the body are one refusal; splitting them would make "what the server said" a different
shape depending on which `ApiError` variant carried it.

**Which headers are kept is an allow-list of four, and that is the security property.** §19.2 of
the generic contract permits provider-native diagnostics and forbids secrets. Only an allow-list
satisfies both: a filter that strips the headers known to be dangerous keeps the one nobody
thought of, and a `Set-Cookie` surviving into a `Debug` line is a session token in a log file.
This is `ADR-0003`'s rule applied to a second surface — destroyed at the boundary rather than
filtered on the way out.

### Retryability is declared on the error; permission comes from the verb

`ApiError::retryability()` answers `Yes`, `No` or `Unknown`, and `Unknown` is not a synonym for
`Yes` (§19.4). A `504` leaves the server's outcome unknown, and the error says so.

`budget::RetryPolicy` is constructed **from** a `budget::Idempotent`, which is a newtype with a
private field and exactly three constructors: `get()`, `list()`, `watch()`. There is no
`From<&str>`, no `new`, and no public field. A retry of a mutation is therefore not a rule someone
has to remember at four in the afternoon — it is a sentence that does not compile. When mutation
arrives, the way in is a fourth constructor added in that file, named after what makes the replay
safe (a `resourceVersion` precondition, §56.1; a UID precondition, §56.3; server-side apply's
field ownership, §44.1), with a doc comment attached. That is the review the decision deserves.

`Retryability::Unknown` does retry inside a `RetryPolicy`, and the reason is the `Idempotent`
rather than the error: what makes repeating a timed-out `list` safe is that it cannot duplicate
anything. The error never claims more than it knows.

### `watch::Backoff` is reused rather than reimplemented

`RetryPolicy` holds a `watch::Backoff`. That type already solves the doubling and the ceiling, and
it already carries the reason the ceiling is not optional: an unbounded loop either hammers a
struggling API server or, once the multiplication overflows, wraps round to no delay at all. Two
backoffs in one provider would be two chances to get that wrong, and the second one is always the
one nobody re-reads.

What is added around it is what §20.2 of the generic contract asks for and a watch reconnect loop
does not need: a bounded attempt allowance, a cancellation check made **before** anything else, the
server's own `Retry-After` treated as a floor, and a per-client spread.

**The spread is derived from the provider instance name (FNV-1a), not from a random number.** Two
Ono sessions that lost the same API server in the same second and back off by the same arithmetic
return in the same instant, and that second wave is what keeps a recovering server down. Deriving
the offset from `kubernetes:<context>` gives the property that matters — different between
clients — without giving up the one this repository needs, which is that a test asserts the same
number on every run. It only ever shortens a delay; lengthening one would silently exceed a
ceiling that was chosen on purpose.

### A budget counts and refuses; it never truncates

`budget::Budget` bounds all six of §20.4's quantities, `budget::Ledger` counts against them with an
injected `Clock`, and every check happens **before** the spending. A budget that notices afterwards
has already paid for what it was protecting.

Exceeding one produces a `budget::Overrun` naming the limit, what was allowed and what was
reached. `Overrun::record` writes the stop into a `Coverage` in one call, so that stopping and
saying so cannot come apart into two statements with a bug between them.

**The gap it writes is `Outcome::NotQueried`.** That is literally what became of the scopes past
the bound: nobody asked. The coverage vocabulary has no word for "budget", and inventing an eighth
outcome would give a renderer two ways to say the one thing §4 invariant 13 cares about — that
this is not absence. The reason lives on the `Overrun`, in `describe()`, to be attached alongside.
This follows the precedent already in `transport`, where a `410` becomes `RequestFailed` in the
coverage vocabulary while the error keeps the continuity distinction. `Overrun::kind()` is
`partial_result` and never `timeout`: nothing failed, and saying otherwise sends an operator to
look at a cluster that is behaving perfectly.

`Budget::admits(&Estimate)` answers §17.6 and §12.6 before the first request rather than on the
four hundredth. `Budget::interactive()` bounds all six, because a default that leaves one
dimension `None` is an unbounded default and the default is what every unconfigured query runs
under.

**Nothing in `budget.rs` waits, sleeps, spawns or connects.** Every delay it computes is a
`Duration` handed back to the caller. The provider is a library inside someone else's scheduler,
and a library that decides when to sleep has taken a decision that was not its own.

## Consequences

- Seven distinctions exist that did not: `unauthenticated` apart from `authorization_denied`,
  `conflict` apart from `invalid`, `service_unavailable` apart from `server_timeout` apart from
  `timeout`, `api_not_served` apart from `not_found`, and `AlreadyExists` apart from `Conflict`
  inside one class. Each sends an operator somewhere different.
- A `503` carrying `Retry-After` is now honoured, where before only a `429` was. Honouring a
  header selectively is worse than not reading it, because the inconsistency is invisible.
- `ApiError` gained methods and no variants, so no module outside `transport` needed changing.
  `ono-kubernetes-plugin` reads errors through `outcome()` and `Display` and is untouched.
- **The retry executor has no caller yet.** `transport` is synchronous and nothing loops over
  `RetryPolicy`. This is a shape, deliberately built before the mutations that would make getting
  it wrong expensive, and it joins the modules `docs/coverage.md` already counts as built and
  unreachable. The honest version of that entry is that `budget.rs` is proven and unwired.
- The same is true of the budget: `Client::list` does not yet take a `Ledger`. Wiring it is a
  change to `transport` and to `query.rs`, and it belongs to whoever owns those next.
- `Status` grew from five fields to twelve. It is boxed inside every `ApiError` variant that
  carries one, so the successful read path is unaffected.
- `Retry-After` is read only in its delay-seconds form. The HTTP-date form needs a clock and the
  server's idea of now, and guessing at that would turn a stated delay into an invented one, so an
  unreadable value is `None` and the caller falls back to its own bounded backoff.

## Alternatives considered

**Add the missing classes as `ApiError` variants.** It reads better in isolation — one enum, one
answer. It was rejected because the taxonomy and the transport shape are answering different
questions: `ApiError` is "what came back over the wire", and `ErrorKind` is "which of the
seventeen things that is". Merging them would also have broken every exhaustive match in modules
other agents hold open right now, for a gain that two methods deliver.

**Put the response-head values in their own type beside the `Status` in each variant.** Purer:
a `Status` is a JSON document and an `Audit-Id` is not in it. Rejected because it would make
`ApiError` variants structurally different from one another, so a caller asking "what did the
server say" would destructure twice and get it right once.

**A deny-list of sensitive headers instead of an allow-list of four.** Rejected on the standard
argument, which is not standard enough to skip: a deny-list fails open. The header that leaks is
the one nobody had heard of when the list was written.

**Random jitter.** The usual answer, and it makes the retry-storm test unassertable — either the
test seeds a generator, which is this decision with more machinery, or it asserts a range and
stops proving that two clients differ.

**A `Budget` that truncates the result itself.** Tempting because it puts the enforcement next to
the data. Rejected because it makes the silent truncation *easy*: the caller receives a shorter
list and a coverage marker it has to remember to read. Refusing before the spend and handing back
an `Overrun` that must be recorded keeps the honest path the shortest one.

**A new `Outcome::BudgetExhausted` in `coverage.rs`.** Rejected: the eight outcomes are a
vocabulary a renderer switches on, and a ninth that means "not queried, but for a reason we chose"
would be the second way to say the thing §4 invariant 13 exists to protect. `coverage.rs` is also
outside this change's file scope, and a vocabulary that grows whenever a new module wants a word
is not a vocabulary.

**A `RetryPolicy` that takes the `Idempotent` per call rather than at construction.** Equivalent
in safety and worse in practice: the proof would be re-supplied at every decision point, which is
five places to get it right instead of one, and each of them a place to pass the wrong thing.

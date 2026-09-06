//! What a query is allowed to cost, and what it says when it stops.
//!
//! Specification §49 and §50, with §20.2 and §20.4 of the generic provider contract behind them.
//! Most of §50 is not about speed. It is about bounds: §50.1 says a large cluster must not freeze
//! the shell, §49.1 says the provider is not a load generator, and §20.4 names the six quantities
//! a host budget may limit — requests, scopes, pages, elapsed time, transferred bytes and
//! concurrent requests. This module is those six, counted.
//!
//! **A budget is a value that counts and refuses.** It starts nothing, waits for nothing and owns
//! no thread. Every delay it computes is a [`Duration`] handed back to whoever asked; the caller
//! does the work and the waiting. That is what keeps §49's retry rules testable without a moving
//! clock, and it is also the honest shape: the provider is a library inside someone else's
//! scheduler, and a library that decides when to sleep has taken a decision that was not its own.
//!
//! Two rules give this module its shape.
//!
//! **An exceeded budget produces a stated incomplete result.** Never a shorter list. §18.3 and
//! §48.6 both say the same thing in their own domain, and [`crate::coverage`] already has the
//! word for it: the scopes past the budget were *not queried*, which is what happened, and is
//! never "there is nothing there". [`Overrun::record`] is the one call that writes that down, so
//! that stopping and saying so cannot come apart.
//!
//! **An unsafe retry is not written wrong here — it cannot be written.** §49.3 forbids replaying
//! a mutation whose server outcome is unknown, and §20.3 of the generic contract says unknown
//! idempotency means no automatic retry. A rule in a doc comment is a rule someone forgets at
//! four in the afternoon, so [`RetryPolicy`] is constructed *from* an [`Idempotent`], which has
//! three constructors named after the three read verbs and no other way in. The first mutation
//! that wants a retry has to add a constructor here and say what makes it replayable.

use std::fmt;
use std::time::Duration;

use crate::coverage::{Coverage, Gap, Outcome, Scope};
use crate::transport::{
    ApiError, Clock, ErrorKind, ObservedAt, Operation, Retryability, SystemClock,
};
use crate::watch::Backoff;

// --- the six bounds ------------------------------------------------------------------------------

/// One quantity a budget bounds (§20.4 of the generic contract).
///
/// Six rather than one, because they fail differently: a thousand cheap requests, one request
/// carrying a hundred megabytes, and a fan-out across four hundred namespaces are three ways to
/// be expensive, and a bound on any single one of them leaves the other two open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Limit {
    /// How many requests the query may send.
    Requests,
    /// How many distinct scopes it may reach into (§9.4, §17.6).
    Scopes,
    /// How many pages of a collection it may follow (§18.1).
    Pages,
    /// How long it may take.
    Elapsed,
    /// How many bytes it may transfer (§18.5).
    Bytes,
    /// How many requests may be in flight at once (§49.1).
    Concurrency,
}

impl Limit {
    /// Every quantity, in the order §20.4 lists them.
    ///
    /// A list rather than prose, so a test can hold the vocabulary: a budget decays by leaving
    /// one dimension unbounded, and the unbounded one is where the runaway query leaves.
    #[must_use]
    pub fn all() -> [Self; 6] {
        [
            Self::Requests,
            Self::Scopes,
            Self::Pages,
            Self::Elapsed,
            Self::Bytes,
            Self::Concurrency,
        ]
    }

    /// The word this bound is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::Scopes => "scopes",
            Self::Pages => "pages",
            Self::Elapsed => "elapsed",
            Self::Bytes => "bytes",
            Self::Concurrency => "concurrency",
        }
    }

    /// The unit the bound is counted in, for a message a person reads.
    #[must_use]
    pub fn unit(self) -> &'static str {
        match self {
            Self::Elapsed => "ms",
            Self::Bytes => "bytes",
            Self::Requests => "requests",
            Self::Scopes => "scopes",
            Self::Pages => "pages",
            Self::Concurrency => "in flight",
        }
    }
}

/// What one query may spend.
///
/// Every bound is optional, and `None` means unbounded rather than zero — the two are opposite
/// and a `0` that meant "no limit" would be the most expensive typo in the module.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Budget {
    requests: Option<u64>,
    scopes: Option<u64>,
    pages: Option<u64>,
    elapsed: Option<Duration>,
    bytes: Option<u64>,
    concurrency: Option<u64>,
}

impl Budget {
    /// A budget that refuses nothing.
    ///
    /// The starting point for a builder and for a caller that has its own bound elsewhere. It is
    /// deliberately not the default a query runs under: see [`Self::interactive`].
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Conservative defaults for a shell (§49.5, §50.1).
    ///
    /// All six bounded, because a default that leaves one dimension open is an unbounded default,
    /// and the default is what every query nobody configured runs under. The numbers are a
    /// starting position rather than a measurement: interactive means a person is waiting, so the
    /// elapsed bound is the one that matters most and the rest are sized to stay under it.
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            requests: Some(64),
            scopes: Some(32),
            pages: Some(16),
            elapsed: Some(Duration::from_secs(10)),
            bytes: Some(32 * 1024 * 1024),
            concurrency: Some(4),
        }
    }

    /// Bounds how many requests may be sent.
    #[must_use]
    pub fn with_requests(mut self, requests: u64) -> Self {
        self.requests = Some(requests);
        self
    }

    /// Bounds how many distinct scopes may be reached into.
    #[must_use]
    pub fn with_scopes(mut self, scopes: u64) -> Self {
        self.scopes = Some(scopes);
        self
    }

    /// Bounds how many pages may be followed.
    #[must_use]
    pub fn with_pages(mut self, pages: u64) -> Self {
        self.pages = Some(pages);
        self
    }

    /// Bounds how long the query may take.
    #[must_use]
    pub fn with_elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed = Some(elapsed);
        self
    }

    /// Bounds how many bytes may be transferred.
    #[must_use]
    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }

    /// Bounds how many requests may be in flight at once.
    #[must_use]
    pub fn with_concurrency(mut self, concurrency: u64) -> Self {
        self.concurrency = Some(concurrency);
        self
    }

    /// One bound, in the unit [`Limit::unit`] names — milliseconds for elapsed time.
    #[must_use]
    pub fn bound(&self, limit: Limit) -> Option<u64> {
        match limit {
            Limit::Requests => self.requests,
            Limit::Scopes => self.scopes,
            Limit::Pages => self.pages,
            Limit::Elapsed => self
                .elapsed
                .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
            Limit::Bytes => self.bytes,
            Limit::Concurrency => self.concurrency,
        }
    }

    /// Whether a query of this declared breadth is allowed to start (§17.6, §12.6 generic).
    ///
    /// Asked before the first request rather than discovered on the four hundredth. §12.6 says an
    /// operation that fans out across many scopes is declared; refusing halfway hands an operator
    /// a partial answer they never asked for, while refusing up front lets them narrow the query
    /// or raise the bound.
    ///
    /// # Errors
    ///
    /// [`Overrun`] naming the first bound the estimate already passes.
    pub fn admits(&self, estimate: &Estimate) -> Result<(), Overrun> {
        check(
            self.bound(Limit::Requests),
            estimate.requests,
            Limit::Requests,
        )?;
        check(self.bound(Limit::Scopes), estimate.scopes, Limit::Scopes)
    }
}

/// What a query says it will cost before it runs (§17.6).
///
/// An estimate, and named one: §17.6 asks the provider to *expose* breadth, not to promise it.
/// A plan that guessed low still has the ledger underneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
    requests: u64,
    scopes: u64,
}

impl Estimate {
    /// A query expected to send this many requests across this many scopes.
    #[must_use]
    pub fn new(requests: u64, scopes: u64) -> Self {
        Self { requests, scopes }
    }

    /// How many requests it expects to send.
    #[must_use]
    pub fn requests(self) -> u64 {
        self.requests
    }

    /// How many distinct scopes it expects to reach into.
    #[must_use]
    pub fn scopes(self) -> u64 {
        self.scopes
    }

    /// The breadth, in one line, for the confirmation §12.6 lets a host ask for.
    #[must_use]
    pub fn describe(self) -> String {
        format!("{} requests across {} scopes", self.requests, self.scopes)
    }
}

/// A bound that would have been passed, and by how much.
///
/// Carries the reached value rather than only the allowed one, because "over budget" and "four
/// hundred times over budget" call for different answers from the person reading it: one raises
/// the bound, the other narrows the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overrun {
    limit: Limit,
    allowed: u64,
    reached: u64,
}

impl Overrun {
    /// Which bound stopped the query.
    #[must_use]
    pub fn limit(self) -> Limit {
        self.limit
    }

    /// What the budget allowed.
    #[must_use]
    pub fn allowed(self) -> u64 {
        self.allowed
    }

    /// What the query would have reached.
    #[must_use]
    pub fn reached(self) -> u64 {
        self.reached
    }

    /// Which class of failure this is, in §48.2's vocabulary.
    ///
    /// `partial_result`, never `timeout` or `transport_error`: nothing failed. The query was
    /// stopped by a policy this provider was given, and saying otherwise sends an operator to
    /// look at a cluster that is behaving perfectly.
    #[must_use]
    pub fn kind(self) -> ErrorKind {
        ErrorKind::PartialResult
    }

    /// One line naming the bound, what it allowed and where the query got to.
    #[must_use]
    pub fn describe(self) -> String {
        format!(
            "{} budget exceeded: {} of {} {} allowed",
            self.limit.as_str(),
            self.reached,
            self.allowed,
            self.limit.unit()
        )
    }

    /// Writes the stop into a query's coverage, as a gap rather than as a shorter answer.
    ///
    /// The single call that keeps §18.3's rule from coming apart: stopping and saying so happen
    /// in the same statement, so there is no version of this where a truncated list is returned
    /// and the gap is recorded on the next line by someone who remembered.
    ///
    /// The gap is [`Outcome::NotQueried`] because that is literally what became of the scopes
    /// past the bound — nobody asked. The coverage vocabulary has no word for "budget", and
    /// inventing an eighth outcome for it would give the renderer two ways to say the one thing
    /// §4 invariant 13 cares about, which is that this is not absence. The reason lives here, in
    /// [`Self::describe`], where it can be attached alongside.
    pub fn record(self, coverage: &mut Coverage, scope: Scope) {
        coverage.record(Gap::new(scope, Outcome::NotQueried));
        coverage.more_available();
    }
}

impl fmt::Display for Overrun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

impl std::error::Error for Overrun {}

fn check(bound: Option<u64>, reached: u64, limit: Limit) -> Result<(), Overrun> {
    match bound {
        Some(allowed) if reached > allowed => Err(Overrun {
            limit,
            allowed,
            reached,
        }),
        _ => Ok(()),
    }
}

// --- the ledger ----------------------------------------------------------------------------------

/// What one query has spent so far, and whether it may spend more.
///
/// Cooperative: it refuses *before* the spending rather than noticing after. A budget that
/// discovers the overrun once the bytes have arrived has already paid for what it was protecting,
/// which is a report rather than a bound.
#[derive(Debug, Clone)]
pub struct Ledger<C: Clock = SystemClock> {
    budget: Budget,
    clock: C,
    started: ObservedAt,
    requests: u64,
    pages: u64,
    bytes: u64,
    in_flight: u64,
    scopes: Vec<Scope>,
}

impl<C: Clock> Ledger<C> {
    /// A ledger against this budget, starting now by the clock it is given.
    ///
    /// The clock is injected for the same reason [`crate::transport`]'s is: a test that cannot fix
    /// or step time cannot assert an elapsed bound at all, and an elapsed bound nobody tests is
    /// the one that silently never fires.
    pub fn new(budget: Budget, clock: C) -> Self {
        let started = clock.now();
        Self {
            budget,
            clock,
            started,
            requests: 0,
            pages: 0,
            bytes: 0,
            in_flight: 0,
            scopes: Vec::new(),
        }
    }

    /// What this ledger is counting against.
    #[must_use]
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Takes leave to send one request, and counts it.
    ///
    /// # Errors
    ///
    /// [`Overrun`] when the elapsed, request or concurrency bound would be passed. Nothing is
    /// counted in that case: a request that was refused was not sent.
    pub fn begin_request(&mut self) -> Result<(), Overrun> {
        self.check_elapsed()?;
        check(
            self.budget.bound(Limit::Requests),
            self.requests + 1,
            Limit::Requests,
        )?;
        check(
            self.budget.bound(Limit::Concurrency),
            self.in_flight + 1,
            Limit::Concurrency,
        )?;
        self.requests += 1;
        self.in_flight += 1;
        Ok(())
    }

    /// Gives back the concurrency slot a request held.
    ///
    /// Concurrency is the one bound that is not a total: it limits what the *cluster* sees at an
    /// instant, so a finished request stops counting. The request itself still does, which is
    /// what [`Limit::Requests`] is for.
    pub fn end_request(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Takes leave to reach into one scope, and counts it if it is new.
    ///
    /// Counted once however often it is entered: the budgeted quantity is how wide the query
    /// reached (§9.4, §17.6), not how often it came back to a namespace it already had. Counting
    /// re-entries would exhaust a scope budget inside a single namespace and then call a complete
    /// answer incomplete.
    ///
    /// # Errors
    ///
    /// [`Overrun`] when a new scope would pass the scope bound.
    pub fn enter_scope(&mut self, scope: &Scope) -> Result<(), Overrun> {
        if self.scopes.iter().any(|known| known == scope) {
            return Ok(());
        }
        check(
            self.budget.bound(Limit::Scopes),
            self.scopes.len() as u64 + 1,
            Limit::Scopes,
        )?;
        self.scopes.push(scope.clone());
        Ok(())
    }

    /// Takes leave to follow one more page of a collection (§18.1).
    ///
    /// # Errors
    ///
    /// [`Overrun`] when the page bound would be passed.
    pub fn page(&mut self) -> Result<(), Overrun> {
        check(
            self.budget.bound(Limit::Pages),
            self.pages + 1,
            Limit::Pages,
        )?;
        self.pages += 1;
        Ok(())
    }

    /// Takes leave to transfer this many bytes (§18.5).
    ///
    /// # Errors
    ///
    /// [`Overrun`] when the byte bound would be passed. The refused bytes are not counted.
    pub fn transfer(&mut self, bytes: u64) -> Result<(), Overrun> {
        let reached = self.bytes.saturating_add(bytes);
        check(self.budget.bound(Limit::Bytes), reached, Limit::Bytes)?;
        self.bytes = reached;
        Ok(())
    }

    /// Asks whether the query has run out of time (§50.1).
    ///
    /// Cheap enough to call between records, which is where it belongs: a bound checked only
    /// before the first request is a bound on starting, not on running.
    ///
    /// # Errors
    ///
    /// [`Overrun`] when more time has passed than the budget allows.
    pub fn check_elapsed(&mut self) -> Result<(), Overrun> {
        let elapsed = u64::try_from(self.elapsed().as_millis()).unwrap_or(u64::MAX);
        check(self.budget.bound(Limit::Elapsed), elapsed, Limit::Elapsed)
    }

    /// How long this query has been running, by the injected clock.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        Duration::from_millis(
            self.clock
                .now()
                .unix_millis()
                .saturating_sub(self.started.unix_millis()),
        )
    }

    /// How many requests have been sent.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.requests
    }

    /// How many distinct scopes have been reached into.
    #[must_use]
    pub fn scopes(&self) -> u64 {
        self.scopes.len() as u64
    }

    /// How many pages have been followed.
    #[must_use]
    pub fn pages(&self) -> u64 {
        self.pages
    }

    /// How many bytes have been transferred.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// How many requests are in flight.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.in_flight
    }
}

// --- why it was throttled (§49.2) ----------------------------------------------------------------

/// What API Priority and Fairness said when it refused a request.
///
/// §49.2 asks that a rate-limited response be represented as rate limiting rather than as a
/// generic network failure. This is the step after that one. Under APF a `429` is a queue
/// decision, and the API server names the queue in the response head — so the provider can say
/// *why* it was throttled and not only *that* it was. "You were throttled" is a fact nobody can
/// act on; "you were throttled at this priority level, under this flow schema" points at the two
/// objects that decide it, and both are readable and editable by a cluster administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Throttle {
    retry_after: Option<Duration>,
    flow_schema_uid: Option<String>,
    priority_level_uid: Option<String>,
    request_id: Option<String>,
}

impl Throttle {
    /// Reads the fairness verdict out of a refusal, when the refusal was one.
    ///
    /// `None` for anything that is not rate limiting. A `403` has no queue behind it, and
    /// reporting one as a throttle would send an operator to read flow schemas for a problem that
    /// is a missing RoleBinding.
    #[must_use]
    pub fn of(error: &ApiError) -> Option<Self> {
        if error.kind(Operation::List) != ErrorKind::RateLimited {
            return None;
        }
        let status = error.status()?;
        Some(Self {
            retry_after: status.retry_after(),
            flow_schema_uid: status.flow_schema_uid().map(str::to_owned),
            priority_level_uid: status.priority_level_uid().map(str::to_owned),
            request_id: status.request_id().map(str::to_owned),
        })
    }

    /// How long the server asked to be left alone (§49.2).
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Which flow schema matched the request.
    #[must_use]
    pub fn flow_schema_uid(&self) -> Option<&str> {
        self.flow_schema_uid.as_deref()
    }

    /// Which priority level queued it.
    #[must_use]
    pub fn priority_level_uid(&self) -> Option<&str> {
        self.priority_level_uid.as_deref()
    }

    /// The `Audit-Id` of the refused exchange, for whoever has the audit log.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// The refusal in one line, naming whatever the server named.
    ///
    /// Absent identifiers are left out rather than printed as `unknown`: an older API server, or
    /// one with APF disabled, has not withheld the flow schema — it has none, and a line claiming
    /// otherwise would invent a mechanism the cluster does not run.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut told = String::from("rate limited");
        if let Some(level) = &self.priority_level_uid {
            told.push_str(&format!(" at priority level {level}"));
        }
        if let Some(flow) = &self.flow_schema_uid {
            told.push_str(&format!(" under flow schema {flow}"));
        }
        if let Some(after) = self.retry_after {
            told.push_str(&format!("; retry after {}s", after.as_secs()));
        }
        if let Some(id) = &self.request_id {
            told.push_str(&format!(" (audit {id})"));
        }
        told
    }
}

// --- retries (§49.3) -------------------------------------------------------------------------

/// A request whose repetition cannot be told from its first execution.
///
/// The proof [`RetryPolicy`] demands before it will hand back a delay. §49.3 forbids replaying a
/// mutation whose server outcome is unknown, and §20.3 of the generic contract says unknown
/// idempotency means no automatic retry — and both of those are rules a person has to remember at
/// the wrong moment.
///
/// So this is a type with a private field and exactly three constructors, each named after a read
/// verb that Kubernetes defines as safe. There is no `From<&str>`, no `new`, and no way to build
/// one for `create`, `patch`, `delete` or `post`. An unsafe automatic retry is therefore not a
/// mistake this codebase can make quietly: it is a sentence that does not compile.
///
/// When mutation arrives, the way in is a fourth constructor added here, named after what makes
/// the replay safe — a `resourceVersion` precondition (§56.1), a UID precondition (§56.3) or
/// server-side apply's field ownership (§44.1). That is a visible edit to this file with a doc
/// comment attached, which is exactly the review that decision deserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Idempotent(Verb);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    Get,
    List,
    Watch,
}

impl Idempotent {
    /// Reading one object by name (§17.1).
    #[must_use]
    pub fn get() -> Self {
        Self(Verb::Get)
    }

    /// Reading a collection (§17.2).
    #[must_use]
    pub fn list() -> Self {
        Self(Verb::List)
    }

    /// Opening a watch stream (§19.1).
    #[must_use]
    pub fn watch() -> Self {
        Self(Verb::Watch)
    }

    /// Every verb a retry may be built for.
    #[must_use]
    pub fn verbs() -> [Self; 3] {
        [Self::get(), Self::list(), Self::watch()]
    }

    /// The verb, as the API server names it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self.0 {
            Verb::Get => "get",
            Verb::List => "list",
            Verb::Watch => "watch",
        }
    }
}

/// Whether the caller still wants the answer (§50.1).
///
/// Passed in on every decision rather than stored, because cancellation is a fact about the
/// caller at this instant and a copy of it held here would be a stale one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancellation {
    /// The caller is still waiting.
    Live,
    /// The caller has stopped waiting.
    Cancelled,
}

/// What to do after a failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Wait this long, then send the same request again.
    Wait(Duration),
    /// Do not send it again, for this reason.
    Stop(StopReason),
}

/// Why a retry sequence ended.
///
/// Named rather than folded into "gave up", because the three call for different things from the
/// caller: a cancelled request is not reported at all, an exhausted allowance is a partial result
/// (§18.3), and a failure that cannot succeed by repetition is the error itself, unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The caller stopped waiting.
    Cancelled,
    /// The failure cannot be repeated into a success (§19.4).
    NotRetryable,
    /// The bounded number of attempts is spent (§20.2 of the generic contract).
    AttemptsExhausted,
}

/// A bounded, cancellable, de-synchronised retry sequence for one safe request (§49.3).
///
/// Built on [`Backoff`] from [`crate::watch`] rather than beside it. That type already solves the
/// doubling and the ceiling, and it already carries the reason the ceiling is not optional: an
/// unbounded loop either hammers a struggling API server or, once the multiplication overflows,
/// wraps round to no delay at all. Two backoffs in one provider would be two chances to get that
/// wrong, and the second one is always the one nobody re-reads. What is added around it is what
/// §20.2 of the generic contract asks for and a reconnect loop does not need: an attempt
/// allowance, a cancellation check, the server's own `Retry-After`, and a per-client spread.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    operation: Idempotent,
    backoff: Backoff,
    allowance: u32,
    taken: u32,
    jitter: Jitter,
}

impl RetryPolicy {
    /// A policy for one safe request, doubling from `base` up to `ceiling`, `allowance` times.
    ///
    /// The operation comes first because it is the argument that makes the rest legal.
    #[must_use]
    pub fn new(operation: Idempotent, base: Duration, ceiling: Duration, allowance: u32) -> Self {
        Self {
            operation,
            backoff: Backoff::new(base, ceiling),
            allowance,
            taken: 0,
            jitter: Jitter::none(),
        }
    }

    /// Spreads this client's delays so it does not return in step with another (§20.2 generic).
    #[must_use]
    pub fn with_jitter(mut self, jitter: Jitter) -> Self {
        self.jitter = jitter;
        self
    }

    /// Which safe request this policy was built for.
    #[must_use]
    pub fn operation(&self) -> Idempotent {
        self.operation
    }

    /// How many delays have been handed out since the last reset.
    #[must_use]
    pub fn attempts_taken(&self) -> u32 {
        self.taken
    }

    /// Starts the sequence over, after an attempt that worked.
    ///
    /// A backoff that never resets treats an hour-old outage as evidence about the request being
    /// sent now, and one hiccup early in a session would leave every later retry at the ceiling.
    pub fn reset(&mut self) {
        self.taken = 0;
        self.backoff.reset();
    }

    /// What to do about this failure.
    ///
    /// The order of the three refusals is the order they are checked in, and it is deliberate.
    /// Cancellation comes first: a loop that finishes the current backoff before noticing has
    /// made the shell unresponsive for exactly as long as the delay it was being polite with.
    /// Retryability comes next, because a `403` cannot be repeated into a success and spending
    /// the allowance on one spends it on arithmetic. The allowance comes last, so that a bounded
    /// sequence ends by saying it is spent rather than by saying the error was fatal.
    ///
    /// [`Retryability::Unknown`] does retry here, and the reason is [`Idempotent`] rather than the
    /// error: a `504` leaves the server's outcome unknown, and what makes repeating it safe is
    /// that this request cannot duplicate anything. The error itself never claims more than it
    /// knows.
    pub fn plan(&mut self, error: &ApiError, cancellation: Cancellation) -> Decision {
        if cancellation == Cancellation::Cancelled {
            return Decision::Stop(StopReason::Cancelled);
        }
        if error.retryability() == Retryability::No {
            return Decision::Stop(StopReason::NotRetryable);
        }
        if self.taken >= self.allowance {
            return Decision::Stop(StopReason::AttemptsExhausted);
        }
        self.taken = self.taken.saturating_add(1);
        let ours = self.jitter.apply(self.backoff.next_delay());
        // The server's advice is a floor, not a suggestion (§49.2). A backoff shorter than what
        // the API server asked for is a client deciding it knows better than the API server how
        // loaded the API server is.
        let theirs = error.retry_after().unwrap_or_default();
        Decision::Wait(ours.max(theirs))
    }
}

/// A per-client spread that keeps two clients from retrying in step (§20.2 of the generic contract).
///
/// Two Ono sessions that lost the same API server in the same second, and back off by the same
/// arithmetic, return in the same instant — and that second wave is what keeps a recovering
/// server down. The spread here is derived from the provider instance rather than from a random
/// number, which gives the property that matters without giving up the one this repository needs:
/// it differs between clients, and it is the same on every run of a test.
///
/// It only ever shortens a delay. Lengthening one would silently exceed a ceiling that was chosen
/// on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jitter {
    spread_permille: u32,
    offset_permille: u32,
}

impl Jitter {
    /// No spread, for a caller that supplies its own or a test that wants the bare arithmetic.
    #[must_use]
    pub fn none() -> Self {
        Self {
            spread_permille: 0,
            offset_permille: 0,
        }
    }

    /// A spread of up to a quarter, placed by the provider instance's name (§6.2).
    #[must_use]
    pub fn for_instance(instance: &str) -> Self {
        Self {
            spread_permille: 250,
            offset_permille: u32::try_from(fnv1a(instance) % 1_000).unwrap_or_default(),
        }
    }

    /// This client's delay, shortened by its own share of the spread.
    #[must_use]
    pub fn apply(self, delay: Duration) -> Duration {
        let millis = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        let shave = millis
            .saturating_mul(u64::from(self.spread_permille))
            .saturating_mul(u64::from(self.offset_permille))
            / 1_000_000;
        Duration::from_millis(millis.saturating_sub(shave))
    }
}

/// FNV-1a, because the spread needs a stable number from a name and nothing more.
///
/// Not a cryptographic hash and never used as one: §10.2's fingerprint is SHA-256 and lives in
/// `diagnostics`. What is wanted here is that two instance names land in different places and
/// that they land in the same place on every run.
fn fnv1a(text: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

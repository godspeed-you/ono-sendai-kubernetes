//! What a query is allowed to cost, and what it says when it stops.
//!
//! Specification §49 (API priority, fairness, rate limits and retries) and §50 (performance),
//! with §20.2 and §20.4 of the generic provider contract behind them. §17.6 and §12.6 are the
//! reason a breadth estimate exists at all: an expensive fan-out is declared before it is run,
//! not discovered halfway through.
//!
//! Nothing here waits, sleeps, spawns or connects. A budget is a value that counts and refuses,
//! and every delay it computes is a `Duration` handed back to the caller — which is what lets
//! §49's retry rules be tested without a clock that moves on its own or a cluster to annoy.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::cell::Cell;
use std::time::Duration;

use ono_provider_kubernetes::budget::{
    Budget, Cancellation, Decision, Estimate, Idempotent, Jitter, Ledger, Limit, RetryPolicy,
    StopReason, Throttle,
};
use ono_provider_kubernetes::coverage::{Coverage, Scope};
use ono_provider_kubernetes::discovery::Gvr;
use ono_provider_kubernetes::transport::{
    ApiError, Client, Clock, ErrorKind, FixedClock, FixtureStream, ListOptions, ObservedAt,
};

const INSTANCE: &str = "kubernetes:prod-eu";
const HOST: &str = "kubernetes.default.svc";
const STARTED: u64 = 1_700_000_000_000;

/// A clock that moves one step every time it is read.
///
/// `FixedClock` cannot express elapsed time, and elapsed time is one of the six things §20.4 asks
/// a budget to bound. Stepping deterministically keeps the test as reproducible as a fixed one.
struct StepClock {
    at: Cell<u64>,
    step: u64,
}

impl StepClock {
    fn new(step: u64) -> Self {
        Self {
            at: Cell::new(STARTED),
            step,
        }
    }
}

impl Clock for StepClock {
    fn now(&self) -> ObservedAt {
        let now = self.at.get();
        self.at.set(now + self.step);
        ObservedAt::from_unix_millis(now)
    }
}

fn response(status_line: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut text = format!("HTTP/1.1 {status_line}\r\n");
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    text.push_str(body);
    text
}

fn status(code: u16, reason: &str, message: &str) -> String {
    format!(
        r#"{{"kind":"Status","apiVersion":"v1","status":"Failure","message":"{message}","reason":"{reason}","code":{code}}}"#
    )
}

/// The error a real API server hands back, rather than one assembled by hand: the retry rules are
/// only worth testing against the shape the wire actually produces.
fn refusal(status_line: &str, headers: &[(&str, &str)], reason: &str, code: u16) -> ApiError {
    let recorded = response(status_line, headers, &status(code, reason, "refused"));
    let stream = FixtureStream::replaying(&[recorded]);
    let mut client =
        Client::with_clock(stream, HOST, INSTANCE, FixedClock::at_unix_millis(STARTED));
    client
        .list_page(
            &Gvr::new("", "v1", "pods"),
            &Scope::in_namespace("shop"),
            &ListOptions::new(),
        )
        .expect_err("the fixture refuses")
}

fn throttled() -> ApiError {
    refusal(
        "429 Too Many Requests",
        &[
            ("Retry-After", "3"),
            ("Audit-Id", "8f0c-1"),
            ("X-Kubernetes-PF-FlowSchema-UID", "flow-77"),
            ("X-Kubernetes-PF-PriorityLevel-UID", "level-4"),
            ("Content-Type", "application/json"),
        ],
        "TooManyRequests",
        429,
    )
}

// --- what a budget bounds (§50, §20.4 generic) -------------------------------------------------

#[test]
fn should_bound_every_dimension_the_host_budget_names() {
    // §20.4 of the generic contract lists six. Implementing five and calling it a budget leaves
    // the sixth unbounded, and an unbounded dimension is the one a runaway query escapes through
    // — a bound on requests means nothing if one request may transfer a gigabyte.
    let named: Vec<&str> = Limit::all().into_iter().map(Limit::as_str).collect();

    assert_eq!(
        named,
        vec![
            "requests",
            "scopes",
            "pages",
            "elapsed",
            "bytes",
            "concurrency",
        ]
    );
}

#[test]
fn should_bound_all_six_dimensions_in_the_budget_a_shell_runs_under() {
    // §49.5 asks for conservative defaults aligned with interactive use, and §49.1 says why: the
    // provider is a shell, not a load generator. A default that leaves one dimension `None` is an
    // unbounded default, and the default is what every query nobody configured runs under.
    let budget = Budget::interactive();

    for limit in Limit::all() {
        assert!(
            budget.bound(limit).is_some(),
            "{} is unbounded by default",
            limit.as_str()
        );
    }
    assert!(
        Budget::unlimited().bound(Limit::Requests).is_none(),
        "an unlimited budget is the explicit opt-out, not the default"
    );
}

#[test]
fn should_refuse_the_request_that_would_exceed_the_request_budget() {
    // The refusal happens *before* the request, not after it. A budget that notices afterwards
    // has already spent what it was protecting.
    let mut ledger = Ledger::new(
        Budget::unlimited().with_requests(2),
        FixedClock::at_unix_millis(STARTED),
    );

    assert!(ledger.begin_request().is_ok());
    ledger.end_request();
    assert!(ledger.begin_request().is_ok());
    ledger.end_request();
    let overrun = ledger
        .begin_request()
        .expect_err("the third is over budget");

    assert_eq!(overrun.limit(), Limit::Requests);
    assert_eq!(overrun.allowed(), 2);
    assert_eq!(ledger.requests(), 2, "the refused request was not counted");
}

#[test]
fn should_count_a_scope_once_however_often_it_is_entered() {
    // §9.4 and §17.6: the budgeted quantity is how wide the query reached, not how often it came
    // back to a namespace it already had. Counting re-entries would exhaust a scope budget on a
    // single namespace and call a complete answer incomplete.
    let mut ledger = Ledger::new(
        Budget::unlimited().with_scopes(2),
        FixedClock::at_unix_millis(STARTED),
    );

    assert!(ledger.enter_scope(&Scope::in_namespace("shop")).is_ok());
    assert!(ledger.enter_scope(&Scope::in_namespace("shop")).is_ok());
    assert!(ledger.enter_scope(&Scope::in_namespace("payments")).is_ok());
    let overrun = ledger
        .enter_scope(&Scope::in_namespace("infra"))
        .expect_err("the third distinct scope is over budget");

    assert_eq!(overrun.limit(), Limit::Scopes);
    assert_eq!(ledger.scopes(), 2);
}

#[test]
fn should_stop_a_page_walk_at_the_page_budget() {
    // §18.1: a collection with a `continue` token is incomplete until the pages are consumed.
    // The budget is what stops that walk from being unbounded, and §18.3 is why stopping must be
    // visible rather than silent.
    let mut ledger = Ledger::new(
        Budget::unlimited().with_pages(1),
        FixedClock::at_unix_millis(STARTED),
    );

    assert!(ledger.page().is_ok());
    let overrun = ledger.page().expect_err("the second page is over budget");

    assert_eq!(overrun.limit(), Limit::Pages);
}

#[test]
fn should_refuse_a_transfer_that_would_pass_the_byte_budget() {
    // §18.5 and §50.6: the object count says nothing about the payload. One CRD with a megabyte
    // of status is a bigger read than a thousand Pods, and a budget counting only requests
    // cannot tell.
    let mut ledger = Ledger::new(
        Budget::unlimited().with_bytes(1_000),
        FixedClock::at_unix_millis(STARTED),
    );

    assert!(ledger.transfer(900).is_ok());
    let overrun = ledger.transfer(200).expect_err("1100 bytes is over budget");

    assert_eq!(overrun.limit(), Limit::Bytes);
    assert_eq!(
        overrun.reached(),
        1_100,
        "the overrun says how far over it went"
    );
    assert_eq!(ledger.bytes(), 900, "the refused transfer was not counted");
}

#[test]
fn should_refuse_to_start_more_requests_than_the_concurrency_budget_allows() {
    // §49.1: Ono is a shell, not a load generator. Concurrency is the one dimension that bounds
    // the load the *cluster* sees at an instant rather than what this query costs in total, and
    // a request that finishes gives its slot back — otherwise the bound would be a total, which
    // the request budget already is.
    let mut ledger = Ledger::new(
        Budget::unlimited().with_concurrency(2),
        FixedClock::at_unix_millis(STARTED),
    );

    assert!(ledger.begin_request().is_ok());
    assert!(ledger.begin_request().is_ok());
    let overrun = ledger
        .begin_request()
        .expect_err("a third in flight is over budget");
    assert_eq!(overrun.limit(), Limit::Concurrency);

    ledger.end_request();
    assert!(
        ledger.begin_request().is_ok(),
        "a finished request frees its slot"
    );
}

#[test]
fn should_notice_an_elapsed_budget_from_the_clock_it_was_given() {
    // §50.1: remote work is cancellable, and a wall-clock bound is the cancellation that needs no
    // one to be watching. Reading the host's clock in place instead of the injected one is how a
    // test for this becomes untestable.
    let mut ledger = Ledger::new(
        Budget::unlimited().with_elapsed(Duration::from_millis(250)),
        StepClock::new(100),
    );

    assert!(ledger.check_elapsed().is_ok());
    assert!(ledger.check_elapsed().is_ok());
    let overrun = ledger.check_elapsed().expect_err("300ms is past 250ms");

    assert_eq!(overrun.limit(), Limit::Elapsed);
}

#[test]
fn should_declare_a_query_too_broad_before_it_is_run() {
    // §17.6 and §12.6 of the generic contract: an operation that fans out across many scopes is
    // declared, not discovered. Refusing halfway leaves an operator with a partial answer they
    // did not ask for; refusing up front lets them narrow the query or raise the budget.
    let budget = Budget::unlimited().with_requests(10).with_scopes(4);

    assert!(budget.admits(&Estimate::new(8, 4)).is_ok());
    let overrun = budget
        .admits(&Estimate::new(8, 40))
        .expect_err("forty scopes is a fan-out");

    assert_eq!(overrun.limit(), Limit::Scopes);
    assert_eq!(overrun.reached(), 40);
}

// --- what exceeding one produces (§18.3, §48.6) ------------------------------------------------

#[test]
fn should_leave_a_stated_gap_when_a_budget_stops_a_query() {
    // The whole point of §50's budgets and §18.3's partial pages: a truncated answer that does
    // not say it is truncated is worse than no answer, because it invites conclusions. The
    // coverage vocabulary already has the right word — the scopes past the budget were *not
    // queried*, which is exactly what happened, and never "there is nothing there".
    let mut ledger = Ledger::new(
        Budget::unlimited().with_requests(1),
        FixedClock::at_unix_millis(STARTED),
    );
    ledger.begin_request().expect("the first is within budget");
    ledger.end_request();
    let overrun = ledger.begin_request().expect_err("the second is not");

    let mut coverage = Coverage::complete(Scope::all_namespaces());
    coverage.observed(Scope::in_namespace("shop"));
    overrun.record(&mut coverage, Scope::all_namespaces());

    assert!(!coverage.is_complete());
    assert!(coverage.may_have_more());
    assert_eq!(coverage.describe(), "all-namespaces: not queried");
    assert_eq!(
        overrun.kind(),
        ErrorKind::PartialResult,
        "nothing failed: the query was stopped by a policy, and calling that a timeout sends an \
         operator to look at a cluster that is behaving perfectly"
    );
    assert!(
        overrun.describe().contains("requests"),
        "the overrun names the limit that stopped it: {}",
        overrun.describe()
    );
}

// --- why it was throttled (§49.2) --------------------------------------------------------------

#[test]
fn should_say_which_priority_level_refused_rather_than_only_that_one_did() {
    // §49.2. Under API Priority and Fairness a 429 is a queue decision, and the server names the
    // queue in the response head. "You were throttled" is a fact nobody can act on; "you were
    // throttled at this priority level under this flow schema" points at the object that decides
    // it. Dropping the headers leaves the operator with the first sentence.
    let throttle = Throttle::of(&throttled()).expect("a 429 is a throttle");

    assert_eq!(throttle.flow_schema_uid(), Some("flow-77"));
    assert_eq!(throttle.priority_level_uid(), Some("level-4"));
    assert_eq!(throttle.retry_after(), Some(Duration::from_secs(3)));
    assert_eq!(throttle.request_id(), Some("8f0c-1"));

    let told = throttle.describe();
    assert!(told.contains("flow-77"), "{told}");
    assert!(told.contains("level-4"), "{told}");
}

#[test]
fn should_not_call_a_denial_a_throttle() {
    // A 403 has no queue behind it. Reporting one as throttling would send an operator to look at
    // flow schemas for a problem that is a missing RoleBinding.
    let denied = refusal("403 Forbidden", &[], "Forbidden", 403);

    assert!(Throttle::of(&denied).is_none());
}

// --- retries (§49.3, §20.2 generic) ------------------------------------------------------------

#[test]
fn should_offer_a_retry_only_for_the_verbs_that_can_be_replayed() {
    // §49.3 and §19.4 of the generic contract. `Idempotent` has three constructors and no other
    // way in: there is no `Idempotent::from(verb)`, no `Idempotent::new(&str)`, and no public
    // field. A retry of a mutation is therefore not a rule someone has to remember — it is a
    // sentence that does not compile, and adding one means adding a named constructor here, next
    // to the doc comment saying what it must prove first.
    let named: Vec<&str> = Idempotent::verbs()
        .into_iter()
        .map(Idempotent::as_str)
        .collect();

    assert_eq!(named, vec!["get", "list", "watch"]);
}

#[test]
fn should_wait_at_least_as_long_as_the_server_asked() {
    // §49.2: `Retry-After` is honoured. A backoff shorter than the server's advice is a client
    // deciding it knows better than the API server how loaded the API server is.
    let mut policy = RetryPolicy::new(
        Idempotent::list(),
        Duration::from_millis(100),
        Duration::from_secs(30),
        3,
    )
    .with_jitter(Jitter::none());

    let decision = policy.plan(&throttled(), Cancellation::Live);

    assert_eq!(decision, Decision::Wait(Duration::from_secs(3)));
}

#[test]
fn should_grow_the_delay_between_attempts_and_stop_at_the_allowance() {
    // §20.2 of the generic contract: bounded. An unbounded retry loop against a struggling API
    // server is a denial of service written by someone being helpful, and the bound has to be a
    // count rather than a promise to stop eventually.
    let mut policy = RetryPolicy::new(
        Idempotent::get(),
        Duration::from_millis(100),
        Duration::from_secs(30),
        3,
    )
    .with_jitter(Jitter::none());
    let unavailable = refusal("503 Service Unavailable", &[], "ServiceUnavailable", 503);

    let delays: Vec<Decision> = (0..4)
        .map(|_| policy.plan(&unavailable, Cancellation::Live))
        .collect();

    assert_eq!(
        delays,
        vec![
            Decision::Wait(Duration::from_millis(100)),
            Decision::Wait(Duration::from_millis(200)),
            Decision::Wait(Duration::from_millis(400)),
            Decision::Stop(StopReason::AttemptsExhausted),
        ]
    );
}

#[test]
fn should_not_retry_what_cannot_succeed_by_being_asked_again() {
    // §19.4: retryability is declared where it is known. A 403 becomes a 200 when someone edits
    // a RoleBinding, never when the same request is sent twice, and a retry loop around one burns
    // the budget that a genuinely transient failure would have needed.
    let mut policy = RetryPolicy::new(
        Idempotent::get(),
        Duration::from_millis(100),
        Duration::from_secs(30),
        5,
    );

    let denied = policy.plan(
        &refusal("403 Forbidden", &[], "Forbidden", 403),
        Cancellation::Live,
    );
    let conflicted = policy.plan(
        &refusal("409 Conflict", &[], "Conflict", 409),
        Cancellation::Live,
    );

    assert_eq!(denied, Decision::Stop(StopReason::NotRetryable));
    assert_eq!(
        conflicted,
        Decision::Stop(StopReason::NotRetryable),
        "§48.4: a conflict is resolved by re-reading, not by repeating"
    );
}

#[test]
fn should_retry_an_unknown_outcome_only_because_the_operation_can_be_replayed() {
    // §19.4 again, from the other side. A 504 leaves the server's outcome unknown, and the error
    // says so rather than saying "yes". What makes the retry safe is not the error: it is the
    // `Idempotent` the policy was built from, which is the only thing that knows a repeat cannot
    // duplicate anything. Reading `Unknown` as permission is how that reasoning gets lost.
    let timed_out = refusal("504 Gateway Timeout", &[], "Timeout", 504);
    assert!(!timed_out.retryability().is_declared_safe());

    let mut policy = RetryPolicy::new(
        Idempotent::list(),
        Duration::from_millis(100),
        Duration::from_secs(30),
        2,
    )
    .with_jitter(Jitter::none());

    assert_eq!(
        policy.plan(&timed_out, Cancellation::Live),
        Decision::Wait(Duration::from_millis(100))
    );
}

#[test]
fn should_stop_retrying_the_moment_the_caller_stops_waiting() {
    // §20.2 of the generic contract and §50.1: cancellation is honoured, and it is checked before
    // anything else. A loop that finishes the current backoff before noticing has made the shell
    // unresponsive for exactly as long as the delay it was being polite with.
    let mut policy = RetryPolicy::new(
        Idempotent::list(),
        Duration::from_millis(100),
        Duration::from_secs(30),
        5,
    );

    let decision = policy.plan(&throttled(), Cancellation::Cancelled);

    assert_eq!(decision, Decision::Stop(StopReason::Cancelled));
    assert_eq!(
        policy.attempts_taken(),
        0,
        "a cancelled attempt was not an attempt"
    );
}

#[test]
fn should_spread_two_clients_so_they_do_not_come_back_together() {
    // §20.2 of the generic contract: avoid synchronised retry storms. Two Ono sessions that lost
    // the same API server at the same second and back off by the same arithmetic return at the
    // same instant, and the second wave is what keeps the server down. The spread comes from the
    // provider instance rather than from a random number so that a test can still assert it: it
    // is reproducible per client and different between clients, which is the property that
    // matters.
    let unavailable = refusal("503 Service Unavailable", &[], "ServiceUnavailable", 503);
    let mut here = RetryPolicy::new(
        Idempotent::list(),
        Duration::from_secs(1),
        Duration::from_secs(30),
        3,
    )
    .with_jitter(Jitter::for_instance("kubernetes:prod-eu"));
    let mut there = RetryPolicy::new(
        Idempotent::list(),
        Duration::from_secs(1),
        Duration::from_secs(30),
        3,
    )
    .with_jitter(Jitter::for_instance("kubernetes:prod-us"));

    let ours = here.plan(&unavailable, Cancellation::Live);
    let theirs = there.plan(&unavailable, Cancellation::Live);

    assert_ne!(ours, theirs, "two clients backed off in step");
    for decision in [ours, theirs] {
        let Decision::Wait(delay) = decision else {
            panic!("a 503 is retryable: {decision:?}");
        };
        assert!(
            delay <= Duration::from_secs(1) && delay >= Duration::from_millis(750),
            "jitter shortens a delay, it does not invent one: {delay:?}"
        );
    }
}

#[test]
fn should_start_the_delays_over_once_a_request_has_worked() {
    // A backoff that never resets treats an hour-old outage as evidence about the request being
    // sent now, and the first hiccup of a long session would leave every later retry at the
    // ceiling.
    let unavailable = refusal("503 Service Unavailable", &[], "ServiceUnavailable", 503);
    let mut policy = RetryPolicy::new(
        Idempotent::get(),
        Duration::from_millis(100),
        Duration::from_secs(30),
        5,
    )
    .with_jitter(Jitter::none());

    let _ = policy.plan(&unavailable, Cancellation::Live);
    let _ = policy.plan(&unavailable, Cancellation::Live);
    policy.reset();

    assert_eq!(
        policy.plan(&unavailable, Cancellation::Live),
        Decision::Wait(Duration::from_millis(100))
    );
    assert_eq!(policy.attempts_taken(), 1);
}

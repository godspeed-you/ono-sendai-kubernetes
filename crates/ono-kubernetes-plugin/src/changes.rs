//! Watching a collection for as long as the operator wants it watched, and making the periods it
//! could not observe impossible to miss (§19, §41, Gate F).
//!
//! `watch.rs` in the domain layer holds the state machine and the frame decoder, `transport.rs`
//! builds the request and streams the chunks, and `session.rs` holds the registry a watch lives
//! in. None of them opens one. This module is the route, and four decisions shape it.
//!
//! **List, then watch from the collection's version — never watch from "now".** §19.1 is one
//! sequence and its order is the requirement: a watch opened without a `resourceVersion` starts
//! at the present moment and silently loses everything that already exists, so the initial
//! listing is not an optimisation but the thing that makes the stream mean anything. The listing
//! is fed to [`Session::synchronise`], which refuses it if it is not a snapshot a cache may stand
//! on (§18.2, §18.3) — a listing that lost a page is a fine answer to a query and a terrible
//! cache, because every object it was refused would afterwards read as absent.
//!
//! **A gap is a record, not a log line.** §4 invariant 14 and §19.4 forbid stitching pre-gap and
//! post-gap observation into one continuous history. A stream of changes with nothing in it to
//! mark the break *is* that stitching: the reader sees an ordered sequence and has no way to know
//! that part of it was never observed. So `410 Gone` produces a record of its own, with the
//! reason and both edges of the break, and everything after it carries the next `segment` and
//! `continuous = false`. Gate F is that sentence, checked.
//!
//! **The invocation is live, and a bound is something a query asks for.** A record is emitted as
//! each frame arrives, with the response body still open, and the loop runs until the operator
//! cancels it. That is possible because the brokered connection borrows the invocation context
//! for the length of one read rather than for the length of the connection ([`crate::broker`]),
//! which is the first of the three shapes `ADR-0022` §5 said a live view would need. A query that
//! wants the older, bounded answer names `max_changes` and gets a prefix that says which segment
//! it stopped in (ADR-0023).
//!
//! **Nothing is buffered between the cluster and the consumer.** `Ctx::emit` blocks until the
//! host has credit, and the credit is created by the consumer taking a record. A watch that
//! produces faster than its reader therefore stops reading the socket rather than growing a
//! queue: the backpressure ends up on the API server's connection, where TCP already knows what
//! to do with it.

use std::sync::Arc;
use std::time::Duration;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, EmitError, Outcome};
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::{self, Gvr, Resource, Verb};
use ono_provider_kubernetes::live::{LiveView, ViewState};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::{Session, SyncRefused};
use ono_provider_kubernetes::transport::{
    ApiError, ByteStream, Client, Freshness, ListOptions, Listing, SystemClock, watch_request,
};
use ono_provider_kubernetes::watch::{
    Backoff, Reception, SyncState, WatchDecoder, WatchEvent, WatchFailure,
};
use ono_value::Schema;
use serde_json::Value as Json;

use crate::broker::{Lease, ReadPolicy};
use crate::contributions::Target;
use crate::dynamic::Selector;
use crate::query::{
    self, Conversation, Endpoint, UNAVAILABLE, UNAVAILABLE_CODE, UNSUPPORTED, UNSUPPORTED_CODE,
    converse_on, failure,
};
use crate::records::{Change, change_record};
use crate::sessions::Sessions;

/// How many objects the initial listing asks the API server for per page.
const PAGE_SIZE: u32 = 500;

/// The shortest and longest pause before a watch that ended with nothing is reopened (§19.5).
///
/// It is not a retry policy for failures — those carry their own gap — but a guard against one
/// pathological server: an API server that answers a watch and closes it again immediately would
/// otherwise be reconnected to in a tight loop for as long as the operator watched. A watch that
/// delivered anything at all resets it, so a healthy stream never waits.
const RECONNECT_FLOOR: Duration = Duration::from_millis(50);
const RECONNECT_CEILING: Duration = Duration::from_secs(1);

/// How long a view may go without a live observation before it says `stale` (§41.4).
///
/// **A source-declared threshold rather than a universal rule.** The shell has none and must not
/// grow one — a live event stream with nothing recent in it is not automatically stale — but a
/// *source* may declare the cadence it expects, and this one can: a Kubernetes watch that is
/// healthy is refreshed on every round of this loop, so a view that has not been refreshed
/// against a live stream for thirty seconds is one whose reader is looking at something older
/// than the connection claims. The operator can move it with `stale_after_ms`.
const STALE_AFTER: Duration = Duration::from_secs(30);

/// How many objects of the watched collection the view holds before it starts withholding.
///
/// §18.5 and §50.4: a bound, and one that is *reported* — `withheld` rides on every record, so a
/// truncated view is never a complete-looking one. Two thousand is enough for the collections an
/// operator watches by hand and small enough that a runaway namespace cannot exhaust the
/// instance's 256 MiB.
const VIEW_CAPACITY: usize = 2_000;

/// Answers a `k8s-change` query: acquire the collection, watch it, and account for the gaps.
#[must_use]
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let selector = Selector::from_options(ctx.arguments());
    // Absent is unbounded, which is what a watch is. §41's live view has no natural end and
    // neither does this: the operator ends it. A query that wants a prefix says how long a one.
    let budget = ctx
        .arguments()
        .get("max_changes")
        .and_then(Json::as_u64)
        .and_then(|limit| usize::try_from(limit).ok())
        .filter(|limit| *limit > 0);
    // §19.4 step 4: after an expiry, state is re-acquired by listing rather than resumed. It is
    // an option because re-acquiring costs a second listing, and an operator who only wanted to
    // know *that* continuity broke should not have to pay for it — the gap record is emitted
    // either way, which is the part that is not optional.
    let reacquire = ctx.arguments().get("reacquire").and_then(Json::as_bool) != Some(false);
    // §41.4's `stale`, and the window it is measured against. A source-declared threshold, which
    // is the only kind that may exist: the shell must not grow a universal "stale after N
    // seconds" rule, and a *source* that knows its own cadence may say so.
    let stale_after = ctx
        .arguments()
        .get("stale_after_ms")
        .and_then(Json::as_u64)
        .filter(|window| *window > 0)
        .map_or(STALE_AFTER, Duration::from_millis);
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
    };
    if ctx.cancelled() {
        return Outcome::Cancelled;
    }

    sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            // From here on the context is lent rather than held: a read borrows it, gives it
            // back, and the emission between two reads borrows it again (ADR-0023).
            let lease = Lease::new(ctx);
            let mut emitter = Emitter {
                target,
                schema,
                budget,
                emitted: 0,
                view: None,
                clock: SystemClock,
                stale_after,
            };
            observe(
                &lease,
                session,
                &mut emitter,
                &Watched {
                    endpoint: &endpoint,
                    selector: &selector,
                    reacquire,
                },
            )
        },
    )
}

/// Everything one `k8s-change` invocation was asked for, beyond what it emits with.
struct Watched<'a> {
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    reacquire: bool,
}

/// What the watch loop does next.
///
/// [`Step::Reading`] never escapes one watch response: it is how the frame handler says that the
/// body may go on being read, and [`Step::Ended`] is how it says the body is over and the loop
/// above must decide whether to reopen the stream or re-acquire the collection.
enum Step {
    /// The response body may go on being read.
    Reading,
    /// This response is over.
    Ended,
    /// The invocation is over, with this outcome.
    Stopped(Outcome),
}

/// Acquires the collection, then watches it until the operator stops it (§19.1, §19.4, §19.5).
fn observe(
    lease: &Lease<'_, '_>,
    session: &mut Session,
    emitter: &mut Emitter,
    watched: &Watched<'_>,
) -> Outcome {
    let acquired = match converse_on(
        lease,
        watched.endpoint,
        Acquire {
            endpoint: watched.endpoint,
            selector: watched.selector,
            session,
        },
    ) {
        Ok(acquired) => acquired,
        Err(error) => return refused(lease, error),
    };
    let (resource, listing) = acquired;
    let gvr = resource.gvr().clone();
    let scope = scope_of(watched.endpoint, &resource);
    let outcome = live(
        lease,
        session,
        emitter,
        watched,
        gvr.clone(),
        scope.clone(),
        listing,
    );
    // §19.7: the view is closing, so the watch behind it is released unless the session's own
    // object cache is still entitled to answer from it — which is the "another active consumer"
    // §19.7 names, and the only one this provider has. `Session::close_view` asks that question,
    // so a watch quarantined by a `410` stops costing a checkpoint the server has already
    // discarded, and a healthy one stays where §20.2's `origin=cache` can still reach it.
    session.close_view(&gvr, &scope);
    outcome
}

/// Watches one collection until the operator, a bound or the cluster ends the observation.
///
/// Split from [`observe`] so that every way out of the loop — cancelled, exhausted, denied,
/// refused — passes through the one place §19.7's release is written, instead of each `return`
/// having to remember it.
fn live(
    lease: &Lease<'_, '_>,
    session: &mut Session,
    emitter: &mut Emitter,
    watched: &Watched<'_>,
    gvr: Gvr,
    scope: Scope,
    listing: Listing,
) -> Outcome {
    let mut freshness = listing.freshness().clone();

    // §19.1 and §20.3: the listing becomes the cache the watch keeps true, or it becomes nothing.
    if let Err(refusal) = session.synchronise(&gvr, &scope, listing) {
        return Outcome::Failed(unacquirable(&refusal));
    }
    if let Step::Stopped(outcome) = acquisition(lease, session, emitter, &gvr, &scope, &freshness) {
        return outcome;
    }

    let mut backoff = Backoff::new(RECONNECT_FLOOR, RECONNECT_CEILING);
    // What the last record told a reader the view was. A notice is emitted when this stops being
    // true and nothing else is going to say so (§41.4).
    let mut announced = emitter.observed_state(session, &gvr, &scope);
    loop {
        if lease.cancelled() {
            return Outcome::Cancelled;
        }
        let delivered = emitter.emitted;
        let from = session.watch_stream(&gvr, &scope).and_then(|stream| {
            stream
                .checkpoint()
                .map(|version| version.as_str().to_owned())
        });
        let round = converse_on(
            lease,
            watched.endpoint,
            Live {
                lease,
                endpoint: watched.endpoint,
                gvr: &gvr,
                scope: &scope,
                from: from.as_deref(),
                freshness: &freshness,
                session,
                emitter,
            },
        );
        match round {
            Ok(Step::Stopped(outcome)) => return outcome,
            Ok(Step::Reading | Step::Ended) => {}
            Err(error) => return refused(lease, error),
        }

        match session.watch(&gvr, &scope).state() {
            // The server closed a healthy watch, which is what a server does when its own
            // timeout expires. Nothing was missed: the next request opens at the checkpoint.
            SyncState::Live => {}
            // §19.5: the body stopped mid-stream. The checkpoint still names a position the
            // server holds, so this is a reconnect rather than a break, and re-listing here
            // would record a gap that observation had not actually lost.
            SyncState::Reconnecting => {
                if session.watch(&gvr, &scope).reconnected().is_err() {
                    return Outcome::Completed;
                }
            }
            // §19.4 step 4: the checkpoint is void, so state is re-acquired by listing — and
            // what that listing shows was inferred from a snapshot rather than observed
            // arriving, which is what the second segment on every following record says.
            SyncState::GapDetected => {
                if !watched.reacquire {
                    return Outcome::Completed;
                }
                let listed = match converse_on(
                    lease,
                    watched.endpoint,
                    Relist {
                        gvr: &gvr,
                        scope: &scope,
                    },
                ) {
                    Ok(listed) => listed,
                    Err(error) => return refused(lease, error),
                };
                freshness = listed.freshness().clone();
                if let Err(refusal) = session.synchronise(&gvr, &scope, listed) {
                    return Outcome::Failed(unacquirable(&refusal));
                }
                if let Step::Stopped(outcome) =
                    acquisition(lease, session, emitter, &gvr, &scope, &freshness)
                {
                    return outcome;
                }
            }
            // Authorization refused the stream. Asking again is not evidence, and a listing
            // would be refused by the same decision (§21.4).
            SyncState::Denied | SyncState::Syncing => return Outcome::Completed,
        }

        // §41.4. A round that delivered a record has already told the reader where the view
        // stands; one that delivered nothing has not, and if the view moved — the stream started
        // reconnecting, or the window passed with no live observation — the last thing the reader
        // was told is now false. That is precisely the frozen table §41.4 forbids, so the notice
        // goes out before the backoff rather than after the next arrival, which may never come.
        let now = emitter.observed_state(session, &gvr, &scope);
        if now != announced {
            announced = now;
            if let Step::Stopped(outcome) = emitter.notice(lease, session, &gvr, &scope, &freshness)
            {
                return outcome;
            }
        }

        // A round that carried nothing and ended at once is the one shape that could spin.
        if emitter.emitted > delivered {
            backoff.reset();
            announced = emitter.observed_state(session, &gvr, &scope);
        } else {
            std::thread::sleep(backoff.next_delay());
        }
    }
}

/// Emits the state the collection was in when observation began or resumed (§19.1, §19.4).
///
/// `listed` rather than `added`: those objects did not arrive, they were there. §19.1's snapshot
/// and §19.3's classes are different claims and the word is what keeps them apart.
fn acquisition(
    lease: &Lease<'_, '_>,
    session: &mut Session,
    emitter: &mut Emitter,
    gvr: &Gvr,
    scope: &Scope,
    freshness: &Freshness,
) -> Step {
    let objects: Vec<Object> = session
        .watch_stream(gvr, scope)
        .map(|stream| stream.objects().cloned().collect())
        .unwrap_or_default();
    for object in objects {
        let view = emitter.refresh(session, gvr, scope);
        match emitter.deliver(
            lease,
            session,
            gvr,
            scope,
            freshness,
            "listed",
            Some(object),
            view,
        ) {
            Step::Reading | Step::Ended => {}
            Step::Stopped(outcome) => return Step::Stopped(outcome),
        }
    }
    Step::Reading
}

/// A cancellation that surfaced as a failed exchange is a cancellation, not a failure.
///
/// A read that is interrupted by the operator stopping the query comes back as a stream error,
/// because that is all a byte stream can say. §62.12 asks for the invocation to *terminate*
/// promptly, and terminating with a fault the operator caused would be a lie about the cluster.
fn refused(lease: &Lease<'_, '_>, error: WireError) -> Outcome {
    if lease.cancelled() {
        return Outcome::Cancelled;
    }
    Outcome::Failed(error)
}

/// What one invocation emits with, and the budget it emits under.
struct Emitter {
    target: &'static Target,
    schema: Arc<Schema>,
    /// `None` is a watch that runs until the operator stops it, which is the default.
    budget: Option<usize>,
    emitted: usize,
    /// §41's view over the collection, built once the acquisition says which collection it is.
    ///
    /// The view is what turns a stream of changes into something a reader can be told the *state*
    /// of. `watch.rs` knows five of §41.4's six words without a clock; the sixth — `stale` — is
    /// the view's, because it is a statement about how long ago rather than about the connection.
    view: Option<LiveView>,
    /// The clock the staleness window is measured against. `live.rs` takes it as a parameter and
    /// has a test that it never reaches for one of its own, so this is where the wall clock
    /// enters.
    clock: SystemClock,
    /// How long without a live observation makes the view stale (§41.4).
    stale_after: Duration,
}

impl Emitter {
    /// Builds one change record and emits it under the host's credit.
    #[allow(
        clippy::too_many_arguments,
        reason = "\
        every argument is a distinct fact the record carries and none of them can be derived \
        from another: the collection, the scope and the freshness come from the acquisition, the \
        word and the object come from the event, and the continuity is read from the stream. \
        Bundling them into a struct would move the argument list rather than shorten it."
    )]
    fn deliver(
        &mut self,
        lease: &Lease<'_, '_>,
        session: &Session,
        gvr: &Gvr,
        scope: &Scope,
        freshness: &Freshness,
        class: &str,
        object: Option<Object>,
        // What the view was when this record was decided — refreshed by an arrival, and merely
        // *read* by a notice. A notice that refreshed first would report the state it had just
        // erased: `LiveView::refresh` advances the live observation it measures staleness
        // against, which is right for something that arrived and wrong for something that did
        // not.
        view: (ViewState, usize),
    ) -> Step {
        if lease.cancelled() {
            return Step::Stopped(Outcome::Cancelled);
        }
        // §22 and Gate I: a watched Secret is a Secret. There is one door into the emission path
        // and a change stream does not get a second one.
        let guarded = match object.map(Guarded::hold).transpose() {
            Ok(guarded) => guarded,
            Err(error) => {
                return Step::Stopped(Outcome::Failed(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!("an object could not be taken across the redaction boundary: {error}"),
                    "This is a defect in the Kubernetes provider, not in the cluster.",
                )));
            }
        };
        // §20.2's third origin. A listing is a direct read of the collection; everything after it
        // arrived because the server pushed it, and a reader deciding how much to trust a record
        // is entitled to know which of the two this was.
        let stamped = if class == "listed" {
            freshness.clone()
        } else {
            freshness.as_watch_event()
        };
        let (segment, continuous, state, gap) = continuity(session, gvr, scope);
        let (view_state, withheld) = view;
        let collection = gvr.to_string();
        let asked_about = scope.to_string();
        let change = Change {
            class,
            resource: &collection,
            scope: &asked_about,
            segment,
            continuous,
            sync_state: state.as_str(),
            view_state: view_state.as_str(),
            withheld,
            gap_reason: gap.as_ref().map(|(reason, _)| *reason),
            gap_detail: gap.map(|(_, detail)| detail),
            object: guarded.as_ref(),
        };
        let value = match change_record(self.target, &self.schema, &change, &stamped) {
            Ok(value) => value,
            Err(error) => {
                return Step::Stopped(Outcome::Failed(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!(
                        "a record of `{}` could not be built: {error}",
                        self.target.schema
                    ),
                    "This is a defect in the Kubernetes provider's schema table.",
                )));
            }
        };
        // The credit is the backpressure: this blocks until the consumer has taken enough for
        // the host to have more to give, and nothing is queued here while it does.
        match lease.with(|ctx| ctx.emit(&value)) {
            Ok(Ok(())) => {
                self.emitted += 1;
                if self.budget.is_some_and(|budget| self.emitted >= budget) {
                    return Step::Stopped(Outcome::Completed);
                }
                Step::Reading
            }
            Ok(Err(EmitError::Cancelled)) => Step::Stopped(Outcome::Cancelled),
            Ok(Err(error)) => Step::Stopped(Outcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the host refused a record: {error}"),
                "The stream ended before the query did.",
            ))),
            Err(overlap) => Step::Stopped(Outcome::Failed(overlap)),
        }
    }
}

impl Emitter {
    /// Refreshes the view against the session's stream and answers what a reader is looking at.
    ///
    /// Built lazily, because the collection is not known until the acquisition has resolved it,
    /// and rebuilt on every emission because that is where the clock is read: `LiveView` does no
    /// timing of its own, so a view refreshed once and asked twice would go stale between the two
    /// asks rather than because anything happened.
    fn refresh(&mut self, session: &Session, gvr: &Gvr, scope: &Scope) -> (ViewState, usize) {
        let Some(stream) = session.watch_stream(gvr, scope) else {
            // No stream yet is the acquisition, and §20.3 is explicit that a view which has not
            // synchronised is `syncing` rather than a cluster with nothing in it.
            return (ViewState::Syncing, 0);
        };
        let view = self.view.get_or_insert_with(|| {
            LiveView::new(gvr.clone(), scope.clone(), VIEW_CAPACITY, self.stale_after)
        });
        view.refresh(stream, &self.clock);
        (view.state(&self.clock), view.withheld().len())
    }

    /// The state a reader would be looking at right now, without touching the view's rows.
    ///
    /// Used by the loop between rounds, where nothing arrived to carry a state on.
    fn observed_state(&self, session: &Session, gvr: &Gvr, scope: &Scope) -> ViewState {
        match (self.view.as_ref(), session.watch_stream(gvr, scope)) {
            (Some(view), Some(_)) => view.state(&self.clock),
            _ => ViewState::Syncing,
        }
    }

    /// Emits one `notice`: the view changed state and no observation arrived to say so.
    ///
    /// **This is what §41.4's second sentence asks for.** "A disconnected watch MUST not leave a
    /// frozen table that visually appears live" — and a reader of a stream learns only from
    /// records that arrive, so a stream that goes quiet *because* it is reconnecting says nothing
    /// at all, and the last thing it said was `live`. A notice carries no object, exactly as a
    /// gap does: it is a fact about the view rather than about anything in the cluster.
    fn notice(
        &mut self,
        lease: &Lease<'_, '_>,
        session: &Session,
        gvr: &Gvr,
        scope: &Scope,
        freshness: &Freshness,
    ) -> Step {
        let view = (
            self.observed_state(session, gvr, scope),
            self.view.as_ref().map_or(0, |view| view.withheld().len()),
        );
        self.deliver(lease, session, gvr, scope, freshness, "notice", None, view)
    }
}

/// Which observation period the stream is in, and what it has failed to observe.
///
/// The segment is the count of periods rather than an index into them, so the first record of a
/// stream that has never broken says `1` and the first record after a `410` says `2`. Nothing
/// here reads the *contents* of a segment: what a reader needs is which period a record belongs
/// to, and handing over the changes inside one would offer the concatenation §19.4 forbids.
fn continuity(
    session: &Session,
    gvr: &Gvr,
    scope: &Scope,
) -> (usize, bool, SyncState, Option<(&'static str, String)>) {
    let Some(stream) = session.watch_stream(gvr, scope) else {
        return (0, false, SyncState::Syncing, None);
    };
    // The reason word comes from `GapReason::as_str` rather than from a table here, so Appendix
    // D.4's vocabulary is spelled in one place and a reason added there cannot go unreported.
    let gap = stream
        .gaps()
        .last()
        .map(|gap| (gap.reason().as_str(), gap.describe()));
    (
        stream.segments().len(),
        stream.is_gap_free(),
        stream.state(),
        gap,
    )
}

/// The initial acquisition: discover what serves the kind, then list it (§19.1).
struct Acquire<'a> {
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    session: &'a mut Session,
}

impl Conversation for Acquire<'_> {
    type Answer = (Resource, Listing);

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        // §11.2 through the one reader that negotiates it, so a watch pays the same discovery
        // cost a query does and never a second, older one.
        let served = query::served(session, client, self.endpoint)?;
        let resource = query::resolve_in(
            session,
            client,
            self.endpoint,
            &served,
            self.selector,
            Verb::Watch,
        )?;
        if !resource.supports(Verb::Watch) {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!(
                    "the cluster serves `{}` and does not offer `watch` on it",
                    resource.gvr()
                ),
                "A collection nobody may watch is not a collection in which nothing happens. \
                 `get k8s-resource` reads it once instead.",
            ));
        }
        let scope = scope_of(self.endpoint, &resource);
        let listing = client.list(resource.gvr(), &scope, &ListOptions::new().limit(PAGE_SIZE));
        Ok((resource, listing))
    }
}

/// A fresh listing, for §19.4 step 4's re-acquisition after continuity broke.
///
/// Nothing is discovered again: the collection was resolved when the watch was acquired, and
/// re-resolving it here would ask the cluster a question whose answer this session already holds.
struct Relist<'a> {
    gvr: &'a Gvr,
    scope: &'a Scope,
}

impl Conversation for Relist<'_> {
    type Answer = Listing;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        Ok(client.list(self.gvr, self.scope, &ListOptions::new().limit(PAGE_SIZE)))
    }
}

/// One watch response, read frame by frame, with a record emitted as each frame arrives.
///
/// This is the whole of what `ADR-0022` §5 said the protocol could not express. The connection
/// borrows the context per read, so between two chunks the same context is free for `Ctx::emit`
/// — and a response body that never ends is no longer a body nothing can be said about.
struct Live<'a, 'ctx, 'io> {
    lease: &'a Lease<'ctx, 'io>,
    endpoint: &'a Endpoint,
    gvr: &'a Gvr,
    scope: &'a Scope,
    from: Option<&'a str>,
    freshness: &'a Freshness,
    session: &'a mut Session,
    emitter: &'a mut Emitter,
}

impl Conversation for Live<'_, '_, '_> {
    type Answer = Step;

    fn read_policy(&self) -> ReadPolicy {
        ReadPolicy::watch()
    }

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let Self {
            lease,
            endpoint,
            gvr,
            scope,
            from,
            freshness,
            session,
            emitter,
        } = self;
        let request = endpoint.authorise(
            watch_request(gvr, scope, &ListOptions::new(), from)
                .header("Accept", "application/json"),
        );
        let instance = client.provider_instance().to_owned();
        let mut decoder = WatchDecoder::new(instance);
        let mut stream = client
            .connection()
            .open(&request)
            .map_err(|error| watch_failure(gvr, &error))?;

        // §19.4's case that is easy to get wrong in the other direction: a `410` may arrive as
        // the *status* of the response, when the checkpoint names history the server has already
        // discarded, or as an error frame inside a perfectly successful `200` stream, when it
        // expires while the stream is open. Both are the same expiry and neither is a transport
        // failure, so both become the event the state machine reads.
        let opening = match stream.status() {
            200 => None,
            410 => Some(WatchEvent::Error(WatchFailure::Expired)),
            403 => Some(WatchEvent::Error(WatchFailure::Denied)),
            other => {
                return Err(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!("the API server answered a watch on `{gvr}` with {other}"),
                    "A watch that could not be opened is not a collection in which nothing \
                     happened.",
                ));
            }
        };
        if let Some(event) = opening {
            return Ok(
                match apply(event, lease, session, emitter, gvr, scope, freshness) {
                    Step::Stopped(outcome) => Step::Stopped(outcome),
                    Step::Reading | Step::Ended => Step::Ended,
                },
            );
        }

        let mut announced = emitter.observed_state(session, gvr, scope);
        loop {
            // §62.12: between two chunks, which is where a live watch spends its life. The read
            // itself watches for it too, because a quiet watch is quiet for minutes at a time.
            if lease.cancelled() {
                return Ok(Step::Stopped(Outcome::Cancelled));
            }
            // §41.4, in the place where the silence actually happens. A watch spends most of its
            // life blocked here, and if the view crosses its staleness window while it does, the
            // last thing the reader was told is `live` and nothing is coming to correct it. That
            // is the frozen table §41.4 forbids, so the correction is emitted rather than waited
            // for.
            let now = emitter.observed_state(session, gvr, scope);
            if now != announced {
                announced = now;
                if let Step::Stopped(outcome) =
                    emitter.notice(lease, session, gvr, scope, freshness)
                {
                    return Ok(Step::Stopped(outcome));
                }
            }
            let Some(chunk) = stream.next_chunk() else {
                break;
            };
            let events = match chunk {
                Ok(chunk) => match decoder.decode(&chunk) {
                    Ok(events) => events,
                    // A frame that arrived whole and could not be read is not an expiry and not
                    // a protocol fault to report as one. It suspends the stream, so the events
                    // after it are never filed inside the history before it, and the reconnect
                    // that follows opens at the last position anything was actually observed at.
                    Err(error) => interrupted(&error.to_string()),
                },
                // A window passed and the server said nothing. The connection is open, the
                // buffer is untouched, and the next read continues mid-frame — so this is the
                // one read outcome that is neither an event nor an interruption. It exists so
                // that a watch can notice its own silence: the loop head above has just checked
                // whether the view moved, which is §41.4's "MUST not leave a frozen table".
                Err(ApiError::Quiet) => continue,
                // The body stopped mid-stream. §19.5: an interruption is not an expiry — the
                // checkpoint is still usable — so it suspends the stream rather than voiding it.
                Err(error) => {
                    if lease.cancelled() {
                        return Ok(Step::Stopped(Outcome::Cancelled));
                    }
                    interrupted(&error.to_string())
                }
            };
            for event in events {
                match apply(event, lease, session, emitter, gvr, scope, freshness) {
                    Step::Reading => {}
                    Step::Ended => return Ok(Step::Ended),
                    Step::Stopped(outcome) => return Ok(Step::Stopped(outcome)),
                }
            }
            // Whatever arrived carried the state on its own record, so that is what the reader
            // was last told.
            announced = emitter.observed_state(session, gvr, scope);
        }

        let rest = match decoder.finish() {
            Ok(rest) => rest,
            Err(error) => interrupted(&error.to_string()),
        };
        for event in rest {
            match apply(event, lease, session, emitter, gvr, scope, freshness) {
                Step::Reading | Step::Ended => {}
                Step::Stopped(outcome) => return Ok(Step::Stopped(outcome)),
            }
        }
        Ok(Step::Ended)
    }
}

/// One event of a watch: what the state machine made of it, and what a reader is told.
///
/// The state machine decides what may be claimed; this only reports what it decided. An event
/// handed to a stream that is not receiving is discarded rather than filed inside a history it
/// does not belong to (§19.4), and a discarded event must not reach a reader as an observation.
#[allow(
    clippy::too_many_arguments,
    reason = "the same list `Emitter::deliver` carries, plus the event and the state machine it \
              is fed to. Every one of them is a distinct fact and none is derivable from another."
)]
fn apply(
    event: WatchEvent,
    lease: &Lease<'_, '_>,
    session: &mut Session,
    emitter: &mut Emitter,
    gvr: &Gvr,
    scope: &Scope,
    freshness: &Freshness,
) -> Step {
    let class = event.class();
    let object = match &event {
        WatchEvent::Added(object) | WatchEvent::Modified(object) | WatchEvent::Deleted(object) => {
            Some(object.clone())
        }
        WatchEvent::Bookmark(_) | WatchEvent::Error(_) => None,
    };
    match session.watch(gvr, scope).observe(event) {
        Reception::Applied => {
            let word = match class {
                "ADDED" => "added",
                "DELETED" => "deleted",
                _ => "modified",
            };
            let view = emitter.refresh(session, gvr, scope);
            emitter.deliver(lease, session, gvr, scope, freshness, word, object, view)
        }
        // A checkpoint moved and nothing else did; a bookmark is not a change and reporting it
        // as one is how a cache picks up a change the cluster never made (§19.3).
        //
        // It *is* evidence the stream is alive, though, which is the one thing §41.4's `stale`
        // is measured against — so the view is refreshed and no record is emitted. A healthy
        // watch that nothing is happening in stays `live` because its bookmarks say so, and a
        // connected watch whose server has gone silent goes `stale` because nothing does.
        Reception::Checkpointed | Reception::Discarded => {
            emitter.refresh(session, gvr, scope);
            Step::Reading
        }
        // The body is over as far as observation goes, and the checkpoint survives it.
        Reception::Suspended => Step::Ended,
        Reception::ContinuityBroken => {
            let view = emitter.refresh(session, gvr, scope);
            match emitter.deliver(lease, session, gvr, scope, freshness, "gap", None, view) {
                Step::Reading | Step::Ended => Step::Ended,
                Step::Stopped(outcome) => Step::Stopped(outcome),
            }
        }
    }
}

/// One interruption, as the single event a suspended stream is told about.
fn interrupted(detail: &str) -> Vec<WatchEvent> {
    vec![WatchEvent::Error(WatchFailure::Interrupted(
        detail.to_owned(),
    ))]
}

/// §9.2 again: a cluster-scoped collection has no namespace, and inventing one names nothing.
fn scope_of(endpoint: &Endpoint, resource: &Resource) -> Scope {
    match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => endpoint.scope.clone(),
    }
}

/// A listing that may not become the cache a watch keeps true (§18.2, §18.3, §20.3).
fn unacquirable(refused: &SyncRefused) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!("the collection could not be acquired: {refused}"),
        "A watch is only as true as the snapshot it opened from. A listing that lost a page is a \
         legitimate answer to `get` and an illegitimate cache: every object it was refused would \
         afterwards be reported as absent (§4 invariant 13).",
    )
}

/// The watch request itself could not be made.
fn watch_failure(gvr: &Gvr, error: &ApiError) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!("a watch on `{gvr}` could not be opened: {error}"),
        "The bytes travel through the host's broker; a refusal there is a capability decision.",
    )
}

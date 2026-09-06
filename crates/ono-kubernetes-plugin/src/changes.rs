//! Opening a watch, and making the periods it could not observe impossible to miss (§19, Gate F).
//!
//! `watch.rs` in the domain layer holds the state machine and the frame decoder, `transport.rs`
//! builds the request and streams the chunks, and `session.rs` holds the registry a watch lives
//! in. None of them opens one. This module is the route, and three decisions shape it.
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
//! **The invocation is bounded, and the boundedness is honest about what it costs.** A watch is
//! unbounded and a `provider.query` answers with a value stream under credit, which the SDK will
//! block on — that part composes. What does not compose is the borrow: the brokered connection
//! holds the invocation context for as long as it lives, and `Ctx::emit` needs the same context,
//! so nothing can be emitted while a response body is open. The consequence is written into the
//! shape rather than hidden: this invocation opens one watch, reads its response to the end,
//! and answers with what that response carried — plus, where continuity broke, the gap and the
//! re-acquired state on the other side of it. It is a *bounded observation of a live stream*
//! rather than a live view, and `sync_state` on every record says which of §41.4's five states
//! the stream was in when the answer was given. See ADR-0022 for what a live view would need
//! from the host protocol.

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, EmitError, Outcome};
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::{self, Discovery, Gvr, Resource, Verb};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::{Session, SyncRefused};
use ono_provider_kubernetes::transport::{
    ApiError, ByteStream, Client, Freshness, ListOptions, Listing, watch_request,
};
use ono_provider_kubernetes::watch::{
    Reception, SyncState, WatchDecoder, WatchEvent, WatchFailure,
};
use ono_value::Schema;
use serde_json::Value as Json;

use crate::contributions::Target;
use crate::dynamic::Selector;
use crate::query::{
    self, Conversation, Endpoint, UNAVAILABLE, UNAVAILABLE_CODE, UNSUPPORTED, UNSUPPORTED_CODE,
    failure,
};
use crate::records::{Change, change_record};
use crate::sessions::Sessions;

/// How many objects the initial listing asks the API server for per page.
const PAGE_SIZE: u32 = 500;

/// How many events one watch response may deliver before this invocation stops reading it.
///
/// A bound with a reason rather than a round number: the response body of a watch does not end
/// on its own, so something has to decide when this invocation has seen enough, and an
/// invocation that never returns is worse for an operator than one that returns a prefix and
/// says which segment it stopped in. A query that wants a different bound passes `max_changes`.
const DEFAULT_MAX_CHANGES: usize = 500;

/// Answers a `k8s-change` query: acquire the collection, watch it, and account for the gaps.
#[must_use]
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let selector = Selector::from_options(ctx.arguments());
    let budget = ctx
        .arguments()
        .get("max_changes")
        .and_then(Json::as_u64)
        .and_then(|limit| usize::try_from(limit).ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_MAX_CHANGES);
    // §19.4 step 4: after an expiry, state is re-acquired by listing rather than resumed. It is
    // an option because re-acquiring costs a second listing, and an operator who only wanted to
    // know *that* continuity broke should not have to pay for it — the gap record is emitted
    // either way, which is the part that is not optional.
    let reacquire = ctx.arguments().get("reacquire").and_then(Json::as_bool) != Some(false);
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
            observe(
                ctx,
                session,
                &Watched {
                    target,
                    schema: &schema,
                    endpoint: &endpoint,
                    selector: &selector,
                    budget,
                    reacquire,
                },
            )
        },
    )
}

/// Everything one `k8s-change` invocation was asked for.
struct Watched<'a> {
    target: &'static Target,
    schema: &'a Arc<Schema>,
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    budget: usize,
    reacquire: bool,
}

/// Acquires the collection, reads one watch response, and accounts for whatever it lost.
fn observe(ctx: &mut Ctx<'_>, session: &mut Session, watched: &Watched<'_>) -> Outcome {
    let acquired = match query::converse(
        ctx,
        watched.endpoint,
        Acquire {
            endpoint: watched.endpoint,
            selector: watched.selector,
            session,
        },
    ) {
        Ok(acquired) => acquired,
        Err(error) => return Outcome::Failed(error),
    };
    let (resource, listing) = acquired;
    let gvr = resource.gvr().clone();
    let scope = scope_of(watched.endpoint, &resource);
    let freshness = listing.freshness().clone();

    // §19.1 and §20.3: the listing becomes the cache the watch keeps true, or it becomes nothing.
    if let Err(refused) = session.synchronise(&gvr, &scope, listing) {
        return Outcome::Failed(unacquirable(&refused));
    }
    let acquired_objects: Vec<Object> = session
        .watch_stream(&gvr, &scope)
        .map(|stream| stream.objects().cloned().collect())
        .unwrap_or_default();
    for object in acquired_objects {
        match deliver(
            ctx,
            session,
            watched,
            &gvr,
            &scope,
            &freshness,
            "listed",
            Some(object),
        ) {
            Delivered::Continue => {}
            Delivered::Stopped(outcome) => return outcome,
        }
    }

    let from = session.watch_stream(&gvr, &scope).and_then(|stream| {
        stream
            .checkpoint()
            .map(|version| version.as_str().to_owned())
    });
    let batch = match query::converse(
        ctx,
        watched.endpoint,
        Round {
            endpoint: watched.endpoint,
            gvr: &gvr,
            scope: &scope,
            from: from.as_deref(),
            budget: watched.budget,
        },
    ) {
        Ok(batch) => batch,
        Err(error) => return Outcome::Failed(error),
    };

    for event in batch {
        let class = event.class();
        let object = match &event {
            WatchEvent::Added(object)
            | WatchEvent::Modified(object)
            | WatchEvent::Deleted(object) => Some(object.clone()),
            WatchEvent::Bookmark(_) | WatchEvent::Error(_) => None,
        };
        // The state machine decides what may be claimed; this module only reports what it
        // decided. An event handed to a stream that is not receiving is discarded rather than
        // filed inside a history it does not belong to (§19.4), and a discarded event must not
        // reach a reader as an observation.
        let reception = session.watch(&gvr, &scope).observe(event);
        match reception {
            Reception::Applied => {
                let word = match class {
                    "ADDED" => "added",
                    "DELETED" => "deleted",
                    _ => "modified",
                };
                match deliver(
                    ctx, session, watched, &gvr, &scope, &freshness, word, object,
                ) {
                    Delivered::Continue => {}
                    Delivered::Stopped(outcome) => return outcome,
                }
            }
            // A checkpoint moved and nothing else did; a bookmark is not a change and reporting
            // it as one is how a cache picks up a change the cluster never made (§19.3).
            Reception::Checkpointed | Reception::Suspended | Reception::Discarded => {}
            Reception::ContinuityBroken => {
                match deliver(ctx, session, watched, &gvr, &scope, &freshness, "gap", None) {
                    Delivered::Continue => {}
                    Delivered::Stopped(outcome) => return outcome,
                }
            }
        }
    }

    // §19.4 step 4 and §19.5, which are different repairs for different breaks. Only an expiry
    // voids the checkpoint, and only then does state have to be re-acquired by listing. An
    // interruption leaves the checkpoint usable, so the stream stays `reconnecting` and the next
    // invocation opens from where this one stopped — re-listing it here would record a gap that
    // observation had not actually lost. A denied stream is not re-listed either: the listing
    // would be refused by the same authorization, and asking again is not evidence.
    if watched.reacquire && session.watch(&gvr, &scope).state() == SyncState::GapDetected {
        return reacquire(ctx, session, watched, &gvr, &scope);
    }
    Outcome::Completed
}

/// §19.4 step 4: re-acquire by listing, and say that the new state was inferred rather than seen.
///
/// The gap does not close in any sense that fills it in. `WatchStream::listed` records the
/// version observation resumed at, opens a new segment, and leaves the break in the record
/// forever — so the objects emitted below carry the *next* segment number and `continuous =
/// false`, which is the whole of §19.4's prohibition expressed as two fields.
fn reacquire(
    ctx: &mut Ctx<'_>,
    session: &mut Session,
    watched: &Watched<'_>,
    gvr: &Gvr,
    scope: &Scope,
) -> Outcome {
    let listed = match query::converse(ctx, watched.endpoint, Relist { gvr, scope }) {
        Ok(listed) => listed,
        Err(error) => return Outcome::Failed(error),
    };
    let freshness = listed.freshness().clone();
    if let Err(refused) = session.synchronise(gvr, scope, listed) {
        return Outcome::Failed(unacquirable(&refused));
    }
    let objects: Vec<Object> = session
        .watch_stream(gvr, scope)
        .map(|stream| stream.objects().cloned().collect())
        .unwrap_or_default();
    for object in objects {
        match deliver(
            ctx,
            session,
            watched,
            gvr,
            scope,
            &freshness,
            "listed",
            Some(object),
        ) {
            Delivered::Continue => {}
            Delivered::Stopped(outcome) => return outcome,
        }
    }
    Outcome::Completed
}

/// Whether the caller should keep going, or stop with this outcome.
enum Delivered {
    /// The record reached the host and the next one may be built.
    Continue,
    /// The invocation ended — cancelled, or refused.
    Stopped(Outcome),
}

/// Builds one change record and emits it under the host's credit.
#[allow(
    clippy::too_many_arguments,
    reason = "\
    every argument is a distinct fact the record carries and none of them can be derived from \
    another: the collection, the scope and the freshness come from the acquisition, the word and \
    the object come from the event, and the continuity is read from the stream. Bundling them \
    into a struct would move the argument list rather than shorten it."
)]
fn deliver(
    ctx: &mut Ctx<'_>,
    session: &mut Session,
    watched: &Watched<'_>,
    gvr: &Gvr,
    scope: &Scope,
    freshness: &Freshness,
    class: &str,
    object: Option<Object>,
) -> Delivered {
    if ctx.cancelled() {
        return Delivered::Stopped(Outcome::Cancelled);
    }
    // §22 and Gate I: a watched Secret is a Secret. There is one door into the emission path and
    // a change stream does not get a second one.
    let guarded = match object.map(Guarded::hold).transpose() {
        Ok(guarded) => guarded,
        Err(error) => {
            return Delivered::Stopped(Outcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("an object could not be taken across the redaction boundary: {error}"),
                "This is a defect in the Kubernetes provider, not in the cluster.",
            )));
        }
    };
    // §20.2's third origin. A listing is a direct read of the collection; everything after it
    // arrived because the server pushed it, and a reader deciding how much to trust a record is
    // entitled to know which of the two this was.
    let stamped = if class == "listed" {
        freshness.clone()
    } else {
        freshness.as_watch_event()
    };
    let (segment, continuous, state, gap) = continuity(session, gvr, scope);
    let collection = gvr.to_string();
    let asked_about = scope.to_string();
    let change = Change {
        class,
        resource: &collection,
        scope: &asked_about,
        segment,
        continuous,
        sync_state: state.as_str(),
        gap_reason: gap.as_ref().map(|(reason, _)| *reason),
        gap_detail: gap.map(|(_, detail)| detail),
        object: guarded.as_ref(),
    };
    let value = match change_record(watched.target, watched.schema, &change, &stamped) {
        Ok(value) => value,
        Err(error) => {
            return Delivered::Stopped(Outcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!(
                    "a record of `{}` could not be built: {error}",
                    watched.target.schema
                ),
                "This is a defect in the Kubernetes provider's schema table.",
            )));
        }
    };
    match ctx.emit(&value) {
        Ok(()) => Delivered::Continue,
        Err(EmitError::Cancelled) => Delivered::Stopped(Outcome::Cancelled),
        Err(error) => Delivered::Stopped(Outcome::Failed(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("the host refused a record: {error}"),
            "The stream ended before the query did.",
        ))),
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
        let core = query::document(session, client, self.endpoint, "/api")?;
        let groups = query::document(session, client, self.endpoint, "/apis")?;
        let served = Discovery::builder()
            .core_versions(&core)
            .and_then(|builder| builder.groups(&groups))
            .map_err(|error| {
                failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!("the API server's discovery documents did not read: {error}"),
                    "The endpoint answered, but not as a Kubernetes API server.",
                )
            })?
            .build();
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

/// One watch response, read to its end or to the budget, as the events it carried.
struct Round<'a> {
    endpoint: &'a Endpoint,
    gvr: &'a Gvr,
    scope: &'a Scope,
    from: Option<&'a str>,
    budget: usize,
}

impl Conversation for Round<'_> {
    type Answer = Vec<WatchEvent>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let request = self.endpoint.authorise(
            watch_request(self.gvr, self.scope, &ListOptions::new(), self.from)
                .header("Accept", "application/json"),
        );
        let instance = client.provider_instance().to_owned();
        let mut decoder = WatchDecoder::new(instance);
        let mut stream = client
            .connection()
            .open(&request)
            .map_err(|error| watch_failure(self.gvr, &error))?;

        // §19.4's case that is easy to get wrong in the other direction: a `410` may arrive as
        // the *status* of the response, when the checkpoint names history the server has already
        // discarded, or as an error frame inside a perfectly successful `200` stream, when it
        // expires while the stream is open. Both are the same expiry and neither is a transport
        // failure, so both become the event the state machine reads.
        match stream.status() {
            200 => {}
            410 => return Ok(vec![WatchEvent::Error(WatchFailure::Expired)]),
            403 => return Ok(vec![WatchEvent::Error(WatchFailure::Denied)]),
            other => {
                return Err(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!(
                        "the API server answered a watch on `{}` with {other}",
                        self.gvr
                    ),
                    "A watch that could not be opened is not a collection in which nothing \
                     happened.",
                ));
            }
        }

        let mut events: Vec<WatchEvent> = Vec::new();
        while let Some(chunk) = stream.next_chunk() {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                // The body stopped mid-stream. §19.5: an interruption is not an expiry — the
                // checkpoint is still usable — so it becomes the event that suspends the stream
                // rather than the one that quarantines it.
                Err(error) => {
                    events.push(WatchEvent::Error(WatchFailure::Interrupted(
                        error.to_string(),
                    )));
                    return Ok(events);
                }
            };
            match decoder.decode(&chunk) {
                Ok(decoded) => events.extend(decoded),
                // A frame that arrived whole and could not be read is not an expiry and not a
                // protocol fault to report as one. It suspends the stream, which means the
                // events after it are never filed inside the history before it — and the
                // re-acquisition that follows records the gap that leaves, because a stream
                // re-listed rather than resumed did not observe what produced the new state.
                Err(error) => {
                    events.push(WatchEvent::Error(WatchFailure::Interrupted(
                        error.to_string(),
                    )));
                    return Ok(events);
                }
            }
            if events.len() >= self.budget {
                return Ok(events);
            }
        }
        match decoder.finish() {
            Ok(rest) => events.extend(rest),
            Err(error) => events.push(WatchEvent::Error(WatchFailure::Interrupted(
                error.to_string(),
            ))),
        }
        Ok(events)
    }
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

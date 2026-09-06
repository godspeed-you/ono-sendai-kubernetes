//! What is known to have happened to one object, with the clock behind every time (§39).
//!
//! `temporal.rs` is the vocabulary that keeps five clocks apart. This module is the route from a
//! query to it, and routing it honestly is the hard part of §39 rather than an afterthought: the
//! shape of the answer decides what a reader is able to conclude from it.
//!
//! **The window is the read.** A `Timeline` opens when observation starts and never earlier, so
//! an object created last year and first read a moment ago has a window a moment wide. Every
//! record carries `window_opened` and `window_latest` on this provider's own clock — the only
//! clock this machine owns — and a record without them would let a sequence of observations read
//! as a complete history of the object (§39.2, §39.3).
//!
//! **`reported` is not `observed`.** Everything this route produces is
//! [`Basis::Reported`](ono_provider_kubernetes::temporal::Basis::Reported): a `creationTimestamp`,
//! a condition's `lastTransitionTime`, a `managedFields` entry, an Event's `eventTime` and the
//! snapshot itself are all timestamps read off state. Only a watch event within an unbroken
//! observation period is something this provider witnessed, and this target opens no watch — so a
//! Pod created at 08:00 and first read at 14:00 cannot be filed here as six hours of history. The
//! type makes it impossible rather than the code making it unlikely: `Basis::Observed` is
//! reachable only through `Observation::watched`, and `ReportedSource` has no word for a watch
//! event.
//!
//! **`stamp` is a string beside its `clock`.** There is deliberately no timestamp field a shell
//! could sort. Parsing five machines' clocks into one column produces something that reads as a
//! history of the cluster and is a picture of the skew between those machines (§39.2). The only
//! ordering `temporal.rs` offers is per clock, and it is reached by naming one.
//!
//! **Both kinds of hole travel with the answer.** `gaps` is the stretches observation could not
//! cover, and `not_observed` is the scopes that were never readable — a namespace whose Events
//! are denied is not a namespace in which nothing was reported. A continuous window over a denied
//! scope is not a complete answer, and a record that printed only the window would read as one.

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, Outcome};
use ono_provider_kubernetes::condition;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::temporal::{Observation, ReportedSource, Stamp, Timeline};
use ono_provider_kubernetes::transport::{ByteStream, Client, Clock, SystemClock};
use ono_value::Schema;
use serde_json::Value as Json;

use crate::conditions::named;
use crate::contributions::Target;
use crate::dynamic::Selector;
use crate::events::{self, Reported};
use crate::query::{self, Conversation, Endpoint, Subject};
use crate::records::observation_record;
use crate::sessions::Sessions;

/// Answers a `k8s-timeline` query: one object in, what is known about its times out.
#[must_use]
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let selector = Selector::from_options(ctx.arguments());
    let Some(name) = named(ctx) else {
        return Outcome::Failed(query::unnamed(
            "to assemble a timeline for",
            "--kind Pod --name api-7d9f-abc",
        ));
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
    };
    if ctx.cancelled() {
        return Outcome::Cancelled;
    }

    let read = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            query::converse(
                ctx,
                &endpoint,
                Observed {
                    endpoint: &endpoint,
                    selector: &selector,
                    name: &name,
                    session,
                },
            )
        },
    );
    match read {
        Ok(read) => emit(ctx, target, &schema, read.as_ref()),
        Err(error) => Outcome::Failed(error),
    }
}

/// Resolve the object, read it, and read the Events of its scope.
pub(crate) struct Observed<'a> {
    pub(crate) endpoint: &'a Endpoint,
    pub(crate) selector: &'a Selector,
    pub(crate) name: &'a str,
    pub(crate) session: &'a mut Session,
}

impl Conversation for Observed<'_> {
    type Answer = Option<(Subject, Reported)>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        let Some(subject) =
            query::subject(session, client, self.endpoint, self.selector, self.name)?
        else {
            return Ok(None);
        };
        // A scope whose Events cannot be read is a gap on the answer rather than a refusal of it:
        // the object's own timestamps are still worth having, and the coverage says what is
        // missing beside them.
        let reported = events::read(session, client, self.endpoint, &subject.scope)?;
        Ok(Some((subject, reported)))
    }
}

/// Builds the timeline of one object from everything a read can honestly contribute (§39.1).
///
/// Five of §39.1's six sources, and the sixth is deliberately absent: a watch event is the only
/// thing this provider *witnesses*, and this route opens no watch. Everything below is a
/// timestamp somebody else wrote, carried with the clock that wrote it.
pub(crate) fn assemble(subject: &Subject, reported: &Reported, clock: &impl Clock) -> Timeline {
    let object = subject.guarded.object();
    let identity = object.identity();
    let mut timeline = Timeline::opened(
        subject.freshness.provider_instance(),
        subject.scope.clone(),
        clock,
    );

    // The read itself (§39.4). A snapshot proves that state was so at a moment; it never proves
    // the sequence of changes that reached it, which is why its basis is `reported` even though
    // its stamp is this machine's own clock.
    timeline.record(Observation::reported(
        identity.clone(),
        ReportedSource::ResourceSnapshot,
        Stamp::observed(subject.freshness.observed_at()),
        format!("read at its own endpoint as {}", subject.resource.gvr()),
    ));

    // §14.1's two metadata instants, on the API server's clock.
    if let Some(created) = Observation::of_creation(object) {
        timeline.record(created);
    }
    if let Some(deleted) = object
        .field("/metadata/deletionTimestamp")
        .and_then(Json::as_str)
    {
        timeline.record(Observation::reported(
            identity.clone(),
            ReportedSource::ObjectMetadata,
            Stamp::api_server(deleted),
            "deletion accepted",
        ));
    }

    // §37.1's transitions. The clock is unattributed: `status.conditions` does not say which
    // controller wrote an entry, so two conditions may be two machines' idea of the time.
    for observed in condition::conditions(object) {
        if let Some(transition) = Observation::of_condition(&identity, &observed) {
            timeline.record(transition);
        }
    }

    // §14.7's field managers, each with the time the API server recorded for the apply.
    for (manager, time) in field_manager_times(object) {
        timeline.record(Observation::reported(
            identity.clone(),
            ReportedSource::ManagedField,
            Stamp::api_server(time),
            manager,
        ));
    }

    // §38's Events, each on the clock of whichever component reported it.
    for (_, event) in &reported.read {
        if let Some(observed) = Observation::of_event(&identity, event) {
            timeline.record(observed);
        }
    }

    // The other kind of hole: a scope that was never readable is not a scope in which nothing was
    // reported (§21.4, §4 invariant 13).
    for gap in reported.coverage.gaps() {
        timeline.coverage_mut().record(gap.clone());
    }
    timeline.advance(clock);
    timeline
}

/// Every `managedFields` entry that recorded a time, as the manager that wrote it (§14.7).
///
/// Entries without a time are skipped rather than stamped with anything: a manager with no
/// recorded moment is a manager, and giving it one would be this provider inventing an instant.
fn field_manager_times(object: &Object) -> Vec<(String, String)> {
    let Some(entries) = object
        .field("/metadata/managedFields")
        .and_then(Json::as_array)
    else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let time = entry.get("time")?.as_str()?.to_owned();
            let manager = entry
                .get("manager")
                .and_then(Json::as_str)
                .unwrap_or("an unnamed manager");
            let operation = entry
                .get("operation")
                .and_then(Json::as_str)
                .unwrap_or("wrote");
            Some((format!("{manager} {operation}"), time))
        })
        .collect()
}

/// Streams one record per observation, each carrying the window it was made in.
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    read: Option<&(Subject, Reported)>,
) -> Outcome {
    // An object that is not there has no observations, and that is an answer rather than a
    // refusal (§21.4 `absent`).
    let Some((subject, reported)) = read else {
        return Outcome::Completed;
    };
    let timeline = assemble(subject, reported, &SystemClock);
    for observation in timeline.observations() {
        if ctx.cancelled() {
            return Outcome::Cancelled;
        }
        let value = match query::built(
            target,
            observation_record(
                target,
                schema,
                &subject.guarded,
                observation,
                &timeline,
                &subject.freshness,
            ),
        ) {
            Ok(value) => value,
            Err(outcome) => return outcome,
        };
        if let Err(outcome) = query::deliver(ctx, &value) {
            return outcome;
        }
    }
    Outcome::Completed
}

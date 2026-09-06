//! The Events a cluster reported about one object, and everything they are not (§38).
//!
//! `events.rs` in the domain layer reads both of §38.2's representations, preserves counts
//! without inventing occurrences, refuses to attach an Event to a later lifetime of the same
//! name, and answers an empty search as *not observed* rather than as absent. All of that was
//! true in a library nothing imported. This module is the route to a user, and its whole job is
//! to carry those refusals across the boundary rather than to deliver data past them.
//!
//! **A count is a count.** An Event the server aggregated 47 times arrives as **one** record with
//! `recorded_count: 47` and `aggregate: true`. There is no expansion here and there is none in
//! the domain module: Kubernetes aggregates precisely so that the individual occurrences need not
//! be stored, so 46 of them were never observed and manufacturing them would produce records a
//! reader could not tell from observed ones (§38.4).
//!
//! **Nothing observed is not nothing happened.** A search that matches no Event ends the
//! invocation with §38.6 stated, rather than completing with an empty stream. An empty stream is
//! read as absence by every consumer that has ever been written, and retention is minutes to
//! hours, delivery is best-effort, and these observations were never a complete query of
//! anything. `Found::NotObserved` carries an [`Outcome`] that can never be
//! [`Outcome::Absent`](ono_provider_kubernetes::coverage::Outcome::Absent), and this is where that
//! type reaches somebody. ADR-0025 records the decision.
//!
//! **An Event belongs to a lifetime, not to a name.** The subject is read at its own endpoint
//! first, and the filter is `Event::regards`, which matches on UID where both sides carry one and
//! refuses across provider instances. A Pod deleted and recreated under one name is two Pods, and
//! the old one's Events are about decisions the new one never saw (§4 invariants 4–5, Gate J).

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, Outcome};
use ono_provider_kubernetes::coverage::{Coverage, Scope};
use ono_provider_kubernetes::discovery::{self, Discovery, Resource, Verb};
use ono_provider_kubernetes::events::{Event, Found, Observations};
use ono_provider_kubernetes::object::Identity;
use ono_provider_kubernetes::place::Place;
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{ByteStream, Client, Freshness, ListOptions};
use ono_value::Schema;

use crate::conditions::named;
use crate::contributions::Target;
use crate::dynamic::Selector;
use crate::query::{
    self, Conversation, Endpoint, REFUSED, REFUSED_CODE, Subject, UNAVAILABLE, UNAVAILABLE_CODE,
    UNSUPPORTED, UNSUPPORTED_CODE, failure,
};
use crate::records::event_record;
use crate::sessions::Sessions;

/// How many Events one page asks the API server for.
const PAGE_SIZE: u32 = 500;

/// The two representations §38.2 keeps readable, the preferred one first.
///
/// Both, because a cluster inside the support window of §5.1 may serve only the core one, and
/// because the newer group renamed almost every field — a provider that knew one spelling would
/// report a blank Event from half the clusters it can talk to. The order is §38.2's preference
/// and not a fallback chain invented here.
const REPRESENTATIONS: &[(&str, &str)] = &[("events.k8s.io", "Event"), ("", "Event")];

/// Answers a `k8s-event` query: one object in, the Events regarding it out.
#[must_use]
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let selector = Selector::from_options(ctx.arguments());
    let Some(name) = named(ctx) else {
        return Outcome::Failed(query::unnamed(
            "the Events are about",
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
                Regarding {
                    endpoint: &endpoint,
                    selector: &selector,
                    name: &name,
                    session,
                },
            )
        },
    );
    match read {
        Ok(read) => emit(ctx, target, &schema, read),
        Err(error) => Outcome::Failed(error),
    }
}

/// What one read of a cluster's Events came to.
///
/// The Event objects are kept beside the parsed Events because both are needed and neither is
/// derivable from the other at emission time: §14's metadata projection is the *object's*, and
/// what the Event says is the parse's.
pub(crate) struct Reported {
    /// One entry per Event read, in the order the server sent it. Arrival order, which is not
    /// chronology and is not causality.
    pub(crate) read: Vec<(Guarded, Event)>,
    /// What the search of the Events collection did and did not reach (§21.4).
    pub(crate) coverage: Coverage,
    /// What §17.1 requires the read of the Events to state about itself.
    pub(crate) freshness: Freshness,
}

impl Reported {
    /// The Events, as the bag the domain layer models them as.
    ///
    /// A bag rather than a history: it offers no sort, no earliest and no latest, because their
    /// timestamps come from the clocks of the components that reported them, delivery is
    /// unordered, and retention has already discarded part of what happened (§38.1, §39.2).
    pub(crate) fn observations(&self) -> Observations {
        Observations::read(self.read.iter().map(|(_, event)| event.clone()).collect())
    }
}

/// Resolve the object, read it, then read the Events of its namespace.
struct Regarding<'a> {
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    name: &'a str,
    session: &'a mut Session,
}

impl Conversation for Regarding<'_> {
    type Answer = Option<(Subject, Reported)>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        let Some(subject) =
            query::subject(session, client, self.endpoint, self.selector, self.name)?
        else {
            return Ok(None);
        };
        let reported = read(session, client, self.endpoint, &subject.scope)?;
        Ok(Some((subject, reported)))
    }
}

/// Reads the Events of one scope, from whichever representation the cluster serves (§38.2).
///
/// A scope that serves neither is a refusal rather than an empty answer: a cluster with no Events
/// API is a cluster nobody asked, and §21.4 keeps the two apart.
///
/// # Errors
///
/// Whatever kept the Events from being read, in the vocabulary of core's `errors.yaml`.
pub(crate) fn read<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    scope: &Scope,
) -> Result<Reported, WireError> {
    let served = query::served(session, client, endpoint)?;
    let mut resource = None;
    for (group, kind) in REPRESENTATIONS {
        if let Some(found) = serving(session, client, endpoint, &served, group, kind)?
            && found.supports(Verb::List)
        {
            resource = Some(found);
            break;
        }
    }
    let Some(resource) = resource else {
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            "this cluster serves neither `events.k8s.io` Events nor core Events that may be \
             listed"
                .to_owned(),
            "An unserved API is not a cluster in which nothing was reported: nothing was asked, \
             so nothing is known (specification section 21.4).",
        ));
    };
    let scope = match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => scope.clone(),
    };
    let mut options = ListOptions::new().limit(PAGE_SIZE);
    if let Some(pages) = endpoint.max_pages {
        options = options.max_pages(pages);
    }
    // Buffered rather than walked, and §18.5 is not being ignored here. The question is "what
    // happened to *this object*", and answering it means asking the whole bag of Events whether
    // it observed that identity — §38.6's `Found::NotObserved`, which is the difference between
    // "no Events about it" and "no Events read". A streaming reader would have to answer that
    // question before it had seen the last Event, which is to say guess at it.
    let listing = client.list(resource.gvr(), &scope, &options);
    let coverage = listing.coverage().clone();
    let freshness = listing.freshness().clone();
    let mut read = Vec::new();
    for object in listing.into_objects() {
        // §22 and Gate I: an Event's `note` is a message a controller wrote and may quote
        // anything, so it crosses the same one door every other object crosses.
        let guarded = query::hold(object)?;
        match Event::from_object(guarded.object()) {
            Ok(event) => read.push((guarded, event)),
            // A collection of Events answered with something that is not one. Kept as a refusal
            // rather than skipped: silently dropping it would report fewer Events than the server
            // sent, which is the shape of an absence this provider must not manufacture.
            Err(error) => {
                return Err(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!("the Events collection answered with something else: {error}"),
                    "The endpoint answered, but not as the collection discovery named.",
                ));
            }
        }
    }
    Ok(Reported {
        read,
        coverage,
        freshness,
    })
}

/// The resource serving one kind, or [`None`] where this cluster serves none of it.
fn serving<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    group: &str,
    kind: &str,
) -> Result<Option<Resource>, WireError> {
    let Some(version) = served.preferred_version(group) else {
        return Ok(None);
    };
    let group_version = query::group_version_of(group, version);
    let discovery = query::resource_list(session, client, endpoint, &group_version)?;
    Ok(discovery.by_kind(&group_version, kind).cloned())
}

/// Streams one record per Event regarding the subject, and refuses to answer nothing with silence.
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    read: Option<(Subject, Reported)>,
) -> Outcome {
    // An object that is not there is the one outcome of §21.4 that is evidence of absence, and an
    // Event cannot be attached to a lifetime that does not exist (§4 invariants 4–5). No records,
    // and completed.
    let Some((subject, reported)) = read else {
        return Outcome::Completed;
    };
    let identity = subject.guarded.object().identity();
    let observations = reported.observations();
    // The decision about the empty case belongs to `Found`, which is the type §38.6 lives in: its
    // `NotObserved` arm carries an outcome that can never be `Absent`, whatever the input.
    let matched: Vec<Identity> = match observations.about(&identity) {
        Found::Observed(events) => events
            .iter()
            .map(|event| event.identity().clone())
            .collect(),
        Found::NotObserved(outcome) => return not_observed(&identity, outcome.as_str()),
    };
    let instance = reported.freshness.provider_instance().to_owned();
    for (guarded, event) in &reported.read {
        if !matched.contains(event.identity()) {
            continue;
        }
        if ctx.cancelled() {
            return Outcome::Cancelled;
        }
        // An address for what the Event is about, where the reference names something completely
        // enough to be looked up. Null where it does not: an Event whose reference names nothing is still an
        // observation and is still kept, rather than dropped for being unaddressable (§38.3).
        let regarding = event
            .regarding()
            .and_then(|target| Place::of_target(&instance, target).ok());
        let value = match query::built(
            target,
            event_record(
                target,
                schema,
                guarded,
                event,
                regarding.as_ref(),
                &reported.freshness,
            ),
        ) {
            Ok(value) => value,
            Err(outcome) => return outcome,
        };
        if let Err(outcome) = query::deliver(ctx, &value) {
            return outcome;
        }
    }
    if reported.coverage.is_complete() {
        return Outcome::Completed;
    }
    Outcome::Failed(failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "the Events could not all be read: {}",
            reported.coverage.describe()
        ),
        "The Events that did arrive are true. Events are best-effort and briefly retained even \
         when the read is complete, so a short read is short twice over (specification sections \
         38.1 and 21.4).",
    ))
}

/// §38.6, as the answer to a search that matched nothing.
///
/// A failure rather than an empty stream, because an empty stream of records is read as absence
/// by every consumer that has ever been written — and the absence of an Event never proves that
/// nothing happened. Retention is minutes to hours, delivery is best-effort, and these
/// observations were never a complete query of anything. ADR-0025.
///
/// `contribution.refused` since ADR-0028: this is the package's own rule about what an empty
/// answer proves, and the code that used to carry it claimed the cluster had not answered.
fn not_observed(subject: &Identity, outcome: &str) -> Outcome {
    Outcome::Failed(failure(
        REFUSED_CODE,
        REFUSED,
        format!(
            "no Event regarding `{}/{}` was observed: {outcome}",
            subject.gvk().kind(),
            subject.name()
        ),
        "This is not evidence that nothing happened. Kubernetes Events are best-effort and \
         retained for minutes to hours, so what is not here may have been reported and discarded, \
         or never reported at all (specification section 38.6).",
    ))
}

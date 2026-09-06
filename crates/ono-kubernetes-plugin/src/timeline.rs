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
//! **`reported` is not `observed`.** Every timestamp this route *reads* is
//! [`Basis::Reported`](ono_provider_kubernetes::temporal::Basis::Reported): a `creationTimestamp`,
//! a condition's `lastTransitionTime`, a `managedFields` entry, an Event's `eventTime` and the
//! snapshot itself are all timestamps somebody else wrote onto state. A Pod created at 08:00 and
//! first read at 14:00 is not filed here as six hours of history, and no amount of neighbouring
//! evidence upgrades it: `ReportedSource` has no word for a watch event, so the mistake does not
//! typecheck (§39.2).
//!
//! **What the session watched is included, and only that.** This target opens no watch, and it no
//! longer has to: if `k8s-change` has watched this object's collection in this process, the
//! session still holds the stream, and `Timeline::include_watch` takes the changes it *witnessed*
//! of this object into the answer with `basis: observed` and `source: watch-event` (§39.3, §61.6).
//! Before that composition existed, §39.3's history was observable through `k8s-change` and
//! retrievable through nothing. Three refusals travel with it: only this object's changes cross
//! over, matched on the lifetime identity rather than the name (§4 invariants 4–5); the objects a
//! list put in the cache are not history, because a list is one look at current state (§39.2); and
//! each change is filed under the unbroken period it arrived in, so a timeline that spans a
//! `410 Gone` says so and never runs the two sides together (§4 invariant 14).
//!
//! **A witnessed change carries a position and no instant.** `watch.rs` records which change
//! arrived and in what order and keeps no arrival time, so the record's `clock` is `unclocked`,
//! its `stamp` is empty and `placeable` is false, and the position it was seen at is in `detail`
//! — a `resourceVersion`, which is a position and never a time (§14.3, §4 invariant 6). Stamping
//! them with the moment the answer was assembled would invent acquisition times that sort
//! convincingly against this machine's real readings. What *is* measured is the moment the session
//! last observed the collection, and it widens `window_opened` rather than being attached to any
//! one change.
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
use ono_provider_kubernetes::transport::{ByteStream, Client, Clock, ObservedAt, SystemClock};
use ono_provider_kubernetes::watch::WatchStream;
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
                Composed {
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
        read(
            self.session,
            client,
            self.endpoint,
            self.selector,
            self.name,
        )
    }
}

/// The same read, and then whatever the session's watch witnessed of the object's collection.
///
/// A conversation of its own rather than a flag on [`Observed`], because the two answer different
/// questions: `why.rs` asks what is *stated* about an object and reasons over that, while this
/// target asks what is *known to have happened* to it — and only the second may take the watch
/// into the answer. The stream is read after the conversation's I/O and before the session lock is
/// released, which is the only point at which both the object and the session are in hand.
pub(crate) struct Composed<'a> {
    pub(crate) endpoint: &'a Endpoint,
    pub(crate) selector: &'a Selector,
    pub(crate) name: &'a str,
    pub(crate) session: &'a mut Session,
}

impl Conversation for Composed<'_> {
    type Answer = Option<(Subject, Timeline)>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        let Some((subject, reported)) =
            read(session, client, self.endpoint, self.selector, self.name)?
        else {
            return Ok(None);
        };
        // The watch this session already holds over the object's own collection and scope, where
        // one has run in this process (§19.6, §39.3). Nothing is opened here: a target that
        // started a watch to answer a timeline would be watching on behalf of a query that has
        // already ended.
        let gvr = subject.resource.gvr().clone();
        let watched = session
            .watch_stream(&gvr, &subject.scope)
            .zip(session.watch_observed_at(&gvr, &subject.scope));
        let timeline = compose(&subject, &reported, watched, &SystemClock);
        Ok(Some((subject, timeline)))
    }
}

/// Reads the object a timeline is about, and the Events of its scope.
fn read<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    selector: &Selector,
    name: &str,
) -> Result<Option<(Subject, Reported)>, WireError> {
    let Some(subject) = query::subject(session, client, endpoint, selector, name)? else {
        return Ok(None);
    };
    // A scope whose Events cannot be read is a gap on the answer rather than a refusal of it:
    // the object's own timestamps are still worth having, and the coverage says what is
    // missing beside them.
    let reported = events::read(session, client, endpoint, &subject.scope)?;
    Ok(Some((subject, reported)))
}

/// The read's timeline, plus what a watch on the object's collection witnessed of it (§39.3).
///
/// The whole of the composition, in one call so that neither half can be taken without the other:
/// [`assemble`] answers what the object *states* about its own times, and `include_watch` adds
/// what this provider *saw happen* while it was watching. `None` is the ordinary case — no watch
/// has run in this process — and it produces exactly the answer this target produced before the
/// composition existed.
pub(crate) fn compose(
    subject: &Subject,
    reported: &Reported,
    watched: Option<(&WatchStream, ObservedAt)>,
    clock: &impl Clock,
) -> Timeline {
    let mut timeline = assemble(subject, reported, clock);
    if let Some((stream, observed_at)) = watched {
        timeline.include_watch(&subject.guarded.object().identity(), stream, observed_at);
    }
    timeline
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
    read: Option<&(Subject, Timeline)>,
) -> Outcome {
    // An object that is not there has no observations, and that is an answer rather than a
    // refusal (§21.4 `absent`).
    let Some((subject, timeline)) = read else {
        return Outcome::Completed;
    };
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
                timeline,
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "a test states its preconditions directly (AGENTS.md section 16)"
    )]

    use ono_provider_kubernetes::coverage::{Coverage, Scope};
    use ono_provider_kubernetes::discovery::Discovery;
    use ono_provider_kubernetes::kubeconfig::Credential;
    use ono_provider_kubernetes::temporal::Basis;
    use ono_provider_kubernetes::transport::{EndpointCategory, FixedClock, Freshness, ObservedAt};
    use ono_provider_kubernetes::watch::{ResourceVersion, WatchEvent, WatchFailure};
    use ono_value::Value;

    use super::{Arc, Object, Reported, Session, Subject, compose};

    const INSTANCE: &str = "kubernetes:test";

    /// What the API server says serves a Pod. Discovery answers it even for a kind that has been
    /// in the core group since v1 (§4 invariants 1–2).
    const SERVED: &str = r#"{
      "kind":"APIResourceList","groupVersion":"v1",
      "resources":[{"name":"pods","singularName":"pod","namespaced":true,"kind":"Pod",
        "verbs":["get","list","watch"]}]
    }"#;

    const POD: &str = r#"{
      "apiVersion":"v1","kind":"Pod",
      "metadata":{"name":"checkout-7f9d","namespace":"shop","uid":"pod-1",
        "resourceVersion":"9000","creationTimestamp":"2026-09-05T08:00:00Z"}
    }"#;

    fn pod_at(version: &str) -> Object {
        Object::parse(
            INSTANCE,
            &POD.replace(
                "\"resourceVersion\":\"9000\"",
                &format!("\"resourceVersion\":\"{version}\""),
            ),
        )
        .expect("the fixture is a well-formed Pod")
    }

    fn subject() -> Subject {
        let discovery = Discovery::builder()
            .resources(SERVED)
            .expect("the fixture is an APIResourceList")
            .build();
        let resource = discovery
            .by_kind("v1", "Pod")
            .expect("the fixture serves Pods")
            .clone();
        let object = pod_at("9000");
        let freshness = Freshness::direct_read(
            ObservedAt::from_unix_millis(50_000),
            Some("9000".to_owned()),
            INSTANCE,
            Scope::in_namespace("shop"),
            EndpointCategory::Core,
        );
        Subject {
            resource,
            scope: Scope::in_namespace("shop"),
            guarded: crate::query::hold(object).expect("a Pod is not a Secret"),
            freshness,
        }
    }

    /// A scope whose Events were read and held none.
    fn reported() -> Reported {
        Reported {
            read: Vec::new(),
            coverage: Coverage::complete(Scope::in_namespace("shop")),
            freshness: Freshness::direct_read(
                ObservedAt::from_unix_millis(50_000),
                None,
                INSTANCE,
                Scope::in_namespace("shop"),
                EndpointCategory::Core,
            ),
        }
    }

    fn session() -> Session {
        Session::for_endpoint(
            INSTANCE,
            "https://cluster.test:6443",
            Some("shop"),
            Credential::Anonymous,
        )
    }

    #[test]
    fn should_answer_only_reported_times_when_no_watch_has_run_in_this_process() {
        // The ordinary case, and the one that must not change: nothing has watched this
        // collection, so the answer is what the object states about its own times and nothing is
        // presented as witnessed (§39.2).
        let timeline = compose(
            &subject(),
            &reported(),
            None,
            &FixedClock::at_unix_millis(50_000),
        );

        assert!(timeline.observed().is_empty());
        assert!(timeline.periods().is_empty());
        assert!(
            timeline
                .reported()
                .iter()
                .any(|observation| observation.basis() == Basis::Reported),
            "the creation timestamp and the snapshot are still read"
        );
    }

    #[test]
    fn should_take_the_watch_the_session_holds_over_the_objects_own_collection() {
        // §39.3 and §61.6 at the boundary. `k8s-change` watched `pods` in `shop` earlier in this
        // process and the session still holds the stream; the timeline route finds it under the
        // object's own GVR and scope — never under the kind's name, which is not a collection
        // identity (§13.1) — and the changes it witnessed reach the answer as observed.
        let mut session = session();
        let subject = subject();
        let gvr = subject.resource.gvr().clone();
        {
            let stream = session.watch(&gvr, &subject.scope);
            stream.listed(vec![pod_at("9000")], ResourceVersion::new("9000"));
            stream.observe(WatchEvent::Modified(pod_at("9005")));
            stream.observe(WatchEvent::Error(WatchFailure::Expired));
        }

        let watched = session
            .watch_stream(&gvr, &subject.scope)
            .zip(session.watch_observed_at(&gvr, &subject.scope));
        assert!(
            watched.is_some(),
            "the session holds the stream between calls"
        );
        let timeline = compose(
            &subject,
            &reported(),
            watched,
            &FixedClock::at_unix_millis(50_000),
        );

        assert_eq!(timeline.observed().len(), 1);
        assert_eq!(timeline.observed()[0].source().as_str(), "watch-event");
        assert!(
            !timeline.is_continuous(),
            "the expiry is a hole in the period this answer covers (§4 invariant 14)"
        );
        assert_eq!(timeline.gaps()[0].reason().as_str(), "watch_expired_410");
    }

    #[test]
    fn should_emit_a_witnessed_change_as_a_record_with_no_timestamp_to_sort_on() {
        // The composition has to survive into what a user receives. A witnessed change has no
        // instant — `watch.rs` kept the order and not the times — so the record says so rather
        // than carrying a fabricated one: `clock` is `unclocked`, `stamp` is empty, `placeable` is
        // false, and the position it was seen at is in `detail` as a position (§14.3, §39.3).
        let mut session = session();
        let subject = subject();
        let gvr = subject.resource.gvr().clone();
        {
            let stream = session.watch(&gvr, &subject.scope);
            stream.listed(vec![pod_at("9000")], ResourceVersion::new("9000"));
            stream.observe(WatchEvent::Modified(pod_at("9005")));
        }
        let watched = session
            .watch_stream(&gvr, &subject.scope)
            .zip(session.watch_observed_at(&gvr, &subject.scope));
        let timeline = compose(
            &subject,
            &reported(),
            watched,
            &FixedClock::at_unix_millis(50_000),
        );

        let target = crate::contributions::target("k8s-timeline").expect("the package has one");
        let schema = Arc::new(
            target
                .schema_contribution()
                .to_schema()
                .expect("the contributed schema is well formed"),
        );
        let witnessed = timeline
            .observed()
            .first()
            .copied()
            .expect("the watch witnessed one change")
            .clone();
        let Ok(Value::Record(record)) = crate::records::observation_record(
            target,
            &schema,
            &subject.guarded,
            &witnessed,
            &timeline,
            &subject.freshness,
        ) else {
            panic!("every field the table names is one the schema declares");
        };

        assert_eq!(record.get("basis"), Some(&Value::String("observed".into())));
        assert_eq!(
            record.get("source"),
            Some(&Value::String("watch-event".into()))
        );
        assert_eq!(
            record.get("clock"),
            Some(&Value::String("unclocked".into()))
        );
        assert_eq!(
            record.get("stamp"),
            Some(&Value::String("".into())),
            "no clock read it, so there is no reading to show and none is invented"
        );
        assert_eq!(record.get("placeable"), Some(&Value::Bool(false)));
        let Some(Value::String(detail)) = record.get("detail") else {
            panic!("a witnessed change says what it was");
        };
        assert!(
            detail.contains("modified") && detail.contains("9005"),
            "the change and the position it was seen at: {detail}"
        );
    }

    #[test]
    fn should_not_take_a_watch_over_another_scope_as_this_objects_history() {
        // §6.5 and §9.2. A watch over `payments` is a watch over another set of objects, and a
        // lookup that ignored the scope would file another namespace's changes as this Pod's
        // history. The key is the collection *and* the scope, and both have to match.
        let mut session = session();
        let subject = subject();
        let gvr = subject.resource.gvr().clone();
        {
            let elsewhere = session.watch(&gvr, &Scope::in_namespace("payments"));
            elsewhere.listed(Vec::new(), ResourceVersion::new("9000"));
            elsewhere.observe(WatchEvent::Modified(pod_at("9005")));
        }

        let watched = session
            .watch_stream(&gvr, &subject.scope)
            .zip(session.watch_observed_at(&gvr, &subject.scope));
        assert!(watched.is_none());
        let timeline = compose(
            &subject,
            &reported(),
            watched,
            &FixedClock::at_unix_millis(50_000),
        );
        assert!(timeline.observed().is_empty());
    }
}

//! Kubernetes Events as supplemental evidence, and as nothing more than that.
//!
//! Specification §38, §39.1 and §63.6. Events are best-effort observations with a retention the
//! cluster chooses, and the specification spends five of its six subsections saying what they are
//! not: not an audit log, not a causal history, not stable machine semantics, and never proof that
//! something did not happen.
//!
//! So these tests are mostly refusals, and each one names the plausible mistake it stops. The two
//! that matter most: an aggregated Event records a *count*, and expanding it into that many
//! occurrences invents observations nobody made (§38.4); and an empty search of a set of Events is
//! not evidence that the thing never happened (§38.6).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::coverage::Outcome;
use ono_provider_kubernetes::events::{Event, Level, Observations, Representation};
use ono_provider_kubernetes::object::Object;

/// The stable representation §38.2 prefers, aggregated into a series.
const EVENTS_V1: &str = r#"{
  "apiVersion":"events.k8s.io/v1","kind":"Event",
  "metadata":{"name":"checkout-7f9d.17c1","namespace":"shop","uid":"ev-1","resourceVersion":"9001"},
  "eventTime":"2026-09-05T09:14:02.113344Z",
  "reportingController":"default-scheduler","reportingInstance":"default-scheduler-cp-1",
  "action":"Binding","reason":"FailedScheduling","type":"Warning",
  "note":"0/3 nodes are available: 3 Insufficient cpu.",
  "regarding":{"apiVersion":"v1","kind":"Pod","namespace":"shop","name":"checkout-7f9d","uid":"pod-1"},
  "related":{"apiVersion":"v1","kind":"Node","name":"worker-03","uid":"node-1"},
  "series":{"count":47,"lastObservedTime":"2026-09-05T09:41:55.000000Z"}
}"#;

/// The core representation §38.2 still reads, aggregated by `count` rather than by a series.
const CORE_V1: &str = r#"{
  "apiVersion":"v1","kind":"Event",
  "metadata":{"name":"checkout-7f9d.17c0","namespace":"shop","uid":"ev-2"},
  "involvedObject":{"apiVersion":"v1","kind":"Pod","namespace":"shop","name":"checkout-7f9d","uid":"pod-1"},
  "reason":"BackOff","message":"Back-off restarting failed container",
  "type":"Warning","count":12,
  "firstTimestamp":"2026-09-05T08:00:00Z","lastTimestamp":"2026-09-05T09:40:00Z",
  "source":{"component":"kubelet","host":"worker-03"}
}"#;

const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"checkout-7f9d","namespace":"shop","uid":"pod-1"},
  "spec":{}
}"#;

/// The same name, a later lifetime (§16.3).
const RECREATED_POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"checkout-7f9d","namespace":"shop","uid":"pod-9"},
  "spec":{}
}"#;

fn object(json: &str) -> Object {
    Object::parse("kubernetes:prod-eu", json).expect("the fixture parses")
}

fn event(json: &str) -> Event {
    Event::from_object(&object(json)).expect("the fixture is an Event")
}

#[test]
fn should_read_the_stable_representation_the_specification_prefers() {
    // §38.2. `events.k8s.io/v1` renamed almost every field the core Event used, and a provider
    // that read only the old names would report a blank Event from a current cluster.
    let event = event(EVENTS_V1);

    assert_eq!(event.representation(), Representation::Events);
    assert_eq!(event.reason(), Some("FailedScheduling"));
    assert_eq!(
        event.note(),
        Some("0/3 nodes are available: 3 Insufficient cpu.")
    );
    assert_eq!(event.action(), Some("Binding"));
    assert_eq!(event.level(), &Level::Warning);
    assert_eq!(event.event_time(), Some("2026-09-05T09:14:02.113344Z"));
    assert_eq!(event.regarding().map(|at| at.name()), Some("checkout-7f9d"));
    assert_eq!(event.related().map(|at| at.name()), Some("worker-03"));
}

#[test]
fn should_read_the_core_representation_alike() {
    // §38.2 keeps the compatible core representation readable, because a cluster inside the
    // support window may serve only that one. The two spell everything differently —
    // `involvedObject` against `regarding`, `message` against `note`, `source` against
    // `reportingController` — and a caller should not have to know which it got.
    let event = event(CORE_V1);

    assert_eq!(event.representation(), Representation::Core);
    assert_eq!(event.reason(), Some("BackOff"));
    assert_eq!(event.note(), Some("Back-off restarting failed container"));
    assert_eq!(event.level(), &Level::Warning);
    assert_eq!(event.regarding().map(|at| at.name()), Some("checkout-7f9d"));
    assert_eq!(event.regarding().and_then(|at| at.uid()), Some("pod-1"));
}

#[test]
fn should_say_which_representation_it_read_and_which_one_is_preferred() {
    // §38.2 states a preference, so a caller choosing between two served APIs needs the preference
    // readable. It is also what makes a `deprecatedCount` legible as the old field it is.
    assert!(Representation::Events.is_preferred());
    assert!(!Representation::Core.is_preferred());
    assert_eq!(Representation::Events.as_str(), "events.k8s.io");
}

#[test]
fn should_preserve_an_aggregate_count_without_fabricating_the_occurrences() {
    // §38.4, and the mistake most likely to be made: the server aggregated 47 scheduling failures
    // into one object with a count and two endpoints, so 46 of them were never observed as
    // individual facts. Expanding the count into 47 entries would manufacture observations — and
    // they would look exactly like ones that had been seen.
    let observations = Observations::read(vec![event(EVENTS_V1)]);

    assert_eq!(observations.seen().len(), 1);
    let occurrences = observations.seen()[0].occurrences();
    assert_eq!(occurrences.recorded_count(), Some(47));
    assert!(occurrences.is_aggregate());
}

#[test]
fn should_keep_a_series_apart_from_a_plain_count() {
    // §38.4: `count` and `series` are two different upstream mechanisms with different meanings —
    // a total, against an ongoing series with a last-observed time. Merging them into one number
    // would lose the fact that the series is still running.
    let series = event(EVENTS_V1);
    let counted = event(CORE_V1);

    assert!(series.occurrences().is_series());
    assert_eq!(series.occurrences().series_count(), Some(47));
    assert_eq!(
        series.occurrences().series_last_observed(),
        Some("2026-09-05T09:41:55.000000Z")
    );

    assert!(!counted.occurrences().is_series());
    assert_eq!(counted.occurrences().series_count(), None);
    assert_eq!(counted.occurrences().recorded_count(), Some(12));
    assert_eq!(
        counted.occurrences().first_seen(),
        Some("2026-09-05T08:00:00Z")
    );
    assert_eq!(
        counted.occurrences().last_seen(),
        Some("2026-09-05T09:40:00Z")
    );
}

#[test]
fn should_not_backfill_a_timestamp_it_never_observed() {
    // §38.3 requires timestamp semantics to be preserved, and §38.4 forbids inventing what was not
    // observed. `eventTime` is when the reporter saw this occurrence; it is not the first time the
    // thing happened, and copying it into `firstTimestamp` to fill a rendering would state a
    // beginning nobody recorded.
    let only_event_time = event(EVENTS_V1);

    assert_eq!(
        only_event_time.event_time(),
        Some("2026-09-05T09:14:02.113344Z")
    );
    assert_eq!(only_event_time.occurrences().first_seen(), None);
    assert_eq!(only_event_time.occurrences().last_seen(), None);
}

#[test]
fn should_preserve_the_source_identity_that_reported_it() {
    // §38.3: the edge MUST preserve source identity. "The kubelet said it" and "the scheduler said
    // it" are different claims about the same Pod, and an Event stripped of its reporter is an
    // anonymous assertion.
    let stable = event(EVENTS_V1);
    assert_eq!(stable.reporter().controller(), Some("default-scheduler"));
    assert_eq!(stable.reporter().instance(), Some("default-scheduler-cp-1"));

    // The core representation carries the same two facts under `source`.
    let core = event(CORE_V1);
    assert_eq!(core.reporter().controller(), Some("kubelet"));
    assert_eq!(core.reporter().instance(), Some("worker-03"));
}

#[test]
fn should_relate_an_event_to_the_object_it_regards() {
    // §38.3: an Event relates to its regarding object when that identity resolves. Without it an
    // Event is a note in a namespace, and `why` (§40.1) has nothing to attach evidence to.
    let pod = object(POD).identity();
    let observations = Observations::read(vec![event(EVENTS_V1), event(CORE_V1)]);

    let found = observations.about(&pod);
    assert_eq!(found.observed().len(), 2);
    assert!(found.is_observed());
}

#[test]
fn should_refuse_to_attach_an_event_to_a_later_lifetime_of_the_same_name() {
    // §4 invariants 4 and 5 applied to §38.3. A Pod deleted and recreated under one name is two
    // lifetimes, and the old Pod's Events are about hardware and decisions the new one never saw.
    // Matching on name — which is what a rendering keyed on `involvedObject.name` does — is how a
    // fresh Pod inherits its predecessor's failures.
    let recreated = object(RECREATED_POD).identity();
    let observations = Observations::read(vec![event(EVENTS_V1), event(CORE_V1)]);

    let found = observations.about(&recreated);
    assert!(!found.is_observed(), "{:?}", found.observed());
    assert!(!event(EVENTS_V1).regards(&recreated));
    assert!(event(EVENTS_V1).regards(&object(POD).identity()));
}

#[test]
fn should_not_attach_an_event_to_an_object_in_another_cluster() {
    // Gate J. Two clusters hand out UIDs independently and an Event carries no provider instance
    // of its own, so the instance it was read through is what keeps one cluster's Events off
    // another cluster's objects.
    let elsewhere = Object::parse("kubernetes:dev", POD).expect("the fixture parses");
    assert!(!event(EVENTS_V1).regards(&elsewhere.identity()));
}

#[test]
fn should_keep_an_event_whose_regarding_object_cannot_be_resolved() {
    // §38.3 relates an Event "when the identity can be resolved", which means the other case
    // exists: an Event about something the object reference does not name completely. It is still
    // an observation and is still readable — dropping it would delete evidence for tidiness.
    let orphan = r#"{
      "apiVersion":"events.k8s.io/v1","kind":"Event",
      "metadata":{"name":"cluster.17c2","namespace":"default","uid":"ev-3"},
      "reason":"NodeNotReady","type":"Warning","note":"node status unknown",
      "regarding":{"apiVersion":"v1","kind":"Node"}
    }"#;
    let event = event(orphan);

    assert!(event.regarding().is_none());
    assert_eq!(event.note(), Some("node status unknown"));
    assert!(!event.regards(&object(POD).identity()));
}

#[test]
fn should_answer_a_search_that_found_nothing_as_not_observed_rather_than_absent() {
    // §38.6, the whole point of the module: absence of an Event MUST NEVER prove that an action or
    // failure did not occur. Retention is minutes to hours, delivery is best-effort, and the query
    // that produced this set was never a complete query of anything. An empty `Vec` invites
    // `if events.is_empty() { "nothing went wrong" }`, which is §63.6 in one line.
    let unrelated = object(RECREATED_POD).identity();
    let observations = Observations::read(vec![event(EVENTS_V1)]);
    let found = observations.about(&unrelated);

    assert!(found.observed().is_empty());
    let outcome = found
        .outcome()
        .expect("a search that found nothing says why");
    assert!(
        !outcome.is_evidence_of_absence(),
        "an Event search reported `{}`, which reads as proof that nothing happened",
        outcome.as_str()
    );
    assert_eq!(outcome, Outcome::NotQueried);

    // And on the other side: a set that did find something reports no outcome to misread.
    let found = observations.about(&object(POD).identity());
    assert_eq!(found.outcome(), None);
}

#[test]
fn should_leave_observations_in_the_order_they_arrived_rather_than_ordering_them() {
    // §38.1 and §39.2: a set of Events is not a timeline. Their timestamps come from the clocks of
    // the components that reported them, delivery is unordered, and retention has already thrown
    // some away — so sorting by time produces something that *looks* like a causal history and is
    // not one. The refusal has to be visible: nothing here reorders, and there is no `earliest`,
    // `latest` or time-range query to reach for.
    let later = event(EVENTS_V1);
    let earlier = event(CORE_V1);
    let observations = Observations::read(vec![later, earlier]);

    let names: Vec<&str> = observations
        .seen()
        .iter()
        .map(|event| event.identity().name())
        .collect();
    assert_eq!(names, vec!["checkout-7f9d.17c1", "checkout-7f9d.17c0"]);
}

#[test]
fn should_branch_on_no_reason_string() {
    // §38.5: `reason` and `note` are evidence and MUST NOT be treated as stable machine semantics
    // without a curated adapter, because upstream warns that they evolve. Code that reads
    // `reason == "FailedScheduling"` is an unversioned dependency on a string a controller author
    // may reword in the next minor release, and it fails silently when they do — the branch simply
    // stops being taken.
    let source = include_str!("../src/events.rs");
    for reason in REASONS {
        assert!(
            !source.contains(&format!("\"{reason}\"")),
            "src/events.rs holds the literal `{reason}`, which is a branch on an unstable string"
        );
    }

    // The values themselves stay readable — they are useful evidence, just not an API.
    assert_eq!(event(EVENTS_V1).reason(), Some("FailedScheduling"));
}

#[test]
fn should_keep_an_unrecognised_event_type_rather_than_reading_it_as_normal() {
    // §12.5 and §4 invariant 17. Upstream documents two types today; a controller may write a
    // third, and a parser with a `_ => Normal` arm would render an unknown severity as routine.
    let odd = r#"{
      "apiVersion":"events.k8s.io/v1","kind":"Event",
      "metadata":{"name":"odd.17c3","namespace":"shop","uid":"ev-4"},
      "type":"Critical","reason":"Whatever","note":"n"
    }"#;
    assert_eq!(event(odd).level(), &Level::Other("Critical".to_owned()));
    assert_eq!(event(odd).level().as_str(), "Critical");

    // An Event with no type at all does not become a Normal one either.
    let untyped = r#"{
      "apiVersion":"events.k8s.io/v1","kind":"Event",
      "metadata":{"name":"untyped.17c4","namespace":"shop","uid":"ev-5"},"note":"n"
    }"#;
    assert_eq!(event(untyped).level(), &Level::Unstated);
}

#[test]
fn should_filter_on_the_typed_level_rather_than_on_a_reason() {
    // §38.5 again, from the query side. Selecting "the things that went wrong" has to be a
    // question about `type`, which is API structure with documented values, rather than a list of
    // reason strings a caller assembled — that list would go quietly stale.
    let observations = Observations::read(vec![event(EVENTS_V1), event(CORE_V1)]);

    assert_eq!(observations.at_level(&Level::Warning).observed().len(), 2);
    let none = observations.at_level(&Level::Normal);
    assert!(!none.is_observed());
    assert_eq!(none.outcome(), Some(Outcome::NotQueried));
}

#[test]
fn should_render_an_event_with_its_reporter_and_its_recorded_count() {
    // §38.3 and §38.4 in one line of output. A rendering that dropped the reporter would show an
    // anonymous assertion, and one that dropped the count would show a single failure where the
    // cluster recorded forty-seven — the difference between a blip and an outage.
    let rendered = event(EVENTS_V1).describe();

    assert!(rendered.contains("Warning"), "{rendered}");
    assert!(
        rendered.contains("regarding Pod/checkout-7f9d"),
        "{rendered}"
    );
    assert!(rendered.contains("47 recorded"), "{rendered}");
    assert!(
        rendered.contains("reported by default-scheduler"),
        "{rendered}"
    );
}

#[test]
fn should_refuse_an_object_that_is_not_an_event() {
    // The field names below belong to two Event representations. Read across a Pod they would
    // produce an Event with nothing in it, which renders as an observation that was made and said
    // nothing rather than as the wrong question.
    let refused = Event::from_object(&object(POD)).expect_err("a Pod is not an Event");
    assert!(refused.to_string().contains("Pod"));
}

/// Event reasons in wide use upstream. Not a vocabulary this provider knows — a list of the
/// literals whose presence in the source would mean it had started depending on one (§38.5).
const REASONS: &[&str] = &[
    "FailedScheduling",
    "BackOff",
    "Unhealthy",
    "OOMKilling",
    "Killing",
    "Scheduled",
    "Pulled",
    "Pulling",
    "Created",
    "Started",
    "Failed",
    "FailedMount",
    "NodeNotReady",
    "Evicted",
    "SuccessfulCreate",
    "ScalingReplicaSet",
];

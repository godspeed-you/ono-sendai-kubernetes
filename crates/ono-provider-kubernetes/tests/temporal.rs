//! What a temporal answer observed, when it observed it, and which clock said so.
//!
//! Specification §39, and §13.3/§13.4 of the generic contract. Kubernetes hands out four kinds of
//! timestamp — an object's `creationTimestamp`, an Event's `eventTime`, a condition's
//! `lastTransitionTime`, a container runtime's log prefix — and not one of them is on the same
//! clock as the moment this provider acquired the object. The tempting move is to parse them all
//! into milliseconds and sort, which produces a timeline that reads as a history and is an
//! artefact of clock skew.
//!
//! So these tests are mostly about what will not be answered: two stamps from different writers
//! are `unordered` rather than ordered the wrong way round, a `resourceVersion` never fills in a
//! duration (§14.3, §4 invariant 6), and a timestamp read off current state is `reported` and
//! never `observed` (§39.2).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::condition::conditions;
use ono_provider_kubernetes::coverage::{Gap, Outcome, Scope};
use ono_provider_kubernetes::discovery::Gvr;
use ono_provider_kubernetes::events::Event;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::temporal::{
    Basis, ClockSource, Observation, Order, ReportedSource, Stamp, TemporalGap, Timeline,
    Undecidable,
};
use ono_provider_kubernetes::transport::{Clock, FixedClock, ObservedAt};
use ono_provider_kubernetes::watch::{ResourceVersion, WatchEvent, WatchFailure, WatchStream};

const INSTANCE: &str = "kubernetes:prod-eu";

/// A Pod created long before this provider started watching anything (§39.2).
const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{
    "name":"checkout-7f9d","namespace":"shop","uid":"pod-1","resourceVersion":"9000",
    "creationTimestamp":"2026-09-05T08:00:00Z"
  },
  "status":{"conditions":[
    {"type":"Ready","status":"False","lastTransitionTime":"2026-09-05T14:22:00Z"},
    {"type":"PodScheduled","status":"True","lastTransitionTime":"2026-09-05T14:21:00Z"}
  ]}
}"#;

/// A scheduler Event about that Pod, timestamped by the scheduler's own clock.
const EVENT: &str = r#"{
  "apiVersion":"events.k8s.io/v1","kind":"Event",
  "metadata":{"name":"checkout-7f9d.17c1","namespace":"shop","uid":"ev-1"},
  "eventTime":"2026-09-05T14:21:30.500000Z",
  "reportingController":"default-scheduler","reportingInstance":"default-scheduler-cp-1",
  "reason":"FailedScheduling","type":"Warning",
  "regarding":{"apiVersion":"v1","kind":"Pod","namespace":"shop","name":"checkout-7f9d","uid":"pod-1"}
}"#;

fn pod() -> Object {
    Object::parse(INSTANCE, POD).expect("the fixture is a well-formed Pod")
}

fn scheduler_event() -> Event {
    let object = Object::parse(INSTANCE, EVENT).expect("the fixture is a well-formed Event");
    Event::from_object(&object).expect("the fixture is an Event")
}

// --- the window and its holes -------------------------------------------------------------------

#[test]
fn should_state_the_window_it_observed() {
    // §39.2. An answer that does not name its window invites the reader to assume the window is
    // "always", which is exactly the retroactive history the section forbids.
    let opened = FixedClock::at_unix_millis(1_000);
    let mut timeline = Timeline::opened(INSTANCE, Scope::in_namespace("shop"), &opened);

    timeline.advance(&FixedClock::at_unix_millis(61_000));

    assert_eq!(timeline.window().opened_at().unix_millis(), 1_000);
    assert_eq!(timeline.window().latest_at().unix_millis(), 61_000);
    assert_eq!(timeline.window().span_millis(), 60_000);
    assert!(
        !timeline
            .window()
            .contains(ObservedAt::from_unix_millis(999)),
        "a moment before observation began is outside the window, however old the objects are"
    );
    assert!(
        timeline.describe().contains("1000"),
        "the window must be readable: {}",
        timeline.describe()
    );
}

#[test]
fn should_carry_the_holes_in_the_window_rather_than_a_continuous_history() {
    // §39.3 and §19.4. The plausible mistake is to relist after `410 Gone` and keep appending to
    // one history: the record then looks complete while missing everything that happened during
    // the break, which is worse than no record because it invites conclusions.
    let mut stream = WatchStream::new(Gvr::new("", "v1", "pods"), Scope::in_namespace("shop"));
    stream.listed(vec![pod()], ResourceVersion::new("9000"));
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    stream.listed(vec![pod()], ResourceVersion::new("9600"));

    let mut timeline = Timeline::opened(
        INSTANCE,
        Scope::in_namespace("shop"),
        &FixedClock::at_unix_millis(1_000),
    );
    timeline.absorb_continuity(&stream, &FixedClock::at_unix_millis(30_000));

    assert!(
        !timeline.is_continuous(),
        "an expiry is a hole in the window and must survive into the timeline"
    );
    assert_eq!(timeline.gaps().len(), 1);
    let gap = &timeline.gaps()[0];
    assert_eq!(gap.reason().as_str(), "watch_expired_410");
    assert_eq!(
        gap.after_version().map(ResourceVersion::as_str),
        Some("9000")
    );
    assert!(
        timeline.describe().contains("watch_expired_410"),
        "a gap nobody can read is a gap nobody accounts for: {}",
        timeline.describe()
    );
}

#[test]
fn should_record_the_scope_it_could_not_read_beside_the_time_it_covered() {
    // §61.6 asks for explicit observation coverage, and coverage has two axes: which scopes
    // answered, and which stretches of time were observed. Reporting only one of them lets a
    // denied namespace hide behind a continuous window.
    let mut timeline = Timeline::opened(
        INSTANCE,
        Scope::all_namespaces(),
        &FixedClock::at_unix_millis(1_000),
    );
    timeline.coverage_mut().record(Gap::new(
        Scope::in_namespace("payments"),
        Outcome::ListDenied,
    ));

    assert!(timeline.is_continuous(), "no watch broke");
    assert!(
        !timeline.coverage().is_complete(),
        "a denied namespace is a hole even when the clock never stopped"
    );
    assert!(timeline.describe().contains("list denied"));
}

// --- clocks that disagree -------------------------------------------------------------------------

#[test]
fn should_not_order_two_observations_written_by_different_clocks() {
    // §39.2 and §13.4. The API server stamped `creationTimestamp`; the scheduler stamped
    // `eventTime` from its own machine. Parsing both into milliseconds and comparing is the
    // plausible mistake, and skew of a few seconds is enough to reverse the answer.
    let pod = pod();
    let created = Observation::of_creation(&pod).expect("the fixture has a creationTimestamp");
    let event = scheduler_event();
    let reported = Observation::of_event(&pod.identity(), &event)
        .expect("the fixture Event regards the Pod and carries an eventTime");

    assert_eq!(created.stamp().source(), &ClockSource::ApiServer);
    assert_eq!(
        reported.stamp().source(),
        &ClockSource::Reporter("default-scheduler".to_owned())
    );
    assert_eq!(
        created.stamp().relate(reported.stamp()),
        Order::Unordered(Undecidable::DifferentClocks)
    );
    assert_eq!(
        created.stamp().apart_millis(reported.stamp()),
        None,
        "a distance between two clocks is skew plus elapsed time, and neither is recoverable"
    );
}

#[test]
fn should_not_order_two_timestamps_whose_writer_is_unstated() {
    // A condition's `lastTransitionTime` is written by whichever controller wrote the status, and
    // the object does not say which. Two unattributed stamps may be from two machines, so they are
    // not comparable even with each other — the plausible mistake is to treat "same field" as
    // "same clock".
    let pod = pod();
    let found = conditions(&pod);
    let ready = Observation::of_condition(&pod.identity(), &found[0])
        .expect("the Ready condition has a lastTransitionTime");
    let scheduled = Observation::of_condition(&pod.identity(), &found[1])
        .expect("the PodScheduled condition has a lastTransitionTime");

    assert_eq!(ready.stamp().source(), &ClockSource::Unattributed);
    assert_eq!(
        ready.stamp().relate(scheduled.stamp()),
        Order::Unordered(Undecidable::ClockUnattributed)
    );
}

#[test]
fn should_order_two_stamps_the_same_clock_wrote() {
    // The other half of the rule: refusing every comparison would be safe and useless. One clock,
    // two moments, one answer — and the fractional-second form must not sort before the whole one.
    let earlier = Stamp::api_server("2026-09-05T14:21:00Z");
    let later = Stamp::api_server("2026-09-05T14:21:00.500000Z");

    assert_eq!(earlier.relate(&later), Order::Before);
    assert_eq!(later.relate(&earlier), Order::After);
    assert_eq!(earlier.relate(&earlier), Order::Simultaneous);
    assert_eq!(earlier.apart_millis(&later), Some(500));
}

#[test]
fn should_refuse_to_place_a_timestamp_it_cannot_read() {
    // Unknown data is null, never zero (AGENTS.md §6). A stamp coerced to the epoch would sort
    // before every real observation and look like the oldest thing in the cluster.
    let unreadable = Stamp::api_server("last Tuesday");

    assert!(!unreadable.is_placeable());
    assert_eq!(unreadable.raw(), "last Tuesday");
    assert_eq!(
        unreadable.relate(&Stamp::api_server("2026-09-05T14:21:00Z")),
        Order::Unordered(Undecidable::Unplaceable)
    );
}

#[test]
fn should_read_a_kubernetes_timestamp_as_the_instant_it_names() {
    // The calendar conversion, checked against a fixed pair rather than against itself. A parser
    // that is merely monotonic would pass every ordering test above while placing everything in
    // the wrong century, and a temporal answer whose absolute times are wrong is worse than one
    // that refuses to place them.
    let epoch = Stamp::api_server("1970-01-01T00:00:00Z");
    assert_eq!(
        epoch.apart_millis(&Stamp::api_server("2026-09-05T14:21:00Z")),
        Some(1_788_618_060_000)
    );
    // A leap day, because February is where a hand-written civil-date conversion goes wrong.
    assert_eq!(
        epoch.apart_millis(&Stamp::api_server("2024-02-29T23:59:59Z")),
        Some(1_709_251_199_000)
    );
    // A month and a day outside the calendar are refused rather than folded into the next one.
    assert!(!Stamp::api_server("2026-13-05T14:21:00Z").is_placeable());
    assert!(!Stamp::api_server("2026-09-05T14:21:00+02:00").is_placeable());
}

#[test]
fn should_name_the_clock_each_kind_of_stamp_came_from() {
    // Five writers, five words. Collapsing any two of them is how a node's clock ends up being
    // compared with this machine's (§39.1, and `logs.rs` on why node timestamps stay strings).
    let named: Vec<String> = [
        ClockSource::Provider,
        ClockSource::ApiServer,
        ClockSource::Reporter("kubelet".to_owned()),
        ClockSource::Node("worker-03".to_owned()),
        ClockSource::Unattributed,
    ]
    .iter()
    .map(ClockSource::to_string)
    .collect();

    let mut unique = named.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 5, "each writer needs its own word: {named:?}");
}

#[test]
fn should_not_compare_a_node_clock_with_this_machines() {
    // §42.1's log timestamps come from the container runtime on the node. `logs.rs` keeps them as
    // strings for this reason; the temporal model must not be the place that finally parses them
    // into one timeline.
    // The two name the same instant, which is the sharp version of the point: the values compare
    // perfectly well and the comparison means nothing.
    let node = Stamp::on_node("worker-03", "2026-09-05T14:21:00Z");
    let here = Stamp::observed(ObservedAt::from_unix_millis(1_788_618_060_000));

    assert_eq!(
        node.relate(&here),
        Order::Unordered(Undecidable::DifferentClocks)
    );
    assert_eq!(
        Stamp::on_node("worker-04", "2026-09-05T14:21:00Z").relate(&node),
        Order::Unordered(Undecidable::DifferentClocks),
        "two nodes are two clocks"
    );
}

#[test]
fn should_not_be_sortable_as_a_bare_stamp() {
    // The discipline is in the type: an ordering trait on `Stamp` would make
    // `stamps.sort()` compile, and a sorted list of stamps from four writers is precisely the
    // cross-clock timeline §39.2 forbids. `relate` is the only way to ask, and it can answer
    // "unordered".
    struct Probe<T>(std::marker::PhantomData<T>);
    trait Fallback {
        const SORTABLE: bool = false;
    }
    impl<T> Fallback for Probe<T> {}
    impl<T: PartialOrd> Probe<T> {
        const SORTABLE: bool = true;
    }

    // Through locals, so the assertions are the test's rather than the compiler's: a constant
    // `assert!` would be folded away and read as a lint problem instead of as a claim.
    let control = Probe::<u64>::SORTABLE;
    let stamp = Probe::<Stamp>::SORTABLE;
    let observation = Probe::<Observation>::SORTABLE;

    assert!(control, "the probe detects an ordering where there is one");
    assert!(
        !stamp,
        "`Stamp` must carry no ordering, so a cross-clock sort cannot be written"
    );
    assert!(
        !observation,
        "an observation is not sortable either, for the same reason"
    );
}

// --- observed against reported ---------------------------------------------------------------------

#[test]
fn should_keep_a_timestamp_read_off_current_state_from_becoming_an_observed_change() {
    // §39.2 in one assertion. The Pod says it was created at 08:00; this provider started looking
    // at 14:00. Recording that as something observed would manufacture six hours of history out of
    // a metadata field.
    let pod = pod();
    let created = Observation::of_creation(&pod).expect("the fixture has a creationTimestamp");

    assert_eq!(created.basis(), Basis::Reported);
    assert_eq!(created.source().as_str(), "object-metadata");

    let mut timeline = Timeline::opened(
        INSTANCE,
        Scope::in_namespace("shop"),
        &FixedClock::at_unix_millis(1_000),
    );
    timeline.record(created);

    assert_eq!(timeline.observations().len(), 1);
    assert!(
        timeline.observed().is_empty(),
        "nothing was observed to happen; a creation timestamp was read"
    );
    assert_eq!(timeline.reported().len(), 1);
}

#[test]
fn should_stamp_a_watched_change_with_this_providers_own_clock() {
    // The one thing this provider may claim it saw happen (§39.3). It is stamped with the
    // acquisition clock because that is the only clock this machine owns; using the object's
    // `resourceVersion` or its metadata would borrow a clock that is not one.
    let clock = FixedClock::at_unix_millis(42_000);
    let watched = Observation::watched(pod().identity(), clock.now(), "modified");

    assert_eq!(watched.basis(), Basis::Observed);
    assert_eq!(watched.stamp().source(), &ClockSource::Provider);
    assert_eq!(watched.source().as_str(), "watch-event");

    let mut timeline = Timeline::opened(
        INSTANCE,
        Scope::in_namespace("shop"),
        &FixedClock::at_unix_millis(1_000),
    );
    timeline.record(watched);
    timeline.advance(&clock);

    assert_eq!(timeline.observed().len(), 1);
    assert!(
        timeline
            .observed()
            .iter()
            .all(|observation| observation.stamp().source() == &ClockSource::Provider),
        "everything claimed as observed must be on the clock that did the observing"
    );
}

#[test]
fn should_offer_no_reported_source_that_claims_a_change_was_watched() {
    // A single `Source` enum with a public constructor would let a `creationTimestamp` be filed
    // as a watch event by passing the wrong variant. `Observation::reported` takes a smaller
    // vocabulary that has no word for it, so the mistake does not typecheck.
    let subject = pod().identity();
    let snapshot = Observation::reported(
        subject,
        ReportedSource::ResourceSnapshot,
        Stamp::observed(ObservedAt::from_unix_millis(5_000)),
        "listed",
    );

    assert_eq!(snapshot.basis(), Basis::Reported);
    for source in ReportedSource::all() {
        assert_ne!(
            source.as_source().basis(),
            Basis::Observed,
            "{source:?} must not be able to claim a change was watched"
        );
    }
}

// --- grouping by clock ------------------------------------------------------------------------------

#[test]
fn should_group_a_timeline_by_clock_rather_than_merging_them() {
    // The composition rule: a timeline holds observations from several writers and orders within
    // each, never across. `ordered_on` needs a clock named, so there is no call that returns one
    // merged sequence.
    let pod = pod();
    let mut timeline = Timeline::opened(
        INSTANCE,
        Scope::in_namespace("shop"),
        &FixedClock::at_unix_millis(1_000),
    );
    timeline.record(Observation::of_creation(&pod).expect("a creationTimestamp"));
    timeline
        .record(Observation::of_event(&pod.identity(), &scheduler_event()).expect("an eventTime"));
    timeline.record(Observation::watched(
        pod.identity(),
        ObservedAt::from_unix_millis(2_000),
        "modified",
    ));
    timeline.record(Observation::watched(
        pod.identity(),
        ObservedAt::from_unix_millis(1_500),
        "added",
    ));

    let mut clocks: Vec<String> = timeline
        .clocks()
        .iter()
        .map(ClockSource::to_string)
        .collect();
    clocks.sort();
    assert_eq!(clocks.len(), 3, "three writers, three clocks: {clocks:?}");

    let ours = timeline.ordered_on(&ClockSource::Provider);
    assert_eq!(ours.sequence().len(), 2);
    assert_eq!(ours.sequence()[0].detail(), "added");
    assert_eq!(ours.sequence()[1].detail(), "modified");

    let api = timeline.ordered_on(&ClockSource::ApiServer);
    assert_eq!(api.sequence().len(), 1, "the API server wrote one of these");
}

#[test]
fn should_place_nothing_in_sequence_on_an_unattributed_clock() {
    // Asking for the order of stamps nobody claimed must not silently produce one. They come back
    // as unplaceable, which is an answer a renderer can show.
    let pod = pod();
    let mut timeline = Timeline::opened(
        INSTANCE,
        Scope::in_namespace("shop"),
        &FixedClock::at_unix_millis(1_000),
    );
    for condition in conditions(&pod) {
        timeline.record(
            Observation::of_condition(&pod.identity(), &condition).expect("a transition time"),
        );
    }

    let attempted = timeline.ordered_on(&ClockSource::Unattributed);
    assert!(attempted.sequence().is_empty());
    assert_eq!(attempted.unplaceable().len(), 2);
}

// --- resourceVersion is not a clock -------------------------------------------------------------------

#[test]
fn should_not_let_a_resource_version_stand_in_for_a_time() {
    // §14.3 and §4 invariant 6. A gap knows two continuity tokens and, separately, when this
    // provider noticed the break. Subtracting the tokens is the plausible mistake — they are
    // opaque, they are not monotonic across resources, and the difference means nothing.
    let mut stream = WatchStream::new(Gvr::new("", "v1", "pods"), Scope::in_namespace("shop"));
    stream.listed(vec![pod()], ResourceVersion::new("9000"));
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    let watch_gap = stream.gaps()[0].clone();

    let open = TemporalGap::from_watch(&watch_gap, ObservedAt::from_unix_millis(30_000));
    assert_eq!(
        open.unobserved_millis(),
        None,
        "an unresumed gap has no duration; the versions do not supply one"
    );
    assert!(!open.is_closed());

    let closed = open.resumed(ObservedAt::from_unix_millis(45_000));
    assert_eq!(
        closed.unobserved_millis(),
        Some(15_000),
        "a duration comes from this provider's clock, at both ends or not at all"
    );
    assert!(closed.is_closed());
    assert!(
        closed.describe().contains("9000"),
        "the token is named as a position, not as a time: {}",
        closed.describe()
    );
}

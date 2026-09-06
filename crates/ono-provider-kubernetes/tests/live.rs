//! A live view of a watch, and the honesty it inherits from one.
//!
//! Specification §41, resting on §19 (watch model), §20.3 (sync state) and §4 invariant 14. §41.4
//! names six states a live view must be able to show — `syncing`, `live`, `reconnecting`, `gap
//! detected`, `stale`, `denied` — and one sentence that is the whole point of the section: a
//! disconnected watch must not leave a frozen table that visually appears live.
//!
//! Two mistakes these tests exist to catch.
//!
//! The first is a view that keeps rendering rows after its stream broke. The rows are still
//! there, they are still what the cache last held, and nothing about them says that the cluster
//! moved on without anybody watching. So a view that is not entitled to be believed cannot hand
//! its rows over unqualified: `Shown::Current` is unreachable while anything is wrong.
//!
//! The second is `stale`. `watch.rs` deliberately models the other five states and not this one,
//! because it holds no clock — a stream that is fed no events cannot tell an idle cluster from a
//! dead poller. A view is where the clock legitimately enters, and it enters as a parameter so
//! that these tests are arithmetic rather than sleeps.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::time::Duration;

use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::Gvr;
use ono_provider_kubernetes::live::{LiveView, Neighbourhood, Shown, ViewState};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::transport::FixedClock;
use ono_provider_kubernetes::watch::{
    ChangeClass, ResourceVersion, WatchEvent, WatchFailure, WatchStream,
};

const INSTANCE: &str = "kubernetes:prod-eu";

/// The instant every test starts at, so that a staleness window is arithmetic on a fixed number.
const T0: u64 = 1_757_000_000_000;

/// How long a view may go without a live observation before it stops calling itself live.
fn window() -> Duration {
    Duration::from_secs(30)
}

/// One Pod as the API server sends it.
fn pod(name: &str, uid: &str, resource_version: &str) -> Object {
    let json = format!(
        r#"{{
          "apiVersion": "v1",
          "kind": "Pod",
          "metadata": {{
            "name": "{name}",
            "namespace": "shop",
            "uid": "{uid}",
            "resourceVersion": "{resource_version}"
          }}
        }}"#
    );
    Object::parse(INSTANCE, &json).expect("the fixture Pod parses")
}

/// A watch over `core/v1 Pods` in one namespace that has listed and is live.
fn live_stream(objects: Vec<Object>) -> WatchStream {
    let mut stream = WatchStream::new(Gvr::new("", "v1", "pods"), Scope::in_namespace("shop"));
    stream.listed(objects, ResourceVersion::new("4000"));
    stream
}

/// A view with room for everything the tests put in it.
fn view() -> LiveView {
    LiveView::new(
        Gvr::new("", "v1", "pods"),
        Scope::in_namespace("shop"),
        16,
        window(),
    )
}

// --- the five states a view inherits (§41.4) ----------------------------------------------------

/// §41.4 lists six states. The plausible mistake is a view with three — loading, ready, error —
/// which folds "the cache never synchronised" together with "the cluster is empty" and folds a
/// `410 Gone` together with a connection reset, losing the only distinction §4 invariant 14 cares
/// about.
#[test]
fn should_give_every_state_of_41_4_its_own_word() {
    let words: Vec<&str> = [
        ViewState::Syncing,
        ViewState::Live,
        ViewState::Reconnecting,
        ViewState::GapDetected,
        ViewState::Stale,
        ViewState::Denied,
    ]
    .into_iter()
    .map(ViewState::as_str)
    .collect();

    assert_eq!(
        words,
        vec![
            "syncing",
            "live",
            "reconnecting",
            "gap detected",
            "stale",
            "denied"
        ]
    );
}

/// §20.3: a cache that has not listed is empty because nobody read, not because the cluster is.
/// The plausible mistake is rendering "no Pods" over a view that has never spoken to the server.
#[test]
fn should_not_show_a_syncing_view_as_a_cluster_with_nothing_in_it() {
    let stream = WatchStream::new(Gvr::new("", "v1", "pods"), Scope::in_namespace("shop"));
    let mut view = view();
    let clock = FixedClock::at_unix_millis(T0);
    view.refresh(&stream, &clock);

    assert_eq!(view.state(&clock), ViewState::Syncing);
    match view.shown(&clock) {
        Shown::Qualified { rows, notice } => {
            assert!(rows.is_empty());
            assert!(notice.describe().contains("syncing"));
        }
        Shown::Current(_) => panic!("a view that has not listed has nothing to be current about"),
    }
}

/// The counterpart, so that the discipline above is not simply "never trust anything": a listed,
/// watching, unbroken, freshly observed view is entitled to show its rows as they are.
#[test]
fn should_show_rows_as_current_when_the_stream_is_live_and_unbroken() {
    let stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    let mut view = view();
    let clock = FixedClock::at_unix_millis(T0);
    view.refresh(&stream, &clock);

    assert_eq!(view.state(&clock), ViewState::Live);
    match view.shown(&clock) {
        Shown::Current(rows) => assert_eq!(rows.len(), 1),
        Shown::Qualified { notice, .. } => panic!("nothing is wrong: {}", notice.describe()),
    }
}

/// §21.4 and §4 invariant 13: a refused watch is an unknown upstream, not an empty one. The
/// plausible mistake is an error state that clears the table, which shows a denial as a cluster
/// that lost its Pods.
#[test]
fn should_say_denied_rather_than_show_an_empty_table() {
    let mut stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    stream.observe(WatchEvent::Error(WatchFailure::Denied));
    let mut view = view();
    let clock = FixedClock::at_unix_millis(T0);
    view.refresh(&stream, &clock);

    assert_eq!(view.state(&clock), ViewState::Denied);
    assert!(view.shown(&clock).notice().is_some());
}

// --- a gap stays visible (§41.4, §19.4, Gate F) --------------------------------------------------

/// The failure §41 exists to prevent. A `410 Gone` breaks continuity; the rows are still on
/// screen; nothing about them looks different. The plausible mistake is exactly that — leaving
/// the table up because the data in it is still the last thing that was true.
#[test]
fn should_not_show_rows_as_current_while_a_gap_is_open() {
    let mut stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    let mut view = view();
    let clock = FixedClock::at_unix_millis(T0);
    view.refresh(&stream, &clock);

    assert_eq!(view.state(&clock), ViewState::GapDetected);
    let shown = view.shown(&clock);
    assert!(!shown.is_current());
    assert!(
        shown
            .notice()
            .expect("a broken view says so")
            .describe()
            .contains("watch_expired_410"),
        "the view must name the break, not merely change colour"
    );
}

/// The subtler half, and the one a reasonable implementation gets wrong. Re-listing after a `410`
/// makes the rows current again — and the view's record of how they got there still has a hole in
/// it, which is what a §41.3 transition would be drawn from. The plausible mistake is clearing
/// the notice the moment the stream goes live again, so the gap becomes invisible one refresh
/// after it happened.
#[test]
fn should_keep_naming_a_gap_after_the_stream_recovered() {
    let mut stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    stream.listed(
        vec![pod("api-2", "uid-2", "5001")],
        ResourceVersion::new("5000"),
    );
    let mut view = view();
    let clock = FixedClock::at_unix_millis(T0);
    view.refresh(&stream, &clock);

    assert_eq!(view.state(&clock), ViewState::Live);
    let shown = view.shown(&clock);
    assert!(
        !shown.is_current(),
        "the rows are current; the record they sit in is not"
    );
    let notice = shown.notice().expect("the recovered view still qualifies");
    assert_eq!(notice.gaps().len(), 1);
    assert!(notice.describe().contains("resumed at 5000"));
}

// --- staleness (§41.4) ----------------------------------------------------------------------------

/// The state `watch.rs` cannot model. A stream that is handed no events looks identical to one
/// nobody is feeding any more, and only a clock tells them apart. The plausible mistake is
/// trusting `SyncState::Live` forever: the poller dies, the stream object never hears about it,
/// and the table stays green.
#[test]
fn should_go_stale_when_no_live_observation_arrives_within_the_window() {
    let stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    let mut view = view();
    view.refresh(&stream, &FixedClock::at_unix_millis(T0));

    let just_inside = FixedClock::at_unix_millis(T0 + 29_999);
    assert_eq!(view.state(&just_inside), ViewState::Live);

    let past_it = FixedClock::at_unix_millis(T0 + 30_001);
    assert_eq!(view.state(&past_it), ViewState::Stale);
    assert!(!view.shown(&past_it).is_current());
}

/// `stale` masks `live` and nothing else. The plausible mistake is letting the clock overwrite a
/// more specific state: "reconnecting" tells an operator why the view stopped moving, and "stale"
/// only tells them that it did.
#[test]
fn should_keep_naming_the_more_specific_state_and_report_staleness_beside_it() {
    let mut stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    let mut view = view();
    view.refresh(&stream, &FixedClock::at_unix_millis(T0));

    stream.observe(WatchEvent::Error(WatchFailure::Interrupted(
        "connection reset".to_owned(),
    )));
    let later = FixedClock::at_unix_millis(T0 + 60_000);
    view.refresh(&stream, &later);

    assert_eq!(view.state(&later), ViewState::Reconnecting);
    assert!(
        view.is_stale(&later),
        "it is both, and the operator is entitled to both"
    );
}

/// The clock must not advance on a refresh that observed nothing live. The plausible mistake is
/// touching the timestamp on every refresh, which makes a view that polls a dead stream look
/// permanently fresh — the frozen table with a heartbeat.
#[test]
fn should_not_treat_refreshing_a_broken_stream_as_a_live_observation() {
    let mut stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    let mut view = view();
    view.refresh(&stream, &FixedClock::at_unix_millis(T0));

    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    for tick in 1..=10 {
        view.refresh(&stream, &FixedClock::at_unix_millis(T0 + tick * 10_000));
    }

    let now = FixedClock::at_unix_millis(T0 + 100_000);
    assert!(
        view.is_stale(&now),
        "ten refreshes of a broken stream are not ten observations"
    );
}

/// A view that has never been live is not stale — it is syncing, and that word already says what
/// is happening. The plausible mistake is an `Option` unwrapped to "very old", which shows a view
/// three milliseconds into its first list as stale.
#[test]
fn should_not_call_a_view_stale_before_it_has_ever_been_live() {
    let stream = WatchStream::new(Gvr::new("", "v1", "pods"), Scope::in_namespace("shop"));
    let mut view = view();
    view.refresh(&stream, &FixedClock::at_unix_millis(T0));

    let much_later = FixedClock::at_unix_millis(T0 + 10_000_000);
    assert!(!view.is_stale(&much_later));
    assert_eq!(view.state(&much_later), ViewState::Syncing);
}

/// The clock is a parameter, so that a test can place a view at any instant without sleeping and
/// so that two views can be asked about the same moment. The plausible mistake is reaching for
/// the wall clock inside the module, which makes staleness untestable and every assertion about
/// it a race.
#[test]
fn should_take_its_clock_as_a_parameter() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/live.rs");
    let source = std::fs::read_to_string(path).expect("the module this test covers is readable");

    for forbidden in ["SystemTime", "SystemClock", "Instant::now"] {
        assert!(
            !source.contains(forbidden),
            "`{forbidden}` would make staleness a race rather than arithmetic"
        );
    }
}

// --- bounded resources (§18.5, §50) ---------------------------------------------------------------

/// §18.5 and §50.4: a view is bounded. The plausible mistake is an unbounded one, which turns a
/// namespace with forty thousand Pods into a memory profile nobody chose.
#[test]
fn should_hold_no_more_rows_than_its_capacity() {
    let objects: Vec<Object> = (0..5)
        .map(|index| pod(&format!("api-{index}"), &format!("uid-{index}"), "4001"))
        .collect();
    let stream = live_stream(objects);
    let mut view = LiveView::new(
        Gvr::new("", "v1", "pods"),
        Scope::in_namespace("shop"),
        2,
        window(),
    );
    let clock = FixedClock::at_unix_millis(T0);
    view.refresh(&stream, &clock);

    assert_eq!(view.row_count(), 2);
}

/// Bounding is only acceptable when what fell outside the bound is knowable. The plausible
/// mistake is silently truncating, which shows two Pods of five in a table that looks like the
/// whole namespace — the same lie as an invisible gap, arrived at by arithmetic.
#[test]
fn should_name_what_it_did_not_admit() {
    let objects: Vec<Object> = (0..5)
        .map(|index| pod(&format!("api-{index}"), &format!("uid-{index}"), "4001"))
        .collect();
    let stream = live_stream(objects);
    let mut view = LiveView::new(
        Gvr::new("", "v1", "pods"),
        Scope::in_namespace("shop"),
        2,
        window(),
    );
    let clock = FixedClock::at_unix_millis(T0);
    view.refresh(&stream, &clock);

    assert_eq!(view.withheld().len(), 3);
    let names: Vec<&str> = view
        .withheld()
        .iter()
        .map(ono_provider_kubernetes::object::Identity::name)
        .collect();
    assert_eq!(names, vec!["api-2", "api-3", "api-4"]);

    let shown = view.shown(&clock);
    assert!(!shown.is_current(), "a truncated view is not a current one");
    assert!(
        shown
            .notice()
            .expect("a truncated view says so")
            .describe()
            .contains("3 not shown")
    );
}

/// A view is a projection rather than a store, so the bound is re-applied against whatever the
/// stream holds now. The plausible mistake is evicting on the way in and never reconsidering,
/// which leaves a row invisible forever after a single busy moment.
#[test]
fn should_admit_a_withheld_object_once_the_stream_has_room_for_it() {
    let mut stream = live_stream(vec![
        pod("api-0", "uid-0", "4001"),
        pod("api-1", "uid-1", "4001"),
    ]);
    let mut view = LiveView::new(
        Gvr::new("", "v1", "pods"),
        Scope::in_namespace("shop"),
        1,
        window(),
    );
    let clock = FixedClock::at_unix_millis(T0);
    view.refresh(&stream, &clock);
    assert_eq!(view.withheld().len(), 1);

    stream.observe(WatchEvent::Deleted(pod("api-0", "uid-0", "4002")));
    view.refresh(&stream, &clock);

    assert_eq!(view.withheld().len(), 0);
    assert_eq!(view.row_count(), 1);
    assert!(view.shown(&clock).is_current());
}

// --- what a row carries -------------------------------------------------------------------------

/// A row records when this view learned it, from the injected clock. The plausible mistake is
/// reading a timestamp off the object, which is the cluster's clock and says when the object was
/// created rather than when anybody here saw it (§39.2).
#[test]
fn should_record_when_the_view_learned_each_row() {
    let stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    let mut view = view();
    view.refresh(&stream, &FixedClock::at_unix_millis(T0));

    let rows = view.shown(&FixedClock::at_unix_millis(T0)).rows().to_vec();
    assert_eq!(rows[0].observed_at().unix_millis(), T0);
    assert_eq!(rows[0].change(), ChangeClass::Added);
}

/// A refresh that changes nothing must not restamp the rows. The plausible mistake is stamping
/// every row on every refresh, which makes "changed 2 seconds ago" true of a Pod that has been
/// sitting still for a week — the arrow of §41.3 pointing at nothing.
#[test]
fn should_keep_a_rows_observation_time_when_the_object_did_not_change() {
    let mut stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    let mut view = view();
    view.refresh(&stream, &FixedClock::at_unix_millis(T0));
    view.refresh(&stream, &FixedClock::at_unix_millis(T0 + 5_000));

    let clock = FixedClock::at_unix_millis(T0 + 5_000);
    assert_eq!(
        view.shown(&clock).rows()[0].observed_at().unix_millis(),
        T0,
        "nothing happened, so nothing was observed"
    );

    stream.observe(WatchEvent::Modified(pod("api-1", "uid-1", "4002")));
    let later = FixedClock::at_unix_millis(T0 + 9_000);
    view.refresh(&stream, &later);
    assert_eq!(
        view.shown(&later).rows()[0].observed_at().unix_millis(),
        T0 + 9_000
    );
    assert_eq!(view.shown(&later).rows()[0].change(), ChangeClass::Modified);
}

// --- relationship-live views (§41.3) --------------------------------------------------------------

/// §41.3's example, spelled the way the specification spells it. The plausible mistake is
/// deriving the change from two renderings of a table rather than from two typed observations,
/// which §41.3 forbids in as many words.
#[test]
fn should_show_a_transition_between_two_typed_observations() {
    let mut near = Neighbourhood::of("Service checkout");
    near.observe("selected Pods", 4);
    near.observe("ready endpoints", 4);
    near.observe("selected Pods", 3);
    near.observe("ready endpoints", 2);

    let described = near.describe();
    assert!(described.contains("selected Pods: 4 -> 3"), "{described}");
    assert!(described.contains("ready endpoints: 4 -> 2"), "{described}");
}

/// The arrow is a claim that one became the other, and across a gap it is a claim nobody
/// observed: between the 4 and the 3 the stream missed an unknown number of arrivals and
/// departures. The plausible mistake is keeping the previous value across the break, which
/// manufactures a change out of two unrelated counts.
#[test]
fn should_drop_the_transition_arrow_across_a_gap() {
    let mut near = Neighbourhood::of("Service checkout");
    near.observe("selected Pods", 4);
    near.observe("selected Pods", 3);
    near.record_gap();
    near.observe("selected Pods", 2);

    let described = near.describe();
    assert!(described.contains("selected Pods: 2"), "{described}");
    assert!(
        !described.contains("->"),
        "{described} draws a transition across a period nobody observed"
    );
}

/// Between the break and the next observation there is no count at all, and saying so is better
/// than showing the last one. The plausible mistake is holding the pre-gap number on screen,
/// which is a value the view has no current evidence for.
#[test]
fn should_have_no_count_between_a_gap_and_the_next_observation() {
    let mut near = Neighbourhood::of("Service checkout");
    near.observe("selected Pods", 4);
    near.record_gap();

    let described = near.describe();
    assert!(
        !described.contains('4'),
        "{described} still shows a stale count"
    );
    assert!(described.contains("unknown"), "{described}");
}

/// §4 invariants 4 and 5, seen from a table. A Pod deleted and remade under the same name is a
/// different lifetime, and the plausible mistake is keying the view on the name alone — which
/// renders the replacement as the original having changed, and leaves the age of the row reading
/// from a lifetime that ended.
#[test]
fn should_read_a_recreated_object_as_an_arrival_rather_than_a_change() {
    let mut stream = live_stream(vec![pod("api-1", "uid-1", "4001")]);
    let mut view = view();
    view.refresh(&stream, &FixedClock::at_unix_millis(T0));

    stream.observe(WatchEvent::Deleted(pod("api-1", "uid-1", "4002")));
    stream.observe(WatchEvent::Added(pod("api-1", "uid-2", "4003")));
    let later = FixedClock::at_unix_millis(T0 + 4_000);
    view.refresh(&stream, &later);

    let shown = view.shown(&later);
    assert_eq!(shown.rows()[0].identity().uid(), Some("uid-2"));
    assert_eq!(shown.rows()[0].change(), ChangeClass::Added);
    assert_eq!(shown.rows()[0].observed_at().unix_millis(), T0 + 4_000);
}

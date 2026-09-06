//! What a watch observed without interruption, and where it stopped being able to say so.
//!
//! Specification §19 (watch model), §20.3 (informer-style cache), §20.4 (eventual reconciliation)
//! and §4 invariants 6 and 14. Gate F: a `410 Gone` expiry produces a visible gap and never a
//! false continuous timeline (§62.6, §63.11).
//!
//! The mistake these tests exist to catch is the comfortable one: relist after an expiry, carry
//! on appending events to the same history, and present the result as an unbroken stream. It
//! looks like the watch never faltered, which is precisely the claim the provider is not allowed
//! to make.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::time::Duration;

use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::Gvr;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::transport::{
    FixtureStream, HttpConnection, ListOptions, watch_request,
};
use ono_provider_kubernetes::watch::{
    Backoff, CHANGE_LOG_CAPACITY, ChangeClass, FrameError, GapReason, Reception, Reconciliation,
    ReconciliationStage, ResourceVersion, ResumeError, SyncState, WatchDecoder, WatchEvent,
    WatchFailure, WatchStream,
};

const INSTANCE: &str = "kubernetes:prod-eu";
const HOST: &str = "kubernetes.default.svc";

/// One Pod as the API server sends it, with the metadata continuity reasoning needs.
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

/// A stream over `core/v1 Pods` in one namespace, before anything has been read.
fn pods() -> WatchStream {
    WatchStream::new(Gvr::new("", "v1", "pods"), Scope::in_namespace("shop"))
}

/// A stream that has completed its initial list and is watching.
fn live_pods() -> WatchStream {
    let mut stream = pods();
    stream.listed(
        vec![pod("checkout-1", "uid-1", "18005")],
        ResourceVersion::new("18010"),
    );
    stream
}

#[test]
fn should_watch_from_the_collection_version_the_list_returned() {
    // §19.1: the watch opens from the collection's resourceVersion, which the LIST response
    // carries in `metadata.resourceVersion`. Taking the newest item version instead is the
    // plausible mistake, and it silently skips every change the server folded into the snapshot
    // after that item.
    let mut stream = pods();
    stream.listed(
        vec![
            pod("checkout-1", "uid-1", "18005"),
            pod("checkout-2", "uid-2", "18009"),
        ],
        ResourceVersion::new("18010"),
    );

    assert_eq!(
        stream.checkpoint().map(ResourceVersion::as_str),
        Some("18010")
    );
}

#[test]
fn should_keep_a_resource_version_as_the_opaque_token_the_server_sent() {
    // §4 invariant 6 and §14.3. Real clusters emit non-numeric continuity tokens, and an
    // implementation that parses resourceVersion into an integer to compare or sort it either
    // fails here or fabricates an order the token never had.
    let opaque = ResourceVersion::new("eyJ2IjoxLCJydiI6MTgwMTB9");
    assert_eq!(opaque.as_str(), "eyJ2IjoxLCJydiI6MTgwMTB9");
    assert_eq!(opaque.to_string(), "eyJ2IjoxLCJydiI6MTgwMTB9");

    let mut stream = pods();
    stream.listed(Vec::new(), opaque.clone());
    assert_eq!(stream.checkpoint(), Some(&opaque));
    assert_eq!(stream.state(), SyncState::Live);
}

#[test]
fn should_accept_a_checkpoint_that_is_numerically_lower_than_the_one_before_it() {
    // §14.3: resourceVersion is not a clock and not a monotonic number this provider may reason
    // about. Keeping the "highest" token — the natural implementation if you believe it is a
    // counter — would ignore the checkpoint the server just handed out and reopen the watch at a
    // position the server never offered.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Bookmark(ResourceVersion::new("42")));
    assert_eq!(stream.checkpoint().map(ResourceVersion::as_str), Some("42"));

    stream.observe(WatchEvent::Modified(pod("checkout-1", "uid-1", "7")));
    assert_eq!(
        stream.checkpoint().map(ResourceVersion::as_str),
        Some("7"),
        "the checkpoint is the last token the server gave, not the largest number seen"
    );
}

#[test]
fn should_not_read_a_bookmark_as_a_resource_change() {
    // §19.3: a BOOKMARK is a continuity checkpoint, not a mutation. Feeding it through the same
    // path as ADDED/MODIFIED/DELETED — the shortcut of "every event updates the cache" — invents
    // an object change that never happened and pollutes the observed history.
    let mut stream = live_pods();
    let before = stream.object_count();

    let reception = stream.observe(WatchEvent::Bookmark(ResourceVersion::new("18030")));

    assert_eq!(reception, Reception::Checkpointed);
    assert_eq!(stream.object_count(), before);
    assert!(
        stream.continuous_changes().is_empty(),
        "a checkpoint is not a change: {:?}",
        stream.continuous_changes()
    );
    assert_eq!(
        stream.checkpoint().map(ResourceVersion::as_str),
        Some("18030")
    );
}

#[test]
fn should_apply_added_modified_and_deleted_to_the_cache() {
    // §19.1: the three mutation classes are what keeps a watched cache equal to upstream state.
    let mut stream = live_pods();

    stream.observe(WatchEvent::Added(pod("checkout-2", "uid-2", "18011")));
    assert!(stream.find(Some("shop"), "checkout-2").is_some());

    stream.observe(WatchEvent::Modified(pod("checkout-2", "uid-2", "18012")));
    assert_eq!(
        stream
            .find(Some("shop"), "checkout-2")
            .and_then(Object::resource_version),
        Some("18012")
    );

    stream.observe(WatchEvent::Deleted(pod("checkout-2", "uid-2", "18013")));
    assert!(stream.find(Some("shop"), "checkout-2").is_none());

    let classes: Vec<ChangeClass> = stream
        .continuous_changes()
        .iter()
        .map(|change| change.class())
        .collect();
    assert_eq!(
        classes,
        vec![
            ChangeClass::Added,
            ChangeClass::Modified,
            ChangeClass::Deleted
        ]
    );
}

#[test]
fn should_not_call_an_unsynced_cache_evidence_of_absence() {
    // §20.3 and §4 invariant 13. Before the initial list completes the cache is empty because
    // nothing was read yet. Answering "not found" from it is the mistake that turns a slow start
    // into a confident lie about the cluster.
    let stream = pods();

    assert_eq!(stream.state(), SyncState::Syncing);
    assert!(!stream.has_synced());
    assert!(!stream.absence_is_conclusive());
    assert_eq!(stream.object_count(), 0);
}

#[test]
fn should_call_absence_conclusive_only_while_the_stream_is_live() {
    // §20.3 again, from the other side: once the list completed and the watch is running, a name
    // missing from the cache really is missing upstream — and that stops being true the moment
    // the stream is no longer receiving events.
    let mut stream = live_pods();
    assert!(stream.has_synced());
    assert!(stream.absence_is_conclusive());

    stream.observe(WatchEvent::Error(WatchFailure::Interrupted(
        "connection reset by peer".to_owned(),
    )));
    assert!(
        stream.has_synced(),
        "a disconnect does not undo the initial synchronization"
    );
    assert!(
        !stream.absence_is_conclusive(),
        "a cache that is no longer fed may be behind upstream"
    );
}

#[test]
fn should_break_continuity_when_the_server_answers_410_gone() {
    // §19.4 and §4 invariant 14, the centre of Gate F. An expiry means the server no longer holds
    // the history the checkpoint names; treating it as one more retryable error and carrying on
    // is exactly the prohibited behaviour of §63.11.
    let mut stream = live_pods();

    let reception = stream.observe(WatchEvent::Error(WatchFailure::Expired));

    assert_eq!(reception, Reception::ContinuityBroken);
    assert_eq!(stream.state(), SyncState::GapDetected);
    assert!(!stream.is_gap_free());
    assert_eq!(stream.gaps().len(), 1);

    let gap = &stream.gaps()[0];
    assert_eq!(gap.reason(), GapReason::Expired);
    assert_eq!(gap.after().map(ResourceVersion::as_str), Some("18010"));
    assert!(gap.resumed_at().is_none(), "the gap is still open");
}

#[test]
fn should_void_the_expired_checkpoint_instead_of_offering_it_again() {
    // §19.4 step 4: the provider resumes from a *new* known resourceVersion. Keeping the old
    // token around is how a reconnect loop asks the server for the same vanished history over and
    // over, and how a renderer ends up printing a continuity position that no longer exists.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Error(WatchFailure::Expired));

    assert!(stream.checkpoint().is_none());
    assert_eq!(stream.reconnected(), Err(ResumeError::CheckpointExpired));
}

#[test]
fn should_quarantine_the_cache_after_an_expiry_without_pretending_it_is_empty() {
    // §19.4 step 2. The last known state stays readable — an operator still wants to see it — but
    // it may no longer answer questions that need gap-free observation. Clearing the cache and
    // reporting "no Pods" would be the same lie in the opposite direction.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Error(WatchFailure::Expired));

    assert!(
        stream.find(Some("shop"), "checkout-1").is_some(),
        "last known state remains visible"
    );
    assert!(!stream.has_synced());
    assert!(!stream.absence_is_conclusive());
}

#[test]
fn should_discard_events_that_arrive_after_an_expiry_and_before_re_acquisition() {
    // Gate F. A post-gap event appended to the pre-gap segment is a fabricated continuous
    // history: the record would claim the change was observed in sequence when the changes before
    // it were not seen at all.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Error(WatchFailure::Expired));

    let reception = stream.observe(WatchEvent::Added(pod("checkout-9", "uid-9", "18700")));

    assert_eq!(reception, Reception::Discarded);
    assert_eq!(stream.discarded_events(), 1);
    assert!(stream.find(Some("shop"), "checkout-9").is_none());
    assert_eq!(
        stream.segments()[0].changes().len(),
        0,
        "nothing may be appended to a segment the gap already closed"
    );
}

#[test]
fn should_never_join_pre_gap_and_post_gap_changes_into_one_history() {
    // §19.4's closing sentence and §39.3. Two observation periods separated by a gap are two
    // histories. Concatenating them produces an ordered change list that looks complete and is
    // not, which is the single failure this module exists to prevent.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Modified(pod("checkout-1", "uid-1", "18011")));
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    stream.listed(
        vec![pod("checkout-1", "uid-1", "18699")],
        ResourceVersion::new("18700"),
    );
    stream.observe(WatchEvent::Modified(pod("checkout-1", "uid-1", "18701")));

    assert_eq!(stream.segments().len(), 2);
    assert_eq!(stream.segments()[0].changes().len(), 1);
    assert_eq!(stream.segments()[1].changes().len(), 1);
    assert!(!stream.is_gap_free());
    assert_eq!(
        stream.continuous_changes().len(),
        1,
        "only the current unbroken period may be offered as a continuous history"
    );
    assert_eq!(
        stream.segments()[1].started_at().as_str(),
        "18700",
        "the new period starts at the version the fresh list returned"
    );
}

#[test]
fn should_close_the_gap_with_the_version_the_fresh_list_returned() {
    // §19.4 steps 3 to 5 and Appendix D.4: the gap records where continuity stopped and where it
    // resumed. A gap without both ends cannot tell an operator which observations to distrust.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    stream.listed(Vec::new(), ResourceVersion::new("18700"));

    let gap = &stream.gaps()[0];
    assert_eq!(gap.after().map(ResourceVersion::as_str), Some("18010"));
    assert_eq!(gap.resumed_at().map(ResourceVersion::as_str), Some("18700"));
    assert!(gap.is_closed());
    assert_eq!(stream.state(), SyncState::Live);
    assert!(
        !stream.is_gap_free(),
        "resuming closes the gap, it does not erase it"
    );
}

#[test]
fn should_forget_objects_that_vanished_during_the_gap() {
    // §19.4 step 3 is a *fresh state acquisition*, not a merge. Merging the relist into the
    // surviving cache is the natural shortcut and it resurrects every object deleted while the
    // watch was blind, permanently.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    stream.listed(
        vec![pod("checkout-2", "uid-2", "18699")],
        ResourceVersion::new("18700"),
    );

    assert!(stream.find(Some("shop"), "checkout-1").is_none());
    assert!(stream.find(Some("shop"), "checkout-2").is_some());
    assert_eq!(stream.object_count(), 1);
}

#[test]
fn should_expose_the_gap_in_words_an_operator_can_act_on() {
    // §19.4 step 5 and Appendix D.4. A gap nobody can read is a gap nobody accounts for; the
    // description names the reason and both edges rather than saying "incomplete".
    let mut stream = live_pods();
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    stream.listed(Vec::new(), ResourceVersion::new("18700"));

    let described = stream.describe_continuity();
    assert!(described.contains("watch_expired_410"), "{described}");
    assert!(described.contains("18010"), "{described}");
    assert!(described.contains("18700"), "{described}");
}

#[test]
fn should_bound_the_change_log_and_report_a_trimmed_history_as_a_gap() {
    // §18.5 and §50.1: a watch is open for as long as an operator watches it, so a structure that
    // grows with the *event count* rather than with the collection has no bound at all. The cache
    // is bounded by the collection — ten thousand modifications of one Pod are one Pod — and the
    // change log needs a bound of its own.
    //
    // What matters more than the number is what a trimmed log *says*. §19.4 exists to stop a
    // history being handed over as whole when it is not, and a log that silently forgot its
    // oldest entries would be exactly that: an ordered list of changes that begins in the middle
    // of the period it claims to describe. So the trim is reported the way every other
    // discontinuity is — as a gap, with the version the period began at and the version the
    // retained record now begins at.
    let mut stream = live_pods();
    let events = CHANGE_LOG_CAPACITY + 500;
    for index in 0..events {
        let version = 20_000 + index;
        stream.observe(WatchEvent::Modified(pod(
            "checkout-1",
            "uid-1",
            &version.to_string(),
        )));
    }

    assert_eq!(stream.discarded_events(), 0, "every event was applied");
    assert_eq!(stream.object_count(), 1, "and the cache holds one Pod");
    assert!(
        stream.continuous_changes().len() <= CHANGE_LOG_CAPACITY,
        "the log holds its bound and not one entry more: {}",
        stream.continuous_changes().len()
    );
    assert_eq!(
        stream.trimmed_changes() + stream.continuous_changes().len(),
        events,
        "and what it no longer holds is counted rather than forgotten"
    );

    let trim = stream
        .gaps()
        .iter()
        .find(|gap| gap.reason() == GapReason::ChangeLogTrimmed)
        .expect("a trimmed record is a gap in that record");
    assert_eq!(trim.after().map(ResourceVersion::as_str), Some("18010"));
    assert!(trim.is_closed(), "the record continues after the hole");
    assert!(
        !stream.is_gap_free(),
        "and nothing may call this one whole history"
    );
    assert!(
        stream.describe_continuity().contains("change_log_trimmed"),
        "{}",
        stream.describe_continuity()
    );

    // A second period starts its own log and its own account of what it dropped, because a
    // segment is the largest span this provider may present as an ordered history (§19.4).
    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    stream.listed(Vec::new(), ResourceVersion::new("30000"));
    assert_eq!(stream.trimmed_changes(), 0);
    assert!(stream.continuous_changes().is_empty());
}

#[test]
fn should_resume_a_transient_disconnect_from_the_checkpoint_without_recording_a_gap() {
    // §19.5. A reset connection is not an expiry: the server still holds the history, so resuming
    // from the last safe checkpoint observes every change. Recording a gap here would be the
    // opposite error to Gate F — crying discontinuity at a stream that never lost any.
    let mut stream = live_pods();

    let reception = stream.observe(WatchEvent::Error(WatchFailure::Interrupted(
        "unexpected EOF".to_owned(),
    )));
    assert_eq!(reception, Reception::Suspended);
    assert_eq!(stream.state(), SyncState::Reconnecting);
    assert_eq!(
        stream.checkpoint().map(ResourceVersion::as_str),
        Some("18010"),
        "the checkpoint stays usable across a transient failure"
    );

    assert_eq!(stream.reconnected(), Ok(()));
    assert_eq!(stream.state(), SyncState::Live);
    assert!(stream.is_gap_free());
    assert_eq!(stream.gaps().len(), 0);
    assert_eq!(stream.segments().len(), 1);
}

#[test]
fn should_not_apply_events_while_the_stream_is_reconnecting() {
    // §19.5 with §41.4: a view that is reconnecting must not look live. Events cannot arrive on a
    // stream that is not connected, so anything offered in that state is out of sequence and
    // applying it would put the cache ahead of the checkpoint it claims to hold.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Error(WatchFailure::Interrupted(
        "unexpected EOF".to_owned(),
    )));

    let reception = stream.observe(WatchEvent::Added(pod("checkout-3", "uid-3", "18011")));

    assert_eq!(reception, Reception::Discarded);
    assert!(stream.find(Some("shop"), "checkout-3").is_none());
}

#[test]
fn should_refuse_to_reconnect_a_stream_that_never_listed() {
    // §19.1: watch follows list. A watch opened without a collection resourceVersion starts from
    // "now" and quietly misses everything that already exists, which reads as an empty cluster.
    let mut stream = pods();
    assert_eq!(stream.reconnected(), Err(ResumeError::NotAcquired));
}

#[test]
fn should_treat_a_denied_watch_as_a_break_rather_than_as_an_empty_result() {
    // §4 invariant 13 and §21.4. Authorization refusing the stream says nothing about what is in
    // the cluster; the honest outcome is a named break with a quarantined cache, never a live
    // view of zero objects.
    let mut stream = live_pods();

    let reception = stream.observe(WatchEvent::Error(WatchFailure::Denied));

    assert_eq!(reception, Reception::ContinuityBroken);
    assert_eq!(stream.state(), SyncState::Denied);
    assert!(!stream.absence_is_conclusive());
    assert_eq!(stream.gaps()[0].reason(), GapReason::AccessDenied);
    assert_eq!(
        stream.reconnected(),
        Err(ResumeError::AccessDenied),
        "a denial is not something a reconnect loop can retry its way past"
    );
}

#[test]
fn should_name_the_five_upstream_watch_event_classes_apart() {
    // §19.3 names five classes and two of them carry no object at all. A stream that keeps only
    // the three mutation classes has to invent something for a BOOKMARK — usually a no-op that
    // still touches the cache, or a dropped checkpoint that costs the next reconnect its
    // position.
    let object = pod("checkout-1", "uid-1", "18005");
    let events = [
        WatchEvent::Added(object.clone()),
        WatchEvent::Modified(object.clone()),
        WatchEvent::Deleted(object),
        WatchEvent::Bookmark(ResourceVersion::new("18010")),
        WatchEvent::Error(WatchFailure::Expired),
    ];

    let classes: Vec<&str> = events.iter().map(WatchEvent::class).collect();
    assert_eq!(
        classes,
        vec!["ADDED", "MODIFIED", "DELETED", "BOOKMARK", "ERROR"]
    );

    let mutations: Vec<bool> = events.iter().map(WatchEvent::is_mutation).collect();
    assert_eq!(
        mutations,
        vec![true, true, true, false, false],
        "a bookmark and an error report no resource change"
    );
}

#[test]
fn should_record_a_relist_of_a_live_stream_as_a_break_in_change_observation() {
    // §19.4's prohibition generalised: a fresh list replaces state without reporting the changes
    // that produced it. Even when nothing failed, the change history either side of that list is
    // two histories, so the segment boundary and the reason are recorded.
    let mut stream = live_pods();
    stream.listed(Vec::new(), ResourceVersion::new("19000"));

    assert_eq!(stream.segments().len(), 2);
    assert!(!stream.is_gap_free());
    assert_eq!(
        stream.gaps()[0].reason(),
        GapReason::RestartedWithoutCheckpoint
    );
    assert_eq!(stream.state(), SyncState::Live);
}

#[test]
fn should_not_read_a_reused_name_as_one_continuing_object() {
    // §4 invariants 4 and 5, §16.3, Gate C. The cache is keyed by name because that is what a
    // lookup asks for, so the recorded changes are what carries the lifetime identity: a delete
    // and a recreate under the same name are two lifetimes, never one long-lived Pod.
    let mut stream = live_pods();
    stream.observe(WatchEvent::Deleted(pod("checkout-1", "uid-1", "18011")));
    stream.observe(WatchEvent::Added(pod("checkout-1", "uid-2", "18012")));

    let uids: Vec<Option<&str>> = stream
        .continuous_changes()
        .iter()
        .map(|change| change.identity().uid())
        .collect();
    assert_eq!(uids, vec![Some("uid-1"), Some("uid-2")]);
    assert_eq!(
        stream
            .find(Some("shop"), "checkout-1")
            .and_then(Object::uid),
        Some("uid-2")
    );
}

#[test]
fn should_give_every_live_view_state_its_own_word() {
    // §41.4: syncing, live, reconnecting, gap detected and denied call for different actions from
    // whoever reads them. Rendering two of them with one word — the tempting "not live" — hides
    // the difference between a view that is starting and a view that lost its history.
    let words: Vec<&str> = vec![
        SyncState::Syncing,
        SyncState::Live,
        SyncState::Reconnecting,
        SyncState::GapDetected,
        SyncState::Denied,
    ]
    .into_iter()
    .map(SyncState::as_str)
    .collect();

    let mut unique = words.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 5, "each state needs its own word: {words:?}");
}

#[test]
fn should_bound_the_reconnect_backoff_and_never_overflow_it() {
    // §19.5 and §49.4: reconnect loops MUST be bounded. Unbounded doubling either hammers a
    // struggling API server or, once the multiplication overflows, wraps back to no delay at all.
    let mut backoff = Backoff::new(Duration::from_millis(100), Duration::from_secs(30));

    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    assert_eq!(backoff.next_delay(), Duration::from_millis(200));
    assert_eq!(backoff.next_delay(), Duration::from_millis(400));

    for _ in 0..1_000 {
        assert!(backoff.next_delay() <= Duration::from_secs(30));
    }

    backoff.reset();
    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
}

#[test]
fn should_not_let_one_reconciliation_stage_prove_another() {
    // §20.4 and §4 invariant 18. Each stage needs its own evidence: an accepted API write is not
    // an observed spec, and an observed spec is not a converged status. Treating the ladder as a
    // level — everything below the furthest stage counts as reached — is how "the apply
    // succeeded" gets rendered as "the rollout is healthy".
    let mut reconciliation = Reconciliation::new();
    reconciliation.record(ReconciliationStage::ChangeAccepted);
    assert!(!reconciliation.has_reached(ReconciliationStage::SpecObserved));

    reconciliation.record(ReconciliationStage::StatusConverged);
    assert!(
        !reconciliation.has_reached(ReconciliationStage::SpecObserved),
        "a later observation does not backfill evidence for an earlier stage"
    );
    assert!(!reconciliation.has_reached(ReconciliationStage::ExternallyHealthy));
    assert_eq!(
        reconciliation.furthest(),
        Some(ReconciliationStage::StatusConverged)
    );
    assert!(
        reconciliation
            .unproven()
            .contains(&ReconciliationStage::ExternallyHealthy)
    );
}

#[test]
fn should_survive_the_canonical_watch_expiry_scenario() {
    // §60.4 end to end: known state, injected 410, gap state, relist, live again, and a temporal
    // record that never claims gap-free continuity across the break.
    let mut stream = pods();
    stream.listed(
        vec![pod("checkout-1", "uid-1", "18000")],
        ResourceVersion::new("18001"),
    );
    stream.observe(WatchEvent::Modified(pod("checkout-1", "uid-1", "18001")));
    assert_eq!(stream.state(), SyncState::Live);

    stream.observe(WatchEvent::Error(WatchFailure::Expired));
    assert_eq!(stream.state(), SyncState::GapDetected);

    stream.listed(
        vec![pod("checkout-1", "uid-1", "18720")],
        ResourceVersion::new("18722"),
    );
    stream.observe(WatchEvent::Bookmark(ResourceVersion::new("18730")));

    assert_eq!(stream.state(), SyncState::Live);
    assert!(stream.absence_is_conclusive());
    assert!(!stream.is_gap_free());
    assert_eq!(stream.gaps().len(), 1);
    assert_eq!(stream.segments().len(), 2);
    assert_eq!(
        stream.checkpoint().map(ResourceVersion::as_str),
        Some("18730")
    );
}

// --- decoding the wire (§19.3) ------------------------------------------------------------------

/// One watch frame as the API server writes it: a JSON object, then a newline.
fn frame(class: &str, object: &str) -> String {
    format!(r#"{{"type":"{class}","object":{object}}}"#) + "\n"
}

/// A Pod as a watch frame carries it, which is the whole object rather than a summary.
fn pod_json(name: &str, uid: &str, resource_version: &str) -> String {
    format!(
        r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"{name}","namespace":"shop",
           "uid":"{uid}","resourceVersion":"{resource_version}"}}}}"#
    )
    .replace('\n', "")
}

/// A `Status` as the server sends it inside an `ERROR` frame.
fn status_json(code: u16, reason: &str, message: &str) -> String {
    format!(
        r#"{{"kind":"Status","apiVersion":"v1","metadata":{{}},"status":"Failure",
           "message":"{message}","reason":"{reason}","code":{code}}}"#
    )
    .replace('\n', "")
}

/// A chunked HTTP response body, framed exactly as a keep-alive watch delivers one.
fn chunked_response(chunks: &[&str]) -> String {
    let mut text =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_owned();
    for chunk in chunks {
        text.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
    }
    text.push_str("0\r\n\r\n");
    text
}

#[test]
fn should_decode_each_watch_frame_into_the_event_class_it_names() {
    // §19.3: the five upstream classes are distinct and the provider MUST understand them. The
    // plausible mistake is to decode only the object and treat every frame as a change, which
    // turns a DELETED into an upsert and leaves the cache holding an object the cluster removed.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let wire = format!(
        "{}{}{}",
        frame("ADDED", &pod_json("checkout-1", "uid-1", "18011")),
        frame("MODIFIED", &pod_json("checkout-1", "uid-1", "18012")),
        frame("DELETED", &pod_json("checkout-1", "uid-1", "18013")),
    );

    let events = decoder.decode(wire.as_bytes()).expect("the frames decode");

    let classes: Vec<&str> = events.iter().map(WatchEvent::class).collect();
    assert_eq!(classes, ["ADDED", "MODIFIED", "DELETED"]);
    assert!(events.iter().all(WatchEvent::is_mutation));
    match &events[0] {
        WatchEvent::Added(object) => {
            assert_eq!(object.name(), "checkout-1");
            assert_eq!(object.uid(), Some("uid-1"));
            assert_eq!(object.resource_version(), Some("18011"));
        }
        other => panic!("the first frame is an ADDED, not {other:?}"),
    }
}

#[test]
fn should_decode_a_bookmark_as_a_checkpoint_carrying_no_object_change() {
    // §19.3: a BOOKMARK's object holds nothing but metadata.resourceVersion, and it is a
    // continuity signal rather than a mutation. Decoding it through the object path is the
    // plausible mistake: the frame parses as an object with no name, and the cache acquires a
    // phantom entry — or worse, the frame is dropped and the checkpoint never advances, so every
    // reconnect asks for a position further in the past than the server still holds.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let wire = frame(
        "BOOKMARK",
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"resourceVersion":"18730"}}"#,
    );

    let events = decoder
        .decode(wire.as_bytes())
        .expect("the bookmark decodes");

    assert_eq!(events.len(), 1);
    assert!(!events[0].is_mutation());
    assert_eq!(
        events[0],
        WatchEvent::Bookmark(ResourceVersion::new("18730"))
    );

    let mut stream = live_pods();
    let before = stream.continuous_changes().len();
    assert_eq!(stream.observe(events[0].clone()), Reception::Checkpointed);
    assert_eq!(
        stream.checkpoint().map(ResourceVersion::as_str),
        Some("18730")
    );
    assert_eq!(stream.continuous_changes().len(), before);
}

#[test]
fn should_decode_a_410_error_frame_as_an_expiry_rather_than_a_generic_failure() {
    // §19.4 and §4 invariant 14. A `410 Gone` arrives inside the stream as an ERROR frame whose
    // object is a Status, not as an HTTP status code — the response was `200 OK` minutes ago.
    // Reading it as an unspecified failure is the plausible mistake and the expensive one: the
    // stream would go to Reconnecting, resume from a checkpoint the server has discarded, and
    // present the events after the break as a continuation of the history before it.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let wire = frame(
        "ERROR",
        &status_json(410, "Expired", "too old resource version: 18010 (18700)"),
    );

    let events = decoder.decode(wire.as_bytes()).expect("the error decodes");

    assert_eq!(events, vec![WatchEvent::Error(WatchFailure::Expired)]);

    let mut stream = live_pods();
    assert_eq!(
        stream.observe(events[0].clone()),
        Reception::ContinuityBroken
    );
    assert_eq!(stream.state(), SyncState::GapDetected);
    assert_eq!(stream.gaps().len(), 1);
    assert_eq!(stream.gaps()[0].reason(), GapReason::Expired);
    assert_eq!(stream.checkpoint(), None);
}

#[test]
fn should_decode_a_forbidden_error_frame_as_a_denial_rather_than_an_expiry() {
    // §21.4 and §4 invariant 13: a refused watch leaves the upstream state unknown, and an
    // expiry says the history is gone. Both break continuity and they are not the same break —
    // collapsing them would relist a collection the identity may not read at all.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let wire = frame(
        "ERROR",
        &status_json(403, "Forbidden", "pods is forbidden: no permission"),
    );

    let events = decoder.decode(wire.as_bytes()).expect("the error decodes");

    assert_eq!(events, vec![WatchEvent::Error(WatchFailure::Denied)]);

    let mut stream = live_pods();
    stream.observe(events[0].clone());
    assert_eq!(stream.state(), SyncState::Denied);
    assert_eq!(stream.gaps()[0].reason(), GapReason::AccessDenied);
}

#[test]
fn should_decode_an_unclassified_error_frame_as_an_interruption_that_keeps_the_checkpoint() {
    // §19.5: a server-side blip is not a continuity break. The checkpoint still names history the
    // server holds, so the stream may resume from it. Treating every ERROR as an expiry is the
    // plausible over-correction, and it throws away a usable position and forces a full relist.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let wire = frame(
        "ERROR",
        &status_json(500, "InternalError", "etcd is unavailable"),
    );

    let events = decoder.decode(wire.as_bytes()).expect("the error decodes");

    match &events[0] {
        WatchEvent::Error(WatchFailure::Interrupted(detail)) => {
            assert!(
                detail.contains("etcd is unavailable"),
                "the interruption keeps what the server said, but was {detail:?}"
            );
        }
        other => panic!("a 500 is an interruption, not {other:?}"),
    }

    let mut stream = live_pods();
    assert_eq!(stream.observe(events[0].clone()), Reception::Suspended);
    assert_eq!(stream.state(), SyncState::Reconnecting);
    assert!(stream.checkpoint().is_some());
    assert!(stream.reconnected().is_ok());
}

#[test]
fn should_hold_a_frame_split_across_two_chunks_until_it_is_whole() {
    // Chunked transfer framing and JSON framing are unrelated: a chunk boundary lands wherever
    // the server's writer flushed, routinely mid-object and even mid-string. Decoding each chunk
    // on its own is the plausible mistake — it fails to parse a perfectly good event, and a
    // decoder that then skips the unparsable bytes drops a change nobody will ever see again.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let whole = frame("ADDED", &pod_json("checkout-1", "uid-1", "18011"));
    let (head, tail) = whole.split_at(whole.len() / 2);

    assert_eq!(
        decoder
            .decode(head.as_bytes())
            .expect("a partial frame is not an error"),
        Vec::new(),
        "half an object is not an event yet"
    );
    assert!(decoder.pending_bytes() > 0);

    let events = decoder
        .decode(tail.as_bytes())
        .expect("the frame completes");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].class(), "ADDED");
    assert_eq!(decoder.pending_bytes(), 0);
}

#[test]
fn should_decode_the_frames_of_a_chunked_watch_response_off_the_transport() {
    // §19.1 end to end over recorded bytes: the response the API server writes for
    // `?watch=true` is a chunked body whose chunks are watch frames, and `next_chunk` hands them
    // over one at a time. This is the connection the provider did not have — the state machine
    // was only ever fed by hand — so the test drives it the way the real path will: bytes in,
    // WatchEvents out, a stream that is live at the end.
    let pod_one = pod_json("checkout-1", "uid-1", "18011");
    let pod_two = pod_json("checkout-2", "uid-2", "18012");
    let added = frame("ADDED", &pod_one);
    let modified = frame("MODIFIED", &pod_two);
    let bookmark = frame(
        "BOOKMARK",
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"resourceVersion":"18999"}}"#,
    );
    // The second frame is deliberately cut in half across two chunks.
    let (modified_head, modified_tail) = modified.split_at(modified.len() / 2);
    let wire = chunked_response(&[&added, modified_head, &format!("{modified_tail}{bookmark}")]);

    let mut connection = HttpConnection::new(FixtureStream::new(&wire), HOST);
    let request = watch_request(
        &Gvr::new("", "v1", "pods"),
        &Scope::in_namespace("shop"),
        &ListOptions::new(),
        Some("18010"),
    );
    let mut response = connection.open(&request).expect("the watch response opens");
    assert_eq!(response.status(), 200);

    let mut decoder = WatchDecoder::new(INSTANCE);
    let mut stream = live_pods();
    let mut receptions = Vec::new();
    while let Some(chunk) = response.next_chunk() {
        let chunk = chunk.expect("the chunk is framed");
        for event in decoder.decode(&chunk).expect("the frames decode") {
            receptions.push(stream.observe(event));
        }
    }

    assert_eq!(
        receptions,
        vec![
            Reception::Applied,
            Reception::Applied,
            Reception::Checkpointed
        ]
    );
    assert_eq!(stream.state(), SyncState::Live);
    assert_eq!(stream.object_count(), 2);
    assert!(stream.find(Some("shop"), "checkout-2").is_some());
    assert_eq!(
        stream.checkpoint().map(ResourceVersion::as_str),
        Some("18999")
    );
    assert!(stream.is_gap_free());
}

#[test]
fn should_refuse_a_frame_whose_class_it_does_not_model() {
    // §19.3 lists the classes that matter for continuity and says "including", so a future
    // Kubernetes release may add one. Skipping the unknown frame is the plausible mistake: the
    // stream would carry on looking continuous while something the server considered worth
    // sending was never accounted for. Saying so lets the caller break continuity deliberately.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let wire = frame("RESYNC", &pod_json("checkout-1", "uid-1", "18011"));

    let failure = decoder
        .decode(wire.as_bytes())
        .expect_err("an unmodelled class is not silently dropped");

    assert_eq!(failure, FrameError::UnknownClass("RESYNC".to_owned()));
    assert!(failure.to_string().contains("RESYNC"));
}

#[test]
fn should_not_decode_a_truncated_final_frame_as_an_event() {
    // A watch stream that is cut mid-object ends with bytes that are not a frame. Parsing them
    // anyway would either fail loudly for the wrong reason or, with a lenient parser, invent a
    // half-populated object. The truncation is itself the news: it is an interruption (§19.5),
    // not a malformed protocol, and the checkpoint survives it.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let whole = frame("ADDED", &pod_json("checkout-1", "uid-1", "18011"));
    let (head, _) = whole.split_at(whole.len() / 2);

    assert!(
        decoder
            .decode(head.as_bytes())
            .expect("no frame yet")
            .is_empty()
    );

    assert_eq!(
        decoder.finish().expect_err("a cut frame is not an event"),
        FrameError::Truncated
    );
}

#[test]
fn should_refuse_a_bookmark_that_names_no_position() {
    // §19.3: a BOOKMARK's entire content is the resourceVersion it checkpoints. One without it
    // checkpoints nothing, and the plausible mistake — checkpointing at the empty string — sends
    // the next watch request to a position the server will reject or, worse, silently read as
    // "from now", which skips everything in between.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let wire = frame(
        "BOOKMARK",
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{}}"#,
    );

    assert_eq!(
        decoder
            .decode(wire.as_bytes())
            .expect_err("a bookmark without a position is not a checkpoint"),
        FrameError::UncheckpointedBookmark
    );
}

#[test]
fn should_ignore_the_blank_lines_between_frames() {
    // Servers and proxies do insert an empty line. Treating one as a frame produces a JSON parse
    // failure that ends a perfectly healthy watch.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let wire = format!(
        "\n{}\n\n",
        frame("ADDED", &pod_json("checkout-1", "uid-1", "18011"))
    );

    let events = decoder.decode(wire.as_bytes()).expect("the frame decodes");

    assert_eq!(events.len(), 1);
    assert_eq!(decoder.pending_bytes(), 0);
}

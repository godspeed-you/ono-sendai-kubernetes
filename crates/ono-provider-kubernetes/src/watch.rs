//! What a watch actually observed, and where it stopped being able to say so.
//!
//! Specification §19, §20.3, §20.4 and §4 invariants 6 and 14. A watch is the only mechanism this
//! provider has for claiming it saw a change *happen* rather than finding a different state
//! later, and that claim is worth exactly as much as the continuity behind it.
//!
//! ```text
//! syncing        listed nothing yet; the cache is empty because nobody read, not because the
//!                cluster is
//! live           listed, watching, every change since the list observed
//! reconnecting   the connection dropped; the checkpoint still names history the server holds
//! gap detected   410 Gone; the history the checkpoint named is gone with it
//! denied         authorization refused the stream; what is upstream is unknown, not absent
//! ```
//!
//! `410 Gone` is the case everything here is shaped around (§19.4, Gate F). The comfortable
//! response — relist, keep appending to the same history, carry on — produces a change record
//! that looks complete and is not, which is worse than no record at all because it invites
//! conclusions. So an expiry closes the current observation segment, voids the checkpoint,
//! quarantines the cache, and the changes seen afterwards land in a new segment that is never
//! concatenated with the old one (§63.11).
//!
//! Nothing here does I/O. A stream is fed events and asked questions, so the awkward sequences —
//! expiry mid-stream, an event arriving after the break, a relist that resurrects a deleted
//! object — are ordinary tests rather than a cluster somebody has to break on purpose.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde_json::Value as Json;

use crate::coverage::Scope;
use crate::discovery::Gvr;
use crate::object::{Identity, Object};

/// A Kubernetes continuity token, as opaque as the server means it to be.
///
/// Deliberately not ordered (§4 invariant 6, §14.3). Kubernetes documents `resourceVersion` as an
/// opaque string; that it usually *looks* like an increasing integer is an etcd implementation
/// detail the API contract does not promise. A type with `Ord` on it invites `max()`, sorting a
/// change list by it, and comparing one across two resources as if it were a clock — three
/// mistakes that pass every test written against a cluster that happens to hand out integers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceVersion(String);

impl ResourceVersion {
    /// Takes the token as the server wrote it.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// The token, unchanged.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a watch stopped delivering events (§19.3 `ERROR`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchFailure {
    /// `410 Gone`: the server no longer holds the history the checkpoint names (§19.4).
    Expired,
    /// The stream ended without the server saying the history is gone — a reset, a timeout, a
    /// proxy closing an idle connection. The checkpoint stays usable (§19.5).
    Interrupted(String),
    /// Authorization refused the stream (§21.4, §4 invariant 13).
    Denied,
}

impl fmt::Display for WatchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => f.write_str("the watch expired: 410 Gone"),
            Self::Interrupted(detail) => write!(f, "the watch was interrupted: {detail}"),
            Self::Denied => f.write_str("the watch was denied"),
        }
    }
}

/// One event as it arrives from the watch stream (§19.3).
#[derive(Debug, Clone, PartialEq)]
pub enum WatchEvent {
    /// An object entered the watched set.
    Added(Object),
    /// A watched object changed.
    Modified(Object),
    /// An object left the watched set.
    Deleted(Object),
    /// A checkpoint, carrying a resourceVersion and no object change.
    Bookmark(ResourceVersion),
    /// The stream failed.
    Error(WatchFailure),
}

impl WatchEvent {
    /// The upstream class name, spelled as the API spells it.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            Self::Added(_) => "ADDED",
            Self::Modified(_) => "MODIFIED",
            Self::Deleted(_) => "DELETED",
            Self::Bookmark(_) => "BOOKMARK",
            Self::Error(_) => "ERROR",
        }
    }

    /// Whether the event reports that a resource changed.
    ///
    /// False for `BOOKMARK` and `ERROR`. A bookmark says "you are still current at this version"
    /// and nothing about any object; routing it through the mutation path is how a cache picks up
    /// a change the cluster never made (§19.3).
    #[must_use]
    pub fn is_mutation(&self) -> bool {
        matches!(self, Self::Added(_) | Self::Modified(_) | Self::Deleted(_))
    }
}

/// What kind of change an observation recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeClass {
    /// The object entered the watched set.
    Added,
    /// The object changed.
    Modified,
    /// The object left the watched set.
    Deleted,
}

impl ChangeClass {
    /// The word this change is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
        }
    }
}

/// One change this stream saw happen, with the identity it happened to.
///
/// The identity rather than the name (§4 invariants 4 and 5): a delete and a recreate under one
/// name are two lifetimes, and a change log keyed by name alone reads them as one object that
/// briefly went away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedChange {
    class: ChangeClass,
    identity: Identity,
    resource_version: Option<ResourceVersion>,
}

impl ObservedChange {
    /// What happened.
    #[must_use]
    pub fn class(&self) -> ChangeClass {
        self.class
    }

    /// Who it happened to.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The version the object carried when it was observed.
    #[must_use]
    pub fn resource_version(&self) -> Option<&ResourceVersion> {
        self.resource_version.as_ref()
    }
}

/// One unbroken period of observation.
///
/// A segment is the largest span this provider may present as an ordered history: it begins at a
/// resourceVersion the server handed out and holds every change seen from there until continuity
/// broke. Two segments are two histories, and the space between them is the gap (§39.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    started_at: ResourceVersion,
    closed_at: Option<ResourceVersion>,
    changes: Vec<ObservedChange>,
}

impl Segment {
    /// The version this period of observation began at.
    #[must_use]
    pub fn started_at(&self) -> &ResourceVersion {
        &self.started_at
    }

    /// The last version observed before continuity broke, for a segment that ended.
    #[must_use]
    pub fn closed_at(&self) -> Option<&ResourceVersion> {
        self.closed_at.as_ref()
    }

    /// Whether this period is still being observed.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }

    /// The changes seen in this period, in the order they arrived.
    #[must_use]
    pub fn changes(&self) -> &[ObservedChange] {
        &self.changes
    }
}

/// Why observation stopped being continuous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    /// `410 Gone` — the requested history is no longer available (§19.4).
    Expired,
    /// Authorization refused the stream, so the period is unobserved rather than uneventful.
    AccessDenied,
    /// State was re-acquired by listing rather than resumed from a checkpoint, so the changes
    /// that produced the new state were never seen.
    RestartedWithoutCheckpoint,
}

impl GapReason {
    /// The token this reason is reported under, matching Appendix D.4.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "watch_expired_410",
            Self::AccessDenied => "watch_denied",
            Self::RestartedWithoutCheckpoint => "restarted_without_checkpoint",
        }
    }
}

/// A period this stream could not observe.
///
/// Not a [`crate::coverage::Gap`], which answers a different question: a coverage gap says a
/// *scope* produced no objects and why, and its vocabulary is about reachability and permission
/// at one moment. A watch gap is about time — it needs the continuity token observation stopped
/// after and the one it resumed at, which is what lets a reader place an observation on the
/// correct side of the break. Folding the two together would cost either the tokens or the
/// scopes, and both are load-bearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchGap {
    reason: GapReason,
    after: Option<ResourceVersion>,
    resumed_at: Option<ResourceVersion>,
}

impl WatchGap {
    /// Why continuity broke.
    #[must_use]
    pub fn reason(&self) -> GapReason {
        self.reason
    }

    /// The last version observed before the break, where there was one.
    #[must_use]
    pub fn after(&self) -> Option<&ResourceVersion> {
        self.after.as_ref()
    }

    /// The version observation resumed at, once it did.
    #[must_use]
    pub fn resumed_at(&self) -> Option<&ResourceVersion> {
        self.resumed_at.as_ref()
    }

    /// Whether the stream has re-acquired state after this gap.
    ///
    /// A closed gap is still a gap. Closing it says observation continues, never that the
    /// unobserved period was filled in (§19.4).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.resumed_at.is_some()
    }

    /// The gap in words, in the shape Appendix D.4 sketches.
    #[must_use]
    pub fn describe(&self) -> String {
        let after = self.after.as_ref().map_or_else(
            || "an unknown position".to_owned(),
            ResourceVersion::to_string,
        );
        let mut described = format!("gap after {after}: {}", self.reason.as_str());
        if let Some(resumed) = &self.resumed_at {
            described.push_str(&format!(", resumed at {resumed}"));
        }
        described
    }
}

/// What a live view may honestly show about a stream (§41.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// The initial list has not completed. Absence here is absence of reading (§20.3).
    Syncing,
    /// Listed and watching, with every change since the list observed.
    Live,
    /// The connection dropped and the checkpoint still names history the server holds (§19.5).
    Reconnecting,
    /// Continuity broke and state has not been re-acquired (§19.4).
    GapDetected,
    /// Authorization refused the stream (§21.4).
    Denied,
}

impl SyncState {
    /// The word this state is shown under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Syncing => "syncing",
            Self::Live => "live",
            Self::Reconnecting => "reconnecting",
            Self::GapDetected => "gap detected",
            Self::Denied => "denied",
        }
    }
}

impl fmt::Display for SyncState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the stream did with an event it was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reception {
    /// The cache changed and the change went into the current segment.
    Applied,
    /// A checkpoint moved and nothing else did (§19.3).
    Checkpointed,
    /// The stream stopped delivering and may resume from its checkpoint (§19.5).
    Suspended,
    /// Continuity broke; a fresh acquisition is required before anything is applied (§19.4).
    ContinuityBroken,
    /// The stream was not receiving, so the event was not applied. Applying it would file a
    /// post-break change inside a pre-break history.
    Discarded,
}

/// Why a stream could not resume from where it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeError {
    /// No list has completed, so there is no version to watch from (§19.1).
    NotAcquired,
    /// The checkpoint named history the server has discarded (§19.4).
    CheckpointExpired,
    /// Authorization refused the stream (§21.4).
    AccessDenied,
}

impl fmt::Display for ResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAcquired => f.write_str(
                "the stream has no checkpoint: a watch follows a list, and one opened without a \
                 collection resourceVersion starts from now and misses what already exists",
            ),
            Self::CheckpointExpired => f.write_str(
                "the checkpoint expired: the server no longer holds that history, so state must \
                 be acquired afresh",
            ),
            Self::AccessDenied => f.write_str("the watch was denied"),
        }
    }
}

impl std::error::Error for ResumeError {}

/// How a cached object is looked up: what a human asks for, which is a name (§16.2).
type CacheKey = (Option<String>, String);

/// One watched collection: its cache, its continuity, and what it will not claim.
#[derive(Debug, Clone)]
pub struct WatchStream {
    gvr: Gvr,
    scope: Scope,
    state: SyncState,
    checkpoint: Option<ResourceVersion>,
    objects: BTreeMap<CacheKey, Object>,
    segments: Vec<Segment>,
    gaps: Vec<WatchGap>,
    discarded: usize,
}

impl WatchStream {
    /// A stream over one collection, before anything has been read.
    ///
    /// It starts in [`SyncState::Syncing`] rather than empty-and-live, because those two states
    /// answer the question "is there a Pod called X" differently and only one of them is entitled
    /// to say no (§20.3).
    #[must_use]
    pub fn new(gvr: Gvr, scope: Scope) -> Self {
        Self {
            gvr,
            scope,
            state: SyncState::Syncing,
            checkpoint: None,
            objects: BTreeMap::new(),
            segments: Vec::new(),
            gaps: Vec::new(),
            discarded: 0,
        }
    }

    /// The REST collection being watched (§13.1).
    #[must_use]
    pub fn gvr(&self) -> &Gvr {
        &self.gvr
    }

    /// What the stream was asked to cover.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// What a live view may show right now.
    #[must_use]
    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Records a completed list: the objects it returned and the collection's resourceVersion.
    ///
    /// This serves both §19.1's initial list and §19.4's fresh acquisition after a break. The
    /// version is the *collection's* — the one the watch must open from — not the newest version
    /// among the objects, which would skip whatever the server folded into the snapshot after it.
    ///
    /// The cache is replaced rather than merged. A merge keeps objects that were deleted while
    /// nobody was watching, and keeps them forever, because no delete event for them will ever
    /// arrive.
    pub fn listed(&mut self, objects: Vec<Object>, collection_version: ResourceVersion) {
        self.close_open_segment();

        let has_open_gap = self.gaps.last().is_some_and(|gap| !gap.is_closed());
        if has_open_gap {
            if let Some(gap) = self.gaps.last_mut() {
                gap.resumed_at = Some(collection_version.clone());
            }
        } else if !self.segments.is_empty() {
            // Re-listing a stream that never failed still splits the record: the changes that
            // produced the new state were not observed, they were inferred from the snapshot.
            self.gaps.push(WatchGap {
                reason: GapReason::RestartedWithoutCheckpoint,
                after: self.checkpoint.clone(),
                resumed_at: Some(collection_version.clone()),
            });
        }

        self.objects = objects
            .into_iter()
            .map(|object| (key_of(&object), object))
            .collect();
        self.checkpoint = Some(collection_version.clone());
        self.segments.push(Segment {
            started_at: collection_version,
            closed_at: None,
            changes: Vec::new(),
        });
        self.state = SyncState::Live;
    }

    /// Feeds one event to the stream and says what became of it.
    pub fn observe(&mut self, event: WatchEvent) -> Reception {
        match event {
            WatchEvent::Error(failure) => self.fail(&failure),
            WatchEvent::Bookmark(version) => {
                if self.state != SyncState::Live {
                    return self.discard();
                }
                self.checkpoint = Some(version);
                Reception::Checkpointed
            }
            WatchEvent::Added(object) => self.record(ChangeClass::Added, object),
            WatchEvent::Modified(object) => self.record(ChangeClass::Modified, object),
            WatchEvent::Deleted(object) => self.record(ChangeClass::Deleted, object),
        }
    }

    /// Resumes a suspended stream from its checkpoint (§19.5).
    ///
    /// # Errors
    ///
    /// [`ResumeError::CheckpointExpired`] after a `410 Gone`, because the token names history the
    /// server discarded and re-sending it asks for the same vanished position again;
    /// [`ResumeError::NotAcquired`] when no list has completed; [`ResumeError::AccessDenied`]
    /// when authorization refused the stream.
    pub fn reconnected(&mut self) -> Result<(), ResumeError> {
        match self.state {
            SyncState::Syncing => Err(ResumeError::NotAcquired),
            SyncState::GapDetected => Err(ResumeError::CheckpointExpired),
            SyncState::Denied => Err(ResumeError::AccessDenied),
            SyncState::Live | SyncState::Reconnecting => {
                if self.checkpoint.is_none() {
                    return Err(ResumeError::NotAcquired);
                }
                self.state = SyncState::Live;
                Ok(())
            }
        }
    }

    /// The version the next watch request opens from (§19.1).
    ///
    /// Absent once an expiry voided it: there is no position to resume from, and offering the old
    /// token would send a reconnect loop back to a history that no longer exists.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&ResourceVersion> {
        self.checkpoint.as_ref()
    }

    /// Whether the cache has completed an initial synchronization (§20.3).
    ///
    /// Survives a transient disconnect — the cache is still coherent as of its checkpoint — and
    /// does not survive an expiry, which is what "quarantine" means here (§19.4).
    #[must_use]
    pub fn has_synced(&self) -> bool {
        matches!(self.state, SyncState::Live | SyncState::Reconnecting)
    }

    /// Whether a name missing from the cache may be reported as missing from the cluster.
    ///
    /// Only while live. A synchronized cache that is no longer being fed knows what was true at
    /// its checkpoint, and an object created since then is absent from it for a reason that has
    /// nothing to do with the cluster (§20.3, §4 invariant 13).
    #[must_use]
    pub fn absence_is_conclusive(&self) -> bool {
        self.state == SyncState::Live
    }

    /// One cached object by the namespace and name a human looks it up with.
    #[must_use]
    pub fn find(&self, namespace: Option<&str>, name: &str) -> Option<&Object> {
        self.objects
            .get(&(namespace.map(str::to_owned), name.to_owned()))
    }

    /// Every cached object.
    pub fn objects(&self) -> impl Iterator<Item = &Object> {
        self.objects.values()
    }

    /// How many objects the cache holds.
    ///
    /// Deliberately not an `is_empty`: whether zero means anything is
    /// [`Self::absence_is_conclusive`]'s question, and a caller that has to reach for the count
    /// is one step less likely to render "0 Pods" over a cache that never synchronized.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Every observation period, oldest first, each one internally continuous.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// The changes of the current unbroken period, and only those.
    ///
    /// The whole point of the segment model. Concatenating the periods either side of a gap would
    /// produce an ordered change list that reads as complete while missing everything that
    /// happened during the break (§19.4, §63.11).
    #[must_use]
    pub fn continuous_changes(&self) -> &[ObservedChange] {
        self.segments.last().map_or(&[], Segment::changes)
    }

    /// Whether one unbroken period covers everything this stream has observed.
    #[must_use]
    pub fn is_gap_free(&self) -> bool {
        self.gaps.is_empty() && self.segments.len() < 2
    }

    /// The periods this stream could not observe (§19.4 step 5).
    #[must_use]
    pub fn gaps(&self) -> &[WatchGap] {
        &self.gaps
    }

    /// How many events were handed to a stream that was not receiving.
    ///
    /// A count worth keeping rather than a silent drop: events arriving while the stream is
    /// broken mean something upstream is still feeding a consumer that must not trust them.
    #[must_use]
    pub fn discarded_events(&self) -> usize {
        self.discarded
    }

    /// The continuity of this stream in one line.
    ///
    /// A gap nobody can read is a gap nobody accounts for. This names the state, where the
    /// current period began, and every break with both of its edges (Appendix D.4).
    #[must_use]
    pub fn describe_continuity(&self) -> String {
        let mut parts = vec![self.state.as_str().to_owned()];
        if let Some(segment) = self.segments.last() {
            parts.push(format!("continuous from {}", segment.started_at));
        }
        parts.extend(self.gaps.iter().map(WatchGap::describe));
        parts.join("; ")
    }

    fn record(&mut self, class: ChangeClass, object: Object) -> Reception {
        if self.state != SyncState::Live {
            return self.discard();
        }
        let change = ObservedChange {
            class,
            identity: object.identity(),
            resource_version: object.resource_version().map(ResourceVersion::new),
        };
        if let Some(version) = object.resource_version() {
            self.checkpoint = Some(ResourceVersion::new(version));
        }
        let key = key_of(&object);
        match class {
            ChangeClass::Added | ChangeClass::Modified => {
                self.objects.insert(key, object);
            }
            ChangeClass::Deleted => {
                self.objects.remove(&key);
            }
        }
        if let Some(segment) = self.segments.last_mut() {
            segment.changes.push(change);
        }
        Reception::Applied
    }

    fn fail(&mut self, failure: &WatchFailure) -> Reception {
        match failure {
            WatchFailure::Interrupted(_) => {
                if self.state == SyncState::Live {
                    self.state = SyncState::Reconnecting;
                }
                Reception::Suspended
            }
            WatchFailure::Expired => {
                self.break_continuity(GapReason::Expired, SyncState::GapDetected)
            }
            WatchFailure::Denied => {
                self.break_continuity(GapReason::AccessDenied, SyncState::Denied)
            }
        }
    }

    fn break_continuity(&mut self, reason: GapReason, state: SyncState) -> Reception {
        if matches!(self.state, SyncState::GapDetected | SyncState::Denied) {
            return Reception::ContinuityBroken;
        }
        self.close_open_segment();
        self.gaps.push(WatchGap {
            reason,
            after: self.checkpoint.take(),
            resumed_at: None,
        });
        self.state = state;
        Reception::ContinuityBroken
    }

    fn close_open_segment(&mut self) {
        let checkpoint = self.checkpoint.clone();
        if let Some(segment) = self.segments.last_mut()
            && segment.is_open()
        {
            segment.closed_at = checkpoint;
        }
    }

    fn discard(&mut self) -> Reception {
        self.discarded += 1;
        Reception::Discarded
    }
}

fn key_of(object: &Object) -> CacheKey {
    (
        object.namespace().map(str::to_owned),
        object.name().to_owned(),
    )
}

/// A bounded reconnect delay (§19.5, §49.4).
///
/// Doubling with a ceiling, and the ceiling is the point: an unbounded loop either hammers an API
/// server that is already struggling or, once the multiplication overflows, wraps round to no
/// delay at all — which is the same thing with an alibi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backoff {
    base: Duration,
    ceiling: Duration,
    attempt: u32,
}

impl Backoff {
    /// A backoff that starts at `base` and never waits longer than `ceiling`.
    #[must_use]
    pub fn new(base: Duration, ceiling: Duration) -> Self {
        Self {
            base,
            ceiling,
            attempt: 0,
        }
    }

    /// How long to wait before the next attempt.
    #[must_use = "the delay is the whole point of asking"]
    pub fn next_delay(&mut self) -> Duration {
        let factor = 2_u32.checked_pow(self.attempt).unwrap_or(u32::MAX);
        self.attempt = self.attempt.saturating_add(1);
        self.base.saturating_mul(factor).min(self.ceiling)
    }

    /// Starts over, after an attempt that worked.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// How many delays have been handed out since the last reset.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempt
    }
}

/// A stage a desired-state change passes through (§20.4).
///
/// An ordered ladder, and ordering it is safe only because nothing here infers one rung from
/// another: the sequence describes what must happen, never what did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReconciliationStage {
    /// The API server accepted the write.
    ChangeAccepted,
    /// The object was observed carrying the new spec.
    SpecObserved,
    /// A controller reported having observed that generation.
    GenerationObserved,
    /// Status reached the desired condition.
    StatusConverged,
    /// The workload is healthy as something outside Kubernetes sees it.
    ExternallyHealthy,
}

impl ReconciliationStage {
    /// Every stage, in the order they must occur.
    #[must_use]
    pub fn ladder() -> [Self; 5] {
        [
            Self::ChangeAccepted,
            Self::SpecObserved,
            Self::GenerationObserved,
            Self::StatusConverged,
            Self::ExternallyHealthy,
        ]
    }

    /// The word this stage is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChangeAccepted => "change accepted",
            Self::SpecObserved => "spec observed",
            Self::GenerationObserved => "generation observed",
            Self::StatusConverged => "status converged",
            Self::ExternallyHealthy => "externally healthy",
        }
    }
}

/// What has actually been observed of one asynchronous change (§20.4, §4 invariant 18).
///
/// Every stage carries its own evidence and none is inferred from a neighbour. The tempting
/// shortcut is a single "level" — the furthest stage reached, with everything below it assumed —
/// and it is how "the apply succeeded" becomes "the rollout is healthy" without anyone deciding
/// to claim that.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciliation {
    reached: BTreeSet<ReconciliationStage>,
}

impl Reconciliation {
    /// A change nothing has yet been observed about.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records evidence that one stage was reached.
    pub fn record(&mut self, stage: ReconciliationStage) {
        self.reached.insert(stage);
    }

    /// Whether this stage has evidence of its own.
    #[must_use]
    pub fn has_reached(&self, stage: ReconciliationStage) -> bool {
        self.reached.contains(&stage)
    }

    /// The furthest stage with evidence.
    ///
    /// Stages before it may still be unproven, and stages after it are unknown rather than failed.
    #[must_use]
    pub fn furthest(&self) -> Option<ReconciliationStage> {
        self.reached.iter().copied().next_back()
    }

    /// The stages nothing has been observed for.
    #[must_use]
    pub fn unproven(&self) -> Vec<ReconciliationStage> {
        ReconciliationStage::ladder()
            .into_iter()
            .filter(|stage| !self.reached.contains(stage))
            .collect()
    }

    /// What is proven and what is not, in words.
    #[must_use]
    pub fn describe(&self) -> String {
        ReconciliationStage::ladder()
            .into_iter()
            .map(|stage| {
                let mark = if self.has_reached(stage) {
                    "observed"
                } else {
                    "unknown"
                };
                format!("{}: {mark}", stage.as_str())
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// --- the wire (§19.3) ---------------------------------------------------------------------------

/// Why a watch frame could not be read as an event.
///
/// Every variant is a refusal rather than a silent skip. A decoder that drops what it cannot read
/// leaves the stream looking continuous over bytes nobody accounted for, which is the same lie
/// §19.4 forbids after a `410` — arrived at by a quieter route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The frame is not a JSON object, or the stream is not a watch stream at all.
    Malformed(String),
    /// The frame carries no `type`, so nothing says what it is.
    Untyped,
    /// A `type` this provider does not model (§19.3 lists the classes it must, and says
    /// "including" — a later Kubernetes release may add one).
    UnknownClass(String),
    /// The frame carries a class but no `object`, which every class sends one of.
    ObjectMissing(String),
    /// The object of a mutation frame is not a Kubernetes object.
    NotAnObject(String),
    /// A `BOOKMARK` with no `metadata.resourceVersion`, which checkpoints nothing.
    UncheckpointedBookmark,
    /// The stream ended part-way through a frame.
    ///
    /// Its own variant because it is not a protocol fault: it is how a cut connection looks from
    /// here, and the honest response is [`WatchFailure::Interrupted`] rather than a decoder bug
    /// report.
    Truncated,
    /// A frame grew past the decoder's hold-back bound without ending (§18.5).
    ///
    /// A watch body is newline-delimited and a watch has no length, so bytes with no newline in
    /// them are held indefinitely by a decoder that only waits. That is not a slow server: it is
    /// a server — or a proxy, or an aggregated API server (§34.2) — turning the client's heap
    /// into its own. The bound is stated in the refusal because a limit nobody can see is a limit
    /// nobody can raise.
    Oversized {
        /// How many bytes had accumulated with no frame boundary among them.
        held: usize,
        /// The bound that was reached.
        limit: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "the watch frame is not JSON: {detail}"),
            Self::Untyped => f.write_str("the watch frame states no type"),
            Self::UnknownClass(class) => write!(
                f,
                "the watch frame class {class:?} is not one this provider models"
            ),
            Self::ObjectMissing(class) => {
                write!(f, "the {class} watch frame carries no object")
            }
            Self::NotAnObject(detail) => {
                write!(
                    f,
                    "the watch frame's object is not a Kubernetes object: {detail}"
                )
            }
            Self::UncheckpointedBookmark => f.write_str(
                "the BOOKMARK carries no metadata.resourceVersion, so it checkpoints nothing",
            ),
            Self::Truncated => f.write_str("the watch stream ended part-way through a frame"),
            Self::Oversized { held, limit } => write!(
                f,
                "the watch stream sent {held} bytes with no frame boundary in them, past the \
                 {limit}-byte bound this decoder holds back (§18.5). The stream is not a watch \
                 stream, or something between here and the API server is not framing it"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

/// Turns the bytes of a watch response into [`WatchEvent`]s (§19.3).
///
/// A watch body is a sequence of JSON objects, one per line, each `{"type":…,"object":…}`. The
/// two framings involved are unrelated: HTTP chunked transfer flushes wherever the server's
/// writer did, and a chunk boundary lands mid-object as a matter of course. So this buffers —
/// bytes go in, whole events come out, and a half-arrived frame is held rather than guessed at.
///
/// It is deliberately separate from [`WatchStream`]. Decoding answers "what did the server say",
/// the stream answers "what may this provider now claim", and a decoder that also updated a cache
/// would make the second question untestable without the first.
#[derive(Debug, Clone)]
pub struct WatchDecoder {
    provider_instance: String,
    buffer: Vec<u8>,
    limit: usize,
}

/// How many bytes of an unfinished frame this decoder will hold (§18.5, core §30.4).
///
/// **Sixteen mebibytes, and the number is the largest object an API server admits with headroom
/// rather than a round figure.** etcd refuses a value above about 1.5 MiB and the API server
/// refuses the object that would make one, so a frame carrying a legitimate object is an order of
/// magnitude below this. The headroom is for the case §34 makes real: an aggregated API server
/// serves what it likes, and a bound tight enough to be provably sufficient for the core API
/// would refuse a large custom resource that is perfectly valid. Above it, no legitimate framing
/// explains the absence of a newline, and the honest answer is a break in continuity rather than
/// a buffer that keeps growing until the process is killed — a killed process reports nothing at
/// all, which is the one outcome §48.2's taxonomy has no word for.
pub const FRAME_LIMIT: usize = 16 * 1024 * 1024;

impl WatchDecoder {
    /// A decoder for one provider instance's stream.
    ///
    /// The instance travels with every object it decodes (§6.5): an identity is only unique
    /// within the cluster that issued it, and two sessions decoding into a shared identity space
    /// is how one cluster's Pod comes to answer for another's.
    #[must_use]
    pub fn new(provider_instance: impl Into<String>) -> Self {
        Self {
            provider_instance: provider_instance.into(),
            buffer: Vec::new(),
            limit: FRAME_LIMIT,
        }
    }

    /// The same decoder holding back at most `limit` bytes of an unfinished frame.
    ///
    /// [`FRAME_LIMIT`] is the default and is right for an API server. A caller that knows it is
    /// reading something else — a test, or a stream whose objects are known to be small — states
    /// its own bound rather than editing a constant everyone shares.
    #[must_use]
    pub fn holding_back(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// The bound on an unfinished frame, so a caller can report what it was bounded by (§18.5).
    #[must_use]
    pub fn frame_limit(&self) -> usize {
        self.limit
    }

    /// Decodes every whole frame this chunk completes, holding any remainder.
    ///
    /// # Errors
    ///
    /// [`FrameError`] for a frame that arrived whole and could not be read. The decoder keeps
    /// whatever followed, but a caller should treat a frame it could not read as a break in
    /// continuity rather than resuming: the events after an unreadable one are a history with a
    /// hole in it.
    pub fn decode(&mut self, chunk: &[u8]) -> Result<Vec<WatchEvent>, FrameError> {
        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = &line[..line.len() - 1];
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            events.push(self.frame(line)?);
        }
        // Whatever is left is a frame that has not ended. Bounded here rather than before the
        // loop, so the check is against the *residue* and a chunk that happens to be large is
        // not mistaken for a frame that never ends. The buffer is released with the refusal: a
        // decoder that reported the fault and then kept the bytes would have refused nothing.
        if self.buffer.len() > self.limit {
            let held = self.buffer.len();
            self.buffer = Vec::new();
            return Err(FrameError::Oversized {
                held,
                limit: self.limit,
            });
        }
        Ok(events)
    }

    /// Decodes what is left once the response body has ended.
    ///
    /// # Errors
    ///
    /// [`FrameError::Truncated`] when the stream stopped part-way through a frame, and whatever
    /// [`Self::decode`] would have reported for a final frame the server did not terminate.
    pub fn finish(&mut self) -> Result<Vec<WatchEvent>, FrameError> {
        let rest = std::mem::take(&mut self.buffer);
        if rest.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        match self.frame(&rest) {
            Ok(event) => Ok(vec![event]),
            // A frame that is not whole JSON at the end of a body is a cut connection rather than
            // a server that writes malformed frames, and the two want different responses.
            Err(FrameError::Malformed(_)) => Err(FrameError::Truncated),
            Err(other) => Err(other),
        }
    }

    /// How many bytes are held back as an incomplete frame.
    ///
    /// Exposed so a caller can tell "nothing arrived" from "something arrived and is not a frame
    /// yet" — the difference between an idle watch and a stalled one.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Which provider instance the decoded objects belong to (§6.2).
    #[must_use]
    pub fn provider_instance(&self) -> &str {
        &self.provider_instance
    }

    fn frame(&self, line: &[u8]) -> Result<WatchEvent, FrameError> {
        let frame: Json = serde_json::from_slice(line)
            .map_err(|error| FrameError::Malformed(error.to_string()))?;
        let class = frame
            .get("type")
            .and_then(Json::as_str)
            .ok_or(FrameError::Untyped)?
            .to_owned();
        let object = frame
            .get("object")
            .ok_or_else(|| FrameError::ObjectMissing(class.clone()))?;

        match class.as_str() {
            "ADDED" => Ok(WatchEvent::Added(self.object(object)?)),
            "MODIFIED" => Ok(WatchEvent::Modified(self.object(object)?)),
            "DELETED" => Ok(WatchEvent::Deleted(self.object(object)?)),
            "BOOKMARK" => object
                .get("metadata")
                .and_then(|metadata| metadata.get("resourceVersion"))
                .and_then(Json::as_str)
                .filter(|version| !version.is_empty())
                .map(|version| WatchEvent::Bookmark(ResourceVersion::new(version)))
                .ok_or(FrameError::UncheckpointedBookmark),
            "ERROR" => Ok(WatchEvent::Error(failure_of(object))),
            other => Err(FrameError::UnknownClass(other.to_owned())),
        }
    }

    fn object(&self, value: &Json) -> Result<Object, FrameError> {
        Object::from_json(&self.provider_instance, value.clone())
            .map_err(|error| FrameError::NotAnObject(error.to_string()))
    }
}

/// What an `ERROR` frame's `Status` means for continuity (§19.4, §21.4).
///
/// The code inside the frame is the one that matters. The HTTP status was `200 OK` when the watch
/// opened, possibly hours earlier, so a `410` never arrives as a response code — it arrives here,
/// and an implementation that only classifies HTTP codes will never see one.
fn failure_of(object: &Json) -> WatchFailure {
    let Ok(bytes) = serde_json::to_vec(object) else {
        return WatchFailure::Interrupted("the ERROR frame could not be read".to_owned());
    };
    let Some(status) = crate::transport::Status::parse(&bytes) else {
        // Not a `Status`, but still the server saying the stream failed. Reporting it as an
        // interruption keeps the watch honest; discarding it would leave the stream looking live.
        return WatchFailure::Interrupted(
            "the server sent an ERROR frame that is not a Status".to_owned(),
        );
    };
    let expired =
        status.code() == Some(410) || status.reason().is_some_and(|reason| reason == "Expired");
    if expired {
        return WatchFailure::Expired;
    }
    if matches!(status.code(), Some(401 | 403)) {
        return WatchFailure::Denied;
    }
    WatchFailure::Interrupted(
        status
            .message()
            .map_or_else(|| "the watch failed".to_owned(), str::to_owned),
    )
}

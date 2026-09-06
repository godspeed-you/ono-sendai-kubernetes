//! A view of a watch over time, and the honesty it is not allowed to lose on the way.
//!
//! Specification §41, resting on §19, §20.3 and §4 invariant 14. A live view is a projection of a
//! [`WatchStream`], so it inherits everything that stream knows about its own continuity — and
//! §41.4 says what it must do with that knowledge:
//!
//! ```text
//! syncing        no list has completed; the emptiness is nobody having read
//! live           listed, watching, unbroken, recently observed
//! reconnecting   the connection dropped and the checkpoint still names history the server holds
//! gap detected   410 Gone; the record has a hole in it
//! stale          nothing has been observed for longer than this view's window
//! denied         authorization refused the stream
//! ```
//!
//! and then the sentence the whole section exists for: *a disconnected watch MUST not leave a
//! frozen table that visually appears live.*
//!
//! Two things follow, and both are in the shape of the types rather than in a comment.
//!
//! **Rows cannot be handed over unqualified when something is wrong.** [`LiveView`] has no plain
//! `rows` accessor. It answers [`Shown`], and [`Shown::Current`] is reachable only when the
//! stream is live, its record holds no gap at all, nothing was withheld for capacity, and an
//! observation arrived recently enough. Every other case is [`Shown::Qualified`], which carries
//! the rows *and* a [`Notice`] saying what is wrong with them. A gap that recovered still
//! qualifies the view: the rows are current again, and the record they sit in has a hole where a
//! §41.3 transition would otherwise be drawn.
//!
//! **The clock is a parameter.** `watch.rs` models five of §41.4's six states and deliberately
//! not `stale`, because a stream that is handed no events cannot tell a quiet cluster from a
//! dead poller — its ADR says it holds no clock. A view is where the clock legitimately enters,
//! and it enters through [`crate::transport::Clock`], asked at the moment the question is put
//! rather than stored. A view refreshed once and asked twice goes stale between the asks, which
//! is exactly the frozen table §41.4 names — and with the clock injected, saying so in a test is
//! arithmetic instead of a sleep.
//!
//! Nothing here does I/O, and nothing here reads the host's clock on its own account.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use crate::coverage::Scope;
use crate::discovery::Gvr;
use crate::object::{Identity, Object};
use crate::transport::{Clock, ObservedAt};
use crate::watch::{ChangeClass, SyncState, WatchStream};

/// How a row is looked up: what a human asks for, which is a name (§16.2).
type RowKey = (Option<String>, String);

/// What a live view may honestly call itself (§41.4).
///
/// Five of these are [`SyncState`] under another name, because a view must not invent a state its
/// stream did not report. The sixth, [`Self::Stale`], is the view's own: it is the only one that
/// needs a clock, and the only one a stream that is simply not being fed cannot detect about
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewState {
    /// The initial list has not completed. Absence here is absence of reading (§20.3).
    Syncing,
    /// Listed, watching, unbroken, and observed recently.
    Live,
    /// The connection dropped and the checkpoint still names history the server holds (§19.5).
    Reconnecting,
    /// Continuity broke and state has not been re-acquired (§19.4).
    GapDetected,
    /// Nothing has been observed for longer than this view's window.
    ///
    /// Masks [`Self::Live`] and nothing else. `reconnecting` and `gap detected` say *why* the
    /// view stopped moving, and `stale` only says that it did — so the more specific word is
    /// kept and [`LiveView::is_stale`] answers the other half beside it.
    Stale,
    /// Authorization refused the stream (§21.4).
    Denied,
}

impl ViewState {
    /// The word this state is shown under, spelled as §41.4 spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Syncing => "syncing",
            Self::Live => "live",
            Self::Reconnecting => "reconnecting",
            Self::GapDetected => "gap detected",
            Self::Stale => "stale",
            Self::Denied => "denied",
        }
    }

    /// Whether a reader may take what the view shows as the state of the cluster now.
    ///
    /// Only [`Self::Live`]. Every other state is the view saying that what is on screen is the
    /// last thing it knew rather than the thing that is true.
    #[must_use]
    pub fn is_current(self) -> bool {
        matches!(self, Self::Live)
    }
}

impl fmt::Display for ViewState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One object as this view holds it, with the moment the view learned it.
///
/// The moment comes from the injected clock rather than from the object. `creationTimestamp` is
/// when the cluster made it and `resourceVersion` is not a clock at all (§14.3), so neither
/// answers the question a live view asks — which is how long this row has been sitting there
/// without anybody seeing it change.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    object: Object,
    observed_at: ObservedAt,
    change: ChangeClass,
}

impl Row {
    /// The object.
    #[must_use]
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// Its identity, including the UID that makes a recreate a different lifetime (§16.3).
    #[must_use]
    pub fn identity(&self) -> Identity {
        self.object.identity()
    }

    /// When this view last saw this row change.
    #[must_use]
    pub fn observed_at(&self) -> ObservedAt {
        self.observed_at
    }

    /// What the last change to it was.
    #[must_use]
    pub fn change(&self) -> ChangeClass {
        self.change
    }

    /// How long ago that was, in milliseconds, at the instant asked about.
    #[must_use]
    pub fn age_millis(&self, now: ObservedAt) -> u64 {
        now.unix_millis()
            .saturating_sub(self.observed_at.unix_millis())
    }
}

/// What is wrong with what a view is showing.
///
/// Assembled at the moment it is asked for, because two of its facts — the state and the age —
/// are functions of *now* and a stored copy of either would be the frozen table in miniature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    state: ViewState,
    stale: bool,
    since_live_millis: Option<u64>,
    gaps: Vec<String>,
    withheld: usize,
    rows: usize,
}

impl Notice {
    /// What the view calls itself (§41.4).
    #[must_use]
    pub fn state(&self) -> ViewState {
        self.state
    }

    /// Whether the window has passed without a live observation, whatever the state says.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.stale
    }

    /// How long since the last live observation, where there has ever been one.
    #[must_use]
    pub fn since_live_millis(&self) -> Option<u64> {
        self.since_live_millis
    }

    /// Every break in the stream's record, described as `watch.rs` describes it.
    ///
    /// Including the ones that closed. A closed gap means the rows are current again, never that
    /// the unobserved period was filled in (§19.4).
    #[must_use]
    pub fn gaps(&self) -> &[String] {
        &self.gaps
    }

    /// How many objects the stream holds that this view had no room for.
    #[must_use]
    pub fn withheld(&self) -> usize {
        self.withheld
    }

    /// How many rows are being shown.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows
    }

    /// Everything that is wrong, in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = vec![self.state.as_str().to_owned()];
        parts.push(format!("{} rows shown", self.rows));
        if self.withheld > 0 {
            parts.push(format!("{} not shown", self.withheld));
        }
        if let Some(age) = self.since_live_millis {
            parts.push(format!("last live observation {age} ms ago"));
        }
        parts.extend(self.gaps.iter().cloned());
        parts.join("; ")
    }
}

impl fmt::Display for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// What a view is entitled to put on screen.
///
/// An enum rather than a list plus a status flag, because §41.4's requirement is precisely that
/// the two cannot be separated: a table of rows with a status somewhere else is a table somebody
/// renders without the status. Getting at the rows of a broken view means naming
/// [`Self::Qualified`] and therefore holding its [`Notice`].
#[derive(Debug, Clone, PartialEq)]
pub enum Shown<'a> {
    /// The stream is live, its record is unbroken, nothing was withheld and an observation
    /// arrived inside the window. These rows may be shown as the cluster's state.
    Current(Vec<&'a Row>),
    /// These rows are the last thing the view knew, and this is what is wrong with them.
    Qualified {
        /// What the view holds.
        rows: Vec<&'a Row>,
        /// Why it may not be read as the cluster's state.
        notice: Notice,
    },
}

impl<'a> Shown<'a> {
    /// The rows, in either case.
    #[must_use]
    pub fn rows(&self) -> &[&'a Row] {
        match self {
            Self::Current(rows) | Self::Qualified { rows, .. } => rows,
        }
    }

    /// What is wrong, or [`None`] when nothing is.
    #[must_use]
    pub fn notice(&self) -> Option<&Notice> {
        match self {
            Self::Current(_) => None,
            Self::Qualified { notice, .. } => Some(notice),
        }
    }

    /// Whether these rows may be read as the cluster's state.
    #[must_use]
    pub fn is_current(&self) -> bool {
        matches!(self, Self::Current(_))
    }
}

/// A bounded projection of one watched collection, over time (§41.2).
///
/// It holds no stream and opens nothing. [`Self::refresh`] reads a [`WatchStream`] and takes from
/// it what a view needs: the objects, the sync state and every gap in the record. Everything a
/// view adds on top of that — bounded rows, per-row observation times, staleness — is computed
/// here, from an injected clock, which is what makes the whole of §41 testable without a cluster
/// and without a timer.
#[derive(Debug, Clone)]
pub struct LiveView {
    gvr: Gvr,
    scope: Scope,
    capacity: usize,
    stale_after: Duration,
    rows: BTreeMap<RowKey, Row>,
    withheld: Vec<Identity>,
    sync: SyncState,
    gaps: Vec<String>,
    last_live_at: Option<ObservedAt>,
}

impl LiveView {
    /// A view of one collection, holding at most `capacity` rows, stale after `stale_after`.
    ///
    /// It starts syncing rather than empty-and-live, for §20.3's reason: those two states answer
    /// "is there a Pod called X" differently and only one of them may say no.
    #[must_use]
    pub fn new(gvr: Gvr, scope: Scope, capacity: usize, stale_after: Duration) -> Self {
        Self {
            gvr,
            scope,
            capacity,
            stale_after,
            rows: BTreeMap::new(),
            withheld: Vec::new(),
            sync: SyncState::Syncing,
            gaps: Vec::new(),
            last_live_at: None,
        }
    }

    /// Projects the stream as it is now.
    ///
    /// The rows are rebuilt rather than patched, so the capacity bound is re-applied against
    /// whatever the stream holds at this moment: an object that had no room a minute ago is
    /// admitted as soon as one frees, and [`Self::withheld`] is the exact set that did not fit
    /// rather than a running count of refusals.
    ///
    /// The staleness clock advances only when the stream is [`SyncState::Live`]. Refreshing a
    /// broken stream is not an observation of the cluster, and treating it as one would produce
    /// the precise thing §41.4 forbids: a frozen table with a heartbeat.
    pub fn refresh(&mut self, stream: &WatchStream, clock: &impl Clock) {
        let now = clock.now();
        self.sync = stream.state();
        self.gaps = stream.gaps().iter().map(|gap| gap.describe()).collect();
        if self.sync == SyncState::Live {
            self.last_live_at = Some(now);
        }

        let mut rows = BTreeMap::new();
        let mut withheld = Vec::new();
        for object in stream.objects() {
            let key = key_of(object);
            if rows.len() < self.capacity {
                rows.insert(key.clone(), self.project(&key, object, now));
            } else {
                withheld.push(object.identity());
            }
        }
        self.rows = rows;
        self.withheld = withheld;
    }

    /// The REST collection this view projects (§13.1).
    #[must_use]
    pub fn gvr(&self) -> &Gvr {
        &self.gvr
    }

    /// What it was asked to cover.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The most rows it will hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many rows it holds.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Which objects the stream holds that this view had no room for.
    ///
    /// Identities rather than objects: a bound that discards without saying what it discarded
    /// shows a fraction of a namespace in a table that looks like all of it, and an identity is
    /// two names and a UID rather than a whole object, so keeping them costs a fraction of what
    /// the bound saved.
    #[must_use]
    pub fn withheld(&self) -> &[Identity] {
        &self.withheld
    }

    /// Every break in the stream's record, open or closed (§19.4).
    #[must_use]
    pub fn gaps(&self) -> &[String] {
        &self.gaps
    }

    /// Whether the window has passed since the last live observation.
    ///
    /// `false` for a view that has never been live: it is syncing, or denied, and that word
    /// already says what is happening. Calling a view three milliseconds into its first list
    /// stale would be a second wrong answer on top of a state that is already the right one.
    #[must_use]
    pub fn is_stale(&self, clock: &impl Clock) -> bool {
        let Some(last) = self.last_live_at else {
            return false;
        };
        let window = u64::try_from(self.stale_after.as_millis()).unwrap_or(u64::MAX);
        clock.now().unix_millis().saturating_sub(last.unix_millis()) > window
    }

    /// What this view may call itself at this instant (§41.4).
    #[must_use]
    pub fn state(&self, clock: &impl Clock) -> ViewState {
        match self.sync {
            SyncState::Denied => ViewState::Denied,
            SyncState::GapDetected => ViewState::GapDetected,
            SyncState::Reconnecting => ViewState::Reconnecting,
            SyncState::Syncing => ViewState::Syncing,
            SyncState::Live => {
                if self.is_stale(clock) {
                    ViewState::Stale
                } else {
                    ViewState::Live
                }
            }
        }
    }

    /// Everything that is wrong with what this view holds, at this instant.
    #[must_use]
    pub fn notice(&self, clock: &impl Clock) -> Notice {
        Notice {
            state: self.state(clock),
            stale: self.is_stale(clock),
            since_live_millis: self
                .last_live_at
                .map(|last| clock.now().unix_millis().saturating_sub(last.unix_millis())),
            gaps: self.gaps.clone(),
            withheld: self.withheld.len(),
            rows: self.rows.len(),
        }
    }

    /// The rows, and what may be believed about them (§41.4).
    ///
    /// [`Shown::Current`] requires all four: the stream is live, the record holds no gap at all,
    /// nothing was withheld, and an observation arrived inside the window. A recovered gap still
    /// qualifies the view — the rows are current, and the record they sit in is not, which is
    /// what a transition between two of them would be drawn from (§41.3).
    #[must_use]
    pub fn shown(&self, clock: &impl Clock) -> Shown<'_> {
        let rows: Vec<&Row> = self.rows.values().collect();
        if self.state(clock).is_current() && self.gaps.is_empty() && self.withheld.is_empty() {
            Shown::Current(rows)
        } else {
            Shown::Qualified {
                rows,
                notice: self.notice(clock),
            }
        }
    }

    /// One row, keeping the observation time of a row that did not change.
    ///
    /// A recreate is an arrival rather than a modification: same namespace and name, different
    /// UID, is a different lifetime (§4 invariants 4 and 5), and reporting it as a change would
    /// present a Pod that was deleted and remade as one that carried on.
    fn project(&self, key: &RowKey, object: &Object, now: ObservedAt) -> Row {
        let (observed_at, change) = match self.rows.get(key) {
            Some(existing) if existing.object.uid() != object.uid() => (now, ChangeClass::Added),
            Some(existing) if existing.object.resource_version() == object.resource_version() => {
                (existing.observed_at, existing.change)
            }
            Some(_) => (now, ChangeClass::Modified),
            None => (now, ChangeClass::Added),
        };
        Row {
            object: object.clone(),
            observed_at,
            change,
        }
    }
}

fn key_of(object: &Object) -> RowKey {
    (
        object.namespace().map(str::to_owned),
        object.name().to_owned(),
    )
}

// --- relationship-live views (§41.3) --------------------------------------------------------------

/// One counted neighbour of a subject, and the value it had before.
///
/// The arrow §41.3 draws — `selected Pods: 4 -> 3` — is a claim that one number *became* the
/// other. That claim needs two observations of an unbroken stream; across a gap the stream missed
/// an unknown number of arrivals and departures, and the arrow would be manufactured out of two
/// counts that have nothing to do with each other.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    previous: Option<u64>,
    current: Option<u64>,
}

impl Tally {
    /// The value before the most recent observation, where the two are comparable.
    #[must_use]
    pub fn previous(self) -> Option<u64> {
        self.previous
    }

    /// The most recent observation.
    #[must_use]
    pub fn current(self) -> Option<u64> {
        self.current
    }

    /// The count, with an arrow only where one number was observed to become the other.
    #[must_use]
    pub fn describe(self) -> String {
        match (self.previous, self.current) {
            (Some(previous), Some(current)) if previous != current => {
                format!("{previous} -> {current}")
            }
            (_, Some(current)) => current.to_string(),
            (_, None) => "unknown".to_owned(),
        }
    }
}

/// A subject and its changing neighbours (§41.3).
///
/// Values are fed in as typed provider observations — a selector evaluation, an EndpointSlice
/// read, a cached count from a [`LiveView`] — which is what §41.3 requires in as many words. It
/// parses nothing and reads no rendered output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbourhood {
    subject: String,
    tallies: BTreeMap<String, Tally>,
    crossed_gap: bool,
}

impl Neighbourhood {
    /// A neighbourhood around one subject, before anything has been counted.
    #[must_use]
    pub fn of(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            tallies: BTreeMap::new(),
            crossed_gap: false,
        }
    }

    /// Records one typed observation of a counted neighbour.
    pub fn observe(&mut self, label: impl Into<String>, value: u64) {
        let tally = self.tallies.entry(label.into()).or_default();
        tally.previous = tally.current;
        tally.current = Some(value);
    }

    /// Records that the stream behind these counts lost continuity (§19.4).
    ///
    /// Every count becomes unknown, rather than every count keeping its last value. A number left
    /// on screen after a gap is one the view has no current evidence for, and the next
    /// observation after it would draw an arrow across a period nobody watched.
    pub fn record_gap(&mut self) {
        self.crossed_gap = true;
        for tally in self.tallies.values_mut() {
            *tally = Tally::default();
        }
    }

    /// What this is a neighbourhood of.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// One counted neighbour.
    #[must_use]
    pub fn tally(&self, label: &str) -> Option<&Tally> {
        self.tallies.get(label)
    }

    /// Whether continuity broke at some point behind these counts.
    #[must_use]
    pub fn crossed_gap(&self) -> bool {
        self.crossed_gap
    }

    /// The subject and its neighbours, in the shape §41.3 sketches.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut described = self.subject.clone();
        for (label, tally) in &self.tallies {
            described.push_str(&format!("\n  {label}: {}", tally.describe()));
        }
        if self.crossed_gap {
            described.push_str(
                "\n  the stream lost continuity, so counts either side of it are not comparable",
            );
        }
        described
    }
}

impl fmt::Display for Neighbourhood {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

//! When something was observed, by whose clock, and what that does not license.
//!
//! Specification §39, and §13.3/§13.4 of the generic provider contract. Kubernetes hands out
//! timestamps generously and no two of them are guaranteed to be on the same clock:
//!
//! ```text
//! creationTimestamp     the API server's clock, written once
//! eventTime             the reporting component's clock, on whichever machine it runs
//! lastTransitionTime    whichever controller wrote the status; the object does not say which
//! log line prefix       the container runtime's clock, on the node
//! observed_at           this machine's clock, when the read completed
//! ```
//!
//! Parsing all five into milliseconds and sorting produces something that reads as a history of
//! the cluster and is in fact a picture of the skew between five machines. `logs.rs` refuses that
//! conflation for node timestamps by keeping them as strings; this module is where the refusal
//! becomes a vocabulary the rest of the provider can use.
//!
//! Three rules carry it, and each is in the shape of a type rather than in a warning:
//!
//! **A stamp has no ordering.** [`Stamp`] implements no comparison trait, so `stamps.sort()` does
//! not compile and the cross-clock timeline §39.2 forbids cannot be assembled by accident. The
//! only way to ask is [`Stamp::relate`], and one of its answers is
//! [`Order::Unordered`] — the answer a comparison operator has no room for.
//!
//! **A read timestamp is not an observed change.** [`Basis::Observed`] is reachable only through
//! [`Observation::watched`], which stamps with this provider's own clock. Everything read off
//! current state arrives through [`Observation::reported`], whose [`ReportedSource`] vocabulary
//! has no word for a watch event. A Pod created at 08:00 and first seen at 14:00 therefore cannot
//! be filed as six hours of history (§39.2).
//!
//! **`resourceVersion` is not a clock.** A [`TemporalGap`] carries the two continuity tokens the
//! break lies between *and*, separately, the provider-clock instants at which the break was
//! noticed and observation resumed. A duration comes from the second pair or from nowhere: the
//! tokens are opaque, they are not comparable, and §14.3 and §4 invariant 6 say so.
//!
//! Nothing here does I/O. Time enters through [`crate::transport::Clock`], so a fixture fixes it
//! and every assertion below is deterministic (§59.1).

use std::fmt;

use crate::condition::Condition;
use crate::coverage::{Coverage, Scope};
use crate::events::Event;
use crate::object::{Identity, Object};
use crate::transport::{Clock, ObservedAt};
use crate::watch::{GapReason, ObservedChange, ResourceVersion, WatchGap, WatchStream};

// --- clocks ---------------------------------------------------------------------------------------

/// Which machine's clock wrote a timestamp.
///
/// The distinction the whole module rests on. Two timestamps are comparable when the same clock
/// wrote both, and a Kubernetes object routinely carries four that were written by four different
/// machines — so the writer travels with the value rather than being reconstructed later from the
/// field name, which is where it would be lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockSource {
    /// This machine, at the moment a read or a watch event was acquired (§17.1, §20.2).
    Provider,
    /// The API server, which writes `creationTimestamp`, `deletionTimestamp` and the times in
    /// `managedFields`.
    ApiServer,
    /// A named component that reported an Event, timestamping it from wherever it runs (§38.3).
    Reporter(String),
    /// A container runtime on a named node (§42.1).
    Node(String),
    /// Written by something the object does not name.
    ///
    /// A condition's `lastTransitionTime` is the common case: some controller wrote it and the
    /// status does not record which. Deliberately not comparable even with itself — two
    /// unattributed stamps may be from two machines, and "same field" is not "same clock".
    Unattributed,
}

impl ClockSource {
    /// Whether a timestamp from this clock may be ordered against one from `other`.
    ///
    /// False for [`Self::Unattributed`] against itself, which is the case worth stating: an
    /// equality test alone would let two conditions written by two controllers be sorted into a
    /// sequence that has never existed anywhere.
    #[must_use]
    pub fn is_comparable_with(&self, other: &Self) -> bool {
        self == other && !matches!(self, Self::Unattributed)
    }
}

impl fmt::Display for ClockSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider => f.write_str("provider"),
            Self::ApiServer => f.write_str("api-server"),
            Self::Reporter(name) => write!(f, "reported-by/{name}"),
            Self::Node(name) => write!(f, "node/{name}"),
            Self::Unattributed => f.write_str("unattributed"),
        }
    }
}

/// Why two stamps could not be put in an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undecidable {
    /// Two different clocks wrote them (§39.2).
    DifferentClocks,
    /// Neither stamp names its writer, so they may be from the same clock or from two.
    ClockUnattributed,
    /// At least one of them could not be read as an instant at all.
    Unplaceable,
}

impl Undecidable {
    /// The word this reason is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DifferentClocks => "different clocks",
            Self::ClockUnattributed => "clock unattributed",
            Self::Unplaceable => "unplaceable timestamp",
        }
    }
}

/// How two stamps sit relative to each other.
///
/// Four answers rather than three, and the fourth is the one an operator needs: `unordered` says
/// the question has no defensible answer, where `Ordering::Equal` would have said the two happened
/// at the same moment. Uncertainty survives instead of being resolved into a guess (§13.4 of the
/// generic contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// The left stamp is earlier.
    Before,
    /// The left stamp is later.
    After,
    /// Both name the same instant on one clock.
    Simultaneous,
    /// No order is defensible, and here is why.
    Unordered(Undecidable),
}

impl Order {
    /// Whether an order was established.
    #[must_use]
    pub fn is_ordered(self) -> bool {
        !matches!(self, Self::Unordered(_))
    }

    /// The word this relation is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::Simultaneous => "simultaneous",
            Self::Unordered(_) => "unordered",
        }
    }
}

/// One timestamp, with the clock that wrote it and the raw text it arrived as.
///
/// Carries no ordering trait, on purpose. `#[derive(PartialOrd)]` here would make
/// `stamps.sort()` compile, and a sorted list of stamps from four writers is exactly the
/// cross-clock history §39.2 forbids. [`Self::relate`] is the only way to compare, and it is able
/// to refuse.
///
/// The raw text is kept beside the parsed instant because the parse may fail and the original is
/// still evidence: an unreadable timestamp is reported as unreadable rather than coerced to the
/// epoch, which would sort before everything real and look like the oldest fact in the cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    source: ClockSource,
    raw: String,
    unix_millis: Option<u64>,
}

impl Stamp {
    /// A moment on this provider's own clock (§17.1).
    #[must_use]
    pub fn observed(at: ObservedAt) -> Self {
        Self {
            source: ClockSource::Provider,
            raw: at.unix_millis().to_string(),
            unix_millis: Some(at.unix_millis()),
        }
    }

    /// An RFC 3339 timestamp the API server wrote.
    #[must_use]
    pub fn api_server(raw: impl Into<String>) -> Self {
        Self::rfc3339(ClockSource::ApiServer, raw)
    }

    /// An RFC 3339 timestamp a named component wrote (§38.3).
    #[must_use]
    pub fn reported_by(controller: impl Into<String>, raw: impl Into<String>) -> Self {
        Self::rfc3339(ClockSource::Reporter(controller.into()), raw)
    }

    /// An RFC 3339 timestamp a container runtime on a named node wrote (§42.1).
    #[must_use]
    pub fn on_node(node: impl Into<String>, raw: impl Into<String>) -> Self {
        Self::rfc3339(ClockSource::Node(node.into()), raw)
    }

    /// An RFC 3339 timestamp whose writer the object does not name.
    #[must_use]
    pub fn unattributed(raw: impl Into<String>) -> Self {
        Self::rfc3339(ClockSource::Unattributed, raw)
    }

    /// An RFC 3339 timestamp from a named clock.
    #[must_use]
    pub fn rfc3339(source: ClockSource, raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let unix_millis = parse_rfc3339_millis(&raw);
        Self {
            source,
            raw,
            unix_millis,
        }
    }

    /// Which clock wrote it.
    #[must_use]
    pub fn source(&self) -> &ClockSource {
        &self.source
    }

    /// The text it arrived as, unaltered.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Whether it could be read as an instant at all.
    ///
    /// A stamp that could not is still kept and still shown. Unknown data is absent, never zero
    /// (AGENTS.md §6).
    #[must_use]
    pub fn is_placeable(&self) -> bool {
        self.unix_millis.is_some()
    }

    /// How this stamp sits relative to another.
    ///
    /// Refuses across clocks before it looks at the values, so no arithmetic is ever performed on
    /// two machines' idea of the time. That is the whole point: the values compare perfectly well
    /// and the comparison means nothing.
    #[must_use]
    pub fn relate(&self, other: &Self) -> Order {
        if !self.source.is_comparable_with(&other.source) {
            return if self.source == other.source {
                Order::Unordered(Undecidable::ClockUnattributed)
            } else {
                Order::Unordered(Undecidable::DifferentClocks)
            };
        }
        let (Some(mine), Some(theirs)) = (self.unix_millis, other.unix_millis) else {
            return Order::Unordered(Undecidable::Unplaceable);
        };
        match mine.cmp(&theirs) {
            std::cmp::Ordering::Less => Order::Before,
            std::cmp::Ordering::Greater => Order::After,
            std::cmp::Ordering::Equal => Order::Simultaneous,
        }
    }

    /// The distance between two stamps, where one clock wrote both and both could be read.
    ///
    /// [`None`] otherwise, because a distance across two clocks is skew plus elapsed time and
    /// nothing separates the two terms.
    #[must_use]
    pub fn apart_millis(&self, other: &Self) -> Option<u64> {
        if !self.relate(other).is_ordered() {
            return None;
        }
        let (mine, theirs) = (self.unix_millis?, other.unix_millis?);
        Some(mine.abs_diff(theirs))
    }
}

// --- what an observation is ---------------------------------------------------------------------------

/// Whether the provider saw a change happen or read a timestamp off current state.
///
/// §39.2's distinction, and the reason the provider cannot manufacture history: only a watch event
/// within an unbroken observation period is something this provider witnessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// This provider saw the change while it was watching.
    Observed,
    /// A timestamp was read from an object, an Event or a condition.
    Reported,
}

impl Basis {
    /// The word this basis is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Reported => "reported",
        }
    }
}

/// Where a temporal observation came from (§39.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A watch event, seen as it arrived.
    WatchEvent,
    /// A list or get that captured state at a moment (§39.4).
    ResourceSnapshot,
    /// A Kubernetes Event (§38).
    EventRecord,
    /// `metadata.creationTimestamp` or `metadata.deletionTimestamp` (§14.1).
    ObjectMetadata,
    /// A condition's `lastTransitionTime` (§37.1).
    ConditionTransition,
    /// A `managedFields` entry's time (§14.7).
    ManagedField,
}

impl Source {
    /// Whether this source witnesses a change or reports a timestamp.
    ///
    /// Only a watch event witnesses one. A snapshot proves that two states differed, never the
    /// sequence of changes between them (§39.4), and a metadata timestamp proves only that
    /// somebody wrote it.
    #[must_use]
    pub fn basis(self) -> Basis {
        match self {
            Self::WatchEvent => Basis::Observed,
            Self::ResourceSnapshot
            | Self::EventRecord
            | Self::ObjectMetadata
            | Self::ConditionTransition
            | Self::ManagedField => Basis::Reported,
        }
    }

    /// The word this source is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatchEvent => "watch-event",
            Self::ResourceSnapshot => "resource-snapshot",
            Self::EventRecord => "event-record",
            Self::ObjectMetadata => "object-metadata",
            Self::ConditionTransition => "condition-transition",
            Self::ManagedField => "managed-field",
        }
    }
}

/// The sources a *reported* observation may come from.
///
/// A second, smaller vocabulary rather than a validated [`Source`] parameter. If
/// [`Observation::reported`] took a `Source`, a `creationTimestamp` could be filed as a watch
/// event by passing the wrong variant, and the result would be indistinguishable from a change
/// this provider actually saw. This enum has no word for that, so the mistake does not typecheck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedSource {
    /// A list or get (§39.4).
    ResourceSnapshot,
    /// A Kubernetes Event (§38).
    EventRecord,
    /// Object metadata (§14.1).
    ObjectMetadata,
    /// A condition transition (§37.1).
    ConditionTransition,
    /// A `managedFields` entry (§14.7).
    ManagedField,
}

impl ReportedSource {
    /// Every reported source, for a caller that has to prove it handled all of them.
    #[must_use]
    pub fn all() -> [Self; 5] {
        [
            Self::ResourceSnapshot,
            Self::EventRecord,
            Self::ObjectMetadata,
            Self::ConditionTransition,
            Self::ManagedField,
        ]
    }

    /// The same source in the wider vocabulary.
    #[must_use]
    pub fn as_source(self) -> Source {
        match self {
            Self::ResourceSnapshot => Source::ResourceSnapshot,
            Self::EventRecord => Source::EventRecord,
            Self::ObjectMetadata => Source::ObjectMetadata,
            Self::ConditionTransition => Source::ConditionTransition,
            Self::ManagedField => Source::ManagedField,
        }
    }
}

/// One thing that is known to have a time attached, and everything qualifying that time.
///
/// Like [`Stamp`], it carries no ordering trait: a `Vec<Observation>` cannot be sorted, and the
/// only sequence available is [`Timeline::ordered_on`], which requires a clock to be named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    subject: Identity,
    source: Source,
    stamp: Stamp,
    detail: String,
}

impl Observation {
    /// A change this provider saw happen while it was watching (§39.3).
    ///
    /// Stamped with the acquisition clock, because that is the only clock this machine owns. The
    /// object's own `resourceVersion` is not one (§14.3), and its metadata belongs to the API
    /// server's.
    #[must_use]
    pub fn watched(subject: Identity, at: ObservedAt, detail: impl Into<String>) -> Self {
        Self {
            subject,
            source: Source::WatchEvent,
            stamp: Stamp::observed(at),
            detail: detail.into(),
        }
    }

    /// A watch event this provider recorded, as a temporal observation.
    ///
    /// Reuses `watch.rs`'s record rather than re-deriving one: the identity and the change class
    /// were already established there, and a second derivation is a second chance to key a change
    /// on a name instead of a UID (§4 invariants 4 and 5).
    #[must_use]
    pub fn from_change(change: &ObservedChange, at: ObservedAt) -> Self {
        Self::watched(change.identity().clone(), at, change.class().as_str())
    }

    /// A timestamp read off state, with the clock that wrote it.
    #[must_use]
    pub fn reported(
        subject: Identity,
        source: ReportedSource,
        stamp: Stamp,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            subject,
            source: source.as_source(),
            stamp,
            detail: detail.into(),
        }
    }

    /// When the API server says the object was created, where it says so.
    ///
    /// [`Basis::Reported`], always. A cluster this provider first looked at an hour ago is full of
    /// objects created last year, and filing their creation times as observations is precisely the
    /// retroactive history §39.2 forbids.
    #[must_use]
    pub fn of_creation(object: &Object) -> Option<Self> {
        let raw = object.creation_timestamp()?;
        Some(Self::reported(
            object.identity(),
            ReportedSource::ObjectMetadata,
            Stamp::api_server(raw),
            "created",
        ))
    }

    /// When a reporter says it observed what an Event describes (§38.3).
    ///
    /// [`None`] where the Event is not about this subject or carries no `eventTime`. The clock is
    /// the reporting controller's — a different machine from the API server and from this one — so
    /// the stamp is not comparable with either.
    #[must_use]
    pub fn of_event(subject: &Identity, event: &Event) -> Option<Self> {
        if !event.regards(subject) {
            return None;
        }
        let raw = event.event_time()?;
        let source = event
            .reporter()
            .controller()
            .map_or(ClockSource::Unattributed, |controller| {
                ClockSource::Reporter(controller.to_owned())
            });
        Some(Self::reported(
            subject.clone(),
            ReportedSource::EventRecord,
            Stamp::rfc3339(source, raw),
            event.describe(),
        ))
    }

    /// When a condition last changed, as the controller that wrote the status recorded it.
    ///
    /// The clock is [`ClockSource::Unattributed`]: `status.conditions` does not say which
    /// controller wrote the entry, so two conditions on one object may be two machines' idea of
    /// the time and must not be sorted against each other (§37.1, §37.2).
    #[must_use]
    pub fn of_condition(subject: &Identity, condition: &Condition) -> Option<Self> {
        let raw = condition.last_transition_time()?;
        Some(Self::reported(
            subject.clone(),
            ReportedSource::ConditionTransition,
            Stamp::unattributed(raw),
            condition.to_string(),
        ))
    }

    /// Which object this is about.
    #[must_use]
    pub fn subject(&self) -> &Identity {
        &self.subject
    }

    /// Where it came from (§39.1).
    #[must_use]
    pub fn source(&self) -> Source {
        self.source
    }

    /// Whether it was witnessed or read (§39.2).
    #[must_use]
    pub fn basis(&self) -> Basis {
        self.source.basis()
    }

    /// The time, and the clock that wrote it.
    #[must_use]
    pub fn stamp(&self) -> &Stamp {
        &self.stamp
    }

    /// What was observed, in words.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// One line: basis, source, clock and what happened.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} {} ({}, {}): {}",
            self.basis().as_str(),
            self.source.as_str(),
            self.stamp.source,
            self.stamp.raw,
            self.detail
        )
    }
}

// --- the window and its holes ----------------------------------------------------------------------

/// The period this provider was actually looking, on its own clock.
///
/// Both ends are [`ObservedAt`], which is a provider fact. A window whose ends were taken from
/// object metadata would be a window in the API server's time, and the answer "we observed from
/// 14:00" would then be a claim about a clock this machine does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    opened_at: ObservedAt,
    latest_at: ObservedAt,
}

impl Window {
    /// When observation began.
    #[must_use]
    pub fn opened_at(self) -> ObservedAt {
        self.opened_at
    }

    /// The latest moment observation is known to have reached.
    #[must_use]
    pub fn latest_at(self) -> ObservedAt {
        self.latest_at
    }

    /// How long the window is, in milliseconds.
    #[must_use]
    pub fn span_millis(self) -> u64 {
        self.latest_at
            .unix_millis()
            .saturating_sub(self.opened_at.unix_millis())
    }

    /// Whether a provider-clock instant falls inside the window.
    ///
    /// Takes an [`ObservedAt`] and nothing else, so there is no way to ask whether a
    /// `creationTimestamp` falls inside it. That question has no answer: the window and the
    /// timestamp are on two clocks.
    #[must_use]
    pub fn contains(self, at: ObservedAt) -> bool {
        at.unix_millis() >= self.opened_at.unix_millis()
            && at.unix_millis() <= self.latest_at.unix_millis()
    }

    /// The window in words, in the units it is measured in.
    #[must_use]
    pub fn describe(self) -> String {
        format!(
            "observed from {} to {} (provider clock, unix millis)",
            self.opened_at.unix_millis(),
            self.latest_at.unix_millis()
        )
    }
}

/// A stretch of time this provider could not observe.
///
/// Built from a [`WatchGap`], which knows the two continuity tokens the break lies between, plus
/// the provider-clock instants at which the break was noticed and observation resumed. The two
/// pairs are kept apart deliberately: subtracting the tokens would be arithmetic on opaque
/// strings, and §14.3 with §4 invariant 6 rule that out. A duration comes from the clock or from
/// nowhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporalGap {
    reason: GapReason,
    after_version: Option<ResourceVersion>,
    resumed_version: Option<ResourceVersion>,
    noticed_at: ObservedAt,
    resumed_at: Option<ObservedAt>,
}

impl TemporalGap {
    /// The temporal reading of a watch discontinuity (§19.4, §39.3).
    ///
    /// `noticed_at` is when *this provider* saw the break, which is the only time it can honestly
    /// attach. When the server stopped holding the history is unknown and stays unknown.
    #[must_use]
    pub fn from_watch(gap: &WatchGap, noticed_at: ObservedAt) -> Self {
        Self {
            reason: gap.reason(),
            after_version: gap.after().cloned(),
            resumed_version: gap.resumed_at().cloned(),
            noticed_at,
            resumed_at: None,
        }
    }

    /// The same gap, with the moment observation resumed on this provider's clock.
    #[must_use]
    pub fn resumed(mut self, at: ObservedAt) -> Self {
        self.resumed_at = Some(at);
        self
    }

    /// Why observation stopped being continuous.
    #[must_use]
    pub fn reason(&self) -> GapReason {
        self.reason
    }

    /// The last continuity token observed before the break — a position, never a time (§14.3).
    #[must_use]
    pub fn after_version(&self) -> Option<&ResourceVersion> {
        self.after_version.as_ref()
    }

    /// The continuity token observation resumed at — a position, never a time (§14.3).
    #[must_use]
    pub fn resumed_version(&self) -> Option<&ResourceVersion> {
        self.resumed_version.as_ref()
    }

    /// When this provider noticed the break.
    #[must_use]
    pub fn noticed_at(&self) -> ObservedAt {
        self.noticed_at
    }

    /// When this provider resumed observing, where it has.
    #[must_use]
    pub fn resumed_at(&self) -> Option<ObservedAt> {
        self.resumed_at
    }

    /// Whether observation has resumed. A closed gap is still a gap (§19.4).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.resumed_at.is_some()
    }

    /// How long observation was interrupted, measured on this provider's clock at both ends.
    ///
    /// [`None`] while the gap is open. Filling it in from the two `resourceVersion`s is the
    /// mistake this type exists to prevent: they are opaque, they are not monotonic across
    /// resources, and their difference is not a quantity.
    #[must_use]
    pub fn unobserved_millis(&self) -> Option<u64> {
        let resumed = self.resumed_at?;
        Some(
            resumed
                .unix_millis()
                .saturating_sub(self.noticed_at.unix_millis()),
        )
    }

    /// The gap in words: the position it starts after, the reason, and what is known about its
    /// length.
    #[must_use]
    pub fn describe(&self) -> String {
        let after = self
            .after_version
            .as_ref()
            .map_or_else(|| "an unknown position".to_owned(), ToString::to_string);
        let mut described = format!(
            "unobserved after {after}: {} (noticed at {})",
            self.reason.as_str(),
            self.noticed_at.unix_millis()
        );
        match self.unobserved_millis() {
            Some(millis) => described.push_str(&format!(", {millis}ms unobserved")),
            None => described.push_str(", length unknown"),
        }
        described
    }
}

/// The observations on one clock, in order, and the ones that could not be placed on it.
///
/// Two lists rather than one sorted list with the awkward entries dropped: an unplaceable stamp is
/// evidence that something happened and evidence that its time is unusable, and discarding it for
/// tidiness would lose both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ordered<'a> {
    on: ClockSource,
    sequence: Vec<&'a Observation>,
    unplaceable: Vec<&'a Observation>,
}

impl<'a> Ordered<'a> {
    /// Which clock this sequence is on.
    #[must_use]
    pub fn on(&self) -> &ClockSource {
        &self.on
    }

    /// The observations that clock wrote, earliest first.
    #[must_use]
    pub fn sequence(&self) -> &[&'a Observation] {
        &self.sequence
    }

    /// The observations attributed to that clock that could not be put in the sequence.
    #[must_use]
    pub fn unplaceable(&self) -> &[&'a Observation] {
        &self.unplaceable
    }

    /// Whether the clock carried nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sequence.is_empty() && self.unplaceable.is_empty()
    }
}

/// What one temporal answer observed: a window, the observations in it, and the holes.
///
/// Composed rather than re-derived. Scope truth comes from [`Coverage`] — the eight-way vocabulary
/// that already distinguishes a denied namespace from an empty one — and continuity truth comes
/// from `watch.rs`'s gaps. What this type adds is the window itself and the rule that observations
/// are grouped by the clock that wrote them.
///
/// There is deliberately no method returning one merged sequence. [`Self::ordered_on`] requires a
/// clock to be named, so the merged cross-clock timeline has no entry point rather than a warning
/// against it.
#[derive(Debug, Clone)]
pub struct Timeline {
    provider_instance: String,
    window: Window,
    coverage: Coverage,
    observations: Vec<Observation>,
    gaps: Vec<TemporalGap>,
}

impl Timeline {
    /// Opens a window at the clock's current instant.
    ///
    /// The window opens when observation starts and never earlier, which is §39.2 as a
    /// constructor: there is no way to build a `Timeline` that begins before the moment somebody
    /// started looking.
    #[must_use]
    pub fn opened(provider_instance: impl Into<String>, scope: Scope, clock: &impl Clock) -> Self {
        let at = clock.now();
        Self {
            provider_instance: provider_instance.into(),
            window: Window {
                opened_at: at,
                latest_at: at,
            },
            coverage: Coverage::complete(scope),
            observations: Vec::new(),
            gaps: Vec::new(),
        }
    }

    /// Which provider instance observed this (§6.2, Gate J).
    #[must_use]
    pub fn provider_instance(&self) -> &str {
        &self.provider_instance
    }

    /// The period observed.
    #[must_use]
    pub fn window(&self) -> Window {
        self.window
    }

    /// Extends the window to the clock's current instant.
    ///
    /// Monotonic: a clock that answers an earlier instant does not shorten a window that has
    /// already been observed, because the observations in it were still made.
    pub fn advance(&mut self, clock: &impl Clock) {
        let at = clock.now();
        if at.unix_millis() > self.window.latest_at.unix_millis() {
            self.window.latest_at = at;
        }
    }

    /// Records one observation.
    pub fn record(&mut self, observation: Observation) {
        self.observations.push(observation);
    }

    /// Records a stretch that could not be observed.
    pub fn record_gap(&mut self, gap: TemporalGap) {
        self.gaps.push(gap);
    }

    /// Takes a watch stream's continuity into the timeline (§19.4, §39.3).
    ///
    /// The gaps and the scope, and deliberately not the changes. `watch.rs` records what changed
    /// and in what arrival order; it does not record when each one arrived, and stamping them all
    /// with the moment of this call would invent acquisition times that look exactly like measured
    /// ones. A caller that wants watched observations builds them with
    /// [`Observation::from_change`] as the events arrive, while the clock still means something.
    pub fn absorb_continuity(&mut self, stream: &WatchStream, clock: &impl Clock) {
        let at = clock.now();
        self.coverage.observed(stream.scope().clone());
        for gap in stream.gaps() {
            self.gaps.push(TemporalGap::from_watch(gap, at));
        }
    }

    /// What the query did and did not reach, in the provider's scope vocabulary (§21.4).
    #[must_use]
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// The coverage, for a caller recording a scope that did not answer.
    pub fn coverage_mut(&mut self) -> &mut Coverage {
        &mut self.coverage
    }

    /// Everything recorded, in the order it was recorded.
    #[must_use]
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// The changes this provider witnessed (§39.3).
    #[must_use]
    pub fn observed(&self) -> Vec<&Observation> {
        self.observations
            .iter()
            .filter(|observation| observation.basis() == Basis::Observed)
            .collect()
    }

    /// The timestamps this provider read off state (§39.2).
    #[must_use]
    pub fn reported(&self) -> Vec<&Observation> {
        self.observations
            .iter()
            .filter(|observation| observation.basis() == Basis::Reported)
            .collect()
    }

    /// Every clock that wrote something in this timeline, in first-seen order.
    #[must_use]
    pub fn clocks(&self) -> Vec<ClockSource> {
        let mut seen: Vec<ClockSource> = Vec::new();
        for observation in &self.observations {
            let source = observation.stamp.source.clone();
            if !seen.contains(&source) {
                seen.push(source);
            }
        }
        seen
    }

    /// The observations one clock wrote, earliest first.
    ///
    /// The only ordering this module offers, and it is per clock. Asking for
    /// [`ClockSource::Unattributed`] yields an empty sequence and every candidate as unplaceable:
    /// stamps nobody claimed may be from several machines, so an order over them would be
    /// invented (§37.1).
    #[must_use]
    pub fn ordered_on(&self, source: &ClockSource) -> Ordered<'_> {
        let mine: Vec<&Observation> = self
            .observations
            .iter()
            .filter(|observation| &observation.stamp.source == source)
            .collect();

        if !source.is_comparable_with(source) {
            return Ordered {
                on: source.clone(),
                sequence: Vec::new(),
                unplaceable: mine,
            };
        }

        let (mut sequence, unplaceable): (Vec<_>, Vec<_>) = mine
            .into_iter()
            .partition(|observation| observation.stamp.is_placeable());
        sequence.sort_by_key(|observation| observation.stamp.unix_millis);
        Ordered {
            on: source.clone(),
            sequence,
            unplaceable,
        }
    }

    /// The stretches that could not be observed (§19.4).
    #[must_use]
    pub fn gaps(&self) -> &[TemporalGap] {
        &self.gaps
    }

    /// Whether one unbroken stretch covers the window.
    #[must_use]
    pub fn is_continuous(&self) -> bool {
        self.gaps.is_empty()
    }

    /// The window, its holes and its scope truth in one line.
    ///
    /// Both kinds of hole, because they answer different questions: a watch gap says a stretch of
    /// time was not observed, and a coverage gap says a scope was never readable. A continuous
    /// window over a denied namespace is not a complete answer, and an answer that printed only
    /// the window would read as one.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = vec![self.window.describe()];
        parts.extend(self.gaps.iter().map(TemporalGap::describe));
        let scope = self.coverage.describe();
        if !scope.is_empty() {
            parts.push(scope);
        }
        parts.join("; ")
    }
}

// --- reading a Kubernetes timestamp -----------------------------------------------------------------

/// Reads the RFC 3339 form Kubernetes serialises, and nothing else.
///
/// `metav1.Time` and `metav1.MicroTime` both marshal in UTC with a `Z` suffix, so an offset form
/// is not something an API server produces. Refusing it keeps the parser from having to guess at
/// input this provider has no reason to see: an unreadable stamp becomes unplaceable, which is an
/// answer, where a guessed offset would become a wrong instant that sorts convincingly.
fn parse_rfc3339_millis(raw: &str) -> Option<u64> {
    let bytes = raw.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }

    let year = digits(raw.get(0..4)?)?;
    let month = digits(raw.get(5..7)?)?;
    let day = digits(raw.get(8..10)?)?;
    let hour = digits(raw.get(11..13)?)?;
    let minute = digits(raw.get(14..16)?)?;
    // 60 is a leap second, which upstream does not emit but which is a legal RFC 3339 value.
    let second = digits(raw.get(17..19)?)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let rest = raw.get(19..)?;
    let sub_second = if let Some(fraction) = rest.strip_prefix('.') {
        let fraction = fraction.strip_suffix('Z')?;
        if fraction.is_empty() || fraction.len() > 9 {
            return None;
        }
        // Truncating rather than rounding: a nanosecond timestamp rounded up could be made to
        // follow an observation it in fact preceded.
        let mut millis = String::with_capacity(3);
        for index in 0..3 {
            millis.push(
                fraction
                    .as_bytes()
                    .get(index)
                    .map_or('0', |byte| char::from(*byte)),
            );
        }
        digits(&millis)?
    } else {
        if rest != "Z" {
            return None;
        }
        0
    };

    let days = days_from_civil(i64::try_from(year).ok()?, month, day);
    if days < 0 {
        return None;
    }
    let seconds = u64::try_from(days).ok()? * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(seconds * 1_000 + sub_second)
}

/// Reads a run of ASCII digits, refusing anything else.
fn digits(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Days between 1970-01-01 and a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
///
/// Written out rather than pulled in with a date crate: this provider needs one direction of one
/// calendar conversion, and a dependency for it would widen the supply chain of a package that
/// already carries a TLS stack for a reason.
fn days_from_civil(year: i64, month: u64, day: u64) -> i64 {
    let month = i64::try_from(month).unwrap_or(1);
    let day = i64::try_from(day).unwrap_or(1);
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

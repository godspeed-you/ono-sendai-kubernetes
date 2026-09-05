//! Kubernetes Events: what was observed about an object, by whom, and how little that proves.
//!
//! Specification §38, §39.1 and §63.6. Events are the most tempting data Kubernetes offers and the
//! least dependable. They arrive with reasons that read like an API, timestamps that look like a
//! history, and counts that look like a list of occurrences — and §38 spends five of its six
//! subsections saying that none of those readings is available:
//!
//! ```text
//! §38.1  best-effort, limited retention — not a durable audit log, not a causal history
//! §38.3  an Event relates to what it regards, and keeps the source identity that reported it
//! §38.4  counts and series are preserved; occurrences that were not observed are not invented
//! §38.5  reason and note are evidence, not stable machine semantics
//! §38.6  the absence of an Event never proves that nothing happened
//! ```
//!
//! Three of those are expressed here in the shape of the types rather than in a warning comment.
//!
//! **A set of Events is a bag, not a timeline.** [`Observations`] keeps what it was given in the
//! order it was given, and offers no sort, no earliest, no latest and no time range. The clocks
//! belong to the components that reported the Events, delivery is unordered, and retention has
//! already discarded some of what happened — so an ordering assembled here would look like a
//! causal history while being an artefact of three unrelated accidents (§39.2).
//!
//! **A count is a count.** [`Occurrences`] carries the number the server recorded and the
//! endpoints it recorded it between. There is no `expand`: 46 of 47 aggregated failures were never
//! observed individually, and manufacturing them would produce records indistinguishable from ones
//! that had been seen.
//!
//! **Finding nothing is not finding an absence.** A search returns [`Found`], whose empty case
//! carries an [`Outcome`] and never [`Outcome::Absent`]. `if events.is_empty()` is §63.6 in one
//! line, and the type is what stops it being written.
//!
//! What this module deliberately does not do is read a `reason` (§38.5). Upstream warns that
//! reasons and messages evolve, so a branch on one is an unversioned dependency that fails
//! silently when a controller author rewords a string — the branch simply stops being taken.
//! `tests/events.rs` reads this source and fails if a known reason literal appears in it.

use serde_json::Value as Json;

use crate::coverage::Outcome;
use crate::object::{Identity, Object};
use crate::relationship::Target;

/// Why an object could not be read as an Event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    /// The object is not an Event in either representation.
    NotAnEvent {
        /// What it turned out to be.
        gvk: String,
    },
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnEvent { gvk } => write!(
                f,
                "`{gvk}` is not an Event; read through Event field names it would yield an \
                 observation that says nothing rather than the wrong question"
            ),
        }
    }
}

impl std::error::Error for EventError {}

/// Which of the two Event representations an object came in (§38.2).
///
/// Both stay readable because a cluster inside the support window of §5.1 may serve only the core
/// one, and because the newer group renamed almost every field: a provider that knew one spelling
/// would report a blank Event from half the clusters it can talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Representation {
    /// `events.k8s.io`, the representation §38.2 prefers.
    Events,
    /// The core group's Event, still served and still compatible.
    Core,
}

impl Representation {
    /// The group this representation lives in.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Events => "events.k8s.io",
            Self::Core => "core",
        }
    }

    /// Whether §38.2 prefers this one where both are served.
    #[must_use]
    pub fn is_preferred(self) -> bool {
        matches!(self, Self::Events)
    }
}

/// An Event's `type`, kept as the API wrote it.
///
/// Two values are documented upstream and a third may arrive from any controller. An `Other` arm
/// rather than a fallback to [`Self::Normal`], for §12.5's reason: a parser that folded an unknown
/// severity into the routine one would render a warning nobody has a name for as nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Level {
    /// Routine.
    Normal,
    /// Something the reporter wants attention for.
    Warning,
    /// A value neither of the above, preserved rather than coerced.
    Other(String),
    /// The Event carried no `type` at all, which is not the same as a routine one.
    Unstated,
}

impl Level {
    /// The value as the Event spelled it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Normal => "Normal",
            Self::Warning => "Warning",
            Self::Other(value) => value,
            Self::Unstated => "unstated",
        }
    }
}

/// Who reported an Event (§38.3).
///
/// "The kubelet said it" and "the scheduler said it" are different claims about the same object,
/// and an Event stripped of its reporter is an anonymous assertion. The instance is kept beside
/// the controller because one controller runs in several places and only one of them saw this.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reporter {
    controller: Option<String>,
    instance: Option<String>,
}

impl Reporter {
    /// The controller that reported it.
    #[must_use]
    pub fn controller(&self) -> Option<&str> {
        self.controller.as_deref()
    }

    /// The instance of that controller.
    #[must_use]
    pub fn instance(&self) -> Option<&str> {
        self.instance.as_deref()
    }
}

/// What the server recorded about how often the thing happened (§38.4).
///
/// A count and two endpoints. Not a list, and there is no way to make one: Kubernetes aggregates
/// repeated events precisely so that the individual occurrences do not have to be stored, so 46 of
/// 47 were never observed and cannot be reconstructed. A method that expanded the count would
/// produce records a reader could not tell from observed ones.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Occurrences {
    count: Option<u64>,
    series_count: Option<u64>,
    series_last_observed: Option<String>,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

impl Occurrences {
    /// How many the server recorded, from whichever mechanism recorded it.
    #[must_use]
    pub fn recorded_count(&self) -> Option<u64> {
        self.count.or(self.series_count)
    }

    /// The count of an ongoing series, where the Event is one (§38.4).
    #[must_use]
    pub fn series_count(&self) -> Option<u64> {
        self.series_count
    }

    /// When the series was last observed continuing.
    #[must_use]
    pub fn series_last_observed(&self) -> Option<&str> {
        self.series_last_observed.as_deref()
    }

    /// The first occurrence the server timestamped, where it timestamped one.
    ///
    /// Never filled in from `eventTime`: that is when the reporter saw *this* occurrence, and
    /// copying it here to complete a rendering would state a beginning nobody recorded.
    #[must_use]
    pub fn first_seen(&self) -> Option<&str> {
        self.first_seen.as_deref()
    }

    /// The last occurrence the server timestamped, where it timestamped one.
    #[must_use]
    pub fn last_seen(&self) -> Option<&str> {
        self.last_seen.as_deref()
    }

    /// Whether this Event stands for more than one occurrence.
    #[must_use]
    pub fn is_aggregate(&self) -> bool {
        self.is_series() || self.recorded_count().is_some_and(|count| count > 1)
    }

    /// Whether the server recorded this as a series rather than as a total.
    ///
    /// Two upstream mechanisms with two meanings — a total that has stopped moving, against a
    /// series with a last-observed time — and collapsing them into one number would lose the fact
    /// that the series is still running.
    #[must_use]
    pub fn is_series(&self) -> bool {
        self.series_count.is_some() || self.series_last_observed.is_some()
    }
}

/// One Event, in whichever representation it arrived in.
///
/// Deliberately without an ordering. A type with `Ord` on it invites sorting a set of Events by
/// time, and the result would be presented as a sequence of what happened — which is exactly the
/// claim §38.1 and §39.2 forbid, from data whose clocks belong to different reporters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    identity: Identity,
    representation: Representation,
    regarding: Option<Target>,
    related: Option<Target>,
    reason: Option<String>,
    note: Option<String>,
    action: Option<String>,
    level: Level,
    reporter: Reporter,
    event_time: Option<String>,
    occurrences: Occurrences,
}

impl Event {
    /// Reads one Event from either representation (§38.2).
    ///
    /// # Errors
    ///
    /// [`EventError::NotAnEvent`] for any other object.
    pub fn from_object(object: &Object) -> Result<Self, EventError> {
        let representation = match (object.gvk().group(), object.gvk().kind()) {
            ("events.k8s.io", "Event") => Representation::Events,
            ("", "Event") => Representation::Core,
            _ => {
                return Err(EventError::NotAnEvent {
                    gvk: object.gvk().to_string(),
                });
            }
        };

        Ok(Self {
            identity: object.identity(),
            representation,
            // `regarding` and `involvedObject` are the same fact renamed. Both are read whichever
            // representation this is: a server may serve one group and populate the other's field
            // during a migration, and refusing to look would lose the relationship §38.3 asks for.
            regarding: reference(object, "/regarding")
                .or_else(|| reference(object, "/involvedObject")),
            related: reference(object, "/related"),
            reason: text(object, "/reason"),
            note: text(object, "/note").or_else(|| text(object, "/message")),
            action: text(object, "/action"),
            level: match object.field("/type").and_then(Json::as_str) {
                Some("Normal") => Level::Normal,
                Some("Warning") => Level::Warning,
                Some(other) => Level::Other(other.to_owned()),
                None => Level::Unstated,
            },
            reporter: Reporter {
                controller: text(object, "/reportingController")
                    .or_else(|| text(object, "/reportingComponent"))
                    .or_else(|| text(object, "/source/component"))
                    .or_else(|| text(object, "/deprecatedSource/component")),
                instance: text(object, "/reportingInstance")
                    .or_else(|| text(object, "/source/host"))
                    .or_else(|| text(object, "/deprecatedSource/host")),
            },
            event_time: text(object, "/eventTime"),
            occurrences: Occurrences {
                count: count(object, "/count").or_else(|| count(object, "/deprecatedCount")),
                series_count: count(object, "/series/count"),
                series_last_observed: text(object, "/series/lastObservedTime"),
                first_seen: text(object, "/firstTimestamp")
                    .or_else(|| text(object, "/deprecatedFirstTimestamp")),
                last_seen: text(object, "/lastTimestamp")
                    .or_else(|| text(object, "/deprecatedLastTimestamp")),
            },
        })
    }

    /// The Event object's own identity — the Event is a resource like any other (§14).
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Which representation it was read from.
    #[must_use]
    pub fn representation(&self) -> Representation {
        self.representation
    }

    /// What the Event is about, where the reference names it completely enough to look up (§38.3).
    ///
    /// [`None`] where it does not. Such an Event is still an observation and is still kept:
    /// dropping it for being unattachable would delete evidence for tidiness.
    #[must_use]
    pub fn regarding(&self) -> Option<&Target> {
        self.regarding.as_ref()
    }

    /// The secondary object the Event mentions, where the newer representation carried one.
    #[must_use]
    pub fn related(&self) -> Option<&Target> {
        self.related.as_ref()
    }

    /// Whether this Event is about that object.
    ///
    /// UID first, and name only where a UID is missing on either side (§4 invariants 4 and 5). A
    /// Pod deleted and recreated under one name is two lifetimes, and the old Pod's Events are
    /// about decisions the new one never saw; a match on name alone is how a fresh Pod inherits its
    /// predecessor's failures. The provider instance has to agree too (Gate J): two clusters hand
    /// out UIDs independently, and an Event carries no instance of its own.
    #[must_use]
    pub fn regards(&self, subject: &Identity) -> bool {
        let Some(target) = &self.regarding else {
            return false;
        };
        if self.identity.provider_instance() != subject.provider_instance() {
            return false;
        }
        if target.kind() != subject.gvk().kind() {
            return false;
        }
        if let Some(stated) = target.api_version()
            && stated != api_version_of(subject)
        {
            return false;
        }
        match (target.uid(), subject.uid()) {
            (Some(stated), Some(observed)) => stated == observed,
            _ => target.namespace() == subject.namespace() && target.name() == subject.name(),
        }
    }

    /// The `reason`, as evidence (§38.5).
    ///
    /// A string to show a reader, never a value to branch on: upstream warns that reasons evolve,
    /// so code that switched on one would be an unversioned dependency that stops matching without
    /// failing. A curated adapter (§33.8) is where a stable meaning may be attached to one.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The human note — `note` in the newer representation, `message` in the core one (§38.5).
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// The action the reporter took or attempted, where it stated one.
    #[must_use]
    pub fn action(&self) -> Option<&str> {
        self.action.as_deref()
    }

    /// The Event's `type`.
    #[must_use]
    pub fn level(&self) -> &Level {
        &self.level
    }

    /// Who reported it (§38.3).
    #[must_use]
    pub fn reporter(&self) -> &Reporter {
        &self.reporter
    }

    /// When the reporter observed *this* occurrence.
    ///
    /// One clock among many. It is not comparable with another reporter's timestamps as a
    /// sequence, and it is not the beginning of anything (§38.4).
    #[must_use]
    pub fn occurrences(&self) -> &Occurrences {
        &self.occurrences
    }

    /// The reporter's timestamp for this observation.
    #[must_use]
    pub fn event_time(&self) -> Option<&str> {
        self.event_time.as_deref()
    }

    /// One line: what, about whom, from whom, and how many times it was recorded.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut line = self.level.as_str().to_owned();
        if let Some(reason) = &self.reason {
            line.push(' ');
            line.push_str(reason);
        }
        if let Some(target) = &self.regarding {
            line.push_str(" regarding ");
            line.push_str(target.kind());
            line.push('/');
            line.push_str(target.name());
        }
        if let Some(count) = self.occurrences.recorded_count() {
            line.push_str(&format!(", {count} recorded"));
        }
        if let Some(controller) = self.reporter.controller() {
            line.push_str(&format!(" (reported by {controller})"));
        }
        if let Some(note) = &self.note {
            line.push_str(": ");
            line.push_str(note);
        }
        line
    }
}

/// What a search of a set of Events came back with.
///
/// An enum rather than a possibly-empty list, because §38.6 makes the empty case a different kind
/// of answer: nothing was observed, which is not that nothing happened. A bare `Vec` invites
/// `if events.is_empty() { "nothing went wrong" }` — §63.6 in one line — and this type is what
/// makes that sentence require a second thought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found<'a> {
    /// Events matching the question were observed.
    Observed(Vec<&'a Event>),
    /// None were, and here is what that does and does not mean.
    NotObserved(Outcome),
}

impl<'a> Found<'a> {
    /// What was observed — empty when nothing was.
    #[must_use]
    pub fn observed(&self) -> &[&'a Event] {
        match self {
            Self::Observed(events) => events,
            Self::NotObserved(_) => &[],
        }
    }

    /// Whether anything was observed.
    #[must_use]
    pub fn is_observed(&self) -> bool {
        matches!(self, Self::Observed(_))
    }

    /// Why nothing was observed, or [`None`] where something was.
    ///
    /// Never [`Outcome::Absent`], at any input. Retention is minutes to hours, delivery is
    /// best-effort, and these observations were never a complete query of anything — so what is
    /// not here was not asked about, and [`Outcome::is_evidence_of_absence`] answers `false` for
    /// it. That is §38.6 said in a vocabulary the rest of the provider already speaks.
    #[must_use]
    pub fn outcome(&self) -> Option<Outcome> {
        match self {
            Self::Observed(_) => None,
            Self::NotObserved(outcome) => Some(*outcome),
        }
    }
}

/// The Events that were read, and nothing implied about the ones that were not.
///
/// A bag rather than a history. It keeps what it was given in the order it was given, and offers
/// no sort, no earliest, no latest and no time range — because their timestamps come from the
/// clocks of the components that reported them, delivery is unordered, and the cluster has already
/// discarded whatever fell out of retention. An ordering assembled here would read as a causal
/// history while being an artefact of those three accidents (§38.1, §39.2, §63.6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observations {
    seen: Vec<Event>,
}

impl Observations {
    /// Takes what was read.
    #[must_use]
    pub fn read(events: Vec<Event>) -> Self {
        Self { seen: events }
    }

    /// What was read, in the order it arrived.
    ///
    /// Arrival order, which is not chronology and is not causality. It is preserved rather than
    /// improved on, so that what a caller sees is what the server sent.
    #[must_use]
    pub fn seen(&self) -> &[Event] {
        &self.seen
    }

    /// The Events observed about one object (§38.3).
    #[must_use]
    pub fn about(&self, subject: &Identity) -> Found<'_> {
        self.gather(self.seen.iter().filter(|event| event.regards(subject)))
    }

    /// The Events observed at one level.
    ///
    /// Filtering on `type` rather than on `reason`: the type is API structure with two documented
    /// values, and the reason is a string a controller author may reword (§38.5).
    #[must_use]
    pub fn at_level(&self, level: &Level) -> Found<'_> {
        self.gather(self.seen.iter().filter(|event| &event.level == level))
    }

    fn gather<'a>(&'a self, events: impl Iterator<Item = &'a Event>) -> Found<'a> {
        let matched: Vec<&Event> = events.collect();
        if matched.is_empty() {
            // Never `Absent`: see `Found::outcome`.
            Found::NotObserved(Outcome::NotQueried)
        } else {
            Found::Observed(matched)
        }
    }
}

fn text(object: &Object, pointer: &str) -> Option<String> {
    object
        .field(pointer)
        .and_then(Json::as_str)
        .map(str::to_owned)
}

fn count(object: &Object, pointer: &str) -> Option<u64> {
    object.field(pointer).and_then(Json::as_u64)
}

/// An object reference, where it names something completely enough to be looked up (§38.3).
///
/// Kind and name are the two facts a reference cannot do without: a namespace can be absent for a
/// cluster-scoped object and a UID can be absent from an older reporter, but a reference missing
/// either of those two names nothing at all.
fn reference(object: &Object, pointer: &str) -> Option<Target> {
    let at = object.field(pointer)?;
    let kind = at.get("kind")?.as_str()?;
    let name = at.get("name")?.as_str()?;
    Some(
        Target::new(kind, name)
            .with_api_version(at.get("apiVersion").and_then(Json::as_str))
            .in_namespace(at.get("namespace").and_then(Json::as_str))
            .with_uid(at.get("uid").and_then(Json::as_str)),
    )
}

/// How an identity's group and version spell the `apiVersion` a reference would carry (§13.3).
fn api_version_of(identity: &Identity) -> String {
    let gvk = identity.gvk();
    if gvk.group().is_empty() {
        gvk.version().to_owned()
    } else {
        format!("{}/{}", gvk.group(), gvk.version())
    }
}

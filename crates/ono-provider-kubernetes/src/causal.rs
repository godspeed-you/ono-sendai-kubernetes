//! What `why` may say about two facts, and the sentence it has no way to construct.
//!
//! Specification §40, §23.4 of the generic provider contract, and §11.3 of the Cloud-Native
//! Vision. This is the module the project's truth claim rests on, and it is almost entirely about
//! what must not be said.
//!
//! A timeline showing a policy change at 14:21 and a health failure at 14:22 supports temporal
//! reasoning. It does not prove causation, and the reason to build a module for that sentence
//! rather than a code-review rule is that the sentence is always the one somebody wants to write.
//! So the discipline is in the type: the strongest thing a [`Finding`] can carry is a [`Claim`],
//! there are five of those, and none of them says a thing caused another thing.
//!
//! ```text
//! CAUSALITY_NOT_PROVEN     nothing sufficient was found, and here is what was missing
//! CORRELATED_WITH          two observations on one clock, close together. Proximity, nothing else
//! PRECEDED_BY              two observations on one clock, in an order. Order, nothing else
//! DEPENDENCY_PATH_EXISTS   a relationship path, so influence was possible. Possibility, not history
//! ASSERTED_BY_KUBERNETES   the API server states the link itself (§23.4)
//! ```
//!
//! Four things follow from that shape, and each is checked by a test rather than remembered:
//!
//! **Proximity has one reachable claim.** [`Finding::proximity`] returns
//! [`Claim::CorrelatedWith`] or [`Claim::CausalityNotProven`] and cannot be made to return
//! anything else, whatever window it is given. §23.4 forbids inferring causality from timestamp
//! proximity, and the constructor is where that becomes structural.
//!
//! **Two clocks produce no correlation at all.** A distance needs one clock (`temporal.rs`), so a
//! `creationTimestamp` against this machine's acquisition time yields
//! [`Unproven::ClocksDisagree`] rather than a number.
//!
//! **A path is possibility.** [`Claim::DependencyPathExists`] says influence *could* have
//! travelled along edges `relationship.rs` already derived. Whether it did is not in the graph.
//! The edges reach this module through a [`Walk`], which is bounded twice — in hops, which is
//! the question, and in reads, which is the cost — and which visits every object once, so a
//! cycle in the graph is a path that stops rather than one that never ends.
//!
//! **Kubernetes does assert some things, and they stay separable.** An ownerReference, an
//! `observedGeneration` that has caught up, an Event's `regarding` — §23.4 permits exposing
//! provider-native causality where the system actually asserts it, so those get their own rung.
//! It is still the top of the ladder rather than a claim of cause: §40.4 says ownership is
//! management responsibility, not the cause of every state change.
//!
//! And §40.5's required conclusion is reachable and cheap: a [`Why`] with nothing above the bottom
//! rung answers `insufficient evidence`, which the specification calls preferable to a plausible
//! invented explanation.

use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use crate::condition::Condition;
use crate::coverage::{Coverage, Gap, Outcome, Scope};
use crate::events::Event;
use crate::object::{Identity, Object};
use crate::relationship::{Edge, Evidence, Target};
use crate::temporal::{ClockSource, Observation, Order, Undecidable};

/// The strongest thing this provider may say about a link between two facts.
///
/// Five rungs, and the ladder stops here. A sixth variant meaning "brought about" would make
/// every refusal below a matter of whoever is reviewing the diff; its absence is what makes them
/// structural.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// Nothing sufficient was found (§40.5).
    CausalityNotProven,
    /// Two observations on one clock, within a stated window of each other.
    CorrelatedWith,
    /// Two observations on one clock, in a stated order.
    PrecededBy,
    /// A relationship path connects them, so influence was possible (§23).
    DependencyPathExists,
    /// Kubernetes states the link in a field of its own (§23.4, §37.3, §38.3).
    AssertedByKubernetes,
}

impl Claim {
    /// Every claim, weakest first.
    ///
    /// The order is how much of the evidential burden has been discharged, and the top of it is
    /// still short of causation — which is the property worth being able to enumerate and assert.
    #[must_use]
    pub fn ladder() -> [Self; 5] {
        [
            Self::CausalityNotProven,
            Self::CorrelatedWith,
            Self::PrecededBy,
            Self::DependencyPathExists,
            Self::AssertedByKubernetes,
        ]
    }

    /// The token this claim is reported under, matching §11.3 of the Cloud-Native Vision.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CausalityNotProven => "CAUSALITY_NOT_PROVEN",
            Self::CorrelatedWith => "CORRELATED_WITH",
            Self::PrecededBy => "PRECEDED_BY",
            Self::DependencyPathExists => "DEPENDENCY_PATH_EXISTS",
            Self::AssertedByKubernetes => "ASSERTED_BY_KUBERNETES",
        }
    }

    /// What the claim licenses a reader to conclude, and where it stops.
    ///
    /// Written into the vocabulary rather than left to a renderer, because a token on its own is
    /// read as strongly as its reader needs it to be.
    #[must_use]
    pub fn means(self) -> &'static str {
        match self {
            Self::CausalityNotProven => {
                "nothing was established; this is a statement about the search, not the cluster"
            }
            Self::CorrelatedWith => {
                "one clock saw both, close together; proximity is not a causal link"
            }
            Self::PrecededBy => {
                "one clock saw both, in this order; an order rules explanations out and \
                 establishes none"
            }
            Self::DependencyPathExists => {
                "a known relationship path connects them, so influence was possible; whether it \
                 travelled is not recorded anywhere"
            }
            Self::AssertedByKubernetes => {
                "the API server states this link; §40.4 makes that management responsibility \
                 rather than the origin of any particular state change"
            }
        }
    }

    /// Where the claim sits on the ladder, for [`Why::strongest_claim`].
    fn rung(self) -> u8 {
        match self {
            Self::CausalityNotProven => 0,
            Self::CorrelatedWith => 1,
            Self::PrecededBy => 2,
            Self::DependencyPathExists => 3,
            Self::AssertedByKubernetes => 4,
        }
    }
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a finding established nothing.
///
/// A refusal that names its reason is actionable — widen the window, ask for access, look for a
/// path — where a bare "unknown" sends the reader back to guessing (§40.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unproven {
    /// The two observations were written by different clocks, so no distance exists (§39.2).
    ClocksDisagree,
    /// At least one timestamp could not be read as an instant.
    Unplaceable,
    /// One clock wrote both, and they are further apart than the window asked about.
    OutsideWindow,
    /// One clock wrote both, and the earlier one is not the one offered as earlier.
    NotInThatOrder,
    /// No relationship path connects them (§23).
    NoPath,
    /// Kubernetes states nothing here; whatever is known was derived by this provider (§23.3).
    NotAsserted,
    /// A selector this provider does not evaluate left part of the neighbourhood undetermined
    /// (ADR-0007, §23.3), so a path through it can neither be reported nor ruled out.
    NotEvaluated,
    /// Nothing was gathered at all (§40.5).
    NoEvidence,
}

impl Unproven {
    /// The words this refusal is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClocksDisagree => "different clocks wrote the two timestamps",
            Self::Unplaceable => "a timestamp could not be read",
            Self::OutsideWindow => "further apart than the window asked about",
            Self::NotInThatOrder => "the observations are not in that order",
            Self::NoPath => "no relationship path connects them",
            Self::NotAsserted => "Kubernetes states no such link",
            Self::NotEvaluated => {
                "a selector this provider does not evaluate leaves part of the neighbourhood \
                 undetermined"
            }
            Self::NoEvidence => "nothing was gathered",
        }
    }
}

/// What a finding actually read.
///
/// A claim without its support is an opinion, and Gate D's rule for relationships applies here for
/// the same reason: an answer a user cannot check is one they have to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    /// Two observations one clock wrote, and how far apart it put them.
    Sequence {
        /// The clock that wrote both.
        clock: ClockSource,
        /// The distance it recorded, in milliseconds.
        apart_millis: u64,
    },
    /// The relationship edges along which influence was possible (§23).
    Path(Vec<Edge>),
    /// Something Kubernetes states, with the evidence class `relationship.rs` already defines.
    Assertion {
        /// What the API server states, in words.
        statement: String,
        /// The field or reference it states it in.
        evidence: Evidence,
    },
    /// Nothing sufficient, and why.
    Nothing(Unproven),
}

impl Support {
    /// One line naming what was read.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Sequence {
                clock,
                apart_millis,
            } => format!("{apart_millis}ms apart on {clock}"),
            // Each hop names its evidence class beside it, because a path is only as strong as
            // its weakest hop and a reader deciding how much to trust it has to be able to see
            // which hop that is (Gate D, §23).
            Self::Path(edges) => {
                let hops: Vec<String> = edges
                    .iter()
                    .map(|edge| {
                        format!(
                            "{} {}/{} [{}]",
                            edge.relation().as_str(),
                            edge.target().kind(),
                            edge.target().name(),
                            edge.evidence().class()
                        )
                    })
                    .collect();
                hops.join(" -> ")
            }
            Self::Assertion {
                statement,
                evidence,
            } => format!(
                "{statement} [{}: {}]",
                evidence.class(),
                evidence.describe()
            ),
            Self::Nothing(unproven) => unproven.as_str().to_owned(),
        }
    }
}

/// One thing this provider is prepared to say, and what it read to say it.
///
/// Every constructor is bounded in what it may return, which is where the discipline lives. There
/// is no `Finding::new(claim, support)`: a general constructor would let proximity be filed as an
/// assertion, and the type would stop carrying any guarantee at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    subject: Identity,
    claim: Claim,
    support: Support,
}

impl Finding {
    /// Two observations were close together in time (§23.4 of the generic contract).
    ///
    /// Returns [`Claim::CorrelatedWith`] or [`Claim::CausalityNotProven`] and cannot return
    /// anything else at any input. A change at 14:21 and a failure at 14:22 come back correlated,
    /// which is what was observed; the sentence everybody wants — that the first broke the second
    /// — has no representation here.
    #[must_use]
    pub fn proximity(
        subject: Identity,
        one: &Observation,
        other: &Observation,
        within_millis: u64,
    ) -> Self {
        let Some(apart) = one.stamp().apart_millis(other.stamp()) else {
            return Self::nothing(subject, unproven_from(one, other));
        };
        if apart > within_millis {
            return Self::nothing(subject, Unproven::OutsideWindow);
        }
        Self {
            subject,
            claim: Claim::CorrelatedWith,
            support: Support::Sequence {
                clock: one.stamp().source().clone(),
                apart_millis: apart,
            },
        }
    }

    /// One observation came before another on one clock.
    ///
    /// A real and useful fact — an order rules explanations out — and still not a cause. It is a
    /// separate rung from correlation because it discharges more of the burden: proximity says the
    /// two were near each other, precedence says which way round.
    #[must_use]
    pub fn precedence(subject: Identity, earlier: &Observation, later: &Observation) -> Self {
        match earlier.stamp().relate(later.stamp()) {
            Order::Before => {
                let apart = earlier.stamp().apart_millis(later.stamp()).unwrap_or(0);
                Self {
                    subject,
                    claim: Claim::PrecededBy,
                    support: Support::Sequence {
                        clock: earlier.stamp().source().clone(),
                        apart_millis: apart,
                    },
                }
            }
            Order::After | Order::Simultaneous => Self::nothing(subject, Unproven::NotInThatOrder),
            Order::Unordered(_) => Self::nothing(subject, unproven_from(earlier, later)),
        }
    }

    /// A relationship path connects the two, so influence was possible (§23, §40.3).
    ///
    /// The edges come from `relationship.rs` rather than being re-derived here: each already
    /// carries the evidence class that says whether the API server stated it or this provider
    /// derived it, and a path assembled from a second set of rules would lose that.
    #[must_use]
    pub fn dependency_path(subject: Identity, path: Vec<Edge>) -> Self {
        if path.is_empty() {
            return Self::nothing(subject, Unproven::NoPath);
        }
        Self {
            subject,
            claim: Claim::DependencyPathExists,
            support: Support::Path(path),
        }
    }

    /// Kubernetes states this relationship in a field of its own (§23.4).
    ///
    /// Only for evidence the API server asserts — a native field or an owner reference. A selector
    /// this provider evaluated is not an assertion however confident the match, and it comes back
    /// [`Unproven::NotAsserted`]: §23.3 keeps derivation and assertion apart, and this is the same
    /// boundary in the causal vocabulary.
    #[must_use]
    pub fn asserted(subject: Identity, edge: &Edge) -> Self {
        if !edge.evidence().is_asserted_by_provider() {
            return Self::nothing(subject, Unproven::NotAsserted);
        }
        Self {
            subject,
            claim: Claim::AssertedByKubernetes,
            support: Support::Assertion {
                statement: format!(
                    "{} {}/{}",
                    edge.relation().as_str(),
                    edge.target().kind(),
                    edge.target().name()
                ),
                evidence: edge.evidence().clone(),
            },
        }
    }

    /// The controller has acted on the spec this object currently carries (§37.3, §40.4).
    ///
    /// `observedGeneration` equal to `metadata.generation` is the API's own record that whoever
    /// wrote this status had seen this spec — an assertion about who acted on what, which the
    /// provider did not derive. A stale one is the opposite: nothing in that status is about the
    /// current spec, so it asserts nothing about it, and reading it as the controller's verdict is
    /// how a rollout comes to look finished.
    #[must_use]
    pub fn controller_acknowledged(
        subject: Identity,
        object: &Object,
        condition: &Condition,
    ) -> Self {
        let (Some(generation), Some(observed)) =
            (object.generation(), condition.observed_generation())
        else {
            return Self::nothing(subject, Unproven::NotAsserted);
        };
        if generation != observed {
            return Self::nothing(subject, Unproven::NotAsserted);
        }
        Self {
            subject,
            claim: Claim::AssertedByKubernetes,
            support: Support::Assertion {
                statement: format!(
                    "the controller writing `{}` had seen generation {generation}",
                    condition.type_name()
                ),
                evidence: Evidence::NativeField {
                    path: "/status/conditions/observedGeneration".to_owned(),
                    value: observed.to_string(),
                },
            },
        }
    }

    /// An Event states which object a reporter's action was about (§38.3).
    ///
    /// `regarding` is API structure, so the link between reporter and object is asserted rather
    /// than guessed. The Event's `reason` and `note` are not promoted with it: §38.5 makes those
    /// evolving strings, and a causal claim resting on one would be an unversioned dependency.
    #[must_use]
    pub fn event_regards(subject: Identity, event: &Event) -> Self {
        if !event.regards(&subject) {
            return Self::nothing(subject, Unproven::NotAsserted);
        }
        let Some(target) = event.regarding() else {
            return Self::nothing(subject, Unproven::NotAsserted);
        };
        let statement = format!(
            "{} reported an Event regarding {}/{}",
            event
                .reporter()
                .controller()
                .unwrap_or("an unnamed reporter"),
            target.kind(),
            target.name()
        );
        Self {
            subject,
            claim: Claim::AssertedByKubernetes,
            support: Support::Assertion {
                statement,
                evidence: Evidence::NativeField {
                    path: "/regarding".to_owned(),
                    value: format!("{}/{}", target.kind(), target.name()),
                },
            },
        }
    }

    /// A finding that establishes nothing, and says why (§40.5).
    #[must_use]
    pub fn nothing(subject: Identity, unproven: Unproven) -> Self {
        Self {
            subject,
            claim: Claim::CausalityNotProven,
            support: Support::Nothing(unproven),
        }
    }

    /// Which object the finding is about.
    #[must_use]
    pub fn subject(&self) -> &Identity {
        &self.subject
    }

    /// The strongest thing this finding says.
    #[must_use]
    pub fn claim(&self) -> Claim {
        self.claim
    }

    /// What was read to say it.
    #[must_use]
    pub fn support(&self) -> &Support {
        &self.support
    }

    /// One line: the claim, and what it rests on.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}: {}", self.claim.as_str(), self.support.describe())
    }
}

/// Why an object is in the state it is in — as far as evidence goes, and no further.
///
/// Carries its [`Coverage`] because the honesty of an answer depends on what the search could
/// reach: "nothing was found" over a denied namespace and "nothing was found" over a complete read
/// are different answers, and §21.4 has already given the provider a vocabulary for the
/// difference.
#[derive(Debug, Clone)]
pub struct Why {
    subject: Identity,
    coverage: Coverage,
    findings: Vec<Finding>,
}

impl Why {
    /// An answer about one object, over a stated coverage.
    #[must_use]
    pub fn about(subject: Identity, coverage: Coverage) -> Self {
        Self {
            subject,
            coverage,
            findings: Vec::new(),
        }
    }

    /// Adds a finding, including one that establishes nothing.
    ///
    /// The empty ones are kept on purpose: a refusal is evidence about the search, and an answer
    /// with them dropped looks like one where nobody looked (§4 invariant 13).
    ///
    /// A finding already made is not made twice. Its identity is the object, the claim and what
    /// the claim rests on — which is how the record it becomes is keyed — and two Pod conditions
    /// that each carry no `observedGeneration` are one fact about the object, not two. Counting
    /// it twice would be the summation [`Self::strongest_claim`] refuses, arriving by another
    /// door.
    pub fn add(&mut self, finding: Finding) {
        if self.findings.contains(&finding) {
            return;
        }
        self.findings.push(finding);
    }

    /// Which object this is about.
    #[must_use]
    pub fn subject(&self) -> &Identity {
        &self.subject
    }

    /// What the search could and could not reach (§21.4).
    #[must_use]
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Everything found, in the order it was found.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The strongest claim any finding makes.
    ///
    /// The maximum of a ladder whose top is [`Claim::AssertedByKubernetes`], never a summation:
    /// three weak findings do not add up to a strong one, and a scoring function is how they
    /// would. [`Claim::CausalityNotProven`] where there is nothing.
    #[must_use]
    pub fn strongest_claim(&self) -> Claim {
        self.findings
            .iter()
            .map(Finding::claim)
            .max_by_key(|claim| claim.rung())
            .unwrap_or(Claim::CausalityNotProven)
    }

    /// Whether the required conclusion of §40.5 is the honest one.
    #[must_use]
    pub fn is_insufficient(&self) -> bool {
        self.strongest_claim() == Claim::CausalityNotProven
    }

    /// The answer in words: every finding, the ceiling it reaches, and what the search missed.
    ///
    /// Always ends with the limit rather than with the strongest finding, because a reader who
    /// stops early should stop on the qualification and not on the claim.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.is_insufficient() {
            parts.push("insufficient evidence".to_owned());
        }
        parts.extend(self.findings.iter().map(Finding::describe));
        let scope = self.coverage.describe();
        if !scope.is_empty() {
            parts.push(format!("not observed: {scope}"));
        }
        let strongest = self.strongest_claim();
        parts.push(format!("{}: {}", strongest.as_str(), strongest.means()));
        parts.join("; ")
    }
}

// --- a bounded walk over the relationship graph (§40.3) -------------------------------------------

/// How far a dependency walk may go, and how much it may read on the way (§40.3, §49.1, §50.1).
///
/// Two bounds rather than one, because they stop different things. **Hops** is the question —
/// how many edges away from the subject a path may reach — and the caller sets it. **Reads** is
/// the cost — how many objects at the far ends of those edges the walk may fetch to learn the
/// next hop — and it is the bound §49.1 asks for: a walk that reads until the graph runs out is
/// the load generator that section forbids. A walk stopped by the second says so as a coverage
/// gap rather than by coming back shorter, which is §18.3's rule restated for a graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkBounds {
    hops: usize,
    reads: usize,
}

impl WalkBounds {
    /// How many hops a walk follows when nobody says: the subject's own edges, and no further.
    ///
    /// One, because the subject's edges cost nothing beyond what answering about that object
    /// already spends, and every further hop is a read of somebody else's object.
    pub const DEFAULT_HOPS: usize = 1;

    /// The most hops a walk may be asked for.
    ///
    /// Three reaches a Deployment from one of its Pods with a hop to spare, and matches the
    /// default the shell's own `trace` stops at. A deeper question is answered by asking it of
    /// the object the third hop reached, which keeps every answer's cost in proportion to what
    /// was typed.
    pub const MAX_HOPS: usize = 3;

    /// How many far-end objects a walk may read when nobody says.
    pub const DEFAULT_READS: usize = 32;

    /// A walk of this many hops, under the default read bound.
    ///
    /// # Errors
    ///
    /// [`WalkError::TooDeep`] above [`Self::MAX_HOPS`]. Refused rather than clamped, because a
    /// question silently answered for a shallower depth than it asked is a wrong answer that
    /// looks right.
    pub fn new(hops: usize) -> Result<Self, WalkError> {
        if hops > Self::MAX_HOPS {
            return Err(WalkError::TooDeep {
                asked: hops,
                allowed: Self::MAX_HOPS,
            });
        }
        Ok(Self {
            hops,
            reads: Self::DEFAULT_READS,
        })
    }

    /// The same walk, allowed this many far-end reads.
    #[must_use]
    pub fn with_reads(mut self, reads: usize) -> Self {
        self.reads = reads;
        self
    }

    /// How many hops the walk follows.
    #[must_use]
    pub fn hops(self) -> usize {
        self.hops
    }

    /// How many far-end objects it may read.
    #[must_use]
    pub fn reads(self) -> usize {
        self.reads
    }
}

impl Default for WalkBounds {
    fn default() -> Self {
        Self {
            hops: Self::DEFAULT_HOPS,
            reads: Self::DEFAULT_READS,
        }
    }
}

/// Why a walk was refused before it began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// More hops were asked for than [`WalkBounds::MAX_HOPS`] allows.
    TooDeep {
        /// What was asked for.
        asked: usize,
        /// The most that is allowed.
        allowed: usize,
    },
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::TooDeep { asked, allowed } = self;
        write!(
            f,
            "a dependency walk of {asked} hops was asked for, and at most {allowed} are followed"
        )
    }
}

impl std::error::Error for WalkError {}

/// What the far end of an edge yielded when the walk asked about it.
///
/// The walk owns the traversal and nothing else: which edges an object has is decided by the
/// same rules that answer `k8s-relation`, supplied by the caller, so that a path a user reads
/// hop by hop and one they are shown whole cannot disagree.
#[derive(Debug, Clone)]
pub enum Expansion {
    /// The object was read, and these are its edges, with whatever the derivation could not see.
    Edges {
        /// Every edge the object states or this provider derives about it.
        edges: Vec<Edge>,
        /// The scopes a derivation could not read (§21.4).
        gaps: Vec<Gap>,
        /// The selectors a derivation declined to evaluate, in its own words (ADR-0007).
        unevaluated: Vec<String>,
    },
    /// It is not there (§21.4 `absent`): the edge that named it stands, and nothing lies beyond.
    Absent,
    /// It could not be read, and this is what became of the attempt (§21.4).
    Unread(Gap),
}

/// The paths a bounded walk found from one object, and what it could not see (§40.3).
///
/// Every object is visited once, in a fixed order, and the walk stops at the hop bound and at
/// the read bound. Four things follow, each pinned by a test rather than remembered:
///
/// - **a cycle is a path that stops.** A ReplicaSet owns the Pod the walk started from; the edge
///   back to the subject is seen and not followed, and the walk ends;
/// - **an object reached twice is reported once**, along the first path found, which is a
///   shortest one because the walk is breadth-first;
/// - **an edge Kubernetes asserts is reported as the assertion** at the first hop, not as a
///   weaker path beside it — one fact, one finding, on the rung it earned;
/// - **the read bound is a coverage gap.** The far ends it left unread are recorded as
///   [`Outcome::NotQueried`] in their scopes, so a walk cut short is distinguishable from one
///   that reached the edge of the graph (§4 invariant 13).
#[derive(Debug, Clone)]
pub struct Walk {
    findings: Vec<Finding>,
    gaps: Vec<Gap>,
    unevaluated: Vec<String>,
    reads: usize,
    unexpanded: usize,
    stopped_by_reads: bool,
}

impl Walk {
    /// Walks outward from `subject` along `edges` and whatever `expand` learns beyond them.
    ///
    /// `edges` are the subject's own, already derived. `expand` is asked once per object the
    /// walk decides to read, in a fixed order, and never for the subject or for an object
    /// already reached.
    ///
    /// # Errors
    ///
    /// Whatever `expand` fails with. A failure is the connection under every remaining read
    /// breaking, which no walk continues past; a far end that merely could not be read is an
    /// [`Expansion::Unread`] and the walk goes on.
    pub fn explore<E>(
        subject: &Identity,
        bounds: WalkBounds,
        edges: Vec<Edge>,
        mut expand: impl FnMut(&Target) -> Result<Expansion, E>,
    ) -> Result<Self, E> {
        let mut walk = Self {
            findings: Vec::new(),
            gaps: Vec::new(),
            unevaluated: Vec::new(),
            reads: 0,
            unexpanded: 0,
            stopped_by_reads: false,
        };
        let mut seen = Seen::of(subject);
        let mut frontier: VecDeque<(Target, Vec<Edge>)> = VecDeque::new();

        // The first hop: every edge is a finding of its own, on the rung it earned. An edge
        // whose far end is the subject itself is a fact about the object and not a path anywhere.
        for edge in ordered(edges) {
            if seen.is_subject(edge.target()) {
                continue;
            }
            let finding = if edge.evidence().is_asserted_by_provider() {
                Finding::asserted(subject.clone(), &edge)
            } else {
                Finding::dependency_path(subject.clone(), vec![edge.clone()])
            };
            walk.findings.push(finding);
            if seen.mark(edge.target()) {
                frontier.push_back((edge.target().clone(), vec![edge]));
            }
        }

        // Every further hop costs a read, and is a path only where it reaches something new.
        while let Some((target, path)) = frontier.pop_front() {
            if path.len() >= bounds.hops {
                walk.unexpanded += 1;
                continue;
            }
            if walk.reads >= bounds.reads {
                walk.stopped_by_reads = true;
                walk.unexpanded += 1;
                walk.not_queried(&target);
                continue;
            }
            walk.reads += 1;
            match expand(&target)? {
                Expansion::Absent => {}
                Expansion::Unread(gap) => walk.gaps.push(gap),
                Expansion::Edges {
                    edges,
                    gaps,
                    unevaluated,
                } => {
                    walk.gaps.extend(gaps);
                    walk.unevaluated.extend(unevaluated);
                    for edge in ordered(edges) {
                        // The subject, or something already reached — a cycle, or a second
                        // route to one object. Either way it is not a new place influence could
                        // have reached, and following it is how a walk fails to end.
                        if !seen.mark(edge.target()) {
                            continue;
                        }
                        let mut extended = path.clone();
                        extended.push(edge.clone());
                        walk.findings
                            .push(Finding::dependency_path(subject.clone(), extended.clone()));
                        frontier.push_back((edge.target().clone(), extended));
                    }
                }
            }
        }
        Ok(walk)
    }

    /// Records a far end the read bound left unread, in its own scope (§18.3, §21.4).
    fn not_queried(&mut self, target: &Target) {
        let scope = target
            .namespace()
            .map_or_else(Scope::cluster, Scope::in_namespace);
        let gap = Gap::new(scope, Outcome::NotQueried);
        if !self.gaps.contains(&gap) {
            self.gaps.push(gap);
        }
    }

    /// Every finding, in the order the walk made it: the first hop, then each further hop.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The findings, for an answer that takes them.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }

    /// What the walk could not read: far ends past the read bound, and the scopes a derivation
    /// along the way could not see (§21.4).
    #[must_use]
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    /// The selectors a derivation along the way declined to evaluate (ADR-0007).
    #[must_use]
    pub fn unevaluated(&self) -> &[String] {
        &self.unevaluated
    }

    /// How many far-end objects were read.
    #[must_use]
    pub fn reads(&self) -> usize {
        self.reads
    }

    /// How many reached objects were not asked for their edges — at the hop bound, or past the
    /// read bound.
    #[must_use]
    pub fn unexpanded(&self) -> usize {
        self.unexpanded
    }

    /// Whether the read bound, rather than the hop bound or the graph, ended the walk.
    #[must_use]
    pub fn was_cut_short(&self) -> bool {
        self.stopped_by_reads
    }
}

/// The objects a walk has already reached, so that none is reached twice.
///
/// Keyed on the lifetime identity where a reference carries one, and on the locator where it
/// does not (§16.1, §16.2): a `spec.nodeName` names a Node and no uid, and a walk that could
/// not recognise that Node when an owner reference later named it with one would visit it twice.
struct Seen {
    subject_uid: Option<String>,
    subject_locator: (Option<String>, String, Option<String>, String),
    uids: BTreeSet<String>,
    locators: BTreeSet<(Option<String>, String, Option<String>, String)>,
}

impl Seen {
    fn of(subject: &Identity) -> Self {
        let locator = (
            Some(subject.gvk().group().to_owned()),
            subject.gvk().kind().to_owned(),
            subject.namespace().map(str::to_owned),
            subject.name().to_owned(),
        );
        let mut seen = Self {
            subject_uid: subject.uid().map(str::to_owned),
            subject_locator: locator.clone(),
            uids: BTreeSet::new(),
            locators: BTreeSet::new(),
        };
        if let Some(uid) = &seen.subject_uid {
            seen.uids.insert(uid.clone());
        }
        seen.locators.insert(locator);
        seen
    }

    fn locator_of(target: &Target) -> (Option<String>, String, Option<String>, String) {
        let group = target.api_version().map(|api_version| {
            api_version
                .split_once('/')
                .map_or("", |(group, _)| group)
                .to_owned()
        });
        (
            group,
            target.kind().to_owned(),
            target.namespace().map(str::to_owned),
            target.name().to_owned(),
        )
    }

    /// Whether a reference names the object the walk started from.
    fn is_subject(&self, target: &Target) -> bool {
        match (target.uid(), &self.subject_uid) {
            (Some(uid), Some(subject)) => uid == subject,
            _ => Self::locator_of(target) == self.subject_locator,
        }
    }

    /// Marks a reference as reached, and says whether it was new.
    fn mark(&mut self, target: &Target) -> bool {
        if self.is_subject(target) {
            return false;
        }
        let locator = Self::locator_of(target);
        let known_uid = target.uid().is_some_and(|uid| self.uids.contains(uid));
        let known_locator = self.locators.contains(&locator);
        if known_uid || known_locator {
            return false;
        }
        if let Some(uid) = target.uid() {
            self.uids.insert(uid.to_owned());
        }
        self.locators.insert(locator);
        true
    }
}

/// The edges in a fixed order, so that an answer is the same answer whatever order a listing
/// came back in.
fn ordered(mut edges: Vec<Edge>) -> Vec<Edge> {
    edges.sort_by(|left, right| {
        let key = |edge: &Edge| {
            (
                edge.relation().as_str(),
                edge.target().kind().to_owned(),
                edge.target().namespace().map(str::to_owned),
                edge.target().name().to_owned(),
                edge.evidence().class(),
                edge.evidence().describe(),
            )
        };
        key(left).cmp(&key(right))
    });
    edges
}

/// Which refusal a failed temporal comparison deserves.
///
/// Reads the reason out of `temporal.rs` rather than restating it: the module that knows why two
/// stamps are incomparable is the one that refused to compare them.
fn unproven_from(one: &Observation, other: &Observation) -> Unproven {
    match one.stamp().relate(other.stamp()) {
        Order::Unordered(Undecidable::DifferentClocks | Undecidable::ClockUnattributed) => {
            Unproven::ClocksDisagree
        }
        Order::Unordered(Undecidable::Unplaceable) => Unproven::Unplaceable,
        Order::Before | Order::After | Order::Simultaneous => Unproven::NoEvidence,
    }
}

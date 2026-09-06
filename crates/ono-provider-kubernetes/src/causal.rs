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

use std::fmt;

use crate::condition::Condition;
use crate::coverage::Coverage;
use crate::events::Event;
use crate::object::{Identity, Object};
use crate::relationship::{Edge, Evidence};
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
            Self::Path(edges) => {
                let hops: Vec<String> = edges
                    .iter()
                    .map(|edge| {
                        format!(
                            "{} {}/{}",
                            edge.relation().as_str(),
                            edge.target().kind(),
                            edge.target().name()
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
    pub fn add(&mut self, finding: Finding) {
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

//! Conditions as observations, and reconciliation states that name the fields they rest on.
//!
//! Specification §37, §20.4 and §4 invariants 8 and 9. Gate G: a successful spec update cannot be
//! rendered as a successful rollout until verification evidence arrives.
//!
//! Kubernetes writes desired state and observed state into the same document, and the distance
//! between them is where most operational surprise lives. `metadata.generation` moved because the
//! API server accepted a write. `status.observedGeneration` moved because a controller read it.
//! Neither says the workload runs. §20.4 lists five stages — accepted, spec observed, generation
//! observed, status converged, externally healthy — and no one of them proves the next.
//!
//! Two habits are refused here.
//!
//! **One synthetic status string** (§4 invariant 9). A condition carries `type`, `status`,
//! `reason`, `message`, and often the generation it was written about. Reducing that to a green
//! word throws away the only parts an operator can act on, and it hides that a Deployment can be
//! `Available=True` on its old replicas while `Progressing=False` because the new ones never came
//! up.
//!
//! **`observedGeneration` as success** (§37.3). It is evidence that a controller saw a desired
//! state, and by itself it is nothing more. Every state this module derives therefore carries
//! [`Citation`]s: the paths it read and what it found there, so the reader can disagree. A derived
//! state without them is a verdict rather than an observation, and §37.5 requires the citation.
//!
//! Condition *semantics* are kind-specific (§37.2). This module parses conditions for anything and
//! judges convergence only where it has a rule it can name — one rule for Deployments, and
//! otherwise the kind-independent statement that a generation was or was not observed.

use std::fmt;

use serde_json::Value as Json;

use crate::object::Object;

/// The `status` field of a condition, which is a string in the API and not a boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionStatus {
    /// `"True"`.
    True,
    /// `"False"`.
    False,
    /// `"Unknown"` — the controller says it does not know (§37.1).
    Unknown,
    /// Something else a controller wrote.
    ///
    /// Kept verbatim rather than coerced: §37.2 forbids assuming every resource uses conditions
    /// consistently, and turning an unfamiliar vocabulary into `false` is a wrong answer where
    /// "unfamiliar" was the honest one.
    Other(String),
}

impl ConditionStatus {
    /// Reads the string the API server sent.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "True" => Self::True,
            "False" => Self::False,
            "Unknown" => Self::Unknown,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The string as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::True => "True",
            Self::False => "False",
            Self::Unknown => "Unknown",
            Self::Other(value) => value,
        }
    }

    /// Whether the controller affirmed the condition.
    ///
    /// True only for `"True"`. What that affirmation *means* depends on the condition type and
    /// the kind (§37.2), so this answers about the field and not about health.
    #[must_use]
    pub fn is_true(&self) -> bool {
        matches!(self, Self::True)
    }
}

impl fmt::Display for ConditionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One structured observation from a controller (§37.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    type_name: String,
    status: ConditionStatus,
    reason: Option<String>,
    message: Option<String>,
    observed_generation: Option<i64>,
    last_transition_time: Option<String>,
}

impl Condition {
    /// The condition's `type`, which is the kind's own vocabulary (§37.2).
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// The condition's `status`.
    #[must_use]
    pub fn status(&self) -> &ConditionStatus {
        &self.status
    }

    /// The machine-readable `reason`, where the controller gave one.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The human-readable `message`, where the controller gave one.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The generation this observation was written about (§37.3).
    ///
    /// Absent rather than zero when the controller wrote none: a defaulted `0` would read as
    /// "observed generation 0", a claim the object never made.
    #[must_use]
    pub fn observed_generation(&self) -> Option<i64> {
        self.observed_generation
    }

    /// When the status last changed, as the string the server sent.
    #[must_use]
    pub fn last_transition_time(&self) -> Option<&str> {
        self.last_transition_time.as_deref()
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.type_name, self.status)?;
        if let Some(reason) = &self.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

/// Every condition under `status.conditions`, in the order the object lists them.
///
/// Order is preserved rather than sorted: it is what the controller wrote, and re-ordering an
/// observation is a small edit of someone else's record.
#[must_use]
pub fn conditions(object: &Object) -> Vec<Condition> {
    let Some(entries) = object.field("/status/conditions").and_then(Json::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            Some(Condition {
                type_name: entry.get("type")?.as_str()?.to_owned(),
                status: ConditionStatus::parse(entry.get("status")?.as_str()?),
                reason: string_at(entry, "reason"),
                message: string_at(entry, "message"),
                observed_generation: entry.get("observedGeneration").and_then(Json::as_i64),
                last_transition_time: string_at(entry, "lastTransitionTime"),
            })
        })
        .collect()
}

/// The condition of one type, where the object states it.
#[must_use]
pub fn condition<'a>(conditions: &'a [Condition], type_name: &str) -> Option<&'a Condition> {
    conditions.iter().find(|item| item.type_name() == type_name)
}

/// One container's observed state, which is where a Pod failure usually says what it is (§37.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerStatus {
    name: String,
    ready: bool,
    restart_count: Option<i64>,
    state: Option<String>,
    reason: Option<String>,
    message: Option<String>,
    exit_code: Option<i64>,
}

impl ContainerStatus {
    /// The container's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the kubelet reports it ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// How often it has restarted, which is what separates "starting" from "failing repeatedly".
    #[must_use]
    pub fn restart_count(&self) -> Option<i64> {
        self.restart_count
    }

    /// `waiting`, `running` or `terminated`, where the object states one.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// The state's `reason`, such as `CrashLoopBackOff` or `OOMKilled`.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The state's `message`.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The exit code of a terminated container, which distinguishes a clean exit from a kill.
    #[must_use]
    pub fn exit_code(&self) -> Option<i64> {
        self.exit_code
    }
}

/// Every container status a Pod reports, init containers included.
#[must_use]
pub fn container_statuses(object: &Object) -> Vec<ContainerStatus> {
    let mut statuses = Vec::new();
    for field in ["/status/initContainerStatuses", "/status/containerStatuses"] {
        let Some(entries) = object.field(field).and_then(Json::as_array) else {
            continue;
        };
        for entry in entries {
            let Some(name) = entry.get("name").and_then(Json::as_str) else {
                continue;
            };
            let state = entry
                .get("state")
                .and_then(Json::as_object)
                .and_then(|map| map.iter().next());
            statuses.push(ContainerStatus {
                name: name.to_owned(),
                ready: entry.get("ready").and_then(Json::as_bool).unwrap_or(false),
                restart_count: entry.get("restartCount").and_then(Json::as_i64),
                state: state.map(|(key, _)| key.clone()),
                reason: state.and_then(|(_, body)| string_at(body, "reason")),
                message: state.and_then(|(_, body)| string_at(body, "message")),
                exit_code: state.and_then(|(_, body)| body.get("exitCode")?.as_i64()),
            });
        }
    }
    statuses
}

/// A Pod's phase together with the observations the phase does not carry (§37.4).
///
/// Phase is a useful summary and a poor verdict: `Running` is true of a Pod whose only container
/// has restarted seven times in five minutes. The type exists so that the summary cannot be built
/// without the conditions and container statuses beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodView {
    phase: Option<String>,
    conditions: Vec<Condition>,
    containers: Vec<ContainerStatus>,
}

impl PodView {
    /// Reads a Pod.
    ///
    /// `None` for any other kind: phase is a Pod concept, and deriving one for a Deployment would
    /// be this provider assuming a vocabulary the kind does not use (§37.2).
    #[must_use]
    pub fn of(object: &Object) -> Option<Self> {
        if object.gvk().kind() != "Pod" {
            return None;
        }
        Some(Self {
            phase: object
                .field("/status/phase")
                .and_then(Json::as_str)
                .map(str::to_owned),
            conditions: conditions(object),
            containers: container_statuses(object),
        })
    }

    /// `status.phase`, where the object states one.
    #[must_use]
    pub fn phase(&self) -> Option<&str> {
        self.phase.as_deref()
    }

    /// The Pod's conditions.
    #[must_use]
    pub fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    /// The Pod's container statuses.
    #[must_use]
    pub fn container_statuses(&self) -> &[ContainerStatus] {
        &self.containers
    }

    /// How many containers the kubelet reports ready.
    #[must_use]
    pub fn ready_container_count(&self) -> usize {
        self.containers
            .iter()
            .filter(|container| container.is_ready())
            .count()
    }

    /// One line that carries the phase and everything the phase would otherwise hide (§37.4).
    #[must_use]
    pub fn summary_line(&self) -> String {
        let mut parts = vec![
            self.phase
                .clone()
                .unwrap_or_else(|| "phase absent".to_owned()),
        ];
        if !self.containers.is_empty() {
            parts.push(format!(
                "{}/{} containers ready",
                self.ready_container_count(),
                self.containers.len()
            ));
        }
        for container in &self.containers {
            if let Some(reason) = container.reason() {
                let restarts = container
                    .restart_count()
                    .map_or_else(String::new, |count| format!(", {count} restarts"));
                parts.push(format!("{}: {reason}{restarts}", container.name()));
            }
        }
        for condition in &self.conditions {
            if !condition.status().is_true() {
                parts.push(condition.to_string());
            }
        }
        parts.join("; ")
    }
}

/// One field a derived state depends on, and what it held (§37.5).
///
/// The value is `None` when the field is absent, because an absence is often exactly what decided
/// the state, and "the field was not there" is a different fact from "the field said nothing".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Citation {
    path: String,
    value: Option<String>,
}

impl Citation {
    /// The JSON pointer that was read.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What it held, or `None` where the field is absent.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl fmt::Display for Citation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{} = {value}", self.path),
            None => write!(f, "{} absent", self.path),
        }
    }
}

/// The stages §20.4 requires to stay distinguishable.
///
/// A ladder where no rung implies the next. It is ordered so that a reader can see how far the
/// evidence reaches, not so that reaching one stage may be reported as reaching a later one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// The API server accepted a desired-state change.
    ApiAccepted,
    /// The object was read back carrying the new spec.
    SpecObserved,
    /// A controller recorded that it observed the generation.
    GenerationObserved,
    /// Status converged by a rule this provider can name.
    StatusConverged,
    /// The workload is healthy as seen from outside.
    ///
    /// Never derivable from an API read: it needs a probe, a request or a metric. The variant
    /// exists so that the ladder is complete and so the gap is visible rather than assumed away.
    ExternallyHealthy,
}

impl Stage {
    /// The stage's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiAccepted => "API accepted desired-state change",
            Self::SpecObserved => "object observed with new spec",
            Self::GenerationObserved => "controller observed generation",
            Self::StatusConverged => "status converged",
            Self::ExternallyHealthy => "workload externally healthy",
        }
    }
}

/// Where an object stands between a desired state and an observed one (§37.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationState {
    /// The desired state changed and no controller has recorded seeing it.
    DesiredChangedNotObserved,
    /// A controller observed the generation; convergence is not established.
    ObservedConvergencePending,
    /// Converged, by a rule the derivation names.
    Converged,
    /// Failed, by a rule the derivation names.
    Failed,
    /// Not enough evidence to say anything (§37.5).
    UnknownInsufficientEvidence,
}

impl ReconciliationState {
    /// The state's wording, as §37.5 phrases it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DesiredChangedNotObserved => "desired state changed; controller not yet observed",
            Self::ObservedConvergencePending => "controller observed; convergence pending",
            Self::Converged => "converged by provider-specific rule",
            Self::Failed => "failed by provider-specific rule",
            Self::UnknownInsufficientEvidence => "unknown due to insufficient evidence",
        }
    }

    /// Whether convergence was actually verified.
    ///
    /// True for [`Self::Converged`] alone. `observedGeneration` matching is not convergence
    /// (§37.3), and a renderer that wants one green word has to ask this question rather than
    /// treating "not failed" as success.
    #[must_use]
    pub fn is_verified_convergence(self) -> bool {
        matches!(self, Self::Converged)
    }

    /// The furthest stage of §20.4 this state establishes.
    ///
    /// Never [`Stage::ExternallyHealthy`], and `None` where the evidence establishes nothing.
    #[must_use]
    pub fn established_stage(self) -> Option<Stage> {
        match self {
            Self::DesiredChangedNotObserved => Some(Stage::SpecObserved),
            Self::ObservedConvergencePending | Self::Failed => Some(Stage::GenerationObserved),
            Self::Converged => Some(Stage::StatusConverged),
            Self::UnknownInsufficientEvidence => None,
        }
    }
}

impl fmt::Display for ReconciliationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A derived reconciliation state, the rule that derived it, and the fields it read (§37.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    state: ReconciliationState,
    rule: &'static str,
    citations: Vec<Citation>,
}

impl Reconciliation {
    /// The state.
    #[must_use]
    pub fn state(&self) -> ReconciliationState {
        self.state
    }

    /// The rule that produced it, named so a reader can look it up and disagree with it.
    #[must_use]
    pub fn rule(&self) -> &'static str {
        self.rule
    }

    /// The fields the state depends on — required by §37.5 and never empty.
    #[must_use]
    pub fn citations(&self) -> &[Citation] {
        &self.citations
    }

    /// The state, its rule and its evidence in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        let cited: Vec<String> = self
            .citations
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        format!(
            "{} [{}] from {}",
            self.state.as_str(),
            self.rule,
            cited.join(", ")
        )
    }
}

/// Derives where an object stands between desired and observed state (§37.5, Gate G).
///
/// Kind-specific by construction (§37.2). Deployments get a rule that reads replica counts and
/// the `Progressing` condition. Every other kind gets the kind-independent statement that a
/// generation was or was not observed — which is all `observedGeneration` supports and, by §37.3,
/// is never on its own a claim of health.
#[must_use]
pub fn reconciliation(object: &Object) -> Reconciliation {
    let desired = cite(object, "/metadata/generation");
    let observed = cite(object, "/status/observedGeneration");

    let (Some(generation), Some(observed_generation)) = (
        object.generation(),
        object
            .field("/status/observedGeneration")
            .and_then(Json::as_i64),
    ) else {
        // §21.4's spirit: no evidence is its own answer. A controller that writes no status has
        // not said the object is fine, and it has not said it is broken.
        return Reconciliation {
            state: ReconciliationState::UnknownInsufficientEvidence,
            rule: "no-generation-evidence",
            citations: vec![desired, observed],
        };
    };

    if observed_generation < generation {
        return Reconciliation {
            state: ReconciliationState::DesiredChangedNotObserved,
            rule: "generation-ahead-of-observed",
            citations: vec![desired, observed],
        };
    }

    if object.gvk().kind() == "Deployment" && object.gvk().group() == "apps" {
        return deployment_state(object, desired, observed);
    }

    // §37.3, held literally: the controller saw this generation, and this provider has no rule
    // for what convergence means for this kind. Reporting anything better would be inventing one.
    Reconciliation {
        state: ReconciliationState::ObservedConvergencePending,
        rule: "generation-observed-only",
        citations: vec![desired, observed],
    }
}

/// The Deployment rule: `Progressing` for failure, replica counts for convergence.
fn deployment_state(object: &Object, desired: Citation, observed: Citation) -> Reconciliation {
    let rule = "deployment-generation-and-replicas";
    let conditions = conditions(object);
    let progressing = conditions
        .iter()
        .position(|item| item.type_name() == "Progressing")
        .map(|index| (index, &conditions[index]));

    if let Some((index, condition)) = progressing
        && !condition.status().is_true()
    {
        let mut citations = vec![desired, observed];
        citations.push(cite(object, &format!("/status/conditions/{index}/status")));
        citations.push(cite(object, &format!("/status/conditions/{index}/reason")));
        return Reconciliation {
            state: ReconciliationState::Failed,
            rule,
            citations,
        };
    }

    let wanted = object.field("/spec/replicas").and_then(Json::as_i64);
    let replica_fields = [
        "/status/replicas",
        "/status/updatedReplicas",
        "/status/availableReplicas",
    ];
    let mut citations = vec![desired, observed, cite(object, "/spec/replicas")];
    citations.extend(replica_fields.iter().map(|path| cite(object, path)));

    let counts: Vec<Option<i64>> = replica_fields
        .iter()
        .map(|path| object.field(path).and_then(Json::as_i64))
        .collect();
    let converged = wanted.is_some() && counts.iter().all(|count| *count == wanted);

    Reconciliation {
        state: if converged {
            ReconciliationState::Converged
        } else {
            ReconciliationState::ObservedConvergencePending
        },
        rule,
        citations,
    }
}

/// Reads one field as a citation: what it held, or that it was absent.
fn cite(object: &Object, path: &str) -> Citation {
    Citation {
        path: path.to_owned(),
        value: object.field(path).map(render),
    }
}

/// A JSON value as a citation reads it — a string unquoted, anything else as JSON.
fn render(value: &Json) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn string_at(value: &Json, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

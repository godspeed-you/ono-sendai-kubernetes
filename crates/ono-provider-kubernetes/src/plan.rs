//! What a change says about itself before anybody is asked to approve it.
//!
//! Specification §46 (prospective change), §56 (mutation preconditions), §45.2–§45.5 (propagation,
//! finalizers, dependents, storage) and §24.4 (ownership edges are impact evidence, not an order
//! of deletion). Nothing here sends anything: a plan is a value describing a change that has not
//! happened, and it is built from an object that was read and a clock nobody has to consult.
//!
//! Four properties shape the module.
//!
//! **A curated action is not an apply that happens to touch the right field.** §43.3 names seven
//! bounded actions and every one of them reduces to a field change; [`Curated`] carries *which*
//! one, because the reduction loses the three things §46.2 and §46.3 ask for — the word the change
//! is reported under, the effects it has beyond the field it writes (a cordon stops scheduling and
//! evicts nothing), and the rule by which its outcome could be verified. [`Action::Apply`] is what
//! is left when nobody curated it: §43.4's raw escape hatch, which [`Action::is_low_level`] and
//! [`Caveat::LowLevelChange`] say out loud rather than leaving to be inferred.
//!
//! **The guarded form is the short one.** [`Plan::of`] takes the object that was read and derives
//! the `resourceVersion` and UID preconditions §56 asks for. A plan for a target assembled by hand
//! is *refused* when those are missing, and the expert path out is [`Plan::unguarded`], which
//! takes a reason and marks the plan for the rest of its life. A mutation without a precondition
//! can land on an object that was recreated under the same name since the plan was made (§16.3),
//! and that is not a mistake a codebase should be able to make quietly.
//!
//! **Reversibility is not one question.** §46.5 separates reapplying a previous spec from getting
//! back what the change consumed. A container image change is reversible as configuration and
//! irreversible in every other respect: the pods that served the old image are gone, and so are the
//! requests they were serving. So every effect carries its own [`Reversibility`], the plan reports
//! the weakest of them, and [`Recovery`] states in two lists what reapplying would and would not
//! restore.
//!
//! **A plan is prospective and says so.** Nothing in it is evidence that anything happened (§4
//! invariant 18). What can be *verified* afterwards is a plan field too — [`VerificationRule`] —
//! because "how would we know this worked" is a question to answer before the change rather than
//! after it, and because the honest answer is sometimes that this provider has no rule (§46.3).

use std::fmt;

use serde_json::{Map as JsonMap, Value as Json};

use crate::condition::Stage;
use crate::coverage::{Coverage, Gap, Outcome, Scope};
use crate::discovery::{Gvk, Gvr};
use crate::object::{Identity, Object, OwnerReference};

// --- the target ---------------------------------------------------------------------------------

/// Which object a change is aimed at, and the facts that let it be aimed precisely (§16.1, §56).
///
/// The UID and the `resourceVersion` are `Option` because a target can be assembled from a name
/// that was typed, and a name is not an identity (§4 invariant 4). What that costs is stated by
/// [`Plan::targeting`], which refuses to build a plan around the gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    provider_instance: String,
    gvk: Gvk,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
    resource_version: Option<String>,
}

impl Target {
    /// The object that was read, as a target: identity and continuity token included.
    ///
    /// The constructor that should be reached for. Everything §56 requires comes from the
    /// observation itself, so the guarded plan is the one that needs no extra sentence.
    #[must_use]
    pub fn observed(object: &Object) -> Self {
        Self {
            provider_instance: object.identity().provider_instance().to_owned(),
            gvk: object.gvk().clone(),
            namespace: object.namespace().map(str::to_owned),
            name: object.name().to_owned(),
            uid: object.uid().map(str::to_owned),
            resource_version: object.resource_version().map(str::to_owned),
        }
    }

    /// A target named rather than observed: no UID, no `resourceVersion`.
    #[must_use]
    pub fn named(
        provider_instance: impl Into<String>,
        gvk: Gvk,
        namespace: Option<&str>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            provider_instance: provider_instance.into(),
            gvk,
            namespace: namespace.map(str::to_owned),
            name: name.into(),
            uid: None,
            resource_version: None,
        }
    }

    /// The same target with a `resourceVersion` precondition (§56.1).
    #[must_use]
    pub fn at_resource_version(mut self, resource_version: impl Into<String>) -> Self {
        self.resource_version = Some(resource_version.into());
        self
    }

    /// The same target with a UID precondition (§56.3).
    #[must_use]
    pub fn with_uid(mut self, uid: impl Into<String>) -> Self {
        self.uid = Some(uid.into());
        self
    }

    /// Which provider instance the target lives in (§6.2).
    #[must_use]
    pub fn provider_instance(&self) -> &str {
        &self.provider_instance
    }

    /// The kind identity (§13.1).
    #[must_use]
    pub fn gvk(&self) -> &Gvk {
        &self.gvk
    }

    /// The namespace, absent for a cluster-scoped object (§9.2).
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The UID, where the target was observed rather than typed.
    #[must_use]
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }

    /// The `resourceVersion` the plan was built against — a continuity token, never a clock
    /// (§14.3).
    #[must_use]
    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    /// The scope the request goes to.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.namespace
            .as_ref()
            .map_or_else(Scope::cluster, Scope::in_namespace)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.provider_instance, self.gvk)?;
        match &self.namespace {
            Some(namespace) => write!(f, "{namespace}/{}", self.name),
            None => write!(f, "{}", self.name),
        }
    }
}

// --- preconditions ------------------------------------------------------------------------------

/// A precondition a target could not supply (§56.1, §56.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingPrecondition {
    /// No `resourceVersion`, so a concurrent write would be overwritten unseen (§56.1).
    ResourceVersion,
    /// No UID, so a recreated object of the same name would be hit instead (§56.3).
    Uid,
}

impl fmt::Display for MissingPrecondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceVersion => f.write_str(
                "no resourceVersion precondition: a change made since the plan was built would be \
                 overwritten unseen (§56.1)",
            ),
            Self::Uid => f.write_str(
                "no UID precondition: an object recreated under this name since the plan was \
                 built would be hit instead (§56.3)",
            ),
        }
    }
}

/// What a mutation asserts about its target before the server carries it out (§56).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Preconditions {
    resource_version: Option<String>,
    uid: Option<String>,
}

impl Preconditions {
    /// The preconditions a target can supply.
    #[must_use]
    pub fn of(target: &Target) -> Self {
        Self {
            resource_version: target.resource_version.clone(),
            uid: target.uid.clone(),
        }
    }

    /// The `resourceVersion` this mutation requires the object to still be at (§56.1).
    #[must_use]
    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    /// The UID this mutation requires the object to still be (§56.3).
    #[must_use]
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }

    /// Whether a concurrent write would be caught rather than overwritten (§56.1).
    #[must_use]
    pub fn guards_lost_update(&self) -> bool {
        self.resource_version.is_some()
    }

    /// Whether a same-name object of a different lifetime would be refused (§56.3, §16.3).
    #[must_use]
    pub fn guards_recreation(&self) -> bool {
        self.uid.is_some()
    }

    /// The preconditions that are not there, so a refusal can name them rather than say "invalid".
    #[must_use]
    pub fn missing(&self) -> Vec<MissingPrecondition> {
        let mut missing = Vec::new();
        if !self.guards_lost_update() {
            missing.push(MissingPrecondition::ResourceVersion);
        }
        if !self.guards_recreation() {
            missing.push(MissingPrecondition::Uid);
        }
        missing
    }
}

impl fmt::Display for Preconditions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.resource_version, &self.uid) {
            (Some(version), Some(uid)) => write!(f, "resourceVersion {version} and uid {uid}"),
            (Some(version), None) => write!(f, "resourceVersion {version}"),
            (None, Some(uid)) => write!(f, "uid {uid}"),
            (None, None) => f.write_str("none"),
        }
    }
}

// --- the action ---------------------------------------------------------------------------------

/// How dependents are treated when the target goes (§45.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Propagation {
    /// The target stays until its dependents are gone.
    Foreground,
    /// The target goes now and the collector removes dependents afterwards.
    Background,
    /// Dependents stay behind, owned by nothing.
    Orphan,
}

impl Propagation {
    /// The word the API server uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Foreground => "Foreground",
            Self::Background => "Background",
            Self::Orphan => "Orphan",
        }
    }

    /// Whether known dependents are expected to be removed with the target.
    ///
    /// "Expected", not "guaranteed": §24.4 is explicit that ownership edges are impact evidence
    /// and not a promise about what the garbage collector does or in which order.
    #[must_use]
    pub fn removes_dependents(self) -> bool {
        matches!(self, Self::Foreground | Self::Background)
    }
}

impl fmt::Display for Propagation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One field a change touches, with what it holds now and what it would hold (§46.2).
///
/// `from` and `to` are `Option` because absence is a value here: a field that is not there yet and
/// a field being removed are both ordinary changes, and rendering either as `null` would make them
/// indistinguishable from a field explicitly set to null.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldChange {
    path: String,
    from: Option<Json>,
    to: Option<Json>,
}

impl FieldChange {
    /// A field set to a value, with no claim about what it holds now.
    #[must_use]
    pub fn set(path: impl Into<String>, to: Json) -> Self {
        Self {
            path: path.into(),
            from: None,
            to: Some(to),
        }
    }

    /// A field moving from one observed value to another.
    #[must_use]
    pub fn change(path: impl Into<String>, from: Json, to: Json) -> Self {
        Self {
            path: path.into(),
            from: Some(from),
            to: Some(to),
        }
    }

    /// A field being removed, with what it holds now.
    #[must_use]
    pub fn remove(path: impl Into<String>, from: Json) -> Self {
        Self {
            path: path.into(),
            from: Some(from),
            to: None,
        }
    }

    /// The JSON pointer of the field, as [`Object::field`] reads it.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What the field held when the plan was built, where that was observed.
    #[must_use]
    pub fn from(&self) -> Option<&Json> {
        self.from.as_ref()
    }

    /// What the field would hold, or `None` when the change removes it.
    #[must_use]
    pub fn to(&self) -> Option<&Json> {
        self.to.as_ref()
    }

    /// The change in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        let from = self
            .from
            .as_ref()
            .map_or_else(|| "absent".to_owned(), ToString::to_string);
        let to = self
            .to
            .as_ref()
            .map_or_else(|| "removed".to_owned(), ToString::to_string);
        format!("{}: {from} -> {to}", self.path)
    }
}

/// One of §43.3's named state transitions.
///
/// §43.3 lists seven candidate actions and every one of them reduces to a bounded field change —
/// scaling is `/spec/replicas`, cordoning is `/spec/unschedulable`, a rollout restart is an
/// annotation on the pod template. Reducing them is not the same as *offering* them: what §43.3
/// asks for is a surface a user can reason about, and a surface whose only word is "apply a JSON
/// pointer" makes every one of these an exercise in knowing the schema.
///
/// So the transition is carried beside the fields rather than inferred from them. It decides
/// three things a bare field list cannot: the word the change is reported under, the effects it
/// has beyond the field (a cordon stops scheduling and evicts nothing), and the verification rule
/// §46.3 requires to match the action's semantics. A curated action whose rule is an apply's rule
/// is a curated action in name only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curated {
    /// A workload's replica count (§43.3, §46.3's first worked example).
    Scale,
    /// A container image in a workload's pod template, or on a Pod (§43.3, §46.3's second).
    SetImage,
    /// A rollout restarted through the pod-template annotation that makes controllers roll
    /// (§43.3's "explicit supported mechanism").
    RestartRollout,
    /// A Node taken out of scheduling (§43.3, §46.3's third worked example).
    Cordon,
    /// A Node put back into scheduling (§43.3).
    Uncordon,
    /// Labels on the object's metadata (§43.3, §14.5).
    Label,
    /// Annotations on the object's metadata (§43.3, §14.5).
    Annotate,
}

impl Curated {
    /// The word the transition is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scale => "scale",
            Self::SetImage => "set-image",
            Self::RestartRollout => "restart-rollout",
            Self::Cordon => "cordon",
            Self::Uncordon => "uncordon",
            Self::Label => "label",
            Self::Annotate => "annotate",
        }
    }

    /// What the transition does, in one line.
    #[must_use]
    pub fn summary(self) -> &'static str {
        match self {
            Self::Scale => "change how many replicas the workload asks for",
            Self::SetImage => {
                "change a container's image, which rolls the pods that ran the old one"
            }
            Self::RestartRollout => {
                "roll every pod of the workload by marking its pod template as changed"
            }
            Self::Cordon => "stop the scheduler placing new pods on this node",
            Self::Uncordon => "let the scheduler place new pods on this node again",
            Self::Label => "change labels on the object's metadata",
            Self::Annotate => "change annotations on the object's metadata",
        }
    }
}

impl fmt::Display for Curated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the change is, in the bounded vocabulary §43.3 asks for.
///
/// Three members rather than one per HTTP verb. Every candidate action of §43.3 reduces to a
/// bounded field change or to a deletion, and the third member is the difference §43.4 insists
/// on: [`Self::Curated`] is one of §43.3's named transitions, and [`Self::Apply`] is the raw
/// escape hatch — a field list somebody assembled by JSON pointer, which "MUST be explicitly
/// low-level" and "MUST NOT become the default UX simply because it is easy to implement".
/// [`Self::is_low_level`] is how the rest of the system can tell them apart, and
/// [`Caveat::LowLevelChange`] is how a user does.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// One of §43.3's named transitions, as the bounded field change it reduces to.
    Curated(Curated, Vec<FieldChange>),
    /// A raw set of field changes named by JSON pointer: §43.4's expert escape hatch.
    Apply(Vec<FieldChange>),
    /// Deletion, with the propagation policy it was chosen with (§45.2).
    Delete(Propagation),
}

impl Action {
    /// A bounded field change nobody curated: §43.4's low-level path.
    #[must_use]
    pub fn apply(fields: Vec<FieldChange>) -> Self {
        Self::Apply(fields)
    }

    /// One of §43.3's named transitions, with the field changes it makes.
    #[must_use]
    pub fn curated(transition: Curated, fields: Vec<FieldChange>) -> Self {
        Self::Curated(transition, fields)
    }

    /// A deletion with a propagation policy.
    #[must_use]
    pub fn delete(propagation: Propagation) -> Self {
        Self::Delete(propagation)
    }

    /// Which of §43.3's transitions this is, where it is one of them.
    #[must_use]
    pub fn curation(&self) -> Option<Curated> {
        match self {
            Self::Curated(transition, _) => Some(*transition),
            Self::Apply(_) | Self::Delete(_) => None,
        }
    }

    /// Whether this is §43.4's raw escape hatch rather than one of §43.3's named transitions.
    ///
    /// A deletion is not low-level: `remove` is one of §43.3's own candidate actions and it says
    /// exactly what it does. What is low-level is a field list aimed by pointer at a schema the
    /// caller is expected to know.
    #[must_use]
    pub fn is_low_level(&self) -> bool {
        matches!(self, Self::Apply(_))
    }

    /// The verb this action is reported under.
    #[must_use]
    pub fn verb(&self) -> &'static str {
        match self {
            Self::Curated(transition, _) => transition.as_str(),
            Self::Apply(_) => "apply",
            Self::Delete(_) => "delete",
        }
    }

    /// The API server's own verb for this action, as discovery and an authorization review
    /// spell it (§11.5, §21.2).
    ///
    /// Not [`Self::verb`]: that is the word a record is reported under, and `apply` is not a
    /// Kubernetes verb. Server-side apply is a `PATCH`, so an authorizer asked about `apply`
    /// answers about nothing.
    #[must_use]
    pub fn api_verb(&self) -> &'static str {
        match self {
            Self::Curated(_, _) | Self::Apply(_) => "patch",
            Self::Delete(_) => "delete",
        }
    }

    /// Whether the action removes something rather than changing it (§56.3).
    #[must_use]
    pub fn is_destructive(&self) -> bool {
        matches!(self, Self::Delete(_))
    }

    /// The fields the action touches; empty for a deletion, which touches the whole object.
    #[must_use]
    pub fn field_changes(&self) -> &[FieldChange] {
        match self {
            Self::Curated(_, fields) | Self::Apply(fields) => fields,
            Self::Delete(_) => &[],
        }
    }

    /// The propagation policy, for a deletion.
    #[must_use]
    pub fn propagation(&self) -> Option<Propagation> {
        match self {
            Self::Curated(_, _) | Self::Apply(_) => None,
            Self::Delete(policy) => Some(*policy),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Curated(transition, fields) => write!(
                f,
                "{transition} — {} — through {} field change(s)",
                transition.summary(),
                fields.len()
            ),
            Self::Apply(fields) => write!(
                f,
                "apply {} low-level field change(s) named by JSON pointer (§43.4)",
                fields.len()
            ),
            Self::Delete(policy) => write!(f, "delete (propagation {policy})"),
        }
    }
}

// --- effects and recovery -------------------------------------------------------------------------

/// What a change is expected to do beyond the field it names (§46.2, §46.5).
///
/// Prospective by construction: these are the effects a change of this shape has, not effects
/// anybody observed. They exist so that the destructive part of an innocuous-looking field change
/// is visible at the moment of approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectKind {
    /// The object's configuration differs afterwards.
    ConfigurationChanged,
    /// Running pods are replaced by new ones, losing whatever was only in them.
    PodsReplaced,
    /// Running pods are stopped and not replaced.
    PodsStopped,
    /// The scheduler stops placing new pods here; what is already running keeps running (§43.3).
    SchedulingStopped,
    /// The scheduler may place new pods here again (§43.3).
    SchedulingRestored,
    /// Requests in flight and connections held to the old pods end (§46.5).
    TrafficDisrupted,
    /// The object itself is removed; anything recreated under the name is a new lifetime (§16.3).
    ObjectRemoved,
    /// Known dependents are expected to be removed with it (§45.4, §24.4).
    DependentsRemoved,
    /// Known dependents stay behind, owned by nothing (§45.2).
    DependentsOrphaned,
    /// Persistent data may be reclaimed, by a controller this provider does not watch (§45.5).
    PersistentDataAtRisk,
    /// Effects outside the API server — cloud load balancers, volumes, DNS (§45.5, §46.5).
    ExternalSideEffects,
}

impl EffectKind {
    /// The effect in the words it is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigurationChanged => "configuration changes",
            Self::PodsReplaced => "running pods are replaced",
            Self::PodsStopped => "running pods are stopped",
            Self::SchedulingStopped => {
                "no new pods are scheduled here; pods already running are neither stopped nor moved"
            }
            Self::SchedulingRestored => "new pods may be scheduled here again",
            Self::TrafficDisrupted => "requests in flight and existing connections end",
            Self::ObjectRemoved => "the object is removed and its lifetime ends",
            Self::DependentsRemoved => "known dependents are expected to be removed",
            Self::DependentsOrphaned => "known dependents are left owned by nothing",
            Self::PersistentDataAtRisk => "persistent data may be reclaimed",
            Self::ExternalSideEffects => "effects outside the API server may follow",
        }
    }
}

impl fmt::Display for EffectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether an effect can be undone, and by what (§46.5).
///
/// Three answers, and the first one is narrower than it looks: reapplying a previous spec restores
/// *the spec*. It does not restore what happened while the other spec was in force, and §46.5 lists
/// admission results that may differ on the way back. There is deliberately no variant meaning
/// "fully reversible".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reversibility {
    /// The previous field values can be reapplied, which restores configuration and nothing else.
    ConfigurationReapplicable,
    /// Nothing this provider can send restores what this effect consumed.
    Irreversible,
    /// This provider cannot tell, which is not the same as "yes".
    Unknown,
}

impl Reversibility {
    /// The answer in the words it is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigurationReapplicable => "configuration reapplicable",
            Self::Irreversible => "irreversible",
            Self::Unknown => "unknown",
        }
    }

    /// How bad this answer is, so a plan can report the weakest of its effects.
    ///
    /// `Unknown` ranks above `ConfigurationReapplicable` because a plan that cannot tell must not
    /// summarise itself with the friendliest of its parts.
    fn severity(self) -> u8 {
        match self {
            Self::ConfigurationReapplicable => 0,
            Self::Unknown => 1,
            Self::Irreversible => 2,
        }
    }
}

impl fmt::Display for Reversibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One expected effect and what could be done about it afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effect {
    kind: EffectKind,
    reversibility: Reversibility,
}

impl Effect {
    /// What is expected to happen.
    #[must_use]
    pub fn kind(&self) -> EffectKind {
        self.kind
    }

    /// What could be done about it afterwards (§46.5).
    #[must_use]
    pub fn reversibility(&self) -> Reversibility {
        self.reversibility
    }
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.kind, self.reversibility)
    }
}

/// What reapplying the previous state would restore, and what it would not (§46.5).
///
/// Two lists rather than a verdict. "Recoverable" as a single word is the claim §46.5 forbids, and
/// the second list is the one an operator needs: it is where the deleted ephemeral data, the
/// dropped connections and the storage reclaim end up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    restores: Vec<EffectKind>,
    does_not_restore: Vec<EffectKind>,
}

impl Recovery {
    /// The effects reapplying the previous values would undo.
    #[must_use]
    pub fn restores(&self) -> &[EffectKind] {
        &self.restores
    }

    /// The effects it would not undo — the list §46.5 requires to be stated.
    #[must_use]
    pub fn does_not_restore(&self) -> &[EffectKind] {
        &self.does_not_restore
    }

    /// Both lists, and the sentence that stops the first one being read as a rollback.
    #[must_use]
    pub fn describe(&self) -> String {
        let restores = if self.restores.is_empty() {
            "nothing".to_owned()
        } else {
            join(self.restores.iter().map(|kind| kind.as_str()))
        };
        let mut line = format!("reapplying the previous values restores {restores}");
        if self.does_not_restore.is_empty() {
            line.push_str("; it is not a rollback: admission may default differently on reapply");
        } else {
            line.push_str(&format!(
                "; it is not a rollback and does not restore {}",
                join(self.does_not_restore.iter().map(|kind| kind.as_str()))
            ));
        }
        line
    }
}

// --- dependents ------------------------------------------------------------------------------------

/// An object that names the target as an owner (§24.1), previewed as deletion impact (§45.4).
///
/// Owner-reference evidence and nothing weaker. §23 keeps four evidence classes apart, and a
/// dependent preview assembled from label conventions or from "everything in the namespace" would
/// present a guess with the weight of a provider-proven edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependent {
    identity: Identity,
    controller: bool,
    blocks_owner_deletion: bool,
}

impl Dependent {
    /// The object as a dependent of `owner`, or `None` when no owner reference says so.
    #[must_use]
    pub fn of(object: &Object, owner: &Target) -> Option<Self> {
        let uid = owner.uid()?;
        let reference = object
            .owner_references()
            .iter()
            .find(|reference| reference.uid() == uid)?;
        Some(Self {
            identity: object.identity(),
            controller: reference.is_controller(),
            blocks_owner_deletion: reference.blocks_owner_deletion(),
        })
    }

    /// Which object this is (§16.1).
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Whether the owner reference is the controlling one (§24.3).
    #[must_use]
    pub fn is_controller(&self) -> bool {
        self.controller
    }

    /// Whether the reference asks the collector to keep the owner until this is gone.
    #[must_use]
    pub fn blocks_owner_deletion(&self) -> bool {
        self.blocks_owner_deletion
    }
}

// --- the surroundings of a plan --------------------------------------------------------------------

// --- competing desired-state writers (§54) --------------------------------------------------------

/// Which of §54.1's five sources named a writer.
///
/// A vocabulary rather than a sentence, because the sources are not equally strong and a reader
/// deciding whether to go ahead needs to know which one spoke. A field manager on `managedFields`
/// is a record of a write that already happened; an HPA target is a controller that is *going* to
/// write; an owner is a controller that reconciles the whole object. Flattening the three into
/// "something else writes this" would lose the only part that predicts what happens next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterEvidence {
    /// `metadata.managedFields` records this manager owning fields of the object (§14.7, §44.3).
    FieldManager,
    /// A HorizontalPodAutoscaler names this object in `spec.scaleTargetRef` (§54.2).
    Autoscaler,
    /// A controller owns this object through an owner reference (§24.3).
    Owner,
}

impl WriterEvidence {
    /// The source in the words it is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FieldManager => "managedFields",
            Self::Autoscaler => "HorizontalPodAutoscaler scaleTargetRef",
            Self::Owner => "owner reference",
        }
    }
}

impl fmt::Display for WriterEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Something other than this change that writes this object's desired state (§54.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompetingWriter {
    name: String,
    evidence: WriterEvidence,
    writes: String,
    detail: Option<String>,
}

impl CompetingWriter {
    /// A manager `metadata.managedFields` already records (§54.1's first source).
    #[must_use]
    pub fn field_manager(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            evidence: WriterEvidence::FieldManager,
            writes: "fields of this object it already owns".to_owned(),
            detail: None,
        }
    }

    /// The controller that owns this object, which reconciles the whole of it (§24.3, §54.1).
    ///
    /// The *controller* owner and not every owner: §24.3 keeps the two apart because one owner
    /// reference in the list is the thing that actually reconciles the object and the rest are
    /// ownership for garbage collection. A ReplicaSet's Deployment writes its spec back; a
    /// non-controller owner does not.
    #[must_use]
    pub fn controller(reference: &OwnerReference) -> Self {
        Self {
            name: format!("{} {}", reference.kind(), reference.name()),
            evidence: WriterEvidence::Owner,
            writes: "this object's spec, which it reconciles from its own".to_owned(),
            detail: Some(
                "a change made here may be reconciled back by the controller that owns this \
                 object (§24.3, §54.1)"
                    .to_owned(),
            ),
        }
    }

    /// The autoscaler that governs this workload, where the candidate object is one (§54.2).
    ///
    /// `None` for every HorizontalPodAutoscaler that names a different workload. §54.1 asks for
    /// *known* competing writers, and an HPA in the same namespace is not evidence about this
    /// object: the match is `spec.scaleTargetRef` against the target's kind, group and name, which
    /// is the reference the autoscaler itself acts on. Matching on less would make every HPA in a
    /// busy namespace a warning, and a warning that fires on everything is read as noise.
    #[must_use]
    pub fn autoscaler(candidate: &Object, target: &Target) -> Option<Self> {
        let reference = candidate.field("/spec/scaleTargetRef")?;
        if reference.get("name").and_then(Json::as_str)? != target.name() {
            return None;
        }
        if reference.get("kind").and_then(Json::as_str)? != target.gvk().kind() {
            return None;
        }
        // §13.1: the reference carries an `apiVersion`, which is group *and* version. Only the
        // group identifies the kind — a `Deployment` in `apps` and a `Deployment` in somebody
        // else's group are different kinds, and the version is not part of that difference.
        let referenced_group = reference
            .get("apiVersion")
            .and_then(Json::as_str)
            .map_or("", |api_version| {
                api_version.split_once('/').map_or("", |(group, _)| group)
            });
        if referenced_group != target.gvk().group() {
            return None;
        }
        // An HPA is namespaced and scales only within its own namespace, so a match across
        // namespaces is not a match at all.
        if candidate.namespace() != target.namespace() {
            return None;
        }
        let bounds = match (
            candidate.field("/spec/minReplicas").and_then(Json::as_i64),
            candidate.field("/spec/maxReplicas").and_then(Json::as_i64),
        ) {
            (Some(min), Some(max)) => Some(format!("it keeps the count between {min} and {max}")),
            (None, Some(max)) => Some(format!("it keeps the count at or below {max}")),
            _ => None,
        };
        Some(Self {
            name: candidate.name().to_owned(),
            evidence: WriterEvidence::Autoscaler,
            writes: "/spec/replicas".to_owned(),
            detail: bounds,
        })
    }

    /// The writer's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Which of §54.1's sources named it.
    #[must_use]
    pub fn evidence(&self) -> WriterEvidence {
        self.evidence
    }

    /// What it is known to write.
    #[must_use]
    pub fn writes(&self) -> &str {
        &self.writes
    }

    /// What else is known about it, where anything is.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// The writer in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut line = format!(
            "{} writes {} (evidence: {})",
            self.name, self.writes, self.evidence
        );
        if let Some(detail) = &self.detail {
            line.push_str("; ");
            line.push_str(detail);
        }
        line
    }
}

impl fmt::Display for CompetingWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

// --- what a namespace holds (§55.2) ---------------------------------------------------------------

/// One resource type a namespace holds, and how many of it were seen (§55.2's first bullet).
///
/// The count carries whether it is a total or a floor. A page that ended has counted a namespace's
/// worth of objects; a page that did not has counted the page, and printing that number as a total
/// under-reports the blast radius of the deletion by exactly the amount that matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contained {
    gvr: String,
    count: usize,
    lower_bound: bool,
}

impl Contained {
    /// A type whose objects were all counted.
    #[must_use]
    pub fn counted(gvr: impl Into<String>, count: usize) -> Self {
        Self {
            gvr: gvr.into(),
            count,
            lower_bound: false,
        }
    }

    /// A type whose enumeration stopped before the collection ended (§18.1, §18.4).
    #[must_use]
    pub fn at_least(gvr: impl Into<String>, count: usize) -> Self {
        Self {
            gvr: gvr.into(),
            count,
            lower_bound: true,
        }
    }

    /// Which REST collection was counted (§13.1).
    #[must_use]
    pub fn gvr(&self) -> &str {
        &self.gvr
    }

    /// How many were seen.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Whether the number is a floor rather than a total.
    #[must_use]
    pub fn is_lower_bound(&self) -> bool {
        self.lower_bound
    }

    /// The count in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.lower_bound {
            format!("{}: at least {}", self.gvr, self.count)
        } else {
            format!("{}: {}", self.gvr, self.count)
        }
    }
}

impl fmt::Display for Contained {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// What a namespace was found to hold, and what the finding did not cover (§55.2, §55.4, §45.4).
///
/// The coverage travels with the counts rather than beside them, because §55.4 and §45.4 both say
/// the same thing in different words: what could not be listed is reported as *not listed*. A list
/// of counts with no coverage is a list that reads as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contents {
    counted: Vec<Contained>,
    coverage: Coverage,
}

impl Contents {
    /// The types that were counted, and how many of each.
    #[must_use]
    pub fn counted(&self) -> &[Contained] {
        &self.counted
    }

    /// What the enumeration covered and what it did not (§21.4).
    #[must_use]
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// How many objects of a type were seen, where it was counted at all.
    #[must_use]
    pub fn of(&self, gvr: &str) -> Option<&Contained> {
        self.counted.iter().find(|entry| entry.gvr == gvr)
    }

    /// The contents in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        let counts = if self.counted.is_empty() {
            "nothing was counted".to_owned()
        } else {
            self.counted
                .iter()
                .map(Contained::describe)
                .collect::<Vec<String>>()
                .join(", ")
        };
        format!("{counts} ({})", self.coverage.describe())
    }
}

/// Whether the caller may do this, as far as anybody asked (§21.2, §46.2).
///
/// [`Self::NotChecked`] is the default and is not a permission. A boolean here would default to
/// one of the two answers, and whichever it defaulted to would be claimed by every plan built
/// before the preflight was written.
///
/// Four members for §21.6's three words, because "nobody asked" and "the answer was not one" are
/// different facts about a cluster and the same thing to a user: both are `unknown / unchecked`,
/// and neither is a denial. §21.4 calls both of them `not queried`, and the distinction between
/// an unserved review API, a failed review request and an authorizer with no opinion is exactly
/// what the reason string carries.
///
/// **Nothing here is authority.** §21.1 leaves the Kubernetes authorizer as the only authorizer,
/// so [`Self::Allowed`] is a fact about a moment that has already passed and [`Self::Denied`] is
/// what one API server said when asked, not a decision this provider made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preflight {
    /// Nobody asked the API server (§21.1: it remains the authority).
    NotChecked,
    /// A check was attempted and produced no answer, for this reason (§21.4 `not queried`).
    ///
    /// An unserved `authorization.k8s.io`, a review request the server refused, or an authorizer
    /// that neither allowed nor denied. None of them is a denial and none of them is a grant.
    NotAnswered(String),
    /// A `SelfSubjectAccessReview` said yes.
    Allowed,
    /// A `SelfSubjectAccessReview` said no, for this reason.
    Denied(String),
}

impl Preflight {
    /// A denial with what the server said.
    #[must_use]
    pub fn denied(reason: impl Into<String>) -> Self {
        Self::Denied(reason.into())
    }

    /// A check that was attempted and produced no answer, with what stopped it.
    #[must_use]
    pub fn not_answered(reason: impl Into<String>) -> Self {
        Self::NotAnswered(reason.into())
    }

    /// Whether a preflight actually granted this — true for [`Self::Allowed`] alone.
    #[must_use]
    pub fn permits(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// What a `SelfSubjectAccessReview` the API server answered with amounts to (§21.2).
    ///
    /// The upstream status has two booleans rather than one, and the difference is the whole
    /// reason this function is not `allowed.into()`. `allowed: true` is a grant. `denied: true`
    /// is a refusal. **`allowed: false` with `denied: false` is neither**: it means no authorizer
    /// expressed an opinion, which upstream is explicit about, and reading it as a refusal would
    /// be this provider deciding an authorization question the API server declined to decide
    /// (§21.1). It usually *would* be refused, because the aggregate authorizer defaults to deny
    /// — but "usually" is not a word a plan may put in the place of an answer.
    ///
    /// `evaluationError` travels the same way. An authorizer that could not finish evaluating has
    /// not denied anything, and §21.3's warning that a rules summary is not a complete oracle is
    /// the same caution one step earlier.
    #[must_use]
    pub fn from_review(review: &Json) -> Self {
        let Some(status) = review.get("status") else {
            return Self::not_answered(
                "the API server's SelfSubjectAccessReview came back without a status",
            );
        };
        let flag = |name: &str| status.get(name).and_then(Json::as_bool).unwrap_or(false);
        let text = |name: &str| {
            status
                .get(name)
                .and_then(Json::as_str)
                .filter(|s| !s.is_empty())
        };
        if flag("allowed") {
            return Self::Allowed;
        }
        if flag("denied") {
            return Self::Denied(
                text("reason")
                    .unwrap_or("the API server denied this and gave no reason")
                    .to_owned(),
            );
        }
        let mut said = Vec::new();
        if let Some(error) = text("evaluationError") {
            said.push(format!(
                "the authorizer could not finish evaluating: {error}"
            ));
        }
        if let Some(reason) = text("reason") {
            said.push(reason.to_owned());
        }
        if said.is_empty() {
            said.push(
                "no authorizer expressed an opinion: the review neither allowed nor denied this"
                    .to_owned(),
            );
        }
        Self::NotAnswered(said.join("; "))
    }
}

impl fmt::Display for Preflight {
    /// §21.6's three words, and never a fourth.
    ///
    /// A reason follows the words rather than replacing them, because §46.2 asks a plan for the
    /// preflight *result* and a user reading a denial needs to know what to ask to be granted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotChecked => f.write_str("unknown / unchecked"),
            Self::NotAnswered(reason) => write!(f, "unknown / unchecked: {reason}"),
            Self::Allowed => f.write_str("allowed by preflight check"),
            Self::Denied(reason) => write!(f, "denied by preflight check: {reason}"),
        }
    }
}

/// The `SelfSubjectAccessReview` that asks whether this identity may make this change (§21.2).
///
/// Three arguments and no constants: the target's GVR comes from discovery because §13.1 makes the
/// REST collection a different string from the kind, and the review's own GVK comes from discovery
/// too because §5.3 forbids assuming which version of `authorization.k8s.io` a cluster serves.
///
/// The verb is the API server's, not the plan's: a server-side apply is a `PATCH`, so a review
/// that asked about `apply` would be asking about a verb no Kubernetes authorizer has an opinion
/// on, and would come back unanswered while looking like a check.
#[must_use]
pub fn access_review(plan: &Plan, target: &Gvr, review: &Gvk) -> Json {
    let mut attributes = JsonMap::new();
    attributes.insert(
        "verb".to_owned(),
        Json::String(plan.action().api_verb().to_owned()),
    );
    attributes.insert("group".to_owned(), Json::String(target.group().to_owned()));
    attributes.insert(
        "version".to_owned(),
        Json::String(target.version().to_owned()),
    );
    attributes.insert(
        "resource".to_owned(),
        Json::String(target.resource().to_owned()),
    );
    attributes.insert(
        "name".to_owned(),
        Json::String(plan.target().name().to_owned()),
    );
    // §9.2: a cluster-scoped object has no namespace, and inventing one would ask about an
    // object that does not exist. An absent namespace here means cluster scope to the authorizer.
    if let Some(namespace) = plan.target().namespace() {
        attributes.insert("namespace".to_owned(), Json::String(namespace.to_owned()));
    }
    let mut spec = JsonMap::new();
    spec.insert("resourceAttributes".to_owned(), Json::Object(attributes));

    let mut document = JsonMap::new();
    document.insert(
        "apiVersion".to_owned(),
        Json::String(if review.group().is_empty() {
            review.version().to_owned()
        } else {
            format!("{}/{}", review.group(), review.version())
        }),
    );
    document.insert("kind".to_owned(), Json::String(review.kind().to_owned()));
    document.insert("spec".to_owned(), Json::Object(spec));
    Json::Object(document)
}

/// How the outcome of this action could be verified afterwards (§46.3).
///
/// Chosen from the action's semantics, because §46.3 requires exactly that. The rule is part of
/// the plan rather than of the verification code so that "how would we know this worked" is
/// answered before the change, and so that [`Self::NoneKnown`] — this provider has no rule — is a
/// visible answer rather than a silently optimistic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRule {
    /// The requested fields are read back on the object. Nothing about a controller is claimed.
    FieldObserved,
    /// A controller observed the generation and converged, by a rule `condition.rs` names (§37.5).
    ControllerConvergence,
    /// §46.3's second worked example: the pod template changed, a new ReplicaSet is observed, the
    /// rollout progresses, new pods become ready and the old ReplicaSet scales down.
    RolloutObserved,
    /// §46.3's third worked example: `spec.unschedulable` holds the requested value. Nothing is
    /// claimed about the pods already on the node — cordoning is not draining.
    SchedulabilityObserved,
    /// The requested labels or annotations are read back. Nothing is claimed about the selectors,
    /// controllers or admission policies that read them (§14.5, §26.1).
    MetadataObserved,
    /// The object is gone, or the name now holds a different lifetime (§45.1, §16.3).
    Absence,
    /// This provider has no rule for what success would look like here.
    NoneKnown,
}

impl VerificationRule {
    /// The rule in the words it is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FieldObserved => "the requested fields are observed on the object",
            Self::ControllerConvergence => "a controller observes the generation and converges",
            Self::RolloutObserved => {
                "the pod template changed, a new ReplicaSet is observed, its new pods become ready \
                 and the old one scales down"
            }
            Self::SchedulabilityObserved => {
                "the node's `spec.unschedulable` holds the requested value; the pods already \
                 running on it are neither stopped nor moved"
            }
            Self::MetadataObserved => {
                "the requested labels or annotations are read back on the object; what selects on \
                 them is not something this provider verifies"
            }
            Self::Absence => "the object's lifetime has ended",
            Self::NoneKnown => "the outcome of this action cannot be verified by this provider",
        }
    }

    /// The furthest rung of §20.4's ladder a confirmed verification of this rule reaches.
    ///
    /// Never [`Stage::ExternallyHealthy`]: no API read establishes that, and a rule that claimed
    /// it would turn a green status into a promise about traffic nobody measured (§37.5, Gate G).
    #[must_use]
    pub fn established_stage(self) -> Option<Stage> {
        match self {
            Self::FieldObserved | Self::SchedulabilityObserved | Self::MetadataObserved => {
                Some(Stage::SpecObserved)
            }
            Self::ControllerConvergence | Self::RolloutObserved => Some(Stage::StatusConverged),
            Self::Absence | Self::NoneKnown => None,
        }
    }
}

impl fmt::Display for VerificationRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Something true of this plan that a list of field changes does not show.
///
/// A vocabulary rather than prose, so that a renderer can decide what to emphasise and a test can
/// assert that a caveat is present. Every one of these is a sentence somebody would otherwise have
/// to remember to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caveat {
    /// Deletion completes only when these finalizers are removed (§45.3).
    FinalizersMustBeRemoved(Vec<String>),
    /// The target was not observed, so its finalizers are unknown (§45.3).
    FinalizerStateUnknown,
    /// The target already carries a `deletionTimestamp` (§45.1).
    TargetAlreadyTerminating,
    /// The dependent preview did not see everything (§45.4).
    DependentPreviewIncomplete,
    /// Ownership edges are impact evidence and not an order of removal (§24.4).
    DependentOrderNotGuaranteed,
    /// Storage and cloud resources may be reclaimed, and this provider promises nothing (§45.5).
    StorageReclaimNotPromised,
    /// No server dry run has been made, so admission and defaulting are unpreviewed (§44.5).
    AdmissionEffectsNotPreviewed,
    /// No permission preflight granted this (§46.2, §21.1).
    PermissionNotVerified,
    /// A preflight granted this, and a grant is not a guarantee (§21.2).
    PermissionCheckIsAdvisory,
    /// A preflight said this identity may not do this, for this reason (§21.2, §21.6).
    PermissionDeniedByPreflight(String),
    /// Nothing guards the target against a concurrent write or a recreation (§56).
    NoPreconditionGuardsTheTarget(String),
    /// The outcome of this action cannot be verified by this provider (§46.3).
    NoVerificationRule,
    /// Other field managers already own fields of this object (§44.3, §54.1).
    OtherFieldManagers(Vec<String>),
    /// This is §43.4's raw escape hatch rather than one of §43.3's curated transitions.
    LowLevelChange,
    /// A HorizontalPodAutoscaler of this name governs the replica count being changed (§54.2).
    AutoscalerMayReconcileReplicas(String),
    /// Not every source of §54.1 was consulted, so the writers named are not all of them.
    CompetingWriterEvidenceIncomplete(String),
    /// Nobody enumerated what this Namespace holds, so the deletion's reach is unknown (§55.2).
    ContainedInventoryNotEnumerated,
    /// The enumeration of what this Namespace holds did not cover everything (§55.2, §55.4).
    ContainedInventoryIncomplete,
    /// This Namespace holds PersistentVolumeClaims, whose storage reclaim is a controller's
    /// decision this provider does not make and cannot undo (§55.2, §45.5).
    NamespaceHoldsPersistentVolumeClaims(usize),
    /// Load balancers, DNS records and volumes provisioned for this namespace may survive it
    /// (§55.2's last bullet, §46.5).
    ExternalEffectsMayOutliveTheNamespace,
}

impl fmt::Display for Caveat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinalizersMustBeRemoved(names) => write!(
                f,
                "deletion completes only when these finalizers are removed: {}",
                names.join(", ")
            ),
            Self::FinalizerStateUnknown => f.write_str(
                "the target was not read, so whether finalizers delay its deletion is unknown",
            ),
            Self::TargetAlreadyTerminating => {
                f.write_str("the target is already terminating; this action does not hasten it")
            }
            Self::DependentPreviewIncomplete => f.write_str(
                "the dependent preview is incomplete: what is affected may be more than this",
            ),
            Self::DependentOrderNotGuaranteed => f.write_str(
                "ownership edges are impact evidence, not a guarantee of what is removed or in \
                 which order",
            ),
            Self::StorageReclaimNotPromised => f.write_str(
                "storage reclaim and cloud resources are outside this provider's evidence; no \
                 rollback is promised",
            ),
            Self::AdmissionEffectsNotPreviewed => f.write_str(
                "no server dry run has been made, so defaulting and admission effects are unknown",
            ),
            Self::PermissionNotVerified => {
                f.write_str("no permission preflight granted this; the API server decides")
            }
            Self::PermissionCheckIsAdvisory => f.write_str(
                "a permission check said this is allowed, which is advisory: authorization can \
                 change between the check and the request, and the API server decides on the \
                 request itself",
            ),
            Self::PermissionDeniedByPreflight(reason) => write!(
                f,
                "a permission check said this identity may not make this change: {reason}. The \
                 API server remains the authority and would decide again on the request"
            ),
            Self::NoPreconditionGuardsTheTarget(reason) => write!(
                f,
                "no precondition guards the target, so a concurrent write or a recreated object \
                 would be hit: {reason}"
            ),
            Self::NoVerificationRule => f.write_str(
                "the outcome of this action cannot be verified by this provider; acceptance will \
                 be all that is known",
            ),
            Self::OtherFieldManagers(managers) => write!(
                f,
                "other field managers already own fields of this object: {}",
                managers.join(", ")
            ),
            Self::AutoscalerMayReconcileReplicas(name) => write!(
                f,
                "a HorizontalPodAutoscaler named `{name}` targets this workload and writes \
                 `/spec/replicas` itself. A direct replica change may be reconciled back within \
                 the autoscaler's next interval, and the API server accepting `spec.replicas` is \
                 not evidence of a durable effect (§54.2)"
            ),
            Self::CompetingWriterEvidenceIncomplete(reason) => write!(
                f,
                "the search for competing desired-state writers was incomplete, so the writers \
                 named here are not necessarily all of them: {reason} (§54.1, §21.4)"
            ),
            Self::ContainedInventoryNotEnumerated => f.write_str(
                "nothing enumerated what this Namespace holds, so what the deletion would remove \
                 with it is unknown rather than nothing (§55.2, §4 invariant 13)",
            ),
            Self::ContainedInventoryIncomplete => f.write_str(
                "the enumeration of what this Namespace holds did not cover every type: what was \
                 not listed is not listed, and never a count of zero (§55.2, §55.4, §45.4)",
            ),
            Self::NamespaceHoldsPersistentVolumeClaims(count) => write!(
                f,
                "this Namespace holds {count} PersistentVolumeClaim(s); whether their volumes are \
                 reclaimed or retained is a StorageClass and controller decision outside this \
                 provider's evidence, and no rollback is promised (§55.2, §45.5)"
            ),
            Self::ExternalEffectsMayOutliveTheNamespace => f.write_str(
                "external side effects may outlive the namespace: cloud load balancers, DNS \
                 records and volumes provisioned for objects in it are not removed by the API \
                 server and this provider does not observe them (§55.2, §46.5)",
            ),
            Self::LowLevelChange => f.write_str(
                "this is the low-level raw field change of §43.4: the fields are named by JSON \
                 pointer against a schema the caller is expected to know, and no curated action \
                 vouches for what they mean together. The curated transitions of §43.3 — scale, \
                 set-image, restart-rollout, cordon, uncordon, label, annotate — each carry their \
                 own effects and their own verification rule",
            ),
        }
    }
}

// --- staleness -----------------------------------------------------------------------------------

/// Whether a plan still describes the object it was built from (§56.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staleness {
    /// The object is where the plan left it.
    Fresh,
    /// The object has moved on; the plan was built on an assumption that no longer holds.
    Changed {
        /// The `resourceVersion` the plan was built at.
        planned: String,
        /// The `resourceVersion` observed now.
        observed: String,
    },
    /// The name now holds a different lifetime (§16.3): the planned object is gone.
    TargetReplaced {
        /// The UID the plan was built for.
        planned: String,
        /// The UID observed now.
        observed: String,
    },
    /// One side has no continuity token, so staleness cannot be decided.
    Unverifiable,
}

impl Staleness {
    /// Whether the plan may be applied as it stands.
    ///
    /// True for [`Self::Fresh`] alone. [`Self::Unverifiable`] is deliberately false: a comparison
    /// that could not be made is not a comparison that passed.
    #[must_use]
    pub fn permits_apply(&self) -> bool {
        matches!(self, Self::Fresh)
    }
}

impl fmt::Display for Staleness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh => f.write_str("the target is as the plan found it"),
            Self::Changed { planned, observed } => write!(
                f,
                "the target has changed since the plan was built (resourceVersion {planned} -> \
                 {observed}); re-plan rather than apply"
            ),
            Self::TargetReplaced { planned, observed } => write!(
                f,
                "the name now holds a different object lifetime (uid {planned} -> {observed}); \
                 the planned target is gone"
            ),
            Self::Unverifiable => {
                f.write_str("staleness cannot be decided: no continuity token to compare")
            }
        }
    }
}

// --- refusals ---------------------------------------------------------------------------------------

/// Why a plan was not built.
///
/// A refusal rather than a plan with a warning on it. §56 is written as SHOULD, and this provider
/// reads it as: the guarded form is what [`Plan::of`] and [`Plan::targeting`] build, and the way
/// past it is [`Plan::unguarded`], which names its reason and marks the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanRefusal {
    /// The target cannot supply a precondition the action needs (§56).
    MissingPrecondition(MissingPrecondition),
    /// The change would change nothing.
    EmptyChange,
}

impl fmt::Display for PlanRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrecondition(missing) => write!(f, "{missing}"),
            Self::EmptyChange => f.write_str(
                "the change touches no field: applying it would take field ownership and alter \
                 nothing (§44.2)",
            ),
        }
    }
}

impl std::error::Error for PlanRefusal {}

// --- the plan ------------------------------------------------------------------------------------

/// What the target was observed to be, for the caveats that depend on it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Observed {
    was_read: bool,
    terminating: bool,
    finalizers: Vec<String>,
    field_managers: Vec<String>,
    controllers: Vec<OwnerReference>,
}

/// A change described before it is made (§46.2).
///
/// Everything §46.2 asks a plan to carry, and one thing it does not: the plan states what could be
/// verified afterwards and what could not. It is a value with no connection behind it, so a plan
/// can be built, shown, kept, and compared against the cluster later without anything having
/// happened.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    target: Target,
    action: Action,
    preconditions: Preconditions,
    unguarded_because: Option<String>,
    observed: Observed,
    effects: Vec<Effect>,
    dependents: Vec<Dependent>,
    dependent_coverage: Coverage,
    preflight: Preflight,
    competing_writers: Vec<CompetingWriter>,
    writer_coverage: Coverage,
    contents: Option<Contents>,
    verification: VerificationRule,
    caveats: Vec<Caveat>,
}

impl Plan {
    /// A plan for an object that was read: the guarded form, and the short one (§56).
    ///
    /// The preconditions, the finalizers, the field managers and the terminating state all come
    /// from the observation, so the plan that knows the most is also the one that takes the fewest
    /// arguments.
    ///
    /// # Errors
    ///
    /// [`PlanRefusal::MissingPrecondition`] where the object carries no `resourceVersion`, or no
    /// UID for a destructive action (§16.5 allows both to be absent; §56 does not allow a mutation
    /// to proceed without them), and [`PlanRefusal::EmptyChange`] for an apply that touches no
    /// field.
    pub fn of(object: &Object, action: Action) -> Result<Self, PlanRefusal> {
        let observed = Observed {
            was_read: true,
            terminating: object.is_terminating(),
            finalizers: object.finalizers().to_vec(),
            field_managers: object.field_managers().to_vec(),
            controllers: object
                .owner_references()
                .iter()
                .filter(|reference| reference.is_controller())
                .cloned()
                .collect(),
        };
        Self::build(Target::observed(object), action, observed, None)
    }

    /// A plan for a target assembled rather than read.
    ///
    /// # Errors
    ///
    /// As [`Self::of`]. A target built from a typed name has neither precondition, so this refuses
    /// unless the caller supplied them.
    pub fn targeting(target: Target, action: Action) -> Result<Self, PlanRefusal> {
        Self::build(target, action, Observed::default(), None)
    }

    /// A plan that no precondition guards, and that says so for the rest of its life (§43.4).
    ///
    /// The expert path §43.4 permits, with the two properties that section requires: it is
    /// explicitly low-level, and it takes the same route through planning as everything else. The
    /// reason is not decoration — it is what a reviewer reads when asking why this one mutation
    /// was allowed to be aimed by name.
    #[must_use]
    pub fn unguarded(target: Target, action: Action, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let mut plan = Self::assemble(target, action, Observed::default(), Some(reason));
        plan.rebuild_caveats();
        plan
    }

    fn build(
        target: Target,
        action: Action,
        observed: Observed,
        unguarded_because: Option<String>,
    ) -> Result<Self, PlanRefusal> {
        if let Action::Apply(fields) = &action
            && fields.is_empty()
        {
            return Err(PlanRefusal::EmptyChange);
        }
        let preconditions = Preconditions::of(&target);
        if !preconditions.guards_lost_update() && !action.is_destructive() {
            return Err(PlanRefusal::MissingPrecondition(
                MissingPrecondition::ResourceVersion,
            ));
        }
        if !preconditions.guards_recreation() && action.is_destructive() {
            return Err(PlanRefusal::MissingPrecondition(MissingPrecondition::Uid));
        }
        let mut plan = Self::assemble(target, action, observed, unguarded_because);
        plan.rebuild_caveats();
        Ok(plan)
    }

    fn assemble(
        target: Target,
        action: Action,
        observed: Observed,
        unguarded_because: Option<String>,
    ) -> Self {
        let preconditions = Preconditions::of(&target);
        let effects = effects_of(&target, &action);
        let verification = rule_for(&target, &action);
        let mut dependent_coverage = Coverage::complete(target.scope());
        // Nobody has looked for dependents yet, and §4 invariant 13's whole point is that "nobody
        // asked" is a different answer from "there are none".
        dependent_coverage.record(Gap::new(target.scope(), Outcome::NotQueried));
        // §54.1's first source is already in hand: `managedFields` came with the object, so the
        // managers that own fields of it are competing writers before anybody sends a request.
        // The other four sources need a query nobody has made, so the coverage says so.
        let mut competing_writers: Vec<CompetingWriter> = observed
            .field_managers
            .iter()
            .map(CompetingWriter::field_manager)
            .collect();
        competing_writers.extend(observed.controllers.iter().map(CompetingWriter::controller));
        let mut writer_coverage = Coverage::complete(target.scope());
        writer_coverage.record(Gap::new(target.scope(), Outcome::NotQueried));
        Self {
            target,
            action,
            preconditions,
            unguarded_because,
            observed,
            effects,
            dependents: Vec::new(),
            dependent_coverage,
            preflight: Preflight::NotChecked,
            competing_writers,
            writer_coverage,
            contents: None,
            verification,
            caveats: Vec::new(),
        }
    }

    /// The same plan with the dependents a listing found, and what that listing covered (§45.4).
    ///
    /// The objects are filtered through [`Dependent::of`], so an object that does not name this
    /// target as an owner does not enter the preview however it was found. The coverage is kept
    /// beside the list because the two answer different questions: which dependents were seen, and
    /// whether anything could have been missed.
    #[must_use]
    pub fn with_dependents(mut self, candidates: Vec<Object>, coverage: Coverage) -> Self {
        self.dependents = candidates
            .iter()
            .filter_map(|object| Dependent::of(object, &self.target))
            .collect();
        self.dependent_coverage = coverage;
        self.rebuild_caveats();
        self
    }

    /// The same plan with the result of a permission preflight (§46.2).
    #[must_use]
    pub fn with_preflight(mut self, preflight: Preflight) -> Self {
        self.preflight = preflight;
        self.rebuild_caveats();
        self
    }

    /// The same plan with the competing desired-state writers a search found (§54.1, §54.2).
    ///
    /// The candidates are filtered through [`CompetingWriter::autoscaler`], so an object that does
    /// not target this one does not become a warning however it was found. The coverage is kept
    /// beside the list for the same reason the dependent preview keeps one: an empty list from a
    /// group that would not answer is not an absence of autoscalers (§21.4).
    ///
    /// The field managers the object already carried stay in the list — this appends rather than
    /// replaces, because §54.1 asks for the sources together rather than one at a time.
    #[must_use]
    pub fn with_competing_writers(mut self, candidates: Vec<Object>, coverage: Coverage) -> Self {
        self.competing_writers.extend(
            candidates
                .iter()
                .filter_map(|candidate| CompetingWriter::autoscaler(candidate, &self.target)),
        );
        self.writer_coverage = coverage;
        self.rebuild_caveats();
        self
    }

    /// The same plan with what an enumeration found the target Namespace to hold (§55.2).
    #[must_use]
    pub fn with_contents(mut self, counted: Vec<Contained>, coverage: Coverage) -> Self {
        self.contents = Some(Contents { counted, coverage });
        self.rebuild_caveats();
        self
    }

    /// The same plan, stating that this provider cannot verify the outcome (§46.3).
    ///
    /// Only ever weakens the claim. There is no method that strengthens a verification rule,
    /// because a rule chosen to make a verification pass is not a verification.
    #[must_use]
    pub fn without_verification_rule(mut self) -> Self {
        self.verification = VerificationRule::NoneKnown;
        self.rebuild_caveats();
        self
    }

    /// What the change is aimed at.
    #[must_use]
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// What the change does.
    #[must_use]
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// The fields the change touches (§46.2).
    #[must_use]
    pub fn field_changes(&self) -> &[FieldChange] {
        self.action.field_changes()
    }

    /// The propagation policy, for a deletion (§45.2).
    #[must_use]
    pub fn propagation(&self) -> Option<Propagation> {
        self.action.propagation()
    }

    /// What the mutation will assert about its target (§56).
    #[must_use]
    pub fn preconditions(&self) -> &Preconditions {
        &self.preconditions
    }

    /// Whether a precondition stands between this change and the wrong object (§56).
    #[must_use]
    pub fn is_precondition_guarded(&self) -> bool {
        self.unguarded_because.is_none()
    }

    /// What is expected to happen beyond the fields (§46.2).
    #[must_use]
    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    /// The weakest reversibility among the effects (§46.5).
    ///
    /// The weakest rather than the commonest: a change with one irreversible effect is an
    /// irreversible change, whatever the rest of the list says.
    #[must_use]
    pub fn reversibility(&self) -> Reversibility {
        self.effects
            .iter()
            .map(Effect::reversibility)
            .max_by_key(|reversibility| reversibility.severity())
            .unwrap_or(Reversibility::Unknown)
    }

    /// What reapplying the previous values would and would not restore (§46.5).
    #[must_use]
    pub fn recovery(&self) -> Recovery {
        let mut restores = Vec::new();
        let mut does_not_restore = Vec::new();
        for effect in &self.effects {
            if effect.reversibility() == Reversibility::ConfigurationReapplicable {
                restores.push(effect.kind());
            } else {
                does_not_restore.push(effect.kind());
            }
        }
        Recovery {
            restores,
            does_not_restore,
        }
    }

    /// The dependents the preview found, on owner-reference evidence (§24.1, §45.4).
    #[must_use]
    pub fn dependents(&self) -> &[Dependent] {
        &self.dependents
    }

    /// What the dependent preview covered, and what it could not (§45.4, §21.4).
    #[must_use]
    pub fn dependent_coverage(&self) -> &Coverage {
        &self.dependent_coverage
    }

    /// What else writes this object's desired state, as far as anybody looked (§54.1).
    #[must_use]
    pub fn competing_writers(&self) -> &[CompetingWriter] {
        &self.competing_writers
    }

    /// What the search for competing writers covered, and what it did not (§54.1, §21.4).
    #[must_use]
    pub fn competing_writer_coverage(&self) -> &Coverage {
        &self.writer_coverage
    }

    /// What the target Namespace was found to hold, where anybody enumerated it (§55.2).
    #[must_use]
    pub fn contents(&self) -> Option<&Contents> {
        self.contents.as_ref()
    }

    /// Whether anybody asked the API server if this is allowed (§46.2).
    #[must_use]
    pub fn preflight(&self) -> &Preflight {
        &self.preflight
    }

    /// How the outcome could be verified afterwards (§46.3).
    #[must_use]
    pub fn verification_rule(&self) -> VerificationRule {
        self.verification
    }

    /// Everything true of this plan that the field list does not show.
    #[must_use]
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    /// Whether the plan still describes the object it was built from (§56.2).
    ///
    /// The UID is compared before the `resourceVersion`, because a different UID is not a stale
    /// plan: it is a plan whose target no longer exists (§16.3). Reporting that as staleness would
    /// invite the fix staleness gets — re-read and apply — against an object nobody chose.
    #[must_use]
    pub fn staleness(&self, observed: &Object) -> Staleness {
        match (self.preconditions.uid(), observed.uid()) {
            (Some(planned), Some(now)) if planned != now => {
                return Staleness::TargetReplaced {
                    planned: planned.to_owned(),
                    observed: now.to_owned(),
                };
            }
            _ => {}
        }
        match (
            self.preconditions.resource_version(),
            observed.resource_version(),
        ) {
            (Some(planned), Some(now)) if planned == now => Staleness::Fresh,
            (Some(planned), Some(now)) => Staleness::Changed {
                planned: planned.to_owned(),
                observed: now.to_owned(),
            },
            _ => Staleness::Unverifiable,
        }
    }

    /// The whole plan, as it would be shown to somebody deciding whether to say yes (§46.2).
    ///
    /// The last line is the one the rest of the module exists for: a plan is prospective, and none
    /// of it is evidence that anything happened (§4 invariant 18).
    #[must_use]
    pub fn describe(&self) -> String {
        let mut lines = vec![
            format!("prospective change: {} on {}", self.action, self.target),
            format!("preconditions: {}", self.preconditions),
        ];
        for change in self.field_changes() {
            lines.push(format!("  field {}", change.describe()));
        }
        for effect in &self.effects {
            lines.push(format!("  effect {effect}"));
        }
        lines.push(format!("recovery: {}", self.recovery().describe()));
        // Appendix E's `AUTHORIZATION` block, in one line: what the check said, and — through
        // the caveat every state of it produces — that the request is where it is really decided.
        lines.push(format!("authorization: {}", self.preflight));
        lines.push(format!("verification: {}", self.verification));
        if !self.competing_writers.is_empty() {
            lines.push(format!(
                "competing desired-state writers: {} ({})",
                self.competing_writers
                    .iter()
                    .map(CompetingWriter::describe)
                    .collect::<Vec<String>>()
                    .join("; "),
                self.writer_coverage.describe()
            ));
        }
        if let Some(contents) = &self.contents {
            lines.push(format!("the namespace holds: {}", contents.describe()));
        }
        if !self.dependents.is_empty() {
            lines.push(format!(
                "dependents previewed: {} ({})",
                self.dependents.len(),
                self.dependent_coverage.describe()
            ));
        }
        for caveat in &self.caveats {
            lines.push(format!("caveat: {caveat}"));
        }
        lines.push(
            "this is a prospective description and is not evidence: no part of it says that the \
             change was made or that it took effect (§4 invariant 18, §46.1)"
                .to_owned(),
        );
        lines.join("\n")
    }

    /// Whether this change writes the replica count an autoscaler would reconcile (§54.2).
    fn touches_replicas(&self) -> bool {
        self.action
            .field_changes()
            .iter()
            .any(|change| change.path() == "/spec/replicas")
    }

    /// Derives the caveats from the plan's parts.
    ///
    /// Recomputed whenever a part changes rather than appended to, so that a preflight arriving
    /// after the plan was built removes "nobody asked" instead of leaving it beside "allowed".
    fn rebuild_caveats(&mut self) {
        let mut caveats = Vec::new();
        if let Some(reason) = &self.unguarded_because {
            caveats.push(Caveat::NoPreconditionGuardsTheTarget(reason.clone()));
        }
        if self.observed.terminating {
            caveats.push(Caveat::TargetAlreadyTerminating);
        }
        if self.action.is_destructive() {
            if self.observed.was_read {
                if !self.observed.finalizers.is_empty() {
                    caveats.push(Caveat::FinalizersMustBeRemoved(
                        self.observed.finalizers.clone(),
                    ));
                }
            } else {
                caveats.push(Caveat::FinalizerStateUnknown);
            }
            if self
                .action
                .propagation()
                .is_some_and(Propagation::removes_dependents)
            {
                caveats.push(Caveat::DependentOrderNotGuaranteed);
            }
            if !self.dependent_coverage.is_complete() {
                caveats.push(Caveat::DependentPreviewIncomplete);
            }
            if storage_bearing(self.target.gvk()) {
                caveats.push(Caveat::StorageReclaimNotPromised);
            }
            // §55.2: deleting a Namespace "MUST receive enhanced prospective analysis". The
            // analysis is a *read* somebody has to make, so what the plan can guarantee on its
            // own is that the reader is told which of the three states this plan is in: nobody
            // enumerated, the enumeration was partial, or it was complete.
            if is_namespace(self.target.gvk()) {
                caveats.push(Caveat::ExternalEffectsMayOutliveTheNamespace);
                match &self.contents {
                    None => caveats.push(Caveat::ContainedInventoryNotEnumerated),
                    Some(contents) => {
                        if !contents.coverage.is_complete() {
                            caveats.push(Caveat::ContainedInventoryIncomplete);
                        }
                        if let Some(claims) = contents
                            .counted
                            .iter()
                            .find(|entry| entry.gvr.ends_with("persistentvolumeclaims"))
                            .filter(|entry| entry.count > 0)
                        {
                            caveats
                                .push(Caveat::NamespaceHoldsPersistentVolumeClaims(claims.count));
                        }
                    }
                }
            }
        } else {
            if self.action.is_low_level() {
                caveats.push(Caveat::LowLevelChange);
            }
            caveats.push(Caveat::AdmissionEffectsNotPreviewed);
            if !self.observed.field_managers.is_empty() {
                caveats.push(Caveat::OtherFieldManagers(
                    self.observed.field_managers.clone(),
                ));
            }
        }
        // §21.2: every one of the four states says something a reader needs, and "allowed" is
        // the one most easily mistaken for a guarantee, so it is the one that carries a caveat
        // rather than the one that loses it.
        match &self.preflight {
            Preflight::Allowed => caveats.push(Caveat::PermissionCheckIsAdvisory),
            Preflight::Denied(reason) => {
                caveats.push(Caveat::PermissionDeniedByPreflight(reason.clone()));
            }
            Preflight::NotChecked | Preflight::NotAnswered(_) => {
                caveats.push(Caveat::PermissionNotVerified);
            }
        }
        // §54.2: the warning belongs to the change that would be undone, so it is derived from
        // the field the change touches rather than pushed by whoever ran the search.
        if self.touches_replicas() {
            for writer in &self.competing_writers {
                if writer.evidence == WriterEvidence::Autoscaler {
                    caveats.push(Caveat::AutoscalerMayReconcileReplicas(writer.name.clone()));
                }
            }
        }
        if !self.action.is_destructive() && !self.writer_coverage.is_complete() {
            caveats.push(Caveat::CompetingWriterEvidenceIncomplete(
                self.writer_coverage.describe(),
            ));
        }
        if self.verification == VerificationRule::NoneKnown {
            caveats.push(Caveat::NoVerificationRule);
        }
        self.caveats = caveats;
    }
}

/// The effects a change of this shape has, before anybody has made it.
fn effects_of(target: &Target, action: &Action) -> Vec<Effect> {
    let mut effects = Vec::new();
    let mut push = |kind: EffectKind, reversibility: Reversibility| {
        if !effects.iter().any(|effect: &Effect| effect.kind == kind) {
            effects.push(Effect {
                kind,
                reversibility,
            });
        }
    };
    match action {
        Action::Curated(_, fields) | Action::Apply(fields) => {
            push(
                EffectKind::ConfigurationChanged,
                Reversibility::ConfigurationReapplicable,
            );
            // §43.3: a curated transition has effects the field it writes does not spell out. A
            // cordon is the clearest of them — `spec.unschedulable` reads as an ordinary boolean,
            // and what it does is take a node out of scheduling without moving anything on it.
            match action.curation() {
                Some(Curated::Cordon) => {
                    push(
                        EffectKind::SchedulingStopped,
                        Reversibility::ConfigurationReapplicable,
                    );
                }
                Some(Curated::Uncordon) => {
                    push(
                        EffectKind::SchedulingRestored,
                        Reversibility::ConfigurationReapplicable,
                    );
                }
                Some(Curated::RestartRollout) => {
                    push(EffectKind::PodsReplaced, Reversibility::Irreversible);
                    push(EffectKind::TrafficDisrupted, Reversibility::Irreversible);
                }
                _ => {}
            }
            for change in fields {
                if change.path().starts_with("/spec/template") {
                    // A pod template change is a rollout: the pods that served the old template
                    // are replaced, and whatever was only inside them goes with them (§25.1).
                    push(EffectKind::PodsReplaced, Reversibility::Irreversible);
                    push(EffectKind::TrafficDisrupted, Reversibility::Irreversible);
                }
                if change.path() == "/spec/replicas" && is_scale_down(change) {
                    push(EffectKind::PodsStopped, Reversibility::Irreversible);
                    push(EffectKind::TrafficDisrupted, Reversibility::Irreversible);
                }
            }
        }
        Action::Delete(policy) => {
            // Not reversible by creating an object of the same name: that object has a new UID and
            // no history, which §16.3 makes a different lifetime rather than the same one back.
            push(EffectKind::ObjectRemoved, Reversibility::Irreversible);
            if runs_workload(target.gvk()) {
                push(EffectKind::PodsStopped, Reversibility::Irreversible);
                push(EffectKind::TrafficDisrupted, Reversibility::Irreversible);
            }
            if policy.removes_dependents() {
                push(EffectKind::DependentsRemoved, Reversibility::Irreversible);
            } else {
                push(EffectKind::DependentsOrphaned, Reversibility::Unknown);
            }
            if storage_bearing(target.gvk()) {
                push(
                    EffectKind::PersistentDataAtRisk,
                    Reversibility::Irreversible,
                );
            }
            // §45.5 and §46.5: load balancers, volumes and DNS records live outside the API
            // server, and this provider watches none of them.
            push(EffectKind::ExternalSideEffects, Reversibility::Unknown);
        }
    }
    effects
}

/// Whether a replica change lowers the count, where both counts are known.
fn is_scale_down(change: &FieldChange) -> bool {
    let (Some(from), Some(to)) = (
        change.from().and_then(Json::as_i64),
        change.to().and_then(Json::as_i64),
    ) else {
        return false;
    };
    to < from
}

/// The verification rule this action's semantics allow (§46.3).
fn rule_for(target: &Target, action: &Action) -> VerificationRule {
    match action {
        Action::Delete(_) => VerificationRule::Absence,
        // §46.3 names three worked examples and each one is a different question. A curated
        // transition answers with its own; reaching for the neighbouring rule is how "the field
        // is set" comes to be reported as "the rollout finished" (Gate G).
        Action::Curated(Curated::Cordon | Curated::Uncordon, _) => {
            VerificationRule::SchedulabilityObserved
        }
        Action::Curated(Curated::Label | Curated::Annotate, _) => {
            VerificationRule::MetadataObserved
        }
        Action::Curated(Curated::SetImage | Curated::RestartRollout, _)
            if controller_backed(target.gvk()) =>
        {
            VerificationRule::RolloutObserved
        }
        Action::Curated(Curated::Scale, _) if controller_backed(target.gvk()) => {
            VerificationRule::ControllerConvergence
        }
        Action::Apply(_) if controller_backed(target.gvk()) => {
            VerificationRule::ControllerConvergence
        }
        // Honest rather than optimistic for everything else, including custom resources: the field
        // can be read back, and whether a controller acted on it is not something this provider
        // has a rule for (§33.7). Reaching for the convergence rule here is how "the field is set"
        // becomes "the rollout finished".
        Action::Curated(_, _) | Action::Apply(_) => VerificationRule::FieldObserved,
    }
}

/// Kinds whose desired state is carried out by a controller this provider has a rule for (§37.2).
fn controller_backed(gvk: &Gvk) -> bool {
    matches!(
        (gvk.group(), gvk.kind()),
        (
            "apps",
            "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet"
        ) | ("batch", "Job" | "CronJob")
    )
}

/// Kinds whose deletion stops running processes.
fn runs_workload(gvk: &Gvk) -> bool {
    controller_backed(gvk) || matches!((gvk.group(), gvk.kind()), ("", "Pod" | "Namespace"))
}

/// Whether the target is a Namespace, whose deletion §55.2 singles out.
fn is_namespace(gvk: &Gvk) -> bool {
    matches!((gvk.group(), gvk.kind()), ("", "Namespace"))
}

/// Kinds whose deletion may reach storage this provider does not observe (§45.5).
fn storage_bearing(gvk: &Gvk) -> bool {
    matches!(
        (gvk.group(), gvk.kind()),
        (
            "",
            "PersistentVolumeClaim" | "PersistentVolume" | "Namespace"
        ) | ("apps", "StatefulSet")
    )
}

/// Joins names for a sentence, because `Vec::join` needs owned strings and these are static.
fn join<'a>(items: impl Iterator<Item = &'a str>) -> String {
    items.collect::<Vec<&str>>().join(", ")
}

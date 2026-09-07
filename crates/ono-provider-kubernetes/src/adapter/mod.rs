//! Curated ecosystem knowledge, beside the record and never in it.
//!
//! Specification §33.8, §58.4, §15.4 and §66.2; `ADR-0062`. Every custom resource already works
//! without anything here — discovered, typed from the cluster's own schema, addressable, watched,
//! stating whatever relationships its own fields state (§15.1, §33.1). An [`Adapter`] adds what a
//! reader *of that ecosystem* knows and the floor cannot: that an HTTPRoute's `parentRefs` names
//! a Gateway, that a Gateway answers to the `network-endpoint` role. It is layered over the
//! dynamic representation, and it is optional in the strict sense — a cluster that does not
//! serve the group never presents an object an adapter recognises.
//!
//! **An adapter cannot replace the record.** §33.8's `MUST NOT` is a property of the signatures:
//! an adapter is handed `&Object` and returns roles, edges, a view, effects, a rule and evidence.
//! No method here takes `&mut Object`, returns an `Object`, or returns anything an `Object` is
//! built from. `get k8s-resource` on an adapted kind returns what the cluster served because
//! there is no path by which it could return anything else.
//!
//! **Coverage is explicit, and a version nobody listed is dynamic.** [`Coverage`] is a group,
//! the kinds an adapter has rules for, and the served versions whose field layout it has seen.
//! §5.3 forbids assuming the newest version and §27.3 requires version awareness, so there is no
//! wildcard: [`Compatibility::UnknownVersion`] means the object gets the floor, which is where an
//! unknown schema belongs.
//!
//! **The registry never presents an inference as a relationship.** [`Registry::relationships`]
//! keeps out any edge whose deciding or supporting evidence is [`Evidence::Inferred`] (§23.5).
//! A correlation an ecosystem has to offer goes under [`Adapter::cross_system_evidence`], where
//! it is labelled as what it is.
//!
//! Adding an ecosystem is one file beside [`gateway`] and one entry in [`BUILTIN`]. The
//! contributor guide is `docs/adapters.md`.

pub mod gateway;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use crate::discovery::Gvk;
use crate::evidence::IdentityEvidence;
use crate::object::Object;
use crate::place::SemanticRole;
use crate::plan::{Action, EffectKind, Reversibility, VerificationRule};
use crate::relationship::{Edge, Evidence};

/// The members compiled into this build, in the order they answer.
///
/// This list is the registration. A new ecosystem is a module beside [`gateway`] and one entry
/// here; nothing in the parser, the shell, the handlers or the built-in relationship rules
/// changes (§66.2).
pub const BUILTIN: &[&dyn Adapter] = &[&gateway::GatewayApi];

static BUILTIN_REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    BUILTIN.iter().fold(Registry::empty(), |registry, adapter| {
        registry.with_member(Member::Borrowed(*adapter))
    })
});

// --- what an adapter covers --------------------------------------------------------------------

/// The group, kinds and served versions an adapter has written rules for (§33.8).
///
/// Versions are a list rather than a matcher, because an adapter has seen the field layout of
/// the versions it names and a matcher would say it has seen versions it has not (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    group: &'static str,
    kinds: &'static [&'static str],
    versions: &'static [&'static str],
}

impl Coverage {
    /// One API group, the kinds within it this adapter has rules for, and the served versions
    /// whose field layout it has seen.
    #[must_use]
    pub const fn new(
        group: &'static str,
        kinds: &'static [&'static str],
        versions: &'static [&'static str],
    ) -> Self {
        Self {
            group,
            kinds,
            versions,
        }
    }

    /// The API group.
    #[must_use]
    pub fn group(&self) -> &'static str {
        self.group
    }

    /// The kinds covered within the group.
    #[must_use]
    pub fn kinds(&self) -> &'static [&'static str] {
        self.kinds
    }

    /// The served versions the adapter has seen.
    #[must_use]
    pub fn versions(&self) -> &'static [&'static str] {
        self.versions
    }

    /// How this coverage relates to one GVK.
    ///
    /// Group and kind decide whether the adapter has anything to say at all (§13.5); the version
    /// decides whether it may say it.
    #[must_use]
    pub fn compatibility(&self, gvk: &Gvk) -> Compatibility {
        if gvk.group() != self.group || !self.kinds.contains(&gvk.kind()) {
            Compatibility::NotCovered
        } else if self.versions.contains(&gvk.version()) {
            Compatibility::Adapted
        } else {
            Compatibility::UnknownVersion
        }
    }
}

/// Whether an adapter applies to a GVK, and if not, which half of the answer is missing.
///
/// Three answers rather than a boolean, because [`Self::UnknownVersion`] is worth saying: the
/// group and kind are known and the version is not, so the object is dynamic for §5.3's reason
/// rather than for want of an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compatibility {
    /// The adapter has rules for this group, kind and served version.
    Adapted,
    /// The adapter has rules for this group and kind, and has not seen this served version. The
    /// object gets universal dynamic support (§15.1) and no curated semantics.
    UnknownVersion,
    /// No rule for this group and kind.
    NotCovered,
}

impl Compatibility {
    /// Whether curated semantics apply.
    #[must_use]
    pub fn is_adapted(self) -> bool {
        matches!(self, Self::Adapted)
    }
}

// --- what an adapter is handed and what it answers ----------------------------------------------

/// What the caller has already read, for an adapter that derives an edge from two objects.
///
/// Objects in hand and nothing else. Nothing in the domain crate performs I/O (§58.1, §59.1),
/// so an adapter that needs a second object reads it from [`Self::candidates`] and derives
/// nothing when it is not there — the caller decides what to offer and therefore owns the scope
/// of every answer (§9.4).
#[derive(Default)]
pub struct Context<'a> {
    candidates: &'a [Object],
}

impl<'a> Context<'a> {
    /// A context holding the objects the caller has already read.
    #[must_use]
    pub const fn with_candidates(candidates: &'a [Object]) -> Self {
        Self { candidates }
    }

    /// The objects in hand.
    #[must_use]
    pub fn candidates(&self) -> &'a [Object] {
        self.candidates
    }
}

impl fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("candidates", &self.candidates.len())
            .finish()
    }
}

/// One field of a default view: a label, and the JSON pointer into the object that supplies it.
///
/// A pointer rather than a value, so a view is a way of reading the record and never a second
/// document beside it (§33.8, §52.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewField {
    label: String,
    pointer: String,
}

impl ViewField {
    /// A labelled pointer.
    #[must_use]
    pub fn new(label: impl Into<String>, pointer: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            pointer: pointer.into(),
        }
    }

    /// The word the field is shown under.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The JSON pointer into the object.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }
}

/// The fields an adapter would show by default for an object of its kind (§33.8, §52).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    fields: Vec<ViewField>,
}

impl View {
    /// A view of these fields, in this order.
    #[must_use]
    pub fn new(fields: Vec<ViewField>) -> Self {
        Self { fields }
    }

    /// The fields, in the order they are shown.
    #[must_use]
    pub fn fields(&self) -> &[ViewField] {
        &self.fields
    }
}

/// An effect an adapter expects a change to have, in the plan's vocabulary (§46.2, §46.5).
///
/// The adapter's statement rather than the plan's [`crate::plan::Effect`]: the plan builds its
/// own effects, and this is what an ecosystem hands it to build from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prospect {
    kind: EffectKind,
    reversibility: Reversibility,
}

impl Prospect {
    /// An expected effect, and what could be done about it afterwards.
    #[must_use]
    pub const fn new(kind: EffectKind, reversibility: Reversibility) -> Self {
        Self {
            kind,
            reversibility,
        }
    }

    /// What is expected to happen.
    #[must_use]
    pub fn kind(&self) -> EffectKind {
        self.kind
    }

    /// What could be done about it afterwards.
    #[must_use]
    pub fn reversibility(&self) -> Reversibility {
        self.reversibility
    }
}

// --- the interface ------------------------------------------------------------------------------

/// Curated knowledge about one ecosystem's kinds, at the served versions it has seen (§58.4).
///
/// Every method after [`Self::coverage`] has a no-op default, so a member contributes only what it
/// knows. Everything takes the object by shared reference and answers with values built beside
/// it; there is no way to hand back an object.
pub trait Adapter: Send + Sync {
    /// The adapter's name, as it appears in evidence and diagnostics.
    fn name(&self) -> &'static str;

    /// The group, kinds and served versions this adapter has rules for.
    fn coverage(&self) -> Coverage;

    /// How this adapter relates to one GVK.
    fn compatibility(&self, gvk: &Gvk) -> Compatibility {
        self.coverage().compatibility(gvk)
    }

    /// Whether curated semantics apply to this GVK.
    fn supports(&self, gvk: &Gvk) -> bool {
        self.compatibility(gvk).is_adapted()
    }

    /// The generic roles a kind answers to (§36.2).
    ///
    /// A judgement about the kind rather than about one object, which is why this takes the GVK:
    /// the generic contract registers native resource *types* under roles, and a place is built
    /// from an identity.
    fn semantic_roles(&self, _gvk: &Gvk) -> Vec<SemanticRole> {
        Vec::new()
    }

    /// The relationships this object states, each with the evidence that decided it (Gate D).
    ///
    /// Cite the pointer read as [`Evidence::NativeField`], and name the adapter and the version
    /// it assumed as supporting [`Evidence::Derived`]. An edge resting on an inference is not
    /// presented by the registry (§23.5).
    fn relationships(&self, _object: &Object, _context: &Context<'_>) -> Vec<Edge> {
        Vec::new()
    }

    /// The fields to show by default for an object of this kind (§52).
    fn default_view(&self, _object: &Object) -> Option<View> {
        None
    }

    /// What a change to this object is expected to do (§46.2).
    fn prospective_effects(&self, _object: &Object, _action: &Action) -> Vec<Prospect> {
        Vec::new()
    }

    /// How the outcome of a change to this object could be verified (§46.3).
    fn verification(&self, _object: &Object, _action: &Action) -> Option<VerificationRule> {
        None
    }

    /// What this object states about systems outside the cluster (§47).
    fn cross_system_evidence(&self, _object: &Object) -> Vec<IdentityEvidence> {
        Vec::new()
    }
}

// --- the registry -------------------------------------------------------------------------------

/// One registered adapter, however it was handed in.
enum Member {
    Borrowed(&'static dyn Adapter),
    Owned(Box<dyn Adapter>),
}

impl Member {
    fn adapter(&self) -> &dyn Adapter {
        match self {
            Self::Borrowed(adapter) => *adapter,
            Self::Owned(adapter) => adapter.as_ref(),
        }
    }
}

/// The adapters this build knows, looked up by group and kind and gated by served version.
///
/// Two members may cover one GVK; each contributes and the answers are concatenated in
/// registration order. There is no precedence and no de-duplication (`ADR-0062`).
pub struct Registry {
    members: Vec<Member>,
    by_group_and_kind: BTreeMap<(String, String), Vec<usize>>,
}

impl Registry {
    /// A registry with no members: every kind is dynamic.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            members: Vec::new(),
            by_group_and_kind: BTreeMap::new(),
        }
    }

    /// The registry with one more member.
    #[must_use]
    pub fn with(self, adapter: impl Adapter + 'static) -> Self {
        self.with_member(Member::Owned(Box::new(adapter)))
    }

    /// The members compiled into this build ([`BUILTIN`]), assembled once.
    #[must_use]
    pub fn builtin() -> &'static Self {
        &BUILTIN_REGISTRY
    }

    fn with_member(mut self, member: Member) -> Self {
        let coverage = member.adapter().coverage();
        let at = self.members.len();
        for kind in coverage.kinds() {
            self.by_group_and_kind
                .entry((coverage.group().to_owned(), (*kind).to_owned()))
                .or_default()
                .push(at);
        }
        self.members.push(member);
        self
    }

    /// Every member, in registration order.
    pub fn members(&self) -> impl Iterator<Item = &dyn Adapter> {
        self.members.iter().map(Member::adapter)
    }

    /// The members registered for this GVK's group and kind, whatever their version list says.
    fn covering(&self, gvk: &Gvk) -> impl Iterator<Item = &dyn Adapter> {
        self.by_group_and_kind
            .get(&(gvk.group().to_owned(), gvk.kind().to_owned()))
            .into_iter()
            .flatten()
            .map(|at| self.members[*at].adapter())
    }

    /// How the registry relates to one GVK.
    ///
    /// Adapted if any member has seen the version; unknown-version if members cover the group
    /// and kind and none has seen the version; not covered otherwise.
    #[must_use]
    pub fn compatibility(&self, gvk: &Gvk) -> Compatibility {
        let mut answer = Compatibility::NotCovered;
        for adapter in self.covering(gvk) {
            match adapter.compatibility(gvk) {
                Compatibility::Adapted => return Compatibility::Adapted,
                Compatibility::UnknownVersion => answer = Compatibility::UnknownVersion,
                Compatibility::NotCovered => {}
            }
        }
        answer
    }

    /// The members whose curated semantics apply to this GVK, in registration order.
    #[must_use]
    pub fn adapters_for(&self, gvk: &Gvk) -> Vec<&dyn Adapter> {
        self.covering(gvk)
            .filter(|adapter| adapter.supports(gvk))
            .collect()
    }

    /// The generic roles the members state for this kind (§36.2).
    #[must_use]
    pub fn semantic_roles(&self, gvk: &Gvk) -> Vec<SemanticRole> {
        self.adapters_for(gvk)
            .into_iter()
            .flat_map(|adapter| adapter.semantic_roles(gvk))
            .collect()
    }

    /// The relationships the members state for this object, each one checkable.
    ///
    /// An edge whose deciding or supporting evidence is an inference is not presented (§23.5,
    /// §4 invariant 20): a guess does not become a relationship by being registered.
    #[must_use]
    pub fn relationships(&self, object: &Object, context: &Context<'_>) -> Vec<Edge> {
        self.adapters_for(object.gvk())
            .into_iter()
            .flat_map(|adapter| adapter.relationships(object, context))
            .filter(is_checkable)
            .collect()
    }

    /// The first default view a member states for this object.
    #[must_use]
    pub fn default_view(&self, object: &Object) -> Option<View> {
        self.adapters_for(object.gvk())
            .into_iter()
            .find_map(|adapter| adapter.default_view(object))
    }

    /// What the members expect a change to this object to do (§46.2).
    #[must_use]
    pub fn prospective_effects(&self, object: &Object, action: &Action) -> Vec<Prospect> {
        self.adapters_for(object.gvk())
            .into_iter()
            .flat_map(|adapter| adapter.prospective_effects(object, action))
            .collect()
    }

    /// The first verification rule a member states for a change to this object (§46.3).
    #[must_use]
    pub fn verification(&self, object: &Object, action: &Action) -> Option<VerificationRule> {
        self.adapters_for(object.gvk())
            .into_iter()
            .find_map(|adapter| adapter.verification(object, action))
    }

    /// What the members say this object states about systems outside the cluster (§47).
    #[must_use]
    pub fn cross_system_evidence(&self, object: &Object) -> Vec<IdentityEvidence> {
        self.adapters_for(object.gvk())
            .into_iter()
            .flat_map(|adapter| adapter.cross_system_evidence(object))
            .collect()
    }
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.members().map(Adapter::name))
            .finish()
    }
}

/// Whether every piece of evidence on the edge is something a reader can go and check.
fn is_checkable(edge: &Edge) -> bool {
    let inferred = |evidence: &Evidence| matches!(evidence, Evidence::Inferred { .. });
    !inferred(edge.evidence()) && !edge.supporting().iter().any(inferred)
}

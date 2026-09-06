//! Relationships between Kubernetes objects, and the evidence each one rests on.
//!
//! Specification §23 to §32. The organising rule is Gate D: an edge must be able to say where it
//! came from and which fields decided it. That is why [`Evidence`] is a required part of every
//! [`Edge`] rather than an optional annotation — an edge that cannot be checked is one a user has
//! to trust, and §4 invariant 20 forbids a guess arriving in the shape of an assertion.
//!
//! Three kinds of thing live here and are deliberately not blurred:
//!
//! - what the API server **states** in a field — `spec.nodeName`, an owner reference;
//! - what this provider **derives** from two states — a selector evaluated against labels;
//! - what someone might **infer** — a name that looks similar, a matching address.
//!
//! The first two are produced here. The third is not produced at all, and the type exists so
//! that a later cross-system resolver has somewhere honest to put its results.

use std::collections::BTreeMap;

use serde_json::Value as Json;

use crate::object::{Identity, Object};
use crate::workload::SelectorMatch;

/// A named relationship between two objects.
///
/// One vocabulary for the whole provider. A relationship a user can follow is one word wherever
/// it was derived, so a curated routing edge and an owner reference are the same kind of thing
/// with different evidence behind them — and a second enum of relationship names is one more than
/// a user should ever see.
///
/// Direction is part of the name, which is why `owned-by` and `owns` are both here. They are the
/// same fact read from the two ends, and an edge that named only one of them would force the far
/// end to be described backwards.
///
/// Near-synonyms stay apart for the same reason: `owns` says a controller's mark is on the child
/// and `selector-matches` says two label sets agree (§23.2 against §23.3). Collapsing the two
/// would let a canary ReplicaSet read as one its neighbour controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relation {
    /// The source is owned by the target (`metadata.ownerReferences`).
    OwnedBy,
    /// The source is owned by the target, which is its controller (§24.3).
    ControlledBy,
    /// The target's `metadata.ownerReferences` names the source — `owned-by` read from the
    /// owner's end (§25.1).
    Owns,
    /// As [`Self::Owns`], and the source is the target's controller (§24.3).
    Controls,
    /// The source Pod is placed on the target Node (`spec.nodeName`).
    ScheduledOn,
    /// The source Service selects the target by labels (§26.1).
    Selects,
    /// The source Pod is selected by the target Service — [`Self::Selects`] from the Pod's end
    /// (§26.1, Appendix B).
    SelectedBy,
    /// The source's selector matches the target's labels, which is weaker than owning it (§23.3).
    SelectorMatches,
    /// The source StatefulSet is governed by the target Service (§25.3).
    UsesService,
    /// The source Service is represented by the target EndpointSlice (§26.2).
    RepresentedBy,
    /// The source EndpointSlice holds an endpoint backed by the target (§26.2).
    EndpointFor,
    /// The source routes traffic to the target Service (§27.1, §27.3).
    RoutesTo,
    /// Traffic reaches the source Service from the target router — [`Self::RoutesTo`] from the
    /// backend's end (§27.1, §27.3, Appendix B).
    RoutedFrom,
    /// The source terminates TLS with the target Secret (§27.1).
    UsesTlsSecret,
    /// The source Ingress is handled by the target IngressClass (§27.2).
    UsesIngressClass,
    /// The source route attaches to the target Gateway (§27.3).
    AttachesTo,
    /// The source Gateway is implemented by the target GatewayClass (§27.3).
    UsesGatewayClass,
    /// The source Pod runs under the target ServiceAccount (§32.1).
    RunsAs,
    /// The source mounts the target claim (§30.1).
    Mounts,
    /// The source claim is bound to the target volume (§30.2).
    BoundTo,
    /// The source claim or volume names the target StorageClass (§30.1, §30.3).
    ///
    /// Appendix B's word rather than §30.1's `provisioned-by / storage-class`. ADR-0031 records
    /// why: the appendix says its names are candidates to be reconciled with the project's global
    /// relationship registry, `uses-*` is the shape every other "this object names that one" edge
    /// here already has, and `provisioned-by` would claim the provisioning happened — which the
    /// field does not say and a `Pending` claim disproves.
    UsesStorageClass,
    /// The source reads configuration from the target (§29.1).
    ReferencesConfig,
    /// The source reads a secret from the target (§29.2).
    ReferencesSecret,
    /// The source ServiceAccount carries the target Secret in `secrets` (§22.4).
    UsesSecret,
    /// The source pulls images with the target Secret (§22.4, §32.1).
    UsesImagePullSecret,
    /// The source binding grants the rules of the target Role or ClusterRole (§32.2).
    ///
    /// The binding's `roleRef`, and nothing about who receives it: §32.3's subjects include Users
    /// and Groups, which Kubernetes does not store, and ADR-0040 records why Appendix B's
    /// `grants-to` is not emitted at all rather than emitted for the one subject kind that is an
    /// object.
    Binds,
    /// The source Pod is governed by the target NetworkPolicy (§31.1).
    ///
    /// Appendix B's word for the Pod's end of §31.1's `NetworkPolicy -> selects -> Pod`, and
    /// deliberately not [`Self::SelectedBy`]: a policy is not a Service, and one word for both
    /// ends of both would put a firewall rule in the routing vocabulary. What it does **not**
    /// claim is enforcement — §31.3 makes a policy object intent, and every edge carries that
    /// as supporting evidence rather than leaving the word to imply observed traffic.
    ProtectedBy,
}

impl Relation {
    /// The word a user types after `follow`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnedBy => "owned-by",
            Self::ControlledBy => "controlled-by",
            Self::Owns => "owns",
            Self::Controls => "controls",
            Self::ScheduledOn => "scheduled-on",
            Self::Selects => "selects",
            Self::SelectedBy => "selected-by",
            Self::SelectorMatches => "selector-matches",
            Self::UsesService => "uses-service",
            Self::RepresentedBy => "represented-by",
            Self::EndpointFor => "endpoint-for",
            Self::RoutesTo => "routes-to",
            Self::RoutedFrom => "routed-from",
            Self::UsesTlsSecret => "uses-tls-secret",
            Self::UsesIngressClass => "uses-ingress-class",
            Self::AttachesTo => "attaches-to",
            Self::UsesGatewayClass => "uses-gateway-class",
            Self::RunsAs => "runs-as",
            Self::Mounts => "mounts",
            Self::BoundTo => "bound-to",
            Self::UsesStorageClass => "uses-storage-class",
            Self::ReferencesConfig => "references-config",
            Self::ReferencesSecret => "references-secret",
            Self::UsesSecret => "uses-secret",
            Self::UsesImagePullSecret => "uses-image-pull-secret",
            Self::Binds => "binds",
            Self::ProtectedBy => "protected-by",
        }
    }
}

/// Why an edge exists, in enough detail that a reader can check it (Gate D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// A field of the source object states the relationship.
    NativeField {
        /// The JSON pointer that was read.
        path: String,
        /// What it held.
        value: String,
    },
    /// `metadata.ownerReferences` records it.
    OwnerReference {
        /// Whether the owner is the controller (§24.3).
        controller: bool,
    },
    /// A selector was evaluated against observed labels.
    Selector {
        /// The selector, as the source declared it.
        selector: BTreeMap<String, String>,
        /// The labels of the target that satisfied it — the ones that decided, not all of them.
        matched_labels: BTreeMap<String, String>,
    },
    /// A well-known label or annotation encodes it by convention rather than by API structure.
    Convention {
        /// The key that carried it.
        key: String,
        /// Its value.
        value: String,
    },
    /// A curated adapter derived it from a rule of its own (§33.8).
    Derived {
        /// The rule, named so it can be looked up.
        rule: String,
    },
    /// Something correlated it without proof (§23.5).
    ///
    /// Never produced by this module. The variant exists so that a cross-system resolver has an
    /// honest place to put a correlation, and so that rendering can tell it apart from the rest.
    Inferred {
        /// Why the correlation was drawn.
        reason: String,
    },
}

impl Evidence {
    /// The class name, for `inspect` and for a reader deciding how much to trust the edge.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            Self::NativeField { .. } => "native-field",
            Self::OwnerReference { .. } => "owner-reference",
            Self::Selector { .. } => "selector",
            Self::Convention { .. } => "convention",
            Self::Derived { .. } => "adapter-derivation",
            Self::Inferred { .. } => "inference",
        }
    }

    /// Whether the API server itself states this relationship.
    ///
    /// False for a selector edge: the server states a selector and it states some labels, and it
    /// is *this provider* that evaluated one against the other. That distinction is what §23.3
    /// asks for and what stops a derivation from being read as an assertion.
    #[must_use]
    pub fn is_asserted_by_provider(&self) -> bool {
        matches!(self, Self::NativeField { .. } | Self::OwnerReference { .. })
    }

    /// The JSON pointer this evidence cites, where its class cites one.
    ///
    /// [`None`] for the classes that do not rest on a single field: a selector evaluation read
    /// two objects, a convention read a label key, and a derivation read whatever its rule says.
    /// Reporting one of those under a pointer would name a field as the proof when the proof is
    /// somewhere else.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::NativeField { path, .. } => Some(path),
            Self::OwnerReference { .. }
            | Self::Selector { .. }
            | Self::Convention { .. }
            | Self::Derived { .. }
            | Self::Inferred { .. } => None,
        }
    }

    /// One line naming what was read and what it held.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::NativeField { path, value } => format!("{path} = {value}"),
            Self::OwnerReference { controller } => {
                if *controller {
                    "metadata.ownerReferences with controller: true".to_owned()
                } else {
                    "metadata.ownerReferences".to_owned()
                }
            }
            Self::Selector {
                selector,
                matched_labels,
            } => format!(
                "selector {} matched labels {}",
                render(selector),
                render(matched_labels)
            ),
            Self::Convention { key, value } => format!("{key} = {value}"),
            Self::Derived { rule } => format!("derived by {rule}"),
            Self::Inferred { reason } => format!("inferred: {reason}"),
        }
    }
}

fn render(map: &BTreeMap<String, String>) -> String {
    let pairs: Vec<String> = map
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    format!("{{{}}}", pairs.join(","))
}

/// Where an edge points.
///
/// A descriptor rather than an identity, because §24.1 requires an edge to survive its target
/// being unreadable. What is known is kept; what is not is absent rather than invented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    kind: String,
    api_version: Option<String>,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
    resolved: Option<Identity>,
}

impl Target {
    /// A reference to something not read yet: the two facts every Kubernetes reference carries.
    ///
    /// Everything else a reference may carry — `apiVersion`, namespace, UID, a resolved object —
    /// is added by a named setter rather than by a longer signature. Each of them is separately
    /// optional, and a six-argument constructor of `Option`s reads at the call site as a row of
    /// `None`s whose meaning has to be counted out; a named setter says which fact is missing by
    /// not being there. Nothing is defaulted: what the reference did not state stays absent
    /// rather than being borrowed from the source object.
    #[must_use]
    pub fn new(kind: &str, name: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            api_version: None,
            namespace: None,
            name: name.to_owned(),
            uid: None,
            resolved: None,
        }
    }

    /// The `apiVersion` the reference carried, or implied by the kind it names.
    #[must_use]
    pub fn with_api_version(mut self, api_version: Option<&str>) -> Self {
        self.api_version = api_version.map(str::to_owned);
        self
    }

    /// The namespace the target is looked for in.
    ///
    /// [`None`] means cluster scope and never "wherever the source lives": copying a namespace
    /// onto a cluster-scoped target would name an address that cannot be looked up (§9.2, §9.5),
    /// so the caller states it each time rather than inheriting it.
    #[must_use]
    pub fn in_namespace(mut self, namespace: Option<&str>) -> Self {
        self.namespace = namespace.map(str::to_owned);
        self
    }

    /// The UID the reference carried, which is what makes the far end provable rather than a
    /// name match (§16.1).
    #[must_use]
    pub fn with_uid(mut self, uid: Option<&str>) -> Self {
        self.uid = uid.map(str::to_owned);
        self
    }

    /// Binds the identity of a target something actually read.
    ///
    /// Only for an object in hand. An identity invented for an unread target would claim a
    /// lifetime nobody observed, and §24.1 wants the unresolved edge kept as an unresolved edge.
    #[must_use]
    pub fn resolved_as(mut self, identity: Identity) -> Self {
        self.resolved = Some(identity);
        self
    }

    /// The descriptor for an object that was read, so the edge carries its identity.
    #[must_use]
    pub fn of_object(object: &Object) -> Self {
        Self::new(object.gvk().kind(), object.name())
            .with_api_version(Some(&api_version_of(object)))
            .in_namespace(object.namespace())
            .with_uid(object.uid())
            .resolved_as(object.identity())
    }

    /// The target's kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The target's `apiVersion`, where the reference carried one.
    #[must_use]
    pub fn api_version(&self) -> Option<&str> {
        self.api_version.as_deref()
    }

    /// The namespace the target lives in, where it is namespaced.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The target's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The target's UID, where the reference carried one.
    #[must_use]
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }

    /// Whether the target object was actually read.
    ///
    /// An unresolved target is not a broken edge (§24.1). It is a relationship whose other end
    /// nobody has looked at, or cannot.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.resolved.is_some()
    }

    /// The target's identity, once something resolved it.
    #[must_use]
    pub fn identity(&self) -> Option<&Identity> {
        self.resolved.as_ref()
    }
}

/// One relationship, with the evidence that decided it and the evidence that qualifies it.
///
/// The split between the two matters for routing. `Ingress -> Service` is decided by the backend
/// service name, and the host, path and port are what make the edge worth walking: §27.1 requires
/// them to stay attached, because "which Service" without "for which URL" answers a question
/// nobody asked. Folding them into one list would leave a reader unable to tell what the edge
/// rests on from what it merely tells them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    source: Identity,
    relation: Relation,
    target: Target,
    evidence: Evidence,
    supporting: Vec<Evidence>,
}

impl Edge {
    /// One relationship, and what decided it.
    ///
    /// [`Evidence`] is an argument rather than a setter, so there is no moment — not even a
    /// half-built one inside a builder — at which an edge exists without saying where it came
    /// from. That is Gate D expressed in the type instead of in a review comment: §4 invariant 20
    /// forbids a guess arriving in the shape of an assertion, and an edge that could be built
    /// first and justified afterwards is exactly how that happens.
    #[must_use]
    pub fn new(source: Identity, relation: Relation, target: Target, evidence: Evidence) -> Self {
        Self {
            source,
            relation,
            target,
            evidence,
            supporting: Vec::new(),
        }
    }

    /// Evidence that qualifies the edge rather than deciding it.
    ///
    /// The host, path and port of a route (§27.1), the hosts a certificate serves, the adapter
    /// and version that read a custom resource (§33.8). None of it would make the edge exist, and
    /// all of it changes what the edge means once it does.
    #[must_use]
    pub fn with_supporting(mut self, supporting: Vec<Evidence>) -> Self {
        self.supporting = supporting;
        self
    }

    /// The object the relationship starts at.
    #[must_use]
    pub fn source(&self) -> &Identity {
        &self.source
    }

    /// What the relationship is.
    #[must_use]
    pub fn relation(&self) -> Relation {
        self.relation
    }

    /// Where it points.
    #[must_use]
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Why it exists (Gate D).
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// What qualifies it: the host, path and port of a route, the hosts a certificate serves,
    /// the adapter and version that read a custom resource.
    #[must_use]
    pub fn supporting(&self) -> &[Evidence] {
        &self.supporting
    }
}

/// Extracts the relationships an object states about itself, and the ones a pair of objects
/// makes derivable.
pub struct Graph;

impl Graph {
    /// Every edge one object states about itself.
    ///
    /// Only what the object's own fields carry. Nothing here reads another object, so nothing
    /// here can produce a derived or inferred edge — those need two facts and have their own
    /// entry points.
    #[must_use]
    pub fn edges_of(object: &Object) -> Vec<Edge> {
        let mut edges = Vec::new();
        let source = object.identity();
        let namespace = object.namespace().map(str::to_owned);

        for owner in object.owner_references() {
            // Both edges, deliberately. §24.3 asks for the stronger label where `controller` is
            // set *while preserving generic `owned-by` semantics*, so a caller that wants all
            // ownership does not have to know which of the two words to ask for.
            let target = Target::new(owner.kind(), owner.name())
                .with_api_version(Some(owner.api_version()))
                // An owner reference is namespace-local for a namespaced dependent (§24.2).
                .in_namespace(namespace.as_deref())
                .with_uid(Some(owner.uid()));
            let evidence = Evidence::OwnerReference {
                controller: owner.is_controller(),
            };
            edges.push(Edge::new(
                source.clone(),
                Relation::OwnedBy,
                target.clone(),
                evidence.clone(),
            ));
            if owner.is_controller() {
                edges.push(Edge::new(
                    source.clone(),
                    Relation::ControlledBy,
                    target,
                    evidence,
                ));
            }
        }

        // Group *and* kind, because §13.5 makes GVK the identity: a custom `Pod` in someone
        // else's group carries whatever fields its author chose, and reading `spec.nodeName`
        // there would assert a scheduling fact about an object that never claimed one.
        match (object.gvk().group(), object.gvk().kind()) {
            ("", "Pod") => edges.extend(pod_edges(object, &source, namespace.as_deref())),
            ("", "PersistentVolumeClaim") => edges.extend(claim_edges(object, &source)),
            // A PersistentVolume names its class in the same field a claim does, and nothing
            // else about a volume is a relationship this provider derives: what it is backed by
            // is §47.5's cross-system evidence, exported rather than resolved.
            ("", "PersistentVolume") => edges.extend(storage_class_edge(object, &source)),
            // §32.2's `binds`. Both bindings state their role in the same `roleRef`, and what
            // differs is where the role is looked up (§9.5).
            ("rbac.authorization.k8s.io", "RoleBinding" | "ClusterRoleBinding") => {
                edges.extend(binding_edges(object, &source, namespace.as_deref()));
            }
            _ => {}
        }

        edges
    }

    /// The Pods a Service selects, derived from its selector and their labels (§26.1).
    ///
    /// Namespace-local and conjunctive. A selector-less or empty-selector Service selects nothing:
    /// §26.1 forbids guessing there, because such a Service is routed by endpoints a human
    /// manages rather than by labels.
    #[must_use]
    pub fn selects(service: &Object, candidates: &[Object]) -> Vec<Edge> {
        let selector = string_map(service.field("/spec/selector"));
        if selector.is_empty() {
            return Vec::new();
        }
        let source = service.identity();
        candidates
            .iter()
            .filter(|pod| pod.namespace() == service.namespace())
            .filter_map(|pod| {
                let mut matched = BTreeMap::new();
                for (key, wanted) in &selector {
                    if pod.label(key) != Some(wanted.as_str()) {
                        return None;
                    }
                    matched.insert(key.clone(), wanted.clone());
                }
                Some(Edge::new(
                    source.clone(),
                    Relation::Selects,
                    Target::of_object(pod),
                    Evidence::Selector {
                        selector: selector.clone(),
                        matched_labels: matched,
                    },
                ))
            })
            .collect()
    }

    /// The Services that select one Pod — §26.1 read from the Pod's end (Appendix B).
    ///
    /// The end an operator starts at when one Pod is missing from a Service's endpoints, and the
    /// same evaluation as [`Self::selects`] so that the two directions cannot disagree. The
    /// reversal is stated as supporting evidence, because the selector lives on the Service and
    /// this edge reads it backwards.
    #[must_use]
    pub fn selected_by(pod: &Object, services: &[Object]) -> Vec<Edge> {
        let source = pod.identity();
        services
            .iter()
            .filter(|service| service.gvk().group().is_empty())
            .filter(|service| service.gvk().kind() == "Service")
            .filter_map(|service| {
                let selector = string_map(service.field("/spec/selector"));
                if selector.is_empty() {
                    return None;
                }
                let matched = selected_labels(&selector, pod, service.namespace())?;
                Some(
                    Edge::new(
                        source.clone(),
                        Relation::SelectedBy,
                        Target::of_object(service),
                        Evidence::Selector {
                            selector,
                            matched_labels: matched,
                        },
                    )
                    .with_supporting(vec![Evidence::Derived {
                        rule: format!(
                            "selector reversal: Service/{} states `spec.selector` and this Pod's \
                             labels satisfy it",
                            service.name()
                        ),
                    }]),
                )
            })
            .collect()
    }

    /// The Pods a NetworkPolicy is written for, derived from `spec.podSelector` (§31.1).
    ///
    /// Namespace-local, because a NetworkPolicy governs its own namespace and nothing else. Both
    /// halves of §31.1's `MUST` ride on every edge: the selector and the labels that satisfied it
    /// as the deciding [`Evidence::Selector`], and the policy's namespace as supporting evidence
    /// citing the field that states it.
    ///
    /// **An empty `spec.podSelector` is not an empty selector.** For a Service, empty means
    /// *nothing is selected* (§26.1); for a NetworkPolicy, the API defines it as *every Pod in
    /// this namespace*, which is what a default-deny policy is written as. Reading the two the
    /// same way would report the strictest policy in a cluster as governing nothing.
    ///
    /// **Nothing here says who may reach those Pods.** §31.2 requires a policy's peers to keep
    /// their native structure, so ingress and egress peers produce no edges at all: an edge to a
    /// CIDR block would be the misleading boolean of §31.2 in a different shape.
    #[must_use]
    pub fn policy_selects(policy: &Object, candidates: &[Object]) -> SelectorMatch {
        let selector = match policy_selector(policy) {
            Ok(selector) => selector,
            Err(reason) => return SelectorMatch::NotEvaluated { reason },
        };
        let source = policy.identity();
        let edges = candidates
            .iter()
            .filter(|candidate| is_pod(candidate))
            .filter_map(|pod| {
                let matched = selected_labels(&selector, pod, policy.namespace())?;
                Some(
                    Edge::new(
                        source.clone(),
                        Relation::Selects,
                        Target::of_object(pod),
                        Evidence::Selector {
                            selector: selector.clone(),
                            matched_labels: matched,
                        },
                    )
                    .with_supporting(policy_evidence(policy, &selector)),
                )
            })
            .collect();
        SelectorMatch::Evaluated(edges)
    }

    /// The NetworkPolicies that govern one Pod — §31.1 read from the Pod's end (Appendix B).
    ///
    /// The direction an operator asks in during an outage: what governs *this* Pod, rather than
    /// what one policy covers. The evidence is the same evidence, because it is the same
    /// derivation; only the end it is read from differs.
    ///
    /// One unevaluated selector makes the whole answer [`SelectorMatch::NotEvaluated`], and that
    /// is stricter than [`Self::policy_selects`] on purpose: "which policies govern this Pod" is
    /// one question, and answering it with the policies that happened to be evaluable is the
    /// claim that no other policy applies (ADR-0007, §21.4).
    #[must_use]
    pub fn protected_by(pod: &Object, policies: &[Object]) -> SelectorMatch {
        if !is_pod(pod) {
            return SelectorMatch::NotEvaluated {
                reason: format!(
                    "`{}` is not a Pod, and `spec.podSelector` is evaluated against a Pod's labels",
                    pod.gvk()
                ),
            };
        }
        let source = pod.identity();
        let mut edges = Vec::new();
        for policy in policies.iter().filter(|object| is_policy(object)) {
            let selector = match policy_selector(policy) {
                Ok(selector) => selector,
                Err(reason) => {
                    return SelectorMatch::NotEvaluated {
                        reason: format!("`{}`: {reason}", policy.name()),
                    };
                }
            };
            let Some(matched) = selected_labels(&selector, pod, policy.namespace()) else {
                continue;
            };
            edges.push(
                Edge::new(
                    source.clone(),
                    Relation::ProtectedBy,
                    Target::of_object(policy),
                    Evidence::Selector {
                        selector: selector.clone(),
                        matched_labels: matched,
                    },
                )
                .with_supporting(policy_evidence(policy, &selector)),
            );
        }
        SelectorMatch::Evaluated(edges)
    }
}

/// The Role or ClusterRole a binding names in `roleRef` (§32.2).
///
/// `roleRef.kind` decides where the role is looked up: a `Role` is namespace-local and a
/// `ClusterRole` is cluster-scoped, so only the first carries the binding's namespace onto the
/// target (§9.5, §24.2). A binding whose `roleRef` names neither yields nothing rather than an
/// edge to a kind this provider guessed at.
///
/// The version is the group's `v1`, which is what the reference states in every cluster inside
/// the support window; `roleRef` carries an `apiGroup` and no version, and a target has to name
/// one to be addressable (§13.4).
fn binding_edges(binding: &Object, source: &Identity, namespace: Option<&str>) -> Vec<Edge> {
    let Some(reference) = binding.field("/roleRef") else {
        return Vec::new();
    };
    let (Some(kind), Some(name)) = (
        reference.get("kind").and_then(Json::as_str),
        reference.get("name").and_then(Json::as_str),
    ) else {
        return Vec::new();
    };
    if !matches!(kind, "Role" | "ClusterRole") {
        return Vec::new();
    }
    let group = reference
        .get("apiGroup")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let api_version = if group.is_empty() {
        "v1".to_owned()
    } else {
        format!("{group}/v1")
    };
    let scope = if kind == "Role" { namespace } else { None };
    vec![
        Edge::new(
            source.clone(),
            Relation::Binds,
            Target::new(kind, name)
                .with_api_version(Some(&api_version))
                .in_namespace(scope),
            Evidence::NativeField {
                path: "/roleRef/name".to_owned(),
                value: name.to_owned(),
            },
        )
        .with_supporting(vec![Evidence::NativeField {
            path: "/roleRef/kind".to_owned(),
            value: kind.to_owned(),
        }]),
    ]
}

/// Whether the object is a core-group Pod — GVK identity, so somebody else's `Pod` is not one.
fn is_pod(object: &Object) -> bool {
    object.gvk().group().is_empty() && object.gvk().kind() == "Pod"
}

/// Whether the object is a `networking.k8s.io` NetworkPolicy (§13.5).
fn is_policy(object: &Object) -> bool {
    object.gvk().group() == "networking.k8s.io" && object.gvk().kind() == "NetworkPolicy"
}

/// A policy's `spec.podSelector` as label equalities, or why it was not evaluated (ADR-0007).
///
/// Three refusals, and each is a different thing the answer would otherwise get wrong: an object
/// that is not a NetworkPolicy has no `podSelector` to read, a policy whose namespace nobody
/// projected cannot carry §31.1's namespace evidence, and `matchExpressions` is not evaluated
/// here — its `matchLabels` alone match *more* than the selector does, so a Pod an expression
/// excludes would arrive looking governed.
fn policy_selector(policy: &Object) -> Result<BTreeMap<String, String>, String> {
    if !is_policy(policy) {
        return Err(format!(
            "`{}` is not a NetworkPolicy, and reading `spec.podSelector` from it would assert a \
             policy nobody wrote",
            policy.gvk()
        ));
    }
    if policy.namespace().is_none() {
        return Err(
            "the policy states no `metadata.namespace`, and section 31.1 requires the namespace \
             as evidence on every policy edge"
                .to_owned(),
        );
    }
    let Some(selector) = policy.field("/spec/podSelector") else {
        return Err("the object states no `spec.podSelector`".to_owned());
    };
    if selector
        .get("matchExpressions")
        .and_then(Json::as_array)
        .is_some_and(|expressions| !expressions.is_empty())
    {
        return Err(
            "`spec.podSelector.matchExpressions` is not evaluated here, and its `matchLabels` \
             alone would match more than the selector does"
                .to_owned(),
        );
    }
    Ok(string_map(selector.get("matchLabels")))
}

/// The labels of `pod` that satisfy the selector, or [`None`] where the policy does not reach it.
///
/// An empty selector matches every Pod of the policy's namespace and contributes no matched
/// labels, because none decided.
fn selected_labels(
    selector: &BTreeMap<String, String>,
    pod: &Object,
    namespace: Option<&str>,
) -> Option<BTreeMap<String, String>> {
    if pod.namespace() != namespace {
        return None;
    }
    let mut matched = BTreeMap::new();
    for (key, wanted) in selector {
        if pod.label(key) != Some(wanted.as_str()) {
            return None;
        }
        matched.insert(key.clone(), wanted.clone());
    }
    Some(matched)
}

/// What rides beside a policy edge's selector: the namespace, the intent, and the empty selector.
///
/// The namespace is §31.1's other `MUST`, cited at the field that states it. The intent note is
/// §31.3: a NetworkPolicy object proves that somebody wrote a rule, never that the installed
/// networking implementation enforces it, and an edge read as observed traffic would report a
/// cluster running no policy controller as protected.
fn policy_evidence(policy: &Object, selector: &BTreeMap<String, String>) -> Vec<Evidence> {
    let mut supporting = vec![Evidence::NativeField {
        path: "/metadata/namespace".to_owned(),
        value: policy.namespace().unwrap_or_default().to_owned(),
    }];
    if selector.is_empty() {
        supporting.push(Evidence::Derived {
            rule: "an empty `spec.podSelector`, which the API defines as every Pod in the \
                   namespace"
                .to_owned(),
        });
    }
    supporting.push(Evidence::Derived {
        rule: "policy intent: the API server states this policy, and whether the installed \
               networking implementation enforces it is not observed"
            .to_owned(),
    });
    supporting
}

/// The edges a Pod's own spec states.
fn pod_edges(pod: &Object, source: &Identity, namespace: Option<&str>) -> Vec<Edge> {
    let mut edges = Vec::new();

    // A Node is cluster-scoped, so its edge carries no namespace; every other reference below is
    // namespace-local. Building the node edge on its own is what keeps that difference visible
    // rather than papering over it with the pod's namespace.
    //
    // It is also the one fact here that only a *Pod* states. `spec.nodeName` inside a controller's
    // template is a request for where Pods should go, and reading it through [`pod_spec_edges`]
    // would put a Deployment on a node (§28.1).
    if let Some(node) = pod.field("/spec/nodeName").and_then(Json::as_str) {
        edges.push(Edge::new(
            source.clone(),
            Relation::ScheduledOn,
            Target::new("Node", node).with_api_version(Some("v1")),
            Evidence::NativeField {
                path: "/spec/nodeName".to_owned(),
                value: node.to_owned(),
            },
        ));
    }
    if let Some(spec) = pod.field("/spec") {
        edges.extend(pod_spec_edges(source, namespace, spec, "/spec"));
    }

    edges
}

/// The edges any pod spec states, wherever that spec sits in its object (§29 to §32).
///
/// `base` is the JSON pointer the spec was read at, and every evidence path is built from it, so
/// the same rules serve a Pod at `/spec` and a controller's template at `/spec/template/spec`
/// while each edge still cites the field that decided it (Gate D). Duplicating the rules per
/// location is how the three container lists came to be one for so long.
pub(crate) fn pod_spec_edges(
    source: &Identity,
    namespace: Option<&str>,
    spec: &Json,
    base: &str,
) -> Vec<Edge> {
    let mut edges = Vec::new();

    if let Some(account) = spec.pointer("/serviceAccountName").and_then(Json::as_str) {
        edges.push(reference_edge(
            source,
            Relation::RunsAs,
            "ServiceAccount",
            namespace,
            account,
            &format!("{base}/serviceAccountName"),
        ));
    }
    // §22.4 and §32.1: the Secrets the kubelet pulls images with, in the same word a
    // ServiceAccount's pull secrets already use. A Pod that cannot pull its image is exactly the
    // object an operator asks about, and one vocabulary keeps the two ends of that answer joined.
    if let Some(entries) = spec.pointer("/imagePullSecrets").and_then(Json::as_array) {
        for (index, entry) in entries.iter().enumerate() {
            if let Some(name) = entry.get("name").and_then(Json::as_str) {
                edges.push(reference_edge(
                    source,
                    Relation::UsesImagePullSecret,
                    "Secret",
                    namespace,
                    name,
                    &format!("{base}/imagePullSecrets/{index}/name"),
                ));
            }
        }
    }

    if let Some(volumes) = spec.pointer("/volumes").and_then(Json::as_array) {
        for (index, volume) in volumes.iter().enumerate() {
            edges.extend(volume_edges(
                source,
                namespace,
                volume,
                &format!("{base}/volumes/{index}"),
            ));
        }
    }

    // §29.1's references are stated by every container list, not by `spec.containers` alone. A
    // Pod that cannot start because an init container's ConfigMap is missing would otherwise be
    // reported as a Pod that references no configuration.
    for list in ["containers", "initContainers", "ephemeralContainers"] {
        let Some(containers) = spec.pointer(&format!("/{list}")).and_then(Json::as_array) else {
            continue;
        };
        for (index, container) in containers.iter().enumerate() {
            edges.extend(container_edges(
                source,
                namespace,
                container,
                &format!("{base}/{list}/{index}"),
            ));
        }
    }

    edges
}

/// The objects one volume names, by its typed source (§30.1).
///
/// Typed rather than flattened, which is §30.1's own rule: an `emptyDir` and a `configMap` are
/// not one string with different contents. A source this provider has no rule for contributes
/// nothing, and that includes `serviceAccountToken` — the API server mints that token, so there
/// is no object for an edge to point at.
fn volume_edges(
    source: &Identity,
    namespace: Option<&str>,
    volume: &Json,
    base: &str,
) -> Vec<Edge> {
    let mut edges = Vec::new();

    if let Some(claim) = volume
        .pointer("/persistentVolumeClaim/claimName")
        .and_then(Json::as_str)
    {
        edges.push(reference_edge(
            source,
            Relation::Mounts,
            "PersistentVolumeClaim",
            namespace,
            claim,
            &format!("{base}/persistentVolumeClaim/claimName"),
        ));
    }
    if let Some(name) = volume.pointer("/configMap/name").and_then(Json::as_str) {
        edges.push(
            reference_edge(
                source,
                Relation::ReferencesConfig,
                "ConfigMap",
                namespace,
                name,
                &format!("{base}/configMap/name"),
            )
            .with_supporting(optional_evidence(
                volume.pointer("/configMap"),
                &format!("{base}/configMap"),
            )),
        );
    }
    if let Some(name) = volume.pointer("/secret/secretName").and_then(Json::as_str) {
        edges.push(
            reference_edge(
                source,
                Relation::ReferencesSecret,
                "Secret",
                namespace,
                name,
                &format!("{base}/secret/secretName"),
            )
            .with_supporting(optional_evidence(
                volume.pointer("/secret"),
                &format!("{base}/secret"),
            )),
        );
    }
    // A projected volume composes several sources under one mount, and §29.1 names the projected
    // ConfigMap source explicitly. A Secret projection carries `name` rather than `secretName`.
    if let Some(sources) = volume
        .pointer("/projected/sources")
        .and_then(Json::as_array)
    {
        for (position, projected) in sources.iter().enumerate() {
            let at = format!("{base}/projected/sources/{position}");
            if let Some(name) = projected.pointer("/configMap/name").and_then(Json::as_str) {
                edges.push(
                    reference_edge(
                        source,
                        Relation::ReferencesConfig,
                        "ConfigMap",
                        namespace,
                        name,
                        &format!("{at}/configMap/name"),
                    )
                    .with_supporting(optional_evidence(
                        projected.pointer("/configMap"),
                        &format!("{at}/configMap"),
                    )),
                );
            }
            if let Some(name) = projected.pointer("/secret/name").and_then(Json::as_str) {
                edges.push(
                    reference_edge(
                        source,
                        Relation::ReferencesSecret,
                        "Secret",
                        namespace,
                        name,
                        &format!("{at}/secret/name"),
                    )
                    .with_supporting(optional_evidence(
                        projected.pointer("/secret"),
                        &format!("{at}/secret"),
                    )),
                );
            }
        }
    }

    edges
}

/// The ConfigMaps and Secrets one container reads, and how it reads them (§29.1, §29.2).
fn container_edges(
    source: &Identity,
    namespace: Option<&str>,
    container: &Json,
    base: &str,
) -> Vec<Edge> {
    let mut edges = Vec::new();

    if let Some(from) = container.get("envFrom").and_then(Json::as_array) {
        for (position, entry) in from.iter().enumerate() {
            if let Some(name) = entry.pointer("/configMapRef/name").and_then(Json::as_str) {
                let at = format!("{base}/envFrom/{position}/configMapRef");
                edges.push(
                    reference_edge(
                        source,
                        Relation::ReferencesConfig,
                        "ConfigMap",
                        namespace,
                        name,
                        &format!("{at}/name"),
                    )
                    .with_supporting(optional_evidence(entry.pointer("/configMapRef"), &at)),
                );
            }
            if let Some(name) = entry.pointer("/secretRef/name").and_then(Json::as_str) {
                let at = format!("{base}/envFrom/{position}/secretRef");
                edges.push(
                    reference_edge(
                        source,
                        Relation::ReferencesSecret,
                        "Secret",
                        namespace,
                        name,
                        &format!("{at}/name"),
                    )
                    .with_supporting(optional_evidence(entry.pointer("/secretRef"), &at)),
                );
            }
        }
    }
    if let Some(env) = container.get("env").and_then(Json::as_array) {
        for (position, entry) in env.iter().enumerate() {
            if let Some(name) = entry
                .pointer("/valueFrom/configMapKeyRef/name")
                .and_then(Json::as_str)
            {
                let at = format!("{base}/env/{position}/valueFrom/configMapKeyRef");
                edges.push(
                    reference_edge(
                        source,
                        Relation::ReferencesConfig,
                        "ConfigMap",
                        namespace,
                        name,
                        &format!("{at}/name"),
                    )
                    .with_supporting(optional_evidence(
                        entry.pointer("/valueFrom/configMapKeyRef"),
                        &at,
                    )),
                );
            }
            if let Some(name) = entry
                .pointer("/valueFrom/secretKeyRef/name")
                .and_then(Json::as_str)
            {
                let at = format!("{base}/env/{position}/valueFrom/secretKeyRef");
                edges.push(
                    reference_edge(
                        source,
                        Relation::ReferencesSecret,
                        "Secret",
                        namespace,
                        name,
                        &format!("{at}/name"),
                    )
                    .with_supporting(optional_evidence(
                        entry.pointer("/valueFrom/secretKeyRef"),
                        &at,
                    )),
                );
            }
        }
    }

    edges
}

/// The `optional` flag beside a reference, as supporting evidence (§29.3).
///
/// Supporting rather than deciding: the flag does not make the reference exist, and it changes
/// what a missing target means — §29.3 says an absent optional target is not an error, and an
/// edge that dropped the flag would report a healthy Pod as a broken one. Absent when the object
/// carried no such field, because the default is not something the API server said.
fn optional_evidence(reference: Option<&Json>, base: &str) -> Vec<Evidence> {
    reference
        .and_then(|reference| reference.get("optional"))
        .and_then(Json::as_bool)
        .map(|optional| {
            vec![Evidence::NativeField {
                path: format!("{base}/optional"),
                value: optional.to_string(),
            }]
        })
        .unwrap_or_default()
}

/// The volume a claim states it is bound to (§30.2).
///
/// `spec.volumeName` is the binding, and a claim that names none is not bound to anything: §30.2
/// forbids treating a Pending claim as bound, so an absent or empty name produces no edge rather
/// than an edge to a volume nobody has. A PersistentVolume is cluster-scoped, so the claim's
/// namespace does not travel onto the target (§9.2, §24.2).
fn claim_edges(claim: &Object, source: &Identity) -> Vec<Edge> {
    let mut edges = storage_class_edge(claim, source);
    let Some(volume) = claim
        .field("/spec/volumeName")
        .and_then(Json::as_str)
        .filter(|name| !name.is_empty())
    else {
        return edges;
    };
    // §30.2's "relevant status fields": the phase qualifies the binding without deciding it, so a
    // claim whose spec names a volume the control plane has not confirmed still says so.
    let phase = claim
        .field("/status/phase")
        .and_then(Json::as_str)
        .map(|phase| {
            vec![Evidence::NativeField {
                path: "/status/phase".to_owned(),
                value: phase.to_owned(),
            }]
        })
        .unwrap_or_default();
    edges.push(
        Edge::new(
            source.clone(),
            Relation::BoundTo,
            Target::new("PersistentVolume", volume).with_api_version(Some("v1")),
            Evidence::NativeField {
                path: "/spec/volumeName".to_owned(),
                value: volume.to_owned(),
            },
        )
        .with_supporting(phase),
    );
    edges
}

/// The class a claim or a volume names, where it names one (§30.1, §30.3).
///
/// Three states the field keeps apart, and only one of them is an edge. A name is the class.
/// **The empty string is not**: `storageClassName: ""` is Kubernetes' way of saying *no class,
/// do not provision dynamically*, and an edge there would point at a StorageClass whose name is
/// the empty string. **Absent is not either**: it means the cluster's default class applies, and
/// which class that is, is a fact about the cluster rather than about this object — reading it
/// here would be an inference presented as a native field (§23.5, §4 invariant 20).
///
/// A StorageClass is cluster-scoped, so the target carries no namespace (§9.2).
fn storage_class_edge(object: &Object, source: &Identity) -> Vec<Edge> {
    let Some(class) = object
        .field("/spec/storageClassName")
        .and_then(Json::as_str)
        .filter(|name| !name.is_empty())
    else {
        return Vec::new();
    };
    vec![Edge::new(
        source.clone(),
        Relation::UsesStorageClass,
        Target::new("StorageClass", class).with_api_version(Some("storage.k8s.io/v1")),
        Evidence::NativeField {
            path: "/spec/storageClassName".to_owned(),
            value: class.to_owned(),
        },
    )]
}

fn reference_edge(
    source: &Identity,
    relation: Relation,
    kind: &str,
    namespace: Option<&str>,
    name: &str,
    path: &str,
) -> Edge {
    Edge::new(
        source.clone(),
        relation,
        Target::new(kind, name)
            .with_api_version(Some("v1"))
            .in_namespace(namespace),
        Evidence::NativeField {
            path: path.to_owned(),
            value: name.to_owned(),
        },
    )
}

/// The `apiVersion` string an object would carry, rebuilt from its GVK.
///
/// Rebuilt rather than read back from the document, so that an object assembled from a watch
/// event or a table row carries the same target descriptor as one read whole.
fn api_version_of(object: &Object) -> String {
    let gvk = object.gvk();
    if gvk.group().is_empty() {
        gvk.version().to_owned()
    } else {
        format!("{}/{}", gvk.group(), gvk.version())
    }
}

fn string_map(value: Option<&Json>) -> BTreeMap<String, String> {
    let Some(map) = value.and_then(Json::as_object) else {
        return BTreeMap::new();
    };
    map.iter()
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
        .collect()
}

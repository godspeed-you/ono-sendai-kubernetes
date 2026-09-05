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
    /// The source reads configuration from the target (§29.1).
    ReferencesConfig,
    /// The source reads a secret from the target (§29.2).
    ReferencesSecret,
    /// The source ServiceAccount carries the target Secret in `secrets` (§22.4).
    UsesSecret,
    /// The source pulls images with the target Secret (§22.4, §32.1).
    UsesImagePullSecret,
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
            Self::SelectorMatches => "selector-matches",
            Self::UsesService => "uses-service",
            Self::RepresentedBy => "represented-by",
            Self::EndpointFor => "endpoint-for",
            Self::RoutesTo => "routes-to",
            Self::UsesTlsSecret => "uses-tls-secret",
            Self::UsesIngressClass => "uses-ingress-class",
            Self::AttachesTo => "attaches-to",
            Self::UsesGatewayClass => "uses-gateway-class",
            Self::RunsAs => "runs-as",
            Self::Mounts => "mounts",
            Self::BoundTo => "bound-to",
            Self::ReferencesConfig => "references-config",
            Self::ReferencesSecret => "references-secret",
            Self::UsesSecret => "uses-secret",
            Self::UsesImagePullSecret => "uses-image-pull-secret",
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

        if object.gvk().kind() == "Pod" {
            edges.extend(pod_edges(object, &source, namespace.as_deref()));
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
}

/// The edges a Pod's own spec states.
fn pod_edges(pod: &Object, source: &Identity, namespace: Option<&str>) -> Vec<Edge> {
    let mut edges = Vec::new();

    // A Node is cluster-scoped, so its edge carries no namespace; every other reference below is
    // namespace-local. Building the node edge on its own is what keeps that difference visible
    // rather than papering over it with the pod's namespace.
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
    if let Some(account) = pod.field("/spec/serviceAccountName").and_then(Json::as_str) {
        edges.push(reference_edge(
            source,
            Relation::RunsAs,
            "ServiceAccount",
            namespace,
            account,
            "/spec/serviceAccountName",
        ));
    }

    if let Some(volumes) = pod.field("/spec/volumes").and_then(Json::as_array) {
        for (index, volume) in volumes.iter().enumerate() {
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
                    &format!("/spec/volumes/{index}/persistentVolumeClaim/claimName"),
                ));
            }
            if let Some(name) = volume.pointer("/configMap/name").and_then(Json::as_str) {
                edges.push(reference_edge(
                    source,
                    Relation::ReferencesConfig,
                    "ConfigMap",
                    namespace,
                    name,
                    &format!("/spec/volumes/{index}/configMap/name"),
                ));
            }
            if let Some(name) = volume.pointer("/secret/secretName").and_then(Json::as_str) {
                edges.push(reference_edge(
                    source,
                    Relation::ReferencesSecret,
                    "Secret",
                    namespace,
                    name,
                    &format!("/spec/volumes/{index}/secret/secretName"),
                ));
            }
        }
    }

    if let Some(containers) = pod.field("/spec/containers").and_then(Json::as_array) {
        for (index, container) in containers.iter().enumerate() {
            let base = format!("/spec/containers/{index}");
            if let Some(from) = container.get("envFrom").and_then(Json::as_array) {
                for (position, entry) in from.iter().enumerate() {
                    if let Some(name) = entry.pointer("/configMapRef/name").and_then(Json::as_str) {
                        edges.push(reference_edge(
                            source,
                            Relation::ReferencesConfig,
                            "ConfigMap",
                            namespace,
                            name,
                            &format!("{base}/envFrom/{position}/configMapRef/name"),
                        ));
                    }
                    if let Some(name) = entry.pointer("/secretRef/name").and_then(Json::as_str) {
                        edges.push(reference_edge(
                            source,
                            Relation::ReferencesSecret,
                            "Secret",
                            namespace,
                            name,
                            &format!("{base}/envFrom/{position}/secretRef/name"),
                        ));
                    }
                }
            }
            if let Some(env) = container.get("env").and_then(Json::as_array) {
                for (position, entry) in env.iter().enumerate() {
                    if let Some(name) = entry
                        .pointer("/valueFrom/configMapKeyRef/name")
                        .and_then(Json::as_str)
                    {
                        edges.push(reference_edge(
                            source,
                            Relation::ReferencesConfig,
                            "ConfigMap",
                            namespace,
                            name,
                            &format!("{base}/env/{position}/valueFrom/configMapKeyRef/name"),
                        ));
                    }
                    if let Some(name) = entry
                        .pointer("/valueFrom/secretKeyRef/name")
                        .and_then(Json::as_str)
                    {
                        edges.push(reference_edge(
                            source,
                            Relation::ReferencesSecret,
                            "Secret",
                            namespace,
                            name,
                            &format!("{base}/env/{position}/valueFrom/secretKeyRef/name"),
                        ));
                    }
                }
            }
        }
    }

    edges
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

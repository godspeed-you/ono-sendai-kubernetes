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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Relation {
    /// The source is owned by the target (`metadata.ownerReferences`).
    OwnedBy,
    /// The source is owned by the target, which is its controller (§24.3).
    ControlledBy,
    /// The source Pod is placed on the target Node (`spec.nodeName`).
    ScheduledOn,
    /// The source Service selects the target by labels (§26.1).
    Selects,
    /// The source Pod runs under the target ServiceAccount (§32.1).
    RunsAs,
    /// The source mounts the target claim (§30.1).
    Mounts,
    /// The source reads configuration from the target (§29.1).
    ReferencesConfig,
    /// The source reads a secret from the target (§29.2).
    ReferencesSecret,
}

impl Relation {
    /// The word a user types after `follow`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnedBy => "owned-by",
            Self::ControlledBy => "controlled-by",
            Self::ScheduledOn => "scheduled-on",
            Self::Selects => "selects",
            Self::RunsAs => "runs-as",
            Self::Mounts => "mounts",
            Self::ReferencesConfig => "references-config",
            Self::ReferencesSecret => "references-secret",
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

/// One relationship, with its evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    source: Identity,
    relation: Relation,
    target: Target,
    evidence: Evidence,
}

impl Edge {
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
            let target = Target {
                kind: owner.kind().to_owned(),
                api_version: Some(owner.api_version().to_owned()),
                // An owner reference is namespace-local for a namespaced dependent (§24.2).
                namespace: namespace.clone(),
                name: owner.name().to_owned(),
                uid: Some(owner.uid().to_owned()),
                resolved: None,
            };
            let evidence = Evidence::OwnerReference {
                controller: owner.is_controller(),
            };
            edges.push(Edge {
                source: source.clone(),
                relation: Relation::OwnedBy,
                target: target.clone(),
                evidence: evidence.clone(),
            });
            if owner.is_controller() {
                edges.push(Edge {
                    source: source.clone(),
                    relation: Relation::ControlledBy,
                    target,
                    evidence,
                });
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
                Some(Edge {
                    source: source.clone(),
                    relation: Relation::Selects,
                    target: Target {
                        kind: pod.gvk().kind().to_owned(),
                        api_version: Some(pod.gvk().version().to_owned()),
                        namespace: pod.namespace().map(str::to_owned),
                        name: pod.name().to_owned(),
                        uid: pod.uid().map(str::to_owned),
                        resolved: Some(pod.identity()),
                    },
                    evidence: Evidence::Selector {
                        selector: selector.clone(),
                        matched_labels: matched,
                    },
                })
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
        edges.push(Edge {
            source: source.clone(),
            relation: Relation::ScheduledOn,
            target: Target {
                kind: "Node".to_owned(),
                api_version: Some("v1".to_owned()),
                namespace: None,
                name: node.to_owned(),
                uid: None,
                resolved: None,
            },
            evidence: Evidence::NativeField {
                path: "/spec/nodeName".to_owned(),
                value: node.to_owned(),
            },
        });
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
    Edge {
        source: source.clone(),
        relation,
        target: Target {
            kind: kind.to_owned(),
            api_version: Some("v1".to_owned()),
            namespace: namespace.map(str::to_owned),
            name: name.to_owned(),
            uid: None,
            resolved: None,
        },
        evidence: Evidence::NativeField {
            path: path.to_owned(),
            value: name.to_owned(),
        },
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

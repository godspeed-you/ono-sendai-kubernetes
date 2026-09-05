//! Workload controllers, services and routing: the curated path from a URL to a Node.
//!
//! Specification §25 to §27 and §30. What this module exists for is one traversal —
//! `Ingress -> Service -> EndpointSlice -> Pod -> Node` — because that is the path an operator
//! walks when a URL stops answering, and walking it by hand across five `kubectl` invocations is
//! where the guessing starts.
//!
//! Every step is a separate edge with its own [`Evidence`], never a shortcut. A shortcut from
//! Ingress to Pod would be unanswerable at exactly the hop that usually breaks, and Gate D
//! (§62.4) requires each edge to say what it read to decide.
//!
//! Three distinctions are load-bearing here, and all three are places where a plausible
//! simplification would produce a confident falsehood:
//!
//! - **An owner reference is proof; a selector match is not** (§23.2 against §23.3). A
//!   Deployment's selector matches ReplicaSets it does not control. [`Workload::owns`] answers
//!   what is actually controlled and [`Workload::selector_matches`] answers what merely fits,
//!   and they are different functions returning differently labelled edges on purpose.
//! - **A template is not an object** (§25.3). `volumeClaimTemplates` describes claims that may
//!   never have been provisioned, so it comes back as [`ClaimTemplate`] intent rather than as
//!   storage edges.
//! - **Absence is not evidence** (§25.5, §26.4, §27.3). A Job that history limits deleted, an
//!   endpoint with no Pod behind it, and a cluster without the Gateway API installed are three
//!   different silences, and none of them is filled in here.
//!
//! # Relation vocabulary
//!
//! [`WorkloadRelation`] is a second relation enum beside [`crate::relationship::Relation`]
//! because these curated relations — `owns`, `routes-to`, `represented-by` — did not exist there
//! yet. Merging the two into one vocabulary is a follow-up; two enums naming relationships is one
//! more than a user should ever see.

use std::collections::BTreeMap;

use serde_json::Value as Json;

use crate::object::{Identity, Object};
use crate::relationship::Evidence;

/// The well-known label by which an EndpointSlice names the Service it belongs to (§26.2).
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// The API group the Gateway API is served under, when a cluster serves it at all (§27.3).
const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";

/// The Gateway API versions whose field layout this adapter has actually seen (§27.3, §5.3).
const KNOWN_GATEWAY_VERSIONS: [&str; 3] = ["v1alpha2", "v1beta1", "v1"];

/// A curated relationship among workloads, services and routes.
///
/// Deliberately distinct from a selector match: `Owns` says a controller's mark is on the child,
/// `SelectorMatches` says two label sets agree. Collapsing them would let a canary ReplicaSet
/// read as one its neighbour controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkloadRelation {
    /// The target's `metadata.ownerReferences` names the source (§25.1).
    Owns,
    /// As [`Self::Owns`], and the source is the target's controller (§24.3).
    Controls,
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
}

impl WorkloadRelation {
    /// The word a user types after `follow`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owns => "owns",
            Self::Controls => "controls",
            Self::SelectorMatches => "selector-matches",
            Self::UsesService => "uses-service",
            Self::RepresentedBy => "represented-by",
            Self::EndpointFor => "endpoint-for",
            Self::RoutesTo => "routes-to",
            Self::UsesTlsSecret => "uses-tls-secret",
            Self::UsesIngressClass => "uses-ingress-class",
            Self::AttachesTo => "attaches-to",
            Self::UsesGatewayClass => "uses-gateway-class",
        }
    }
}

/// Where a workload edge points.
///
/// A descriptor rather than an identity, for the same reason as
/// [`crate::relationship::Target`]: an edge to an object nobody has read is a relationship whose
/// far end is unexamined, and that is a different thing from a broken edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadTarget {
    kind: String,
    api_version: Option<String>,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
    resolved: Option<Identity>,
}

impl WorkloadTarget {
    /// The target's kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The target's `apiVersion`, where the reference carried or implied one.
    #[must_use]
    pub fn api_version(&self) -> Option<&str> {
        self.api_version.as_deref()
    }

    /// The namespace the target lives in, absent where it is cluster-scoped.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The target's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The target's UID, where something stated it.
    #[must_use]
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }

    /// Whether the target object was actually read.
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

/// One curated relationship, with the evidence that decided it and the evidence that qualifies it.
///
/// The split between the two matters for routing. `Ingress -> Service` is decided by the backend
/// service name, and the host, path and port are what make the edge worth walking: §27.1 requires
/// them to stay attached, because "which Service" without "for which URL" answers a question
/// nobody asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadEdge {
    source: Identity,
    relation: WorkloadRelation,
    target: WorkloadTarget,
    evidence: Evidence,
    supporting: Vec<Evidence>,
}

impl WorkloadEdge {
    /// The object the relationship starts at.
    #[must_use]
    pub fn source(&self) -> &Identity {
        &self.source
    }

    /// What the relationship is.
    #[must_use]
    pub fn relation(&self) -> WorkloadRelation {
        self.relation
    }

    /// Where it points.
    #[must_use]
    pub fn target(&self) -> &WorkloadTarget {
        &self.target
    }

    /// What decided it (Gate D).
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

/// The outcome of evaluating a workload controller's selector (§23.3).
///
/// Two outcomes rather than one list, because "nothing matched" and "this selector was not
/// evaluated" are different answers and an empty `Vec` says the first while meaning the second.
/// The same distinction §21.4 draws for a denied read: absence of results is not a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorMatch {
    /// The selector was evaluated in full against every candidate offered.
    Evaluated(Vec<WorkloadEdge>),
    /// The selector was not evaluated, and no candidate may be presumed excluded.
    NotEvaluated {
        /// What stopped it, in the words of the field that stopped it.
        reason: String,
    },
}

/// A `volumeClaimTemplate` a StatefulSet declares: intent, not a claim (§25.3).
///
/// Kept as its own type rather than as an edge so that it cannot be mistaken for storage that
/// exists. The materialised claims are reachable the honest way — through the Pods that mount
/// them, where `spec.volumes[].persistentVolumeClaim.claimName` states the link (§30.1). The
/// claim's *name* is predictable from the template, and predicting it is name similarity, which
/// §23.5 forbids promoting to a relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimTemplate {
    name: String,
    storage_class: Option<String>,
    requested_storage: Option<String>,
    access_modes: Vec<String>,
    evidence: Evidence,
}

impl ClaimTemplate {
    /// The template's name, which prefixes the claims the controller will create.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The StorageClass the template asks for, where it names one.
    #[must_use]
    pub fn storage_class(&self) -> Option<&str> {
        self.storage_class.as_deref()
    }

    /// The storage the template requests, as the quantity string the object carries.
    #[must_use]
    pub fn requested_storage(&self) -> Option<&str> {
        self.requested_storage.as_deref()
    }

    /// The access modes the template asks for.
    #[must_use]
    pub fn access_modes(&self) -> &[String] {
        &self.access_modes
    }

    /// Which field this template was read from (Gate D).
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

/// The Jobs a CronJob owns *right now*, and the limits that decide what is missing (§25.5).
///
/// The reason this is not a bare `Vec` is that the list is systematically incomplete: a CronJob
/// keeps a few successes and fewer failures, and everything older was deleted without leaving a
/// trace in the API. Reporting the survivors as the run history is how a job that failed four
/// nights running reads as one that never ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobHistory {
    observed: Vec<WorkloadEdge>,
    successful_history_limit: Option<i64>,
    failed_history_limit: Option<i64>,
}

impl JobHistory {
    /// The ownership edges to the Jobs that still exist.
    #[must_use]
    pub fn observed(&self) -> &[WorkloadEdge] {
        &self.observed
    }

    /// Those same edges, owned.
    #[must_use]
    pub fn into_observed(self) -> Vec<WorkloadEdge> {
        self.observed
    }

    /// `spec.successfulJobsHistoryLimit`, where the object states it.
    #[must_use]
    pub fn successful_history_limit(&self) -> Option<i64> {
        self.successful_history_limit
    }

    /// `spec.failedJobsHistoryLimit`, where the object states it.
    #[must_use]
    pub fn failed_history_limit(&self) -> Option<i64> {
        self.failed_history_limit
    }

    /// Whether these Jobs are the CronJob's whole history — always unknown.
    ///
    /// `None` rather than `false`, and never `true`. A deleted Job left nothing behind to count,
    /// so the question cannot be answered from the live graph at all, and §25.5 forbids
    /// reconstructing the absence without evidence. Unknown is null (AGENTS.md §6); a later
    /// caller holding Event or audit evidence can answer it, and this module cannot.
    #[must_use]
    pub fn is_complete(&self) -> Option<bool> {
        None
    }
}

/// One endpoint of an EndpointSlice, whether or not a Pod stands behind it (§26.4).
///
/// An endpoint with no `targetRef` is an externally managed backend: a database, a VM, something
/// outside the cluster. It stays an endpoint fact. Dropping it would understate the Service, and
/// attaching it to a Pod chosen by address would be the inference §23.5 forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    addresses: Vec<String>,
    ready: Option<bool>,
    pod: Option<WorkloadEdge>,
}

impl Endpoint {
    /// The addresses this endpoint serves, in the slice's `addressType`.
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    /// `conditions.ready`, absent when the slice does not state it.
    ///
    /// An unstated readiness is unknown rather than ready: §26 leaves the condition optional, and
    /// defaulting it to `true` would report an endpoint as serving on no evidence.
    #[must_use]
    pub fn is_ready(&self) -> Option<bool> {
        self.ready
    }

    /// The edge to the object behind this endpoint, where `targetRef` resolves.
    #[must_use]
    pub fn pod_edge(&self) -> Option<&WorkloadEdge> {
        self.pod.as_ref()
    }

    /// Whether a target reference stood behind this endpoint at all.
    #[must_use]
    pub fn has_target(&self) -> bool {
        self.pod.is_some()
    }
}

/// The curated workload, service and routing relationships (§25 to §27).
///
/// Pure functions over objects already read. Nothing here performs I/O, so nothing here can turn
/// "not fetched" into "not there" — the caller decides what to offer as candidates and therefore
/// owns the scope of every answer (§9.4).
pub struct Workload;

impl Workload {
    /// The children among `candidates` whose owner references name `owner` (§25.1).
    ///
    /// Matched by UID, never by name. A Deployment deleted and recreated under the same name is a
    /// second lifetime (§16.3), and a name match would hand the new one the old one's children
    /// while erasing the discontinuity that made the difference visible.
    ///
    /// An owner without a UID yields nothing: there is then no proof to match on, and §16.5 says
    /// such an object falls back to a locator, which cannot carry ownership.
    ///
    /// Both `owns` and `controls` come back for a controller reference, mirroring §24.3 and
    /// [`crate::relationship::Graph::edges_of`], so a caller wanting all ownership does not have
    /// to know which of the two words to ask for.
    #[must_use]
    pub fn owns(owner: &Object, candidates: &[Object]) -> Vec<WorkloadEdge> {
        let Some(owner_uid) = owner.uid() else {
            return Vec::new();
        };
        let source = owner.identity();
        let mut edges = Vec::new();

        for child in candidates {
            // §24.2: a namespaced dependent's owner lives in its own namespace. A cluster-scoped
            // owner may own across namespaces, so only a namespaced owner constrains the child.
            if owner.namespace().is_some() && child.namespace() != owner.namespace() {
                continue;
            }
            for reference in child.owner_references() {
                if reference.uid() != owner_uid || reference.kind() != owner.gvk().kind() {
                    continue;
                }
                let target = target_of(child);
                let evidence = Evidence::OwnerReference {
                    controller: reference.is_controller(),
                };
                // The record lives on the child; this edge reads it the other way round, and
                // says so rather than letting the direction pass as something the owner states.
                let supporting = vec![Evidence::Derived {
                    rule: format!(
                        "owner-reference reversal: {}/{} metadata.ownerReferences names uid \
                         {owner_uid}",
                        child.gvk().kind(),
                        child.name()
                    ),
                }];
                edges.push(WorkloadEdge {
                    source: source.clone(),
                    relation: WorkloadRelation::Owns,
                    target: target.clone(),
                    evidence: evidence.clone(),
                    supporting: supporting.clone(),
                });
                if reference.is_controller() {
                    edges.push(WorkloadEdge {
                        source: source.clone(),
                        relation: WorkloadRelation::Controls,
                        target,
                        evidence,
                        supporting,
                    });
                }
            }
        }
        edges
    }

    /// The candidates a workload controller's `spec.selector` matches (§23.3, §25.1).
    ///
    /// Weaker than ownership and separately labelled for it. A Deployment's selector matches the
    /// canary ReplicaSet next to it, the leftover from a failed migration and anything a human
    /// labelled by hand; none of those is controlled by it.
    ///
    /// Only `matchLabels` is evaluated. A selector carrying `matchExpressions` comes back as
    /// [`SelectorMatch::NotEvaluated`] rather than as its `matchLabels` subset, because that
    /// subset is *wider* than the selector: an object an expression excludes would arrive looking
    /// selected.
    #[must_use]
    pub fn selector_matches(controller: &Object, candidates: &[Object]) -> SelectorMatch {
        let Some(selector) = controller.field("/spec/selector") else {
            return SelectorMatch::NotEvaluated {
                reason: "the object states no `spec.selector`".to_owned(),
            };
        };
        if selector
            .get("matchExpressions")
            .and_then(Json::as_array)
            .is_some_and(|expressions| !expressions.is_empty())
        {
            return SelectorMatch::NotEvaluated {
                reason: "`spec.selector.matchExpressions` is not evaluated here, and its \
                         `matchLabels` alone would match more than the selector does"
                    .to_owned(),
            };
        }
        let labels = string_map(selector.get("matchLabels"));
        if labels.is_empty() {
            return SelectorMatch::NotEvaluated {
                reason: "`spec.selector.matchLabels` is empty, and an empty selector is not a \
                         match on everything"
                    .to_owned(),
            };
        }

        let source = controller.identity();
        let edges = candidates
            .iter()
            .filter(|candidate| candidate.namespace() == controller.namespace())
            .filter_map(|candidate| {
                let mut matched = BTreeMap::new();
                for (key, wanted) in &labels {
                    if candidate.label(key) != Some(wanted.as_str()) {
                        return None;
                    }
                    matched.insert(key.clone(), wanted.clone());
                }
                Some(WorkloadEdge {
                    source: source.clone(),
                    relation: WorkloadRelation::SelectorMatches,
                    target: target_of(candidate),
                    evidence: Evidence::Selector {
                        selector: labels.clone(),
                        matched_labels: matched,
                    },
                    supporting: Vec::new(),
                })
            })
            .collect();
        SelectorMatch::Evaluated(edges)
    }

    /// The Service a StatefulSet names as its governing Service (§25.3).
    ///
    /// `spec.serviceName` states it. The headless Service usually shares the set's name, and
    /// deriving it from that resemblance would be right often enough to be trusted and wrong
    /// exactly where a cluster is unusual.
    #[must_use]
    pub fn governing_service(statefulset: &Object) -> Option<WorkloadEdge> {
        let name = statefulset
            .field("/spec/serviceName")
            .and_then(Json::as_str)
            .filter(|name| !name.is_empty())?;
        Some(WorkloadEdge {
            source: statefulset.identity(),
            relation: WorkloadRelation::UsesService,
            target: WorkloadTarget {
                kind: "Service".to_owned(),
                api_version: Some("v1".to_owned()),
                namespace: statefulset.namespace().map(str::to_owned),
                name: name.to_owned(),
                uid: None,
                resolved: None,
            },
            evidence: Evidence::NativeField {
                path: "/spec/serviceName".to_owned(),
                value: name.to_owned(),
            },
            supporting: Vec::new(),
        })
    }

    /// The claim templates a StatefulSet declares (§25.3).
    ///
    /// Intent, and typed as intent. See [`ClaimTemplate`] for why these are not edges.
    #[must_use]
    pub fn volume_claim_templates(statefulset: &Object) -> Vec<ClaimTemplate> {
        let Some(templates) = statefulset
            .field("/spec/volumeClaimTemplates")
            .and_then(Json::as_array)
        else {
            return Vec::new();
        };
        templates
            .iter()
            .enumerate()
            .filter_map(|(index, template)| {
                let name = template.pointer("/metadata/name").and_then(Json::as_str)?;
                Some(ClaimTemplate {
                    name: name.to_owned(),
                    storage_class: text(template, "/spec/storageClassName"),
                    requested_storage: text(template, "/spec/resources/requests/storage"),
                    access_modes: template
                        .pointer("/spec/accessModes")
                        .and_then(Json::as_array)
                        .map(|modes| {
                            modes
                                .iter()
                                .filter_map(|mode| mode.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                    evidence: Evidence::NativeField {
                        path: format!("/spec/volumeClaimTemplates/{index}/metadata/name"),
                        value: name.to_owned(),
                    },
                })
            })
            .collect()
    }

    /// The Jobs a CronJob owns among `jobs`, with the history limits that bound the answer
    /// (§25.5).
    #[must_use]
    pub fn job_history(cronjob: &Object, jobs: &[Object]) -> JobHistory {
        JobHistory {
            observed: Self::owns(cronjob, jobs),
            successful_history_limit: cronjob
                .field("/spec/successfulJobsHistoryLimit")
                .and_then(Json::as_i64),
            failed_history_limit: cronjob
                .field("/spec/failedJobsHistoryLimit")
                .and_then(Json::as_i64),
        }
    }

    /// The EndpointSlices representing a Service, by the standard service-name label (§26.2).
    ///
    /// The label is a convention rather than API structure, and the edge says so: an operator can
    /// relabel a slice, and a reader deciding how much to trust the edge needs to know that the
    /// evidence is a label rather than a field the API server maintains as structure.
    ///
    /// One edge per slice. §26.3 keeps every slice first-class, so aggregation is a view a caller
    /// may build and never something this function does on their behalf — folding them together
    /// would lose which slice is stale and which controller wrote it.
    #[must_use]
    pub fn endpoint_slices(service: &Object, slices: &[Object]) -> Vec<WorkloadEdge> {
        let source = service.identity();
        slices
            .iter()
            // The label is namespace-local evidence; two namespaces routinely hold a Service of
            // the same name (§24.2).
            .filter(|slice| slice.namespace() == service.namespace())
            .filter(|slice| slice.label(SERVICE_NAME_LABEL) == Some(service.name()))
            .map(|slice| WorkloadEdge {
                source: source.clone(),
                relation: WorkloadRelation::RepresentedBy,
                target: target_of(slice),
                evidence: Evidence::Convention {
                    key: SERVICE_NAME_LABEL.to_owned(),
                    value: service.name().to_owned(),
                },
                supporting: Vec::new(),
            })
            .collect()
    }

    /// The endpoints an EndpointSlice carries, each with its backing object where one is named
    /// (§26.2, §26.4).
    #[must_use]
    pub fn endpoints(slice: &Object) -> Vec<Endpoint> {
        let Some(endpoints) = slice.field("/endpoints").and_then(Json::as_array) else {
            return Vec::new();
        };
        let source = slice.identity();
        endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| Endpoint {
                addresses: endpoint
                    .get("addresses")
                    .and_then(Json::as_array)
                    .map(|list| {
                        list.iter()
                            .filter_map(|address| address.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
                ready: endpoint
                    .pointer("/conditions/ready")
                    .and_then(Json::as_bool),
                pod: endpoint_target(endpoint, index, slice, &source),
            })
            .collect()
    }

    /// The routing relationships an Ingress states (§27.1, §27.2).
    ///
    /// Every routing edge carries the host, path and port that produced it, because §27.1
    /// requires that evidence to stay attached: "which Service" without "for which URL" is not
    /// the question anyone walks this edge to ask.
    #[must_use]
    pub fn ingress_edges(ingress: &Object) -> Vec<WorkloadEdge> {
        let source = ingress.identity();
        let namespace = ingress.namespace().map(str::to_owned);
        let mut edges = Vec::new();

        if let Some(class) = ingress
            .field("/spec/ingressClassName")
            .and_then(Json::as_str)
        {
            edges.push(WorkloadEdge {
                source: source.clone(),
                relation: WorkloadRelation::UsesIngressClass,
                target: WorkloadTarget {
                    kind: "IngressClass".to_owned(),
                    api_version: Some(api_version_of(ingress)),
                    // Cluster-scoped: copying the Ingress's namespace onto it would name
                    // something that cannot be looked up (§9.5).
                    namespace: None,
                    name: class.to_owned(),
                    uid: None,
                    resolved: None,
                },
                evidence: Evidence::NativeField {
                    path: "/spec/ingressClassName".to_owned(),
                    value: class.to_owned(),
                },
                supporting: Vec::new(),
            });
        }

        if let Some(entries) = ingress.field("/spec/tls").and_then(Json::as_array) {
            for (index, entry) in entries.iter().enumerate() {
                let Some(secret) = entry.get("secretName").and_then(Json::as_str) else {
                    continue;
                };
                let hosts = entry
                    .get("hosts")
                    .and_then(Json::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let supporting = hosts
                    .iter()
                    .enumerate()
                    .filter_map(|(position, host)| {
                        Some(Evidence::NativeField {
                            path: format!("/spec/tls/{index}/hosts/{position}"),
                            value: host.as_str()?.to_owned(),
                        })
                    })
                    .collect();
                edges.push(WorkloadEdge {
                    source: source.clone(),
                    relation: WorkloadRelation::UsesTlsSecret,
                    target: WorkloadTarget {
                        kind: "Secret".to_owned(),
                        api_version: Some("v1".to_owned()),
                        namespace: namespace.clone(),
                        name: secret.to_owned(),
                        uid: None,
                        resolved: None,
                    },
                    evidence: Evidence::NativeField {
                        path: format!("/spec/tls/{index}/secretName"),
                        value: secret.to_owned(),
                    },
                    supporting,
                });
            }
        }

        if let Some(edge) = backend_edge(
            ingress,
            &source,
            namespace.as_deref(),
            "/spec/defaultBackend",
            Vec::new(),
        ) {
            edges.push(edge);
        }

        if let Some(rules) = ingress.field("/spec/rules").and_then(Json::as_array) {
            for (rule_index, rule) in rules.iter().enumerate() {
                let mut host_evidence = Vec::new();
                if let Some(host) = rule.get("host").and_then(Json::as_str) {
                    host_evidence.push(Evidence::NativeField {
                        path: format!("/spec/rules/{rule_index}/host"),
                        value: host.to_owned(),
                    });
                }
                let Some(paths) = rule.pointer("/http/paths").and_then(Json::as_array) else {
                    continue;
                };
                for (path_index, path) in paths.iter().enumerate() {
                    let base = format!("/spec/rules/{rule_index}/http/paths/{path_index}");
                    let mut supporting = host_evidence.clone();
                    for field in ["path", "pathType"] {
                        if let Some(value) = path.get(field).and_then(Json::as_str) {
                            supporting.push(Evidence::NativeField {
                                path: format!("{base}/{field}"),
                                value: value.to_owned(),
                            });
                        }
                    }
                    if let Some(edge) = backend_edge(
                        ingress,
                        &source,
                        namespace.as_deref(),
                        &format!("{base}/backend"),
                        supporting,
                    ) {
                        edges.push(edge);
                    }
                }
            }
        }

        edges
    }

    /// The Gateway API relationships an object states, when it is a Gateway API object at all
    /// (§27.3).
    ///
    /// Nothing about this adapter is assumed to exist. A cluster without the Gateway API installed
    /// simply never presents an object this function recognises, and every other relationship in
    /// this module works unchanged — §27.3 forbids hard-coding its presence into the provider.
    ///
    /// A version this adapter has not seen yields no edges. The field names of a future version
    /// are not known to mean what today's mean (§5.3), and the object stays fully available
    /// through universal dynamic support (§15.1), which is where an unknown schema belongs.
    #[must_use]
    pub fn gateway_edges(object: &Object) -> Vec<WorkloadEdge> {
        let gvk = object.gvk();
        if gvk.group() != GATEWAY_GROUP || !KNOWN_GATEWAY_VERSIONS.contains(&gvk.version()) {
            return Vec::new();
        }
        let api_version = api_version_of(object);
        let adapter = Evidence::Derived {
            rule: format!("curated Gateway API adapter for {api_version}"),
        };
        let source = object.identity();
        let namespace = object.namespace().map(str::to_owned);
        let mut edges = Vec::new();

        match gvk.kind() {
            "Gateway" => {
                if let Some(class) = object
                    .field("/spec/gatewayClassName")
                    .and_then(Json::as_str)
                {
                    edges.push(WorkloadEdge {
                        source,
                        relation: WorkloadRelation::UsesGatewayClass,
                        target: WorkloadTarget {
                            kind: "GatewayClass".to_owned(),
                            api_version: Some(api_version),
                            namespace: None,
                            name: class.to_owned(),
                            uid: None,
                            resolved: None,
                        },
                        evidence: Evidence::NativeField {
                            path: "/spec/gatewayClassName".to_owned(),
                            value: class.to_owned(),
                        },
                        supporting: vec![adapter],
                    });
                }
            }
            "HTTPRoute" | "GRPCRoute" => {
                if let Some(parents) = object.field("/spec/parentRefs").and_then(Json::as_array) {
                    for (index, parent) in parents.iter().enumerate() {
                        if let Some(edge) = reference_edge(
                            &source,
                            WorkloadRelation::AttachesTo,
                            parent,
                            "Gateway",
                            Some(&api_version),
                            namespace.as_deref(),
                            &format!("/spec/parentRefs/{index}"),
                            vec![adapter.clone()],
                        ) {
                            edges.push(edge);
                        }
                    }
                }
                if let Some(rules) = object.field("/spec/rules").and_then(Json::as_array) {
                    for (rule_index, rule) in rules.iter().enumerate() {
                        let Some(backends) = rule.get("backendRefs").and_then(Json::as_array)
                        else {
                            continue;
                        };
                        for (backend_index, backend) in backends.iter().enumerate() {
                            if let Some(edge) = reference_edge(
                                &source,
                                WorkloadRelation::RoutesTo,
                                backend,
                                "Service",
                                Some("v1"),
                                namespace.as_deref(),
                                &format!("/spec/rules/{rule_index}/backendRefs/{backend_index}"),
                                vec![adapter.clone()],
                            ) {
                                edges.push(edge);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        edges
    }
}

/// The edge to whatever stands behind one endpoint, where the slice names it (§26.2).
///
/// `None` where no `targetRef` is present. §26.4 keeps such an endpoint an endpoint fact: an
/// externally managed backend is real, and choosing a Pod for it by address would be inference.
fn endpoint_target(
    endpoint: &Json,
    index: usize,
    slice: &Object,
    source: &Identity,
) -> Option<WorkloadEdge> {
    let reference = endpoint.get("targetRef")?;
    let name = reference.get("name").and_then(Json::as_str)?;
    Some(WorkloadEdge {
        source: source.clone(),
        relation: WorkloadRelation::EndpointFor,
        target: WorkloadTarget {
            kind: reference
                .get("kind")
                .and_then(Json::as_str)
                .unwrap_or("Pod")
                .to_owned(),
            api_version: reference
                .get("apiVersion")
                .and_then(Json::as_str)
                .map(str::to_owned),
            namespace: reference
                .get("namespace")
                .and_then(Json::as_str)
                .map(str::to_owned)
                .or_else(|| slice.namespace().map(str::to_owned)),
            name: name.to_owned(),
            // The UID is what makes this step provable rather than a name match, so it is
            // carried through even though nothing here resolved the Pod itself.
            uid: reference
                .get("uid")
                .and_then(Json::as_str)
                .map(str::to_owned),
            resolved: None,
        },
        evidence: Evidence::NativeField {
            path: format!("/endpoints/{index}/targetRef/name"),
            value: name.to_owned(),
        },
        supporting: Vec::new(),
    })
}

/// The routing edge one Ingress backend states, with the port riding along as evidence.
fn backend_edge(
    ingress: &Object,
    source: &Identity,
    namespace: Option<&str>,
    pointer: &str,
    mut supporting: Vec<Evidence>,
) -> Option<WorkloadEdge> {
    let backend = ingress.field(pointer)?;
    let name = backend.pointer("/service/name").and_then(Json::as_str)?;
    if let Some(number) = backend
        .pointer("/service/port/number")
        .and_then(Json::as_i64)
    {
        supporting.push(Evidence::NativeField {
            path: format!("{pointer}/service/port/number"),
            value: number.to_string(),
        });
    }
    if let Some(port) = backend.pointer("/service/port/name").and_then(Json::as_str) {
        supporting.push(Evidence::NativeField {
            path: format!("{pointer}/service/port/name"),
            value: port.to_owned(),
        });
    }
    Some(WorkloadEdge {
        source: source.clone(),
        relation: WorkloadRelation::RoutesTo,
        target: WorkloadTarget {
            kind: "Service".to_owned(),
            api_version: Some("v1".to_owned()),
            // An Ingress backend is namespace-local; there is no cross-namespace form of it.
            namespace: namespace.map(str::to_owned),
            name: name.to_owned(),
            uid: None,
            resolved: None,
        },
        evidence: Evidence::NativeField {
            path: format!("{pointer}/service/name"),
            value: name.to_owned(),
        },
        supporting,
    })
}

/// One Gateway API `*Ref`: a name, with kind, group and namespace defaulted the way the API
/// defaults them.
///
/// The namespace default is the referring object's own, which is why it is passed in rather than
/// assumed: a `parentRef` may name a Gateway in another namespace, and silently localising it
/// would point the edge at a different Gateway that happens to share the name.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct fact the reference needs defaulted; bundling them into \
              a struct used at two call sites would hide rather than clarify"
)]
fn reference_edge(
    source: &Identity,
    relation: WorkloadRelation,
    reference: &Json,
    default_kind: &str,
    default_api_version: Option<&str>,
    default_namespace: Option<&str>,
    pointer: &str,
    supporting: Vec<Evidence>,
) -> Option<WorkloadEdge> {
    let name = reference.get("name").and_then(Json::as_str)?;
    Some(WorkloadEdge {
        source: source.clone(),
        relation,
        target: WorkloadTarget {
            kind: reference
                .get("kind")
                .and_then(Json::as_str)
                .unwrap_or(default_kind)
                .to_owned(),
            api_version: default_api_version.map(str::to_owned),
            namespace: reference
                .get("namespace")
                .and_then(Json::as_str)
                .map(str::to_owned)
                .or_else(|| default_namespace.map(str::to_owned)),
            name: name.to_owned(),
            uid: None,
            resolved: None,
        },
        evidence: Evidence::NativeField {
            path: format!("{pointer}/name"),
            value: name.to_owned(),
        },
        supporting,
    })
}

/// A target descriptor for an object that was actually read, so the edge carries its identity.
fn target_of(object: &Object) -> WorkloadTarget {
    WorkloadTarget {
        kind: object.gvk().kind().to_owned(),
        api_version: Some(api_version_of(object)),
        namespace: object.namespace().map(str::to_owned),
        name: object.name().to_owned(),
        uid: object.uid().map(str::to_owned),
        resolved: Some(object.identity()),
    }
}

/// The `apiVersion` string an object would carry, rebuilt from its GVK.
fn api_version_of(object: &Object) -> String {
    let gvk = object.gvk();
    if gvk.group().is_empty() {
        gvk.version().to_owned()
    } else {
        format!("{}/{}", gvk.group(), gvk.version())
    }
}

fn text(value: &Json, pointer: &str) -> Option<String> {
    value.pointer(pointer)?.as_str().map(str::to_owned)
}

fn string_map(value: Option<&Json>) -> BTreeMap<String, String> {
    let Some(map) = value.and_then(Json::as_object) else {
        return BTreeMap::new();
    };
    map.iter()
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
        .collect()
}

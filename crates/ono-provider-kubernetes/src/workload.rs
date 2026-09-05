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
//! One vocabulary, in [`crate::relationship`]. These relations — `owns`, `routes-to`,
//! `represented-by` — are curated in the sense that this module knows which fields to read for
//! them, not in the sense that they are a second kind of relationship: an [`Edge`] from here is
//! the same value an owner reference produces, and a user follows it by the same word.

use std::collections::BTreeMap;

use serde_json::Value as Json;

use crate::object::{Identity, Object};
use crate::relationship::{Edge, Evidence, Relation, Target};

/// The well-known label by which an EndpointSlice names the Service it belongs to (§26.2).
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// The API group the Gateway API is served under, when a cluster serves it at all (§27.3).
const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";

/// The Gateway API versions whose field layout this adapter has actually seen (§27.3, §5.3).
const KNOWN_GATEWAY_VERSIONS: [&str; 3] = ["v1alpha2", "v1beta1", "v1"];

/// The outcome of evaluating a workload controller's selector (§23.3).
///
/// Two outcomes rather than one list, because "nothing matched" and "this selector was not
/// evaluated" are different answers and an empty `Vec` says the first while meaning the second.
/// The same distinction §21.4 draws for a denied read: absence of results is not a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorMatch {
    /// The selector was evaluated in full against every candidate offered.
    Evaluated(Vec<Edge>),
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
    observed: Vec<Edge>,
    successful_history_limit: Option<i64>,
    failed_history_limit: Option<i64>,
}

impl JobHistory {
    /// The ownership edges to the Jobs that still exist.
    #[must_use]
    pub fn observed(&self) -> &[Edge] {
        &self.observed
    }

    /// Those same edges, owned.
    #[must_use]
    pub fn into_observed(self) -> Vec<Edge> {
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
    pod: Option<Edge>,
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
    pub fn pod_edge(&self) -> Option<&Edge> {
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
    pub fn owns(owner: &Object, candidates: &[Object]) -> Vec<Edge> {
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
                let target = Target::of_object(child);
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
                edges.push(
                    Edge::new(
                        source.clone(),
                        Relation::Owns,
                        target.clone(),
                        evidence.clone(),
                    )
                    .with_supporting(supporting.clone()),
                );
                if reference.is_controller() {
                    edges.push(
                        Edge::new(source.clone(), Relation::Controls, target, evidence)
                            .with_supporting(supporting),
                    );
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
                Some(Edge::new(
                    source.clone(),
                    Relation::SelectorMatches,
                    Target::of_object(candidate),
                    Evidence::Selector {
                        selector: labels.clone(),
                        matched_labels: matched,
                    },
                ))
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
    pub fn governing_service(statefulset: &Object) -> Option<Edge> {
        let name = statefulset
            .field("/spec/serviceName")
            .and_then(Json::as_str)
            .filter(|name| !name.is_empty())?;
        Some(Edge::new(
            statefulset.identity(),
            Relation::UsesService,
            Target::new("Service", name)
                .with_api_version(Some("v1"))
                .in_namespace(statefulset.namespace()),
            Evidence::NativeField {
                path: "/spec/serviceName".to_owned(),
                value: name.to_owned(),
            },
        ))
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
    pub fn endpoint_slices(service: &Object, slices: &[Object]) -> Vec<Edge> {
        let source = service.identity();
        slices
            .iter()
            // The label is namespace-local evidence; two namespaces routinely hold a Service of
            // the same name (§24.2).
            .filter(|slice| slice.namespace() == service.namespace())
            .filter(|slice| slice.label(SERVICE_NAME_LABEL) == Some(service.name()))
            .map(|slice| {
                Edge::new(
                    source.clone(),
                    Relation::RepresentedBy,
                    Target::of_object(slice),
                    Evidence::Convention {
                        key: SERVICE_NAME_LABEL.to_owned(),
                        value: service.name().to_owned(),
                    },
                )
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
    pub fn ingress_edges(ingress: &Object) -> Vec<Edge> {
        let source = ingress.identity();
        let namespace = ingress.namespace().map(str::to_owned);
        let mut edges = Vec::new();

        if let Some(class) = ingress
            .field("/spec/ingressClassName")
            .and_then(Json::as_str)
        {
            edges.push(Edge::new(
                source.clone(),
                Relation::UsesIngressClass,
                // Cluster-scoped, so no namespace: copying the Ingress's onto it would name
                // something that cannot be looked up (§9.5).
                Target::new("IngressClass", class).with_api_version(Some(&api_version_of(ingress))),
                Evidence::NativeField {
                    path: "/spec/ingressClassName".to_owned(),
                    value: class.to_owned(),
                },
            ));
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
                edges.push(
                    Edge::new(
                        source.clone(),
                        Relation::UsesTlsSecret,
                        Target::new("Secret", secret)
                            .with_api_version(Some("v1"))
                            .in_namespace(namespace.as_deref()),
                        Evidence::NativeField {
                            path: format!("/spec/tls/{index}/secretName"),
                            value: secret.to_owned(),
                        },
                    )
                    .with_supporting(supporting),
                );
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
    pub fn gateway_edges(object: &Object) -> Vec<Edge> {
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
                    edges.push(
                        Edge::new(
                            source,
                            Relation::UsesGatewayClass,
                            Target::new("GatewayClass", class).with_api_version(Some(&api_version)),
                            Evidence::NativeField {
                                path: "/spec/gatewayClassName".to_owned(),
                                value: class.to_owned(),
                            },
                        )
                        .with_supporting(vec![adapter]),
                    );
                }
            }
            "HTTPRoute" | "GRPCRoute" => {
                if let Some(parents) = object.field("/spec/parentRefs").and_then(Json::as_array) {
                    for (index, parent) in parents.iter().enumerate() {
                        if let Some(edge) = reference_edge(
                            &source,
                            Relation::AttachesTo,
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
                                Relation::RoutesTo,
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
) -> Option<Edge> {
    let reference = endpoint.get("targetRef")?;
    let name = reference.get("name").and_then(Json::as_str)?;
    let kind = reference
        .get("kind")
        .and_then(Json::as_str)
        .unwrap_or("Pod");
    Some(Edge::new(
        source.clone(),
        Relation::EndpointFor,
        Target::new(kind, name)
            .with_api_version(reference.get("apiVersion").and_then(Json::as_str))
            .in_namespace(
                reference
                    .get("namespace")
                    .and_then(Json::as_str)
                    .or_else(|| slice.namespace()),
            )
            // The UID is what makes this step provable rather than a name match, so it is
            // carried through even though nothing here resolved the Pod itself.
            .with_uid(reference.get("uid").and_then(Json::as_str)),
        Evidence::NativeField {
            path: format!("/endpoints/{index}/targetRef/name"),
            value: name.to_owned(),
        },
    ))
}

/// The routing edge one Ingress backend states, with the port riding along as evidence.
fn backend_edge(
    ingress: &Object,
    source: &Identity,
    namespace: Option<&str>,
    pointer: &str,
    mut supporting: Vec<Evidence>,
) -> Option<Edge> {
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
    Some(
        Edge::new(
            source.clone(),
            Relation::RoutesTo,
            Target::new("Service", name)
                .with_api_version(Some("v1"))
                // An Ingress backend is namespace-local; there is no cross-namespace form of it.
                .in_namespace(namespace),
            Evidence::NativeField {
                path: format!("{pointer}/service/name"),
                value: name.to_owned(),
            },
        )
        .with_supporting(supporting),
    )
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
    relation: Relation,
    reference: &Json,
    default_kind: &str,
    default_api_version: Option<&str>,
    default_namespace: Option<&str>,
    pointer: &str,
    supporting: Vec<Evidence>,
) -> Option<Edge> {
    let name = reference.get("name").and_then(Json::as_str)?;
    let kind = reference
        .get("kind")
        .and_then(Json::as_str)
        .unwrap_or(default_kind);
    Some(
        Edge::new(
            source.clone(),
            relation,
            Target::new(kind, name)
                .with_api_version(default_api_version)
                .in_namespace(
                    reference
                        .get("namespace")
                        .and_then(Json::as_str)
                        .or(default_namespace),
                ),
            Evidence::NativeField {
                path: format!("{pointer}/name"),
                value: name.to_owned(),
            },
        )
        .with_supporting(supporting),
    )
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

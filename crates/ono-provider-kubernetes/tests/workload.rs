//! Workload controllers, services and routing — the curated path an operator actually walks.
//!
//! Specification §25 to §27 and §30. The path these tests hold open is
//! `Ingress -> Service -> EndpointSlice -> Pod -> Node`: the question "why is this URL broken"
//! is answered by walking it, and every step of it must be a relationship a user can check
//! rather than one this provider asserts on their behalf (Gate D, §62.4).
//!
//! Two lines run through nearly every test here. **An owner reference is proof and a selector
//! match is not** (§23.2 against §23.3): a Deployment's selector matches ReplicaSets it does not
//! control, so the two must never collapse into one edge. And **absence is not evidence**
//! (§25.5, §26.4, §27.3): a Job that history limits removed, an endpoint with no Pod behind it
//! and a cluster without Gateway API installed are three different silences, and none of them
//! may be filled in.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::relationship::{Edge, Evidence, Graph, Relation};
use ono_provider_kubernetes::workload::{SelectorMatch, Workload};

const DEPLOYMENT: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"checkout","namespace":"shop","uid":"dep-1","resourceVersion":"11"},
  "spec":{"selector":{"matchLabels":{"app":"checkout"}},
          "template":{"metadata":{"labels":{"app":"checkout"}}}}
}"#;

const REPLICASET: &str = r#"{
  "apiVersion":"apps/v1","kind":"ReplicaSet",
  "metadata":{"name":"checkout-6ac1","namespace":"shop","uid":"rs-1",
    "labels":{"app":"checkout","pod-template-hash":"6ac1"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"Deployment","name":"checkout","uid":"dep-1",
       "controller":true}
    ]},
  "spec":{"selector":{"matchLabels":{"app":"checkout","pod-template-hash":"6ac1"}}}
}"#;

/// Labelled like the Deployment's own children, owned by a different Deployment.
const ADOPTED_ELSEWHERE_REPLICASET: &str = r#"{
  "apiVersion":"apps/v1","kind":"ReplicaSet",
  "metadata":{"name":"checkout-canary","namespace":"shop","uid":"rs-2",
    "labels":{"app":"checkout","pod-template-hash":"9de2"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"Deployment","name":"checkout-canary","uid":"dep-2",
       "controller":true}
    ]},
  "spec":{}
}"#;

/// The same owner *name* as the live Deployment, a different owner UID: a previous lifetime.
const STALE_REPLICASET: &str = r#"{
  "apiVersion":"apps/v1","kind":"ReplicaSet",
  "metadata":{"name":"checkout-1aa0","namespace":"shop","uid":"rs-0",
    "labels":{"app":"checkout"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"Deployment","name":"checkout","uid":"dep-0",
       "controller":true}
    ]},
  "spec":{}
}"#;

const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"checkout-6ac1-x7","namespace":"shop","uid":"pod-1",
    "labels":{"app":"checkout","pod-template-hash":"6ac1"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"ReplicaSet","name":"checkout-6ac1","uid":"rs-1",
       "controller":true}
    ]},
  "spec":{"nodeName":"ip-10-42-2-19"}
}"#;

const EXPRESSION_SELECTED_DEPLOYMENT: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"batch","namespace":"shop","uid":"dep-3"},
  "spec":{"selector":{"matchLabels":{"app":"batch"},
          "matchExpressions":[{"key":"tier","operator":"In","values":["web","api"]}]}}
}"#;

const STATEFULSET: &str = r#"{
  "apiVersion":"apps/v1","kind":"StatefulSet",
  "metadata":{"name":"web","namespace":"shop","uid":"sts-1"},
  "spec":{
    "serviceName":"web-headless",
    "selector":{"matchLabels":{"app":"web"}},
    "volumeClaimTemplates":[
      {"metadata":{"name":"data"},
       "spec":{"storageClassName":"fast","accessModes":["ReadWriteOnce"],
               "resources":{"requests":{"storage":"10Gi"}}}}
    ]}
}"#;

/// Named exactly as the StatefulSet controller would name it, owned by nothing.
const CONVENTION_NAMED_CLAIM: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{"name":"data-web-0","namespace":"shop","uid":"pvc-1"},
  "spec":{"volumeName":"pv-9"}
}"#;

const DAEMONSET: &str = r#"{
  "apiVersion":"apps/v1","kind":"DaemonSet",
  "metadata":{"name":"log-agent","namespace":"shop","uid":"ds-1"},
  "spec":{"selector":{"matchLabels":{"app":"log-agent"}}}
}"#;

const DAEMONSET_POD_A: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"log-agent-aa","namespace":"shop","uid":"pod-a",
    "labels":{"app":"log-agent"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"DaemonSet","name":"log-agent","uid":"ds-1",
       "controller":true}
    ]},
  "spec":{"nodeName":"ip-10-42-2-19"}
}"#;

const DAEMONSET_POD_B: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"log-agent-bb","namespace":"shop","uid":"pod-b",
    "labels":{"app":"log-agent"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"DaemonSet","name":"log-agent","uid":"ds-1",
       "controller":true}
    ]},
  "spec":{"nodeName":"ip-10-42-3-4"}
}"#;

const CRONJOB: &str = r#"{
  "apiVersion":"batch/v1","kind":"CronJob",
  "metadata":{"name":"nightly","namespace":"shop","uid":"cj-1"},
  "spec":{"schedule":"0 2 * * *","successfulJobsHistoryLimit":3,"failedJobsHistoryLimit":1}
}"#;

const JOB: &str = r#"{
  "apiVersion":"batch/v1","kind":"Job",
  "metadata":{"name":"nightly-28001","namespace":"shop","uid":"job-1",
    "ownerReferences":[
      {"apiVersion":"batch/v1","kind":"CronJob","name":"nightly","uid":"cj-1",
       "controller":true}
    ]},
  "spec":{}
}"#;

const SERVICE: &str = r#"{
  "apiVersion":"v1","kind":"Service",
  "metadata":{"name":"checkout","namespace":"shop","uid":"svc-1"},
  "spec":{"type":"ClusterIP","selector":{"app":"checkout"},
          "ports":[{"name":"http","port":80,"targetPort":8080}]}
}"#;

const SLICE_ONE: &str = r#"{
  "apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice",
  "metadata":{"name":"checkout-abc","namespace":"shop","uid":"eps-1",
    "labels":{"kubernetes.io/service-name":"checkout"}},
  "addressType":"IPv4",
  "endpoints":[
    {"addresses":["10.1.0.7"],"conditions":{"ready":true},
     "targetRef":{"kind":"Pod","name":"checkout-6ac1-x7","namespace":"shop","uid":"pod-1"}}
  ],
  "ports":[{"name":"http","port":8080,"protocol":"TCP"}]
}"#;

const SLICE_TWO: &str = r#"{
  "apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice",
  "metadata":{"name":"checkout-def","namespace":"shop","uid":"eps-2",
    "labels":{"kubernetes.io/service-name":"checkout"}},
  "addressType":"IPv4",
  "endpoints":[
    {"addresses":["203.0.113.9"],"conditions":{"ready":true}}
  ],
  "ports":[{"name":"http","port":8080,"protocol":"TCP"}]
}"#;

const OTHER_NAMESPACE_SLICE: &str = r#"{
  "apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice",
  "metadata":{"name":"checkout-xyz","namespace":"other","uid":"eps-3",
    "labels":{"kubernetes.io/service-name":"checkout"}},
  "addressType":"IPv4","endpoints":[]
}"#;

const INGRESS: &str = r#"{
  "apiVersion":"networking.k8s.io/v1","kind":"Ingress",
  "metadata":{"name":"shop","namespace":"shop","uid":"ing-1"},
  "spec":{
    "ingressClassName":"nginx",
    "tls":[{"hosts":["shop.example.com"],"secretName":"shop-tls"}],
    "rules":[
      {"host":"shop.example.com",
       "http":{"paths":[
         {"path":"/checkout","pathType":"Prefix",
          "backend":{"service":{"name":"checkout","port":{"number":80}}}}
       ]}}
    ]}
}"#;

const HTTPROUTE: &str = r#"{
  "apiVersion":"gateway.networking.k8s.io/v1","kind":"HTTPRoute",
  "metadata":{"name":"shop","namespace":"shop","uid":"route-1"},
  "spec":{
    "parentRefs":[{"name":"public","namespace":"gateways"}],
    "rules":[{"backendRefs":[{"name":"checkout","port":80}]}]}
}"#;

const GATEWAY: &str = r#"{
  "apiVersion":"gateway.networking.k8s.io/v1","kind":"Gateway",
  "metadata":{"name":"public","namespace":"gateways","uid":"gw-1"},
  "spec":{"gatewayClassName":"istio"}
}"#;

const FUTURE_HTTPROUTE: &str = r#"{
  "apiVersion":"gateway.networking.k8s.io/v99","kind":"HTTPRoute",
  "metadata":{"name":"tomorrow","namespace":"shop","uid":"route-2"},
  "spec":{"parentRefs":[{"name":"public"}]}
}"#;

fn object(json: &str) -> Object {
    Object::parse("kubernetes:prod", json).expect("the fixture reads")
}

fn edges_to(edges: &[Edge], relation: Relation) -> Vec<&Edge> {
    edges
        .iter()
        .filter(|edge| edge.relation() == relation)
        .collect()
}

#[test]
fn should_own_the_children_whose_owner_reference_names_it() {
    // §25.1: "The owner-reference chain is canonical for actual controlled ReplicaSets." The
    // downward step has to be as checkable as the upward one, or the Deployment -> ReplicaSet
    // -> Pod path is only walkable from the bottom.
    let deployment = object(DEPLOYMENT);
    let candidates = [object(REPLICASET), object(ADOPTED_ELSEWHERE_REPLICASET)];
    let edges = Workload::owns(&deployment, &candidates);

    let owned: Vec<&str> = edges
        .iter()
        .filter(|edge| edge.relation() == Relation::Owns)
        .map(|edge| edge.target().name())
        .collect();
    assert_eq!(owned, vec!["checkout-6ac1"]);
    let edge = &edges[0];
    assert_eq!(edge.target().uid(), Some("rs-1"));
    assert!(
        edge.target().is_resolved(),
        "the child was read, so the edge knows its identity rather than only its name"
    );
    match edge.evidence() {
        Evidence::OwnerReference { controller } => assert!(*controller),
        other => panic!("ownership comes from ownerReferences, got {other:?}"),
    }
}

#[test]
fn should_not_promote_a_selector_match_to_ownership() {
    // §25.1 against §23.3: a Deployment's selector matches ReplicaSets some other controller
    // owns — a canary, a leftover, a hand-made object. Presenting that match as control is the
    // mistake this separation exists to prevent, so the two answers come back separately
    // labelled and carry different evidence classes.
    let deployment = object(DEPLOYMENT);
    let canary = object(ADOPTED_ELSEWHERE_REPLICASET);
    let candidates = [canary];

    assert!(
        Workload::owns(&deployment, &candidates).is_empty(),
        "a label match is not an owner reference"
    );

    let SelectorMatch::Evaluated(matches) = Workload::selector_matches(&deployment, &candidates)
    else {
        panic!("a matchLabels-only selector is evaluable");
    };
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].relation(), Relation::SelectorMatches);
    match matches[0].evidence() {
        Evidence::Selector {
            selector,
            matched_labels,
        } => {
            assert_eq!(selector.get("app").map(String::as_str), Some("checkout"));
            assert_eq!(
                matched_labels.get("app").map(String::as_str),
                Some("checkout")
            );
            assert!(
                !matched_labels.contains_key("pod-template-hash"),
                "only the labels that decided are evidence"
            );
        }
        other => panic!("a selector match is selector-derived, got {other:?}"),
    }
    assert!(
        !matches[0].evidence().is_asserted_by_provider(),
        "the API server stated a selector and some labels; this provider did the matching"
    );
}

#[test]
fn should_not_own_a_child_that_names_the_same_owner_name_with_a_different_uid() {
    // §16.1 and §4 invariant 4: a Deployment deleted and recreated under the same name is a
    // second lifetime. Matching owner references by name would hand the new Deployment the old
    // one's ReplicaSets and quietly erase the discontinuity.
    let deployment = object(DEPLOYMENT);
    let stale = [object(STALE_REPLICASET)];
    assert!(
        Workload::owns(&deployment, &stale).is_empty(),
        "same owner name, different owner UID, different lifetime"
    );
}

#[test]
fn should_label_the_controller_edge_beside_the_generic_ownership_edge() {
    // §24.3 and §25.2: `controller: true` earns the stronger word, and the generic ownership
    // survives beside it so a caller asking for everything an object owns does not have to know
    // which of the two words to ask for.
    let replicaset = object(REPLICASET);
    let edges = Workload::owns(&replicaset, &[object(POD)]);

    assert!(
        edges
            .iter()
            .any(|edge| edge.relation() == Relation::Controls),
        "the ReplicaSet controls the Pod"
    );
    assert!(
        edges.iter().any(|edge| edge.relation() == Relation::Owns),
        "and owns it"
    );
}

#[test]
fn should_not_evaluate_a_selector_it_cannot_read_in_full() {
    // §23.3: a selector-derived edge names the selector it evaluated. `matchExpressions` are not
    // evaluated here, and answering with the matchLabels subset would report a wider match than
    // the controller's own selector describes — a Pod excluded by an expression would arrive
    // looking selected. Silence with a reason, not a partial answer dressed as a full one.
    let deployment = object(EXPRESSION_SELECTED_DEPLOYMENT);
    let pod = object(POD);
    match Workload::selector_matches(&deployment, std::slice::from_ref(&pod)) {
        SelectorMatch::NotEvaluated { reason } => {
            assert!(
                reason.contains("matchExpressions"),
                "the reason names what stopped it, got {reason}"
            );
        }
        SelectorMatch::Evaluated(_) => {
            panic!("a selector with matchExpressions was not fully evaluated here")
        }
    }
}

#[test]
fn should_resolve_the_governing_service_of_a_statefulset_from_the_field_that_names_it() {
    // §25.3: `spec.serviceName` states the headless Service, so the edge is a native field and
    // says which one it read. Deriving it from the StatefulSet's name would be a guess that
    // happens to be right in the common case.
    let statefulset = object(STATEFULSET);
    let edge = Workload::governing_service(&statefulset).expect("serviceName resolves");

    assert_eq!(edge.relation(), Relation::UsesService);
    assert_eq!(edge.target().kind(), "Service");
    assert_eq!(edge.target().name(), "web-headless");
    assert_eq!(
        edge.target().namespace(),
        Some("shop"),
        "the governing Service is namespace-local"
    );
    match edge.evidence() {
        Evidence::NativeField { path, value } => {
            assert_eq!(path, "/spec/serviceName");
            assert_eq!(value, "web-headless");
        }
        other => panic!("serviceName is a native field, got {other:?}"),
    }
}

#[test]
fn should_keep_a_volume_claim_template_as_intent_rather_than_as_a_claim() {
    // §25.3: "The provider MUST distinguish template intent from currently materialized PVC
    // objects." A template is a recipe. Reading `volumeClaimTemplates` as a list of claims
    // reports storage that may never have been provisioned.
    let statefulset = object(STATEFULSET);
    let templates = Workload::volume_claim_templates(&statefulset);

    assert_eq!(templates.len(), 1);
    let template = &templates[0];
    assert_eq!(template.name(), "data");
    assert_eq!(template.storage_class(), Some("fast"));
    assert_eq!(template.requested_storage(), Some("10Gi"));
    match template.evidence() {
        Evidence::NativeField { path, .. } => {
            assert_eq!(path, "/spec/volumeClaimTemplates/0/metadata/name");
        }
        other => panic!("a template is read from a field, got {other:?}"),
    }
}

#[test]
fn should_not_relate_a_statefulset_to_a_claim_that_merely_follows_the_naming_convention() {
    // §25.3 with §23.5: the StatefulSet controller names claims `<template>-<set>-<ordinal>`
    // and sets no owner reference on them. Reconstructing the link from the name is name
    // similarity, which "MUST NOT be promoted to verified relationships". The materialised
    // claim is reachable through the Pod that mounts it, where a field states it.
    let statefulset = object(STATEFULSET);
    let claim = object(CONVENTION_NAMED_CLAIM);
    assert!(
        Workload::owns(&statefulset, std::slice::from_ref(&claim)).is_empty(),
        "`data-web-0` looks like this set's claim and nothing observed says it is"
    );
}

#[test]
fn should_traverse_a_daemonset_to_the_nodes_its_pods_cover() {
    // §25.4: `DaemonSet -> Pod -> Node` is what makes rollout coverage answerable — which nodes
    // have a pod of this set and which do not. The two steps stay separate edges with their own
    // evidence rather than one synthesised DaemonSet-to-Node edge.
    let daemonset = object(DAEMONSET);
    let pods = [object(DAEMONSET_POD_A), object(DAEMONSET_POD_B)];
    let owned = Workload::owns(&daemonset, &pods);

    let mut covered: Vec<String> = Vec::new();
    for edge in edges_to(&owned, Relation::Owns) {
        let pod = pods
            .iter()
            .find(|candidate| candidate.name() == edge.target().name())
            .expect("the edge points at a pod that was read");
        for node in Graph::edges_of(pod)
            .iter()
            .filter(|hop| hop.relation() == Relation::ScheduledOn)
        {
            covered.push(node.target().name().to_owned());
        }
    }
    covered.sort();
    assert_eq!(covered, vec!["ip-10-42-2-19", "ip-10-42-3-4"]);
}

#[test]
fn should_not_claim_a_complete_job_history_for_a_cronjob() {
    // §25.5: "Job history limits and deleted children mean the live graph may be incomplete.
    // Historical absence MUST not be reconstructed without evidence." Reporting the Jobs that
    // exist as *the* run history is how a nightly job that failed four nights ago reads as one
    // that never ran. Unknown is null, never false and never zero.
    let cronjob = object(CRONJOB);
    let history = Workload::job_history(&cronjob, &[object(JOB)]);

    assert_eq!(history.observed().len(), 2, "owns and controls");
    assert_eq!(history.observed()[0].target().name(), "nightly-28001");
    assert_eq!(history.successful_history_limit(), Some(3));
    assert_eq!(history.failed_history_limit(), Some(1));
    assert_eq!(
        history.is_complete(),
        None,
        "whether a Job was deleted is unknown, and unknown is null"
    );
}

#[test]
fn should_relate_a_service_to_its_slices_through_the_service_name_label() {
    // §26.2: the relationship "SHOULD use the standard service-name label when present and
    // preserve that evidence". It is a convention rather than API structure, and saying so is
    // what lets a reader know an operator could break it by relabelling.
    let service = object(SERVICE);
    let edges = Workload::endpoint_slices(&service, &[object(SLICE_ONE)]);

    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].relation(), Relation::RepresentedBy);
    assert_eq!(edges[0].target().kind(), "EndpointSlice");
    match edges[0].evidence() {
        Evidence::Convention { key, value } => {
            assert_eq!(key, "kubernetes.io/service-name");
            assert_eq!(value, "checkout");
        }
        other => panic!("the service-name label is a convention, got {other:?}"),
    }
    assert_eq!(edges[0].evidence().class(), "convention");
}

#[test]
fn should_keep_every_slice_first_class_rather_than_merging_them() {
    // §26.3: "each EndpointSlice remains a first-class resource with its own identity and
    // freshness". A Service over ~100 endpoints has several slices, and folding them into one
    // aggregate loses which slice is stale and which controller wrote it.
    let service = object(SERVICE);
    let edges = Workload::endpoint_slices(&service, &[object(SLICE_ONE), object(SLICE_TWO)]);

    let uids: Vec<Option<&str>> = edges.iter().map(|edge| edge.target().uid()).collect();
    assert_eq!(uids, vec![Some("eps-1"), Some("eps-2")]);
}

#[test]
fn should_not_relate_a_slice_from_another_namespace() {
    // §26.2 with §24.2: the service-name label is only meaningful inside its namespace. Two
    // namespaces routinely hold a Service of the same name.
    let service = object(SERVICE);
    let edges = Workload::endpoint_slices(&service, &[object(OTHER_NAMESPACE_SLICE)]);
    assert!(edges.is_empty(), "the label is namespace-local evidence");
}

#[test]
fn should_relate_an_endpoint_to_its_pod_only_when_the_target_reference_resolves() {
    // §26.2: "EndpointSlice -> endpoint-for -> Pod when targetRef resolves". The UID in the
    // reference is what makes this step provable rather than an address correlation.
    let slice = object(SLICE_ONE);
    let endpoints = Workload::endpoints(&slice);

    assert_eq!(endpoints.len(), 1);
    let edge = endpoints[0].pod_edge().expect("the targetRef names a Pod");
    assert_eq!(edge.relation(), Relation::EndpointFor);
    assert_eq!(edge.target().kind(), "Pod");
    assert_eq!(edge.target().name(), "checkout-6ac1-x7");
    assert_eq!(edge.target().uid(), Some("pod-1"));
    match edge.evidence() {
        Evidence::NativeField { path, value } => {
            assert_eq!(path, "/endpoints/0/targetRef/name");
            assert_eq!(value, "checkout-6ac1-x7");
        }
        other => panic!("a targetRef is a native field, got {other:?}"),
    }
}

#[test]
fn should_keep_an_endpoint_without_a_pod_target_as_an_endpoint_fact() {
    // §26.4: endpoints without Pod target references "MUST remain endpoint facts rather than
    // being forced into Pod relationships". An externally managed backend is a real endpoint;
    // inventing a Pod for it, or dropping it because no Pod fits, both misreport the Service.
    let slice = object(SLICE_TWO);
    let endpoints = Workload::endpoints(&slice);

    assert_eq!(endpoints.len(), 1);
    assert!(
        endpoints[0].pod_edge().is_none(),
        "no targetRef, no Pod relationship"
    );
    assert_eq!(endpoints[0].addresses(), ["203.0.113.9"]);
    assert_eq!(
        endpoints[0].is_ready(),
        Some(true),
        "the endpoint's own facts survive having no Pod behind them"
    );
}

#[test]
fn should_attach_host_path_and_port_evidence_to_a_routing_edge() {
    // §27.1: "Path, host and port evidence MUST remain attached to routing edges." An
    // `Ingress -> Service` edge without them cannot answer why *this* URL reached that Service,
    // which is the only question the edge is ever walked for.
    let ingress = object(INGRESS);
    let edges = Workload::ingress_edges(&ingress);
    let routes = edges_to(&edges, Relation::RoutesTo);

    assert_eq!(routes.len(), 1);
    let route = routes[0];
    assert_eq!(route.target().kind(), "Service");
    assert_eq!(route.target().name(), "checkout");
    assert_eq!(route.target().namespace(), Some("shop"));
    match route.evidence() {
        Evidence::NativeField { path, value } => {
            assert_eq!(path, "/spec/rules/0/http/paths/0/backend/service/name");
            assert_eq!(value, "checkout");
        }
        other => panic!("a backend service is a native field, got {other:?}"),
    }

    let supporting: Vec<(&str, &str)> = route
        .supporting()
        .iter()
        .filter_map(|evidence| match evidence {
            Evidence::NativeField { path, value } => Some((path.as_str(), value.as_str())),
            _ => None,
        })
        .collect();
    assert!(
        supporting.contains(&("/spec/rules/0/host", "shop.example.com")),
        "the host is on the edge, got {supporting:?}"
    );
    assert!(
        supporting.contains(&("/spec/rules/0/http/paths/0/path", "/checkout")),
        "the path is on the edge, got {supporting:?}"
    );
    assert!(
        supporting.contains(&(
            "/spec/rules/0/http/paths/0/backend/service/port/number",
            "80"
        )),
        "the port is on the edge, got {supporting:?}"
    );
}

#[test]
fn should_relate_an_ingress_to_the_secret_that_terminates_its_tls() {
    // §27.1: `Ingress -> uses-tls-secret -> Secret`. The edge exists without reading the Secret
    // and cannot carry its contents (§22.4) — which certificate is in use is a routing fact, and
    // the certificate itself is not.
    let ingress = object(INGRESS);
    let edges = Workload::ingress_edges(&ingress);
    let tls = edges_to(&edges, Relation::UsesTlsSecret);

    assert_eq!(tls.len(), 1);
    assert_eq!(tls[0].target().kind(), "Secret");
    assert_eq!(tls[0].target().name(), "shop-tls");
    assert_eq!(tls[0].target().namespace(), Some("shop"));
    match tls[0].evidence() {
        Evidence::NativeField { path, value } => {
            assert_eq!(path, "/spec/tls/0/secretName");
            assert_eq!(value, "shop-tls");
        }
        other => panic!("secretName is a native field, got {other:?}"),
    }
    assert!(
        tls[0].supporting().iter().any(|evidence| matches!(
            evidence,
            Evidence::NativeField { path, value }
                if path == "/spec/tls/0/hosts/0" && value == "shop.example.com"
        )),
        "the hosts the certificate serves ride along with the edge"
    );
}

#[test]
fn should_relate_an_ingress_to_its_class_when_the_field_names_one() {
    // §27.2: IngressClass "when resolvable from native fields". The class is cluster-scoped, so
    // the edge carries no namespace — copying the Ingress's namespace onto it would produce a
    // target that cannot be looked up.
    let ingress = object(INGRESS);
    let edges = Workload::ingress_edges(&ingress);
    let class = edges_to(&edges, Relation::UsesIngressClass);

    assert_eq!(class.len(), 1);
    assert_eq!(class[0].target().name(), "nginx");
    assert_eq!(
        class[0].target().namespace(),
        None,
        "IngressClass is cluster-scoped"
    );
}

#[test]
fn should_not_assume_the_gateway_api_is_present() {
    // §27.3: "Gateway API is not assumed to be present in every cluster" and MUST NOT be
    // hard-coded into the provider core. On a cluster that only runs Ingress, asking for Gateway
    // relationships answers nothing and the Ingress path is unaffected.
    let ingress = object(INGRESS);
    let service = object(SERVICE);
    assert!(Workload::gateway_edges(&ingress).is_empty());
    assert!(Workload::gateway_edges(&service).is_empty());
    assert!(
        !Workload::ingress_edges(&ingress).is_empty(),
        "routing works in a cluster with no Gateway API installed"
    );
}

#[test]
fn should_relate_a_route_to_its_gateway_and_backend_when_the_gateway_api_is_installed() {
    // §27.3: the curated adapter "MAY add richer relationships" — `HTTPRoute -> attaches-to ->
    // Gateway` and `HTTPRoute -> routes-to -> Service`. A parentRef may name another namespace,
    // and defaulting it to the route's own would point the edge at the wrong Gateway.
    let route = object(HTTPROUTE);
    let edges = Workload::gateway_edges(&route);

    let parents = edges_to(&edges, Relation::AttachesTo);
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0].target().kind(), "Gateway");
    assert_eq!(parents[0].target().name(), "public");
    assert_eq!(parents[0].target().namespace(), Some("gateways"));

    let backends = edges_to(&edges, Relation::RoutesTo);
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0].target().kind(), "Service");
    assert_eq!(
        backends[0].target().namespace(),
        Some("shop"),
        "a backendRef without a namespace is local to the route"
    );

    let gateway = object(GATEWAY);
    let class = Workload::gateway_edges(&gateway);
    assert_eq!(class.len(), 1);
    assert_eq!(class[0].relation(), Relation::UsesGatewayClass);
    assert_eq!(class[0].target().name(), "istio");
    assert_eq!(class[0].target().namespace(), None);
}

#[test]
fn should_name_the_adapter_version_it_read_a_gateway_route_with() {
    // §27.3: Gateway API support "MUST be version/schema aware". The evidence says which
    // version's field layout was assumed, so a cluster serving a version this adapter never saw
    // is a visible fact rather than a silently different reading of the same field names.
    let route = object(HTTPROUTE);
    let edges = Workload::gateway_edges(&route);
    assert!(
        edges[0].supporting().iter().any(|evidence| matches!(
            evidence,
            Evidence::Derived { rule } if rule.contains("gateway.networking.k8s.io/v1")
        )),
        "the adapter names itself and the version it read"
    );
}

#[test]
fn should_not_read_an_unrecognised_gateway_api_version_as_if_the_schema_were_known() {
    // §27.3 and §5.3: the field names of a version this adapter has not seen are not known to
    // mean what today's mean. Reading them anyway is the assumption that the newest version is
    // the one you were built against; the object stays available through universal dynamic
    // support, which is where an unknown schema belongs.
    let route = object(FUTURE_HTTPROUTE);
    assert!(
        Workload::gateway_edges(&route).is_empty(),
        "an unknown version yields no curated edges rather than guessed ones"
    );
}

#[test]
fn should_traverse_the_canonical_path_from_an_ingress_to_a_node() {
    // §2.3 and §15.2: `Ingress -> Service -> EndpointSlice -> Pod -> Node` is the path the
    // provider exists to make walkable. Each hop is a separate edge with its own evidence; a
    // shortcut from Ingress to Pod would be unanswerable at exactly the step that usually
    // breaks.
    let ingress = object(INGRESS);
    let service = object(SERVICE);
    let slice = object(SLICE_ONE);
    let pod = object(POD);

    let route = edges_to(&Workload::ingress_edges(&ingress), Relation::RoutesTo)
        .first()
        .map(|edge| edge.target().name().to_owned())
        .expect("the ingress routes somewhere");
    assert_eq!(route, service.name());

    let represented = Workload::endpoint_slices(&service, std::slice::from_ref(&slice));
    assert_eq!(represented[0].target().name(), slice.name());

    let endpoint = Workload::endpoints(&slice);
    let pod_edge = endpoint[0].pod_edge().expect("the endpoint has a target");
    assert_eq!(pod_edge.target().name(), pod.name());

    let node = Graph::edges_of(&pod)
        .into_iter()
        .find(|edge| edge.relation() == Relation::ScheduledOn)
        .expect("the pod is scheduled");
    assert_eq!(node.target().name(), "ip-10-42-2-19");
}

#[test]
fn should_carry_checkable_evidence_on_every_edge_it_produces() {
    // Gate D (§62.4): every curated relationship can reveal its evidence class and the fields it
    // read. And §23.5: nothing here may be an inference — a module that could quietly emit one
    // would let a correlation arrive with the authority of a field.
    let deployment = object(DEPLOYMENT);
    let statefulset = object(STATEFULSET);
    let service = object(SERVICE);
    let ingress = object(INGRESS);
    let route = object(HTTPROUTE);

    let mut edges = Workload::owns(&deployment, &[object(REPLICASET)]);
    if let SelectorMatch::Evaluated(matched) =
        Workload::selector_matches(&deployment, &[object(REPLICASET)])
    {
        edges.extend(matched);
    }
    edges.extend(Workload::governing_service(&statefulset));
    edges.extend(Workload::endpoint_slices(&service, &[object(SLICE_ONE)]));
    edges.extend(
        Workload::endpoints(&object(SLICE_ONE))
            .into_iter()
            .filter_map(|endpoint| endpoint.pod_edge().cloned()),
    );
    edges.extend(Workload::ingress_edges(&ingress));
    edges.extend(Workload::gateway_edges(&route));
    edges.extend(Workload::job_history(&object(CRONJOB), &[object(JOB)]).into_observed());

    assert!(edges.len() > 10, "the fixtures exercise every producer");
    for edge in &edges {
        assert!(
            !matches!(edge.evidence(), Evidence::Inferred { .. }),
            "{} to {} must not be an inference",
            edge.relation().as_str(),
            edge.target().name()
        );
        assert!(
            !edge.evidence().describe().is_empty(),
            "{} says what it read",
            edge.relation().as_str()
        );
        for support in edge.supporting() {
            assert!(
                !matches!(support, Evidence::Inferred { .. }),
                "supporting evidence is not inference either"
            );
        }
    }
}

const TEMPLATED_DEPLOYMENT: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"api","namespace":"shop","uid":"dep-9","resourceVersion":"4"},
  "spec":{
    "selector":{"matchLabels":{"app":"api"}},
    "template":{
      "metadata":{"labels":{"app":"api"}},
      "spec":{
        "nodeName":"ip-10-42-2-19",
        "serviceAccountName":"api-sa",
        "imagePullSecrets":[{"name":"registry-cred"}],
        "volumes":[
          {"name":"conf","configMap":{"name":"api-config"}},
          {"name":"data","persistentVolumeClaim":{"claimName":"api-data"}}
        ],
        "containers":[
          {"name":"app","image":"api:1",
           "envFrom":[{"secretRef":{"name":"api-token"}}]}
        ]
      }
    }
  }
}"#;

const TEMPLATED_CRONJOB: &str = r#"{
  "apiVersion":"batch/v1","kind":"CronJob",
  "metadata":{"name":"nightly","namespace":"shop","uid":"cj-9"},
  "spec":{
    "schedule":"0 2 * * *",
    "jobTemplate":{"spec":{"template":{"spec":{
      "containers":[{"name":"run","image":"run:1",
                     "envFrom":[{"configMapRef":{"name":"nightly-env"}}]}]
    }}}}
  }
}"#;

#[test]
fn should_read_a_controllers_dependencies_from_the_template_it_states() {
    // §25.1 asks for `Deployment -> uses-template -> PodTemplate semantics`, and §25.3 says a
    // template is not an object. What a template *states* is which ConfigMaps, Secrets, claims
    // and identity the workload needs, and those targets are addressable — so the semantics
    // reach a user as the controller's own reference edges, cited at the template's pointer.
    let deployment = object(TEMPLATED_DEPLOYMENT);
    let edges = Workload::template_dependencies(&deployment);
    let paths: Vec<&str> = edges
        .iter()
        .filter_map(|edge| edge.evidence().path())
        .collect();

    assert!(
        paths.contains(&"/spec/template/spec/volumes/0/configMap/name"),
        "got {paths:?}"
    );
    assert!(
        paths.contains(&"/spec/template/spec/containers/0/envFrom/0/secretRef/name"),
        "got {paths:?}"
    );
    assert!(
        paths.contains(&"/spec/template/spec/serviceAccountName"),
        "got {paths:?}"
    );
    assert!(
        paths.contains(&"/spec/template/spec/imagePullSecrets/0/name"),
        "got {paths:?}"
    );
    assert!(
        paths.contains(&"/spec/template/spec/volumes/1/persistentVolumeClaim/claimName"),
        "got {paths:?}"
    );

    let config = edges
        .iter()
        .find(|edge| edge.relation() == Relation::ReferencesConfig)
        .expect("the template names a ConfigMap");
    assert_eq!(config.source().uid(), Some("dep-9"));
    assert_eq!(
        config.target().namespace(),
        Some("shop"),
        "the template's references live in the controller's namespace (§24.2)"
    );
    assert!(
        edges
            .iter()
            .all(|edge| edge.evidence().is_asserted_by_provider()),
        "every one of these is a field the Deployment itself carries (§23.1)"
    );
}

#[test]
fn should_not_read_a_placement_from_a_template() {
    // §28.1: `scheduled-on` is where a Pod *is*, and a template's `spec.nodeName` is where the
    // Pods it has not created yet are asked to go. A Deployment is scheduled nowhere, and an
    // edge saying otherwise would put a controller on a node.
    let deployment = object(TEMPLATED_DEPLOYMENT);
    assert!(
        Workload::template_dependencies(&deployment)
            .iter()
            .all(|edge| edge.relation() != Relation::ScheduledOn),
        "a template states an intent about placement, never an observation of one"
    );
}

#[test]
fn should_reach_a_cronjobs_template_through_the_job_it_templates() {
    // §25.5: a CronJob's pod template is two levels down, and reading `/spec/template` there
    // would find nothing and report a CronJob that depends on no configuration.
    let cronjob = object(TEMPLATED_CRONJOB);
    let edges = Workload::template_dependencies(&cronjob);
    let config = edges
        .iter()
        .find(|edge| edge.relation() == Relation::ReferencesConfig)
        .expect("the job template names a ConfigMap");
    assert_eq!(config.target().name(), "nightly-env");
    assert_eq!(
        config.evidence().path(),
        Some("/spec/jobTemplate/spec/template/spec/containers/0/envFrom/0/configMapRef/name")
    );
}

#[test]
fn should_read_no_template_from_a_kind_that_states_none() {
    // A Pod is not a controller of anything, and a custom resource that happens to carry a
    // `spec.template` is not a Deployment (§13.5, §23.5). Scanning either would produce edges
    // nobody stated in the shape of ones the API server did.
    for fixture in [POD, SERVICE, INGRESS] {
        assert!(
            Workload::template_dependencies(&object(fixture)).is_empty(),
            "only the kinds §25 names carry a pod template"
        );
    }
}

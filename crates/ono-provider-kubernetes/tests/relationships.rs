//! Relationships, and the evidence that makes each one answerable.
//!
//! Specification §23 to §32. Gate D: every curated relationship can say whether it came from a
//! native field, an owner reference, a selector, a well-known convention, an adapter's derivation
//! or an inference — and which fields it read to decide. An edge that cannot say is an edge a
//! user cannot check, and §4 invariant 20 forbids presenting a guess as a provider's assertion.
//!
//! The line these tests hold most carefully is §23.5. Name similarity, a matching IP or a shared
//! prefix are not relationships. They may become inferences under an explicit confidence model
//! later; they must never arrive looking like something the API server said.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::relationship::{Evidence, Graph, Relation};

const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{
    "name":"checkout-7f9d","namespace":"shop","uid":"pod-1","resourceVersion":"1",
    "labels":{"app":"checkout","tier":"web"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"ReplicaSet","name":"checkout-6ac1","uid":"rs-1",
       "controller":true}
    ]
  },
  "spec":{
    "nodeName":"ip-10-42-2-19",
    "serviceAccountName":"checkout-sa",
    "volumes":[
      {"name":"data","persistentVolumeClaim":{"claimName":"checkout-data"}},
      {"name":"conf","configMap":{"name":"checkout-config"}}
    ],
    "containers":[
      {"name":"app","image":"checkout:1",
       "envFrom":[{"configMapRef":{"name":"checkout-env"}}],
       "env":[{"name":"TOKEN","valueFrom":{"secretKeyRef":{"name":"checkout-secret","key":"t"}}}]}
    ]
  }
}"#;

const UNSCHEDULED_POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"pending-1","namespace":"shop","uid":"pod-2","labels":{"app":"checkout"}},
  "spec":{"nodeSelector":{"disk":"ssd"}}
}"#;

const SERVICE: &str = r#"{
  "apiVersion":"v1","kind":"Service",
  "metadata":{"name":"checkout","namespace":"shop","uid":"svc-1"},
  "spec":{"selector":{"app":"checkout"},"ports":[{"port":80,"targetPort":8080}]}
}"#;

const SELECTORLESS_SERVICE: &str = r#"{
  "apiVersion":"v1","kind":"Service",
  "metadata":{"name":"external","namespace":"shop","uid":"svc-2"},
  "spec":{"ports":[{"port":443}]}
}"#;

const OTHER_NAMESPACE_POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"checkout-elsewhere","namespace":"other","uid":"pod-3",
              "labels":{"app":"checkout"}},
  "spec":{}
}"#;

fn object(json: &str) -> Object {
    Object::parse("kubernetes:prod", json).expect("the fixture reads")
}

#[test]
fn should_read_a_scheduling_edge_from_the_field_that_states_it() {
    // §28.1: `Pod.spec.nodeName` is direct evidence, and the edge names the field it read.
    let edges = Graph::edges_of(&object(POD));
    let scheduled = edges
        .iter()
        .find(|edge| edge.relation() == Relation::ScheduledOn)
        .expect("a scheduled pod has a node edge");

    assert_eq!(scheduled.target().name(), "ip-10-42-2-19");
    assert_eq!(scheduled.target().kind(), "Node");
    match scheduled.evidence() {
        Evidence::NativeField { path, value } => {
            assert_eq!(path, "/spec/nodeName");
            assert_eq!(value, "ip-10-42-2-19");
        }
        other => panic!("scheduling is a native field, got {other:?}"),
    }
}

#[test]
fn should_not_guess_a_node_for_an_unscheduled_pod() {
    // §28.2: a Pod without `spec.nodeName` has no scheduled-on edge. Its constraints are intent
    // and must not be presented as placement.
    let edges = Graph::edges_of(&object(UNSCHEDULED_POD));
    assert!(
        !edges
            .iter()
            .any(|edge| edge.relation() == Relation::ScheduledOn),
        "an unscheduled pod must not have a guessed node edge"
    );
}

#[test]
fn should_distinguish_the_controller_from_a_plain_owner() {
    // §24.3: `controller: true` earns the stronger label while the generic ownership survives.
    let edges = Graph::edges_of(&object(POD));
    let controlled = edges
        .iter()
        .find(|edge| edge.relation() == Relation::ControlledBy)
        .expect("the pod is controlled by its ReplicaSet");

    assert_eq!(controlled.target().kind(), "ReplicaSet");
    assert_eq!(controlled.target().uid(), Some("rs-1"));
    match controlled.evidence() {
        Evidence::OwnerReference { controller } => assert!(*controller),
        other => panic!("ownership comes from ownerReferences, got {other:?}"),
    }
    assert!(
        edges
            .iter()
            .any(|edge| edge.relation() == Relation::OwnedBy),
        "the generic owned-by edge survives beside the controller one (§24.3)"
    );
}

#[test]
fn should_keep_an_owner_edge_whose_target_cannot_be_read() {
    // §24.1: an owner reference is an edge even when the owner is unreadable. It stays dangling
    // with its identity evidence rather than disappearing, because a missing owner is a fact.
    let edges = Graph::edges_of(&object(POD));
    let owner = edges
        .iter()
        .find(|edge| edge.relation() == Relation::ControlledBy)
        .expect("the edge exists");
    assert!(
        !owner.target().is_resolved(),
        "nothing resolved it here, and the edge exists anyway"
    );
    assert_eq!(
        owner.target().uid(),
        Some("rs-1"),
        "the target descriptor carries enough to resolve it later"
    );
}

#[test]
fn should_derive_selection_from_labels_in_the_same_namespace() {
    // §26.1: `Service -> selects -> Pod` is derived by evaluating the selector against observed
    // labels, and the edge carries both so a reader can check the derivation.
    let service = object(SERVICE);
    let pod = object(POD);
    let edges = Graph::selects(&service, std::slice::from_ref(&pod));

    assert_eq!(edges.len(), 1);
    let edge = &edges[0];
    assert_eq!(edge.relation(), Relation::Selects);
    assert_eq!(edge.target().name(), "checkout-7f9d");
    match edge.evidence() {
        Evidence::Selector {
            selector,
            matched_labels,
        } => {
            assert_eq!(selector.get("app").map(String::as_str), Some("checkout"));
            assert_eq!(
                matched_labels.get("app").map(String::as_str),
                Some("checkout"),
                "the evidence names the labels that satisfied the selector, not every label"
            );
            assert!(
                !matched_labels.contains_key("tier"),
                "`tier` did not take part in the decision"
            );
        }
        other => panic!("selection is selector-derived, got {other:?}"),
    }
}

#[test]
fn should_not_select_across_a_namespace_boundary() {
    // §26.1 and §24.2: a Service selects in its own namespace. A pod elsewhere with matching
    // labels is not selected, however much it looks like it should be.
    let service = object(SERVICE);
    let elsewhere = object(OTHER_NAMESPACE_POD);
    let edges = Graph::selects(&service, std::slice::from_ref(&elsewhere));
    assert!(
        edges.is_empty(),
        "matching labels in another namespace is not selection"
    );
}

#[test]
fn should_not_invent_selection_for_a_selectorless_service() {
    // §26.1: "An empty selector or selector-less Service MUST not create guessed Pod edges."
    let service = object(SELECTORLESS_SERVICE);
    let pod = object(POD);
    assert!(Graph::selects(&service, std::slice::from_ref(&pod)).is_empty());
}

#[test]
fn should_require_every_selector_key_to_match() {
    // A selector is a conjunction. One key matching is not selection, and treating it as such
    // would attach a Service to workloads it does not route to.
    let two_key = SERVICE.replace(
        r#""selector":{"app":"checkout"}"#,
        r#""selector":{"app":"checkout","tier":"api"}"#,
    );
    let service = object(&two_key);
    let pod = object(POD);
    assert!(
        Graph::selects(&service, std::slice::from_ref(&pod)).is_empty(),
        "the pod is tier=web, so the conjunction fails"
    );
}

#[test]
fn should_read_configuration_and_storage_dependencies_from_their_fields() {
    // §29 and §30: the edges name how the dependency is consumed, because "mounted as a volume"
    // and "read as an environment variable" have different consequences when it changes.
    let edges = Graph::edges_of(&object(POD));

    let claim = edges
        .iter()
        .find(|edge| edge.relation() == Relation::Mounts)
        .expect("the pod mounts a claim");
    assert_eq!(claim.target().kind(), "PersistentVolumeClaim");
    assert_eq!(claim.target().name(), "checkout-data");

    let configs: Vec<_> = edges
        .iter()
        .filter(|edge| edge.relation() == Relation::ReferencesConfig)
        .collect();
    let names: Vec<_> = configs.iter().map(|edge| edge.target().name()).collect();
    assert!(
        names.contains(&"checkout-config"),
        "the volume source, got {names:?}"
    );
    assert!(
        names.contains(&"checkout-env"),
        "the envFrom source, got {names:?}"
    );

    let secret = edges
        .iter()
        .find(|edge| edge.relation() == Relation::ReferencesSecret)
        .expect("the pod reads a secret");
    assert_eq!(secret.target().name(), "checkout-secret");
    assert_eq!(secret.target().kind(), "Secret");
}

#[test]
fn should_relate_a_pod_to_the_identity_it_runs_as() {
    // §32.1: `Pod -> runs-as -> ServiceAccount`, from the field that states it.
    let edges = Graph::edges_of(&object(POD));
    let runs_as = edges
        .iter()
        .find(|edge| edge.relation() == Relation::RunsAs)
        .expect("the pod names a service account");
    assert_eq!(runs_as.target().kind(), "ServiceAccount");
    assert_eq!(runs_as.target().name(), "checkout-sa");
    assert_eq!(
        runs_as.target().namespace(),
        Some("shop"),
        "a ServiceAccount is namespace-local (§32.1)"
    );
}

#[test]
fn should_carry_the_source_identity_on_every_edge() {
    // An edge without a source is not traversable in reverse and cannot be attributed.
    let pod = object(POD);
    for edge in Graph::edges_of(&pod) {
        assert_eq!(
            edge.source(),
            &pod.identity(),
            "every edge names its source"
        );
    }
}

#[test]
fn should_never_produce_an_edge_without_evidence() {
    // Gate D in one assertion: there is no way to construct an edge that cannot say where it
    // came from, because `evidence()` is not optional.
    let pod = object(POD);
    let service = object(SERVICE);
    let mut all = Graph::edges_of(&pod);
    all.extend(Graph::selects(&service, std::slice::from_ref(&pod)));
    assert!(!all.is_empty());
    for edge in &all {
        let described = edge.evidence().describe();
        assert!(
            !described.is_empty(),
            "every edge describes its own evidence, {edge:?} did not"
        );
    }
}

#[test]
fn should_name_the_evidence_class_a_reader_can_check() {
    // The six classes of Gate D, spelled so `inspect` can print them and a reader can tell a
    // provider's assertion from this provider's derivation.
    assert_eq!(
        Evidence::NativeField {
            path: "/spec/nodeName".to_owned(),
            value: "n".to_owned()
        }
        .class(),
        "native-field"
    );
    assert_eq!(
        Evidence::OwnerReference { controller: true }.class(),
        "owner-reference"
    );
    assert_eq!(
        Evidence::Selector {
            selector: Default::default(),
            matched_labels: Default::default()
        }
        .class(),
        "selector"
    );
    assert_eq!(
        Evidence::Convention {
            key: "k".to_owned(),
            value: "v".to_owned()
        }
        .class(),
        "convention"
    );
    assert_eq!(
        Evidence::Derived {
            rule: "r".to_owned()
        }
        .class(),
        "adapter-derivation"
    );
    assert_eq!(
        Evidence::Inferred {
            reason: "r".to_owned()
        }
        .class(),
        "inference"
    );
}

#[test]
fn should_keep_a_derived_edge_distinguishable_from_a_declared_one() {
    // §4 invariant 20 and §23.5: a guess must never render as a provider-proven relationship.
    // The provider's own derivations are honest about being derivations.
    let declared = Evidence::NativeField {
        path: "/spec/nodeName".to_owned(),
        value: "n".to_owned(),
    };
    let guessed = Evidence::Inferred {
        reason: "the names look alike".to_owned(),
    };
    assert!(declared.is_asserted_by_provider());
    assert!(!guessed.is_asserted_by_provider());
    assert!(
        !Evidence::Selector {
            selector: Default::default(),
            matched_labels: Default::default()
        }
        .is_asserted_by_provider(),
        "a selector edge is derived by this provider from two facts, not asserted by the server"
    );
}

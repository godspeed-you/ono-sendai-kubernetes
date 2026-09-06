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

use std::collections::BTreeMap;

use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::redaction;
use ono_provider_kubernetes::relationship::{Edge, Evidence, Graph, Relation, Target};
use ono_provider_kubernetes::workload::SelectorMatch;

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
fn should_spell_relationships_the_way_the_specification_does() {
    // §22.4, §24.3, §25 to §27 and §30 name these words in the specification's own examples. One
    // vocabulary for the whole provider only helps if it is the vocabulary the specification
    // already uses; a synonym invented here is a word a reader of the spec cannot follow.
    let named = [
        (Relation::OwnedBy, "owned-by"),
        (Relation::ControlledBy, "controlled-by"),
        (Relation::Owns, "owns"),
        (Relation::ScheduledOn, "scheduled-on"),
        (Relation::Selects, "selects"),
        (Relation::SelectedBy, "selected-by"),
        (Relation::SelectorMatches, "selector-matches"),
        (Relation::RepresentedBy, "represented-by"),
        (Relation::EndpointFor, "endpoint-for"),
        (Relation::RoutesTo, "routes-to"),
        (Relation::RoutedFrom, "routed-from"),
        (Relation::UsesTlsSecret, "uses-tls-secret"),
        (Relation::AttachesTo, "attaches-to"),
        (Relation::RunsAs, "runs-as"),
        (Relation::Mounts, "mounts"),
        (Relation::BoundTo, "bound-to"),
        // Appendix B's word rather than §30.1's `provisioned-by / storage-class`. The appendix
        // says its names are candidates to be reconciled with the project's global registry, and
        // `provisioned-by` would claim the provisioning happened where the field only names a
        // class. ADR-0031.
        (Relation::UsesStorageClass, "uses-storage-class"),
        (Relation::ReferencesConfig, "references-config"),
        (Relation::ReferencesSecret, "references-secret"),
        (Relation::UsesImagePullSecret, "uses-image-pull-secret"),
        // Appendix B's words for §31.1's edge read from the Pod's end and for §32.2's `roleRef`.
        (Relation::ProtectedBy, "protected-by"),
        (Relation::Binds, "binds"),
    ];

    for (relation, word) in named {
        assert_eq!(relation.as_str(), word);
    }
}

#[test]
fn should_require_evidence_of_an_edge_built_outside_the_graph() {
    // Gate D, expressed in the type rather than in a review comment: a module that reads fields
    // this one does not — a curated routing adapter, a secret reference — builds its edges here,
    // and cannot build one that fails to say where it came from. §27.1's host, path and port ride
    // along beside that evidence rather than inside it, because they qualify the edge without
    // being what decided it.
    let ingress = object(SERVICE);
    let edge = Edge::new(
        ingress.identity(),
        Relation::RoutesTo,
        Target::new("Service", "checkout")
            .with_api_version(Some("v1"))
            .in_namespace(Some("shop")),
        Evidence::NativeField {
            path: "/spec/rules/0/http/paths/0/backend/service/name".to_owned(),
            value: "checkout".to_owned(),
        },
    )
    .with_supporting(vec![Evidence::NativeField {
        path: "/spec/rules/0/host".to_owned(),
        value: "shop.example.com".to_owned(),
    }]);

    assert_eq!(edge.relation(), Relation::RoutesTo);
    assert_eq!(edge.target().namespace(), Some("shop"));
    assert!(
        !edge.target().is_resolved(),
        "nothing read the Service, and an edge says so rather than inventing its identity (§24.1)"
    );
    assert_eq!(edge.evidence().class(), "native-field");
    assert_eq!(
        edge.supporting().len(),
        1,
        "the host stays attached to the routing edge (§27.1)"
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

const BOUND_CLAIM: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{"name":"checkout-data","namespace":"shop","uid":"pvc-1","resourceVersion":"7"},
  "spec":{"volumeName":"pvc-0e12-4a","storageClassName":"fast","accessModes":["ReadWriteOnce"]},
  "status":{"phase":"Bound"}
}"#;

const PENDING_CLAIM: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{"name":"waiting","namespace":"shop","uid":"pvc-2"},
  "spec":{"storageClassName":"fast","accessModes":["ReadWriteOnce"]},
  "status":{"phase":"Pending"}
}"#;

const UNBOUND_CLAIM: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{"name":"released","namespace":"shop","uid":"pvc-3"},
  "spec":{"volumeName":"","storageClassName":"fast"},
  "status":{"phase":"Pending"}
}"#;

const LAYERED_POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"api-1","namespace":"shop","uid":"pod-9","resourceVersion":"3"},
  "spec":{
    "imagePullSecrets":[{"name":"registry-cred"}],
    "volumes":[
      {"name":"bundle","projected":{"sources":[
        {"configMap":{"name":"trust-bundle"}},
        {"secret":{"name":"client-cert","optional":true}},
        {"serviceAccountToken":{"path":"token","audience":"api","expirationSeconds":3600}}
      ]}}
    ],
    "initContainers":[
      {"name":"migrate","image":"migrate:1",
       "envFrom":[{"configMapRef":{"name":"migrate-env","optional":true}}]}
    ],
    "containers":[
      {"name":"app","image":"api:1",
       "env":[{"name":"KEY","valueFrom":{"secretKeyRef":{"name":"app-key","key":"k",
                                                          "optional":false}}}]}
    ],
    "ephemeralContainers":[
      {"name":"debug","image":"debug:1",
       "envFrom":[{"secretRef":{"name":"debug-token"}}]}
    ]
  }
}"#;

const POD_SHAPED_CUSTOM_RESOURCE: &str = r#"{
  "apiVersion":"acme.example.com/v1","kind":"Pod",
  "metadata":{"name":"impostor","namespace":"shop","uid":"cr-1"},
  "spec":{"nodeName":"ip-10-42-2-19","serviceAccountName":"checkout-sa"}
}"#;

#[test]
fn should_bind_a_claim_to_the_volume_it_names() {
    // §30.2: `spec.volumeName` is the claim's own statement that it is bound, so `bound-to` is a
    // native-field edge rather than a second reading — and a PersistentVolume is cluster-scoped,
    // so the claim's namespace must not travel onto it (§9.2, §24.2).
    let claim = object(BOUND_CLAIM);
    let bound = Graph::edges_of(&claim)
        .into_iter()
        .find(|edge| edge.relation() == Relation::BoundTo)
        .expect("a bound claim names its volume");

    assert_eq!(bound.target().kind(), "PersistentVolume");
    assert_eq!(bound.target().name(), "pvc-0e12-4a");
    assert_eq!(bound.target().api_version(), Some("v1"));
    assert_eq!(
        bound.target().namespace(),
        None,
        "a PersistentVolume is cluster-scoped, and a namespace on it would address nothing"
    );
    assert!(
        !bound.target().is_resolved(),
        "the volume was never read, and §24.1 keeps the edge without inventing its lifetime"
    );
    assert_eq!(
        bound.evidence(),
        &Evidence::NativeField {
            path: "/spec/volumeName".to_owned(),
            value: "pvc-0e12-4a".to_owned(),
        }
    );
    assert_eq!(
        bound.supporting(),
        &[Evidence::NativeField {
            path: "/status/phase".to_owned(),
            value: "Bound".to_owned(),
        }],
        "§30.2's `relevant status fields` qualify the binding without deciding it"
    );
}

#[test]
fn should_not_treat_a_pending_claim_as_bound() {
    // §30.2 MUST: a Pending claim with no `volumeName` is not bound to anything, and an empty
    // string is not a volume name either — an edge to `` would address a volume nobody has.
    for fixture in [PENDING_CLAIM, UNBOUND_CLAIM] {
        let claim = object(fixture);
        assert!(
            !Graph::edges_of(&claim)
                .iter()
                .any(|edge| edge.relation() == Relation::BoundTo),
            "an unbound claim states no binding, and absence is not a reason to guess one"
        );
    }
}

#[test]
fn should_read_configuration_from_containers_that_are_not_the_main_ones() {
    // §29.1: an init container and an ephemeral container reference ConfigMaps and Secrets the
    // same way `spec.containers` does. Scanning only the main containers reports a Pod that
    // cannot start for want of a ConfigMap as one that references none.
    let pod = object(LAYERED_POD);
    let edges = Graph::edges_of(&pod);
    let paths: Vec<&str> = edges
        .iter()
        .filter_map(|edge| edge.evidence().path())
        .collect();

    assert!(
        paths.contains(&"/spec/initContainers/0/envFrom/0/configMapRef/name"),
        "an init container's reference cites its own pointer, got {paths:?}"
    );
    assert!(
        paths.contains(&"/spec/ephemeralContainers/0/envFrom/0/secretRef/name"),
        "an ephemeral container's reference cites its own pointer, got {paths:?}"
    );
    assert!(
        paths.contains(&"/spec/containers/0/env/0/valueFrom/secretKeyRef/name"),
        "the main containers are still scanned, got {paths:?}"
    );
    let migrate = edges
        .iter()
        .find(|edge| edge.target().name() == "migrate-env")
        .expect("the init container's ConfigMap is a target");
    assert_eq!(migrate.relation(), Relation::ReferencesConfig);
    assert_eq!(migrate.target().namespace(), Some("shop"));
}

#[test]
fn should_read_the_sources_a_projected_volume_composes() {
    // §29.1 names the projected ConfigMap source explicitly. A projected volume is how a Pod
    // reads several sources under one mount, and skipping it hides the dependency entirely.
    let pod = object(LAYERED_POD);
    let edges = Graph::edges_of(&pod);
    let from_volume: Vec<&Edge> = edges
        .iter()
        .filter(|edge| {
            edge.evidence()
                .path()
                .is_some_and(|path| path.starts_with("/spec/volumes/0"))
        })
        .collect();

    let paths: Vec<&str> = from_volume
        .iter()
        .filter_map(|edge| edge.evidence().path())
        .collect();
    assert!(
        paths.contains(&"/spec/volumes/0/projected/sources/0/configMap/name"),
        "got {paths:?}"
    );
    assert!(
        paths.contains(&"/spec/volumes/0/projected/sources/1/secret/name"),
        "a projected Secret source names the Secret in `name`, got {paths:?}"
    );
    assert_eq!(
        from_volume.len(),
        2,
        "a `serviceAccountToken` source references no object — the API server mints the token — \
         so it contributes no edge rather than an edge to a name nobody can look up"
    );
}

#[test]
fn should_keep_an_optional_reference_marked_optional() {
    // §29.3: a missing optional target is not an error, and an edge that dropped the flag would
    // make an absent ConfigMap read as a broken Pod. The flag qualifies the edge rather than
    // deciding it, so it rides as supporting evidence with the pointer that stated it.
    let pod = object(LAYERED_POD);
    let edges = Graph::edges_of(&pod);

    let optional = edges
        .iter()
        .find(|edge| edge.target().name() == "migrate-env")
        .expect("the init container references a ConfigMap");
    assert_eq!(
        optional.supporting(),
        &[Evidence::NativeField {
            path: "/spec/initContainers/0/envFrom/0/configMapRef/optional".to_owned(),
            value: "true".to_owned(),
        }]
    );

    let required = edges
        .iter()
        .find(|edge| edge.target().name() == "app-key")
        .expect("the container reads a secret key");
    assert_eq!(
        required.supporting(),
        &[Evidence::NativeField {
            path: "/spec/containers/0/env/0/valueFrom/secretKeyRef/optional".to_owned(),
            value: "false".to_owned(),
        }],
        "a reference that states `optional: false` said so, and the edge repeats what it read"
    );

    let unstated = edges
        .iter()
        .find(|edge| edge.target().name() == "debug-token")
        .expect("the ephemeral container references a Secret");
    assert!(
        unstated.supporting().is_empty(),
        "a reference that carries no `optional` field has none, and a fabricated `false` would \
         report a field the object never held"
    );
}

#[test]
fn should_relate_a_pod_to_the_secrets_its_images_are_pulled_with() {
    // §32.1 and §22.4: `spec.imagePullSecrets` is a Secret reference a Pod states about itself,
    // and a Pod that cannot pull its image is the case an operator asks about. The word is the
    // one a ServiceAccount's pull secrets already use, so there is one vocabulary for one fact.
    let pod = object(LAYERED_POD);
    let edges = Graph::edges_of(&pod);

    let pull = edges
        .iter()
        .find(|edge| edge.relation() == Relation::UsesImagePullSecret)
        .expect("the pod names an image pull secret");
    assert_eq!(pull.target().kind(), "Secret");
    assert_eq!(pull.target().name(), "registry-cred");
    assert_eq!(
        pull.target().namespace(),
        Some("shop"),
        "a pull Secret is namespace-local (§24.2, §32.1)"
    );
    assert_eq!(
        pull.evidence(),
        &Evidence::NativeField {
            path: "/spec/imagePullSecrets/0/name".to_owned(),
            value: "registry-cred".to_owned(),
        }
    );

    // The plugin emits `Graph::edges_of` *and* `redaction::secret_references` filtered to the
    // two `uses-*` words. A Pod pull-secret edge produced by both would reach a user twice.
    assert!(
        !redaction::secret_references(&pod)
            .iter()
            .any(|edge| edge.relation() == Relation::UsesImagePullSecret),
        "`secret_references` adds the ServiceAccount's own entries and takes the Pod's edges \
         from `edges_of`; producing this one twice would double every pull-secret edge"
    );
}

#[test]
fn should_not_read_a_custom_resource_as_a_pod_because_it_is_called_one() {
    // §13.5: GVK identity is group *and* kind. A custom `Pod` in someone else's group carries
    // whatever fields its author chose, and reading `spec.nodeName` there would assert a
    // scheduling fact about an object that never claimed one.
    let impostor = object(POD_SHAPED_CUSTOM_RESOURCE);
    assert!(
        Graph::edges_of(&impostor).is_empty(),
        "only `v1 Pod` states a Pod's fields"
    );
}

const VOLUME_WITH_CLASS: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolume",
  "metadata":{"name":"pvc-0e12-4a","uid":"pv-1"},
  "spec":{"storageClassName":"fast","capacity":{"storage":"20Gi"}}
}"#;

const CLAIM_REFUSING_A_CLASS: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{"name":"static-data","namespace":"shop","uid":"pvc-2"},
  "spec":{"storageClassName":"","volumeName":"pv-static"}
}"#;

const CLAIM_TAKING_THE_DEFAULT: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{"name":"default-data","namespace":"shop","uid":"pvc-3"},
  "spec":{"accessModes":["ReadWriteOnce"]}
}"#;

#[test]
fn should_relate_a_claim_and_a_volume_to_the_class_each_one_names() {
    // §30.1 and §30.3: the class decides the provisioner, the reclaim policy and whether the
    // volume can grow, which is why §30.3 wants it reachable before a change is planned. The
    // field states it, so the edge is a native field on both ends — and a StorageClass is
    // cluster-scoped, so neither namespace travels onto it (§9.2).
    for (fixture, source) in [(BOUND_CLAIM, "a claim"), (VOLUME_WITH_CLASS, "a volume")] {
        let edge = Graph::edges_of(&object(fixture))
            .into_iter()
            .find(|edge| edge.relation() == Relation::UsesStorageClass)
            .unwrap_or_else(|| panic!("{source} that names a class relates to it"));

        assert_eq!(edge.target().kind(), "StorageClass");
        assert_eq!(edge.target().name(), "fast");
        assert_eq!(edge.target().api_version(), Some("storage.k8s.io/v1"));
        assert_eq!(edge.target().namespace(), None, "{source}");
        assert_eq!(
            edge.evidence(),
            &Evidence::NativeField {
                path: "/spec/storageClassName".to_owned(),
                value: "fast".to_owned(),
            },
            "{source}"
        );
    }
}

#[test]
fn should_relate_no_class_where_the_object_named_none() {
    // The two ways of naming no class, and both are answers rather than gaps. `""` is
    // Kubernetes' way of saying *no class, do not provision dynamically*, and an edge would
    // address a StorageClass called the empty string. An absent field means the cluster's
    // default applies, and which class that is, is a fact about the cluster — reading it from
    // here would be an inference wearing a native field's clothes (§23.5, §4 invariant 20).
    for (fixture, how) in [
        (
            CLAIM_REFUSING_A_CLASS,
            "an empty class name refuses a class",
        ),
        (
            CLAIM_TAKING_THE_DEFAULT,
            "an absent one takes the cluster default",
        ),
    ] {
        let classes: Vec<_> = Graph::edges_of(&object(fixture))
            .into_iter()
            .filter(|edge| edge.relation() == Relation::UsesStorageClass)
            .collect();
        assert!(classes.is_empty(), "{how}, got {classes:?}");
    }
}

/// A policy written for one app, with the peer structure §31.2 forbids reducing to a boolean.
const NETWORK_POLICY: &str = r#"{
  "apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
  "metadata":{"name":"checkout-ingress","namespace":"shop","uid":"np-1","resourceVersion":"9"},
  "spec":{
    "podSelector":{"matchLabels":{"app":"checkout"}},
    "policyTypes":["Ingress"],
    "ingress":[{
      "from":[
        {"namespaceSelector":{"matchLabels":{"tier":"edge"}}},
        {"ipBlock":{"cidr":"10.0.0.0/8","except":["10.9.0.0/16"]}}
      ],
      "ports":[{"protocol":"TCP","port":8080}]
    }]
  }
}"#;

/// The namespace-wide default-deny every cluster eventually grows: an empty `podSelector`, which
/// the API defines as *every* Pod in the policy's namespace.
const NAMESPACE_WIDE_POLICY: &str = r#"{
  "apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
  "metadata":{"name":"default-deny","namespace":"shop","uid":"np-2"},
  "spec":{"podSelector":{},"policyTypes":["Ingress"]}
}"#;

/// A policy whose selector this provider does not evaluate in full (ADR-0007).
const EXPRESSIVE_POLICY: &str = r#"{
  "apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
  "metadata":{"name":"tiered","namespace":"shop","uid":"np-3"},
  "spec":{
    "podSelector":{
      "matchLabels":{"app":"checkout"},
      "matchExpressions":[{"key":"tier","operator":"NotIn","values":["web"]}]
    }
  }
}"#;

/// A policy of another namespace that names the same labels.
const OTHER_NAMESPACE_POLICY: &str = r#"{
  "apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
  "metadata":{"name":"checkout-ingress","namespace":"other","uid":"np-4"},
  "spec":{"podSelector":{"matchLabels":{"app":"checkout"}}}
}"#;

fn evaluated(matched: SelectorMatch) -> Vec<Edge> {
    match matched {
        SelectorMatch::Evaluated(edges) => edges,
        SelectorMatch::NotEvaluated { reason } => {
            panic!("the selector is one this provider evaluates: {reason}")
        }
    }
}

#[test]
fn should_derive_the_pods_a_network_policy_applies_to_from_its_pod_selector() {
    // §31.1: `NetworkPolicy -> selects -> Pod`, derived by evaluating `spec.podSelector` against
    // observed labels — §23.3's class, not a field the API server stated. A NetworkPolicy with no
    // relationship at all leaves the object an operator asks about during an outage unreachable
    // from the Pods it governs.
    let policy = object(NETWORK_POLICY);
    let edges = evaluated(Graph::policy_selects(
        &policy,
        &[object(POD), object(UNSCHEDULED_POD), object(SERVICE)],
    ));

    let selected: Vec<(&str, &str)> = edges
        .iter()
        .map(|edge| (edge.relation().as_str(), edge.target().name()))
        .collect();
    assert_eq!(
        selected,
        vec![("selects", "checkout-7f9d"), ("selects", "pending-1")],
        "both Pods carry `app=checkout`, and a Service is not a Pod"
    );
    assert!(
        edges
            .iter()
            .all(|edge| edge.evidence().class() == "selector"),
        "a policy's reach is derived from two objects, never stated by one (§23.3)"
    );
}

#[test]
fn should_keep_the_namespace_and_the_selector_as_evidence_of_a_policy_edge() {
    // §31.1's `MUST`: the edge preserves namespace *and* selector evidence. A NetworkPolicy is
    // namespace-local, so an edge that dropped the namespace would read as a cluster-wide claim
    // — and a policy in `staging` would appear to govern production.
    let policy = object(NETWORK_POLICY);
    let edges = evaluated(Graph::policy_selects(&policy, &[object(POD)]));
    let edge = edges.first().expect("the selector matches the Pod");

    assert_eq!(
        edge.evidence(),
        &Evidence::Selector {
            selector: BTreeMap::from([("app".to_owned(), "checkout".to_owned())]),
            matched_labels: BTreeMap::from([("app".to_owned(), "checkout".to_owned())]),
        },
        "the selector that decided, and the labels that satisfied it"
    );
    assert!(
        edge.supporting().contains(&Evidence::NativeField {
            path: "/metadata/namespace".to_owned(),
            value: "shop".to_owned(),
        }),
        "the namespace the policy is confined to, as the field that states it: {:?}",
        edge.supporting()
    );
    assert_eq!(edge.target().namespace(), Some("shop"));
}

#[test]
fn should_apply_a_policy_with_an_empty_pod_selector_to_every_pod_in_its_namespace() {
    // The one place a Kubernetes selector does not mean what `Graph::selects` means by it: an
    // empty `spec.podSelector` is the API's way of writing *every Pod in this namespace*, which
    // is exactly what a default-deny policy is written as. Treating it as `Service.spec.selector`
    // — where empty selects nothing (§26.1) — would report the strictest policy in the cluster as
    // governing no Pod at all.
    let policy = object(NAMESPACE_WIDE_POLICY);
    let edges = evaluated(Graph::policy_selects(
        &policy,
        &[object(POD), object(OTHER_NAMESPACE_POD)],
    ));

    let selected: Vec<&str> = edges.iter().map(|edge| edge.target().name()).collect();
    assert_eq!(
        selected,
        vec!["checkout-7f9d"],
        "every Pod of the policy's own namespace, and no Pod of another"
    );
    assert!(
        edges[0]
            .supporting()
            .iter()
            .any(|evidence| evidence.describe().contains("every Pod in the namespace")),
        "the reading that produced the edge is stated rather than assumed: {:?}",
        edges[0].supporting()
    );
}

#[test]
fn should_not_evaluate_a_policy_selector_it_cannot_evaluate_in_full() {
    // ADR-0007 and §23.3: `matchExpressions` is not evaluated here, and the `matchLabels` subset
    // is *wider* than the selector — a Pod the expression excludes would arrive looking governed
    // by a policy that does not govern it. Saying so is the only honest answer.
    let policy = object(EXPRESSIVE_POLICY);
    let SelectorMatch::NotEvaluated { reason } = Graph::policy_selects(&policy, &[object(POD)])
    else {
        panic!("a selector carrying `matchExpressions` is not evaluated here");
    };
    assert!(reason.contains("matchExpressions"), "{reason}");
}

#[test]
fn should_state_policy_intent_rather_than_observed_packet_behaviour() {
    // §31.3: the presence of a NetworkPolicy object does not prove enforcement by the installed
    // networking implementation. The edge is API intent, and it says so — a reader who takes it
    // for observed traffic would conclude that a cluster running no policy controller is
    // protected.
    let policy = object(NETWORK_POLICY);
    let edges = evaluated(Graph::policy_selects(&policy, &[object(POD)]));
    let edge = edges.first().expect("the selector matches the Pod");

    assert!(
        !edge.evidence().is_asserted_by_provider(),
        "nothing observed a packet; two objects were read and compared"
    );
    assert!(
        edge.supporting()
            .iter()
            .any(|evidence| evidence.describe().contains("not observed")),
        "the edge names enforcement as unobserved: {:?}",
        edge.supporting()
    );
}

#[test]
fn should_not_reduce_a_policy_s_peers_to_a_reachability_claim() {
    // §31.2: ingress and egress peers combine namespace selectors, pod selectors and IP blocks,
    // and their native structure MUST survive. The derivation therefore relates the policy to the
    // Pods it is written for and says nothing at all about who may reach them: an edge to a CIDR
    // block, or a peer flattened into an edge, would be the misleading boolean in another shape.
    let policy = object(NETWORK_POLICY);
    let edges = evaluated(Graph::policy_selects(
        &policy,
        &[object(POD), object(OTHER_NAMESPACE_POD)],
    ));

    assert!(
        edges.iter().all(|edge| edge.target().kind() == "Pod"),
        "the far end of a policy edge is a Pod, never a peer, a CIDR or a namespace"
    );
    assert!(
        edges
            .iter()
            .all(|edge| !edge.evidence().describe().contains("10.0.0.0/8")),
        "an IP block is structure of the policy, not evidence that anything is reachable"
    );
}

#[test]
fn should_read_a_policy_from_the_pod_s_end_as_protected_by() {
    // Appendix B's word for the far end of §31.1, and the direction an operator actually asks in:
    // "what governs this Pod?" rather than "what does this policy cover?". The word is
    // `protected-by` because the Pod's end of a *policy* is not the Pod's end of a Service —
    // `selected-by` there would put a policy in the routing vocabulary (ADR-0031's reasoning for
    // taking the appendix's word).
    let pod = object(POD);
    let edges = evaluated(Graph::protected_by(
        &pod,
        &[
            object(NETWORK_POLICY),
            object(NAMESPACE_WIDE_POLICY),
            object(OTHER_NAMESPACE_POLICY),
        ],
    ));

    let governing: Vec<(&str, &str)> = edges
        .iter()
        .map(|edge| (edge.relation().as_str(), edge.target().name()))
        .collect();
    assert_eq!(
        governing,
        vec![
            ("protected-by", "checkout-ingress"),
            ("protected-by", "default-deny"),
        ],
        "a policy of another namespace governs nothing here (§31.1)"
    );
    assert_eq!(edges[0].source().name(), "checkout-7f9d");
    assert_eq!(
        edges[0].target().api_version(),
        Some("networking.k8s.io/v1")
    );
}

#[test]
fn should_report_no_policy_reach_at_all_where_one_selector_could_not_be_evaluated() {
    // ADR-0004 and §21.4 at the level of the *answer*: "which policies govern this Pod" is one
    // question, and a subset of it presented as the whole is the claim that no other policy
    // applies. One unevaluated selector makes the set unknown rather than smaller.
    let pod = object(POD);
    let SelectorMatch::NotEvaluated { reason } =
        Graph::protected_by(&pod, &[object(NETWORK_POLICY), object(EXPRESSIVE_POLICY)])
    else {
        panic!("a policy whose selector is not evaluated leaves the set of policies unknown");
    };
    assert!(
        reason.contains("tiered"),
        "the policy that stopped it: {reason}"
    );
}

/// A RoleBinding: `roleRef` is a native field, and its subjects are not all API objects (§32.3).
const ROLE_BINDING: &str = r#"{
  "apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
  "metadata":{"name":"checkout-reader","namespace":"shop","uid":"rb-1"},
  "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},
  "subjects":[
    {"kind":"ServiceAccount","name":"checkout-sa","namespace":"shop"},
    {"kind":"User","apiGroup":"rbac.authorization.k8s.io","name":"alice@example.com"},
    {"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"platform"}
  ]
}"#;

const CLUSTER_ROLE_BINDING: &str = r#"{
  "apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding",
  "metadata":{"name":"operators","uid":"crb-1"},
  "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"edit"},
  "subjects":[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"platform"}]
}"#;

#[test]
fn should_bind_a_role_binding_to_the_role_it_names() {
    // §32.2's `binds`, and it is a native field rather than a derivation: `roleRef` states the
    // Role, and the binding is the only object that says which permissions reach a subject.
    let edges = Graph::edges_of(&object(ROLE_BINDING));
    let bound: Vec<&Edge> = edges
        .iter()
        .filter(|edge| edge.relation() == Relation::Binds)
        .collect();

    assert_eq!(bound.len(), 1, "one `roleRef`, one edge: {edges:?}");
    assert_eq!(bound[0].target().kind(), "Role");
    assert_eq!(bound[0].target().name(), "reader");
    assert_eq!(
        bound[0].target().namespace(),
        Some("shop"),
        "a Role is namespace-local, and the binding's namespace is where it is looked up"
    );
    assert_eq!(
        bound[0].evidence(),
        &Evidence::NativeField {
            path: "/roleRef/name".to_owned(),
            value: "reader".to_owned(),
        }
    );
}

#[test]
fn should_bind_a_cluster_role_binding_to_a_role_that_has_no_namespace() {
    // §9.5 and §24.2 applied to RBAC: a ClusterRole is cluster-scoped, so the binding's namespace
    // — which a ClusterRoleBinding does not even have — never travels onto the target. An edge
    // carrying one would address a Role that cannot be looked up.
    let edges = Graph::edges_of(&object(CLUSTER_ROLE_BINDING));
    let bound: Vec<&Edge> = edges
        .iter()
        .filter(|edge| edge.relation() == Relation::Binds)
        .collect();

    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].target().kind(), "ClusterRole");
    assert_eq!(bound[0].target().namespace(), None);
}

#[test]
fn should_relate_a_binding_to_no_subject_that_kubernetes_does_not_store() {
    // §32.3: a User and a Group are not stored Kubernetes API objects, and the provider MUST NOT
    // imply that a corresponding object exists. Appendix B's `grants-to` is therefore not emitted
    // at all rather than emitted for the one subject kind that happens to be an object: a
    // `grants-to` answering for the ServiceAccount and silent about the User and the Group would
    // read as a binding that grants to one subject, which is the more damaging falsehood. The
    // subjects stay visible as the binding's own fields. ADR-0040.
    let edges = Graph::edges_of(&object(ROLE_BINDING));

    assert!(
        edges
            .iter()
            .all(|edge| edge.relation().as_str() != "grants-to"),
        "no edge claims to reach a subject: {edges:?}"
    );
    assert!(
        edges
            .iter()
            .all(|edge| edge.target().name() != "alice@example.com"),
        "a User is an external identity, never a place this provider can address"
    );
}

#[test]
fn should_read_a_service_from_the_pod_s_end_as_selected_by() {
    // Appendix B's `selected-by`: §26.1's edge read from the Pod's end, which is the end an
    // operator starts at when one Pod is missing from a Service's endpoints. The same selector
    // decides it, so the two directions cannot disagree.
    let pod = object(POD);
    let edges = Graph::selected_by(
        &pod,
        &[
            object(SERVICE),
            object(SELECTORLESS_SERVICE),
            object(OTHER_NAMESPACE_POD),
        ],
    );

    let selecting: Vec<(&str, &str)> = edges
        .iter()
        .map(|edge| (edge.relation().as_str(), edge.target().name()))
        .collect();
    assert_eq!(
        selecting,
        vec![("selected-by", "checkout")],
        "a Service with no selector selects nothing, in either direction (§26.1)"
    );
    assert_eq!(edges[0].evidence().class(), "selector");
    assert!(
        edges[0]
            .supporting()
            .iter()
            .any(|evidence| evidence.describe().contains("reversal")),
        "the record lives on the Service; this edge reads it the other way round and says so"
    );
}

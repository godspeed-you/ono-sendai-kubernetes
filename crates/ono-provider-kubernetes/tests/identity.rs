//! What makes two observations the same object, and what makes them two.
//!
//! Specification §14 (common object metadata projection) and §16 (resource identity and
//! lifetime). Gate C lives here: delete and recreate with the same name must produce two resource
//! lifetimes, because a name is a label a human reuses and `metadata.uid` is what Kubernetes
//! guarantees about one object's life (§4 invariants 4 and 5).
//!
//! The other rule under test is §14.3, which is easy to break by accident. `resourceVersion` is
//! an opaque continuity token. It looks like a number, sorts like a number, and means neither: it
//! is not a timestamp, not comparable across resources, and not a clock.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::discovery::Gvk;
use ono_provider_kubernetes::object::{Identity, Object};

const POD: &str = r#"{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "checkout-7f9d",
    "namespace": "shop",
    "uid": "1a2b3c4d-0000-0000-0000-000000000001",
    "resourceVersion": "884213",
    "generation": 1,
    "creationTimestamp": "2026-09-05T10:00:00Z",
    "labels": {"app": "checkout", "tier": "web"},
    "annotations": {"example.io/note": "kept verbatim"},
    "finalizers": ["example.io/cleanup"],
    "ownerReferences": [
      {"apiVersion":"apps/v1","kind":"ReplicaSet","name":"checkout-6ac1",
       "uid":"9f9f9f9f-0000-0000-0000-000000000002","controller":true,
       "blockOwnerDeletion":true}
    ],
    "managedFields": [
      {"manager":"kube-controller-manager","operation":"Update","apiVersion":"v1",
       "time":"2026-09-05T10:00:01Z","fieldsType":"FieldsV1","fieldsV1":{"f:spec":{}}}
    ]
  },
  "spec": {"nodeName": "ip-10-42-2-19"},
  "status": {"phase": "Running"}
}"#;

fn pod() -> Object {
    Object::parse("kubernetes:prod", POD).expect("the pod reads")
}

#[test]
fn should_project_the_metadata_every_object_carries() {
    let pod = pod();
    assert_eq!(pod.name(), "checkout-7f9d");
    assert_eq!(pod.namespace(), Some("shop"));
    assert_eq!(pod.uid(), Some("1a2b3c4d-0000-0000-0000-000000000001"));
    assert_eq!(pod.resource_version(), Some("884213"));
    assert_eq!(pod.generation(), Some(1));
    assert_eq!(pod.creation_timestamp(), Some("2026-09-05T10:00:00Z"));
    assert_eq!(pod.deletion_timestamp(), None);
    assert_eq!(pod.gvk(), &Gvk::new("", "v1", "Pod"));
}

#[test]
fn should_keep_labels_and_annotations_as_structured_maps() {
    // §14.5: selectors and well-known keys may get meaning later, but arbitrary user keys must
    // survive verbatim. Flattening them into a display string is how a selector stops working.
    let pod = pod();
    assert_eq!(pod.label("app"), Some("checkout"));
    assert_eq!(pod.label("tier"), Some("web"));
    assert_eq!(pod.annotation("example.io/note"), Some("kept verbatim"));
    assert_eq!(pod.labels().len(), 2);
}

#[test]
fn should_identify_an_object_by_uid_rather_than_by_name() {
    // §16.1: the canonical identity is provider instance, group, kind and UID. The name is not
    // in it, because the name is what a human reuses.
    let pod = pod();
    let identity = pod.identity();
    assert_eq!(identity.provider_instance(), "kubernetes:prod");
    assert_eq!(identity.gvk(), &Gvk::new("", "v1", "Pod"));
    assert_eq!(identity.uid(), Some("1a2b3c4d-0000-0000-0000-000000000001"));
}

#[test]
fn should_treat_a_recreated_object_as_a_second_lifetime() {
    // Gate C, and §16.3. Same kind, same namespace, same name, different UID: two lifetimes, and
    // merging them would attribute the new object's state to the old one's history.
    let first = pod();
    let recreated = Object::parse(
        "kubernetes:prod",
        &POD.replace(
            "1a2b3c4d-0000-0000-0000-000000000001",
            "5e6f7a8b-0000-0000-0000-000000000003",
        ),
    )
    .expect("the recreated pod reads");

    assert_eq!(first.name(), recreated.name());
    assert_eq!(first.namespace(), recreated.namespace());
    assert_ne!(
        first.identity(),
        recreated.identity(),
        "same name, different UID is a different resource lifetime (§4 invariant 4)"
    );
    assert!(
        first.identity().is_same_locator(&recreated.identity()),
        "they occupy the same locator, which is what makes the discontinuity worth reporting"
    );
}

#[test]
fn should_keep_the_locator_separate_from_the_identity() {
    // §16.2: a locator is how a human looks an object up; it is not what makes it the same
    // object. Keeping them apart is what lets the provider say "this name now holds a different
    // object" rather than silently answering about the new one.
    let pod = pod();
    let locator = pod.locator();
    assert_eq!(
        locator.to_string(),
        "kubernetes:prod//v1/Pod/shop/checkout-7f9d"
    );
}

#[test]
fn should_refuse_to_treat_resource_version_as_a_number_or_a_time() {
    // §14.3 and §4 invariant 6: `resourceVersion` is an opaque continuity token. It is exposed as
    // the string the server sent and nothing offers to order it, because ordering it across
    // resources is meaningless and ordering it within one is the server's business.
    let pod = pod();
    let version = pod.resource_version().expect("the fixture carries one");
    assert_eq!(version, "884213", "the token is the string the server sent");

    // The type carries no ordering, so a comparison cannot be written by accident.
    let other = Object::parse("kubernetes:prod", &POD.replace("884213", "884300")).expect("reads");
    assert_ne!(pod.resource_version(), other.resource_version());
}

#[test]
fn should_not_conflate_generation_with_resource_version() {
    // §4 invariant 7. They answer different questions: generation counts spec changes, and
    // resourceVersion is the server's continuity token.
    let pod = pod();
    assert_eq!(pod.generation(), Some(1));
    assert_eq!(pod.resource_version(), Some("884213"));
}

#[test]
fn should_expose_owner_references_with_their_controller_flag() {
    // §24.3: where `controller: true`, the edge is stronger than a plain ownership record, and
    // the flag is what says so. Losing it would make every owner look like the controller.
    let pod = pod();
    let owners = pod.owner_references();
    assert_eq!(owners.len(), 1);
    let owner = &owners[0];
    assert_eq!(owner.kind(), "ReplicaSet");
    assert_eq!(owner.name(), "checkout-6ac1");
    assert_eq!(owner.uid(), "9f9f9f9f-0000-0000-0000-000000000002");
    assert!(owner.is_controller());
    assert_eq!(owner.api_version(), "apps/v1");
}

#[test]
fn should_make_finalizers_visible() {
    // §14.6 and §4 invariant 19: finalizers decide whether a deletion completes, so they must be
    // readable before anyone plans one. Gate H depends on this being present.
    let pod = pod();
    assert_eq!(pod.finalizers(), &["example.io/cleanup".to_owned()]);
    assert!(
        !pod.is_terminating(),
        "no deletionTimestamp, so not terminating"
    );
}

#[test]
fn should_report_an_object_with_a_deletion_timestamp_as_terminating() {
    // Gate H: deletion accepted while a finalizer holds the object is "terminating", never
    // "deleted". The object is still there and still answers.
    let terminating = POD.replace(
        r#""creationTimestamp": "2026-09-05T10:00:00Z","#,
        r#""creationTimestamp": "2026-09-05T10:00:00Z", "deletionTimestamp": "2026-09-05T11:00:00Z","#,
    );
    let pod = Object::parse("kubernetes:prod", &terminating).expect("reads");
    assert_eq!(pod.deletion_timestamp(), Some("2026-09-05T11:00:00Z"));
    assert!(pod.is_terminating());
    assert!(
        !pod.finalizers().is_empty(),
        "and the finalizer that holds it is nameable"
    );
}

#[test]
fn should_summarise_managed_fields_rather_than_dropping_them() {
    // §14.7: `managedFields` is large and rarely wanted, and it is also the evidence an apply
    // conflict is diagnosed from. Summarised by default, never absent.
    let pod = pod();
    let managers = pod.field_managers();
    assert_eq!(managers, &["kube-controller-manager".to_owned()]);
}

#[test]
fn should_keep_fields_no_projection_names() {
    // §12.5 and §4 invariant 17: unknown fields stay reachable. A provider that drops what its
    // types do not know turns an unfamiliar cluster into a wrong one.
    let pod = pod();
    assert_eq!(
        pod.field("/spec/nodeName").and_then(|value| value.as_str()),
        Some("ip-10-42-2-19")
    );
    assert_eq!(
        pod.field("/status/phase").and_then(|value| value.as_str()),
        Some("Running")
    );
    assert_eq!(pod.field("/spec/nothingHere"), None);
}

#[test]
fn should_degrade_identity_confidence_for_an_object_without_a_uid() {
    // §16.5: an object with no UID gets a weaker, recreation-ambiguous identity, and it must say
    // so rather than presenting a locator as if it were a lifetime.
    let no_uid = POD.replace(r#""uid": "1a2b3c4d-0000-0000-0000-000000000001","#, "");
    let object = Object::parse("kubernetes:prod", &no_uid).expect("reads");
    assert_eq!(object.uid(), None);

    let identity = object.identity();
    assert_eq!(identity.uid(), None);
    assert!(
        !identity.is_lifetime_stable(),
        "without a UID the identity cannot survive a recreation, and must admit it (§16.5)"
    );
    assert!(pod().identity().is_lifetime_stable());
}

#[test]
fn should_refuse_an_object_that_is_not_one() {
    let error = Object::parse("kubernetes:prod", r#"{"metadata":{"name":"x"}}"#)
        .expect_err("an object without apiVersion and kind is not one");
    assert!(
        format!("{error}").contains("kind"),
        "the error must say what is missing, got {error}"
    );
}

#[test]
fn should_carry_the_provider_instance_so_two_clusters_cannot_collide() {
    // Gate J: two contexts are two instances, and an identity that omitted the instance would
    // make an object in `dev` equal to one in `prod` whenever their UIDs happened to match.
    let here = pod();
    let there = Object::parse("kubernetes:dev", POD).expect("reads");
    assert_ne!(here.identity(), there.identity());
    assert_eq!(here.uid(), there.uid(), "the fixture is the same bytes");
}

#[test]
fn should_expose_a_cluster_scoped_object_without_inventing_a_namespace() {
    // §9.2: a cluster-scoped object must not be given a fake namespace.
    let node = r#"{
      "apiVersion":"v1","kind":"Node",
      "metadata":{"name":"ip-10-42-2-19","uid":"aaaa-0001","resourceVersion":"12"},
      "spec":{"providerID":"aws:///eu-central-1a/i-0abc123"}
    }"#;
    let node = Object::parse("kubernetes:prod", node).expect("reads");
    assert_eq!(node.namespace(), None);
    assert_eq!(
        node.locator().to_string(),
        "kubernetes:prod//v1/Node/ip-10-42-2-19"
    );
}

#[test]
fn should_let_two_identities_of_the_same_object_compare_equal() {
    let first = pod();
    let again = pod();
    assert_eq!(first.identity(), again.identity());
    let identity: Identity = first.identity();
    assert_eq!(identity, again.identity());
}

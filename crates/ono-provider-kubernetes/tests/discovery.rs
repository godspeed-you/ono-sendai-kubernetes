//! What the connected API server actually serves.
//!
//! Specification §11 (API discovery) and §13 (Kubernetes type identity). Discovery is what makes
//! this provider work against a cluster nobody compiled it for: the resources it can answer for
//! are the ones the server says it serves, never a list baked in at build time (§4 invariant 2).
//!
//! The rule that costs the most to get wrong is §13.1. **GVK** identifies an object and its
//! schema; **GVR** identifies the REST collection it lives in. `Pod` and `pods` are not the same
//! string, the difference is not always an `s`, and code that treats them as interchangeable is
//! wrong even where it happens to work.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::discovery::{Discovery, Scope, Verb};

/// `/api` — the unnamed core group, whose `apiVersion` is a bare `v1`.
const CORE_VERSIONS: &str = r#"{"kind":"APIVersions","versions":["v1"]}"#;

/// `/api/v1`, trimmed to the resources these tests reason about.
const CORE_V1: &str = r#"{
  "kind": "APIResourceList",
  "groupVersion": "v1",
  "resources": [
    {"name":"pods","singularName":"pod","namespaced":true,"kind":"Pod",
     "verbs":["get","list","watch","create","delete"],"shortNames":["po"]},
    {"name":"pods/status","singularName":"","namespaced":true,"kind":"Pod",
     "verbs":["get","patch","update"]},
    {"name":"pods/log","singularName":"","namespaced":true,"kind":"Pod","verbs":["get"]},
    {"name":"nodes","singularName":"node","namespaced":false,"kind":"Node",
     "verbs":["get","list","watch"],"shortNames":["no"]},
    {"name":"endpoints","singularName":"endpoints","namespaced":true,"kind":"Endpoints",
     "verbs":["get","list"]}
  ]
}"#;

/// `/apis` — the named groups.
const GROUPS: &str = r#"{
  "kind": "APIGroupList",
  "groups": [
    {"name":"apps",
     "versions":[{"groupVersion":"apps/v1","version":"v1"}],
     "preferredVersion":{"groupVersion":"apps/v1","version":"v1"}},
    {"name":"example.io",
     "versions":[{"groupVersion":"example.io/v1","version":"v1"},
                 {"groupVersion":"example.io/v1alpha1","version":"v1alpha1"}],
     "preferredVersion":{"groupVersion":"example.io/v1","version":"v1"}}
  ]
}"#;

const APPS_V1: &str = r#"{
  "kind": "APIResourceList",
  "groupVersion": "apps/v1",
  "resources": [
    {"name":"deployments","singularName":"deployment","namespaced":true,"kind":"Deployment",
     "verbs":["get","list","watch","create","update","patch","delete"],"shortNames":["deploy"]},
    {"name":"deployments/scale","singularName":"","namespaced":true,"kind":"Scale",
     "verbs":["get","update","patch"]}
  ]
}"#;

/// A custom resource that did not exist when this provider was compiled — Gate A's subject.
const WIDGETS_V1: &str = r#"{
  "kind": "APIResourceList",
  "groupVersion": "example.io/v1",
  "resources": [
    {"name":"widgets","singularName":"widget","namespaced":true,"kind":"Widget",
     "verbs":["get","list","watch"],"shortNames":["wg"]}
  ]
}"#;

/// A discovery snapshot built the way a session builds one.
fn discovered() -> Discovery {
    Discovery::builder()
        .core_versions(CORE_VERSIONS)
        .expect("the core version list reads")
        .resources(CORE_V1)
        .expect("the core resource list reads")
        .groups(GROUPS)
        .expect("the group list reads")
        .resources(APPS_V1)
        .expect("the apps resource list reads")
        .resources(WIDGETS_V1)
        .expect("the widget resource list reads")
        .build()
}

#[test]
fn should_learn_a_resource_the_server_serves() {
    let discovery = discovered();
    let pods = discovery.resource("v1", "pods").expect("`pods` is served");

    assert_eq!(pods.kind(), "Pod");
    assert_eq!(pods.scope(), Scope::Namespaced);
    assert!(pods.supports(Verb::List));
    assert!(pods.supports(Verb::Watch));
}

#[test]
fn should_keep_the_core_group_unambiguous() {
    // §13.3: the core group's REST path and `apiVersion` omit a group name, and that must not
    // collide with a hypothetical non-core `Pod`. The empty group is a group, not a missing one.
    let discovery = discovered();
    let pods = discovery.resource("v1", "pods").expect("`pods` is served");

    assert_eq!(pods.group(), "", "the core group's name is empty");
    assert_eq!(pods.version(), "v1");
    assert_eq!(
        pods.gvk().to_string(),
        "/v1/Pod",
        "a core kind renders with its empty group present, not elided"
    );

    let deployment = discovery
        .resource("apps/v1", "deployments")
        .expect("`deployments` is served");
    assert_eq!(deployment.gvk().to_string(), "apps/v1/Deployment");
}

#[test]
fn should_not_confuse_the_kind_with_the_rest_resource() {
    // §13.1: GVK identifies the object; GVR identifies the collection. Two different strings and
    // two different questions, and `Endpoints` is why the difference cannot be an `s` rule.
    let discovery = discovered();

    let endpoints = discovery
        .resource("v1", "endpoints")
        .expect("`endpoints` is served");
    assert_eq!(endpoints.kind(), "Endpoints");
    assert_eq!(endpoints.plural(), "endpoints");
    assert_eq!(endpoints.gvr().to_string(), "/v1/endpoints");
    assert_eq!(endpoints.gvk().to_string(), "/v1/Endpoints");

    // And a lookup by kind is a different lookup from one by resource.
    assert_eq!(
        discovery.by_kind("v1", "Pod").map(|found| found.plural()),
        Some("pods")
    );
    assert!(
        discovery.by_kind("v1", "pods").is_none(),
        "`pods` is a resource name, never a kind"
    );
}

#[test]
fn should_report_cluster_scope_where_the_server_declares_it() {
    // §9.2: a cluster-scoped resource must not be given a fake namespace.
    let discovery = discovered();
    let nodes = discovery
        .resource("v1", "nodes")
        .expect("`nodes` is served");
    assert_eq!(nodes.scope(), Scope::Cluster);
}

#[test]
fn should_treat_a_subresource_as_a_subresource() {
    // `pods/status` and `pods/log` are not resources a user enumerates; they hang off `pods`.
    // Listing them beside `pods` would offer nouns that cannot be listed.
    let discovery = discovered();

    let pods = discovery.resource("v1", "pods").expect("`pods` is served");
    assert_eq!(
        pods.subresources(),
        &["log".to_owned(), "status".to_owned()],
        "the subresources belong to their parent, sorted so the answer is stable"
    );
    assert!(
        !discovery
            .listable()
            .any(|found| found.plural().contains('/')),
        "no subresource appears among the things a user can list"
    );
}

#[test]
fn should_find_a_custom_resource_nobody_compiled_in() {
    // Gate A: a CRD invented after this provider was built is discoverable without recompiling.
    // Nothing in the implementation may name `Widget`.
    let discovery = discovered();
    let widget = discovery
        .resource("example.io/v1", "widgets")
        .expect("`widgets` is served");

    assert_eq!(widget.kind(), "Widget");
    assert_eq!(widget.group(), "example.io");
    assert_eq!(widget.scope(), Scope::Namespaced);
    assert!(widget.supports(Verb::Watch));
}

#[test]
fn should_offer_a_short_name_without_letting_it_become_identity() {
    // Short names are a convenience for typing. They are not identity, and two groups may use
    // the same one, so resolving one must be able to say that it was ambiguous rather than
    // picking a winner (§13.5, and §35.8's rule against arbitrary type priority).
    let discovery = discovered();
    assert_eq!(
        discovery.by_short_name("po").map(|found| found.plural()),
        Some("pods")
    );
    assert_eq!(discovery.by_short_name("nope"), None);
}

#[test]
fn should_report_a_resource_the_server_does_not_serve_as_not_served() {
    // §11.5 and §21.4: "not served" is its own answer, distinguishable from "none exist". A
    // provider that returns nothing for an API the cluster never had is lying by omission.
    let discovery = discovered();
    assert!(discovery.resource("v1", "widgets").is_none());
    assert!(discovery.resource("batch/v1", "jobs").is_none());
    assert!(
        !discovery.serves_group_version("batch/v1"),
        "a group the server never listed is not served"
    );
    assert!(discovery.serves_group_version("apps/v1"));
}

#[test]
fn should_keep_every_served_version_rather_than_only_the_preferred_one() {
    // §13.4: two served versions of one resource may differ in fields and semantics, so the
    // preferred version is a default and never the only one reachable.
    let discovery = discovered();
    let mut versions = discovery.versions_of("example.io");
    versions.sort();
    assert_eq!(versions, vec!["v1", "v1alpha1"]);
    assert_eq!(discovery.preferred_version("example.io"), Some("v1"));
}

#[test]
fn should_name_every_group_it_serves_including_the_core_group() {
    // A query that names a kind and no group has to look in every group the server serves, and
    // the list of groups is the server's answer rather than a table in this crate (§4
    // invariants 1-2, §11.1). The core group is in it under its empty name, because §13.3 makes
    // it a group rather than a gap.
    let discovery = discovered();
    let mut groups: Vec<&str> = discovery.groups().collect();
    groups.sort_unstable();
    assert!(
        groups.contains(&""),
        "the core group is served and is named by the empty string, got {groups:?}"
    );
    assert!(groups.contains(&"apps"));
    assert!(groups.contains(&"example.io"));
    assert!(
        !groups.contains(&"batch"),
        "a group the server never listed is not one it serves, got {groups:?}"
    );
}

#[test]
fn should_refuse_a_discovery_document_it_cannot_read() {
    // Discovery is the ground everything else stands on. Half-parsing it and carrying on would
    // make every later answer quietly incomplete.
    let error = Discovery::builder()
        .resources("{\"kind\":\"APIResourceList\"")
        .expect_err("a truncated document is not a resource list");
    assert!(
        format!("{error}").contains("resource list"),
        "the error must say which document failed, got {error}"
    );
}

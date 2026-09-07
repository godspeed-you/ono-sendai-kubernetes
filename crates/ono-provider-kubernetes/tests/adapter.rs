//! The semantic adapter registry: curated ecosystem knowledge beside the record, never in it.
//!
//! Specification §33.8, §58.4, §15.4 and §66.2, with ADR-0062. The property every test here
//! circles is §33.8's `MUST NOT`: an adapter contributes roles, edges and views *beside* the
//! dynamically discovered representation, and there is no path by which it could replace,
//! narrow or invent one. The second property is §23.5's: an adapter's relationships carry
//! evidence a reader can check, and an inference does not become one by being registered.
//!
//! The adapter under test is written here, outside the crate, against the public trait — which
//! is the claim §66.2 makes about a contributor.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::adapter::{
    Adapter, Compatibility, Context, Coverage, Registry, View, ViewField,
};
use ono_provider_kubernetes::discovery::Gvk;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::place::{Place, SemanticRole};
use ono_provider_kubernetes::relationship::{Edge, Evidence, Relation, Target};

// --- fixtures ----------------------------------------------------------------------------------

/// A custom resource of the fixture group, at the version the test adapter has seen.
const WIDGET_V1: &str = r#"{
  "apiVersion":"ono.test/v1","kind":"Widget",
  "metadata":{"name":"left-handed","namespace":"shop","uid":"w-1","resourceVersion":"41",
    "labels":{"tier":"edge"}},
  "spec":{"serviceName":"checkout","replicas":3,"gadget":{"colour":"teal","teeth":12}},
  "status":{"phase":"Ready","observedGeneration":2}
}"#;

/// The same object at the other version the adapter lists.
const WIDGET_V1BETA1: &str = r#"{
  "apiVersion":"ono.test/v1beta1","kind":"Widget",
  "metadata":{"name":"left-handed","namespace":"shop","uid":"w-1"},
  "spec":{"serviceName":"checkout"}
}"#;

/// The same object at a version the adapter has never seen (§5.3).
const WIDGET_V2ALPHA1: &str = r#"{
  "apiVersion":"ono.test/v2alpha1","kind":"Widget",
  "metadata":{"name":"tomorrow","namespace":"shop","uid":"w-2"},
  "spec":{"serviceName":"checkout","backend":{"name":"checkout-v2"}}
}"#;

/// A kind of the fixture group the adapter has no rule for.
const GIZMO: &str = r#"{
  "apiVersion":"ono.test/v1","kind":"Gizmo",
  "metadata":{"name":"whirring","namespace":"shop","uid":"g-1"},
  "spec":{"serviceName":"checkout"}
}"#;

/// A `Widget` of somebody else's group (§13.5): the same kind name, a different resource.
const STRANGER: &str = r#"{
  "apiVersion":"acme.example.com/v1","kind":"Widget",
  "metadata":{"name":"left-handed","namespace":"shop","uid":"w-9"},
  "spec":{"serviceName":"checkout","mystery":true}
}"#;

/// A Gateway API route, for the built-in member.
const HTTPROUTE: &str = r#"{
  "apiVersion":"gateway.networking.k8s.io/v1","kind":"HTTPRoute",
  "metadata":{"name":"shop","namespace":"shop","uid":"route-1"},
  "spec":{
    "parentRefs":[{"name":"public","namespace":"gateways"}],
    "rules":[{"backendRefs":[{"name":"checkout","port":80}]}]}
}"#;

/// The same route at a version the built-in member has not seen.
const FUTURE_HTTPROUTE: &str = r#"{
  "apiVersion":"gateway.networking.k8s.io/v99","kind":"HTTPRoute",
  "metadata":{"name":"tomorrow","namespace":"shop","uid":"route-2"},
  "spec":{"parentRefs":[{"name":"public"}]}
}"#;

fn object(json: &str) -> Object {
    Object::parse("kubernetes:prod", json).expect("the fixture reads")
}

fn gvk(group: &str, version: &str, kind: &str) -> Gvk {
    Gvk::new(group, version, kind)
}

// --- the adapter a contributor would write ----------------------------------------------------

/// The fixture group's adapter: what a `Widget` means, at the versions this has seen.
struct WidgetAdapter;

impl Adapter for WidgetAdapter {
    fn name(&self) -> &'static str {
        "ono-test-widget"
    }

    fn coverage(&self) -> Coverage {
        Coverage::new("ono.test", &["Widget"], &["v1beta1", "v1"])
    }

    fn semantic_roles(&self, gvk: &Gvk) -> Vec<SemanticRole> {
        match gvk.kind() {
            "Widget" => vec![SemanticRole::Workload],
            _ => Vec::new(),
        }
    }

    fn relationships(&self, object: &Object, _context: &Context<'_>) -> Vec<Edge> {
        let Some(name) = object
            .field("/spec/serviceName")
            .and_then(serde_json::Value::as_str)
        else {
            return Vec::new();
        };
        vec![
            Edge::new(
                object.identity(),
                Relation::UsesService,
                Target::new("Service", name)
                    .with_api_version(Some("v1"))
                    .in_namespace(object.namespace()),
                Evidence::NativeField {
                    path: "/spec/serviceName".to_owned(),
                    value: name.to_owned(),
                },
            )
            .with_supporting(vec![Evidence::Derived {
                rule: format!("curated {} adapter for {}", self.name(), object.gvk()),
            }]),
        ]
    }

    fn default_view(&self, _object: &Object) -> Option<View> {
        Some(View::new(vec![
            ViewField::new("service", "/spec/serviceName"),
            ViewField::new("phase", "/status/phase"),
        ]))
    }
}

/// An adapter that correlates rather than reads: what §23.5 forbids, written to be refused.
struct GuessingAdapter;

impl Adapter for GuessingAdapter {
    fn name(&self) -> &'static str {
        "guessing"
    }

    fn coverage(&self) -> Coverage {
        Coverage::new("ono.test", &["Widget"], &["v1"])
    }

    fn relationships(&self, object: &Object, _context: &Context<'_>) -> Vec<Edge> {
        let source = object.identity();
        vec![
            // A name that looks like a Deployment's: inference as the deciding evidence.
            Edge::new(
                source.clone(),
                Relation::OwnedBy,
                Target::new("Deployment", object.name())
                    .with_api_version(Some("apps/v1"))
                    .in_namespace(object.namespace()),
                Evidence::Inferred {
                    reason: "the Widget's name matches a Deployment's".to_owned(),
                },
            ),
            // A field genuinely read, with an inference riding along as support.
            Edge::new(
                source.clone(),
                Relation::UsesService,
                Target::new("Service", "checkout")
                    .with_api_version(Some("v1"))
                    .in_namespace(object.namespace()),
                Evidence::NativeField {
                    path: "/spec/serviceName".to_owned(),
                    value: "checkout".to_owned(),
                },
            )
            .with_supporting(vec![Evidence::Inferred {
                reason: "and its labels look like the Service's".to_owned(),
            }]),
            // A field genuinely read, and nothing else: the one edge that may pass.
            Edge::new(
                source,
                Relation::ReferencesConfig,
                Target::new("ConfigMap", "widget-config")
                    .with_api_version(Some("v1"))
                    .in_namespace(object.namespace()),
                Evidence::NativeField {
                    path: "/spec/gadget/colour".to_owned(),
                    value: "teal".to_owned(),
                },
            ),
        ]
    }
}

/// A second member for the same kind, stating one more role and nothing else.
struct PolicyOverlay;

impl Adapter for PolicyOverlay {
    fn name(&self) -> &'static str {
        "policy-overlay"
    }

    fn coverage(&self) -> Coverage {
        Coverage::new("ono.test", &["Widget"], &["v1"])
    }

    fn semantic_roles(&self, _gvk: &Gvk) -> Vec<SemanticRole> {
        vec![SemanticRole::Policy]
    }
}

fn registry() -> Registry {
    Registry::empty().with(WidgetAdapter)
}

// --- the tests ---------------------------------------------------------------------------------

#[test]
fn should_leave_an_unknown_crd_whole_and_unadapted_when_no_adapter_covers_it() {
    // §15.4: adapters "MUST NOT be required for arbitrary CRDs to function as resources". A kind
    // nobody wrote an adapter for — the same kind name under another group, even — is exactly
    // what it was before the registry existed: parsed, addressable, its own fields.
    let stranger = object(STRANGER);
    let registry = registry();

    assert_eq!(
        registry.compatibility(stranger.gvk()),
        Compatibility::NotCovered,
        "a `Widget` of another group is not this adapter's `Widget` (§13.5)"
    );
    assert!(registry.adapters_for(stranger.gvk()).is_empty());
    assert!(registry.semantic_roles(stranger.gvk()).is_empty());
    assert!(
        registry
            .relationships(&stranger, &Context::default())
            .is_empty()
    );
    assert!(registry.default_view(&stranger).is_none());
    assert_eq!(
        stranger
            .field("/spec/mystery")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "and every field the cluster served is still there"
    );
    let place = Place::of_object(&stranger).expect("still addressable (§33.1)");
    assert!(place.roles().is_empty());
    assert_eq!(
        Registry::builtin().compatibility(stranger.gvk()),
        Compatibility::NotCovered,
        "the built-in members do not claim it either"
    );
}

#[test]
fn should_give_an_adapted_crd_its_roles_and_an_edge_that_carries_evidence() {
    // §33.8: an adapter contributes semantic roles and relationship extractors. The edge is an
    // ordinary `Edge` in the ordinary vocabulary, deciding on a field it can cite (Gate D), with
    // the adapter and the version it assumed riding along as supporting evidence.
    let widget = object(WIDGET_V1);
    let registry = registry();

    assert_eq!(registry.compatibility(widget.gvk()), Compatibility::Adapted);
    assert_eq!(
        registry
            .adapters_for(widget.gvk())
            .iter()
            .map(|adapter| adapter.name())
            .collect::<Vec<_>>(),
        ["ono-test-widget"]
    );
    assert_eq!(
        registry.semantic_roles(widget.gvk()),
        [SemanticRole::Workload]
    );

    let edges = registry.relationships(&widget, &Context::default());
    assert_eq!(edges.len(), 1, "{edges:?}");
    let edge = &edges[0];
    assert_eq!(edge.relation(), Relation::UsesService);
    assert_eq!(edge.target().kind(), "Service");
    assert_eq!(edge.target().name(), "checkout");
    assert_eq!(edge.target().namespace(), Some("shop"));
    assert_eq!(
        edge.evidence(),
        &Evidence::NativeField {
            path: "/spec/serviceName".to_owned(),
            value: "checkout".to_owned(),
        }
    );
    assert!(
        edge.supporting().iter().any(|evidence| matches!(
            evidence,
            Evidence::Derived { rule } if rule.contains("ono-test-widget") && rule.contains("ono.test/v1")
        )),
        "the adapter names itself and the version it read: {:?}",
        edge.supporting()
    );

    let view = registry
        .default_view(&widget)
        .expect("the adapter states a view");
    assert_eq!(
        view.fields()
            .iter()
            .map(|field| (field.label(), field.pointer()))
            .collect::<Vec<_>>(),
        [("service", "/spec/serviceName"), ("phase", "/status/phase")]
    );
}

#[test]
fn should_adapt_every_served_version_the_adapter_names() {
    // §33.8's "version compatibility" and §27.3's "version/schema aware": compatibility is a
    // list the adapter states, and each version on it is adapted on its own merits.
    let registry = registry();
    for json in [WIDGET_V1, WIDGET_V1BETA1] {
        let widget = object(json);
        assert_eq!(
            registry.compatibility(widget.gvk()),
            Compatibility::Adapted,
            "{} is on the list",
            widget.gvk()
        );
        assert_eq!(
            registry.relationships(&widget, &Context::default()).len(),
            1,
            "{} yields the curated edge",
            widget.gvk()
        );
    }
    assert_eq!(
        registry.compatibility(&gvk("ono.test", "v1beta1", "Widget")),
        Compatibility::Adapted,
        "a lookup by GVK alone answers the same way"
    );
}

#[test]
fn should_fall_back_to_dynamic_behaviour_for_a_version_the_adapter_did_not_name() {
    // §5.3: the field names of a version the adapter has not seen are not known to mean what
    // today's mean, and reading them anyway is the newest-version assumption. The object stays
    // fully available through universal dynamic support (§15.1); it just gets no curated
    // semantics — no roles, no edges, no view.
    let future = object(WIDGET_V2ALPHA1);
    let registry = registry();

    assert_eq!(
        registry.compatibility(future.gvk()),
        Compatibility::UnknownVersion,
        "the group and kind are known and the version is not, and the answer says which"
    );
    assert!(registry.adapters_for(future.gvk()).is_empty());
    assert!(registry.semantic_roles(future.gvk()).is_empty());
    assert!(
        registry
            .relationships(&future, &Context::default())
            .is_empty(),
        "no guessed edge from a schema nobody has seen"
    );
    assert!(registry.default_view(&future).is_none());
    assert_eq!(
        future
            .field("/spec/backend/name")
            .and_then(serde_json::Value::as_str),
        Some("checkout-v2"),
        "the object is whole"
    );

    // A kind of the same group the adapter never listed is not covered at all.
    let gizmo = object(GIZMO);
    assert_eq!(
        registry.compatibility(gizmo.gvk()),
        Compatibility::NotCovered
    );
    assert!(
        registry
            .relationships(&gizmo, &Context::default())
            .is_empty()
    );
}

#[test]
fn should_leave_the_record_field_for_field_what_dynamic_projection_gave() {
    // §33.8: "An adapter MUST NOT replace the underlying dynamically discovered object
    // representation." The strongest form of the guarantee is in the signatures — nothing on
    // `Adapter` or `Registry` takes `&mut Object` or returns one — and this is the observable
    // form: after every method has run, the object is byte-for-byte the object that was parsed,
    // and the view an adapter states is pointers *into* it, not a second document.
    let widget = object(WIDGET_V1);
    let before = widget.native().clone();
    let registry = registry();
    let context = Context::default();

    let _roles = registry.semantic_roles(widget.gvk());
    let _edges = registry.relationships(&widget, &context);
    let view = registry.default_view(&widget).expect("a view");
    let _evidence = registry.cross_system_evidence(&widget);

    assert_eq!(
        widget.native(),
        &before,
        "not a field added, removed or rewritten"
    );
    assert_eq!(
        widget
            .field("/spec/gadget/teeth")
            .and_then(serde_json::Value::as_i64),
        Some(12),
        "a field the adapter has no opinion about is still there"
    );
    assert_eq!(widget.label("tier"), Some("edge"));
    assert_eq!(widget.resource_version(), Some("41"));
    for field in view.fields() {
        assert!(
            widget.field(field.pointer()).is_some(),
            "a view names pointers that resolve into the object it was given: {}",
            field.pointer()
        );
    }
}

#[test]
fn should_never_let_an_adapter_present_an_inference_as_a_relationship() {
    // §23.5 and §4 invariant 20: name similarity is not promoted to a verified relationship,
    // and it is not promoted by being registered either. The registry keeps every edge whose
    // deciding *or* supporting evidence is an inference out of `relationships`, and lets the one
    // that rests on a field through — so the property the plugin's
    // `should_never_present_an_inference_as_a_relationship` asserts holds for every member,
    // including one written to break it.
    let widget = object(WIDGET_V1);
    let registry = Registry::empty().with(GuessingAdapter);

    let edges = registry.relationships(&widget, &Context::default());
    assert_eq!(
        edges.len(),
        1,
        "two of the three were inferences, in whole or in part: {edges:?}"
    );
    assert_eq!(edges[0].relation(), Relation::ReferencesConfig);
    for edge in &edges {
        assert!(
            !matches!(edge.evidence(), Evidence::Inferred { .. }),
            "{edge:?}"
        );
        assert!(
            !edge
                .supporting()
                .iter()
                .any(|evidence| matches!(evidence, Evidence::Inferred { .. })),
            "{edge:?}"
        );
        assert!(
            [
                "native-field",
                "owner-reference",
                "selector",
                "convention",
                "adapter-derivation",
            ]
            .contains(&edge.evidence().class()),
            "every edge names one of Gate D's classes: {}",
            edge.evidence().class()
        );
    }
}

#[test]
fn should_concatenate_what_two_members_state_about_one_kind() {
    // ADR-0062: two adapters may cover one GVK, each contributes, and the registry does not
    // rank them. Roles come back in registration order and nothing is de-duplicated on a
    // member's behalf.
    let widget = object(WIDGET_V1);
    let registry = Registry::empty().with(WidgetAdapter).with(PolicyOverlay);

    assert_eq!(
        registry
            .adapters_for(widget.gvk())
            .iter()
            .map(|adapter| adapter.name())
            .collect::<Vec<_>>(),
        ["ono-test-widget", "policy-overlay"]
    );
    assert_eq!(
        registry.semantic_roles(widget.gvk()),
        [SemanticRole::Workload, SemanticRole::Policy]
    );
    assert_eq!(
        registry.relationships(&widget, &Context::default()).len(),
        1,
        "the overlay states no edge, so none is invented for it"
    );
}

#[test]
fn should_register_the_gateway_api_as_a_built_in_member() {
    // §27.3's "curated Gateway API adapter", as a member of the registry rather than a branch in
    // the workload module: keyed on its group, listing the versions it has seen, answering the
    // same edges it always answered.
    let registry = Registry::builtin();
    assert!(
        registry
            .members()
            .any(|adapter| adapter.name() == "gateway-api"),
        "the Gateway API is the first genuine member"
    );

    let route = object(HTTPROUTE);
    assert_eq!(registry.compatibility(route.gvk()), Compatibility::Adapted);
    let edges = registry.relationships(&route, &Context::default());
    assert!(
        edges
            .iter()
            .any(|edge| edge.relation() == Relation::AttachesTo
                && edge.target().kind() == "Gateway"
                && edge.target().namespace() == Some("gateways")),
        "{edges:?}"
    );
    assert!(
        edges
            .iter()
            .any(|edge| edge.relation() == Relation::RoutesTo && edge.target().name() == "checkout"),
        "{edges:?}"
    );
    assert_eq!(
        registry.semantic_roles(route.gvk()),
        [SemanticRole::NetworkEndpoint]
    );

    let future = object(FUTURE_HTTPROUTE);
    assert_eq!(
        registry.compatibility(future.gvk()),
        Compatibility::UnknownVersion
    );
    assert!(
        registry
            .relationships(&future, &Context::default())
            .is_empty()
    );
}

#[test]
fn should_give_a_place_the_roles_the_built_in_registry_states() {
    // §36.1 and §36.2 through the registry: a place of an adapted kind answers to the role its
    // adapter states, and a place of a version the adapter has not seen answers to none — the
    // same fallback the edges have, so that a role cannot outlive the schema it was judged on.
    let route = Place::of_object(&object(HTTPROUTE)).expect("addressable");
    assert_eq!(route.roles(), [SemanticRole::NetworkEndpoint]);
    assert!(route.has_role(SemanticRole::NetworkEndpoint));

    let future = Place::of_object(&object(FUTURE_HTTPROUTE)).expect("addressable");
    assert!(
        future.roles().is_empty(),
        "an unadapted version has no overlay, and is still a place"
    );
    assert_eq!(future.gvk().map(Gvk::kind), Some("HTTPRoute"));
}

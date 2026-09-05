//! Kubernetes as places in Ono's world, and the relations that lead between them.
//!
//! Specification §9 (scope model), §35 (spatial mapping) and §36 (semantic roles), with Gate J
//! (§62.10) running through all of it.
//!
//! Four rules are easy to break by accident and are held here deliberately.
//!
//! **A place URI is an identity, so it must parse back** (§35.3). A renderer that produces a
//! pretty string nobody can read again gives the user an address they cannot type.
//!
//! **`up` is spatial, not ownership** (§35.6). A Pod's Deployment is its semantic owner through a
//! ReplicaSet; its spatial parent is the namespace. Conflating the two makes `up` unpredictable —
//! sometimes a container, sometimes a controller.
//!
//! **A cluster-scoped resource never gets a namespace** (§9.2). One flat URI shape with an
//! optional namespace slot is how a Node quietly acquires `default`.
//!
//! **Semantic roles are overlays** (§36.1, §36.3). A Deployment that renders as `workload` and
//! stops rendering as a Deployment has lost the thing that makes it operable.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::discovery::{Gvk, Scope};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::place::{
    NameEntry, Neighbourhood, Place, PlaceError, PlaceShape, PlaceUri, Proximity, SemanticRole,
    TypeSegment, Waypoint, enter_by_name,
};
use ono_provider_kubernetes::relationship::{Evidence, Graph, Relation};

const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{
    "name":"checkout-7c9d","namespace":"production","uid":"pod-1",
    "labels":{"app":"checkout"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"ReplicaSet","name":"checkout-6ac1","uid":"rs-1",
       "controller":true}
    ]
  },
  "spec":{"nodeName":"worker-03","containers":[{"name":"app","image":"checkout:1"}]}
}"#;

const NODE: &str = r#"{
  "apiVersion":"v1","kind":"Node",
  "metadata":{"name":"worker-03","uid":"node-1"},
  "spec":{"providerID":"aws:///eu-central-1a/i-0abc"}
}"#;

const SERVICE: &str = r#"{
  "apiVersion":"v1","kind":"Service",
  "metadata":{"name":"checkout","namespace":"production","uid":"svc-1"},
  "spec":{"selector":{"app":"checkout"},"ports":[{"port":80}]}
}"#;

const DEPLOYMENT: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"checkout","namespace":"production","uid":"dep-1"},
  "spec":{"replicas":3}
}"#;

const ENDPOINT_SLICE: &str = r#"{
  "apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice",
  "metadata":{"name":"checkout-x9f2","namespace":"production","uid":"eps-1",
              "labels":{"kubernetes.io/service-name":"checkout"}}
}"#;

const INGRESS: &str = r#"{
  "apiVersion":"networking.k8s.io/v1","kind":"Ingress",
  "metadata":{"name":"shop","namespace":"production","uid":"ing-1"}
}"#;

const NETWORK_POLICY: &str = r#"{
  "apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
  "metadata":{"name":"checkout-ingress","namespace":"production","uid":"np-1"},
  "spec":{"podSelector":{"matchLabels":{"app":"checkout"}}}
}"#;

const CONFIG_MAP: &str = r#"{
  "apiVersion":"v1","kind":"ConfigMap",
  "metadata":{"name":"checkout-config","namespace":"production","uid":"cm-1"}
}"#;

const NAMESPACE: &str = r#"{
  "apiVersion":"v1","kind":"Namespace",
  "metadata":{"name":"production","uid":"ns-1"}
}"#;

const CUSTOM_RESOURCE: &str = r#"{
  "apiVersion":"acme.example.com/v1","kind":"Widget",
  "metadata":{"name":"left-handed","namespace":"production","uid":"widget-1"}
}"#;

fn object(instance: &str, json: &str) -> Object {
    Object::parse(instance, json).expect("the fixture reads")
}

fn place(instance: &str, json: &str) -> Place {
    Place::of_object(&object(instance, json)).expect("the fixture is addressable")
}

/// §9.1 and §35.2: a provider instance is rooted in a cluster place, and the instance is part of
/// the address rather than ambient state. The mistake is a root that says only `k8s://` and
/// leaves "which cluster" to a hidden current-context — which is exactly the crossover Gate J
/// forbids.
#[test]
fn should_root_a_provider_instance_in_a_cluster_place() {
    let root = PlaceUri::cluster_root("kubernetes:prod").expect("a context is a usable authority");

    assert_eq!(root.to_string(), "k8s://prod/");
    assert_eq!(root.shape(), PlaceShape::Cluster);
    assert_eq!(root.instance(), "kubernetes:prod");
    assert_eq!(root.namespace(), None);
}

/// §35.3: "URI identity MUST remain stable and machine-parseable". Rendering without parsing is
/// the plausible half-implementation: it looks complete in a screenshot and gives the user an
/// address that nothing can consume.
#[test]
fn should_round_trip_every_place_shape_through_its_uri() {
    let shapes = [
        (
            PlaceUri::cluster_root("kubernetes:prod").expect("root"),
            "k8s://prod/",
        ),
        (
            PlaceUri::of_namespace("kubernetes:prod", "production").expect("namespace"),
            "k8s://prod/ns/production/",
        ),
        (
            PlaceUri::namespaced(
                "kubernetes:prod",
                "production",
                TypeSegment::of(&Gvk::new("", "v1", "Pod")),
                "checkout-7c9d",
            )
            .expect("pod place"),
            "k8s://prod/ns/production/pod/checkout-7c9d",
        ),
        (
            PlaceUri::cluster_scoped(
                "kubernetes:prod",
                TypeSegment::of(&Gvk::new("", "v1", "Node")),
                "worker-03",
            )
            .expect("node place"),
            "k8s://prod/cluster/node/worker-03",
        ),
    ];

    for (uri, text) in shapes {
        assert_eq!(uri.to_string(), text, "rendering is the spec's grammar");
        let parsed = PlaceUri::parse(text).expect("a rendered place URI parses back");
        assert_eq!(parsed, uri, "{text} does not survive a round trip");
    }
}

/// §9.2: cluster-scoped resources "MUST not be assigned a fake namespace", so the two shapes are
/// different grammars rather than one grammar with an optional slot. With a single shape, parsing
/// `k8s://prod/x/node/worker-03` has to guess whether `x` is a namespace, and a Node ends up in
/// `default`.
#[test]
fn should_keep_cluster_scope_and_namespace_scope_in_different_shapes() {
    let node = PlaceUri::parse("k8s://prod/cluster/node/worker-03").expect("cluster-scoped place");
    let pod =
        PlaceUri::parse("k8s://prod/ns/production/pod/checkout-7c9d").expect("namespaced place");

    assert_eq!(node.shape(), PlaceShape::ClusterResource);
    assert_eq!(node.namespace(), None, "a Node has no namespace to report");
    assert_eq!(pod.shape(), PlaceShape::NamespacedResource);
    assert_eq!(pod.namespace(), Some("production"));
    assert_ne!(node, pod);
}

/// §9.2 again, from the object side. Discovery is authoritative about scope (§11.1), so a Node
/// that somehow carries `metadata.namespace` is a contradiction to report rather than a namespace
/// to adopt. The plausible mistake is trusting metadata and silently producing a namespaced
/// address for a cluster-scoped kind.
#[test]
fn should_refuse_to_place_a_cluster_scoped_object_inside_a_namespace() {
    let confused = object(
        "kubernetes:prod",
        &NODE.replace(
            r#""name":"worker-03""#,
            r#""name":"worker-03","namespace":"production""#,
        ),
    );

    let error = Place::of_object_with_scope(&confused, Scope::Cluster)
        .expect_err("a cluster-scoped object with a namespace is a contradiction");

    assert!(
        matches!(error, PlaceError::ScopeConflict { .. }),
        "expected a scope conflict, got {error:?}"
    );
    assert!(
        error.to_string().contains("cluster-scoped"),
        "the error has to name the conflict: {error}"
    );
}

/// §9.2, the other direction: a namespaced kind whose object carries no namespace must not be
/// addressed as if it lived at cluster scope.
#[test]
fn should_refuse_to_place_a_namespaced_object_at_cluster_scope() {
    let stray = object(
        "kubernetes:prod",
        &POD.replace(r#""namespace":"production","#, ""),
    );

    let error = Place::of_object_with_scope(&stray, Scope::Namespaced)
        .expect_err("a namespaced object without a namespace cannot be addressed");

    assert!(
        matches!(error, PlaceError::ScopeConflict { .. }),
        "expected a scope conflict, got {error:?}"
    );
}

/// §35.4: "The place MUST bind the resource's lifetime identity when known, not only its mutable
/// name." A place keyed by name alone follows the address rather than the thing, which is how a
/// recreated Pod inherits the history of the one it replaced (Gate C).
#[test]
fn should_bind_lifetime_identity_when_the_object_carries_one() {
    let pod = place("kubernetes:prod", POD);

    let identity = pod.identity().expect("the pod carries a UID");
    assert_eq!(identity.uid(), Some("pod-1"));
    assert!(pod.is_lifetime_bound());
    assert_eq!(
        pod.uri().to_string(),
        "k8s://prod/ns/production/pod/checkout-7c9d"
    );
}

/// §16.5: an object without a UID still has an address, and the place must say that its identity
/// is the weaker locator kind rather than claim a lifetime it cannot prove.
#[test]
fn should_address_an_object_without_a_uid_but_not_claim_lifetime_identity() {
    let without_uid = object("kubernetes:prod", &POD.replace(r#""uid":"pod-1","#, ""));
    let pod = Place::of_object(&without_uid).expect("it still has an address");

    assert_eq!(
        pod.uri().to_string(),
        "k8s://prod/ns/production/pod/checkout-7c9d"
    );
    assert!(
        !pod.is_lifetime_bound(),
        "no UID means no lifetime identity to bind (§16.5)"
    );
}

/// §16.3 read spatially: the same address may be occupied by two different resource lifetimes.
/// The mistake is comparing places by URI only, which merges the recreated Pod into its
/// predecessor and hides the discontinuity Gate C exists to surface.
#[test]
fn should_separate_two_lifetimes_that_occupy_one_address() {
    let first = place("kubernetes:prod", POD);
    let recreated = place(
        "kubernetes:prod",
        &POD.replace(r#""uid":"pod-1""#, r#""uid":"pod-2""#),
    );

    assert!(
        first.is_same_address(&recreated),
        "the address is unchanged — that is what makes the change reportable"
    );
    assert_ne!(first, recreated, "different lifetimes are different places");
}

/// Gate J (§62.10): two kubeconfig contexts must not cross over. Identical namespace, kind and
/// name in `prod` and `dev` are different places, and nothing about them may compare equal. The
/// plausible mistake is treating the context as session state outside the address.
#[test]
fn should_treat_identical_names_in_two_instances_as_different_places() {
    let prod = place("kubernetes:prod", POD);
    let dev = place("kubernetes:dev", POD);

    assert_ne!(prod.uri(), dev.uri());
    assert_eq!(
        dev.uri().to_string(),
        "k8s://dev/ns/production/pod/checkout-7c9d"
    );
    assert!(
        !prod.is_same_address(&dev),
        "same name in two clusters is not the same address"
    );
}

/// §35.6: "`up` is a spatial/context operation, not an owner-reference shortcut." The Pod's
/// controller is a ReplicaSet owned by a Deployment; its spatial parent is the namespace. This is
/// the pin for the plausible mistake — implementing `up` as "follow the controller owner",
/// which makes `up` land somewhere different depending on who created the object.
#[test]
fn should_step_up_into_the_namespace_rather_than_the_owning_controller() {
    let pod_object = object("kubernetes:prod", POD);
    let pod = Place::of_object(&pod_object).expect("addressable");

    let parent = pod
        .up()
        .expect("a namespaced resource has a spatial parent");
    assert_eq!(parent.uri().to_string(), "k8s://prod/ns/production/");
    assert_eq!(parent.uri().shape(), PlaceShape::Namespace);

    let owner = Graph::edges_of(&pod_object)
        .into_iter()
        .find(|edge| edge.relation() == Relation::ControlledBy)
        .expect("the fixture is controlled by a ReplicaSet");
    assert_eq!(owner.target().kind(), "ReplicaSet");
    assert_ne!(
        parent.uri().to_string(),
        "k8s://prod/ns/production/replicaset.apps/checkout-6ac1",
        "ownership is reachable through `follow owned-by`, never through `up`"
    );
}

/// §35.6 and §9.2 together: the spatial parent of a cluster-scoped resource is the cluster root,
/// because there is no namespace above it to invent.
#[test]
fn should_step_up_from_a_cluster_scoped_resource_to_the_cluster_root() {
    let node = place("kubernetes:prod", NODE);

    assert_eq!(node.uri().to_string(), "k8s://prod/cluster/node/worker-03");
    let parent = node.up().expect("a Node sits under the cluster root");
    assert_eq!(parent.uri().to_string(), "k8s://prod/");

    let namespace = Place::at(PlaceUri::of_namespace("kubernetes:prod", "production").expect("ns"));
    assert_eq!(
        namespace.up().map(|up| up.uri().to_string()),
        Some("k8s://prod/".to_owned())
    );
}

/// §35.1: connecting Kubernetes adds places to Ono's existing world. The cluster root has no
/// parent *within this provider* — above it the host's world continues. Inventing a synthetic
/// `k8s://` super-root is how a provider starts owning a hierarchy of its own, which is the first
/// step towards the `k8s>` sub-shell §35.1 forbids.
#[test]
fn should_stop_at_the_cluster_root_rather_than_invent_a_provider_wide_parent() {
    let root = Place::at(PlaceUri::cluster_root("kubernetes:prod").expect("root"));

    assert_eq!(root.up(), None);
}

/// §35.5: `near` prioritises operationally relevant neighbours. The spec names the order for a
/// Service — selected Pods, EndpointSlices, Ingress/Gateway routes, related NetworkPolicies — and
/// that is what the ranking must reproduce. The mistake is returning the graph in whatever order
/// it was assembled, so the answer changes with the traversal.
#[test]
fn should_rank_service_neighbours_by_operational_relevance() {
    let service = object("kubernetes:prod", SERVICE);
    let pod = object("kubernetes:prod", POD);
    let selection = Graph::selects(&service, std::slice::from_ref(&pod));

    let neighbourhood = Neighbourhood::around(Place::of_object(&service).expect("addressable"))
        .with(
            Waypoint::ConstrainedBy,
            place("kubernetes:prod", NETWORK_POLICY),
            Evidence::Selector {
                selector: [("app".to_owned(), "checkout".to_owned())].into(),
                matched_labels: [("app".to_owned(), "checkout".to_owned())].into(),
            },
        )
        .with(
            Waypoint::RoutesTo,
            place("kubernetes:prod", INGRESS),
            Evidence::NativeField {
                path: "/spec/rules/0/http/paths/0/backend/service/name".to_owned(),
                value: "checkout".to_owned(),
            },
        )
        .with(
            Waypoint::HasEndpoints,
            place("kubernetes:prod", ENDPOINT_SLICE),
            Evidence::Convention {
                key: "kubernetes.io/service-name".to_owned(),
                value: "checkout".to_owned(),
            },
        )
        .reached(&selection);

    let ranked: Vec<String> = neighbourhood
        .ranked()
        .iter()
        .map(|neighbour| neighbour.place().uri().to_string())
        .collect();

    assert_eq!(
        ranked,
        vec![
            "k8s://prod/ns/production/pod/checkout-7c9d".to_owned(),
            "k8s://prod/ns/production/endpointslice.discovery.k8s.io/checkout-x9f2".to_owned(),
            "k8s://prod/ns/production/ingress.networking.k8s.io/shop".to_owned(),
            "k8s://prod/ns/production/networkpolicy.networking.k8s.io/checkout-ingress".to_owned(),
        ],
        "§35.5 names this order: selected Pods, EndpointSlices, routes, policies"
    );
    assert_eq!(
        neighbourhood.ranked()[0].proximity(),
        Proximity::Selected,
        "what a Service selects is the nearest thing to it"
    );
}

/// §35.5: `near` prioritises graph neighbours "rather than arbitrary objects in the same
/// namespace". An unrelated ConfigMap is in the namespace and is not a neighbour of the Service;
/// when a caller supplies it as ambient context it must rank behind everything reached by a
/// relationship, and an unobserved neighbourhood must stay empty rather than fill itself with the
/// namespace's contents.
#[test]
fn should_rank_ambient_namespace_objects_behind_every_relationship() {
    let service = object("kubernetes:prod", SERVICE);
    let pod = object("kubernetes:prod", POD);

    let empty = Neighbourhood::around(Place::of_object(&service).expect("addressable"));
    assert!(
        empty.ranked().is_empty(),
        "`near` reports observed neighbours, it does not enumerate the namespace"
    );

    let neighbourhood = Neighbourhood::around(Place::of_object(&service).expect("addressable"))
        .with(
            Waypoint::SharesNamespace,
            place("kubernetes:prod", CONFIG_MAP),
            Evidence::Derived {
                rule: "same-namespace".to_owned(),
            },
        )
        .reached(&Graph::selects(&service, std::slice::from_ref(&pod)));

    let ranked = neighbourhood.ranked();
    assert_eq!(ranked.len(), 2);
    assert_eq!(ranked[0].via(), Waypoint::Selects);
    assert_eq!(
        ranked[1].proximity(),
        Proximity::Ambient,
        "sharing a namespace is the weakest reason to be near something"
    );
}

/// §35.5: the prioritisation is a table, so every relationship this provider can traverse has a
/// declared rank. Without the completeness check a newly modelled relationship silently defaults
/// to the weakest class and disappears from the top of `near`.
#[test]
fn should_give_every_waypoint_a_declared_proximity() {
    for waypoint in Waypoint::ALL {
        let proximity = waypoint.proximity();
        if matches!(waypoint, Waypoint::SharesNamespace) {
            assert_eq!(proximity, Proximity::Ambient);
        } else {
            assert_ne!(
                proximity,
                Proximity::Ambient,
                "{} is a relationship, not ambient co-location",
                waypoint.as_str()
            );
        }
        assert_eq!(
            Waypoint::parse(waypoint.as_str()),
            Some(*waypoint),
            "every waypoint word must parse back to its waypoint"
        );
    }
}

/// §35.7: `follow` traverses *one* named relationship. The five words the spec spells out must
/// all be usable, and following one must not return neighbours reached by another — a `follow`
/// that returns everything is `near` under a different name.
#[test]
fn should_follow_one_named_relationship_and_only_that_one() {
    for word in [
        "owned-by",
        "scheduled-on",
        "selects",
        "routes-to",
        "bound-to",
    ] {
        assert!(
            Waypoint::parse(word).is_some(),
            "§35.7 names `follow {word}`"
        );
    }

    let pod_object = object("kubernetes:prod", POD);
    let neighbourhood = Neighbourhood::around(Place::of_object(&pod_object).expect("addressable"))
        .reached(&Graph::edges_of(&pod_object));

    let node = neighbourhood.follow("scheduled-on").expect("a known word");
    assert_eq!(node.len(), 1);
    assert_eq!(
        node[0].place().uri().to_string(),
        "k8s://prod/cluster/node/worker-03",
        "a Pod's Node is cluster-scoped even though the Pod is not (§9.2)"
    );

    let owners = neighbourhood.follow("owned-by").expect("a known word");
    assert_eq!(owners.len(), 1);
    assert_eq!(
        owners[0].place().uri().to_string(),
        "k8s://prod/ns/production/replicaset.apps/checkout-6ac1"
    );

    assert!(
        neighbourhood
            .follow("bound-to")
            .expect("a known word")
            .is_empty(),
        "a Pod with no claim has nothing bound to it"
    );
}

/// §35.1: this provider contributes places and relationship names to Ono's grammar, never an
/// imperative sub-language. `follow get` and `follow describe` must not resolve, because a
/// relationship vocabulary that quietly accepts `kubectl` verbs is the `k8s>` mode the invariant
/// forbids arriving one word at a time.
#[test]
fn should_reject_kubernetes_verbs_as_relationship_words() {
    for verb in ["get", "describe", "logs", "exec", "apply", "get pods"] {
        assert_eq!(
            Waypoint::parse(verb),
            None,
            "`{verb}` is a command, not a relationship"
        );
    }

    let pod_object = object("kubernetes:prod", POD);
    let neighbourhood = Neighbourhood::around(Place::of_object(&pod_object).expect("addressable"))
        .reached(&Graph::edges_of(&pod_object));
    let error = neighbourhood
        .follow("describe")
        .expect_err("a command word is not followable");
    assert!(
        error.to_string().contains("scheduled-on"),
        "the error should offer the relationships that do exist: {error}"
    );
}

/// §35.8: "name-only entry MUST prompt/require disambiguation rather than choosing by an
/// arbitrary type priority". The plausible mistake is a built-in preference order — Deployment
/// before Service, say — which silently takes the user somewhere they did not ask for.
#[test]
fn should_report_ambiguity_rather_than_pick_a_type() {
    let present = [
        place("kubernetes:prod", DEPLOYMENT),
        place("kubernetes:prod", SERVICE),
    ];
    let namespace = PlaceUri::of_namespace("kubernetes:prod", "production").expect("namespace");

    let entry = enter_by_name(&namespace, "checkout", &present);

    let NameEntry::Ambiguous(candidates) = entry else {
        panic!("two types share the name `checkout`, so entry cannot resolve: {entry:?}");
    };
    let addresses: Vec<String> = candidates
        .iter()
        .map(|candidate| candidate.uri().to_string())
        .collect();
    assert_eq!(
        addresses,
        vec![
            "k8s://prod/ns/production/deployment.apps/checkout".to_owned(),
            "k8s://prod/ns/production/service/checkout".to_owned(),
        ],
        "both candidates are reported so the user can choose"
    );
}

/// §35.8 with §21.4: a unique name resolves, and "nothing here carries that name" is a distinct
/// answer from "several things do". Collapsing absence into an empty ambiguity list would make
/// the two indistinguishable to a caller.
#[test]
fn should_resolve_a_unique_name_and_report_absence_separately() {
    let present = [place("kubernetes:prod", SERVICE)];
    let namespace = PlaceUri::of_namespace("kubernetes:prod", "production").expect("namespace");

    let found = enter_by_name(&namespace, "checkout", &present);
    let NameEntry::One(resolved) = found else {
        panic!("one type carries the name: {found:?}");
    };
    assert_eq!(
        resolved.uri().to_string(),
        "k8s://prod/ns/production/service/checkout"
    );

    assert_eq!(
        enter_by_name(&namespace, "basket", &present),
        NameEntry::None
    );
}

/// Gate J (§62.10) and §9.4: entry by name is scoped to the place it is typed in. A candidate
/// from another context, or from another namespace, must not be offered — the plausible mistake
/// is a flat name index that forgets which cluster and namespace each entry came from.
#[test]
fn should_not_offer_a_name_from_another_instance_or_namespace() {
    let elsewhere = [
        place("kubernetes:dev", SERVICE),
        place(
            "kubernetes:prod",
            &SERVICE.replace(r#""namespace":"production""#, r#""namespace":"staging""#),
        ),
    ];
    let namespace = PlaceUri::of_namespace("kubernetes:prod", "production").expect("namespace");

    assert_eq!(
        enter_by_name(&namespace, "checkout", &elsewhere),
        NameEntry::None,
        "another context and another namespace are both elsewhere"
    );
}

/// §36.1 and §36.3: a role is an overlay for cross-provider discovery; the native Kubernetes type
/// stays canonical and stays visible. A place that renders `workload` and drops `Deployment` has
/// thrown away the only thing that tells the user which API to reason about.
#[test]
fn should_overlay_a_semantic_role_without_replacing_the_native_kind() {
    let deployment = place("kubernetes:prod", DEPLOYMENT);

    assert!(deployment.has_role(SemanticRole::Workload));
    assert_eq!(
        deployment.gvk().map(Gvk::kind),
        Some("Deployment"),
        "the native kind survives the overlay"
    );
    assert_eq!(deployment.gvk().map(Gvk::group), Some("apps"));
    assert_eq!(
        deployment.uri().to_string(),
        "k8s://prod/ns/production/deployment.apps/checkout",
        "the address names the Kubernetes type, not the generic role"
    );
    assert_eq!(
        place("kubernetes:prod", NODE).roles(),
        [SemanticRole::ComputeNode]
    );
    assert_eq!(
        place("kubernetes:prod", SERVICE).roles(),
        [SemanticRole::NetworkEndpoint]
    );
}

/// §36.3: "A Deployment is not an AWS Auto Scaling Group merely because both can produce compute
/// capacity." Within Kubernetes the same trap is nearer: a Pod and a Deployment are both
/// `workload` and are not interchangeable. Sharing a role must never make two places equal or
/// substitutable.
#[test]
fn should_not_equate_two_places_that_share_a_role() {
    let pod = place("kubernetes:prod", POD);
    let deployment = place("kubernetes:prod", DEPLOYMENT);

    assert!(pod.has_role(SemanticRole::Workload));
    assert!(deployment.has_role(SemanticRole::Workload));
    assert_ne!(pod, deployment);
    assert_ne!(pod.uri(), deployment.uri());
    assert_ne!(pod.gvk(), deployment.gvk());
}

/// §36.2 with §33.1: roles are a small known registry, and a custom resource this provider has
/// never seen gets no role rather than a guessed one. The mistake is defaulting an unknown kind
/// into `workload` because most things are; a wrong overlay is worse than none, because a
/// cross-provider query would then act on it.
#[test]
fn should_leave_an_unknown_kind_without_a_role_rather_than_guess() {
    let widget = place("kubernetes:prod", CUSTOM_RESOURCE);

    assert!(
        widget.roles().is_empty(),
        "an unrecognised kind has no role to claim"
    );
    assert_eq!(
        widget.uri().to_string(),
        "k8s://prod/ns/production/widget.acme.example.com/left-handed",
        "it is still a fully addressable place (§33.1)"
    );
    assert_eq!(widget.gvk().map(Gvk::kind), Some("Widget"));
}

/// §13.5: two groups may serve the same kind. A type segment of the bare kind would give both the
/// same address, which breaks the stability §35.3 requires — the URI would silently point at
/// whichever one was resolved first.
#[test]
fn should_separate_colliding_kinds_by_their_group() {
    let core = TypeSegment::of(&Gvk::new("", "v1", "Widget"));
    let custom = TypeSegment::of(&Gvk::new("acme.example.com", "v1", "Widget"));

    assert_eq!(core.to_string(), "widget");
    assert_eq!(custom.to_string(), "widget.acme.example.com");
    assert_ne!(core, custom);

    let parsed = TypeSegment::parse("widget.acme.example.com").expect("a type segment parses");
    assert_eq!(parsed, custom);
    assert!(parsed.matches(&Gvk::new("acme.example.com", "v1", "Widget")));
    assert!(
        !parsed.matches(&Gvk::new("", "v1", "Widget")),
        "the core group is a group, not a gap (§13.3)"
    );
}

/// §35.3: URI identity must be stable, and kubeconfig context names are not URI-safe — an EKS
/// context is an ARN containing slashes. Rendering one raw produces extra path segments and the
/// address stops parsing, which is the same failure as having no address at all.
#[test]
fn should_round_trip_a_context_name_that_is_not_uri_safe() {
    let arn = "kubernetes:arn:aws:eks:eu-central-1:1234:cluster/prod";
    let uri = PlaceUri::of_namespace(arn, "production").expect("an ARN context is still a context");

    assert_eq!(
        uri.to_string(),
        "k8s://arn:aws:eks:eu-central-1:1234:cluster%2Fprod/ns/production/"
    );
    assert_eq!(
        PlaceUri::parse(&uri.to_string()).expect("it parses back"),
        uri
    );
    assert_eq!(uri.instance(), arn);
}

/// §35.3: a machine-parseable grammar has to reject what is not in it. Accepting a near-miss and
/// guessing the shape is how a typo becomes navigation to the wrong cluster.
#[test]
fn should_reject_text_that_is_not_a_place_uri() {
    for text in [
        "https://prod/ns/production/pod/checkout",
        "k8s:/prod/",
        "k8s://",
        "k8s://prod/namespace/production/",
        "k8s://prod/ns/production/pod/checkout/extra",
        "k8s://prod/ns//pod/checkout",
        "k8s://prod/cluster/node",
    ] {
        assert!(
            PlaceUri::parse(text).is_err(),
            "`{text}` is not a place URI and must not be guessed into one"
        );
    }
}

/// §35.3 and §35.4 together: a Namespace is a cluster-scoped *object* and the enterable *place*
/// the spec gives it is `k8s://prod/ns/production/`. Two addresses for one thing would break the
/// stability §35.3 requires, so the namespace place is the one address, and it still binds the
/// Namespace object's lifetime identity.
#[test]
fn should_address_a_namespace_object_as_its_namespace_place() {
    let namespace = place("kubernetes:prod", NAMESPACE);

    assert_eq!(namespace.uri().to_string(), "k8s://prod/ns/production/");
    assert_eq!(namespace.uri().shape(), PlaceShape::Namespace);
    assert_eq!(
        namespace.identity().and_then(|identity| identity.uid()),
        Some("ns-1"),
        "the place binds the object's lifetime identity (§35.4)"
    );
    assert_eq!(namespace.gvk().map(Gvk::kind), Some("Namespace"));
}

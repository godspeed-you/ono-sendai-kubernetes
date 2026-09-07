//! The Gateway API: what a Gateway and a route state about each other (§27.3).
//!
//! The first genuine member of the registry, and the one §27.3 describes by name: "a curated
//! Gateway API adapter MAY add richer relationships", it "MUST be version/schema aware", and it
//! "MUST NOT hard-code the presence of Gateway API into the provider core". Nothing about this
//! module is assumed to exist. A cluster without the Gateway API installed never presents an
//! object it recognises, and every other relationship in the provider works unchanged.
//!
//! Upstream reference: the Gateway API specification at `gateway-api.sigs.k8s.io`, for the
//! versions the adapter lists. A version outside that list yields no roles and no edges — its
//! field names are not known to mean what today's mean (§5.3) — and the object stays fully
//! available through universal dynamic support (§15.1).

use serde_json::Value as Json;

use crate::adapter::{Adapter, Context, Coverage};
use crate::discovery::Gvk;
use crate::object::{Identity, Object};
use crate::place::SemanticRole;
use crate::relationship::{Edge, Evidence, Relation, Target};
use crate::workload::api_version_of;

/// The API group the Gateway API is served under, when a cluster serves it at all.
const GROUP: &str = "gateway.networking.k8s.io";

/// The served versions whose field layout this adapter has actually seen.
const VERSIONS: &[&str] = &["v1alpha2", "v1beta1", "v1"];

/// The kinds this adapter has rules for. A GatewayClass states nothing this adapter reads.
const KINDS: &[&str] = &["Gateway", "HTTPRoute", "GRPCRoute"];

/// The Gateway API adapter. A unit struct: it holds no state, because it performs no I/O.
pub struct GatewayApi;

impl Adapter for GatewayApi {
    fn name(&self) -> &'static str {
        "gateway-api"
    }

    fn coverage(&self) -> Coverage {
        Coverage::new(GROUP, KINDS, VERSIONS)
    }

    /// A Gateway and an HTTPRoute are where traffic is addressed to (§36.2).
    fn semantic_roles(&self, gvk: &Gvk) -> Vec<SemanticRole> {
        match gvk.kind() {
            "Gateway" | "HTTPRoute" => vec![SemanticRole::NetworkEndpoint],
            _ => Vec::new(),
        }
    }

    /// `Gateway -> uses-gateway-class -> GatewayClass`, `*Route -> attaches-to -> Gateway` and
    /// `*Route -> routes-to -> Service`, each citing the reference it read.
    fn relationships(&self, object: &Object, _context: &Context<'_>) -> Vec<Edge> {
        let api_version = api_version_of(object);
        let adapter = Evidence::Derived {
            rule: format!("curated Gateway API adapter for {api_version}"),
        };
        let source = object.identity();
        let namespace = object.namespace().map(str::to_owned);
        let mut edges = Vec::new();

        match object.gvk().kind() {
            "Gateway" => {
                if let Some(class) = object
                    .field("/spec/gatewayClassName")
                    .and_then(Json::as_str)
                {
                    edges.push(
                        Edge::new(
                            source,
                            Relation::UsesGatewayClass,
                            // Cluster-scoped, so no namespace (§9.5).
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

//! Kubernetes objects as places in Ono's world, and the edges between them (§35.2–§35.6, §36).
//!
//! [`crate::records`] and [`crate::relations`] already answer *about* places: every record of an
//! edge carries two `place.rs` URIs bound to the lifetime identity they were read at. Those are
//! strings on a record. This module is what makes the same objects places in the shell's own
//! graph, so that `enter`, `near` and `follow` reach a cluster.
//!
//! **The mechanism is core's and this module is the declaration half of it.** `ADR-0584 (core)`
//! makes every schema a package declares a target for into a kind of place, keyed on the schema
//! id — so `KubernetesPod` is a `--type` a user may name and `get k8s-pod | enter` projects a
//! record into a place, with no code here at all. `ADR-0585 (core)` runs a relation between two
//! such kinds, declared in the manifest as `<from>-><to>` where each endpoint is the id of a
//! schema one of this package's own targets declares, and validated against the documents on disk
//! before the runtime is spawned. [`SHAPES`] is that declaration, and
//! `package/manifest.yaml`'s `contributions.relations` is the same table written out; the edges
//! themselves are answered by the command this module contributes.
//!
//! **Nothing here decides anything the domain layer has already decided.** Which edges exist is
//! `relations::stated_edges` and `Graph`; how near a neighbour is, and in what order, is
//! [`Neighbourhood::ranked`] — §35.5's own prioritisation, so a Service answers with its selected
//! Pods, then its EndpointSlices, then its routes, and this module never re-sorts them. What is
//! decided here is only the boundary: which pairs of kinds are declarable as relations, and how a
//! Kubernetes object becomes the two fields `ono.spatial-relation/1` carries.
//!
//! **Both ends are a lifetime identity, never a name** (§35.4, §4 invariants 4–5). Every schema
//! this package declares is keyed on `uid`, so the host resolves an end by querying the target
//! that answers for the schema with `uid == <the key this record carried>`. An edge whose far end
//! this pass could not resolve to a `uid` is therefore emitted with no key and contributes no
//! edge, rather than travelling with a name that would bind a place to a word two resources can
//! share.
//!
//! **`up` is not this.** §35.6 makes a namespace a Pod's spatial parent *even though a ReplicaSet
//! owns it*, and the two are separate shapes here for exactly that reason: `…pod_to_namespace`
//! carries `in-namespace` and `…pod_to_replicaset` carries `controlled-by`. Neither of them is
//! `up`, which needs the plugin-defined aggregate space of §36.4 that a package cannot declare —
//! `ADR-0584 (core)` says so in its own Consequences and refuses with `spatial.no_parent`. What
//! this package can do is make the spatial parent reachable and keep it distinct from ownership;
//! what it cannot do is make `up` land on it.
//!
//! **The capability is `relation.write`, and it is never granted by default.** A package without
//! it contributes no relation at all — core drops the shapes before the merge, which is §35.5's
//! filter happening before anything is drawn — and the host refuses this command at every
//! invocation besides. So an operator who has not granted it sees a place with no exits and a
//! refusal that names the capability, rather than an empty `near` that reads as "nothing is here".

use std::collections::BTreeMap;
use std::sync::Arc;

use ono_kuang_sdk::protocol::{CommandContribution, WireError};
use ono_kuang_sdk::{Ctx, Outcome};
use ono_provider_kubernetes::discovery::{Discovery, Resource, Verb};
use ono_provider_kubernetes::object::{Identity, Object};
use ono_provider_kubernetes::place::{Neighbourhood, Place};
use ono_provider_kubernetes::relationship::{Edge, Graph};
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{ByteStream, Client, ListOptions};
use ono_provider_kubernetes::workload::Workload;
use ono_value::{RecordValue, SchemaId, Value, builtin_schemas};

use crate::contributions::{Reads, TARGETS};
use crate::query::{
    self, Conversation, Endpoint, UNAVAILABLE, UNAVAILABLE_CODE, UNSUPPORTED, UNSUPPORTED_CODE,
    failure,
};
use crate::sessions::Sessions;

/// The core target a package answers for when it contributes relationship edges (§36.1).
///
/// Not a noun of this package's: `ono.spatial-relation/1` is the shell's own schema for "one
/// contributor asserts an edge between two places", and answering for it is how the host knows
/// these records are edges rather than objects.
pub const RELATION_TARGET: &str = "spatial-relation";

/// The capability the contribution is gated on, in the manifest and at every invocation (§35.5).
pub const RELATION_WRITE: &str = "relation.write";

/// The command id, in the namespace §31.5 reserves to this package's publisher.
pub const COMMAND: &str = "io.github.godspeed-you.kubernetes.command.spatial-relations";

/// The schema every record this command emits carries — the shell's, not this package's.
const SPATIAL_RELATION: &str = "ono.spatial-relation";

/// How many objects one kind's listing asks the API server for.
const PAGE_SIZE: u32 = 500;

/// The contributor's word for the edge that runs from an object to the namespace holding it.
///
/// §35.6's spatial parent, which the relationship model of §23–§32 does not produce because it is
/// not a relationship between two resources — it is where the object's address puts it, which is
/// what [`Place::up`] computes. It is spelled out rather than borrowed from
/// [`ono_provider_kubernetes::place::Waypoint`]: `shares-namespace` is that vocabulary's word for
/// co-tenancy and its documentation says in as many words that it is not a relationship, so using
/// it for containment would make one word mean two things.
const IN_NAMESPACE: &str = "in-namespace";

/// One kind of place this package relates to another, by the schema ids core keys them on.
///
/// The pair is the whole declaration. `ADR-0585 (core)` derives the relation id from the shape's
/// *text* — `io.github.godspeed-you.kubernetes.pod/1->io.github.godspeed-you.kubernetes.node/1`
/// registers `io.github.godspeed-you.kubernetes.pod_to_node` — so a shape carries no word of its
/// own and every Kubernetes relationship that runs between one pair of kinds arrives under one
/// relation, distinguished by the `relation` field each edge carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// The schema id of the kind of place the edge starts at.
    pub from: &'static str,
    /// The schema id of the kind of place it leads to.
    pub to: &'static str,
    /// What runs along it, for the reader of this table and of the manifest.
    pub carries: &'static str,
}

impl Shape {
    const fn new(from: &'static str, to: &'static str, carries: &'static str) -> Self {
        Self { from, to, carries }
    }

    /// The shape as `package/manifest.yaml` spells it (§31.7).
    #[must_use]
    pub fn declaration(&self) -> String {
        format!("{}->{}", self.from, self.to)
    }

    /// The relation id the host registers for it (`ADR-0585 (core)`).
    ///
    /// Derived here the way core derives it — the local name of each schema id, lower-cased,
    /// inside the package's own namespace — so that this package can name the relations it
    /// contributes without loading a host to ask.
    #[must_use]
    pub fn relation_id(&self) -> String {
        format!(
            "{}.{}_to_{}",
            crate::PACKAGE,
            endpoint_word(self.from),
            endpoint_word(self.to)
        )
    }
}

/// The word a shape endpoint contributes to a relation id: the schema's local name, lower-cased.
fn endpoint_word(schema: &str) -> String {
    let without_version = schema.split_once('/').map_or(schema, |(id, _)| id);
    without_version
        .rsplit('.')
        .next()
        .unwrap_or(without_version)
        .to_ascii_lowercase()
}

/// The schema id of a curated target, by the kind it reads.
macro_rules! schema {
    ($name:literal) => {
        concat!("io.github.godspeed-you.kubernetes.", $name, "/1")
    };
}

/// Every pair of kinds this package declares a relation between (§36.1, §35.5, §35.6).
///
/// The order is §35.5's own: what a place *selects* and what carries its endpoints, then what
/// routes to it, then where it runs, then its lineage, then what it needs to run, and last the
/// namespace it is in. Reading it top to bottom is reading the prioritisation the specification
/// gives `near`, which [`Neighbourhood::ranked`] then applies per object.
///
/// A pair is here only where this package actually derives an edge for it, and every entry names
/// what runs along it. A declared shape that nothing ever fills would be a relation a user could
/// `follow` into silence, which is the failure `ADR-0585 (core)` moved the endpoint check to load
/// time to avoid.
pub const SHAPES: &[Shape] = &[
    // §35.5's first three, for a Service: the Pods it selects, the slices that carry its
    // addresses, and what routes traffic to it.
    Shape::new(schema!("service"), schema!("pod"), "selects"),
    Shape::new(
        schema!("service"),
        schema!("endpointslice"),
        "has-endpoints",
    ),
    Shape::new(schema!("endpointslice"), schema!("pod"), "endpoint-for"),
    Shape::new(schema!("ingress"), schema!("service"), "routes-to"),
    // Where it runs (§28.1).
    Shape::new(schema!("pod"), schema!("node"), "scheduled-on"),
    // Lineage, read from the child that states its own owner (§24.1, §24.3).
    Shape::new(
        schema!("pod"),
        schema!("replicaset"),
        "owned-by, controlled-by",
    ),
    Shape::new(
        schema!("pod"),
        schema!("statefulset"),
        "owned-by, controlled-by",
    ),
    Shape::new(
        schema!("pod"),
        schema!("daemonset"),
        "owned-by, controlled-by",
    ),
    Shape::new(schema!("pod"), schema!("job"), "owned-by, controlled-by"),
    Shape::new(
        schema!("replicaset"),
        schema!("deployment"),
        "owned-by, controlled-by",
    ),
    Shape::new(
        schema!("job"),
        schema!("cronjob"),
        "owned-by, controlled-by",
    ),
    // What it needs to run (§29–§32).
    Shape::new(schema!("pod"), schema!("serviceaccount"), "runs-as"),
    Shape::new(schema!("pod"), schema!("configmap"), "references-config"),
    Shape::new(schema!("pod"), schema!("secret"), "references-secret"),
    Shape::new(schema!("pod"), schema!("persistentvolumeclaim"), "mounts"),
    Shape::new(
        schema!("persistentvolumeclaim"),
        schema!("persistentvolume"),
        "bound-to",
    ),
    Shape::new(schema!("statefulset"), schema!("service"), "uses-service"),
    Shape::new(schema!("ingress"), schema!("secret"), "uses-tls-secret"),
    Shape::new(
        schema!("serviceaccount"),
        schema!("secret"),
        "uses-secret, uses-image-pull-secret",
    ),
    // §35.6's spatial parent, which is the namespace and never the owner.
    Shape::new(schema!("pod"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("service"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("endpointslice"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("ingress"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("replicaset"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("deployment"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("statefulset"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("daemonset"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("job"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("cronjob"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(
        schema!("serviceaccount"),
        schema!("namespace"),
        IN_NAMESPACE,
    ),
    Shape::new(schema!("configmap"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(schema!("secret"), schema!("namespace"), IN_NAMESPACE),
    Shape::new(
        schema!("persistentvolumeclaim"),
        schema!("namespace"),
        IN_NAMESPACE,
    ),
];

/// The command contribution, as the handshake carries it (§31.22, §36.1).
///
/// A command rather than a target because a contributed target declares no capability and this
/// contribution is gated on one: `relation.write` is checked by the host before any of this code
/// runs, at every invocation, which is where §35.5 wants the filter. The verb is `get` and the
/// noun is the shell's own `spatial-relation`, so nothing here is a word of this package's own.
#[must_use]
pub fn contribution() -> CommandContribution {
    CommandContribution {
        id: COMMAND.to_owned(),
        verb: "get".to_owned(),
        target: RELATION_TARGET.to_owned(),
        summary: "The edges between the Kubernetes objects this package contributes as kinds of \
                  place (specification sections 35.5, 35.6, 36.1)."
            .to_owned(),
        input: None,
        output: format!("stream<{SPATIAL_RELATION}/1>"),
        capabilities: vec![RELATION_WRITE.to_owned(), "network.connect".to_owned()],
        argument_mode: "words".to_owned(),
        risk: None,
        examples: vec![
            "get k8s-pod --context prod --namespace shop | enter; near".to_owned(),
            "follow io.github.godspeed-you.kubernetes.pod_to_node".to_owned(),
        ],
    }
}

/// The kinds this contribution reads, and the schema id each one becomes.
///
/// Derived from [`TARGETS`] rather than restated: a target already says which group and kind it
/// reads and which schema its records carry, and a second table would be a second chance for the
/// two to disagree about what a Pod is.
fn kind_schemas() -> Vec<(&'static str, &'static str, &'static str)> {
    let named: Vec<&'static str> = SHAPES
        .iter()
        .flat_map(|shape| [shape.from, shape.to])
        .collect();
    let mut kinds: Vec<(&'static str, &'static str, &'static str)> = TARGETS
        .iter()
        .filter(|target| named.contains(&target.schema))
        .filter_map(|target| match target.reads {
            Reads::Kind { group, kind } => Some((group, kind, target.schema)),
            _ => None,
        })
        .collect();
    kinds.dedup();
    kinds
}

/// The schema id a kind of Kubernetes object becomes a place of, where this package declares one.
fn schema_of(group: &str, kind: &str) -> Option<&'static str> {
    kind_schemas()
        .into_iter()
        .find(|(declared_group, declared_kind, _)| {
            *declared_group == group && *declared_kind == kind
        })
        .map(|(.., schema)| schema)
}

/// Whether the package declares a relation between these two kinds of place.
fn declares(from: &str, to: &str) -> bool {
    SHAPES
        .iter()
        .any(|shape| shape.from == from && shape.to == to)
}

/// Answers the `spatial-relation` target: the edges between the places this package contributes.
///
/// The invocation carries no arguments when the shell asks — a merge is asked of every
/// contributing package with nothing to narrow it by (`ADR-0585 (core)` §4) — so which cluster
/// this is comes from the endpoint the operator last named in this process, exactly as a
/// re-read of a place does (ADR-0027).
#[must_use]
pub fn answer(sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match builtin_schemas().get(&SchemaId::new(SPATIAL_RELATION, 1)) {
        Some(schema) => schema,
        None => {
            return Outcome::Failed(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("this host carries no `{SPATIAL_RELATION}/1` schema"),
                "A contributed edge is asserted in the shell's own vocabulary, and this build of \
                 the host does not have it.",
            ));
        }
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
    };
    if ctx.cancelled() {
        return Outcome::Cancelled;
    }
    let inventory = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            query::converse(
                ctx,
                &endpoint,
                InventoryOf {
                    endpoint: &endpoint,
                    session,
                },
            )
        },
    );
    let inventory = match inventory {
        Ok(inventory) => inventory,
        Err(error) => return Outcome::Failed(error),
    };
    emit(ctx, &schema, &inventory)
}

/// What one pass over the cluster read: the objects of every kind a declared shape names.
///
/// Bounded on purpose, and the bound is the honest half of what `ADR-0585 (core)` records as
/// missing: a contributed relation has no way to declare that it costs a network round trip, so
/// what this package can do instead is keep the round trips to one page of one listing per kind
/// the shapes name, in the scope the standing endpoint established.
struct Inventory {
    /// Objects by group and kind, in the order the listings came back.
    objects: BTreeMap<(String, String), Vec<Object>>,
}

impl Inventory {
    /// Every object of one kind that this pass read.
    fn of(&self, group: &str, kind: &str) -> &[Object] {
        self.objects
            .get(&(group.to_owned(), kind.to_owned()))
            .map_or(&[], Vec::as_slice)
    }

    /// The object one reference names, where this pass read it.
    ///
    /// GVK identity on both sides, and the namespace as well: two resources of one name in two
    /// namespaces are two resources, and a lookup that ignored the namespace would give an edge
    /// the wrong far end rather than none (§9.2).
    fn resolve(
        &self,
        kind: &str,
        group: &str,
        namespace: Option<&str>,
        name: &str,
    ) -> Option<&Object> {
        self.of(group, kind).iter().find(|object| {
            object.name() == name
                && object.namespace().map(str::to_owned) == namespace.map(str::to_owned)
        })
    }
}

/// One pass over every kind a declared shape names.
struct InventoryOf<'a> {
    endpoint: &'a Endpoint,
    session: &'a mut Session,
}

impl Conversation for InventoryOf<'_> {
    type Answer = Inventory;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        let served = query::served(session, client, self.endpoint)?;
        let mut objects: BTreeMap<(String, String), Vec<Object>> = BTreeMap::new();
        for (group, kind, _) in kind_schemas() {
            // A kind this cluster does not serve, or serves without `list`, contributes no edges
            // and is not an error: §21.4 keeps "not served" and "nothing there" apart, and a
            // package asked for its edges has been asked what it can see rather than promised
            // that it can see everything.
            let Some(resource) = serving(session, client, self.endpoint, &served, group, kind)?
            else {
                continue;
            };
            if !resource.supports(Verb::List) {
                continue;
            }
            let scope = query::scope_for(self.endpoint, &resource);
            let mut options = ListOptions::new().limit(PAGE_SIZE);
            if let Some(pages) = self.endpoint.max_pages {
                options = options.max_pages(pages);
            }
            let listing = client.list(resource.gvr(), &scope, &options);
            objects.insert((group.to_owned(), kind.to_owned()), listing.into_objects());
        }
        Ok(Inventory { objects })
    }
}

/// The resource serving one kind, or [`None`] where this cluster serves none.
fn serving<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    group: &str,
    kind: &str,
) -> Result<Option<Resource>, WireError> {
    let Some(version) = served.preferred_version(group) else {
        return Ok(None);
    };
    let group_version = query::group_version_of(group, version);
    let discovery = query::resource_list(session, client, endpoint, &group_version)?;
    Ok(discovery.by_kind(&group_version, kind).cloned())
}

/// Streams one record per edge whose two ends are kinds of place a declared shape runs between.
fn emit(ctx: &mut Ctx<'_>, schema: &Arc<ono_value::Schema>, inventory: &Inventory) -> Outcome {
    for (group, kind, source_schema) in kind_schemas() {
        for object in inventory.of(group, kind) {
            if ctx.cancelled() {
                return Outcome::Cancelled;
            }
            for asserted in edges_of(object, inventory, source_schema) {
                let value = match asserted.record(schema) {
                    Ok(value) => value,
                    Err(error) => {
                        return Outcome::Failed(failure(
                            UNAVAILABLE_CODE,
                            UNAVAILABLE,
                            format!("an asserted edge could not be built: {error}"),
                            "This is a defect in the Kubernetes provider, not in the cluster.",
                        ));
                    }
                };
                if let Err(outcome) = query::deliver(ctx, &value) {
                    return outcome;
                }
            }
        }
    }
    Outcome::Completed
}

/// One edge this package asserts between two kinds of place it contributes.
struct Asserted {
    relation: String,
    source_schema: &'static str,
    source_uid: String,
    target_schema: &'static str,
    target_uid: String,
    confidence: &'static str,
}

impl Asserted {
    /// The edge as `ono.spatial-relation/1`.
    fn record(&self, schema: &Arc<ono_value::Schema>) -> Result<Value, ono_value::ErrorValue> {
        let provenance =
            ono_value::Provenance::local(crate::PACKAGE, SchemaId::new(SPATIAL_RELATION, 1));
        let record = RecordValue::builder(Arc::clone(schema), provenance)
            .set("relation", Value::string(&self.relation))?
            .set("source_type", Value::string(self.source_schema))?
            .set("source_key", Value::string(&self.source_uid))?
            .set("target_type", Value::string(self.target_schema))?
            .set("target_key", Value::string(&self.target_uid))?
            .set("confidence", Value::string(self.confidence))?
            .build();
        Ok(Value::Record(Arc::new(record)))
    }
}

/// Every edge one object asserts, in §35.5's order, keyed on both ends' lifetime identities.
fn edges_of(object: &Object, inventory: &Inventory, source_schema: &'static str) -> Vec<Asserted> {
    let Some(source_uid) = object.uid().map(str::to_owned) else {
        // §16.5: an object the server gave no UID has no lifetime identity, so there is nothing
        // for a place to bind to and no honest key for the end of an edge.
        return Vec::new();
    };
    let Ok(here) = Place::of_object(object) else {
        return Vec::new();
    };
    let resolved: Vec<Edge> = derived(object, inventory)
        .into_iter()
        .map(|edge| resolve_far_end(edge, inventory))
        .collect();
    let neighbourhood = Neighbourhood::around(here).reached(&resolved);
    let mut asserted: Vec<Asserted> = Vec::new();
    // §35.5's prioritisation is `Neighbourhood`'s, applied here rather than re-decided: a
    // Service's selected Pods come before its EndpointSlices, which come before its routes.
    for neighbour in neighbourhood.ranked() {
        let Some(gvk) = neighbour.place().gvk() else {
            continue;
        };
        let Some(target_schema) = schema_of(gvk.group(), gvk.kind()) else {
            continue;
        };
        if !declares(source_schema, target_schema) {
            continue;
        }
        let Some(target_uid) = neighbour.place().identity().and_then(Identity::uid) else {
            // §24.1: an edge whose far end nobody read is a relationship rather than a broken
            // edge — and it is not a place, because a place binds a lifetime and this end has
            // none. It stays visible through `get k8s-relation`, which says so in a field.
            continue;
        };
        asserted.push(Asserted {
            relation: neighbour.via().to_string(),
            source_schema,
            source_uid: source_uid.clone(),
            target_schema,
            target_uid: target_uid.to_owned(),
            // §11.5 and §36.2: what the API server itself states is `exact`, and what this
            // provider derived by evaluating one object against another is `strong`. The host
            // lowers `exact` to `strong` on every contributed edge anyway, because it did not
            // observe it — so the distinction that survives is the evidence class on the
            // `k8s-relation` record, and this field never claims more than the edge earned.
            confidence: if neighbour.evidence().is_asserted_by_provider() {
                "exact"
            } else {
                "strong"
            },
        });
    }
    if let Some(containment) = in_namespace(object, inventory, source_schema, &source_uid) {
        asserted.push(containment);
    }
    asserted
}

/// The edge from an object to the namespace that holds it (§35.6).
///
/// Last, because it is the `up` axis rather than a neighbour: §35.5 is about what an object is
/// related to, and where it lives is a different question that happens to travel the same way.
fn in_namespace(
    object: &Object,
    inventory: &Inventory,
    source_schema: &'static str,
    source_uid: &str,
) -> Option<Asserted> {
    let target_schema = schema_of("", "Namespace")?;
    if !declares(source_schema, target_schema) {
        return None;
    }
    let namespace = object.namespace()?;
    let holder = inventory.resolve("Namespace", "", None, namespace)?;
    Some(Asserted {
        relation: IN_NAMESPACE.to_owned(),
        source_schema,
        source_uid: source_uid.to_owned(),
        target_schema,
        target_uid: holder.uid()?.to_owned(),
        // `metadata.namespace` is the object's own field, and where an object is is not something
        // this provider worked out.
        confidence: "exact",
    })
}

/// Every edge one object states or this provider derives from what the pass already read.
fn derived(object: &Object, inventory: &Inventory) -> Vec<Edge> {
    let mut edges = crate::relations::stated_edges(object);
    if crate::relations::is(object, "", "Service") {
        // §26.1 and §26.2: the two edges a Service has that need a second object, evaluated
        // against the objects this pass already read rather than against a second listing.
        edges.extend(Graph::selects(object, inventory.of("", "Pod")));
        edges.extend(Workload::endpoint_slices(
            object,
            inventory.of("discovery.k8s.io", "EndpointSlice"),
        ));
    }
    edges
}

/// Binds an edge's far end to the object this pass read, where it read one.
///
/// An ownerReference already carries a `uid` and needs nothing; `spec.nodeName`, a volume's
/// `configMap.name` and an Ingress backend name carry none, and §35.4 will not let a place be
/// bound to a name. So the reference is matched against what was listed, and an edge whose far
/// end was not listed keeps its unresolved target and contributes no place.
fn resolve_far_end(edge: Edge, inventory: &Inventory) -> Edge {
    if edge.target().identity().is_some() {
        return edge;
    }
    let target = edge.target();
    let group = target
        .api_version()
        .map_or("", |api_version| match api_version.split_once('/') {
            Some((group, _)) => group,
            None => "",
        });
    let Some(found) = inventory.resolve(target.kind(), group, target.namespace(), target.name())
    else {
        return edge;
    };
    let resolved = target.clone().resolved_as(found.identity());
    Edge::new(
        edge.source().clone(),
        edge.relation(),
        resolved,
        edge.evidence().clone(),
    )
    .with_supporting(edge.supporting().to_vec())
}

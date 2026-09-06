//! What one object is related to, and the evidence under each edge (§23 to §32, Gate D).
//!
//! `relationship.rs` and `workload.rs` know the whole `Ingress -> Service -> EndpointSlice ->
//! Pod -> Node` path. This module is the route from a query to those rules and back out as
//! records, and it is written around four things the specification does not leave open.
//!
//! **A relationship is not a resource.** It has no `metadata.uid`, and it is not fetched from a
//! collection: it is *derived* from one object, plus — for the derived classes — whatever second
//! reading the rule needs. So the question is asked about one named object, and the answer is one
//! record per edge rather than a list folded into the object's record. ADR-0014 records why.
//!
//! **Which object is discovery's answer, not this table's.** The query names a `kind` (or a
//! `resource`, a plural or a short name) and a `name`, and [`crate::dynamic`] resolves it against
//! what the cluster serves. That is the same resolution `k8s-resource` uses, which is what makes
//! a CRD's owner references reachable without recompiling anything (§33.1). It needs `get`
//! rather than `list`: §11.5's resource that offers one without the other still has
//! relationships, and §60.5's Pod readable by name in a namespace nobody may enumerate is exactly
//! the object an operator asks this question about.
//!
//! **A derivation that could not read is a gap, never an absence.** A Service's `selects` edges
//! need the Pods of its namespace. When that listing is denied, unserved or short, the edges that
//! *were* derived are true and are emitted — and the invocation then fails naming what was
//! missing, because a value stream of one schema has nowhere to put a coverage report (ADR-0004,
//! §4 invariant 13, §21.4). Reporting "no `selects` edges" would say the Service selects nothing.
//!
//! **Nothing here produces an inference.** Every rule this module calls lives in the
//! domain layer, every one of them states its class, and §23.5 forbids promoting a correlation to
//! a verified relationship. The class travels on the record so that a reader can check rather
//! than trust (§4 invariant 20).

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, EmitError, Outcome};
use ono_provider_kubernetes::coverage::{Gap, Outcome as CoverageOutcome, Scope};
use ono_provider_kubernetes::discovery::{self, Discovery, Resource, Verb};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::place::Place;
use ono_provider_kubernetes::redaction::{self, Guarded};
use ono_provider_kubernetes::relationship::{Edge, Graph, Relation};
use ono_provider_kubernetes::transport::{ByteStream, Client, Freshness, ListOptions};
use ono_provider_kubernetes::workload::Workload;
use ono_value::Schema;
use serde_json::Value as Json;

use crate::contributions::Target;
use crate::dynamic::{self, Selector};
use crate::query::{
    self, AMBIGUOUS, AMBIGUOUS_CODE, Answer, Conversation, Endpoint, UNAVAILABLE, UNAVAILABLE_CODE,
    UNSUPPORTED, UNSUPPORTED_CODE, failure,
};
use crate::records::edge_record;

/// How many objects one derivation's page asks the API server for.
const PAGE_SIZE: u32 = 500;

/// Which kind a controller's children are, for the ownership direction the child does not state.
///
/// §25's chain, read from the owner's end. The reversal is what §25.1, §25.2, §25.4 and §25.5
/// ask for, and it is the one place this module names Kubernetes kinds: an owner reference lives
/// on the *child*, so reading ownership downwards means knowing which collection to look in.
/// A kind that is not here yields the edges it states about itself and no reversal — never a
/// guess, and never a fan-out over every collection the cluster serves.
/// Each row is the owner's group and kind, then the child's — GVK identity on both ends, so a
/// custom resource that happens to be called `Job` is not read as `batch/Job` (§13.5).
const CHILDREN_OF: &[(&str, &str, &str, &str)] = &[
    ("apps", "Deployment", "apps", "ReplicaSet"),
    ("apps", "ReplicaSet", "", "Pod"),
    ("apps", "StatefulSet", "", "Pod"),
    ("apps", "DaemonSet", "", "Pod"),
    ("batch", "Job", "", "Pod"),
    ("batch", "CronJob", "batch", "Job"),
];

/// Answers a `k8s-relation` query: one object in, its edges out.
#[must_use]
pub fn answer(target: &'static Target, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let selector = Selector::from_options(ctx.arguments());
    let Some(name) = ctx
        .arguments()
        .get("name")
        .and_then(Json::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
    else {
        return Outcome::Failed(unnamed());
    };
    // §35.7's word, where the query narrowed to one. Read before the connection opens, because
    // the brokered stream borrows the context for as long as it lives.
    let wanted = match ctx.arguments().get("relation").and_then(Json::as_str) {
        None | Some("") => None,
        Some(word) => match relation_named(word) {
            Some(relation) => Some(relation),
            None => return Outcome::Failed(unknown_relation(word)),
        },
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
    };
    if ctx.cancelled() {
        return Outcome::Cancelled;
    }

    let derived = query::converse(
        ctx,
        &endpoint,
        Related {
            endpoint: &endpoint,
            selector: &selector,
            name: &name,
        },
    );
    let derived = match derived {
        Ok(derived) => derived,
        Err(error) => return Outcome::Failed(error),
    };
    emit(ctx, target, &schema, derived, wanted)
}

/// The relationship conversation: resolve the object, read it, derive its edges.
struct Related<'a> {
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    name: &'a str,
}

impl Conversation for Related<'_> {
    type Answer = Option<Derived>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let served = catalogue(client, self.endpoint, self.selector)?;
        let resource = dynamic::resolve_for(self.selector, &served, Verb::Get)
            .cloned()
            .map_err(|unresolved| query::unresolved_failure(&unresolved, self.selector, &served))?;
        let scope = match resource.scope() {
            discovery::Scope::Cluster => Scope::cluster(),
            discovery::Scope::Namespaced => self.endpoint.scope.clone(),
        };
        let (object, freshness) = match query::fetch(client, &resource, &scope, self.name)? {
            // §21.4's one outcome that is a fact about the cluster: an object that is not there
            // has no relationships, and that is an answer rather than a refusal.
            Answer::Absent => return Ok(None),
            Answer::Fetched(read) => *read,
            // `fetch` is a get, and a get answers with one object or with nothing.
            Answer::Listed(_) => {
                return Err(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    "a direct read answered with a collection".to_owned(),
                    "This is a defect in the Kubernetes provider, not in the cluster.",
                ));
            }
        };
        // §22 and Gate I: the source crosses the redaction boundary before anything derives from
        // it, so asking a Secret what it is related to cannot reach its payload.
        let guarded = Guarded::hold(object).map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the object could not be taken across the redaction boundary: {error}"),
                "This is a defect in the Kubernetes provider, not in the cluster.",
            )
        })?;
        let mut derived = Derived {
            edges: Vec::new(),
            coverage: ono_provider_kubernetes::coverage::Coverage::complete(scope.clone()),
            source: guarded,
            freshness,
        };
        stated(&mut derived);
        two_sided(client, self.endpoint, &served, &scope, &mut derived)?;
        Ok(Some(derived))
    }
}

/// What one object's relationships came to, and what the derivation could not see.
struct Derived {
    edges: Vec<Edge>,
    coverage: ono_provider_kubernetes::coverage::Coverage,
    source: Guarded,
    freshness: Freshness,
}

/// Every edge the object states about itself: no second object, so no derived class (§23.1–§23.2).
fn stated(derived: &mut Derived) {
    let object = derived.source.object();
    derived.edges.extend(Graph::edges_of(object));
    // §22.4's references, which are ordinary edges in the ordinary vocabulary. The Pod cases
    // already came from `edges_of`, so only the ServiceAccount's own two are taken here — adding
    // the whole set would emit each Pod reference twice.
    derived.edges.extend(
        redaction::secret_references(object)
            .into_iter()
            .filter(|edge| {
                matches!(
                    edge.relation(),
                    Relation::UsesSecret | Relation::UsesImagePullSecret
                )
            }),
    );
    // The curated rules below read field *shapes* — `spec.rules[].http.paths[].backend.service`,
    // `spec.serviceName`, `endpoints[]` — so each is offered only the kind it was written for.
    // A custom resource that happened to carry the same shape would otherwise acquire a
    // `routes-to` edge nobody stated, which is §23.5's inference wearing §23.1's clothes. The
    // guard is on group and kind, never on version: §5.3 forbids rejecting an unfamiliar one, and
    // `gateway_edges` checks its own versions because §27.3 makes that adapter version-aware.
    if is(object, "networking.k8s.io", "Ingress") {
        derived.edges.extend(Workload::ingress_edges(object));
    }
    derived.edges.extend(Workload::gateway_edges(object));
    if is(object, "apps", "StatefulSet") {
        derived.edges.extend(Workload::governing_service(object));
    }
    // §26.2 and §26.4: an endpoint with no target reference stays an endpoint fact rather than
    // being forced into a Pod relationship, which is why this reads the edge and not the address.
    if is(object, "discovery.k8s.io", "EndpointSlice") {
        derived.edges.extend(
            Workload::endpoints(object)
                .into_iter()
                .filter_map(|endpoint| endpoint.pod_edge().cloned()),
        );
    }
}

/// Whether the object is of that group and kind — GVK identity without the version (§13.1, §5.3).
fn is(object: &Object, group: &str, kind: &str) -> bool {
    object.gvk().group() == group && object.gvk().kind() == kind
}

/// The edges that need a second object read, each recording its own gap where it could not.
fn two_sided<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    scope: &Scope,
    derived: &mut Derived,
) -> Result<(), WireError> {
    if is(derived.source.object(), "", "Service") {
        // §26.1: the Service's selector against the labels of the Pods in its own namespace.
        if let Some(pods) = collection(client, endpoint, served, scope, "", "Pod", derived)? {
            let edges = Graph::selects(derived.source.object(), &pods);
            derived.edges.extend(edges);
        }
        // §26.2: the slices that carry the standard service-name label.
        if let Some(slices) = collection(
            client,
            endpoint,
            served,
            scope,
            "discovery.k8s.io",
            "EndpointSlice",
            derived,
        )? {
            let edges = Workload::endpoint_slices(derived.source.object(), &slices);
            derived.edges.extend(edges);
        }
    }
    if let Some((.., group, child)) = CHILDREN_OF
        .iter()
        .find(|(owner_group, owner_kind, ..)| is(derived.source.object(), owner_group, owner_kind))
        && let Some(children) = collection(client, endpoint, served, scope, group, child, derived)?
    {
        let edges = Workload::owns(derived.source.object(), &children);
        derived.edges.extend(edges);
    }
    Ok(())
}

/// One collection a derivation needs, or [`None`] with a gap recorded against the answer.
///
/// Three ways this reads nothing, and all three are gaps rather than empty results (§21.4): the
/// cluster serves no such API, it serves it without `list`, or the listing itself came back
/// short. The rule that wanted the objects is then not evaluated at all, which is ADR-0007's
/// position: an unevaluated selector says so rather than returning the subset it could evaluate.
fn collection<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    scope: &Scope,
    group: &str,
    kind: &str,
    derived: &mut Derived,
) -> Result<Option<Vec<Object>>, WireError> {
    let Some(resource) = serving(client, endpoint, served, group, kind)? else {
        derived
            .coverage
            .record(Gap::new(scope.clone(), CoverageOutcome::TypeNotServed));
        return Ok(None);
    };
    if !resource.supports(Verb::List) {
        derived
            .coverage
            .record(Gap::new(scope.clone(), CoverageOutcome::TypeNotServed));
        return Ok(None);
    }
    let scope = match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => scope.clone(),
    };
    let mut options = ListOptions::new().limit(PAGE_SIZE);
    if let Some(pages) = endpoint.max_pages {
        options = options.max_pages(pages);
    }
    let listing = client.list(resource.gvr(), &scope, &options);
    let complete = listing.coverage().is_complete() && listing.continuity().is_intact();
    for gap in listing.coverage().gaps() {
        derived.coverage.record(gap.clone());
    }
    let objects = listing.into_objects();
    if !complete {
        // The rule needs every candidate: a selector evaluated against half the Pods reports the
        // other half as unselected, which is a wrong answer rather than a partial one.
        return Ok(None);
    }
    // §22 and Gate I again: every object a derivation reads crosses the same boundary as the
    // source, so there is one door into the emission path rather than two.
    let guarded = Guarded::hold_all(objects).map_err(|error| {
        failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("an object could not be taken across the redaction boundary: {error}"),
            "This is a defect in the Kubernetes provider, not in the cluster.",
        )
    })?;
    Ok(Some(
        guarded
            .into_iter()
            .map(|held| held.object().clone())
            .collect(),
    ))
}

/// The resource serving one kind, or [`None`] where this cluster serves none.
///
/// Unlike `query::curated`, an unserved kind is not a refusal here. The question was about the
/// object's relationships, and a cluster without EndpointSlices has no `represented-by` edges to
/// report — what it must not do is report that as "none", which is why the caller records a gap.
fn serving<S: ByteStream>(
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
    let discovery = query::resource_list(client, endpoint, &group_version)?;
    Ok(discovery.by_kind(&group_version, kind).cloned())
}

/// The discovery snapshot the object is resolved against.
///
/// The whole preferred surface, because the query may name a kind in any group and §33.1 forbids
/// a compile-time assumption about which one. Narrowed where the query narrowed it, which is what
/// keeps §35.8's ambiguity answerable rather than resolved by an arbitrary type priority.
fn catalogue<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    selector: &Selector,
) -> Result<Discovery, WireError> {
    // Two documents, read once. The version list has to be *known* before the resource lists can
    // be asked for, and a builder answers only once it is built — so the same two documents are
    // parsed into a snapshot that decides the search space and again into the one the resources
    // join. `query::read` does the same for the same reason.
    let core = query::document(client, endpoint, "/api")?;
    let groups = query::document(client, endpoint, "/apis")?;
    let served = versions(&core, &groups)?.build();
    let mut builder = versions(&core, &groups)?;
    for group_version in search_space(&served, selector) {
        let list = query::document(client, endpoint, &query::resource_list_path(&group_version))?;
        builder = builder.resources(&list).map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the resource list of `{group_version}` did not read: {error}"),
                "The endpoint answered, but not as a Kubernetes API server.",
            )
        })?;
    }
    Ok(builder.build())
}

/// A discovery builder holding the version documents and nothing else.
fn versions(core: &str, groups: &str) -> Result<discovery::Builder, WireError> {
    Discovery::builder()
        .core_versions(core)
        .and_then(|builder| builder.groups(groups))
        .map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the API server's discovery documents did not read: {error}"),
                "The endpoint answered, but not as a Kubernetes API server.",
            )
        })
}

/// Which group-versions the search covers: the one the query named, or every preferred one.
fn search_space(served: &Discovery, selector: &Selector) -> Vec<String> {
    if let Some(group) = selector.group() {
        let version = selector
            .version()
            .map(str::to_owned)
            .or_else(|| served.preferred_version(group).map(str::to_owned));
        return version
            .map(|version| vec![query::group_version_of(group, &version)])
            .unwrap_or_default();
    }
    let mut space: Vec<String> = served
        .groups()
        .filter_map(|group| {
            served
                .preferred_version(group)
                .map(|version| query::group_version_of(group, version))
        })
        .collect();
    space.sort();
    space.dedup();
    space
}

/// The relationship that word names, where this provider has one for it (§35.7).
fn relation_named(word: &str) -> Option<Relation> {
    RELATIONS
        .iter()
        .copied()
        .find(|relation| relation.as_str() == word)
}

/// Every relationship word this provider answers for.
///
/// Written out so that a word added to the domain vocabulary and not to this list is a gap a
/// reader can find, rather than a `follow` that silently refuses.
const RELATIONS: &[Relation] = &[
    Relation::OwnedBy,
    Relation::ControlledBy,
    Relation::Owns,
    Relation::Controls,
    Relation::ScheduledOn,
    Relation::Selects,
    Relation::SelectorMatches,
    Relation::UsesService,
    Relation::RepresentedBy,
    Relation::EndpointFor,
    Relation::RoutesTo,
    Relation::UsesTlsSecret,
    Relation::UsesIngressClass,
    Relation::AttachesTo,
    Relation::UsesGatewayClass,
    Relation::RunsAs,
    Relation::Mounts,
    Relation::BoundTo,
    Relation::ReferencesConfig,
    Relation::ReferencesSecret,
    Relation::UsesSecret,
    Relation::UsesImagePullSecret,
];

/// Streams the edges, then reports whatever the derivation could not see.
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    derived: Option<Derived>,
    wanted: Option<Relation>,
) -> Outcome {
    // An object that is not there is a complete answer with nothing in it, reached without
    // emitting anything (§21.4 `absent`, §60.5).
    let Some(derived) = derived else {
        return Outcome::Completed;
    };
    let instance = derived.freshness.provider_instance().to_owned();
    // One address for the near end, because every edge of this answer starts at one object.
    let here = match Place::of_object(derived.source.object()) {
        Ok(here) => here,
        Err(error) => {
            return Outcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the object the edges start at has no address: {error}"),
                "A place needs a name, and §35.4 binds it to the object's lifetime identity.",
            ));
        }
    };
    for edge in &derived.edges {
        if wanted.is_some_and(|relation| edge.relation() != relation) {
            continue;
        }
        // §62.12: a cancelled query stops promptly, and the cheapest place to notice is between
        // two edges.
        if ctx.cancelled() {
            return Outcome::Cancelled;
        }
        // §24.1: an edge whose far end nobody read is still addressable, so the place is built
        // from the *reference* rather than from an object that may never have been fetched.
        let there = match Place::of_target(&instance, edge.target()) {
            Ok(there) => there,
            Err(error) => {
                return Outcome::Failed(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!(
                        "the far end of a `{}` edge has no address: {error}",
                        edge.relation().as_str()
                    ),
                    "A reference that names no resource is not a place this provider can address.",
                ));
            }
        };
        let value = match edge_record(
            target,
            schema,
            &here,
            &there,
            &derived.source,
            edge,
            &derived.freshness,
        ) {
            Ok(value) => value,
            Err(error) => {
                return Outcome::Failed(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!("an edge of `{}` could not be built: {error}", target.schema),
                    "This is a defect in the Kubernetes provider's schema table.",
                ));
            }
        };
        match ctx.emit(&value) {
            Ok(()) => {}
            Err(EmitError::Cancelled) => return Outcome::Cancelled,
            Err(error) => {
                return Outcome::Failed(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!("the host refused a record: {error}"),
                    "The stream ended before the query did.",
                ));
            }
        }
    }
    if derived.coverage.is_complete() {
        return Outcome::Completed;
    }
    Outcome::Failed(failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "the relationships that need a second reading could not all be derived: {}",
            derived.coverage.describe()
        ),
        "The edges that did arrive are true. What is missing is named above: a selector this \
         provider could not evaluate is not a selector that matched nothing, and an unserved API \
         is not an object with no neighbours (specification section 21.4).",
    ))
}

/// The query asked about relationships without saying whose.
fn unnamed() -> WireError {
    failure(
        AMBIGUOUS_CODE,
        AMBIGUOUS,
        "the query named no `name`, so it did not say which object's relationships to derive"
            .to_owned(),
        "A relationship is a fact about one object. Pass `kind` and `name` — for example \
         `--kind Pod --name checkout-7f9d` — and `namespace` where the kind is namespaced. \
         Deriving the edges of a whole collection would read every object in it to answer a \
         question about none of them.",
    )
}

/// A relationship word nobody defines, answered with the ones somebody does.
fn unknown_relation(word: &str) -> WireError {
    let known: Vec<&str> = RELATIONS.iter().map(|relation| relation.as_str()).collect();
    failure(
        UNSUPPORTED_CODE,
        UNSUPPORTED,
        format!("`{word}` is not a relationship this provider derives"),
        &format!(
            "Answering nothing would say the object has no such edges, which is a different \
             claim. The words are: {}.",
            known.join(", ")
        ),
    )
}

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
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{ByteStream, Client, Freshness, ListOptions};
use ono_provider_kubernetes::workload::{SelectorMatch, Workload};
use ono_value::Schema;
use serde_json::Value as Json;

use crate::contributions::Target;
use crate::dynamic::{self, Selector};
use crate::query::{
    self, AMBIGUOUS, AMBIGUOUS_CODE, Answer, Conversation, Endpoint, UNAVAILABLE, UNAVAILABLE_CODE,
    UNSUPPORTED, UNSUPPORTED_CODE, failure,
};
use crate::records::edge_record;
use crate::sessions::Sessions;

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
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
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

    let derived = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            query::converse(
                ctx,
                &endpoint,
                Related {
                    endpoint: &endpoint,
                    selector: &selector,
                    name: &name,
                    session,
                },
            )
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
    session: &'a mut Session,
}

impl Conversation for Related<'_> {
    type Answer = Option<Derived>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        // §34.2: a group-version that did not answer is recorded and stepped over, and the
        // derivation goes on against the groups that did. What it could not read joins this
        // answer's coverage below, because a relationship question resolves its object through
        // the same search a listing does and §35.8 binds it the same way.
        let (served, unread) = catalogue(session, client, self.endpoint, self.selector)?;
        let resource = dynamic::resolve_for(self.selector, &served, Verb::Get)
            .cloned()
            .map_err(|unresolved| {
                query::unresolved_over(&unresolved, self.selector, &served, &unread)
            })?;
        let scope = match resource.scope() {
            discovery::Scope::Cluster => Scope::cluster(),
            discovery::Scope::Namespaced => self.endpoint.scope.clone(),
        };
        let (object, freshness) = match query::fetch(client, &resource, &scope, self.name)? {
            // §21.4's one outcome that is a fact about the cluster: an object that is not there
            // has no relationships, and that is an answer rather than a refusal — unless the
            // search that chose the collection skipped a group, in which case the absence is
            // about one resource rather than about the cluster (§34.2, §35.8).
            Answer::Absent if !unread.is_empty() => return Err(absence_unproven(&unread)),
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
            unevaluated: Vec::new(),
            coverage: ono_provider_kubernetes::coverage::Coverage::complete(scope.clone()),
            source: guarded,
            freshness,
            sources: Vec::new(),
        };
        // §34.2's second sentence: the failed group/version is reported separately, beside the
        // gaps the derivations record for themselves.
        for gap in unread {
            derived.coverage.record(gap);
        }
        stated(&mut derived);
        two_sided(
            session,
            client,
            self.endpoint,
            &served,
            &scope,
            &mut derived,
        )?;
        Ok(Some(derived))
    }
}

/// What one object's relationships came to, and what the derivation could not see.
struct Derived {
    edges: Vec<Edge>,
    /// The selectors a rule declined to evaluate, in the words of the field that stopped it.
    ///
    /// Beside the coverage rather than inside it, because [`Gap`] says which *scope* did not
    /// answer and this is a scope that answered in full and a selector this provider does not
    /// evaluate (ADR-0007). Both end the invocation; only one of them is about the cluster.
    unevaluated: Vec<String>,
    coverage: ono_provider_kubernetes::coverage::Coverage,
    source: Guarded,
    freshness: Freshness,
    /// Every *second* read a derivation drew on, in the order it was made (§23.6).
    ///
    /// The subject's own read is [`Self::freshness`] and is not in here. What is in here is the
    /// collection a rule listed to evaluate a selector against — the second half of a conclusion
    /// neither object states — and it is kept because §23.6 bounds a derived edge's freshness by
    /// *every* source fact, and because Appendix C.2 shows each source's `resourceVersion` on the
    /// edge it produced.
    sources: Vec<SourceRead>,
}

/// One collection a derivation read, and what it was worth.
///
/// The role is the kind, lower-cased, because that is what Appendix C.2's example keys on
/// (`service:`, `pod:`) and because a reader checking an edge against the cluster asks "which
/// Pod list was this?" rather than "which of the three reads was this?".
struct SourceRead {
    role: String,
    freshness: Freshness,
}

/// Appendix C.2's `observed_resource_versions`: what each source of this edge was at.
///
/// The subject is always in it, under its own kind, because every edge rests on the subject's
/// read. The collections are in it only for an edge this provider *concluded* — an owner
/// reference is a field of the subject and nothing else was read to find it, so listing a Pod
/// collection beside it would name a source that had no part in the conclusion, which is the
/// same class of mistake as citing evidence that does not exist.
///
/// A source whose read carried no `resourceVersion` is left out rather than entered as empty
/// text: the point of the map is that a reader can check an edge against the cluster, and a key
/// with nothing behind it is a check that cannot be made (§21.4).
fn observed_resource_versions(derived: &Derived, edge: &Edge) -> Vec<(String, String)> {
    let mut versions = Vec::new();
    let subject = derived.source.object();
    if let Some(version) = subject.resource_version() {
        versions.push((subject.gvk().kind().to_lowercase(), version.to_owned()));
    }
    if !edge.evidence().is_asserted_by_provider() {
        for read in &derived.sources {
            if let Some(version) = read.freshness.resource_version() {
                versions.push((read.role.clone(), version.to_owned()));
            }
        }
    }
    versions
}

/// Every edge the object states about itself: no second object, so no derived class (§23.1–§23.2).
fn stated(derived: &mut Derived) {
    derived.edges.extend(stated_edges(derived.source.object()));
}

/// The edges one object states about itself, with no second reading (§23.1–§23.2).
///
/// Lifted out of [`stated`] so that the spatial contribution derives its edges through exactly
/// this rule rather than through a second copy of it (v0.4.1 §39.1): a relationship a user reads
/// with `get k8s-relation` and one they walk with `follow` must be the same relationship, decided
/// once.
pub(crate) fn stated_edges(object: &Object) -> Vec<Edge> {
    let mut edges = Vec::new();
    edges.extend(Graph::edges_of(object));
    // §22.4's references, which are ordinary edges in the ordinary vocabulary. The Pod cases
    // already came from `edges_of`, so only the ServiceAccount's own two are taken here — adding
    // the whole set would emit each Pod reference twice.
    edges.extend(
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
        edges.extend(Workload::ingress_edges(object));
    }
    edges.extend(Workload::gateway_edges(object));
    if is(object, "apps", "StatefulSet") {
        edges.extend(Workload::governing_service(object));
    }
    // §25.1's `uses-template`, answered as the dependencies the template states rather than as an
    // edge to the template itself: a PodTemplate is not an addressable object (§25.3), so an edge
    // pointing at one would name a place `Place::of_target` cannot build. The guard is the kind
    // table inside the rule, because the pointer differs per kind — a CronJob's template is two
    // levels down — and a second guard here would be a second place for the two to disagree.
    edges.extend(Workload::template_dependencies(object));
    // §26.2 and §26.4: an endpoint with no target reference stays an endpoint fact rather than
    // being forced into a Pod relationship, which is why this reads the edge and not the address.
    if is(object, "discovery.k8s.io", "EndpointSlice") {
        edges.extend(
            Workload::endpoints(object)
                .into_iter()
                .filter_map(|endpoint| endpoint.pod_edge().cloned()),
        );
    }
    edges
}

/// Whether the object is of that group and kind — GVK identity without the version (§13.1, §5.3).
pub(crate) fn is(object: &Object, group: &str, kind: &str) -> bool {
    object.gvk().group() == group && object.gvk().kind() == kind
}

/// The edges that need a second object read, each recording its own gap where it could not.
fn two_sided<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    scope: &Scope,
    derived: &mut Derived,
) -> Result<(), WireError> {
    if is(derived.source.object(), "", "Service") {
        // §26.1: the Service's selector against the labels of the Pods in its own namespace.
        if let Some(pods) =
            collection(session, client, endpoint, served, scope, "", "Pod", derived)?
        {
            let edges = Graph::selects(derived.source.object(), &pods);
            derived.edges.extend(edges);
        }
        // §26.2: the slices that carry the standard service-name label.
        if let Some(slices) = collection(
            session,
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
    // §31.1, from the policy's end: the Pods of its own namespace, evaluated against
    // `spec.podSelector`. The policy is the object an operator names during an outage, and until
    // this derivation existed a NetworkPolicy had no relationship at all.
    if is(
        derived.source.object(),
        "networking.k8s.io",
        "NetworkPolicy",
    ) && let Some(pods) =
        collection(session, client, endpoint, served, scope, "", "Pod", derived)?
    {
        let reached = Graph::policy_selects(derived.source.object(), &pods);
        evaluated(derived, reached);
    }
    if is(derived.source.object(), "", "Pod") {
        // Appendix B's `selected-by`: §26.1 read from the Pod's end, which is where an operator
        // stands when one Pod is missing from a Service's endpoints.
        if let Some(services) = collection(
            session, client, endpoint, served, scope, "", "Service", derived,
        )? {
            let edges = Graph::selected_by(derived.source.object(), &services);
            derived.edges.extend(edges);
        }
        // Appendix B's `protected-by`: §31.1 read from the Pod's end.
        if let Some(policies) = collection(
            session,
            client,
            endpoint,
            served,
            scope,
            "networking.k8s.io",
            "NetworkPolicy",
            derived,
        )? {
            let reached = Graph::protected_by(derived.source.object(), &policies);
            evaluated(derived, reached);
        }
    }
    // Appendix B's `routed-from`: §27.1 read from the backend's end, where an operator stands
    // when a Service has healthy endpoints and the URL in front of it does not answer.
    if is(derived.source.object(), "", "Service")
        && let Some(routers) = collection(
            session,
            client,
            endpoint,
            served,
            scope,
            "networking.k8s.io",
            "Ingress",
            derived,
        )?
    {
        let edges = Workload::routed_from(derived.source.object(), &routers);
        derived.edges.extend(edges);
    }
    if let Some((.., group, child)) = CHILDREN_OF
        .iter()
        .find(|(owner_group, owner_kind, ..)| is(derived.source.object(), owner_group, owner_kind))
        && let Some(children) = collection(
            session, client, endpoint, served, scope, group, child, derived,
        )?
    {
        let edges = Workload::owns(derived.source.object(), &children);
        derived.edges.extend(edges);
    }
    Ok(())
}

/// Takes the edges of an evaluated selector, or records why one was not evaluated (ADR-0007).
///
/// A selector this provider does not evaluate in full yields no edges at all rather than the
/// subset it could evaluate: that subset is *wider* than the selector, so an object the selector
/// excludes would arrive looking related. The reason ends the invocation beside the coverage
/// gaps, because "no such edges" and "this selector was not evaluated" are different answers.
fn evaluated(derived: &mut Derived, reached: SelectorMatch) {
    match reached {
        SelectorMatch::Evaluated(edges) => derived.edges.extend(edges),
        SelectorMatch::NotEvaluated { reason } => derived.unevaluated.push(reason),
    }
}

/// One collection a derivation needs, or [`None`] with a gap recorded against the answer.
///
/// Three ways this reads nothing, and all three are gaps rather than empty results (§21.4): the
/// cluster serves no such API, it serves it without `list`, or the listing itself came back
/// short. The rule that wanted the objects is then not evaluated at all, which is ADR-0007's
/// position: an unevaluated selector says so rather than returning the subset it could evaluate.
fn collection<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    scope: &Scope,
    group: &str,
    kind: &str,
    derived: &mut Derived,
) -> Result<Option<Vec<Object>>, WireError> {
    let Some(resource) = serving(session, client, endpoint, served, group, kind)? else {
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
    // §23.6, recorded at the one moment it is knowable: this listing is the second source of every
    // edge the rule about to run derives, and once the objects are unwrapped the read that
    // produced them is gone.
    derived.sources.push(SourceRead {
        role: kind.to_lowercase(),
        freshness: listing.freshness().clone(),
    });
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

/// The discovery snapshot the object is resolved against.
///
/// The whole preferred surface, because the query may name a kind in any group and §33.1 forbids
/// a compile-time assumption about which one. Narrowed where the query narrowed it, which is what
/// keeps §35.8's ambiguity answerable rather than resolved by an arbitrary type priority.
fn catalogue<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    selector: &Selector,
) -> Result<(Discovery, Vec<Gap>), WireError> {
    // Two documents, read once. The version list has to be *known* before the resource lists can
    // be asked for, and a builder answers only once it is built — so the same two documents are
    // parsed into a snapshot that decides the search space and again into the one the resources
    // join. `query::read` does the same for the same reason.
    //
    // `/api` and `/apis` still fail the query: they are how the provider learns what is served at
    // all (§11.1), and §34.2's isolation is for the groups *behind* them.
    let core = query::document(session, client, endpoint, "/api")?;
    let groups = query::document(session, client, endpoint, "/apis")?;
    let served = versions(&core, &groups)?.build();
    let mut builder = versions(&core, &groups)?;
    let mut unread = Vec::new();
    for group_version in search_space(&served, selector) {
        let outcome = match query::group_document(session, client, endpoint, &group_version)? {
            query::GroupRead::Document(list) => match builder.add_resources(&list) {
                Ok(()) => continue,
                Err(_) => CoverageOutcome::RequestFailed,
            },
            query::GroupRead::Unread(outcome) => outcome,
        };
        unread.push(Gap::new(Scope::in_group_version(&group_version), outcome));
    }
    Ok((builder.build(), unread))
}

/// An object absent from the one resource an incomplete search resolved to (§34.2, §35.8).
fn absence_unproven(unread: &[Gap]) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "the resource the search resolved to holds no such object, and the search could not \
             read every API group: {}",
            query::describe(unread),
        ),
        "An object that is not there has no relationships, and that is an answer — but only over \
         a search that covered every group. A group whose own API server did not answer is not a \
         group with nothing in it (specification sections 34.2 and 21.4).",
    )
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
    Relation::SelectedBy,
    Relation::SelectorMatches,
    Relation::UsesService,
    Relation::RepresentedBy,
    Relation::EndpointFor,
    Relation::RoutesTo,
    Relation::RoutedFrom,
    Relation::UsesTlsSecret,
    Relation::UsesIngressClass,
    Relation::AttachesTo,
    Relation::UsesGatewayClass,
    Relation::RunsAs,
    Relation::Mounts,
    Relation::BoundTo,
    Relation::UsesStorageClass,
    Relation::ReferencesConfig,
    Relation::ReferencesSecret,
    Relation::UsesSecret,
    Relation::UsesImagePullSecret,
    Relation::Binds,
    Relation::ProtectedBy,
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
        // §23.6: an edge this provider concluded from two objects is only as fresh as the older
        // of them, and an edge the API server states about the object is as fresh as that
        // object's read. The difference is `is_asserted_by_provider` — the same fact the record
        // already publishes as `asserted`, so the rule a reader is told about and the rule the
        // code applies are one thing rather than two that can drift.
        let bounded = if edge.evidence().is_asserted_by_provider() {
            derived.freshness.clone()
        } else {
            derived
                .freshness
                .bounded_by(derived.sources.iter().map(|read| &read.freshness))
        };
        let value = match edge_record(
            target,
            schema,
            &here,
            &there,
            &derived.source,
            edge,
            &bounded,
            &observed_resource_versions(&derived, edge),
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
    if !derived.unevaluated.is_empty() {
        return Outcome::Failed(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!(
                "a selector this provider does not evaluate leaves part of this object's \
                 neighbourhood undetermined: {}",
                derived.unevaluated.join("; ")
            ),
            "The edges that did arrive are true. An unevaluated selector is not a selector that \
             matched nothing: its `matchLabels` alone match more than the selector does, so the \
             objects it would have excluded cannot be reported either way (ADR-0007, \
             specification section 23.3).",
        ));
    }
    if derived.coverage.is_complete() {
        return Outcome::Completed;
    }
    Outcome::Failed(failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "the edges of this object could not all be established: {}",
            derived.coverage.describe()
        ),
        "The edges that did arrive are true. What is missing is named above: a selector this \
         provider could not evaluate is not a selector that matched nothing, an unserved API is \
         not an object with no neighbours, and an API group whose own server did not answer is \
         not a group with nothing in it (specification sections 21.4 and 34.2).",
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

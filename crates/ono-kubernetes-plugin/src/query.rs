//! Answering one `provider.query`: from the target word to a stream of records.
//!
//! The shape of an answer is fixed by three things the specification does not leave open.
//!
//! **Discovery decides which collection is read.** A curated target names a group and a kind —
//! GVK identity — and nothing more. Which resource serves that kind, at which version, and
//! whether it is namespaced is asked of the API server every time (§4 invariants 1–2, §5.2,
//! §13.1). A hard-coded `/api/v1/pods` would be a compile-time claim about a cluster this code
//! has never seen, and it is exactly the claim §33.1 forbids for custom resources.
//!
//! **`k8s-resource` takes the kind from the query instead of from the table**, and is otherwise
//! the same path (§15.1, §33.1, ADR-0010). It exists because a document written before this
//! package runs cannot name a kind invented after it, so the noun names the shape of the
//! question. Its records carry the one schema the package can honestly declare for a kind it
//! has never seen, and say which Kubernetes type they are in their fields (§13.2).
//!
//! **Every object crosses the boundary as a [`Guarded`].** There is no path from a listing to an
//! emission that does not go through the redaction guard, so a Secret's payload is destroyed
//! before anything can render, log or navigate it (§22, Gate I).
//!
//! **A context is named, never guessed.** §7.4 requires the selected context to be visible in
//! the provider instance identity, and §4 invariant 1 puts the API server at the authority. So a
//! query names a kubeconfig `context` — which is resolved through `~/.kube/config` under the
//! host's `filesystem.read` capability — or an explicit `host`, which is §7.3's explicit
//! configuration for automation and test hosts. Naming neither is refused: an endpoint this
//! package invented would be a cluster the operator never chose.
//!
//! **An incomplete answer never renders as a whole one.** A `403`, an expired continue token and
//! a page budget are three different reasons for a short list, and none of them is "there are no
//! more" (§4 invariant 13, §21.4). The values already read are emitted — they are true — and the
//! invocation then *fails* with what was missing, because the value stream of a contributed
//! target carries records of one schema and has nowhere to put a coverage report.
//!
//! **`name` asks a different question of the cluster.** A query naming one takes §17.1's direct
//! lookup against the object's own REST endpoint rather than the collection's, and the two are
//! not interchangeable: the direct read needs `get` where the listing needs `list`, and §60.5's
//! scenario — a Pod readable by name in a namespace nobody may enumerate — is exactly the case a
//! provider that listed and filtered would report as a denial. Their failures differ for the
//! same reason: a `404` on a collection is an API the cluster does not serve, and a `404` on one
//! object is that object being absent, which is the only outcome in §21.4's vocabulary that is
//! evidence of absence rather than a statement about what could not be seen (ADR-0012).

use std::fmt;
use std::sync::Arc;

use ono_kuang_sdk::protocol::{WireError, method};
use ono_kuang_sdk::{Ctx, EmitError, Outcome};
use ono_provider_kubernetes::coverage::{Outcome as Coverage, Scope};
use ono_provider_kubernetes::discovery::{self, Discovery, Resource, Verb};
use ono_provider_kubernetes::kubeconfig::{Credential, Kubeconfig, Secret, Trust};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::tls::{Anchors, ClientIdentity, TlsError, TlsSettings, TlsStream};
use ono_provider_kubernetes::transport::{
    ApiError, ByteStream, Client, Freshness, ListOptions, Listing, Operation, Request,
};
use ono_value::Schema;
use serde_json::{Map as JsonMap, Value as Json, json};

use crate::broker::{BrokeredStream, decode_hex};
use crate::contributions::{Reads, Target};
use crate::dynamic::{self, Selector, Typing, Unresolved};
use crate::records::{dynamic_record, record};

/// `provider.unavailable`, as core's `docs/contracts/errors.yaml` publishes it.
///
/// Spelled out rather than taken from `ono_core::ErrorCode`, which a package does not depend on.
/// The KUANG taxonomy has no code for "this provider could not reach the system it fronts", and
/// inventing one would put a code on the wire that no registry explains.
pub(crate) const UNAVAILABLE_CODE: &str = "Ono-Sendai-E0401";
/// The dotted name of [`UNAVAILABLE_CODE`].
pub(crate) const UNAVAILABLE: &str = "provider.unavailable";
/// `provider.unsupported`, for a cluster that serves no such thing.
pub(crate) const UNSUPPORTED_CODE: &str = "Ono-Sendai-E0402";
/// The dotted name of [`UNSUPPORTED_CODE`].
pub(crate) const UNSUPPORTED: &str = "provider.unsupported";
/// `resolve.ambiguous`, for a name that several served types share (§35.8, §13.5).
///
/// Core's own code for "the name matches more than one candidate and no namespace was given",
/// which is exactly what a kind two API groups both serve is. Reusing it rather than inventing a
/// Kubernetes-shaped one keeps §0.4: a shell that already knows how to render an ambiguity needs
/// no Kubernetes special case to render this one.
pub(crate) const AMBIGUOUS_CODE: &str = "Ono-Sendai-E0103";
/// The dotted name of [`AMBIGUOUS_CODE`].
pub(crate) const AMBIGUOUS: &str = "resolve.ambiguous";

/// The port `kubectl proxy` listens on unless told otherwise.
///
/// A default with a source rather than a guess. There is deliberately no default *host*: an
/// endpoint this package invented would be a cluster the operator never named.
const DEFAULT_PORT: u16 = 8001;

/// How many objects one page asks the API server for.
const PAGE_SIZE: u32 = 500;

/// Where a kubeconfig lives unless the query names another file.
const DEFAULT_KUBECONFIG: &str = "~/.kube/config";

/// How many bytes one `filesystem.read` asks for. The host caps a single call at 64 KiB, so a
/// larger file is read in several calls rather than silently truncated.
const READ_CHUNK: u64 = 64 * 1024;

/// How large a kubeconfig may be before this package stops reading it.
///
/// A bound rather than a judgement: a file this size is not a kubeconfig, and reading an
/// unbounded amount of it into memory on the strength of a path is how a wrong path becomes an
/// out-of-memory failure.
const MAX_KUBECONFIG: usize = 4 * 1024 * 1024;

/// Answers a query for one target.
///
/// Never returns [`Outcome::Completed`] for an answer it knows to be partial; see the module
/// documentation for why the values still cross first.
#[must_use]
pub fn answer(target: &'static Target, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    // Read before the connection opens, because the brokered stream borrows the context for as
    // long as it lives and the query's own words are needed after that.
    let selector = Selector::from_options(ctx.arguments());
    let lookup = ctx
        .arguments()
        .get("name")
        .and_then(Json::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
    };
    if ctx.cancelled() {
        return Outcome::Cancelled;
    }

    let answer = converse(
        ctx,
        &endpoint,
        Listed {
            target,
            endpoint: &endpoint,
            selector: &selector,
            lookup: lookup.as_deref(),
        },
    );
    let (answer, shape) = match answer {
        Ok(answer) => answer,
        Err(error) => return Outcome::Failed(error),
    };
    emit(ctx, target, &schema, &shape, answer)
}

/// The listing conversation, as one value [`converse`] can run over either kind of stream.
struct Listed<'a> {
    target: &'static Target,
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    lookup: Option<&'a str>,
}

impl Conversation for Listed<'_> {
    type Answer = (Answer, Shape);

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        read(
            client,
            self.target,
            self.endpoint,
            self.selector,
            self.lookup,
        )
    }
}

/// One exchange with the API server, written once and run over whichever stream the endpoint has.
///
/// A trait rather than a closure because the two arms of [`converse`] hold *different* stream
/// types — plain brokered bytes and a TLS session over them — and one `FnOnce` cannot be called
/// with both. The alternative is the connect-and-close dance written out twice, and the half that
/// would rot is the closing: `network.close` on a handle the host has already retired is a
/// protocol violation that quarantines the package.
pub(crate) trait Conversation {
    /// What the exchange comes back with.
    type Answer;

    /// Talks to the API server over `client`.
    ///
    /// # Errors
    ///
    /// Whatever the exchange could not do, in the vocabulary of core's `errors.yaml`.
    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError>;
}

/// Opens the brokered connection, runs one conversation over it, and closes it.
///
/// The brokered connection borrows the context for as long as it lives, so the whole conversation
/// happens inside the block below and only its result escapes.
pub(crate) fn converse<C: Conversation>(
    ctx: &mut Ctx<'_>,
    endpoint: &Endpoint,
    conversation: C,
) -> Result<C::Answer, WireError> {
    let (answer, handle, open) = {
        let stream = BrokeredStream::connect(ctx, &endpoint.host, endpoint.port)?;
        let handle = stream.handle();
        match &endpoint.tls {
            // Plain HTTP/1.1 over the brokered bytes: what an API server reached through
            // `kubectl proxy` speaks, and never what one reached directly does.
            None => {
                let mut client = endpoint.client(stream);
                let answer = conversation.run(&mut client);
                let open = client.into_stream().is_open();
                (answer, handle, open)
            }
            Some(settings) => match TlsStream::connect(stream, &endpoint.server_name, settings) {
                Ok(session) => {
                    let mut client = endpoint.client(session);
                    let answer = conversation.run(&mut client);
                    let open = client.into_stream().into_inner().is_open();
                    (answer, handle, open)
                }
                // The handshake consumed the stream, so whether the host still holds the
                // connection cannot be asked here. Not closing leaks a handle until the
                // invocation ends; closing one the host has already retired is a protocol
                // violation that quarantines the package, and that is the worse of the two.
                Err(error) => (Err(handshake_failure(endpoint, &error)), handle, false),
            },
        }
    };
    if open {
        // Only while the host still holds it: `network.close` on a handle the host has already
        // retired is a protocol violation, and the host retires one the moment the peer closes.
        let _ = ctx.host_call(method::NETWORK_CLOSE, json!({"connection": handle}));
    }
    answer
}

/// How the records of one answer are built.
///
/// The two cases differ in exactly one thing — where the field values come from — and share
/// everything else: the same discovery, the same list, the same redaction boundary, the same
/// coverage rules. Keeping the difference in one enum is what stops a dynamic resource becoming
/// a second read path with its own bugs (§33.1's "CRDs are normal resources").
enum Shape {
    /// A curated noun: the table's fields, filled from the object (§15.2).
    Curated,
    /// A discovered resource: §13.2's type identity beside the cluster's own typing (§15.1).
    Discovered {
        /// What discovery said this resource is — the group, the plural and the scope no
        /// record could otherwise carry once every kind shares one schema.
        resource: Box<Resource>,
        /// What the cluster publishes about its fields, which may be nothing (§12.3).
        typing: Box<Typing>,
    },
}

/// What the cluster answered, which is one of three things and never a blend of them.
///
/// The list and the get are separate variants rather than one vector of objects, because their
/// *silences* mean different things and the difference has to survive as far as the outcome. A
/// listing that came back short is incomplete (§18.3); a get that came back with nothing is a
/// complete answer about one object.
pub(crate) enum Answer {
    /// A whole collection, as far as it could be read (§17.2, §18).
    ///
    /// Boxed for the same reason the transport boxes its `Status` payloads: a listing carries
    /// its coverage, its continuity and its freshness beside its objects, and an enum sized to
    /// its largest variant would make the answer that carries nothing as expensive as the one
    /// that carries everything.
    Listed(Box<Listing>),
    /// One object, read at its own endpoint (§17.1).
    Fetched(Box<(Object, Freshness)>),
    /// The object's endpoint answered `404`, so the object is not there (§21.4 `absent`).
    ///
    /// The one outcome in §21.4's vocabulary that is evidence of absence rather than a statement
    /// about what could not be seen — which is why it is an answer of no records and not a
    /// failure. Every other way a get comes back empty is a refusal, and every refusal fails.
    Absent,
}

/// Streams whatever the cluster answered, then reports whatever it could not see.
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    shape: &Shape,
    answer: Answer,
) -> Outcome {
    // §60.5 and §21.4 in the shape of a control flow: a named object that is not there is a
    // complete answer with nothing in it, and it is reached without emitting anything, so
    // nothing downstream has to distinguish it from a failure that emitted first.
    let (objects, freshness, listed) = match answer {
        Answer::Absent => return Outcome::Completed,
        Answer::Fetched(read) => {
            let (object, freshness) = *read;
            (vec![object], freshness, None)
        }
        Answer::Listed(listing) => {
            let listing = *listing;
            let coverage = listing.coverage().describe();
            let complete = listing.coverage().is_complete() && listing.continuity().is_intact();
            let broken = !listing.continuity().is_intact();
            let freshness = listing.freshness().clone();
            (
                listing.into_objects(),
                freshness,
                Some((complete, broken, coverage)),
            )
        }
    };
    for object in objects {
        // §62.12: a cancelled query stops promptly, and the cheapest place to notice is between
        // two objects.
        if ctx.cancelled() {
            return Outcome::Cancelled;
        }
        let guarded = match Guarded::hold(object) {
            Ok(guarded) => guarded,
            Err(error) => {
                return Outcome::Failed(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!("an object could not be taken across the redaction boundary: {error}"),
                    "This is a defect in the Kubernetes provider, not in the cluster.",
                ));
            }
        };
        let built = match shape {
            Shape::Curated => record(target, schema, &guarded, &freshness),
            Shape::Discovered { resource, typing } => {
                dynamic_record(target, schema, resource, typing, &guarded, &freshness)
            }
        };
        let value = match built {
            Ok(value) => value,
            Err(error) => {
                return Outcome::Failed(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    format!(
                        "a record of `{}` could not be built: {error}",
                        target.schema
                    ),
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
    let Some((complete, broken, coverage)) = listed else {
        // A get answered, so there is no collection whose coverage could be partial: one object
        // was asked for and one object arrived.
        return Outcome::Completed;
    };
    if complete {
        return Outcome::Completed;
    }
    Outcome::Failed(failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        if broken {
            format!(
                "the listing lost continuity and the records already delivered are one \
                 observation with a gap in it: {coverage}"
            )
        } else {
            format!("the query did not see everything it asked about: {coverage}")
        },
        "The records that did arrive are true. What is missing is named above — a denial, an \
         unserved API and an exhausted page budget are different things, and none of them means \
         the cluster is empty.",
    ))
}

/// Discovers what serves the target's kind, then reads it — one object, or the collection.
fn read<S: ByteStream>(
    client: &mut Client<S>,
    target: &'static Target,
    endpoint: &Endpoint,
    selector: &Selector,
    lookup: Option<&str>,
) -> Result<(Answer, Shape), WireError> {
    let core = document(client, endpoint, "/api")?;
    let groups = document(client, endpoint, "/apis")?;
    // Two passes over the same two documents rather than two round trips: the preferred version
    // has to be known before the resource list can be asked for, and `Builder` answers only once
    // it is built.
    let served = Discovery::builder()
        .core_versions(&core)
        .and_then(|builder| builder.groups(&groups))
        .map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the API server's discovery documents did not read: {error}"),
                "The endpoint answered, but not as a Kubernetes API server.",
            )
        })?
        .build();

    let (resource, shape) = match target.reads {
        Reads::Kind { group, kind } => {
            let resource = curated(client, endpoint, &served, group, kind)?;
            (resource, Shape::Curated)
        }
        // The instance diagnostic is not a listing of anything, so it never reaches this
        // function: `answer` routes it before a collection is chosen. The arm exists so that
        // adding a third way to read cannot silently fall through to a wrong one.
        Reads::Instance => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                "the provider instance is not a collection of objects, so it cannot be listed"
                    .to_owned(),
                "This target reports on the session rather than on anything in the cluster.",
            ));
        }
        // Nor is a relationship: it has no collection of its own, and `relations::answer` routes
        // it long before a collection is chosen.
        Reads::Relations => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                "a relationship is derived from one object rather than fetched from a collection"
                    .to_owned(),
                "Ask for the object's relationships with `get k8s-relation --kind ... --name ...`.",
            ));
        }
        Reads::Discovered => {
            let resource = discovered(client, endpoint, &served, selector)?;
            let typing = typing_of(client, endpoint, &resource)?;
            (
                resource.clone(),
                Shape::Discovered {
                    resource: Box::new(resource),
                    typing: Box::new(typing),
                },
            )
        }
    };

    // §9.2: a cluster-scoped resource has no namespace, and inventing one for it would be a
    // request the server rejects for a reason that has nothing to do with what was asked.
    let scope = match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => endpoint.scope.clone(),
    };

    if let Some(name) = lookup {
        return Ok((fetch(client, &resource, &scope, name)?, shape));
    }

    if !resource.supports(Verb::List) {
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "the cluster serves `{}` but does not offer `list` on it",
                resource.gvr()
            ),
            "A resource that cannot be listed is not an empty collection.",
        ));
    }

    let mut options = ListOptions::new().limit(PAGE_SIZE);
    if let Some(pages) = endpoint.max_pages {
        options = options.max_pages(pages);
    }
    Ok((
        Answer::Listed(Box::new(client.list(resource.gvr(), &scope, &options))),
        shape,
    ))
}

/// One object, at the canonical endpoint discovery resolved for it (§17.1).
///
/// A direct lookup rather than a listing with a filter over it, and the difference is not an
/// optimisation. The two requests need different permissions — §60.5's scenario is a Pod
/// readable by name in a namespace nobody may enumerate — and a provider that answered `name` by
/// listing would report that Pod as denied. `get` is also the only verb a resource may offer
/// without offering `list` at all (§11.5).
pub(crate) fn fetch<S: ByteStream>(
    client: &mut Client<S>,
    resource: &Resource,
    scope: &Scope,
    name: &str,
) -> Result<Answer, WireError> {
    if !resource.supports(Verb::Get) {
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "the cluster serves `{}` but does not offer `get` on it",
                resource.gvr()
            ),
            "A resource that cannot be read by name is not an object that is not there.",
        ));
    }
    match client.get(resource.gvr(), scope, name) {
        Ok(read) => {
            let (object, freshness) = read.into_parts();
            Ok(Answer::Fetched(Box::new((object, freshness))))
        }
        // §21.4, one outcome at a time. `absent` is the only one that is a fact about the
        // cluster, and it is the only one that answers rather than refuses. Every other outcome
        // is a statement about what could not be seen, and rendering any of them as an empty
        // answer would tell an operator the object is gone.
        Err(error) => match error.outcome(Operation::Get) {
            Coverage::Absent => Ok(Answer::Absent),
            outcome => Err(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!(
                    "`{}` in {scope} did not answer for `{name}`: {} — {error}",
                    resource.gvr(),
                    outcome.as_str()
                ),
                "This is what happened instead of a read, and it is not the object being absent: \
                 a refusal, an unreachable server and a failed request are three different \
                 states, and only one of them means there is nothing there (§21.4).",
            )),
        },
    }
}

/// The resource serving a kind this package named at build time (§15.2).
fn curated<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    group: &str,
    kind: &str,
) -> Result<Resource, WireError> {
    let version = served.preferred_version(group).ok_or_else(|| {
        failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "this cluster serves no version of the API group `{}`, so it serves no {kind}",
                if group.is_empty() { "core" } else { group },
            ),
            "An unserved API is not an empty result: nothing was asked, so nothing is known.",
        )
    })?;
    let group_version = group_version_of(group, version);
    let discovery = resource_list(client, endpoint, &group_version)?;
    discovery
        .by_kind(&group_version, kind)
        .cloned()
        .ok_or_else(|| {
            failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("`{group_version}` serves no kind `{kind}` on this cluster"),
                "Discovery is authoritative: this build makes no assumption about which APIs a \
                 cluster serves.",
            )
        })
}

/// The resource the *query* named, resolved against what the cluster serves (§15.1, §33.1).
///
/// The search is over the preferred version of every group the server lists, unless the query
/// narrowed it — which is what makes a kind nobody compiled in reachable by name alone, and what
/// makes §35.8's ambiguity a real possibility rather than a theoretical one.
fn discovered<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    selector: &Selector,
) -> Result<Resource, WireError> {
    let group_versions = search_space(served, selector)?;
    let mut builder = Discovery::builder();
    for group_version in &group_versions {
        let list = document(client, endpoint, &resource_list_path(group_version))?;
        builder = builder.resources(&list).map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the resource list of `{group_version}` did not read: {error}"),
                "The endpoint answered, but not as a Kubernetes API server.",
            )
        })?;
    }
    let discovery = builder.build();

    dynamic::resolve(selector, &discovery)
        .cloned()
        .map_err(|unresolved| unresolved_failure(&unresolved, selector, &discovery))
}

/// Which group-versions the search covers.
///
/// One per group, because two served versions of one resource are one resource and counting them
/// as two candidates would make §13.4's version choice look like §35.8's ambiguity. A query that
/// wants a version other than the preferred one names the group too — a version on its own does
/// not say which group's version it is.
fn search_space(served: &Discovery, selector: &Selector) -> Result<Vec<String>, WireError> {
    let Some(group) = selector.group() else {
        if let Some(version) = selector.version() {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("`version {version}` names no group, so there is no version to look for"),
                "Two API groups may both serve a `v1`. Name `group` beside `version`, or leave \
                 both out and take the version the server prefers (specification section 13.4).",
            ));
        }
        let mut space: Vec<String> = served
            .groups()
            .filter_map(|group| {
                served
                    .preferred_version(group)
                    .map(|version| group_version_of(group, version))
            })
            .collect();
        space.sort();
        space.dedup();
        return Ok(space);
    };
    let version = match selector.version() {
        Some(version) => {
            let available = served.versions_of(group);
            if !available.iter().any(|served| served == version) {
                return Err(failure(
                    UNSUPPORTED_CODE,
                    UNSUPPORTED,
                    format!(
                        "this cluster serves no `{version}` of the API group `{}`",
                        if group.is_empty() { "core" } else { group },
                    ),
                    &format!(
                        "It serves: {}. A version the server does not offer is not an empty \
                         collection.",
                        if available.is_empty() {
                            "no version of that group at all".to_owned()
                        } else {
                            available.join(", ")
                        }
                    ),
                ));
            }
            version.to_owned()
        }
        None => served
            .preferred_version(group)
            .ok_or_else(|| {
                failure(
                    UNSUPPORTED_CODE,
                    UNSUPPORTED,
                    format!(
                        "this cluster serves no version of the API group `{}`",
                        if group.is_empty() { "core" } else { group },
                    ),
                    "An unserved API is not an empty result: nothing was asked, so nothing is \
                     known.",
                )
            })?
            .to_owned(),
    };
    Ok(vec![group_version_of(group, &version)])
}

/// What the cluster publishes about the resolved resource's fields (§12.1, §12.3, §33.3).
///
/// The API server's own OpenAPI v3 document, which carries a CRD's structural schema beside
/// every built-in's — so one request types both and this package needs no permission on
/// `customresourcedefinitions` to understand a custom resource. A server that does not publish
/// one leaves the typing absent, and every field still projects (§12.5, Gate B).
fn typing_of<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    resource: &Resource,
) -> Result<Typing, WireError> {
    let path = if resource.group().is_empty() {
        format!("/openapi/v3/api/{}", resource.version())
    } else {
        format!(
            "/openapi/v3/apis/{}/{}",
            resource.group(),
            resource.version()
        )
    };
    let document = optional_document(client, endpoint, &path)?;
    Ok(Typing::of(
        document.as_deref(),
        resource.group(),
        resource.version(),
        resource.kind(),
    ))
}

/// One group-version's resource list, as a snapshot of its own.
pub(crate) fn resource_list<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    group_version: &str,
) -> Result<Discovery, WireError> {
    let list = document(client, endpoint, &resource_list_path(group_version))?;
    Ok(Discovery::builder()
        .resources(&list)
        .map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the resource list of `{group_version}` did not read: {error}"),
                "The endpoint answered, but not as a Kubernetes API server.",
            )
        })?
        .build())
}

/// `group/version`, or the bare version for the core group (§13.3).
pub(crate) fn group_version_of(group: &str, version: &str) -> String {
    if group.is_empty() {
        version.to_owned()
    } else {
        format!("{group}/{version}")
    }
}

/// Where a group-version's resource list lives: `/api` for the core group, `/apis` for the rest.
pub(crate) fn resource_list_path(group_version: &str) -> String {
    if group_version.contains('/') {
        format!("/apis/{group_version}")
    } else {
        format!("/api/{group_version}")
    }
}

/// A selector that did not name exactly one served, listable resource.
pub(crate) fn unresolved_failure(
    unresolved: &Unresolved,
    selector: &Selector,
    discovery: &Discovery,
) -> WireError {
    match unresolved {
        Unresolved::Unasked => failure(
            AMBIGUOUS_CODE,
            AMBIGUOUS,
            "the query named no `kind` and no `resource`, so it did not say which of the \
             cluster's resources to read"
                .to_owned(),
            &format!(
                "Pass `kind` (or `resource`, which takes a plural or a short name), and `group` \
                 where two groups serve the same kind. This cluster serves:\n{}",
                dynamic::catalogue(discovery).join("\n")
            ),
        ),
        Unresolved::NotServed => failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "this cluster serves nothing matching {}",
                selector.spelling()
            ),
            "Discovery is authoritative, and an unserved resource is not an empty collection: \
             nothing was asked of the cluster, so nothing is known. A kind is spelled as the \
             server spells it, capital and all.",
        ),
        Unresolved::NotListable { gvr } => failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("the cluster serves `{gvr}` but does not offer `list` on it"),
            "A resource that cannot be listed is not an empty collection.",
        ),
        // A different permission on a different endpoint from `list`, and saying so is the
        // difference between an operator granting the right one and the wrong one (§60.5).
        Unresolved::NotGettable { gvr } => failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("the cluster serves `{gvr}` but does not offer `get` on one of them"),
            "A resource whose objects cannot be read one at a time is not an object that is not \
             there.",
        ),
        // §35.8: a name several types share must not resolve by an arbitrary type priority. The
        // candidates travel with the refusal, because "be more specific" that does not say what
        // the choices are leaves the operator worse off than before they asked.
        Unresolved::Ambiguous { candidates } => failure(
            AMBIGUOUS_CODE,
            AMBIGUOUS,
            format!(
                "{} matches {} resources this cluster serves, and this provider does not choose \
                 between them",
                selector.spelling(),
                candidates.len()
            ),
            &format!(
                "Name the group as well. The candidates are:\n{}",
                candidates.join("\n")
            ),
        ),
    }
}

/// Fetches one JSON document that is not a Kubernetes object — a discovery response.
///
/// Takes the endpoint because discovery is an authenticated request like any other: it goes
/// straight to the connection rather than through `Client`'s default headers, so the credential
/// has to be put on it here. A cluster that requires authentication for `/api` answers `401`
/// otherwise, which reads as "not a Kubernetes API server" and is not what happened.
pub(crate) fn document<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    path: &str,
) -> Result<String, WireError> {
    let request = endpoint.authorise(Request::get(path).header("Accept", "application/json"));
    let response = client
        .connection()
        .send(&request)
        .map_err(|error| transport_failure(path, &error))?;
    if response.status() != 200 {
        return Err(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!(
                "the API server answered `{path}` with {} {}",
                response.status(),
                response.reason()
            ),
            "Discovery is the first thing this provider asks for; a cluster that refuses it \
             cannot be read at all.",
        ));
    }
    String::from_utf8(response.body().to_vec()).map_err(|error| {
        failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("the API server's answer to `{path}` is not text: {error}"),
            "A discovery document is JSON.",
        )
    })
}

/// One JSON document the query can do without.
///
/// `Ok(None)` for anything but a `200`, because the caller's question is "does this server
/// publish it", and a `404` answers that. The connection failing is still an error: that is the
/// transport breaking underneath the request rather than the server declining to answer it, and
/// the difference decides whether the next request on the same connection can be made at all.
fn optional_document<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    path: &str,
) -> Result<Option<String>, WireError> {
    let request = endpoint.authorise(Request::get(path).header("Accept", "application/json"));
    let response = client
        .connection()
        .send(&request)
        .map_err(|error| transport_failure(path, &error))?;
    if response.status() != 200 {
        return Ok(None);
    }
    Ok(String::from_utf8(response.body().to_vec()).ok())
}

/// What the query was pointed at, how it proves who it is, and how much it asked about.
///
/// `Debug` is written by hand. The credential is the obvious reason (§8.1), and the TLS state is
/// the other: §8.4 requires an active insecure session to be visible in diagnostics, and a
/// rendering that has to be pattern-matched to find out is not visible.
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The name the server certificate is checked against — the host from the kubeconfig's
    /// `server`, which stays what the operator wrote even where a proxy resolves it elsewhere.
    pub(crate) server_name: String,
    pub(crate) authority: String,
    pub(crate) instance: String,
    pub(crate) scope: Scope,
    pub(crate) max_pages: Option<usize>,
    /// `None` is plain HTTP/1.1, which reaches an API server through `kubectl proxy` and nothing
    /// else. A `https://` server always carries settings.
    pub(crate) tls: Option<TlsSettings>,
    pub(crate) authorization: Option<Secret>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rendered = f.debug_struct("Endpoint");
        rendered
            .field("host", &self.host)
            .field("port", &self.port)
            .field("instance", &self.instance);
        match &self.tls {
            None => rendered.field("tls", &"none: plain HTTP/1.1"),
            Some(settings) if !settings.verifies_certificates() => {
                rendered.field("tls", &"insecure: certificate verification disabled")
            }
            Some(settings) => rendered.field("tls", settings),
        };
        rendered
            .field(
                "credential",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .finish()
    }
}

impl Endpoint {
    /// Works out which API server this query is about, and how it will talk to it.
    ///
    /// Three ways in, in this order: an explicit `host` (§7.3's explicit configuration, which
    /// automation and the test host use), a named `context` resolved through the kubeconfig
    /// (§7.4), or neither — which is refused rather than defaulted.
    pub(crate) fn resolve(ctx: &mut Ctx<'_>) -> Result<Self, WireError> {
        let options = ctx.arguments().clone();
        let context = options
            .get("context")
            .and_then(Json::as_str)
            .filter(|context| !context.is_empty())
            .map(str::to_owned);
        let host = options
            .get("host")
            .and_then(Json::as_str)
            .filter(|host| !host.is_empty())
            .map(str::to_owned);

        match (host, context) {
            (Some(host), context) => Self::explicit(&options, &host, context.as_deref()),
            (None, Some(context)) => Self::from_kubeconfig(ctx, &options, &context),
            (None, None) => Err(no_endpoint()),
        }
    }

    /// An endpoint the query named directly (§7.3).
    fn explicit(
        options: &JsonMap<String, Json>,
        host: &str,
        context: Option<&str>,
    ) -> Result<Self, WireError> {
        let port = options
            .get("port")
            .and_then(Json::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or(DEFAULT_PORT);
        // §6.2: a provider instance is `kubernetes:<context>`. An explicitly configured endpoint
        // may still be given the context name it stands for; without one, the endpoint is the
        // only name the operator has given this cluster, and a context name is not invented.
        let instance = context.map_or_else(
            || format!("kubernetes:{host}:{port}"),
            |context| format!("kubernetes:{context}"),
        );
        Ok(Self {
            host: host.to_owned(),
            port,
            server_name: host.to_owned(),
            authority: format!("{host}:{port}"),
            instance,
            scope: scope_of(options, None),
            max_pages: max_pages(options),
            // Deliberately no TLS on this path, and deliberately no option to ask for it: an
            // explicit host with no kubeconfig behind it has no trust anchors, and a session
            // against the platform store that the operator never chose would be a trust decision
            // taken here (§8.4).
            tls: None,
            authorization: None,
        })
    }

    /// An endpoint resolved from a kubeconfig context (§7.1, §7.4, §8).
    fn from_kubeconfig(
        ctx: &mut Ctx<'_>,
        options: &JsonMap<String, Json>,
        context: &str,
    ) -> Result<Self, WireError> {
        let path = options
            .get("kubeconfig")
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
            .unwrap_or(DEFAULT_KUBECONFIG)
            .to_owned();
        let document = read_file(ctx, &path, "the kubeconfig")?;
        let text = String::from_utf8(document).map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("`{path}` is not text: {error}"),
                "A kubeconfig is YAML.",
            )
        })?;
        let config = Kubeconfig::parse(&text).map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("`{path}` did not read: {error}"),
                "The file was read; what is in it is not a kubeconfig this provider understands.",
            )
        })?;
        let connection = config.connection(context).map_err(|error| {
            let known: Vec<&str> = config.contexts().collect();
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("{error}"),
                &format!(
                    "`{path}` defines these contexts: {}. Naming one that is not there is a \
                     different answer from connecting to the wrong one.",
                    if known.is_empty() {
                        "none".to_owned()
                    } else {
                        known.join(", ")
                    }
                ),
            )
        })?;

        let (secure, host, port) = parse_server(connection.server()).map_err(|detail| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!(
                    "context `{context}` names the server `{}`, which this provider cannot use: \
                     {detail}",
                    connection.server()
                ),
                "The `server` of a kubeconfig cluster is an `http://` or `https://` URL naming a \
                 host and optionally a port.",
            )
        })?;

        let identity = client_identity(ctx, &connection, context)?;
        let tls = if secure {
            Some(tls_settings(ctx, &connection, identity.as_ref(), context)?)
        } else {
            // A context whose server is `http://` asked for no TLS at all, so there is nothing
            // to verify and nothing to disable; §8.4 is about a TLS session's validation and not
            // about inventing one.
            None
        };
        let authorization = bearer_token(&connection, context)?;

        Ok(Self {
            authority: authority_of(&host, port, secure),
            server_name: host.clone(),
            host,
            port,
            instance: connection.instance_id(),
            // §7.5: the context's namespace is a starting point, and a namespace named in the
            // query beats it because it is the more recent deliberate choice.
            scope: scope_of(options, connection.namespace()),
            max_pages: max_pages(options),
            tls,
            authorization,
        })
    }

    /// A client over `stream`, carrying whatever credential the context resolved to.
    pub(crate) fn client<S: ByteStream>(&self, stream: S) -> Client<S> {
        let client = Client::new(stream, self.authority.clone(), self.instance.clone());
        match &self.authorization {
            None => client,
            Some(token) => {
                client.with_default_header("Authorization", format!("Bearer {}", token.expose()))
            }
        }
    }

    /// The same request, carrying the credential (§8.1: built at the call site, never stored on
    /// something that renders).
    pub(crate) fn authorise(&self, request: Request) -> Request {
        match &self.authorization {
            None => request,
            Some(token) => request.header("Authorization", format!("Bearer {}", token.expose())),
        }
    }
}

/// What goes in the `Host` header: the port is written only where it is not the scheme's own.
fn authority_of(host: &str, port: u16, secure: bool) -> String {
    let default = if secure { 443 } else { 80 };
    if port == default {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}

/// What the query asked about, with the context's namespace as the starting point (§9.4, §7.5).
fn scope_of(options: &JsonMap<String, Json>, context_namespace: Option<&str>) -> Scope {
    match options.get("namespace").and_then(Json::as_str) {
        Some(namespace) => Scope::in_namespace(namespace),
        None if options.get("all_namespaces").and_then(Json::as_bool) == Some(true) => {
            Scope::all_namespaces()
        }
        None => Scope::in_namespace(context_namespace.unwrap_or("default")),
    }
}

/// A page budget, where the query set one.
fn max_pages(options: &JsonMap<String, Json>) -> Option<usize> {
    options
        .get("max_pages")
        .and_then(Json::as_u64)
        .and_then(|pages| usize::try_from(pages).ok())
        .filter(|pages| *pages > 0)
}

/// The bearer token a context carries, and a refusal for a credential this build cannot produce.
fn bearer_token(
    connection: &ono_provider_kubernetes::kubeconfig::Connection,
    context: &str,
) -> Result<Option<Secret>, WireError> {
    match connection.credential() {
        Credential::BearerToken => Ok(connection.material().cloned()),
        // §8.2: an exec credential plugin runs only under an explicit process-execution
        // capability, and the host must honour the `Never` / `IfAvailable` / `Always` interaction
        // modes. This package declares no such capability and implements none of those modes, so
        // it refuses rather than connecting as somebody else: a wrong identity is worse than a
        // refused one, and an anonymous request to a cluster that expected `alice` fails in a way
        // that reads as a permission problem.
        Credential::ExecPlugin => Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "context `{context}` authenticates through an `exec` credential plugin, which \
                 this provider does not run"
            ),
            "§8.2 requires an explicit process-execution capability and the `Never`, \
             `IfAvailable` and `Always` interaction modes; this package declares neither. Use a \
             context with a token or a client certificate, or obtain a token another way.",
        )),
        Credential::ClientCertificate | Credential::Anonymous => Ok(None),
    }
}

/// The client certificate a context presents, read where the kubeconfig names a file.
fn client_identity(
    ctx: &mut Ctx<'_>,
    connection: &ono_provider_kubernetes::kubeconfig::Connection,
    context: &str,
) -> Result<Option<ClientIdentity>, WireError> {
    if let Some((certificate, key)) = connection.client_certificate() {
        return ClientIdentity::new(certificate, key)
            .map(Some)
            .map_err(|error| tls_configuration_failure(context, &error));
    }
    let files = connection.client_certificate_files();
    let [certificate_path, key_path] = files.as_slice() else {
        if files.is_empty() {
            return Ok(None);
        }
        return Err(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("context `{context}` names one half of a client certificate and not the other"),
            "A client certificate is a certificate *and* its key; half of one cannot open a \
             session.",
        ));
    };
    let certificate = read_file(ctx, certificate_path, "the client certificate")?;
    let key = read_file(ctx, key_path, "the client key")?;
    ClientIdentity::new(
        &certificate,
        &Secret::new(String::from_utf8_lossy(&key).into_owned()),
    )
    .map(Some)
    .map_err(|error| tls_configuration_failure(context, &error))
}

/// What the session will verify the API server against (§8.4).
///
/// The one place in this package where certificate verification can be off, and it is reached
/// only from [`Trust::Insecure`], which is only reached from `insecure-skip-tls-verify: true` in
/// a kubeconfig. Every other trust setting produces anchors, and a certificate authority that
/// does not read is a refusal rather than a quiet fall back to the platform store.
fn tls_settings(
    ctx: &mut Ctx<'_>,
    connection: &ono_provider_kubernetes::kubeconfig::Connection,
    identity: Option<&ClientIdentity>,
    context: &str,
) -> Result<TlsSettings, WireError> {
    let anchors = match connection.trust() {
        Trust::Insecure => {
            return TlsSettings::without_certificate_verification(identity)
                .map_err(|error| tls_configuration_failure(context, &error));
        }
        // The one read this module does that the TLS layer refuses to do for itself: a path is
        // read here, under the host's capability, and the bytes are what get pinned.
        Trust::CertificateAuthorityFile(path) => {
            let pem = read_file(ctx, path, "the certificate authority")?;
            Anchors::pinned(&pem)
        }
        trust => Anchors::for_trust(trust),
    }
    .map_err(|error| tls_configuration_failure(context, &error))?;
    TlsSettings::verifying(&anchors, identity)
        .map_err(|error| tls_configuration_failure(context, &error))
}

/// Splits a kubeconfig `server` URL into whether it is TLS, its host and its port.
fn parse_server(server: &str) -> Result<(bool, String, u16), String> {
    let (scheme, rest) = server
        .split_once("://")
        .ok_or_else(|| "it names no scheme".to_owned())?;
    let secure = match scheme {
        "https" => true,
        "http" => false,
        other => return Err(format!("`{other}` is not a scheme this provider speaks")),
    };
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    if !path.is_empty() {
        // Dropping the prefix would send every request to a path the operator did not name, and
        // the answers would look like a different cluster's rather than like an error.
        return Err(format!(
            "it names the path prefix `/{path}`, and this provider does not yet prepend one to \
             its requests"
        ));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // An IPv6 literal: `[::1]:6443`.
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "its IPv6 literal is not closed".to_owned())?;
        (host.to_owned(), tail.strip_prefix(':').map(str::to_owned))
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port.to_owned())),
            None => (authority.to_owned(), None),
        }
    };
    if host.is_empty() {
        return Err("it names no host".to_owned());
    }
    let port = match port {
        None => {
            if secure {
                443
            } else {
                80
            }
        }
        Some(port) => port
            .parse()
            .map_err(|_| format!("`{port}` is not a port number"))?,
    };
    Ok((secure, host, port))
}

/// Reads one file through the host, in chunks, under the `filesystem.read` capability.
///
/// `what` names the file's role, so a denial says which read was refused rather than only which
/// path. §27.3 of the generic provider contract is why this goes through the broker at all: the
/// package declares the paths it needs and the operator grants them, and a package that opened
/// the file itself would be making that decision on its own.
fn read_file(ctx: &mut Ctx<'_>, path: &str, what: &str) -> Result<Vec<u8>, WireError> {
    let path = expand_home(path)?;
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let answer = ctx
            .host_call(
                method::FILESYSTEM_READ,
                json!({"path": path, "offset": bytes.len(), "length": READ_CHUNK}),
            )
            .map_err(|error| file_failure(&path, what, &error))?;
        let hex = answer
            .get("content")
            .and_then(|content| content.get("$bytes"))
            .and_then(Json::as_str)
            .unwrap_or_default();
        let chunk = decode_hex(hex).ok_or_else(|| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the host answered `filesystem.read` for `{path}` with bytes that are not hexadecimal"),
                "This is a protocol failure between the package and its host.",
            )
        })?;
        let complete = u64::try_from(chunk.len()).unwrap_or(READ_CHUNK) < READ_CHUNK;
        bytes.extend_from_slice(&chunk);
        if complete {
            return Ok(bytes);
        }
        if bytes.len() > MAX_KUBECONFIG {
            return Err(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("`{path}` is larger than {MAX_KUBECONFIG} bytes, which {what} is not"),
                "The path was read; what is at it is not the file this provider expected.",
            ));
        }
    }
}

/// Resolves a leading `~/`, which the host does not.
///
/// The host checks the *resolved* path against the granted scope, so an unexpanded `~` would be
/// checked as a literal directory name and denied for a reason that has nothing to do with the
/// operator's decision.
fn expand_home(path: &str) -> Result<String, WireError> {
    let Some(rest) = path.strip_prefix("~/") else {
        return Ok(path.to_owned());
    };
    let home = std::env::var("HOME").map_err(|_| {
        failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("`{path}` starts at a home directory, and `HOME` is not set"),
            "Pass `kubeconfig` with an absolute path.",
        )
    })?;
    Ok(format!("{}/{rest}", home.trim_end_matches('/')))
}

/// A file the host would not or could not read.
fn file_failure(path: &str, what: &str, error: &WireError) -> WireError {
    if error.name == "capability.denied" {
        // Distinct from "no such context" on purpose: one is an operator's capability decision
        // and the other is a name that is not in the file, and the corrections have nothing in
        // common (§21.4 applied to configuration).
        return failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!(
                "the host refused to read {what} at `{path}`: {}",
                error.message
            ),
            "This package declares `filesystem.read` as an optional capability scoped to \
             `~/.kube/config` and `~/.kube/*.yaml`. Grant it for this path, or pass `host` to \
             name an API server without a kubeconfig.",
        );
    }
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!("{what} at `{path}` could not be read: {}", error.message),
        "The capability allowed the read; the file itself did not answer.",
    )
}

/// A TLS configuration this package will not build.
fn tls_configuration_failure(context: &str, error: &TlsError) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!("context `{context}` cannot open a TLS session: {error}"),
        "§8.4 puts certificate validation in this package, so a trust setting that cannot be \
         used is a refusal rather than a session with less checking than the kubeconfig asked \
         for.",
    )
}

/// The handshake itself failed.
pub(crate) fn handshake_failure(endpoint: &Endpoint, error: &TlsError) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "the TLS session with `{}:{}` was not established: {error}",
            endpoint.host, endpoint.port
        ),
        "The bytes reached the endpoint and the certificate it presented was not one this \
         context trusts. A cluster with a private certificate authority names it in its \
         kubeconfig as `certificate-authority-data`.",
    )
}

/// No endpoint was named, and this package will not invent one.
fn no_endpoint() -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        "the query named neither a kubeconfig `context` nor a `host`, and this provider does not \
         guess an API server"
            .to_owned(),
        "Pass `context` to resolve a cluster through `~/.kube/config` — its server, its default \
         namespace and its trust anchors come from there — or pass `host` (and `port`, which \
         defaults to 8001) to name an endpoint directly, which speaks plain HTTP/1.1 and so \
         reaches an API server through `kubectl proxy` rather than over TLS.",
    )
}

/// The connection or the protocol failed underneath a request.
pub(crate) fn transport_failure(path: &str, error: &ApiError) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!("`{path}` could not be read: {error}"),
        "The bytes travel through the host's broker; a refusal there is a capability decision, \
         and a protocol error here usually means the endpoint speaks TLS while this build \
         speaks plain HTTP/1.1.",
    )
}

/// One structured error, in the vocabulary of core's `docs/contracts/errors.yaml`.
pub(crate) fn failure(code: &str, name: &str, message: String, help: &str) -> WireError {
    WireError {
        code: code.to_owned(),
        name: name.to_owned(),
        message,
        help: Some(help.to_owned()),
        metadata: Box::default(),
    }
}

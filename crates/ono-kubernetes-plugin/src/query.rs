//! Answering one `provider.query`: from the target word to a stream of records.
//!
//! The shape of an answer is fixed by three things the specification does not leave open.
//!
//! **Discovery decides which collection is read.** The target table names a group and a kind —
//! GVK identity — and nothing more. Which resource serves that kind, at which version, and
//! whether it is namespaced is asked of the API server every time (§4 invariants 1–2, §5.2,
//! §13.1). A hard-coded `/api/v1/pods` would be a compile-time claim about a cluster this code
//! has never seen, and it is exactly the claim §33.1 forbids for custom resources.
//!
//! **Every object crosses the boundary as a [`Guarded`].** There is no path from a listing to an
//! emission that does not go through the redaction guard, so a Secret's payload is destroyed
//! before anything can render, log or navigate it (§22, Gate I).
//!
//! **An incomplete answer never renders as a whole one.** A `403`, an expired continue token and
//! a page budget are three different reasons for a short list, and none of them is "there are no
//! more" (§4 invariant 13, §21.4). The values already read are emitted — they are true — and the
//! invocation then *fails* with what was missing, because the value stream of a contributed
//! target carries records of one schema and has nowhere to put a coverage report.

use std::sync::Arc;

use ono_kuang_sdk::protocol::{WireError, method};
use ono_kuang_sdk::{Ctx, EmitError, Outcome};
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::{self, Discovery, Verb};
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::transport::{
    ApiError, ByteStream, Client, ListOptions, Listing, Request,
};
use ono_value::Schema;
use serde_json::{Value as Json, json};

use crate::broker::BrokeredStream;
use crate::contributions::Target;
use crate::records::record;

/// `provider.unavailable`, as core's `docs/contracts/errors.yaml` publishes it.
///
/// Spelled out rather than taken from `ono_core::ErrorCode`, which a package does not depend on.
/// The KUANG taxonomy has no code for "this provider could not reach the system it fronts", and
/// inventing one would put a code on the wire that no registry explains.
const UNAVAILABLE_CODE: &str = "Ono-Sendai-E0401";
/// The dotted name of [`UNAVAILABLE_CODE`].
const UNAVAILABLE: &str = "provider.unavailable";
/// `provider.unsupported`, for a cluster that serves no such thing.
const UNSUPPORTED_CODE: &str = "Ono-Sendai-E0402";
/// The dotted name of [`UNSUPPORTED_CODE`].
const UNSUPPORTED: &str = "provider.unsupported";

/// The port `kubectl proxy` listens on unless told otherwise.
///
/// A default with a source rather than a guess. There is deliberately no default *host*: an
/// endpoint this package invented would be a cluster the operator never named.
const DEFAULT_PORT: u16 = 8001;

/// How many objects one page asks the API server for.
const PAGE_SIZE: u32 = 500;

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
    let endpoint = match Endpoint::read(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
    };
    if ctx.cancelled() {
        return Outcome::Cancelled;
    }

    // The brokered connection borrows the context for as long as it lives, so the whole
    // conversation with the API server happens inside this block and only its result escapes.
    let (listing, handle, open) = {
        let stream = match BrokeredStream::connect(ctx, &endpoint.host, endpoint.port) {
            Ok(stream) => stream,
            Err(error) => return Outcome::Failed(error),
        };
        let handle = stream.handle();
        let mut client = Client::new(stream, endpoint.authority(), endpoint.instance.clone());
        let listing = read(&mut client, target, &endpoint);
        let stream = client.into_stream();
        (listing, handle, stream.is_open())
    };
    if open {
        // Only while the host still holds it: `network.close` on a handle the host has already
        // retired is a protocol violation, and the host retires one the moment the peer closes.
        let _ = ctx.host_call(method::NETWORK_CLOSE, json!({"connection": handle}));
    }

    let listing = match listing {
        Ok(listing) => listing,
        Err(error) => return Outcome::Failed(error),
    };
    emit(ctx, target, &schema, listing)
}

/// Streams the listing's objects, then reports whatever the listing could not see.
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    listing: Listing,
) -> Outcome {
    let coverage = listing.coverage().describe();
    let complete = listing.coverage().is_complete() && listing.continuity().is_intact();
    let broken = !listing.continuity().is_intact();
    for object in listing.into_objects() {
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
        let value = match record(target, schema, &guarded) {
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

/// Discovers what serves the target's kind, then lists it.
fn read<S: ByteStream>(
    client: &mut Client<S>,
    target: &'static Target,
    endpoint: &Endpoint,
) -> Result<Listing, WireError> {
    let core = document(client, "/api")?;
    let groups = document(client, "/apis")?;
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
    let version = served.preferred_version(target.group).ok_or_else(|| {
        failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "this cluster serves no version of the API group `{}`, so it serves no {}",
                if target.group.is_empty() {
                    "core"
                } else {
                    target.group
                },
                target.kind
            ),
            "An unserved API is not an empty result: nothing was asked, so nothing is known.",
        )
    })?;
    let group_version = if target.group.is_empty() {
        version.to_owned()
    } else {
        format!("{}/{version}", target.group)
    };
    let resources = document(
        client,
        &if target.group.is_empty() {
            format!("/api/{version}")
        } else {
            format!("/apis/{group_version}")
        },
    )?;
    let discovery = Discovery::builder()
        .resources(&resources)
        .map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the resource list of `{group_version}` did not read: {error}"),
                "The endpoint answered, but not as a Kubernetes API server.",
            )
        })?
        .build();

    let resource = discovery
        .by_kind(&group_version, target.kind)
        .ok_or_else(|| {
            failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!(
                    "`{group_version}` serves no kind `{}` on this cluster",
                    target.kind
                ),
                "Discovery is authoritative: this build makes no assumption about which APIs a \
                 cluster serves.",
            )
        })?;
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

    // §9.2: a cluster-scoped resource has no namespace, and inventing one for it would be a
    // request the server rejects for a reason that has nothing to do with what was asked.
    let scope = match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => endpoint.scope.clone(),
    };
    let mut options = ListOptions::new().limit(PAGE_SIZE);
    if let Some(pages) = endpoint.max_pages {
        options = options.max_pages(pages);
    }
    Ok(client.list(resource.gvr(), &scope, &options))
}

/// Fetches one JSON document that is not a Kubernetes object — a discovery response.
fn document<S: ByteStream>(client: &mut Client<S>, path: &str) -> Result<String, WireError> {
    let request = Request::get(path).header("Accept", "application/json");
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

/// What the query was pointed at, and how much of the cluster it asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    host: String,
    port: u16,
    instance: String,
    scope: Scope,
    max_pages: Option<usize>,
}

impl Endpoint {
    /// Reads the endpoint out of the query's options.
    fn read(ctx: &Ctx<'_>) -> Result<Self, WireError> {
        let options = ctx.arguments();
        let host = options
            .get("host")
            .and_then(Json::as_str)
            .filter(|host| !host.is_empty())
            .ok_or_else(no_endpoint)?
            .to_owned();
        let port = options
            .get("port")
            .and_then(Json::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or(DEFAULT_PORT);
        // §6.2: a provider instance is `kubernetes:<context>`. Until the kubeconfig is read, the
        // endpoint is the only name the operator has given this cluster, so it is the one used —
        // never a fabricated context name that no kubeconfig would recognise.
        let instance = options.get("context").and_then(Json::as_str).map_or_else(
            || format!("kubernetes:{host}:{port}"),
            |context| format!("kubernetes:{context}"),
        );
        // §9.4: every namespace is a deliberate request, never the default that a missing
        // namespace quietly becomes.
        let scope = match options.get("namespace").and_then(Json::as_str) {
            Some(namespace) => Scope::in_namespace(namespace),
            None if options.get("all_namespaces").and_then(Json::as_bool) == Some(true) => {
                Scope::all_namespaces()
            }
            None => Scope::in_namespace("default"),
        };
        let max_pages = options
            .get("max_pages")
            .and_then(Json::as_u64)
            .and_then(|pages| usize::try_from(pages).ok())
            .filter(|pages| *pages > 0);
        Ok(Self {
            host,
            port,
            instance,
            scope,
            max_pages,
        })
    }

    /// What goes in the `Host` header.
    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// No endpoint was named, and this package will not invent one.
fn no_endpoint() -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        "the query named no API server, and this provider does not guess one".to_owned(),
        "Pass `host` (and `port`, which defaults to 8001) in the query's options. Reading the \
         endpoint from `~/.kube/config` is not wired yet, and neither is TLS: the connection is \
         HTTP/1.1 straight over the host's brokered bytes, which reaches an API server through \
         `kubectl proxy` and not one over HTTPS.",
    )
}

/// The connection or the protocol failed underneath a request.
fn transport_failure(path: &str, error: &ApiError) -> WireError {
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
fn failure(code: &str, name: &str, message: String, help: &str) -> WireError {
    WireError {
        code: code.to_owned(),
        name: name.to_owned(),
        message,
        help: Some(help.to_owned()),
        metadata: Box::default(),
    }
}

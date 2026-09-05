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

use std::fmt;
use std::sync::Arc;

use ono_kuang_sdk::protocol::{WireError, method};
use ono_kuang_sdk::{Ctx, EmitError, Outcome};
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::{self, Discovery, Verb};
use ono_provider_kubernetes::kubeconfig::{Credential, Kubeconfig, Secret, Trust};
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::tls::{Anchors, ClientIdentity, TlsError, TlsSettings, TlsStream};
use ono_provider_kubernetes::transport::{
    ApiError, ByteStream, Client, ListOptions, Listing, Request,
};
use ono_value::Schema;
use serde_json::{Map as JsonMap, Value as Json, json};

use crate::broker::{BrokeredStream, decode_hex};
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
    let endpoint = match Endpoint::resolve(ctx) {
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
        match &endpoint.tls {
            // Plain HTTP/1.1 over the brokered bytes: what an API server reached through
            // `kubectl proxy` speaks, and never what one reached directly does.
            None => {
                let mut client = endpoint.client(stream);
                let listing = read(&mut client, target, &endpoint);
                let open = client.into_stream().is_open();
                (listing, handle, open)
            }
            Some(settings) => match TlsStream::connect(stream, &endpoint.server_name, settings) {
                Ok(session) => {
                    let mut client = endpoint.client(session);
                    let listing = read(&mut client, target, &endpoint);
                    let open = client.into_stream().into_inner().is_open();
                    (listing, handle, open)
                }
                // The handshake consumed the stream, so whether the host still holds the
                // connection cannot be asked here. Not closing leaks a handle until the
                // invocation ends; closing one the host has already retired is a protocol
                // violation that quarantines the package, and that is the worse of the two.
                Err(error) => (Err(handshake_failure(&endpoint, &error)), handle, false),
            },
        }
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
        endpoint,
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
///
/// Takes the endpoint because discovery is an authenticated request like any other: it goes
/// straight to the connection rather than through `Client`'s default headers, so the credential
/// has to be put on it here. A cluster that requires authentication for `/api` answers `401`
/// otherwise, which reads as "not a Kubernetes API server" and is not what happened.
fn document<S: ByteStream>(
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

/// What the query was pointed at, how it proves who it is, and how much it asked about.
///
/// `Debug` is written by hand. The credential is the obvious reason (§8.1), and the TLS state is
/// the other: §8.4 requires an active insecure session to be visible in diagnostics, and a
/// rendering that has to be pattern-matched to find out is not visible.
struct Endpoint {
    host: String,
    port: u16,
    /// The name the server certificate is checked against — the host from the kubeconfig's
    /// `server`, which stays what the operator wrote even where a proxy resolves it elsewhere.
    server_name: String,
    authority: String,
    instance: String,
    scope: Scope,
    max_pages: Option<usize>,
    /// `None` is plain HTTP/1.1, which reaches an API server through `kubectl proxy` and nothing
    /// else. A `https://` server always carries settings.
    tls: Option<TlsSettings>,
    authorization: Option<Secret>,
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
    fn resolve(ctx: &mut Ctx<'_>) -> Result<Self, WireError> {
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
    fn client<S: ByteStream>(&self, stream: S) -> Client<S> {
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
    fn authorise(&self, request: Request) -> Request {
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
fn handshake_failure(endpoint: &Endpoint, error: &TlsError) -> WireError {
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

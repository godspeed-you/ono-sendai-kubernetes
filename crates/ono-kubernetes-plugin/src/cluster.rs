//! Answering `k8s-cluster`: which cluster is this, can it be reached, who am I to it, and what
//! could I not determine.
//!
//! The last requirement of §61.1, and the one target of this package that reads no Kubernetes
//! object. Three things make it different from every other answer here, and each of them is a
//! rule rather than a convenience.
//!
//! **Nothing it fails to learn is an error.** §8.6 says failure to obtain the effective identity
//! MUST NOT block ordinary read operations, and the same holds for every other signal: a cluster
//! that refuses `SelfSubjectReview`, hides `kube-system` and serves no `/version` still gets a
//! record — a record that says, field by field, what it could not determine and why. The only
//! failure this target reports is a query that named no API server and a capability the operator
//! did not grant, because neither of those is an observation about a cluster.
//!
//! **A cluster that does not answer is an answer.** An unreachable API server produces
//! `reachable: false` with the reason among the unknowns, rather than a failed invocation. That
//! is the whole point of a health diagnostic: `ono get k8s-cluster` has to work precisely when
//! the cluster does not.
//!
//! **Unknown is null and never a default.** An empty list is not "no groups"; a missing
//! `kube-system` UID is not the empty string. A field the cluster *refused* is distinguishable
//! from one it does not have, because the reason travels beside the value in `unknowns` in the
//! vocabulary of §21.4 rather than in words invented here.

use std::sync::Arc;
use std::time::Instant;

use ono_kuang_sdk::protocol::{WireError, method};
use ono_kuang_sdk::{Ctx, EmitError, Outcome as InvocationOutcome};
use ono_provider_kubernetes::coverage::{Outcome, Scope};
use ono_provider_kubernetes::diagnostics::{
    ClusterDiagnostic, Fingerprint, Health, Identity, Impersonation, Known, Probe, ProbeStatus,
    ServerVersion, Signal, Subject, TlsPosture, normalised_origin,
};
use ono_provider_kubernetes::discovery::{Discovery, Verb};
use ono_provider_kubernetes::tls::TlsStream;
use ono_provider_kubernetes::transport::{
    ByteStream, Client, Method, Request, collection_path, object_path,
};
use ono_value::{ErrorValue, MapValue, Provenance, RecordValue, Schema, Value};
use serde_json::json;

use crate::broker::BrokeredStream;
use crate::contributions::Target;
use crate::query::{Endpoint, UNAVAILABLE, UNAVAILABLE_CODE, failure};

/// The group that serves `SelfSubjectReview` (§8.6).
///
/// A name, not a path. Whether this cluster serves the group, at which version, and whether the
/// resource under it accepts `create` is asked of discovery every time — an API server that does
/// not serve it is a stated unknown, never a `404` this build walked into (§11.1).
const AUTHENTICATION_GROUP: &str = "authentication.k8s.io";

/// The namespace whose UID §10.2 offers as cluster evidence.
const KUBE_SYSTEM: &str = "kube-system";

/// Answers the cluster diagnostic for one provider instance.
#[must_use]
pub fn answer(target: &'static Target, ctx: &mut Ctx<'_>) -> InvocationOutcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return InvocationOutcome::Failed(error.into()),
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    if ctx.cancelled() {
        return InvocationOutcome::Cancelled;
    }

    let diagnostic = match observe(ctx, &endpoint) {
        Ok(diagnostic) => diagnostic,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    let value = match record(target, &schema, &diagnostic) {
        Ok(value) => value,
        Err(error) => {
            return InvocationOutcome::Failed(failure(
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
        Ok(()) => InvocationOutcome::Completed,
        Err(EmitError::Cancelled) => InvocationOutcome::Cancelled,
        Err(error) => InvocationOutcome::Failed(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("the host refused the diagnostic: {error}"),
            "The stream ended before the query did.",
        )),
    }
}

/// Opens the connection and asks the cluster about itself.
///
/// The `Err` is reserved for what is not an observation about a cluster: a capability the
/// operator did not grant. Everything else — a refused connection, a failed handshake, a server
/// that answers nothing — becomes a diagnostic that says so, because "it cannot be reached" is
/// the answer this target exists to give.
fn observe(ctx: &mut Ctx<'_>, endpoint: &Endpoint) -> Result<ClusterDiagnostic, WireError> {
    let posture = posture(endpoint);
    let (health, fingerprint, identity, handle, open) = {
        let stream = match BrokeredStream::connect(ctx, &endpoint.host, endpoint.port) {
            Ok(stream) => stream,
            Err(error) if error.name == "capability.denied" => return Err(error),
            Err(error) => {
                return Ok(unreachable(
                    endpoint,
                    posture,
                    format!("connect {}:{}", endpoint.host, endpoint.port),
                    &error.message,
                ));
            }
        };
        let handle = stream.handle();
        match &endpoint.tls {
            None => {
                let mut client = endpoint.client(stream);
                let observed = interrogate(&mut client, endpoint);
                let open = client.into_stream().is_open();
                (observed.0, observed.1, observed.2, handle, open)
            }
            Some(settings) => match TlsStream::connect(stream, &endpoint.server_name, settings) {
                Ok(session) => {
                    let mut client = endpoint.client(session);
                    let observed = interrogate(&mut client, endpoint);
                    let open = client.into_stream().into_inner().is_open();
                    (observed.0, observed.1, observed.2, handle, open)
                }
                // The same trade `query::answer` records: the handshake consumed the stream, so
                // whether the host still holds the connection cannot be asked, and closing one it
                // has already retired is the worse of the two mistakes.
                Err(error) => {
                    return Ok(unreachable(
                        endpoint,
                        posture,
                        "TLS handshake".to_owned(),
                        &error.to_string(),
                    ));
                }
            },
        }
    };
    if open {
        let _ = ctx.host_call(method::NETWORK_CLOSE, json!({"connection": handle}));
    }
    Ok(
        ClusterDiagnostic::for_instance(endpoint.instance.clone(), posture)
            .with_fingerprint(fingerprint)
            .with_identity(identity)
            .with_health(health),
    )
}

/// The diagnostic of a cluster that could not be reached at all.
///
/// Everything the cluster would have answered is `disconnected` rather than absent: §21.4 keeps
/// "I could not ask" apart from "there is none", and a health diagnostic is the last place that
/// distinction should be dropped.
fn unreachable(
    endpoint: &Endpoint,
    posture: TlsPosture,
    source: String,
    detail: &str,
) -> ClusterDiagnostic {
    let mut health = Health::unknown().with_version(Known::Unavailable(Outcome::Disconnected));
    health.record(Probe::new(
        format!("{source}: {detail}"),
        ProbeStatus::DidNotAnswer(Outcome::Disconnected),
        None,
    ));
    ClusterDiagnostic::for_instance(endpoint.instance.clone(), posture)
        .with_fingerprint(
            // The origin is configuration rather than an observation, so it survives a cluster
            // that never answered — a fingerprint of one weak signal, which is what §10.2 means
            // by composing whatever was obtainable.
            fingerprint_of(endpoint)
                .with_kube_system_uid(Known::Unavailable(Outcome::Disconnected)),
        )
        .with_identity(
            Identity::unknown()
                .with_credential(Known::Unavailable(Outcome::Disconnected))
                .with_effective(Known::Unavailable(Outcome::Disconnected)),
        )
        .with_health(health)
}

/// What protects this session, in the words §8.4 requires a diagnostic to use.
fn posture(endpoint: &Endpoint) -> TlsPosture {
    match &endpoint.tls {
        None => TlsPosture::None,
        Some(settings) if !settings.verifies_certificates() => TlsPosture::InsecureSkipVerify,
        Some(_) => TlsPosture::Verified,
    }
}

/// The fingerprint before any request: the origin, and the signals nothing has asked for yet.
///
/// The server's public key is `not queried` rather than absent. This build's TLS session does not
/// surrender the certificate it verified, so the provider never has the bytes to hash — and a
/// signal nobody asked for is a different state from one the cluster refused (§21.4, §10.2).
fn fingerprint_of(endpoint: &Endpoint) -> Fingerprint {
    let scheme = if endpoint.tls.is_some() {
        "https"
    } else {
        "http"
    };
    Fingerprint::unknown()
        .with_origin(Known::Obtained(normalised_origin(
            scheme,
            &endpoint.server_name,
            endpoint.port,
        )))
        .with_server_public_key(Known::Unavailable(Outcome::NotQueried))
}

/// Asks the cluster everything this diagnostic reports, over an open connection.
///
/// Each question is independent: one that fails records why and the next one is still asked. A
/// diagnostic that stopped at the first refusal would report the least interesting cluster —
/// a restricted one — as having told it nothing at all.
fn interrogate<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
) -> (Health, Fingerprint, Identity) {
    let mut health = Health::unknown();
    let mut fingerprint = fingerprint_of(endpoint);

    let version = match ask(client, endpoint, &mut health, Request::get("/version")) {
        Answer::Body(body) => ServerVersion::parse(&body)
            .map_or(Known::Unavailable(Outcome::RequestFailed), Known::Obtained),
        Answer::Refused(code) => Known::Unavailable(refusal(code)),
        Answer::Unreachable => Known::Unavailable(Outcome::Disconnected),
    };
    health = health.with_version(version);

    let served = discover(client, endpoint, &mut health);
    fingerprint = fingerprint.with_kube_system_uid(kube_system_uid(
        client,
        endpoint,
        &mut health,
        served.as_ref(),
    ));
    let effective = effective_identity(client, endpoint, &mut health, served.as_ref());
    let identity = Identity::unknown()
        // With no impersonation configured, one review answers both questions and the two fields
        // carry the same subject. §8.5's requirement is that they be impossible to *confuse*, and
        // two fields that happen to agree cannot be misread the day one of them stops agreeing —
        // a single field would silently change meaning instead.
        .with_credential(effective.clone())
        .with_effective(effective)
        .with_impersonation(Impersonation::Inactive);
    (health, fingerprint, identity)
}

/// What the cluster's discovery documents said about itself.
///
/// Two [`Discovery`] values because they answer two different questions and are built from two
/// different documents: `versions` knows which groups and versions exist, `core` knows which
/// collections the core group serves. Merging them would mean fetching a resource list before
/// knowing which version to fetch it for.
struct Served {
    versions: Discovery,
    core: Discovery,
    core_version: String,
}

/// Reads `/api`, `/apis` and the core resource list, recording each as its own probe (§34.3).
///
/// `None` when the discovery documents did not read, in which case everything that depends on
/// them reports why rather than guessing a path (§11.1).
fn discover<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    health: &mut Health,
) -> Option<Served> {
    let core = text(ask(client, endpoint, health, Request::get("/api")))?;
    let groups = text(ask(client, endpoint, health, Request::get("/apis")))?;
    let versions = Discovery::builder()
        .core_versions(&core)
        .and_then(|builder| builder.groups(&groups))
        .ok()?
        .build();
    // Which version of the core group is preferred is the server's answer, not this build's
    // (§5.2). A cluster that serves none of it serves no Namespace either.
    let core_version = versions.preferred_version("")?.to_owned();
    let resources = text(ask(
        client,
        endpoint,
        health,
        Request::get(format!("/api/{core_version}")),
    ))?;
    Some(Served {
        versions,
        core: Discovery::builder().resources(&resources).ok()?.build(),
        core_version,
    })
}

/// The `kube-system` namespace UID, where discovery names the collection and RBAC allows the read.
fn kube_system_uid<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    health: &mut Health,
    served: Option<&Served>,
) -> Known<String> {
    let Some(served) = served else {
        return Known::Unavailable(Outcome::Disconnected);
    };
    let Some(resource) = served.core.by_kind(&served.core_version, "Namespace") else {
        return Known::Unavailable(Outcome::TypeNotServed);
    };
    if !resource.supports(Verb::Get) {
        return Known::Unavailable(Outcome::TypeNotServed);
    }
    let path = object_path(resource.gvr(), &Scope::cluster(), KUBE_SYSTEM);
    match ask(client, endpoint, health, Request::get(path)) {
        Answer::Body(body) => serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|document| Some(document.pointer("/metadata/uid")?.as_str()?.to_owned()))
            .map_or(Known::Unavailable(Outcome::RequestFailed), Known::Obtained),
        // A namespace the API server says is not there is `namespace absent`, which is a fact
        // about the cluster; the same code on a discovery document would be `not served`, which
        // is a fact about its API surface. Two states, two words (§21.4).
        Answer::Refused(404) => Known::Unavailable(Outcome::NamespaceAbsent),
        Answer::Refused(code) => Known::Unavailable(refusal(code)),
        Answer::Unreachable => Known::Unavailable(Outcome::Disconnected),
    }
}

/// What the API server says this session's requests are, through `SelfSubjectReview` (§8.6).
///
/// Every path out of this function that is not a subject is a *stated* unknown, and none of them
/// is an error: §8.6 requires that failing to obtain the effective identity never block a read,
/// so the strongest form that can take is a function that cannot fail.
fn effective_identity<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    health: &mut Health,
    served: Option<&Served>,
) -> Known<Subject> {
    let Some(served) = served else {
        return Known::Unavailable(Outcome::Disconnected);
    };
    let Some(version) = served.versions.preferred_version(AUTHENTICATION_GROUP) else {
        // A cluster before 1.27, or one with the group disabled. It does not serve the review,
        // which is not the same as refusing it.
        return Known::Unavailable(Outcome::TypeNotServed);
    };
    let group_version = format!("{AUTHENTICATION_GROUP}/{version}");
    let Some(resources) = text(ask(
        client,
        endpoint,
        health,
        Request::get(format!("/apis/{group_version}")),
    )) else {
        return Known::Unavailable(Outcome::RequestFailed);
    };
    let Ok(builder) = Discovery::builder().resources(&resources) else {
        return Known::Unavailable(Outcome::RequestFailed);
    };
    let reviews = builder.build();
    let Some(resource) = reviews.by_kind(&group_version, "SelfSubjectReview") else {
        return Known::Unavailable(Outcome::TypeNotServed);
    };
    if !resource.supports(Verb::Create) {
        return Known::Unavailable(Outcome::TypeNotServed);
    }

    // The review is created rather than read: the API server answers the identity of the request
    // that created it, which is the only way to ask "who am I" and get the authorizer's answer
    // rather than the kubeconfig's opinion.
    let body = json!({"apiVersion": group_version, "kind": "SelfSubjectReview"}).to_string();
    let request = Request::new(
        Method::Post,
        collection_path(resource.gvr(), &Scope::cluster()),
    )
    .header("Content-Type", "application/json")
    .header("Accept", "application/json")
    .body(body.into_bytes());
    match ask(client, endpoint, health, request) {
        Answer::Body(body) => Subject::from_self_subject_review(&body)
            .map_or(Known::Unavailable(Outcome::RequestFailed), Known::Obtained),
        Answer::Refused(code) => Known::Unavailable(refusal(code)),
        Answer::Unreachable => Known::Unavailable(Outcome::Disconnected),
    }
}

/// How one request ended, before a caller decides what that means for the thing it was asking.
enum Answer {
    /// The server answered with a success status, and this is the body.
    Body(Vec<u8>),
    /// The server answered, and refused. The code is kept because `403` and `404` mean different
    /// things for different questions.
    Refused(u16),
    /// Nothing came back.
    Unreachable,
}

/// The body of an answer that carried one.
fn text(answer: Answer) -> Option<String> {
    match answer {
        Answer::Body(body) => String::from_utf8(body).ok(),
        Answer::Refused(_) | Answer::Unreachable => None,
    }
}

/// What a refused request means for the thing it was asking about.
fn refusal(code: u16) -> Outcome {
    match code {
        403 | 401 => Outcome::ReadDenied,
        404 => Outcome::TypeNotServed,
        _ => Outcome::RequestFailed,
    }
}

/// Makes one request, records it as a probe with its source and latency, and hands back the
/// answer (§34.3).
///
/// Every request this diagnostic makes goes through here, so the probe list is complete by
/// construction: there is no path that asks the API server something without recording that it
/// asked.
fn ask<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    health: &mut Health,
    request: Request,
) -> Answer {
    let source = format!("{} {}", request.method().as_str(), request.path());
    let request = endpoint.authorise(request);
    let started = Instant::now();
    let sent = client.connection().send(&request);
    let latency = Some(started.elapsed());
    match sent {
        Err(_) => {
            health.record(Probe::new(
                source,
                ProbeStatus::DidNotAnswer(Outcome::Disconnected),
                latency,
            ));
            Answer::Unreachable
        }
        Ok(response) => {
            let code = response.status();
            health.record(Probe::new(source, ProbeStatus::Answered(code), latency));
            if (200..300).contains(&code) {
                Answer::Body(response.body().to_vec())
            } else {
                Answer::Refused(code)
            }
        }
    }
}

/// The diagnostic as a record of the target's schema.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares. Both come from
/// [`crate::contributions::TARGETS`], so a failure means this crate's table and the schema built
/// from it have drifted apart — a bug here, never something a cluster can cause.
fn record(
    target: &Target,
    schema: &Arc<Schema>,
    diagnostic: &ClusterDiagnostic,
) -> Result<Value, ErrorValue> {
    let provenance = Provenance::local(crate::PACKAGE, schema.id().clone());
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance);
    for field in target.fields {
        builder = builder.set(field.name, field_value(field.name, diagnostic))?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// One field of the diagnostic record, by the name the schema declares it under.
fn field_value(name: &str, diagnostic: &ClusterDiagnostic) -> Value {
    let fingerprint = diagnostic.fingerprint();
    let identity = diagnostic.identity();
    match name {
        // --- which provider instance this is (§6.2, §10.1) ---
        "uid" => Value::String(diagnostic.instance().into()),
        "name" => Value::String(
            diagnostic
                .instance()
                .strip_prefix("kubernetes:")
                .unwrap_or(diagnostic.instance())
                .into(),
        ),

        // --- which cluster it is (§10.2) ---
        "server" => signal(diagnostic, Signal::Origin),
        "server_key_fingerprint" => signal(diagnostic, Signal::ServerPublicKey),
        "kube_system_uid" => signal(diagnostic, Signal::KubeSystemUid),
        "fingerprint" => fingerprint
            .digest()
            .map_or(Value::Null, |digest| Value::String(digest.into())),
        "fingerprint_signals" => Value::List(
            fingerprint
                .obtained_signals()
                .into_iter()
                .map(|signal| Value::String(signal.as_str().into()))
                .collect(),
        ),

        // --- whether it answers (§34.3) ---
        "reachable" => Value::Bool(diagnostic.health().is_reachable()),
        "server_version" => diagnostic
            .health()
            .version()
            .obtained()
            .map_or(Value::Null, |version| {
                Value::String(version.git_version().into())
            }),
        "tls" => Value::String(diagnostic.tls().as_str().into()),
        "probes" => Value::Map(Arc::new(
            diagnostic
                .health()
                .probes()
                .iter()
                .map(|probe| {
                    (
                        Arc::from(probe.source()),
                        Value::String(probe.status().describe().into()),
                    )
                })
                .collect::<MapValue>(),
        )),
        "latency_ms" => Value::Map(Arc::new(
            diagnostic
                .health()
                .probes()
                .iter()
                .filter_map(|probe| {
                    let latency = probe.latency()?;
                    Some((
                        Arc::from(probe.source()),
                        Value::Int(i128::try_from(latency.as_millis()).unwrap_or(i128::MAX)),
                    ))
                })
                .collect::<MapValue>(),
        )),

        // --- who the provider is to it (§8.5, §8.6) ---
        "credential_identity" => identity
            .credential()
            .obtained()
            .map_or(Value::Null, |subject| {
                Value::String(subject.username().into())
            }),
        "effective_identity" => identity
            .effective()
            .obtained()
            .map_or(Value::Null, |subject| {
                Value::String(subject.username().into())
            }),
        "effective_uid" => identity
            .effective()
            .obtained()
            .and_then(|subject| subject.uid())
            .map_or(Value::Null, |uid| Value::String(uid.into())),
        "effective_groups" => identity
            .effective()
            .obtained()
            .map_or(Value::Null, |subject| {
                Value::List(
                    subject
                        .groups()
                        .iter()
                        .map(|group| Value::String(group.as_str().into()))
                        .collect(),
                )
            }),
        "impersonating" => Value::Bool(identity.impersonation().is_active()),
        "impersonated_user" => identity
            .impersonation()
            .user()
            .map_or(Value::Null, |user| Value::String(user.into())),

        // --- what it could not determine ---
        "unknowns" => Value::List(
            diagnostic
                .unknowns()
                .iter()
                .map(|unknown| Value::String(unknown.describe().into()))
                .collect(),
        ),

        _ => Value::Null,
    }
}

/// One fingerprint signal as a field: its value, or null where it was not obtained.
///
/// Null and never the reason. The reason belongs in `unknowns`, in §21.4's vocabulary, so that a
/// field which holds a UID never holds the words "read denied" instead — a renderer cannot tell
/// those apart, and an operator reading a table would take the second for a value.
fn signal(diagnostic: &ClusterDiagnostic, signal: Signal) -> Value {
    diagnostic
        .fingerprint()
        .signal(signal)
        .obtained()
        .map_or(Value::Null, |value| Value::String(value.as_str().into()))
}

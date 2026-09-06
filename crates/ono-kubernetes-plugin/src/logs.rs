//! One container's log, as lines that say what they are not (§42.1, §42.2).
//!
//! `logs.rs` in the domain layer builds the request, decodes the body, keeps a non-UTF-8 line as
//! bytes, and always states a retention bound so that no accessor can mean "everything it
//! printed". This module is the route from a query to those lines, and the sentence it exists to
//! preserve is the one §42.1 spends its provenance requirement on: **a retrieved log is not the
//! output of a container.**
//!
//! So `bounds` is on every record and is never empty. The container runtime rotated and truncated
//! this log long before this provider asked, and that entry is in the list whatever the request
//! said; `tailLines`, `sinceSeconds` and `limitBytes` each add their own. A record that omitted
//! the bounds would imply completeness by saying nothing, and saying nothing is how a reader
//! concludes that a message they cannot find was never printed.
//!
//! Three further refusals come across with it:
//!
//! - **A line is bytes.** `text` is null where the bytes are not UTF-8, and `not_utf8_after` says
//!   how far decoding got. Substituting U+FFFD would hand back something that reads like the
//!   container's output and is not it, with nothing downstream able to tell.
//! - **A timestamp prefix is a string beside its clock.** It is the container runtime's clock on
//!   the node, and parsing it into an instant would make it sortable against this provider's own
//!   observations — the cross-clock timeline §39.2 forbids.
//! - **An empty log is not proof.** A retrieval with no lines ends the invocation naming its
//!   bounds, rather than completing with an empty stream that reads as "the container printed
//!   nothing" (§63.6, ADR-0025).
//!
//! `follow` is deliberately not an option here. A followed log is a live stream with the same
//! shape as `k8s-change` — emit while the body is open, and end when the operator ends it — and
//! offering the word without that machinery would answer a followed request by closing at once,
//! which a reader takes for a container that just stopped. `SessionRequest`'s exec, attach and
//! port forward stay unreachable for the reason ADR-0018 records.

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, Outcome};
use ono_provider_kubernetes::discovery::Verb;
use ono_provider_kubernetes::logs::{
    Ending, LogDecoder, LogLine, LogRequest, PodTarget, Retrieved,
};
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::temporal::ClockSource;
use ono_provider_kubernetes::transport::{ByteStream, Client, Freshness, Request};
use ono_value::Schema;
use serde_json::Value as Json;

use crate::conditions::named;
use crate::contributions::Target;
use crate::query::{
    self, Answer, Conversation, Endpoint, REFUSED, REFUSED_CODE, UNAVAILABLE, UNAVAILABLE_CODE,
    UNSUPPORTED, UNSUPPORTED_CODE, failure,
};
use crate::records::{Line, log_record};
use crate::sessions::Sessions;

/// The subresource a log is read from, as discovery spells it.
const SUBRESOURCE: &str = "log";

/// Answers a `k8s-log` query: one Pod container in, its lines out.
#[must_use]
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let Some(name) = named(ctx) else {
        return Outcome::Failed(query::unnamed(
            "to read a log from",
            "--name api-7d9f-abc --container api",
        ));
    };
    let asked = Asked::from_options(ctx);
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
    };
    let Some(namespace) = endpoint.scope.namespace().map(str::to_owned) else {
        return Outcome::Failed(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            "a log is read from one Pod, and the query named no namespace to find it in".to_owned(),
            "Pass `namespace`, or use a context whose namespace names one. A Pod name is unique \
             within a namespace of one cluster and nowhere else, and a log line attributed to the \
             identically named Pod elsewhere is the most expensive kind of wrong \
             (specification section 42.1).",
        ));
    };
    if ctx.cancelled() {
        return Outcome::Cancelled;
    }

    let read = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            query::converse(
                ctx,
                &endpoint,
                Tail {
                    endpoint: &endpoint,
                    namespace: &namespace,
                    name: &name,
                    asked: &asked,
                    session,
                },
            )
        },
    );
    match read {
        Ok(read) => emit(ctx, target, &schema, read.as_ref()),
        Err(error) => Outcome::Failed(error),
    }
}

/// What the query asked for beyond which container (§42.1).
///
/// Each option narrows the answer further, and each one that is set becomes an entry in the
/// record's `bounds`: the request states what it cut off, so the answer can too.
struct Asked {
    container: Option<String>,
    previous: bool,
    timestamps: bool,
    tail_lines: Option<u32>,
    since_seconds: Option<u64>,
    limit_bytes: Option<u64>,
}

impl Asked {
    fn from_options(ctx: &mut Ctx<'_>) -> Self {
        let options = ctx.arguments();
        let flag = |key: &str| options.get(key).and_then(Json::as_bool) == Some(true);
        let number = |key: &str| options.get(key).and_then(Json::as_u64).filter(|n| *n > 0);
        Self {
            container: options
                .get("container")
                .and_then(Json::as_str)
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
            previous: flag("previous"),
            timestamps: flag("timestamps"),
            tail_lines: number("tail_lines").and_then(|lines| u32::try_from(lines).ok()),
            since_seconds: number("since_seconds"),
            limit_bytes: number("limit_bytes"),
        }
    }

    /// The domain request this asks for.
    fn request(&self, instance: &str, namespace: &str, pod: &str) -> LogRequest {
        let mut target = PodTarget::new(instance, namespace, pod);
        if let Some(container) = &self.container {
            target = target.in_container(container);
        }
        let mut request = LogRequest::new(target);
        if self.previous {
            request = request.of_previous_instance();
        }
        if self.timestamps {
            request = request.with_timestamps();
        }
        if let Some(lines) = self.tail_lines {
            request = request.tail_lines(lines);
        }
        if let Some(seconds) = self.since_seconds {
            request = request.since_seconds(seconds);
        }
        if let Some(bytes) = self.limit_bytes {
            request = request.limit_bytes(bytes);
        }
        request
    }
}

/// What one read of a log produced, with the Pod it was read from.
struct Read {
    pod: Guarded,
    retrieved: Retrieved,
    freshness: Freshness,
    clock: ClockSource,
}

/// Resolve the Pod, read it, then read its container's log subresource.
struct Tail<'a> {
    endpoint: &'a Endpoint,
    namespace: &'a str,
    name: &'a str,
    asked: &'a Asked,
    session: &'a mut Session,
}

impl Conversation for Tail<'_> {
    type Answer = Option<Read>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        let served = query::served(session, client, self.endpoint)?;
        let resource = query::curated(session, client, self.endpoint, &served, "", "Pod")?;
        // Discovery decides whether this cluster serves the subresource at all, exactly as it
        // decides which collection serves a Pod (§4 invariants 1–2, §11.5). A server that lists
        // `pods` without `pods/log` is a server on which no log can be read, and saying so is
        // different from reading an empty one.
        if !resource
            .subresources()
            .iter()
            .any(|name| name == SUBRESOURCE)
        {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!(
                    "this cluster serves `{}` without the `log` subresource",
                    resource.gvr()
                ),
                "A log that cannot be read is not a container that printed nothing.",
            ));
        }
        if !resource.supports(Verb::Get) {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!(
                    "the cluster serves `{}` and does not offer `get` on one of them",
                    resource.gvr()
                ),
                "A log is read through one Pod's own endpoint, which needs `get` rather than \
                 `list` (specification section 60.5).",
            ));
        }
        let scope = query::scope_for(self.endpoint, &resource);
        let (pod, freshness) = match query::fetch(client, &resource, &scope, self.name)? {
            // §21.4's one outcome that is a fact about the cluster. A Pod that is not there has
            // no log, and that is an answer rather than a refusal.
            Answer::Absent => return Ok(None),
            Answer::Fetched(read) => *read,
            Answer::Listed(_) => {
                return Err(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    "a direct read answered with a collection".to_owned(),
                    "This is a defect in the Kubernetes provider, not in the cluster.",
                ));
            }
        };
        let pod = query::hold(pod)?;
        // The node the container runs on, so that the timestamp prefix the server writes arrives
        // with the clock that wrote it rather than as a bare instant (§39.1, §42.1).
        let clock = pod
            .object()
            .field("/spec/nodeName")
            .and_then(Json::as_str)
            .map_or(ClockSource::Unattributed, |node| {
                ClockSource::Node(node.to_owned())
            });

        let request = self
            .asked
            .request(freshness.provider_instance(), self.namespace, self.name);
        let http = request.http_request().map_err(|error| {
            failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("{error}"),
                "A run that has already ended cannot produce another line.",
            )
        })?;
        let body = fetch_body(client, self.endpoint, http, self.name)?;
        let mut decoder = LogDecoder::for_request(&request);
        let mut lines: Vec<LogLine> = decoder.decode(&body);
        // Whatever the body ended on that is not a newline is an unterminated line, and it is
        // handed over as one rather than presented as a line the container finished writing.
        lines.extend(decoder.finish());
        Ok(Some(Read {
            pod,
            retrieved: Retrieved::of(&request, lines, Ending::BodyEnded),
            freshness,
            clock,
        }))
    }
}

/// Sends the log request and hands back the bytes, or says what the server did instead.
fn fetch_body<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    request: Request,
    pod: &str,
) -> Result<Vec<u8>, WireError> {
    let request = endpoint.authorise(request.header("Accept", "text/plain"));
    let response = client
        .connection()
        .send(&request)
        .map_err(|error| query::transport_failure("the log subresource", &error))?;
    if response.status() == 200 {
        return Ok(response.body().to_vec());
    }
    // Every status but `200` is a statement about the read rather than about the container. A
    // `404` here is not the Pod being absent — the Pod was read a moment ago — it is a container
    // this Pod does not have, or one whose prior run the kubelet no longer holds (§21.4).
    Err(failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "the log of `{pod}` did not answer: {} {} — {}",
            response.status(),
            response.reason(),
            String::from_utf8_lossy(response.body()),
        ),
        "This is what happened instead of a read, and it is not the container having printed \
         nothing (specification section 21.4).",
    ))
}

/// Streams one record per line, and refuses to answer an empty log with silence.
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    read: Option<&Read>,
) -> Outcome {
    // A Pod that is not there has no log, and that is an answer with nothing in it (§21.4).
    let Some(read) = read else {
        return Outcome::Completed;
    };
    let retrieved = &read.retrieved;
    if retrieved.lines().is_empty() {
        return empty(retrieved);
    }
    for (at, line) in retrieved.lines().iter().enumerate() {
        if ctx.cancelled() {
            return Outcome::Cancelled;
        }
        let value = match query::built(
            target,
            log_record(
                target,
                schema,
                &Line {
                    pod: &read.pod,
                    retrieved,
                    line,
                    ordinal: at + 1,
                    clock: &read.clock,
                },
                &read.freshness,
            ),
        ) {
            Ok(value) => value,
            Err(outcome) => return outcome,
        };
        if let Err(outcome) = query::deliver(ctx, &value) {
            return outcome;
        }
    }
    Outcome::Completed
}

/// §42.1 and §63.6, as the answer to a read that produced no lines.
///
/// A failure carrying the bounds rather than an empty stream. The bounds are the whole reason: a
/// reader who receives nothing concludes that the container printed nothing, and what actually
/// happened is that the runtime rotated the log away, or the requested tail did not reach back to
/// it, or the process writes to a file. ADR-0025.
///
/// `contribution.refused` since ADR-0028: the retrieval succeeded and this package declines to
/// render its emptiness as an absence, which is not the cluster failing to answer.
fn empty(retrieved: &Retrieved) -> Outcome {
    let bounds: Vec<String> = retrieved
        .bounds()
        .iter()
        .map(|bound| bound.describe())
        .collect();
    Outcome::Failed(failure(
        REFUSED_CODE,
        REFUSED,
        format!(
            "no line was read from {} [{} run]",
            retrieved.target().describe(),
            retrieved.instance().as_str(),
        ),
        &format!(
            "This is not evidence that the container printed nothing. What was retrievable was \
             already bounded before it was requested: {} (specification section 42.1).",
            bounds.join("; ")
        ),
    ))
}

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
//! `follow` is here, and it is a live stream rather than a longer read. It has the same shape as
//! `k8s-change`: the invocation borrows its context per read, a record is emitted as each line
//! arrives with the body still open, and the operator ends it (ADR-0023, ADR-0030). Nothing is
//! accumulated on the way — [`LogFollow`] holds counters and a partial line and never a log,
//! which is the type-level form of §42.2's refusal to let a log become provider state. Two
//! endings say different things and neither is a claim about the container: a body that ended is
//! a fact about the connection, and a follow the operator stopped is a fact about the operator.
//! `follow` with `previous` is refused, because the server accepts that pair and answers it by
//! closing at once. `SessionRequest`'s exec, attach and port forward stay unreachable for the
//! reason ADR-0018 records.

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, EmitError, Outcome};
use ono_provider_kubernetes::discovery::Verb;
use ono_provider_kubernetes::logs::{
    Bound, Ending, LogDecoder, LogFollow, LogLine, LogRequest, PodTarget, Retrieved,
};
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::temporal::ClockSource;
use ono_provider_kubernetes::transport::{ApiError, ByteStream, Client, Freshness, Request};
use ono_value::Schema;
use serde_json::Value as Json;

use crate::broker::{Lease, ReadPolicy};
use crate::conditions::named;
use crate::contributions::Target;
use crate::query::{
    self, Answer, Conversation, Endpoint, REFUSED, REFUSED_CODE, UNAVAILABLE, UNAVAILABLE_CODE,
    UNSUPPORTED, UNSUPPORTED_CODE, converse_on, failure,
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

    let sought = Sought {
        endpoint: &endpoint,
        namespace: &namespace,
        name: &name,
        asked: &asked,
    };
    // The two answers are different invocations rather than two lengths of one. A bounded read
    // fetches a body, decodes it and emits what it found; a follow emits while the body is open
    // and ends when the operator ends it. Sharing an emission loop between them would mean
    // buffering the follow, which is the one thing §42.2 forbids the provider to do with a log.
    if asked.follow {
        return sessions.with(
            &endpoint.session_key(),
            || endpoint.start_session(),
            |session| {
                // From here on the context is lent rather than held: a read borrows it, gives
                // it back, and the emission between two reads borrows it again (ADR-0023).
                let lease = Lease::new(ctx);
                let mut emitter = Emitter {
                    target,
                    schema,
                    ordinal: 0,
                };
                follow(&lease, session, &mut emitter, &sought)
            },
        );
    }

    let read = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            query::converse(
                ctx,
                &endpoint,
                Tail {
                    sought: &sought,
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

/// Which log one invocation was asked for, and where to find it.
struct Sought<'a> {
    endpoint: &'a Endpoint,
    namespace: &'a str,
    name: &'a str,
    asked: &'a Asked,
}

/// What the query asked for beyond which container (§42.1).
///
/// Each option narrows the answer further, and each one that is set becomes an entry in the
/// record's `bounds`: the request states what it cut off, so the answer can too.
struct Asked {
    container: Option<String>,
    previous: bool,
    /// Whether the body stays open and the answer arrives line by line (§42.1, ADR-0030).
    ///
    /// Not a bound and not a narrowing: every other field here shortens the answer and shows up
    /// in the record's `bounds`, and this one removes the end of it.
    follow: bool,
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
            follow: flag("follow"),
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
        if self.follow {
            request = request.following();
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

/// The Pod a log is read from, and the clocks behind what its lines say.
///
/// Shared by both answers, because they are the same provenance: which object the lines belong
/// to, how fresh the read of it was, and whose clock wrote the timestamp prefix. A followed line
/// and a read one carry identical provenance, and this is the type that makes that so by
/// construction rather than by two code paths agreeing.
struct Source {
    pod: Guarded,
    freshness: Freshness,
    clock: ClockSource,
}

/// What one read of a log produced, with the Pod it was read from.
struct Read {
    source: Source,
    retrieved: Retrieved,
}

/// Everything the cluster had to be asked before a single byte of log could be requested.
struct Prepared {
    source: Source,
    request: LogRequest,
    http: Request,
}

/// Resolves the Pod, reads it, and builds the log request its container's subresource takes.
///
/// The whole of what a bounded read and a follow have in common, which is everything up to the
/// moment the body starts arriving. Written once so that the two answers cannot drift on which
/// cluster they discovered, which Pod they read, or which request they would have sent.
fn prepare<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    sought: &Sought<'_>,
) -> Result<Option<Prepared>, WireError> {
    let served = query::served(session, client, sought.endpoint)?;
    let resource = query::curated(session, client, sought.endpoint, &served, "", "Pod")?;
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
    let scope = query::scope_for(sought.endpoint, &resource);
    let (pod, freshness) = match query::fetch(client, &resource, &scope, sought.name)? {
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

    let request =
        sought
            .asked
            .request(freshness.provider_instance(), sought.namespace, sought.name);
    // The one place `follow` and `previous` meet, and the one place either answer can refuse
    // them. The API server accepts the pair and answers it by closing the body immediately,
    // because the prior run has stopped growing — and a caller watching for more lines reads
    // that as a container it has just seen stop (§42.1, ADR-0030).
    let http = request.http_request().map_err(|error| {
        failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("{error}"),
            "A run that has already ended cannot produce another line.",
        )
    })?;
    Ok(Some(Prepared {
        source: Source {
            pod,
            freshness,
            clock,
        },
        request,
        http,
    }))
}

/// Resolve the Pod, read it, then read its container's log subresource to the end of the body.
struct Tail<'a, 'b> {
    sought: &'a Sought<'b>,
    session: &'a mut Session,
}

impl Conversation for Tail<'_, '_> {
    type Answer = Option<Read>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let Some(prepared) = prepare(self.session, client, self.sought)? else {
            return Ok(None);
        };
        let body = fetch_body(
            client,
            self.sought.endpoint,
            prepared.http,
            self.sought.name,
        )?;
        let mut decoder = LogDecoder::for_request(&prepared.request);
        let mut lines: Vec<LogLine> = decoder.decode(&body);
        // Whatever the body ended on that is not a newline is an unterminated line, and it is
        // handed over as one rather than presented as a line the container finished writing.
        lines.extend(decoder.finish());
        Ok(Some(Read {
            source: prepared.source,
            retrieved: Retrieved::of(&prepared.request, lines, Ending::BodyEnded),
        }))
    }
}

/// Resolve the Pod and build the request, and stop there: the body is read by [`Following`].
struct Prepare<'a, 'b> {
    sought: &'a Sought<'b>,
    session: &'a mut Session,
}

impl Conversation for Prepare<'_, '_> {
    type Answer = Option<Prepared>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        prepare(self.session, client, self.sought)
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

/// Follows one container's log until the body ends or the operator stops it (§42.1, §62.12).
///
/// Two exchanges rather than one, and the split is the point: the Pod is read under the ordinary
/// request policy, where silence eventually means a broken server, and the body is then read
/// under the watch policy, where silence means a container with nothing to say. One policy for
/// both would either fail a quiet log after ninety seconds or wait ninety seconds to notice that
/// an API server had stopped answering.
fn follow(
    lease: &Lease<'_, '_>,
    session: &mut Session,
    emitter: &mut Emitter,
    sought: &Sought<'_>,
) -> Outcome {
    let prepared = match converse_on(lease, sought.endpoint, Prepare { sought, session }) {
        Ok(prepared) => prepared,
        Err(error) => return refused(lease, error),
    };
    // A Pod that is not there has no log, and that is an answer with nothing in it (§21.4).
    let Some(prepared) = prepared else {
        return Outcome::Completed;
    };
    // `LogFollow` rather than a `Vec<LogLine>`, and that is a §42.2 decision rather than a
    // stylistic one: it holds counters, a partial line and a state, and there is no accessor on
    // it that could hand anybody the log. A vector would accumulate an unbounded stream in the
    // provider, which is the cache §42.2 forbids, and it would do so silently.
    let mut following = LogFollow::open(prepared.request);
    let answered = converse_on(
        lease,
        sought.endpoint,
        Following {
            lease,
            endpoint: sought.endpoint,
            name: sought.name,
            request: prepared.http,
            follow: &mut following,
            emitter,
            source: &prepared.source,
        },
    );
    match answered {
        Ok(outcome) => outcome,
        Err(error) => refused(lease, error),
    }
}

/// A cancellation that surfaced as a failed exchange is a cancellation, not a failure.
///
/// A read interrupted by the operator stopping the query comes back as a stream error, because
/// that is all a byte stream can say. §62.12 asks for the invocation to *terminate* promptly, and
/// terminating with a fault the operator caused would be a lie about the cluster.
fn refused(lease: &Lease<'_, '_>, error: WireError) -> Outcome {
    if lease.cancelled() {
        return Outcome::Cancelled;
    }
    Outcome::Failed(error)
}

/// One followed log body, read chunk by chunk, with a record emitted as each line arrives.
///
/// The same shape as `k8s-change`'s live watch and for the same reason: the brokered connection
/// borrows the invocation context per read rather than for the length of the connection, so
/// between two chunks the context is free for `Ctx::emit` (ADR-0023).
struct Following<'a, 'ctx, 'io> {
    lease: &'a Lease<'ctx, 'io>,
    endpoint: &'a Endpoint,
    name: &'a str,
    request: Request,
    follow: &'a mut LogFollow,
    emitter: &'a mut Emitter,
    source: &'a Source,
}

impl Conversation for Following<'_, '_, '_> {
    type Answer = Outcome;

    /// A quiet log is the ordinary case, not a stalled connection.
    ///
    /// Without this the three thirty-second idle windows of a request policy would end a follow
    /// of a container that simply had nothing to say for a minute and a half — and end it as a
    /// failure, which reads as a statement about the cluster.
    fn read_policy(&self) -> ReadPolicy {
        ReadPolicy::watch()
    }

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let Self {
            lease,
            endpoint,
            name,
            request,
            follow,
            emitter,
            source,
        } = self;
        let request = endpoint.authorise(request.header("Accept", "text/plain"));
        let mut stream = client
            .connection()
            .open(&request)
            .map_err(|error| query::transport_failure("the log subresource", &error))?;
        // Every status but `200` is a statement about the read rather than about the container,
        // exactly as it is for a bounded one (§21.4). The body is not drained for a message: a
        // failed follow may be answered by a server that then says nothing at all, and waiting
        // to quote it would trade a prompt refusal for a better sentence.
        if stream.status() != 200 {
            return Err(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!(
                    "the log of `{name}` could not be followed: the API server answered {}",
                    stream.status()
                ),
                "This is what happened instead of a stream, and it is not the container having \
                 printed nothing (specification section 21.4).",
            ));
        }

        loop {
            // §62.12: between two chunks, which is where a follow spends its life. A container
            // that prints once an hour is quiet for an hour, and the operator who stops watching
            // it is not asked to wait for the next line.
            if lease.cancelled() {
                follow.cancel();
                return Ok(Outcome::Cancelled);
            }
            let Some(chunk) = stream.next_chunk() else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                // A window passed and the container printed nothing. A followed log is quiet for
                // most of its life, and a quiet log is neither an ended one nor a failed one —
                // the connection is open and the next read continues mid-line. The read hands
                // control back so that a follow can notice the operator stopping it promptly
                // (§62.12), which the check at the head of this loop is for.
                Err(ApiError::Quiet) => continue,
                Err(error) => {
                    if lease.cancelled() {
                        follow.cancel();
                        return Ok(Outcome::Cancelled);
                    }
                    follow.failed(error.to_string());
                    break;
                }
            };
            for line in follow.receive(&chunk) {
                if let Err(outcome) = emitter.deliver(lease, source, follow, line) {
                    return Ok(outcome);
                }
            }
        }

        follow.closed();
        // What the body ended mid-line on is a line the server never finished, and it is handed
        // over as an unterminated one rather than dropped — the same bytes a bounded read hands
        // over through `LogDecoder::finish`.
        if let Some(rest) = follow.finish()
            && let Err(outcome) = emitter.deliver(lease, source, follow, rest)
        {
            return Ok(outcome);
        }
        Ok(ended(follow))
    }
}

/// What one invocation emits with, and how far through the follow it is.
struct Emitter {
    target: &'static Target,
    schema: Arc<Schema>,
    /// Which line of this follow the next record is, counting from one.
    ordinal: usize,
}

impl Emitter {
    /// Builds one record of one line and emits it under the host's credit.
    ///
    /// The [`Retrieved`] is built here, for this line, and dropped with it. It is the record's
    /// provenance — the target, the run, the bounds and the ending — and building one per line
    /// is what keeps a followed log out of provider state: there is no list anywhere that grows
    /// as the container writes (§42.2).
    ///
    /// # Errors
    ///
    /// The outcome the caller returns unchanged. A cancelled stream and a refused record end an
    /// invocation in different ways, and neither is something a follow continues past.
    fn deliver(
        &mut self,
        lease: &Lease<'_, '_>,
        source: &Source,
        follow: &LogFollow,
        line: LogLine,
    ) -> Result<(), Outcome> {
        if lease.cancelled() {
            return Err(Outcome::Cancelled);
        }
        // `Ending::StillOpen` while the body is open, which is what every record of a live
        // follow carries: it says the stream had not stopped when this line was written, rather
        // than claiming an ending that has not happened yet.
        let retrieved = Retrieved::of(follow.request(), vec![line], follow.ending());
        let Some(line) = retrieved.lines().first() else {
            return Ok(());
        };
        self.ordinal += 1;
        let value = query::built(
            self.target,
            log_record(
                self.target,
                &self.schema,
                &Line {
                    pod: &source.pod,
                    retrieved: &retrieved,
                    line,
                    ordinal: self.ordinal,
                    clock: &source.clock,
                },
                &source.freshness,
            ),
        )?;
        // The credit is the backpressure: this blocks until the consumer has taken enough for
        // the host to have more to give, and nothing is queued here while it does.
        match lease.with(|ctx| ctx.emit(&value)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(EmitError::Cancelled)) => Err(Outcome::Cancelled),
            Ok(Err(error)) => Err(Outcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the host refused a record: {error}"),
                "The stream ended before the query did.",
            ))),
            Err(overlap) => Err(Outcome::Failed(overlap)),
        }
    }
}

/// How a follow that stopped by itself ends the invocation.
///
/// Three endings and three different sentences. A stream that failed is a failure whatever it
/// delivered first, because the lines after it were never read and reporting `Completed` would
/// present a truncated follow as a whole one. A body that ended having delivered lines completed.
/// A body that ended having delivered none refuses, for §63.6's reason.
fn ended(follow: &LogFollow) -> Outcome {
    if let Ending::Failed(detail) = follow.ending() {
        return Outcome::Failed(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!(
                "the followed log of {} stopped: {detail}",
                follow.request().target().describe()
            ),
            "The lines already answered were read; what would have come after them was not. A \
             stream that failed is not a container that stopped printing.",
        ));
    }
    if follow.delivered_lines() > 0 {
        return Outcome::Completed;
    }
    Outcome::Failed(unfollowed(follow))
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
                    pod: &read.source.pod,
                    retrieved,
                    line,
                    ordinal: at + 1,
                    clock: &read.source.clock,
                },
                &read.source.freshness,
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
            bounded(retrieved.bounds())
        ),
    ))
}

/// The same refusal for a follow that ended having delivered nothing (§42.1, §63.6, ADR-0030).
///
/// A separate sentence rather than a reuse of [`empty`], because a follow that ended is a
/// different statement from a read that found nothing: the read looked at what was retained and
/// came back with none of it, and the follow was *open* and carried nothing before the body
/// ended — which is a fact about the connection and not about the container. So the ending is in
/// the help text beside the bounds.
///
/// A follow the operator cancelled never reaches here. It ends the invocation as
/// [`Outcome::Cancelled`], because a read somebody interrupted has made no claim at all about
/// what the container did or did not print, and refusing on its behalf would invent one.
fn unfollowed(follow: &LogFollow) -> WireError {
    let request = follow.request();
    failure(
        REFUSED_CODE,
        REFUSED,
        format!(
            "no line arrived while {} was followed [{} run]",
            request.target().describe(),
            request.instance().as_str(),
        ),
        &format!(
            "This is not evidence that the container printed nothing: {}, which is a fact about \
             the connection rather than about the container. What was retrievable was already \
             bounded before it was requested: {} (specification section 42.1).",
            follow.ending().describe(),
            bounded(&request.bounds()),
        ),
    )
}

/// Everything that kept an answer short of the container's output, in one clause.
fn bounded(bounds: &[Bound]) -> String {
    bounds
        .iter()
        .map(|bound| bound.describe())
        .collect::<Vec<String>>()
        .join("; ")
}

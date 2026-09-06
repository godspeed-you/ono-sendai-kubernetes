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
use ono_provider_kubernetes::coverage::{Gap, Outcome as Coverage, Scope};
use ono_provider_kubernetes::discovery::{self, Discovery, Resource, Verb};
use ono_provider_kubernetes::kubeconfig::{Credential, Kubeconfig, Secret, Trust};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::{Lookup, Session};
use ono_provider_kubernetes::tls::{Anchors, ClientIdentity, TlsError, TlsSettings, TlsStream};
use ono_provider_kubernetes::transport::{
    ApiError, ByteStream, Client, Freshness, ListOptions, Listing, Operation, Request,
};
use ono_value::{Schema, Value};
use serde_json::{Map as JsonMap, Value as Json, json};

use crate::broker::{BrokeredStream, Lease, ReadPolicy, decode_hex};
use crate::contributions::{Reads, Target};
use crate::dynamic::{self, Selector, Typing, Unresolved};
use crate::records::{dynamic_record, record};
use crate::sessions::{Key, Sessions};

/// `provider.unavailable`, as core's `docs/contracts/errors.yaml` publishes it.
///
/// Spelled out rather than taken from `ono_core::ErrorCode`, which a package does not depend on.
/// The KUANG taxonomy has no code for "this provider could not reach the system it fronts", and
/// inventing one would put a code on the wire that no registry explains.
pub(crate) const UNAVAILABLE_CODE: &str = "Ono-Sendai-E0401";
/// The dotted name of [`UNAVAILABLE_CODE`].
pub(crate) const UNAVAILABLE: &str = "provider.unavailable";
/// `provider.unsupported`, for a cluster that serves no such thing.
/// `contribution.refused`, as core's `docs/contracts/kuang/errors.v1.yaml` publishes it.
///
/// **The package's own rule, and no other claim.** Its help says so in as many words: "this is
/// the package's rule, not the host's policy and not the external system's answer: a precondition
/// the package requires was not met, so it did nothing." That is exactly the sentence this
/// provider needs for the three refusals it makes on its own authority — a plan whose precondition
/// is missing (§56), an Event search that observed nothing (§38.6) and a log read that produced
/// no lines (§63.6) — and none of the three is what the codes they used to borrow assert.
///
/// `safety.policy_denied` says a *configured* policy forbade it, and nothing was configured.
/// `provider.unavailable` says the cluster did not answer, and it answered. `provider.unsupported`
/// says the provider cannot, and it can and declines. ADR-0025 recorded that gap as a finding and
/// `ADR-0587 (core)` closed it; ADR-0028 here records the migration.
pub(crate) const REFUSED_CODE: &str = "Ono-Sendai-K11901";
/// The dotted name of [`REFUSED_CODE`].
pub(crate) const REFUSED: &str = "contribution.refused";

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
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    // Read before the connection opens, because the brokered stream borrows the context for as
    // long as it lives and the query's own words are needed after that.
    //
    // The standing query fills in what an invocation carrying no arguments did not say. It is
    // read here as well as in [`Endpoint::resolve`] because `k8s-resource` names its collection
    // in the *selector* rather than in the endpoint: a place entered from a query that named a
    // kind is re-read by an invocation with no kind at all, and a re-read that cannot say which
    // collection to look in reports a live object as gone (ADR-0027).
    let selector = Selector::from_options(&standing_arguments(ctx));
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

    // The session is entered around the whole conversation rather than consulted before it: what
    // discovery costs and what it produced are the same question, and asking them at two moments
    // is how a snapshot comes to be fetched twice for one query.
    let answer = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            converse(
                ctx,
                &endpoint,
                Listed {
                    target,
                    endpoint: &endpoint,
                    selector: &selector,
                    lookup: lookup.as_deref(),
                    session,
                },
            )
        },
    );
    let (answer, shape, unread) = match answer {
        Ok(answer) => answer,
        Err(error) => return Outcome::Failed(error),
    };
    emit(ctx, target, &schema, &shape, answer, &unread)
}

/// The listing conversation, as one value [`converse`] can run over either kind of stream.
struct Listed<'a> {
    target: &'static Target,
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    lookup: Option<&'a str>,
    session: &'a mut Session,
}

impl Conversation for Listed<'_> {
    type Answer = (Answer, Shape, Vec<Gap>);

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        read(
            self.session,
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

    /// How the connection reads while this exchange runs.
    ///
    /// A request and its response tolerate silence badly and a watch tolerates it as the normal
    /// case, so the exchange says which it is rather than the connection guessing (§19, §62.12).
    fn read_policy(&self) -> ReadPolicy {
        ReadPolicy::request()
    }

    /// Talks to the API server over `client`.
    ///
    /// # Errors
    ///
    /// Whatever the exchange could not do, in the vocabulary of core's `errors.yaml`.
    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError>;
}

/// Opens the brokered connection, runs one conversation over it, and closes it.
///
/// For a handler that has nothing to emit until the exchange is over, which is every handler but
/// the watch. [`converse_on`] is the same thing against a lease the caller already holds.
pub(crate) fn converse<C: Conversation>(
    ctx: &mut Ctx<'_>,
    endpoint: &Endpoint,
    conversation: C,
) -> Result<C::Answer, WireError> {
    let lease = Lease::new(ctx);
    converse_on(&lease, endpoint, conversation)
}

/// Opens the brokered connection, runs one conversation over it, and closes it.
///
/// The connection borrows the leased context for the length of each read rather than for its own
/// lifetime, so a conversation that holds the same lease may emit between two reads with the
/// response body still open — which is what makes a live watch reachable at all (ADR-0023).
pub(crate) fn converse_on<C: Conversation>(
    lease: &Lease<'_, '_>,
    endpoint: &Endpoint,
    conversation: C,
) -> Result<C::Answer, WireError> {
    let policy = conversation.read_policy();
    let (answer, handle, open) = {
        let stream = BrokeredStream::connect(lease, &endpoint.host, endpoint.port, policy)?;
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
        // A watch abandoned mid-body — cancelled, or at its budget — comes through here too, so
        // the connection is given back rather than left to the end of the invocation.
        let _ =
            lease.with(|ctx| ctx.host_call(method::NETWORK_CLOSE, json!({"connection": handle})));
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
    unread: &[Gap],
) -> Outcome {
    // §60.5 and §21.4 in the shape of a control flow: a named object that is not there is a
    // complete answer with nothing in it, and it is reached without emitting anything, so
    // nothing downstream has to distinguish it from a failure that emitted first.
    let (objects, freshness, listed) = match answer {
        // Unless the search that chose the collection skipped a group. An object absent from the
        // resource one group serves is not an object the cluster does not have, and `absent` is
        // the one word in §21.4's vocabulary that is evidence about the cluster (§34.2, §35.8).
        Answer::Absent if !unread.is_empty() => return Outcome::Failed(absence_unproven(unread)),
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
        // was asked for and one object arrived. What may still be partial is the *search* that
        // decided which collection that was (§34.2, §35.8).
        if unread.is_empty() {
            return Outcome::Completed;
        }
        return Outcome::Failed(read_over_incomplete_search(unread));
    };
    // §48.6: the resources that answered stay visible, with explicit incomplete coverage. The
    // group-versions the search could not read join the listing's own gaps rather than replacing
    // them — a denied namespace and an unavailable API group are two different holes in one
    // answer, and Appendix D.3's report names both.
    let coverage = match (coverage.is_empty(), unread.is_empty()) {
        (_, true) => coverage,
        (true, false) => describe(unread),
        (false, false) => format!("{coverage}; {}", describe(unread)),
    };
    if complete && unread.is_empty() {
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
         unserved API, an API group whose own server did not answer and an exhausted page budget \
         are different things, and none of them means the cluster is empty.",
    ))
}

/// A read that answered over a search which could not cover every group (§34.2, §35.8).
fn read_over_incomplete_search(unread: &[Gap]) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "the object that arrived is true, and the search that chose which resource to read \
             it from could not read every API group: {}",
            describe(unread),
        ),
        "A group whose own API server did not answer is not a group with nothing in it \
         (specification sections 34.2 and 21.4). Another group may serve this kind too, and \
         section 35.8 does not let this provider assume otherwise. Name `group` to settle it.",
    )
}

/// An object absent from the one resource an incomplete search resolved to.
fn absence_unproven(unread: &[Gap]) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "the resource the search resolved to holds no such object, and the search could not \
             read every API group: {}",
            describe(unread),
        ),
        "Absence is the one outcome in section 21.4's vocabulary that is evidence about the \
         cluster rather than about the query, and a search that skipped a group has not earned \
         it. Name `group` to ask one collection, and this becomes an answer again.",
    )
}

/// Discovers what serves the target's kind, then reads it — one object, or the collection.
fn read<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    target: &'static Target,
    endpoint: &Endpoint,
    selector: &Selector,
    lookup: Option<&str>,
) -> Result<(Answer, Shape, Vec<Gap>), WireError> {
    let core = document(session, client, endpoint, "/api")?;
    let groups = document(session, client, endpoint, "/apis")?;
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

    // §34.2's report, carried from the search all the way to the outcome. Empty for every
    // target that names its own group: a curated kind is one group-version's business, and
    // failing to read *that* group is failing to answer the question that was asked.
    let mut unread: Vec<Gap> = Vec::new();
    let (resource, shape) = match target.reads {
        Reads::Kind { group, kind } => {
            let resource = curated(session, client, endpoint, &served, group, kind)?;
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
        // Nor is an observed change: `changes::answer` acquires the collection itself, because
        // §19.1's list-then-watch is one sequence and splitting it across two routes would let a
        // watch open from a version no listing here produced.
        Reads::Changes => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                "a change is observed rather than listed, so there is no collection of changes \
                 to read"
                    .to_owned(),
                "Ask what changed with `get k8s-change --kind ...`, which lists the collection \
                 and then watches it from the version that listing returned.",
            ));
        }
        // Nor is any of the six questions that are *about* one object rather than about a
        // collection of anything. Each is routed by its own handler long before a collection is
        // chosen, and each arm is written out rather than folded into a catch-all so that a
        // seventh reading cannot silently fall through to a wrong one.
        Reads::Events
        | Reads::Evidence
        | Reads::Logs
        | Reads::Timeline
        | Reads::Why
        | Reads::Conditions => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                "this question is asked about one named object rather than about a collection"
                    .to_owned(),
                "Pass `kind` and `name` — for example `get k8s-event --kind Pod --name \
                 api-7d9f-abc` — so that the answer is about one lifetime rather than about a \
                 name several objects have had.",
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
        // Nor is a prospective change: `planning::answer` reads the one object the change is
        // aimed at and builds a plan from it, and a listing of plans would be a listing of
        // changes nobody has asked for.
        Reads::Plan => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                "a plan describes a change to one object rather than a collection of objects"
                    .to_owned(),
                "Ask what a change would do with `get k8s-plan --kind ... --name ... --set ...`, \
                 which reads that one object and describes the change against what it holds.",
            ));
        }
        Reads::Discovered => {
            // §34.2 and §48.6: the search goes on past a group-version that did not answer, and
            // what it could not read travels with the answer instead of ending it.
            let searched = search(session, client, endpoint, &served, selector)?;
            let resource = searched.resolve(selector, Verb::List)?;
            unread.extend_from_slice(searched.gaps());
            let typing = typing_of(session, client, endpoint, &resource)?;
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
        // §20.2's other origin. A session that is watching this collection has already been told
        // what is in it, and answering from that cache is the only way a record's provenance
        // ever says anything but `direct-read`. `Lookup` is four answers rather than an
        // `Option` for exactly this call site: a cache that is still synchronising, or one whose
        // continuity broke, must fall through to the wire rather than report an absence it is
        // not entitled to (§20.3, §4 invariant 13).
        match session.lookup(resource.gvr(), &scope, scope.namespace(), name) {
            Lookup::Cached(read) => {
                let (object, freshness) = read.into_parts();
                return Ok((
                    Answer::Fetched(Box::new((object, freshness))),
                    shape,
                    unread,
                ));
            }
            Lookup::ConfirmedAbsent => return Ok((Answer::Absent, shape, unread)),
            Lookup::NotWatched | Lookup::NotSynced(_) => {}
        }
        return Ok((fetch(client, &resource, &scope, name)?, shape, unread));
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
        unread,
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

/// The whole preferred discovery surface, as one snapshot (§4 invariants 1–2, §5.2).
///
/// Two documents rather than a compile-time table, and read through the session so that the
/// second question of one session is free (§50.2). Every handler that resolves a kind the query
/// named starts here.
///
/// # Errors
///
/// A wire failure, or an endpoint that answered but not as a Kubernetes API server.
pub(crate) fn served<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
) -> Result<Discovery, WireError> {
    let core = document(session, client, endpoint, "/api")?;
    let groups = document(session, client, endpoint, "/apis")?;
    Ok(Discovery::builder()
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
        .build())
}

/// One object a question is *about*, read at its own endpoint (§17.1).
///
/// Four targets ask a question whose subject is one named object — its Events, its conditions,
/// what is known to have happened to it, and what may be said about the state it is in — and all
/// four need exactly this: the resource discovery resolved, the scope it lives in, the object
/// across the redaction boundary, and the freshness of the read. Assembling it once is what stops
/// four handlers disagreeing about which of them is the object's namespace.
pub(crate) struct Subject {
    /// What discovery said serves the kind the query named.
    pub(crate) resource: Resource,
    /// The scope the object was read in — the query's namespace, or cluster scope (§9.2).
    pub(crate) scope: Scope,
    /// The object, past the one door into the emission path (§22, Gate I).
    pub(crate) guarded: Guarded,
    /// What §17.1 requires the read to state about itself.
    pub(crate) freshness: Freshness,
}

/// Reads the object a question is about, or [`None`] where it is not there.
///
/// [`None`] is §21.4's `absent` and nothing else: a `404` on one object's own endpoint is the one
/// outcome that is evidence of absence rather than a statement about what could not be seen. A
/// denial, an unserved API and a failed request are refusals, and every one of them comes back as
/// an error (ADR-0012).
///
/// # Errors
///
/// Whatever kept the object from being read, in the vocabulary of core's `errors.yaml`.
pub(crate) fn subject<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    selector: &Selector,
    name: &str,
) -> Result<Option<Subject>, WireError> {
    let catalogue = served(session, client, endpoint)?;
    let resource = resolve_in(session, client, endpoint, &catalogue, selector, Verb::Get)?;
    let scope = scope_for(endpoint, &resource);
    let (object, freshness) = match fetch(client, &resource, &scope, name)? {
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
    Ok(Some(Subject {
        resource,
        scope,
        guarded: hold(object)?,
        freshness,
    }))
}

/// The scope a resource of this shape is read in (§9.2).
///
/// A cluster-scoped resource has no namespace, and inventing one for it would be a request the
/// server rejects for a reason that has nothing to do with what was asked.
pub(crate) fn scope_for(endpoint: &Endpoint, resource: &Resource) -> Scope {
    match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => endpoint.scope.clone(),
    }
}

/// Takes one object across the redaction boundary (§22, Gate I).
///
/// # Errors
///
/// A defect in this provider rather than anything a cluster can cause, reported as one.
pub(crate) fn hold(object: Object) -> Result<Guarded, WireError> {
    Guarded::hold(object).map_err(|error| {
        failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("an object could not be taken across the redaction boundary: {error}"),
            "This is a defect in the Kubernetes provider, not in the cluster.",
        )
    })
}

/// Hands one record to the host, or says why the invocation is over.
///
/// [`Err`] carries the outcome the caller returns unchanged: a cancelled stream and a refused
/// record end an invocation in different ways, and neither is something a handler continues past.
pub(crate) fn deliver(ctx: &mut Ctx<'_>, value: &Value) -> Result<(), Outcome> {
    match ctx.emit(value) {
        Ok(()) => Ok(()),
        Err(EmitError::Cancelled) => Err(Outcome::Cancelled),
        Err(error) => Err(Outcome::Failed(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("the host refused a record: {error}"),
            "The stream ended before the query did.",
        ))),
    }
}

/// Builds one record, or says why the table and the schema have drifted apart.
///
/// # Errors
///
/// [`Outcome::Failed`], because a record that does not fit its own declared schema is a defect in
/// this crate's table and never something a cluster can cause.
pub(crate) fn built(
    target: &'static Target,
    value: Result<Value, ono_value::ErrorValue>,
) -> Result<Value, Outcome> {
    value.map_err(|error| {
        Outcome::Failed(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!(
                "a record of `{}` could not be built: {error}",
                target.schema
            ),
            "This is a defect in the Kubernetes provider's schema table.",
        ))
    })
}

/// A question about one object that did not say which object.
pub(crate) fn unnamed(what: &str, example: &str) -> WireError {
    failure(
        AMBIGUOUS_CODE,
        AMBIGUOUS,
        format!("the query named no `name`, so it did not say which object {what}"),
        &format!(
            "Pass `kind` and `name` — for example `{example}` — and `namespace` where the kind is \
             namespaced."
        ),
    )
}

/// The resource serving a kind this package named at build time (§15.2).
pub(crate) fn curated<S: ByteStream>(
    session: &mut Session,
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
    let discovery = resource_list(session, client, endpoint, &group_version)?;
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
///
/// §11.5's third state is a resource the server serves and does not let a caller enumerate, and
/// `watch` is a fourth permission on the same collection. Resolving for the verb the question
/// actually needs is what keeps a refusal saying which grant is missing rather than which grant
/// this code happened to ask about first (§60.5, ADR-0012).
///
/// For a caller that can carry a coverage report, [`search`] is the entry point: this one turns
/// an incomplete search into a refusal, because a `Resource` has nowhere to say that the search
/// behind it skipped a group (§34.2, §35.8).
pub(crate) fn resolve_in<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    selector: &Selector,
    verb: Verb,
) -> Result<Resource, WireError> {
    let searched = search(session, client, endpoint, served, selector)?;
    let resource = searched.resolve(selector, verb)?;
    // A caller reached through this signature has a `Resource` to put the answer in and nowhere
    // to put a coverage report, so the incompleteness has to travel as a refusal. That is not a
    // concession to convenience in the other direction either: §35.8 forbids resolving a name
    // several types share by anything but disambiguation, and a search that skipped a group has
    // not established that only one type has it. The routes that *can* carry coverage —
    // `k8s-resource` and `k8s-relation` — use [`search`] directly and keep the values.
    if !searched.is_complete() {
        return Err(unproven_resolution(selector, &searched));
    }
    Ok(resource)
}

/// Reads the discovery of every group-version the query could match in, and records the ones that
/// did not answer instead of failing over them (§34.2, §48.6, §4 invariant 16).
pub(crate) fn search<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    selector: &Selector,
) -> Result<Searched, WireError> {
    let group_versions = search_space(served, selector)?;
    let mut builder = Discovery::builder();
    let mut unread = Vec::new();
    for group_version in &group_versions {
        let outcome = match group_document(session, client, endpoint, group_version)? {
            // The group answered, and not as a Kubernetes API server. Still a fact about *that*
            // group rather than about the cluster (§34.3), so it is recorded as a `503` is —
            // and `add_resources` keeps the groups that did read.
            GroupRead::Document(list) => match builder.add_resources(&list) {
                Ok(()) => continue,
                Err(_) => Coverage::RequestFailed,
            },
            GroupRead::Unread(outcome) => outcome,
        };
        unread.push(Gap::new(Scope::in_group_version(group_version), outcome));
    }
    Ok(Searched {
        discovery: builder.build(),
        unread,
    })
}

/// One search over the served API surface: what answered, and what did not (§34.2).
///
/// The type exists so that "the groups that answered" and "the groups that did not" cannot drift
/// apart on the way to the answer. Every consumer of the first has to hold the second, which is
/// what stops an incomplete search from quietly presenting itself as a complete one (§35.8).
pub(crate) struct Searched {
    discovery: Discovery,
    unread: Vec<Gap>,
}

impl Searched {
    /// Whether every group-version in the search space answered.
    pub(crate) fn is_complete(&self) -> bool {
        self.unread.is_empty()
    }

    /// The group-versions that did not answer, as coverage gaps (§34.2's second sentence).
    pub(crate) fn gaps(&self) -> &[Gap] {
        &self.unread
    }

    /// The one resource the selector names among the group-versions that answered.
    ///
    /// # Errors
    ///
    /// Whatever the selector did not resolve to, said in terms an incomplete search is entitled
    /// to: a kind missing from a search that skipped a group is not a kind the cluster does not
    /// serve (§21.4, §4 invariant 13).
    pub(crate) fn resolve(&self, selector: &Selector, verb: Verb) -> Result<Resource, WireError> {
        dynamic::resolve_for(selector, &self.discovery, verb)
            .cloned()
            .map_err(|unresolved| {
                unresolved_over(&unresolved, selector, &self.discovery, &self.unread)
            })
    }
}

/// One group-version's resource list, or the reason the search has to do without it.
pub(crate) enum GroupRead {
    /// The resource list, as the group's server answered it.
    Document(String),
    /// It did not answer, and this is what became of it (§21.4's vocabulary, plus §34.2's word).
    Unread(Coverage),
}

/// One group-version's resource list, read so that its failure stays its own (§34.2, §34.3).
///
/// [`document`] is the right shape for `/api` and `/apis`: they are how the provider learns what
/// is served at all, and a cluster that refuses them cannot be read. A group-version is not that.
/// An aggregated one is served by a *second* API server behind the aggregation layer, and §34.2
/// forbids that server's outage becoming this provider's — so a non-`200` becomes a coverage
/// outcome and the search goes on without it.
///
/// A transport failure is still an error, because that is the connection under every remaining
/// request breaking rather than one group declining to answer over a connection that works.
pub(crate) fn group_document<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    group_version: &str,
) -> Result<GroupRead, WireError> {
    let path = resource_list_path(group_version);
    if let Some(held) = session.discovery_document(&path) {
        return Ok(GroupRead::Document(held.to_owned()));
    }
    let request =
        endpoint.authorise(Request::get(path.clone()).header("Accept", "application/json"));
    let response = client
        .connection()
        .send(&request)
        .map_err(|error| transport_failure(&path, &error))?;
    if response.status() != 200 {
        return Ok(GroupRead::Unread(unread_outcome(response.status())));
    }
    let Ok(text) = String::from_utf8(response.body().to_vec()) else {
        return Ok(GroupRead::Unread(Coverage::RequestFailed));
    };
    session.cache_discovery_document(&path, text.clone());
    Ok(GroupRead::Document(text))
}

/// What a status code means for a group-version that was listed and did not answer.
///
/// §34.3 in one function: the outcome names what happened to *this group*, so that an operator
/// reads which `APIService` to look at rather than "the cluster failed". §48.2 keeps
/// `service_unavailable` apart from a request that merely errored, and this is that distinction
/// in the coverage vocabulary.
fn unread_outcome(status: u16) -> Coverage {
    match status {
        403 => Coverage::ReadDenied,
        // The group was in the list and is not there now: a CRD or an `APIService` withdrawn
        // between the two requests, which is §11.5's state rather than a failure.
        404 | 410 => Coverage::TypeNotServed,
        502..=504 => Coverage::Unavailable,
        _ => Coverage::RequestFailed,
    }
}

/// A selector that resolved to one candidate over a search that could not read every group.
///
/// §35.8's property, kept where §34.2's isolation would otherwise quietly buy it away: one
/// candidate found among the groups that answered is not one candidate served by the cluster.
fn unproven_resolution(selector: &Selector, searched: &Searched) -> WireError {
    failure(
        UNAVAILABLE_CODE,
        UNAVAILABLE,
        format!(
            "{} resolved against the API groups that answered, and the search could not read \
             every group it had to cover: {}",
            selector.spelling(),
            describe(searched.gaps()),
        ),
        "A group whose own API server did not answer is not a group with nothing in it \
         (specification sections 34.2 and 21.4), so one candidate found here is not proof that \
         only one type has this name (section 35.8). Name `group` to ask a group that answers.",
    )
}

/// Every gap in words, as Appendix D.3 writes a coverage row.
pub(crate) fn describe(gaps: &[Gap]) -> String {
    gaps.iter()
        .map(Gap::describe)
        .collect::<Vec<_>>()
        .join("; ")
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
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    resource: &Resource,
) -> Result<Typing, WireError> {
    // §12.4's cache, and the first thing in this package that reads it. The key is the GVK
    // rather than the document's path, because that is what a schema describes and what §12.4's
    // invalidation rules are written in terms of: a CRD whose structural schema changed, a group
    // version withdrawn, a cluster replaced.
    if let Some(cached) = session.schema(resource.gvk()) {
        return Ok(Typing::from_schema(cached.clone()));
    }
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
    let typing = Typing::of(
        document.as_deref(),
        resource.group(),
        resource.version(),
        resource.kind(),
    );
    // Cached even when the server published nothing: an absent schema is an answer about this
    // cluster (§12.3), and re-asking a server that has already said no is §50.2's cost paid for
    // a document that will not be there next time either.
    session.cache_schema(resource.gvk().clone(), typing.schema().clone());
    Ok(typing)
}

/// One group-version's resource list, as a snapshot of its own.
pub(crate) fn resource_list<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    group_version: &str,
) -> Result<Discovery, WireError> {
    let list = document(
        session,
        client,
        endpoint,
        &resource_list_path(group_version),
    )?;
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

/// A selector that did not resolve, over a search that could not read every group (§34.2).
///
/// The refusal has to be *weaker* than the one a complete search earns. §21.4 and §4 invariant 13
/// draw the line: "not served" is a fact about the cluster, and a search that skipped a group has
/// not established it — the kind may live in exactly the group that did not answer. Every other
/// refusal survives, with the unread groups appended so that nothing in it reads as complete.
pub(crate) fn unresolved_over(
    unresolved: &Unresolved,
    selector: &Selector,
    discovery: &Discovery,
    unread: &[Gap],
) -> WireError {
    if unread.is_empty() {
        return unresolved_failure(unresolved, selector, discovery);
    }
    if matches!(unresolved, Unresolved::NotServed) {
        return failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!(
                "nothing among the API groups that answered matches {}, and the search could \
                 not read every group: {}",
                selector.spelling(),
                describe(unread),
            ),
            "A group whose own API server did not answer is not a group with nothing in it \
             (specification sections 34.2 and 21.4), so this is an incomplete search rather than \
             a kind the cluster does not serve. Retry when the group answers, or name `group` to \
             ask one that does.",
        );
    }
    let mut error = unresolved_failure(unresolved, selector, discovery);
    error.help = Some(format!(
        "{}\n\nThe search could not read every API group, so what it did find is over an \
         incomplete search space: {}.",
        error.help.unwrap_or_default(),
        describe(unread),
    ));
    error
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
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    path: &str,
) -> Result<String, WireError> {
    // §50.2, in one branch. `/api`, `/apis` and a resource list are the same three documents
    // every invocation asked for, and the session is what makes the second query in a session
    // free. The documents are held rather than the assembled snapshot because the snapshot a
    // query resolves against must cover exactly the group-versions that query searched — see
    // `Session::discovery_document`.
    if let Some(held) = session.discovery_document(path) {
        return Ok(held.to_owned());
    }
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
    let text = String::from_utf8(response.body().to_vec()).map_err(|error| {
        failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("the API server's answer to `{path}` is not text: {error}"),
            "A discovery document is JSON.",
        )
    })?;
    session.cache_discovery_document(path, text.clone());
    Ok(text)
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
    /// How this endpoint proves who it is — the kind, never the material (§8.1).
    ///
    /// Beside [`Self::authorization`] rather than derived from it: a client certificate proves an
    /// identity and puts no header on a request, so an endpoint with no `Authorization` is not
    /// the same thing as an anonymous one.
    pub(crate) credential: Credential,
    /// The namespace the context this endpoint came from starts navigation in (§7.5).
    ///
    /// Distinct from [`Self::scope`], which is what *this query* asked about. The session records
    /// the first as a fact about the configuration and never the second, because a scope one
    /// invocation chose has no business surviving into the next (§6.5).
    pub(crate) default_namespace: Option<String>,
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
    /// (§7.4), or neither — in which case the kubeconfig's own `current-context` is taken.
    ///
    /// §7.1 lists "current context as an optional default" among the elements this provider MUST
    /// support, and the default is what makes this package reachable from the spatial layer at
    /// all: the shell invokes a contributed target with **no arguments** when it re-reads a place
    /// or resolves the end of a contributed edge, so a provider that refuses to default cannot be
    /// entered, cannot be looked at without being reported gone, and has no neighbours. ADR-0027.
    ///
    /// It stays a default rather than a guess. Which context answered is on every record's
    /// provenance as `provider_instance=kubernetes:<context>` (§6.2, §7.4), a file that elects no
    /// context is refused with the ones it does define, and a kubeconfig that could not be read
    /// is refused rather than replaced by an endpoint nobody named.
    pub(crate) fn resolve(ctx: &mut Ctx<'_>) -> Result<Self, WireError> {
        let mut options = ctx.arguments().clone();
        if names_an_endpoint(&options) {
            remember_endpoint(&options);
        } else {
            replay_standing_endpoint(&mut options);
        }
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
            (None, context) => Self::from_kubeconfig(ctx, &options, context.as_deref()),
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
            // §7.3's endpoint carries no credential at all, and saying so is not the same as
            // saying nothing: the API server decides what an anonymous request means.
            credential: Credential::Anonymous,
            default_namespace: None,
        })
    }

    /// An endpoint resolved from a kubeconfig context (§7.1, §7.4, §8).
    ///
    /// `context` is [`None`] where the query named none, and the file's `current-context` is then
    /// the answer. A read that failed is reported as itself where a context was named and as
    /// "nothing named an API server" where none was, because a query that asked for no cluster in
    /// particular has not been denied a kubeconfig — it has simply not said which cluster it
    /// meant, and §4's "missing permission is not absence" is served by naming the read failure in
    /// the help rather than by dropping it.
    fn from_kubeconfig(
        ctx: &mut Ctx<'_>,
        options: &JsonMap<String, Json>,
        context: Option<&str>,
    ) -> Result<Self, WireError> {
        let path = options
            .get("kubeconfig")
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
            .unwrap_or(DEFAULT_KUBECONFIG)
            .to_owned();
        let document = match read_file(ctx, &path, "the kubeconfig") {
            Ok(document) => document,
            Err(error) if context.is_none() => return Err(no_endpoint_and_no_kubeconfig(&error)),
            Err(error) => return Err(error),
        };
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
        let contexts = |config: &Kubeconfig| -> String {
            let known: Vec<&str> = config.contexts().collect();
            if known.is_empty() {
                "none".to_owned()
            } else {
                known.join(", ")
            }
        };
        // §7.1's "current context as an optional default". A file that elects none has not chosen
        // a cluster, and choosing one here would be this package deciding which cluster the
        // operator meant — which is exactly what §7.4 keeps explicit.
        let context = match context {
            Some(context) => context.to_owned(),
            None => match config.current_context() {
                Some(current) => current.to_owned(),
                None => {
                    return Err(failure(
                        UNAVAILABLE_CODE,
                        UNAVAILABLE,
                        format!(
                            "the query named neither a kubeconfig `context` nor a `host`, and \
                             `{path}` elects no `current-context` to fall back to"
                        ),
                        &format!(
                            "`{path}` defines these contexts: {}. Pass one as `context`, or pass \
                             `host` (and `port`, which defaults to 8001) to name an endpoint \
                             directly, which speaks plain HTTP/1.1 and so reaches an API server \
                             through `kubectl proxy` rather than over TLS.",
                            contexts(&config)
                        ),
                    ));
                }
            },
        };
        let context = context.as_str();
        let connection = config.connection(context).map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("{error}"),
                &format!(
                    "`{path}` defines these contexts: {}. Naming one that is not there is a \
                     different answer from connecting to the wrong one.",
                    contexts(&config)
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
            credential: connection.credential(),
            default_namespace: connection.namespace().map(str::to_owned),
        })
    }

    /// What makes this invocation the same session as the last one (§6.2, §6.5).
    ///
    /// Everything in the key is something the operator configured; nothing in it is something
    /// the cluster said. §10.3 is the reason for the second half: two instances that reach one
    /// cluster share a fingerprint and are still two instances, so a key that included what the
    /// cluster answered would merge exactly the pair §10.3 forbids merging.
    pub(crate) fn session_key(&self) -> Key {
        Key {
            instance: self.instance.clone(),
            endpoint: self.server_url(),
            transport: match &self.tls {
                None => "plaintext",
                Some(settings) if settings.verifies_certificates() => "tls-verified",
                Some(_) => "tls-unverified",
            },
        }
    }

    /// A session for this endpoint, holding nothing yet (§6.3, §6.4).
    ///
    /// The credential's *kind* travels into the session and its material does not. §8.1 draws
    /// that line, and holding it here is what makes a session safe to keep across invocations: a
    /// rotated token takes effect on the next call rather than at the end of a process, and no
    /// invocation can be answered with a credential another one resolved.
    pub(crate) fn start_session(&self) -> Session {
        Session::for_endpoint(
            self.instance.clone(),
            self.server_url(),
            self.default_namespace.as_deref(),
            self.credential,
        )
    }

    /// The API server as a URL, which is how §6.3 records an endpoint.
    fn server_url(&self) -> String {
        let scheme = if self.tls.is_some() { "https" } else { "http" };
        format!("{scheme}://{}:{}", self.host, self.port)
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

/// The options an invocation that named a cluster is remembered by.
///
/// Only what an operator typed: nothing the cluster answered and nothing resolved from a
/// credential. Replaying these re-reads the kubeconfig and re-resolves the credential from
/// scratch, so §8.1's boundary is untouched — a rotated token takes effect on the next call, as
/// it does on the path that named the endpoint outright.
///
/// The last four are not "which cluster" but "which collection", and they are here because
/// `k8s-resource` needs them to answer at all: a place entered from a query that named a kind is
/// re-read by an invocation carrying none, and a re-read that cannot name the collection reports
/// a live object as gone. The cost is that one process remembers one such query, so a place of a
/// kind older than the last `k8s-resource` question is re-read against the newer kind and answers
/// as absent. That is the shape of the gap rather than a decision taken here: the shell has no
/// way to tell a package which place it is re-reading (ADR-0027).
const STANDING_OPTIONS: &[&str] = &[
    "host",
    "port",
    "context",
    "kubeconfig",
    "namespace",
    "all_namespaces",
    "max_pages",
    "kind",
    "group",
    "version",
    "resource",
];

/// The endpoint options of the last invocation in this process that named one (§6.5, §7.4).
///
/// A `Mutex` rather than a `RefCell` because a package may answer more than one invocation at a
/// time, and what is behind it is a plain map of what somebody typed.
fn standing_endpoint() -> &'static std::sync::Mutex<Option<JsonMap<String, Json>>> {
    static STANDING: std::sync::OnceLock<std::sync::Mutex<Option<JsonMap<String, Json>>>> =
        std::sync::OnceLock::new();
    STANDING.get_or_init(|| std::sync::Mutex::new(None))
}

/// An invocation's own arguments, with the standing query's filled in where it named nothing.
///
/// The same merge [`Endpoint::resolve`] makes, exposed for the one caller that needs more of it
/// than the endpoint: which collection to read.
pub(crate) fn standing_arguments(ctx: &Ctx<'_>) -> JsonMap<String, Json> {
    let mut options = ctx.arguments().clone();
    if !names_an_endpoint(&options) {
        replay_standing_endpoint(&mut options);
    }
    options
}

/// Whether these options say which API server the query is about.
fn names_an_endpoint(options: &JsonMap<String, Json>) -> bool {
    ["host", "context"].iter().any(|key| {
        options
            .get(*key)
            .and_then(Json::as_str)
            .is_some_and(|value| !value.is_empty())
    })
}

/// Records what an invocation named, so that a later one that names nothing can stand where this
/// one stood (§6.5).
fn remember_endpoint(options: &JsonMap<String, Json>) {
    let standing: JsonMap<String, Json> = STANDING_OPTIONS
        .iter()
        .filter_map(|key| {
            options
                .get(*key)
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect();
    if let Ok(mut held) = standing_endpoint().lock() {
        *held = Some(standing);
    }
}

/// Puts the standing endpoint back into an invocation that named none.
///
/// **This is what makes the package reachable from the spatial layer** (ADR-0027). The shell
/// invokes a contributed target with no arguments at all when it re-reads a place (§33.2 of the
/// generic provider contract) or resolves the end of a contributed edge, and the invocation
/// carries no way to say which cluster the place was entered from. What it does carry is the
/// process: the same loaded instance answered the query the operator wrote, so the cluster they
/// named is the cluster that is still standing.
///
/// It is not a guess and it cannot switch behind an operator's back, which is §7.4's rule. The
/// only thing replayed is what somebody typed, an invocation that names an endpoint of its own
/// keeps it and replaces the standing one, and every record still carries
/// `provider_instance=kubernetes:<context>` so a reader can see which cluster answered.
fn replay_standing_endpoint(options: &mut JsonMap<String, Json>) {
    let Ok(held) = standing_endpoint().lock() else {
        return;
    };
    let Some(standing) = held.as_ref() else {
        return;
    };
    for (key, value) in standing {
        options.entry(key.clone()).or_insert_with(|| value.clone());
    }
}

/// No endpoint was named and the kubeconfig that would have defaulted one did not read.
///
/// The read failure travels in the help rather than being dropped: a denied `filesystem.read` is
/// a capability decision and an absent file is a fact about the machine, and neither of them is
/// "there is no cluster" (§4 invariant 13, §21.4).
fn no_endpoint_and_no_kubeconfig(cause: &WireError) -> WireError {
    let mut refusal = no_endpoint();
    refusal.help = Some(format!(
        "{}\n\nThe kubeconfig that would have supplied a default was not read: {}",
        refusal.help.unwrap_or_default(),
        cause.message
    ));
    refusal
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

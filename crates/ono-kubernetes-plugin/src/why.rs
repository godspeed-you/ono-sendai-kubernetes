//! What may be said about the state one object is in, and the rung above which it may not climb
//! (§40).
//!
//! `causal.rs` is the ladder: five claims, of which none says that one thing brought about
//! another. This module is the route to it, and the route is where the discipline is easiest to
//! lose — a boundary that assembled the findings into a sentence, or ranked them, or dropped the
//! ones that established nothing, would undo in a rendering what the type system spent a module
//! preventing.
//!
//! So the answer is **one record per finding**, and:
//!
//! - `claim` carries the module's own word, verbatim: `CAUSALITY_NOT_PROVEN`, `CORRELATED_WITH`,
//!   `PRECEDED_BY`, `DEPENDENCY_PATH_EXISTS`, `ASSERTED_BY_KUBERNETES`. There is no sixth, here
//!   or anywhere;
//! - `claim_means` travels beside it, because a token on its own is read as strongly as its
//!   reader needs it to be. `CORRELATED_WITH` arrives with "one clock saw both, close together;
//!   proximity is not a causal link" attached;
//! - `strongest_claim` is on **every** record rather than on a summary somebody may not read, and
//!   it is the maximum of the ladder and never a sum: three weak findings do not add up to a
//!   strong one, and a score is how they would;
//! - **there is no field a reader could mistake for a cause.** No `cause`, no `because`, no
//!   `root_cause`, no `explanation`, no `impact`. `tests/query.rs` reads this package's declared
//!   field names and fails if one appears.
//!
//! Where the findings come from, and where they stop:
//!
//! - **The relationship graph, walked** (§23, §40.3). The subject's edges are derived by the one
//!   rule set that answers `get k8s-relation` — `relations::derive` — so a path a user
//!   reads hop by hop and one they are shown whole cannot disagree. An edge the API server
//!   asserts — an owner reference, a native field — is reported as `ASSERTED_BY_KUBERNETES`
//!   (§23.4). An edge this provider derived — a selector it evaluated, a convention, an adapter's
//!   rule — is `DEPENDENCY_PATH_EXISTS`: influence *could* have travelled along it, and whether
//!   it did is not in the graph. Beyond the first hop, `depth` says how far the walk reads, up to
//!   a bound; every object is read once, a cycle is a path that stops, and a walk stopped by its
//!   read budget says so as a coverage gap rather than by coming back shorter (§49.1, §18.3).
//!   A selector this provider evaluated is never promoted to an assertion however confident the
//!   match — that would be exactly the derived-as-proven blur §4 invariant 20 forbids.
//! - **A controller acknowledgement** (§37.3, §40.4). `observedGeneration` equal to
//!   `metadata.generation` is the API's own record that whoever wrote this status had seen this
//!   spec. It is an assertion about who acted on what, and §40.4 keeps it from being the origin
//!   of any particular state change.
//! - **Events** (§38.3). `regarding` is API structure, so the link between a reporter and the
//!   object is asserted. The Event's `reason` and `note` are not promoted with it: §38.5 makes
//!   those evolving strings, and a claim resting on one is an unversioned dependency.
//! - **Proximity and order**, per clock, over the observations `timeline.rs` assembled. Two
//!   observations one clock wrote, close together, come back `CORRELATED_WITH` and cannot come
//!   back as anything stronger whatever window they are given. Two observations on *two* clocks
//!   come back `CAUSALITY_NOT_PROVEN` with `different clocks wrote the two timestamps` — a
//!   refusal rather than a number (§39.2).
//!
//! §40.5's required conclusion is reachable and cheap: an answer with nothing above the bottom
//! rung says `insufficient_evidence`, which the specification calls preferable to a plausible
//! invented explanation.

use std::sync::Arc;

use ono_kuang_sdk::Ctx;
use ono_kuang_sdk::Outcome;
use ono_kuang_sdk::protocol::WireError;
use ono_provider_kubernetes::causal::{Expansion, Finding, Unproven, Walk, WalkBounds, Why};
use ono_provider_kubernetes::condition;
use ono_provider_kubernetes::coverage::{Coverage, Gap, Outcome as CoverageOutcome, Scope};
use ono_provider_kubernetes::discovery::{self, Discovery, Verb};
use ono_provider_kubernetes::relationship::Target as FarEnd;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::temporal::Observation;
use ono_provider_kubernetes::transport::{ByteStream, Client, Operation, SystemClock};
use ono_value::Schema;
use serde_json::{Map as JsonMap, Value as Json};

use crate::conditions::named;
use crate::contributions::Target;
use crate::dynamic::Selector;
use crate::events::{self, Reported};
use crate::query::{self, Conversation, Endpoint, Subject, UNSUPPORTED, UNSUPPORTED_CODE, failure};
use crate::records::finding_record;
use crate::relations::{self, Listings};
use crate::sessions::Sessions;
use crate::timeline;

/// How far apart two observations on one clock may be and still be reported as correlated.
///
/// A minute, and it is an option (`within_ms`) rather than a constant an operator cannot see: the
/// window is the whole content of a correlation claim, and one nobody can state is one nobody can
/// argue with. Whatever it is set to, the claim it can produce is still `CORRELATED_WITH`.
const DEFAULT_WINDOW_MILLIS: u64 = 60_000;

/// Answers a `k8s-why` query: one object in, what may honestly be said about it out.
#[must_use]
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let selector = Selector::from_options(ctx.arguments());
    let Some(name) = named(ctx) else {
        return Outcome::Failed(query::unnamed(
            "to answer about",
            "--kind Pod --name api-7d9f-abc",
        ));
    };
    let within = ctx
        .arguments()
        .get("within_ms")
        .and_then(Json::as_u64)
        .unwrap_or(DEFAULT_WINDOW_MILLIS);
    let bounds = match bounds_of(ctx.arguments()) {
        Ok(bounds) => bounds,
        Err(error) => return Outcome::Failed(error),
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
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
                Examined {
                    endpoint: &endpoint,
                    selector: &selector,
                    name: &name,
                    session,
                    bounds,
                },
            )
        },
    );
    match read {
        Ok(read) => emit(ctx, target, &schema, read.as_ref(), within),
        Err(error) => Outcome::Failed(error),
    }
}

/// How far the dependency walk goes, from the `depth` option (§40.3).
///
/// One hop when nobody says — the subject's own edges — and never more than the bound: a
/// question silently answered for a shallower depth than it asked would be a wrong answer that
/// looks right, so a depth past the bound, or no depth at all, is refused by name.
fn bounds_of(arguments: &JsonMap<String, Json>) -> Result<WalkBounds, WireError> {
    let Some(asked) = arguments.get("depth") else {
        return Ok(WalkBounds::default());
    };
    let refused = |what: &str| {
        failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("`depth` {what}"),
            &format!(
                "`depth` is how many relationship hops the dependency walk follows from the \
                 object: 1 is its own edges, and at most {} are followed, each further hop \
                 reading the objects the last one reached (specification section 40.3). Ask a \
                 deeper question of the object the last hop reached.",
                WalkBounds::MAX_HOPS
            ),
        )
    };
    let hops = asked
        .as_u64()
        .and_then(|hops| usize::try_from(hops).ok())
        .ok_or_else(|| refused("is not a whole number of hops"))?;
    if hops == 0 {
        return Err(refused("names no hop at all"));
    }
    WalkBounds::new(hops).map_err(|error| refused(&error.to_string()))
}

/// Resolve the object, read it, read the Events of its scope, and walk its relationships.
struct Examined<'a> {
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    name: &'a str,
    session: &'a mut Session,
    bounds: WalkBounds,
}

/// Everything one `why` reasons over: the object, what was reported about it, and the graph
/// around it as far as the walk went.
struct Examination {
    subject: Subject,
    reported: Reported,
    walk: Walk,
    /// The scopes a derivation of the subject's own edges could not read (§21.4).
    unread: Vec<Gap>,
    /// The selectors a derivation of the subject's own edges declined to evaluate (ADR-0007).
    unevaluated: Vec<String>,
}

impl Conversation for Examined<'_> {
    type Answer = Option<Examination>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        let Some(subject) =
            query::subject(session, client, self.endpoint, self.selector, self.name)?
        else {
            return Ok(None);
        };
        // A scope whose Events cannot be read is a gap on the answer rather than a refusal of
        // it: the object's own edges and timestamps are still worth having, and the coverage
        // says what is missing beside them.
        let reported = events::read(session, client, self.endpoint, &subject.scope)?;

        // The subject's edges, by the rules `k8s-relation` answers with and no others.
        let served = query::served(session, client, self.endpoint)?;
        let mut derived = relations::derive(
            session,
            client,
            self.endpoint,
            &served,
            &subject.scope,
            subject.guarded.clone(),
            subject.freshness.clone(),
            Vec::new(),
            Listings::new(),
        )?;
        let edges = std::mem::take(&mut derived.edges);
        let mut listings = std::mem::take(&mut derived.listings);
        let identity = subject.guarded.object().identity();
        let walk = Walk::explore(&identity, self.bounds, edges, |far_end| {
            expand(
                session,
                client,
                self.endpoint,
                &served,
                &subject.scope,
                &mut listings,
                far_end,
            )
        })?;
        Ok(Some(Examination {
            subject,
            reported,
            walk,
            unread: derived.coverage.gaps().to_vec(),
            unevaluated: derived.unevaluated,
        }))
    }
}

/// Reads the object at the far end of an edge and derives its edges, or says why it could not.
///
/// The same read `get k8s-resource --name` makes, and the same derivation `get k8s-relation`
/// makes, so that the walk can only ever show a user what those two would have shown them one
/// step at a time. Three things are answers rather than errors (§21.4): an object that is not
/// there, a kind this cluster does not serve or serves ambiguously, and a read the API server
/// refused. A broken connection is an error, because it is the connection under every remaining
/// read.
fn expand<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    subject_scope: &Scope,
    listings: &mut Listings,
    far_end: &FarEnd,
) -> Result<Expansion, WireError> {
    let selector = selector_for(far_end);
    let searched = query::search(session, client, endpoint, served, &selector)?;
    let mut gaps = searched.gaps().to_vec();
    let fallback_scope = far_end
        .namespace()
        .map_or_else(|| subject_scope.clone(), Scope::in_namespace);
    let resource = match searched.resolve(&selector, Verb::Get) {
        Ok(resource) => resource,
        // Unserved, ambiguous between groups, or served without `get`: nothing beyond this edge
        // can be read, and the edge itself stands. Which of the three it was is a fact about
        // the cluster's API surface rather than about the object, and `NotQueried` is what
        // became of the object — nobody could ask (§21.4, §35.8).
        Err(_) => {
            gaps.push(Gap::new(fallback_scope, CoverageOutcome::NotQueried));
            return Ok(Expansion::Unread(gaps.remove(gaps.len() - 1)));
        }
    };
    let scope = match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => fallback_scope,
    };
    match client.get(resource.gvr(), &scope, far_end.name()) {
        Ok(read) => {
            let (object, freshness) = read.into_parts();
            // §22 and Gate I: a far end crosses the redaction boundary before anything derives
            // from it, so a walk that reaches a Secret cannot reach its payload.
            let guarded = query::hold(object)?;
            let derived = relations::derive(
                session,
                client,
                endpoint,
                served,
                &scope,
                guarded,
                freshness,
                gaps,
                std::mem::take(listings),
            )?;
            *listings = derived.listings;
            Ok(Expansion::Edges {
                edges: derived.edges,
                gaps: derived.coverage.gaps().to_vec(),
                unevaluated: derived.unevaluated,
            })
        }
        Err(error) => match error.outcome(Operation::Get) {
            CoverageOutcome::Absent => Ok(Expansion::Absent),
            CoverageOutcome::Disconnected => {
                Err(query::transport_failure(&resource.gvr().path(), &error))
            }
            outcome => Ok(Expansion::Unread(Gap::new(scope, outcome))),
        },
    }
}

/// The far end of an edge, as the selector `get k8s-resource` would resolve it by.
///
/// The kind always, and the group where the reference carried an `apiVersion` — an owner
/// reference does, a `spec.nodeName` does not. Without a group the search covers every group the
/// server lists, and a kind two groups share is refused as ambiguous rather than picked (§35.8).
fn selector_for(far_end: &FarEnd) -> Selector {
    let mut options = JsonMap::new();
    options.insert("kind".to_owned(), Json::String(far_end.kind().to_owned()));
    if let Some(api_version) = far_end.api_version() {
        let group = api_version.split_once('/').map_or("", |(group, _)| group);
        options.insert("group".to_owned(), Json::String(group.to_owned()));
    }
    Selector::from_options(&options)
}

/// Gathers everything this provider is prepared to say, refusals included (§40.5).
fn gather(examination: &Examination, within_millis: u64) -> Why {
    let Examination {
        subject,
        reported,
        walk,
        unread,
        unevaluated,
    } = examination;
    let object = subject.guarded.object();
    let identity = object.identity();

    // What the search could and could not reach, from every read it made: the Events of the
    // scope, the collections the subject's own edges needed, and everything the walk read or was
    // stopped from reading. "Nothing was found" over a denied namespace and over a complete read
    // are different answers (§21.4, §4 invariant 13).
    let mut coverage: Coverage = reported.coverage.clone();
    for gap in unread.iter().chain(walk.gaps()) {
        coverage.record(gap.clone());
    }
    if walk.was_cut_short() {
        coverage.more_available();
    }
    let mut why = Why::about(identity.clone(), coverage);

    // §23 and §40.3: the graph, as far as it was walked. An owner reference or a native field is
    // an assertion of the API server's and gets the top rung; everything this provider derived
    // is a path along which influence was possible, and nothing more.
    for finding in walk.findings() {
        why.add(finding.clone());
    }
    // ADR-0007 at the boundary: a selector this provider does not evaluate leaves part of the
    // neighbourhood undetermined, and the paths that were found are not all of them. One refusal
    // however many selectors, because it is one fact about the answer.
    if !unevaluated.is_empty() || !walk.unevaluated().is_empty() {
        why.add(Finding::nothing(identity.clone(), Unproven::NotEvaluated));
    }

    // §37.3 and §40.4: the controller writing this condition had seen this generation. A stale
    // `observedGeneration` produces `NotAsserted` rather than a weaker claim, because a status
    // written about an older spec asserts nothing about the current one.
    for observed in condition::conditions(object) {
        why.add(Finding::controller_acknowledged(
            identity.clone(),
            object,
            &observed,
        ));
    }

    // §38.3: an Event's `regarding` is API structure, so the link between the reporter and this
    // object is asserted rather than guessed.
    for (_, event) in &reported.read {
        if event.regards(&identity) {
            why.add(Finding::event_regards(identity.clone(), event));
        }
    }

    // §23.4 of the generic contract, held structurally: proximity and order, on one clock at a
    // time. `Timeline::ordered_on` refuses to place a stamp on a clock that did not write it, so
    // the pairs below are never two machines' idea of the time — and where they would be, the
    // finding comes back `CAUSALITY_NOT_PROVEN` naming the reason rather than a number.
    let timeline = timeline::assemble(subject, reported, &SystemClock);
    for clock in timeline.clocks() {
        let ordered = timeline.ordered_on(&clock);
        for pair in ordered.sequence().windows(2) {
            let [earlier, later] = pair else { continue };
            close(&mut why, earlier, later, within_millis);
        }
    }

    // §40.5's required answer, where nothing was gathered at all. A search that found nothing is
    // still an answer about the search, and an empty stream would be an answer about nothing.
    if why.findings().is_empty() {
        why.add(Finding::nothing(identity, Unproven::NoEvidence));
    }
    why
}

/// The two things one clock may say about two observations, and neither is a cause.
///
/// Proximity and order are separate rungs because precedence discharges more of the burden:
/// closeness says the two were near each other, order says which way round. Both are recorded,
/// including where they establish nothing, because a refusal is evidence about the search and an
/// answer with the refusals dropped looks like one where nobody looked (§4 invariant 13).
fn close(why: &mut Why, earlier: &Observation, later: &Observation, within_millis: u64) {
    let subject = earlier.subject().clone();
    why.add(Finding::proximity(
        subject.clone(),
        earlier,
        later,
        within_millis,
    ));
    why.add(Finding::precedence(subject, earlier, later));
}

/// Streams one record per finding, each carrying the ceiling of the whole answer.
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    read: Option<&Examination>,
    within_millis: u64,
) -> Outcome {
    // An object that is not there is in no state, and that is an answer rather than a refusal
    // (§21.4 `absent`).
    let Some(examination) = read else {
        return Outcome::Completed;
    };
    let why = gather(examination, within_millis);
    let subject = &examination.subject;
    for finding in why.findings() {
        if ctx.cancelled() {
            return Outcome::Cancelled;
        }
        let value = match query::built(
            target,
            finding_record(
                target,
                schema,
                &subject.guarded,
                finding,
                &why,
                &subject.freshness,
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

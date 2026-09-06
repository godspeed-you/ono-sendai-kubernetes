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
//! - **Assertions** (§23.4). An owner reference or a native field is something the API server
//!   states, so it gets the top rung. A selector this provider evaluated is not an assertion
//!   however confident the match, and it produces no finding here at all — it is a relationship
//!   with a stated evidence class, reachable as `k8s-relation`, and promoting it would be exactly
//!   the derived-as-proven blur §4 invariant 20 forbids.
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

use ono_kuang_sdk::{Ctx, Outcome};
use ono_provider_kubernetes::causal::{Finding, Unproven, Why};
use ono_provider_kubernetes::condition;
use ono_provider_kubernetes::relationship::Graph;
use ono_provider_kubernetes::temporal::Observation;
use ono_provider_kubernetes::transport::SystemClock;
use ono_value::Schema;
use serde_json::Value as Json;

use crate::conditions::named;
use crate::contributions::Target;
use crate::dynamic::Selector;
use crate::events::Reported;
use crate::query::{self, Endpoint, Subject};
use crate::records::finding_record;
use crate::sessions::Sessions;
use crate::timeline::{self, Observed};

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
                Observed {
                    endpoint: &endpoint,
                    selector: &selector,
                    name: &name,
                    session,
                },
            )
        },
    );
    match read {
        Ok(read) => emit(ctx, target, &schema, read.as_ref(), within),
        Err(error) => Outcome::Failed(error),
    }
}

/// Gathers everything this provider is prepared to say, refusals included (§40.5).
fn gather(subject: &Subject, reported: &Reported, within_millis: u64) -> Why {
    let object = subject.guarded.object();
    let identity = object.identity();
    let mut why = Why::about(identity.clone(), reported.coverage.clone());

    // §23.4: what Kubernetes states itself. Only the classes the API server asserts — a native
    // field and an owner reference — reach this rung; a selector this provider evaluated is a
    // relationship with its evidence stated, and it is not an assertion (§23.3).
    for edge in Graph::edges_of(object) {
        if edge.evidence().is_asserted_by_provider() {
            why.add(Finding::asserted(identity.clone(), &edge));
        }
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
    read: Option<&(Subject, Reported)>,
    within_millis: u64,
) -> Outcome {
    // An object that is not there is in no state, and that is an answer rather than a refusal
    // (§21.4 `absent`).
    let Some((subject, reported)) = read else {
        return Outcome::Completed;
    };
    let why = gather(subject, reported, within_millis);
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

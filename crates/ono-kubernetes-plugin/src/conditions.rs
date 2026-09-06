//! The structured observations one object's controllers wrote about it (§37.1).
//!
//! `condition.rs` parses conditions for anything and judges convergence only where it has a rule
//! it can name. This module is the route from a query to those observations and back out as
//! records, and it exists because §37.1's "expose conditions as structured observations" was, up
//! to now, true only of the five kinds whose schema carries a `reconciliation` map — every other
//! kind's conditions reached nobody.
//!
//! Two rules shape it.
//!
//! **One condition is one record.** A Deployment can be `Available=True` on its old replicas
//! while `Progressing=False` because the new ones never came up, and any rendering that reduces
//! the pair to one word loses exactly the half an operator needs (§4 invariant 9). A record per
//! condition is also what makes `type`, `status`, `reason` and `message` filterable rather than
//! buried in a list field.
//!
//! **`observedGeneration` arrives as a number.** It is evidence that a controller saw a desired
//! state and by itself it is nothing more (§37.3). The only derived thing on the record is the
//! `reconciliation` map, which carries the rule that produced it and the fields that rule read
//! (§37.5) — and its `verified_convergence` key is false for `generation-observed-only`, which is
//! what a matching `observedGeneration` on its own establishes. There is no `healthy` field here,
//! and its absence is the point.
//!
//! An object that states no conditions answers with no records and completes. That is not the
//! refusal `events.rs` and `logs.rs` make: the object was read, its `status` carries no
//! `conditions`, and *that* is a fact about the object rather than about the search.

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, Outcome};
use ono_provider_kubernetes::condition;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{ByteStream, Client};
use ono_value::Schema;
use serde_json::Value as Json;

use crate::contributions::Target;
use crate::dynamic::Selector;
use crate::query::{self, Conversation, Endpoint, Subject};
use crate::records::condition_record;
use crate::sessions::Sessions;

/// Answers a `k8s-condition` query: one object in, its conditions out.
#[must_use]
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let selector = Selector::from_options(ctx.arguments());
    let Some(name) = named(ctx) else {
        return Outcome::Failed(query::unnamed(
            "to read the conditions of",
            "--kind Deployment --name api",
        ));
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
        Ok(read) => emit(ctx, target, &schema, read.as_ref()),
        Err(error) => Outcome::Failed(error),
    }
}

/// The `name` option, where the query gave a non-empty one.
pub(crate) fn named(ctx: &mut Ctx<'_>) -> Option<String> {
    ctx.arguments()
        .get("name")
        .and_then(Json::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// Resolve the object the query named, and read it.
struct Observed<'a> {
    endpoint: &'a Endpoint,
    selector: &'a Selector,
    name: &'a str,
    session: &'a mut Session,
}

impl Conversation for Observed<'_> {
    type Answer = Option<Subject>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        query::subject(
            self.session,
            client,
            self.endpoint,
            self.selector,
            self.name,
        )
    }
}

/// Streams one record per condition the object states.
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    subject: Option<&Subject>,
) -> Outcome {
    // An object that is not there has no conditions, and that is an answer rather than a refusal
    // (§21.4 `absent`, §60.5).
    let Some(subject) = subject else {
        return Outcome::Completed;
    };
    for condition in condition::conditions(subject.guarded.object()) {
        if ctx.cancelled() {
            return Outcome::Cancelled;
        }
        let value = match query::built(
            target,
            condition_record(
                target,
                schema,
                &subject.guarded,
                &condition,
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

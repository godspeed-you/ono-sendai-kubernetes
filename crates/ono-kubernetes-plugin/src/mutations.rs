//! The two words that change a cluster, and everything they are made to say about themselves.
//!
//! Specification §43 to §46, §56, Gate G (§62.7) and Gate H (§62.8).
//! `ono_provider_kubernetes::mutation` holds the request, the answer and the verdict; this module
//! is the boundary that reaches them — and it is where the four rules that keep a write from
//! being reachable by accident are actually enforced.
//!
//! **A mutation is a command, not a target.** `get` is a read verb (§21.2 of the generic
//! contract), and a contributed *target* has nowhere to declare a risk or a capability: its wire
//! shape is a name, a schema, a summary and an identity note. A contributed *command* declares
//! both, and the host checks the capability at every invocation before this module runs at all.
//! So `set k8s-resource` and `remove k8s-resource` are commands, on core's own verbs (§31.22).
//!
//! **The default is a prediction.** `dry_run` is true unless the invocation says otherwise, so
//! the shortest sentence a user can write asks the API server to run admission and defaulting and
//! persist nothing (§44.5). A dry run establishes no rung of §20.4's ladder — nothing was
//! written — and the record labels it as a provider-native prediction rather than an observation
//! (§21.4 of the generic contract).
//!
//! **An acceptance reaches one rung.** `MutationOutcome::established_stage` answers
//! `Stage::ApiAccepted` for a write and nothing for anything else, and no field of the emitted
//! record can carry a stronger word. Everything above that rung comes from a later observation,
//! which this module makes exactly once, immediately, with a deadline of zero — so evidence that
//! is not decisive at once is `Inconclusive`, which §46.4 defines as neither failure nor success.
//! That is Gate G with no room left for a friendlier sentence.
//!
//! **Force is a reason.** There is no `force` flag. `force_because` takes the sentence a reviewer
//! will read, and without it a conflict is an answer that names the owning manager and stops
//! (§44.3, §44.4). Nothing here retries.

use std::sync::Arc;
use std::time::Duration;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, EmitError, Outcome as InvocationOutcome};
use ono_provider_kubernetes::coverage::Outcome as Coverage;
use ono_provider_kubernetes::mutation::{
    Acceptance, ApplyOptions, Deadline, DeleteOptions, Deletion, FieldManager, MutationError,
    MutationOutcome, Observation, Verification, admission_differences_of, apply_document,
    apply_request, delete_request,
};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::plan::{Plan, VerificationRule};
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{
    ByteStream, Client, ObservedAt, Operation, Request, Response,
};
use ono_value::{ErrorValue, MapValue, Provenance, RecordValue, Schema, Value};
use serde_json::{Map as JsonMap, Value as Json};

use crate::contributions::{Command, SchemaDef, Writes};
use crate::planning::{self, Intent, Planned, plan_on};
use crate::query::{
    Conversation, Endpoint, UNAVAILABLE, UNAVAILABLE_CODE, converse, failure, transport_failure,
};
use crate::sessions::Sessions;

/// How long verification may wait before it reports that it did not finish (§46.4).
///
/// Zero, and that is a statement rather than a placeholder. This invocation looks at the target
/// exactly once, immediately after the write, and then ends; it is not waiting for anything. So
/// evidence that is not decisive at that moment never became decisive within the window there
/// was, which §46.4 calls `Inconclusive` — "not evidence that the change failed, and not evidence
/// that it succeeded". Reporting it as `Pending` would promise a second look that nobody is going
/// to take.
const VERIFICATION_WINDOW: Duration = Duration::ZERO;

/// Answers one contributed command: plan the change, make it, and say what that establishes.
#[must_use]
pub fn answer(
    command: &'static Command,
    sessions: &Sessions,
    ctx: &mut Ctx<'_>,
) -> InvocationOutcome {
    let Some(declared) = crate::contributions::COMMAND_SCHEMAS
        .iter()
        .find(|schema| schema.id == command.schema)
    else {
        return InvocationOutcome::Failed(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!(
                "`{}` names a schema this package does not contribute",
                command.name
            ),
            "This is a defect in the Kubernetes provider's contribution table.",
        ));
    };
    let schema = match declared.contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return InvocationOutcome::Failed(error.into()),
    };
    let intent = match Intent::of(ctx.arguments(), command.writes) {
        Ok(intent) => intent,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    let how = match How::read(ctx.arguments()) {
        Ok(how) => how,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    if ctx.cancelled() {
        return InvocationOutcome::Cancelled;
    }

    let made = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            converse(
                ctx,
                &endpoint,
                Mutating {
                    writes: command.writes,
                    intent: &intent,
                    how: &how,
                    endpoint: &endpoint,
                    session,
                },
            )
        },
    );
    let made = match made {
        Ok(made) => made,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    let value = match record(declared, &schema, &made) {
        Ok(value) => value,
        Err(error) => {
            return InvocationOutcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("a record of `{}` could not be built: {error}", declared.id),
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
            format!("the host refused the mutation record: {error}"),
            "The change was made or refused before this; the stream ended after it.",
        )),
    }
}

/// How the change is sent: as a prediction or as a write, under whose name, and forcing what.
#[derive(Debug, Clone)]
struct How {
    dry_run: bool,
    manager: FieldManager,
    force_because: Option<String>,
}

impl How {
    /// What the invocation's arguments ask for.
    ///
    /// `dry_run` defaults to **true**. §44.5 asks for a server dry run as the mutation preview,
    /// and the way to make a preview the easy path is to make it the one that needs no argument:
    /// a user who meant to write says so, and a user who typed the command to see what it would
    /// do has not changed anything.
    fn read(options: &JsonMap<String, Json>) -> Result<Self, WireError> {
        let manager = match options.get("field_manager").and_then(Json::as_str) {
            Some(name) => FieldManager::named(name).map_err(|error| {
                failure(
                    planning::REFUSED_CODE,
                    planning::REFUSED,
                    format!("{error}"),
                    "Server-side apply records field ownership under this name, so it has to \
                     name somebody (§44.2). Leave it out to apply as `ono-sendai`.",
                )
            })?,
            None => FieldManager::ono(),
        };
        Ok(Self {
            dry_run: options
                .get("dry_run")
                .and_then(Json::as_bool)
                .unwrap_or(true),
            manager,
            // §44.4: the only way to force is a sentence saying why. There is deliberately no
            // `force` boolean to set, because the shortest path to a green apply must not be
            // flipping a flag on the day somebody is in a hurry.
            force_because: options
                .get("force_because")
                .and_then(Json::as_str)
                .filter(|reason| !reason.trim().is_empty())
                .map(str::to_owned),
        })
    }

    fn apply_options(&self) -> ApplyOptions {
        let mut options = ApplyOptions::new(self.manager.clone());
        if self.dry_run {
            options = options.as_dry_run();
        }
        if let Some(reason) = &self.force_because {
            options = options.force_conflicts_because(reason.clone());
        }
        options
    }

    fn delete_options(&self) -> DeleteOptions {
        let options = DeleteOptions::new();
        if self.dry_run {
            options.as_dry_run()
        } else {
            options
        }
    }
}

/// One attempt at a change: what was planned, what came back, and what a later look established.
pub(crate) struct Made {
    plan: Plan,
    outcome: MutationOutcome,
    manager: FieldManager,
    forced_because: Option<String>,
    dry_run: bool,
    deletion: Option<Deletion>,
    verification: Option<Verification>,
    admission: Vec<String>,
}

/// The exchange a mutation is: discovery, one read, the write, and one look afterwards.
struct Mutating<'a> {
    writes: Writes,
    intent: &'a Intent,
    how: &'a How,
    endpoint: &'a Endpoint,
    session: &'a mut Session,
}

impl Conversation for Mutating<'_> {
    type Answer = Made;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        // The same first step as `get k8s-plan`, deliberately: a mutation *is* a plan that was
        // then carried out, and a second route from arguments to a request would be a second
        // place for a precondition to go missing (§46.1, §56).
        let planned = plan_on(self.session, client, self.endpoint, self.intent)?;
        match self.writes {
            Writes::Fields => apply(client, self.endpoint, &planned, self.how),
            Writes::Object => delete(client, self.endpoint, &planned, self.how),
        }
    }
}

/// Sends the apply, reads what it means, and looks once at the target afterwards.
fn apply<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    planned: &Planned,
    how: &How,
) -> Result<Made, WireError> {
    let options = how.apply_options();
    let document = apply_document(&planned.plan).map_err(unbuildable)?;
    let request =
        apply_request(&planned.plan, planned.resource.gvr(), &options).map_err(unbuildable)?;
    let response = send(client, endpoint, request)?;
    let outcome = MutationOutcome::read(&planned.plan, options.dry_run(), &response);
    let admission = admission(&outcome, &document);
    let verification = verify(client, planned, &outcome, None);
    Ok(Made {
        plan: planned.plan.clone(),
        manager: options.manager().clone(),
        forced_because: options.forced_because().map(str::to_owned),
        dry_run: options.dry_run().is_dry_run(),
        outcome,
        deletion: None,
        verification,
        admission,
    })
}

/// Sends the delete, reads where it leaves the object, and looks once at the target afterwards.
fn delete<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    planned: &Planned,
    how: &How,
) -> Result<Made, WireError> {
    let options = how.delete_options();
    let request =
        delete_request(&planned.plan, planned.resource.gvr(), &options).map_err(unbuildable)?;
    let response = send(client, endpoint, request)?;
    let outcome = MutationOutcome::read(&planned.plan, options.dry_run(), &response);
    // The refusal is already in `outcome`; `Deletion::read` boxes a second copy of it for the
    // caller that has none, and this one does.
    let mut deletion = Deletion::read(&planned.plan, &options, &response).ok();
    let verification = verify(client, planned, &outcome, deletion.as_mut());
    Ok(Made {
        plan: planned.plan.clone(),
        manager: FieldManager::ono(),
        forced_because: None,
        dry_run: options.dry_run().is_dry_run(),
        outcome,
        deletion,
        verification,
        admission: Vec::new(),
    })
}

/// Looks at the target once, and says what that look establishes about the change (§46.3).
///
/// Only after a write. A dry run persisted nothing, so there is nothing to look for; a refusal
/// did not happen, so there is nothing to verify. Looking anyway would spend a request to
/// discover that the object is as it was, and would tempt a reader into treating the answer as
/// being about a change that was never made.
fn verify<S: ByteStream>(
    client: &mut Client<S>,
    planned: &Planned,
    outcome: &MutationOutcome,
    deletion: Option<&mut Deletion>,
) -> Option<Verification> {
    if !outcome.requires_verification() {
        return None;
    }
    let name = planned.plan.target().name();
    let (observation, now) = match client.get(planned.resource.gvr(), &planned.scope, name) {
        Ok(read) => {
            let now = read.freshness().observed_at();
            let (object, _) = read.into_parts();
            (Looked::Object(Box::new(object)), now)
        }
        Err(error) => {
            let outcome = error.outcome(Operation::Get);
            // §21.4 where it costs the most: a `403` on the follow-up read is a permission
            // boundary, and reading it as "the object is gone" would turn a deletion nobody can
            // see into a deletion that finished.
            let looked = if outcome == Coverage::Absent {
                Looked::Absent
            } else {
                Looked::Unobservable(outcome)
            };
            (looked, ObservedAt::from_unix_millis(0))
        }
    };
    if let Some(deletion) = deletion {
        match &observation {
            Looked::Object(object) => deletion.observe(object),
            Looked::Absent => deletion.observe_absence(Coverage::Absent),
            Looked::Unobservable(outcome) => deletion.observe_absence(*outcome),
        }
    }
    let deadline = Deadline::starting_at(now, VERIFICATION_WINDOW);
    Some(Verification::of(
        &planned.plan,
        observation.as_observation(),
        &deadline,
        now,
    ))
}

/// What the follow-up read found, owned so that the borrow ends with the request.
///
/// The object is boxed for the same reason the transport boxes its `Status` payloads: an object
/// is two orders of magnitude larger than the two answers that carry no object, and the case
/// that carries nothing should not be sized by the case that carries everything.
enum Looked {
    Object(Box<Object>),
    Absent,
    Unobservable(Coverage),
}

impl Looked {
    fn as_observation(&self) -> Observation<'_> {
        match self {
            Self::Object(object) => Observation::Object(object),
            Self::Absent => Observation::Absent,
            Self::Unobservable(outcome) => Observation::Unobservable(*outcome),
        }
    }
}

/// What admission and defaulting did to the document on the way in (§44.6).
///
/// The returned object crosses the redaction boundary before it is compared, so a mutating
/// webhook's rewrite of a Secret's payload cannot become a difference a record carries (§22).
fn admission(outcome: &MutationOutcome, requested: &Json) -> Vec<String> {
    let Some(returned) = outcome.returned() else {
        return Vec::new();
    };
    let Ok(guarded) = Guarded::hold(returned.clone()) else {
        return Vec::new();
    };
    admission_differences_of(requested, guarded.object())
        .iter()
        .map(planning::describe_change)
        .collect()
}

/// Sends one request with whatever credential the context resolved to.
fn send<S: ByteStream>(
    client: &mut Client<S>,
    endpoint: &Endpoint,
    request: Request,
) -> Result<Response, WireError> {
    let path = request.path().to_owned();
    let request = endpoint.authorise(request);
    client
        .connection()
        .send(&request)
        .map_err(|error| transport_failure(&path, &error))
}

/// A request `mutation.rs` would not build.
fn unbuildable(error: MutationError) -> WireError {
    failure(
        planning::REFUSED_CODE,
        planning::REFUSED,
        format!("this change was refused before anything was sent: {error}"),
        "Nothing was sent to the cluster. The refusal is about the change as it was written, not \
         about what the API server would have done with it.",
    )
}

// --- the record ---------------------------------------------------------------------------------

/// One attempt at a change, as a record of the mutation schema.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares.
fn record(declared: &SchemaDef, schema: &Arc<Schema>, made: &Made) -> Result<Value, ErrorValue> {
    let provenance = Provenance::local(crate::PACKAGE, schema.id().clone());
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance);
    for field in declared.fields {
        builder = builder.set(field.name, mutation_field(field.name, made))?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// One field of a mutation record, by the name the schema declares it under.
fn mutation_field(name: &str, made: &Made) -> Value {
    match name {
        "acceptance" => Value::String(acceptance(made.outcome.acceptance()).into()),
        "dry_run" => Value::Bool(made.dry_run),
        // §21.4 of the generic provider contract: a prediction says which of the four kinds it
        // is. A write is not a prediction at all, so the field is null rather than a word.
        "prediction" => {
            if made.dry_run {
                Value::String(
                    "provider-native dry run: the API server ran admission and defaulting and \
                     wrote nothing. It predicts API acceptance, not what controllers do \
                     afterwards (§44.5)"
                        .into(),
                )
            } else {
                Value::Null
            }
        }
        "code" => Value::Int(i128::from(made.outcome.code())),
        // Gate G lives here. `established_stage` is `ApiAccepted` for a write and nothing at all
        // for a dry run or a refusal, and there is no other field on this record that could
        // carry a stronger claim.
        "stage" => made
            .outcome
            .established_stage()
            .map_or(Value::Null, |stage| Value::String(stage.as_str().into())),
        "field_manager" => Value::String(made.manager.as_str().into()),
        "forced" => Value::Bool(made.forced_because.is_some()),
        "forced_because" => made
            .forced_because
            .as_deref()
            .map_or(Value::Null, |reason| Value::String(reason.into())),
        "conflict_fields" => made.outcome.conflict().map_or(Value::Null, |conflict| {
            Value::List(
                conflict
                    .fields()
                    .iter()
                    .map(|field| Value::String(field.field().into()))
                    .collect(),
            )
        }),
        "conflict_managers" => made.outcome.conflict().map_or(Value::Null, |conflict| {
            Value::List(
                conflict
                    .managers()
                    .into_iter()
                    .map(|manager| Value::String(manager.into()))
                    .collect(),
            )
        }),
        "resolution" => made.outcome.conflict().map_or(Value::Null, |conflict| {
            Value::String(conflict.resolution().to_string().into())
        }),
        "admission_differences" => {
            if made.admission.is_empty() {
                Value::Null
            } else {
                Value::List(
                    made.admission
                        .iter()
                        .map(|difference| Value::String(difference.as_str().into()))
                        .collect(),
                )
            }
        }
        // Gate H lives here. `DeletionState` has three members and no `is_deleted`, so the word
        // "deleted" is not something this field can produce.
        "deletion_state" => made.deletion.as_ref().map_or(Value::Null, |deletion| {
            Value::String(deletion.state().as_str().into())
        }),
        "finalizers" => made.deletion.as_ref().map_or(Value::Null, |deletion| {
            Value::List(
                deletion
                    .pending_finalizers()
                    .iter()
                    .map(|finalizer| Value::String(finalizer.as_str().into()))
                    .collect(),
            )
        }),
        "verification" => Value::String(made.plan.verification_rule().as_str().into()),
        "verdict" => made
            .verification
            .as_ref()
            .map_or(Value::Null, |verification| {
                Value::String(verification.verdict().as_str().into())
            }),
        "verification_detail" => made
            .verification
            .as_ref()
            .map_or(Value::Null, |verification| {
                Value::String(verification.describe().into())
            }),
        "reconciliation" => made
            .verification
            .as_ref()
            .and_then(Verification::reconciliation)
            .map_or(Value::Null, |state| {
                let mut map = MapValue::new();
                map.insert(
                    Arc::from("state"),
                    Value::String(state.state().as_str().into()),
                );
                map.insert(Arc::from("rule"), Value::String(state.rule().into()));
                map.insert(
                    Arc::from("verified_convergence"),
                    Value::Bool(state.state().is_verified_convergence()),
                );
                map.insert(
                    Arc::from("evidence"),
                    Value::List(
                        state
                            .citations()
                            .iter()
                            .map(|citation| Value::String(citation.to_string().into()))
                            .collect(),
                    ),
                );
                Value::Map(Arc::new(map))
            }),
        "statement" => Value::String(statement(made).into()),
        other => planning::target_field(other, &made.plan),
    }
}

/// The word an acceptance is reported under.
///
/// Deliberately five words and none of them "succeeded": what the API server did with the request
/// is not what became of the cluster (§4 invariant 18).
fn acceptance(acceptance: &Acceptance) -> &'static str {
    match acceptance {
        Acceptance::Persisted => "persisted",
        Acceptance::DryRun => "dry run",
        Acceptance::Conflict(_) => "conflict",
        Acceptance::PreconditionFailed(_) => "precondition failed",
        Acceptance::Refused(_) => "refused",
    }
}

/// Everything one attempt amounts to, in the sentences the domain layer wrote for it.
///
/// Assembled from `MutationOutcome::describe`, `Deletion::describe` and
/// `Verification::describe` rather than written again here, so that the sentence a user reads is
/// the same one the tests of §43 to §46 hold to their invariants. Nothing is added; the order is
/// the only choice this function makes.
fn statement(made: &Made) -> String {
    let mut lines = vec![made.outcome.describe()];
    if let Some(deletion) = &made.deletion {
        lines.push(deletion.describe());
    }
    match &made.verification {
        Some(verification) => lines.push(verification.describe()),
        None => lines.push(format!(
            "nothing was written, so there is nothing to verify; the rule that would have \
             applied is: {}",
            made.plan.verification_rule()
        )),
    }
    if made.plan.verification_rule() == VerificationRule::NoneKnown {
        lines.push(
            "this provider has no rule for what success would look like here, so acceptance is \
             all that will ever be known about it (§46.3)"
                .to_owned(),
        );
    }
    lines.join("; ")
}

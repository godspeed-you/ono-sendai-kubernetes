//! What a change would do, answered before anything is changed.
//!
//! Specification §46 (prospective change), §56 (preconditions) and §43.3 (a bounded action
//! surface). `ono_provider_kubernetes::plan` holds the reasoning; this module is the boundary
//! that reaches it — it reads the object the change is aimed at, turns the invocation's arguments
//! into field changes against what that object actually holds, and answers a record.
//!
//! Four properties decide the shape of everything below.
//!
//! **Asking is a read.** `k8s-plan` is a *target*, so `get k8s-plan` answers it and it changes
//! nothing: discovery, the `GET` of the object, and §21.2's `SelfSubjectAccessReview` — which is
//! a `POST` by the REST verb and a question by its semantics, because the API server computes the
//! answer and stores no object. There is no server dry run on this path: a dry-run `PATCH` is a
//! write-shaped request that runs admission webhooks, and a target a user may point at anything
//! must not do that. The plan says so — `Caveat::AdmissionEffectsNotPreviewed` — rather than
//! leaving the omission to be inferred, and the dry run lives on `set k8s-resource`, where the
//! risk is declared (§44.5, ADR-0024).
//!
//! **The permission check is advisory and never an authorizer.** §21.1 leaves the API server the
//! only authority, so the review's answer is a plan field (§46.2, Appendix E's `AUTHORIZATION`
//! line) and every plan carries a caveat about it: a grant can lapse before the request, and
//! everything that is not an explicit denial — an unserved review API, an authorizer with no
//! opinion, a review the server would not answer — is §21.4's `not queried` rather than a
//! refusal this package invented.
//!
//! **Preconditions come from the object or the plan is refused.** Nothing an invocation can say
//! supplies a `resourceVersion` or a UID: the only source is the object that
//! was read, which is what makes §56 travel rather than be described. `Plan::of` refuses a target
//! that cannot supply one, and the refusal is passed through with the sentence that names what
//! the missing precondition would have prevented.
//!
//! **The change is expressed against what the object holds.** `--set '{"/spec/replicas": 1}'`
//! becomes `FieldChange::change("/spec/replicas", 3, 1)` when the field is there and
//! `FieldChange::set` when it is not, so a plan states the before as well as the after (§46.2). A
//! `--unset` of a field the object does not carry is dropped rather than sent, because removing
//! an absent field changes nothing and taking field ownership of it is not what was asked.
//!
//! **The object crosses the redaction boundary first.** Everything here works from a
//! [`Guarded`], so a plan that touches a Secret states which keys change without ever holding a
//! payload to state (§22, Gate I).

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, EmitError, Outcome as InvocationOutcome};
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::{self, Discovery, Resource, Verb};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::plan::{
    Action, Dependent, Effect, FieldChange, Plan, PlanRefusal, Preconditions, Preflight,
    Propagation, access_review,
};
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{ByteStream, Client, create_request};
use ono_value::{ErrorValue, MapValue, Provenance, RecordValue, Schema, Value};
use serde_json::{Map as JsonMap, Value as Json};

use crate::contributions::{Field, Target, Writes};
use crate::dynamic::Selector;
use crate::query::{
    Answer, Conversation, Endpoint, UNAVAILABLE, UNAVAILABLE_CODE, UNSUPPORTED, UNSUPPORTED_CODE,
    converse, document, failure, fetch, group_version_of, resolve_in, resource_list,
};
use crate::sessions::Sessions;

pub(crate) use crate::query::{REFUSED, REFUSED_CODE};

/// What a plan or a mutation was asked to do, read from one invocation's arguments.
///
/// Deliberately small, and deliberately missing two things. There is no `resource_version` and no
/// `uid` argument, because §56's preconditions come from the object that was read and a caller
/// who could type one could aim a change at an object nobody looked at. And there is no `force`
/// flag: forcing is a *reason*, and it lives on the apply options rather than here (§44.4).
#[derive(Debug, Clone)]
pub(crate) struct Intent {
    selector: Selector,
    name: String,
    wanted: Wanted,
}

/// The two shapes §43.3's candidate actions reduce to.
#[derive(Debug, Clone)]
enum Wanted {
    /// A bounded set of field changes, by JSON pointer.
    Apply {
        set: Vec<(String, Json)>,
        unset: Vec<String>,
    },
    /// The object, with the propagation policy the invocation chose (§45.2).
    Delete { propagation: Propagation },
}

impl Intent {
    /// What the arguments ask for, where the caller may ask for either (the `k8s-plan` target).
    ///
    /// # Errors
    ///
    /// A refusal naming what the arguments did not say.
    pub(crate) fn read(options: &JsonMap<String, Json>) -> Result<Self, WireError> {
        let action = options
            .get("action")
            .and_then(Json::as_str)
            .unwrap_or("apply");
        match action {
            "apply" => Self::of(options, Writes::Fields),
            "delete" => Self::of(options, Writes::Object),
            other => Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("`action {other}` is not a change this provider plans"),
                "§43.3 keeps the action surface bounded: `apply` states a set of field changes, \
                 `delete` removes the object. Every candidate action of that section reduces to \
                 one of the two.",
            )),
        }
    }

    /// What the arguments ask for, where the *command* already decided which kind of write it is.
    ///
    /// # Errors
    ///
    /// A refusal naming what the arguments did not say.
    pub(crate) fn of(options: &JsonMap<String, Json>, writes: Writes) -> Result<Self, WireError> {
        let name = options
            .get("name")
            .and_then(Json::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                failure(
                    UNSUPPORTED_CODE,
                    UNSUPPORTED,
                    "the invocation named no object to change".to_owned(),
                    "§21.3 of the generic provider contract: a change is resolved to one object \
                     before it is made, so `name` is required. A change aimed at a collection is \
                     not something this provider does.",
                )
            })?
            .to_owned();
        let wanted = match writes {
            Writes::Fields => Wanted::Apply {
                set: pointers(options)?,
                unset: unset(options)?,
            },
            Writes::Object => Wanted::Delete {
                propagation: propagation(options)?,
            },
        };
        Ok(Self {
            selector: Selector::from_options(options),
            name,
            wanted,
        })
    }

    /// Which resource the change is aimed at, as the invocation named it.
    pub(crate) fn selector(&self) -> &Selector {
        &self.selector
    }

    /// The object's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The verb the API server has to offer for this change to be possible at all (§11.5).
    ///
    /// Asked of discovery before anything is sent, so that a resource nobody may patch is a
    /// refusal naming the verb rather than a `405` somebody has to interpret.
    pub(crate) fn verb(&self) -> Verb {
        match self.wanted {
            Wanted::Apply { .. } => Verb::Patch,
            Wanted::Delete { .. } => Verb::Delete,
        }
    }

    /// The action, expressed against what the object actually holds (§46.2).
    fn action(&self, object: &Object) -> Action {
        match &self.wanted {
            Wanted::Delete { propagation } => Action::delete(*propagation),
            Wanted::Apply { set, unset } => {
                let mut changes: Vec<FieldChange> = Vec::new();
                for (path, wanted) in set {
                    changes.push(match object.field(path) {
                        Some(held) => FieldChange::change(path, held.clone(), wanted.clone()),
                        None => FieldChange::set(path, wanted.clone()),
                    });
                }
                for path in unset {
                    // A field that is not there cannot be removed, and taking ownership of it in
                    // order to say so is not what was asked.
                    if let Some(held) = object.field(path) {
                        changes.push(FieldChange::remove(path, held.clone()));
                    }
                }
                Action::apply(changes)
            }
        }
    }
}

/// The JSON pointers and values an `apply` sets.
fn pointers(options: &JsonMap<String, Json>) -> Result<Vec<(String, Json)>, WireError> {
    let Some(set) = options.get("set") else {
        return Ok(Vec::new());
    };
    let Some(fields) = set.as_object() else {
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            "`set` is a mapping from a field path to the value it should hold".to_owned(),
            "For example `--set '{\"/spec/replicas\": 2}'`. A path is a JSON pointer into the \
             object, which is the same notation every other part of this provider reads a field \
             by.",
        ));
    };
    fields
        .iter()
        .map(|(path, value)| {
            check_pointer(path)?;
            Ok((path.clone(), value.clone()))
        })
        .collect()
}

/// The JSON pointers an `apply` removes.
fn unset(options: &JsonMap<String, Json>) -> Result<Vec<String>, WireError> {
    let Some(unset) = options.get("unset") else {
        return Ok(Vec::new());
    };
    let paths: Vec<String> = match unset {
        Json::String(one) => vec![one.clone()],
        Json::Array(many) => many
            .iter()
            .filter_map(|path| path.as_str().map(str::to_owned))
            .collect(),
        _ => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                "`unset` is a field path, or a list of them".to_owned(),
                "For example `--unset /spec/replicas`. Server-side apply expresses a removal by \
                 the field's absence from the applied document (§44.1).",
            ));
        }
    };
    for path in &paths {
        check_pointer(path)?;
    }
    Ok(paths)
}

fn check_pointer(path: &str) -> Result<(), WireError> {
    if path.starts_with('/') && path.len() > 1 {
        return Ok(());
    }
    Err(failure(
        UNSUPPORTED_CODE,
        UNSUPPORTED,
        format!("`{path}` is not a field path"),
        "A field path is a JSON pointer: it starts with `/` and names the fields down to the one \
         being changed, as in `/spec/template/spec/containers/0/image`.",
    ))
}

/// The propagation policy a deletion was asked for, defaulting to the API server's own (§45.2).
fn propagation(options: &JsonMap<String, Json>) -> Result<Propagation, WireError> {
    let Some(chosen) = options.get("propagation").and_then(Json::as_str) else {
        return Ok(Propagation::Background);
    };
    match chosen.to_ascii_lowercase().as_str() {
        "foreground" => Ok(Propagation::Foreground),
        "background" => Ok(Propagation::Background),
        "orphan" => Ok(Propagation::Orphan),
        other => Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("`{other}` is not a propagation policy"),
            "§45.2's three: `Foreground` keeps the object until its dependents are gone, \
             `Background` removes it now and collects them afterwards, `Orphan` leaves them \
             behind owned by nothing.",
        )),
    }
}

/// A plan, and what was learnt on the way to it.
pub(crate) struct Planned {
    /// The change, described before it is made.
    pub(crate) plan: Plan,
    /// Which REST collection serves the object, as discovery answered (§13.1).
    pub(crate) resource: Resource,
    /// The scope the object was read in.
    pub(crate) scope: Scope,
}

/// Reads the object a change is aimed at and builds the plan for it.
///
/// Shared by the `k8s-plan` target and by both mutating commands, because §46.1 makes them the
/// same first step: a mutation *is* a plan that was then carried out, and a second path from
/// arguments to a request would be a second place for a precondition to go missing.
///
/// # Errors
///
/// A refusal naming what could not be resolved, read or planned. Every one of them happens
/// before anything is sent that could change a cluster.
pub(crate) fn plan_on<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    intent: &Intent,
) -> Result<Planned, WireError> {
    let core = document(session, client, endpoint, "/api")?;
    let groups = document(session, client, endpoint, "/apis")?;
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

    // Resolved for `get` first, because the object has to be read before it can be changed: §56's
    // preconditions come from the reading, and §21.3 of the generic contract requires the target
    // to be resolved to a stable identity before a mutation rather than after it.
    let resource = resolve_in(
        session,
        client,
        endpoint,
        &served,
        intent.selector(),
        Verb::Get,
    )?;
    let wanted = intent.verb();
    if !resource.supports(wanted) {
        return Err(unsupported_verb(&resource, wanted));
    }
    let scope = match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => endpoint.scope.clone(),
    };

    let object = match fetch(client, &resource, &scope, intent.name())? {
        Answer::Fetched(read) => read.0,
        Answer::Absent => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!(
                    "`{}` in {scope} holds no object named `{}`, so there is nothing to change",
                    resource.gvr(),
                    intent.name()
                ),
                "A change is aimed at an object that exists, and this provider creates nothing \
                 it was not asked to change. A `404` on an object's own endpoint is the one \
                 outcome that is evidence of absence rather than a statement about what could \
                 not be seen (§21.4).",
            ));
        }
        // `fetch` answers a listing only when it was asked for one, and it never is here.
        Answer::Listed(_) => {
            return Err(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                "a direct read answered with a collection".to_owned(),
                "This is a defect in the Kubernetes provider, not in the cluster.",
            ));
        }
    };
    // §22 and Gate I before anything else touches the object: a plan that changes a Secret says
    // which keys it changes, and there is no payload left in the value for it to say more.
    let guarded = Guarded::hold(object).map_err(|error| {
        failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("an object could not be taken across the redaction boundary: {error}"),
            "This is a defect in the Kubernetes provider, not in the cluster.",
        )
    })?;
    let plan = Plan::of(guarded.object(), intent.action(guarded.object()))
        .map_err(|refusal| refused(&refusal))?;
    // §46.2's `permission preflight result`, and Appendix E's `AUTHORIZATION` line. Last, because
    // the review asks about the action the plan turned out to describe, and because a plan that
    // could not be built is a plan whose authorization nobody needs to have asked about.
    let preflight = preflight_for(session, client, endpoint, &served, &plan, &resource);
    let plan = plan.with_preflight(preflight);
    Ok(Planned {
        plan,
        resource,
        scope,
    })
}

/// The API group that answers "may this identity do that" (§21.2).
const REVIEW_GROUP: &str = "authorization.k8s.io";

/// The kind that asks about one action for the caller's own identity.
///
/// `SelfSubjectAccessReview` and not `SubjectAccessReview`: the second asks about *another*
/// identity and needs a privilege this provider has no business holding (§8.1).
const REVIEW_KIND: &str = "SelfSubjectAccessReview";

/// Asks the API server whether this identity may make this change (§21.2, §46.2, Appendix E).
///
/// **This is the one write a read-only path makes, and it changes nothing.** A
/// `SelfSubjectAccessReview` is a create by the REST verb — a `POST` to a collection — and a
/// question by its semantics: the API server computes the answer, returns it in `status`, and
/// stores no object. So `get k8s-plan` stays a read of the cluster while gaining the line
/// Appendix E puts on a plan.
///
/// **It never fails a plan, and it never denies one on this provider's behalf.** Every way this
/// can go wrong — an unserved `authorization.k8s.io`, a resource list that did not read, a review
/// the server refused, an authorizer with no opinion — is §21.4's `not queried`, which reaches a
/// user as §21.6's `unknown / unchecked` with the reason attached. A provider that turned "I
/// could not ask" into "you may not" would be answering an authorization question the API server
/// never answered (§21.1).
fn preflight_for<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    plan: &Plan,
    target: &Resource,
) -> Preflight {
    // §5.3 and §11.1: which version of the review API this cluster serves is learnt, not assumed.
    let Some(version) = served.preferred_version(REVIEW_GROUP) else {
        return Preflight::not_answered(format!(
            "this cluster serves no `{REVIEW_GROUP}` API group, so no permission check \
             could be asked"
        ));
    };
    let group_version = group_version_of(REVIEW_GROUP, version);
    let Ok(catalogue) = resource_list(session, client, endpoint, &group_version) else {
        return Preflight::not_answered(format!(
            "the resource list of `{group_version}` could not be read, so no permission \
             check could be asked"
        ));
    };
    let Some(review) = catalogue.by_kind(&group_version, REVIEW_KIND) else {
        return Preflight::not_answered(format!(
            "this cluster's `{group_version}` serves no `{REVIEW_KIND}`, so no permission \
             check could be asked"
        ));
    };
    // §11.5: a verb the server does not offer is not a permission the caller is missing.
    if !review.supports(Verb::Create) {
        return Preflight::not_answered(format!(
            "this cluster serves `{}` and does not offer `create` on it, so no permission \
             check could be asked",
            review.gvr()
        ));
    }
    let scope = match review.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => endpoint.scope.clone(),
    };
    let request = endpoint.authorise(create_request(
        review.gvr(),
        &scope,
        &access_review(plan, target.gvr(), review.gvk()),
    ));
    let response = match client.connection().send(&request) {
        Ok(response) => response,
        Err(error) => {
            return Preflight::not_answered(format!(
                "the permission check could not be sent: {error}"
            ));
        }
    };
    if !(200..300).contains(&response.status()) {
        return Preflight::not_answered(format!(
            "the API server answered the permission check with {} {}",
            response.status(),
            response.reason()
        ));
    }
    match serde_json::from_slice::<Json>(response.body()) {
        Ok(review) => Preflight::from_review(&review),
        Err(error) => Preflight::not_answered(format!(
            "the API server's answer to the permission check did not read: {error}"
        )),
    }
}

/// A change the cluster does not offer on this resource (§11.5).
fn unsupported_verb(resource: &Resource, verb: Verb) -> WireError {
    let word = match verb {
        Verb::Patch => "patch",
        Verb::Delete => "delete",
        Verb::Get => "get",
        Verb::List => "list",
        Verb::Watch => "watch",
        Verb::Create => "create",
        Verb::Update => "update",
    };
    failure(
        UNSUPPORTED_CODE,
        UNSUPPORTED,
        format!(
            "the cluster serves `{}` and does not offer `{word}` on it",
            resource.gvr()
        ),
        "A verb the API server does not serve is not a permission the caller is missing and not \
         an object that is not there: discovery says which verbs a resource offers, and this one \
         does not offer that (§11.5).",
    )
}

/// A plan `plan.rs` would not build.
fn refused(refusal: &PlanRefusal) -> WireError {
    failure(
        REFUSED_CODE,
        REFUSED,
        format!("this change was refused before anything was sent: {refusal}"),
        "§56 asks a mutation to carry preconditions, and this provider reads that as a refusal \
         rather than a warning: a change with nothing guarding its target can land on an object \
         recreated under the same name since it was planned, and the response would look \
         exactly like success (ADR-0019). Read the object again and plan against what came back.",
    )
}

// --- the target -----------------------------------------------------------------------------------

/// Answers `get k8s-plan`: one prospective change, and nothing sent that could make it.
#[must_use]
pub fn answer(
    target: &'static Target,
    sessions: &Sessions,
    ctx: &mut Ctx<'_>,
) -> InvocationOutcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return InvocationOutcome::Failed(error.into()),
    };
    let intent = match Intent::read(ctx.arguments()) {
        Ok(intent) => intent,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    if ctx.cancelled() {
        return InvocationOutcome::Cancelled;
    }
    let planned = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            converse(
                ctx,
                &endpoint,
                Planning {
                    intent: &intent,
                    endpoint: &endpoint,
                    session,
                },
            )
        },
    );
    let planned = match planned {
        Ok(planned) => planned,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    let value = match record(target.fields, &schema, &planned.plan) {
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
            format!("the host refused the plan: {error}"),
            "The stream ended before the query did.",
        )),
    }
}

/// The exchange a plan needs: discovery, one read, and no write.
struct Planning<'a> {
    intent: &'a Intent,
    endpoint: &'a Endpoint,
    session: &'a mut Session,
}

impl Conversation for Planning<'_> {
    type Answer = Planned;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        plan_on(self.session, client, self.endpoint, self.intent)
    }
}

// --- the record -------------------------------------------------------------------------------------

/// One plan, as a record of the `k8s-plan` schema.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares, which means this crate's
/// table and the schema built from it have drifted apart.
pub(crate) fn record(
    fields: &[Field],
    schema: &Arc<Schema>,
    plan: &Plan,
) -> Result<Value, ErrorValue> {
    let provenance = Provenance::local(crate::PACKAGE, schema.id().clone());
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance);
    for field in fields {
        builder = builder.set(field.name, plan_field(field.name, plan))?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// One field of a plan record, by the name the schema declares it under.
fn plan_field(name: &str, plan: &Plan) -> Value {
    match name {
        // --- what it is aimed at (§16.1, §56) ---
        "prediction" => Value::String(
            "static provider metadata: derived from the object as it was read and from this \
             provider's own rules. No server dry run was made, so admission and defaulting are \
             unpreviewed (§21.4 of the generic provider contract, §44.5)"
                .into(),
        ),
        "precondition_guarded" => Value::Bool(plan.is_precondition_guarded()),
        "effects" => Value::List(plan.effects().iter().map(effect).collect()),
        "reversibility" => Value::String(plan.reversibility().as_str().into()),
        "recovery" => recovery(plan),
        "dependents" => Value::List(plan.dependents().iter().map(dependent).collect()),
        "dependent_coverage" => Value::String(plan.dependent_coverage().describe().into()),
        "preflight" => Value::String(plan.preflight().to_string().into()),
        "verification" => Value::String(plan.verification_rule().as_str().into()),
        "verification_stage" => plan
            .verification_rule()
            .established_stage()
            .map_or(Value::Null, |stage| Value::String(stage.as_str().into())),
        "caveats" => Value::List(
            plan.caveats()
                .iter()
                .map(|caveat| Value::String(caveat.to_string().into()))
                .collect(),
        ),
        "statement" => Value::String(plan.describe().into()),
        other => target_field(other, plan),
    }
}

/// The fields a plan record and a mutation record share: what the change is aimed at (§46.2).
pub(crate) fn target_field(name: &str, plan: &Plan) -> Value {
    let target = plan.target();
    match name {
        "uid" => optional(target.uid()),
        "name" => Value::String(target.name().into()),
        "namespace" => optional(target.namespace()),
        "api_version" => Value::String(
            if target.gvk().group().is_empty() {
                target.gvk().version().to_owned()
            } else {
                format!("{}/{}", target.gvk().group(), target.gvk().version())
            }
            .into(),
        ),
        "kind" => Value::String(target.gvk().kind().into()),
        "resource_version" => optional(target.resource_version()),
        "action" => Value::String(plan.action().verb().into()),
        "changes" => Value::List(
            plan.field_changes()
                .iter()
                .map(|change| Value::String(change.describe().into()))
                .collect(),
        ),
        "preconditions" => preconditions(plan.preconditions()),
        "propagation" => plan
            .propagation()
            .map_or(Value::Null, |policy| Value::String(policy.as_str().into())),
        // Every field of both schemas is answered above; a name that reaches here is a table this
        // crate wrote disagreeing with a schema this crate built, and null is what a record may
        // honestly carry for a fact nobody produced (§4).
        _ => Value::Null,
    }
}

/// One field change in one line, in the words `plan.rs` writes it (§46.2).
///
/// A free function rather than a closure at each call site, so that a plan's `changes` and a
/// mutation's `admission_differences` are spelled the same way: both are "this field held that
/// and would hold this", and a reader comparing the two should not have to translate.
pub(crate) fn describe_change(change: &FieldChange) -> String {
    change.describe()
}

fn optional(text: Option<&str>) -> Value {
    text.map_or(Value::Null, |text| Value::String(text.into()))
}

/// What the mutation will assert about its target, structured rather than in prose (§56).
fn preconditions(preconditions: &Preconditions) -> Value {
    let mut map = MapValue::new();
    map.insert(
        Arc::from("resource_version"),
        optional(preconditions.resource_version()),
    );
    map.insert(Arc::from("uid"), optional(preconditions.uid()));
    map.insert(
        Arc::from("guards_lost_update"),
        Value::Bool(preconditions.guards_lost_update()),
    );
    map.insert(
        Arc::from("guards_recreation"),
        Value::Bool(preconditions.guards_recreation()),
    );
    Value::Map(Arc::new(map))
}

/// One expected effect, with the reversibility that belongs to it rather than to the plan (§46.5).
fn effect(effect: &Effect) -> Value {
    let mut map = MapValue::new();
    map.insert(
        Arc::from("effect"),
        Value::String(effect.kind().as_str().into()),
    );
    map.insert(
        Arc::from("reversibility"),
        Value::String(effect.reversibility().as_str().into()),
    );
    Value::Map(Arc::new(map))
}

/// What reapplying the previous values would and would not restore (§46.5).
///
/// Two lists and a sentence, never a verdict: "recoverable" as one word is the claim §46.5
/// forbids, and the second list is the one an operator needs.
fn recovery(plan: &Plan) -> Value {
    let recovery = plan.recovery();
    let mut map = MapValue::new();
    map.insert(
        Arc::from("restores"),
        Value::List(
            recovery
                .restores()
                .iter()
                .map(|kind| Value::String(kind.as_str().into()))
                .collect(),
        ),
    );
    map.insert(
        Arc::from("does_not_restore"),
        Value::List(
            recovery
                .does_not_restore()
                .iter()
                .map(|kind| Value::String(kind.as_str().into()))
                .collect(),
        ),
    );
    map.insert(
        Arc::from("statement"),
        Value::String(recovery.describe().into()),
    );
    Value::Map(Arc::new(map))
}

/// One object that names the target as an owner, on owner-reference evidence alone (§24.1, §45.4).
fn dependent(dependent: &Dependent) -> Value {
    let identity = dependent.identity();
    let mut map = MapValue::new();
    map.insert(
        Arc::from("uid"),
        identity
            .uid()
            .map_or(Value::Null, |uid| Value::String(uid.into())),
    );
    map.insert(Arc::from("name"), Value::String(identity.name().into()));
    map.insert(
        Arc::from("kind"),
        Value::String(identity.gvk().kind().into()),
    );
    map.insert(
        Arc::from("controller"),
        Value::Bool(dependent.is_controller()),
    );
    map.insert(
        Arc::from("blocks_owner_deletion"),
        Value::Bool(dependent.blocks_owner_deletion()),
    );
    Value::Map(Arc::new(map))
}

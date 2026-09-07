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
//! record can carry a stronger word. Everything above that rung comes from a later observation:
//! one immediate read, and then — where that read is not decisive — a watch over the target for
//! at most `VERIFICATION_WINDOW`, consumed until the rule is proven, refuted, or the window
//! ends (ADR-0060). What the watch could not establish is `Inconclusive` with a *named* reason,
//! which §46.4 defines as neither failure nor success. That is Gate G with no room left for a
//! friendlier sentence.
//!
//! **Force is a reason.** There is no `force` flag. `force_because` takes the sentence a reviewer
//! will read, and without it a conflict is an answer that names the owning manager and stops
//! (§44.3, §44.4). Nothing here retries.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, EmitError, Outcome as InvocationOutcome};
use ono_provider_kubernetes::coverage::Outcome as Coverage;
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::{Gvr, Resource};
use ono_provider_kubernetes::mutation::{
    Acceptance, ApplyOptions, Deadline, DeleteOptions, Deletion, FieldManager, MutationError,
    MutationOutcome, Observation, Unfinished, Verdict, Verification, admission_differences_of,
    apply_document, apply_request, delete_request,
};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::plan::{Plan, Preflight, VerificationRule};
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::{Invalidation, Lookup, Session};
use ono_provider_kubernetes::transport::{
    ApiError, ByteStream, Client, Clock, ListOptions, ObservedAt, Operation, Request, Response,
    SystemClock, watch_request,
};
use ono_provider_kubernetes::watch::{WatchDecoder, WatchEvent, WatchFailure, WatchStream};
use ono_value::{ErrorValue, MapValue, Provenance, RecordValue, Schema, Value};
use serde_json::{Map as JsonMap, Value as Json};

use crate::broker::ReadPolicy;
use crate::contributions::{Command, SchemaDef, Writes};
use crate::planning::{self, Intent, Planned, plan_on};
use crate::query::{
    Conversation, Endpoint, UNAVAILABLE, UNAVAILABLE_CODE, converse, failure, transport_failure,
};
use crate::sessions::{Key, Sessions};

/// How long verification may watch for convergence before it reports that it did not finish
/// (§46.4, ADR-0060).
///
/// Sixty seconds, and the number is an argument. A scale or an image change on a healthy
/// cluster converges in seconds; one that has not converged in a minute is one an operator
/// wants to look at rather than wait on, and §46.4 is explicit that the window ending means
/// *incomplete* and never *failed*. The operator may stop it earlier (§62.12), and the watch
/// notices within a read window (`ReadPolicy::watch`).
///
/// `ONO_K8S_VERIFICATION_WINDOW_MS` overrides it for a process — §7.4 of the generic contract's
/// environment-derived configuration — which is how a deterministic test makes the window end.
const VERIFICATION_WINDOW: Duration = Duration::from_secs(60);

/// The window this process verifies under.
fn verification_window() -> Duration {
    std::env::var("ONO_K8S_VERIFICATION_WINDOW_MS")
        .ok()
        .and_then(|millis| millis.parse::<u64>().ok())
        .map_or(VERIFICATION_WINDOW, Duration::from_millis)
}

/// How often the session's own watch cache is asked while a change is being verified through it.
const CACHE_POLL: Duration = Duration::from_millis(100);

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

    let key = endpoint.session_key();
    let made = sessions.with(
        &key,
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
    let mut made = match made {
        Ok(made) => made,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    // §46.3 and §46.4: the immediate read was not decisive, so the target is watched for
    // convergence until the rule is proven or the window ends (ADR-0060). Outside the session
    // borrow, because the watch may be the session's own and another invocation is feeding it.
    if let Some(verdict) = converge(ctx, sessions, &key, &endpoint, &made) {
        match verdict {
            Converged::Verified(verification) => made.verification = Some(verification),
            Converged::Cancelled => return InvocationOutcome::Cancelled,
        }
    }
    // §51.6, before the record is built and whatever becomes of it. A change is the event an
    // audit trail exists for, and the broker cannot see one: everything this command did to the
    // cluster travelled as bytes on a connection it authorised by host and port. The *fields*
    // are named; their values are not, because a value written to a Secret is a payload and the
    // trail is kept.
    let acceptance = match made.outcome.acceptance() {
        Acceptance::Persisted => "persisted".to_owned(),
        Acceptance::DryRun => "dry run".to_owned(),
        Acceptance::Conflict(_) => "conflict".to_owned(),
        Acceptance::PreconditionFailed(_) => "precondition failed".to_owned(),
        // The classified reason and not the server's sentence: a `Status` message is the API
        // server's prose about somebody's object, and prose is where a payload hides.
        Acceptance::Refused(kind) => format!("refused: {}", kind.as_str()),
    };
    crate::audit::mutated(
        ctx,
        made.plan.target().provider_instance(),
        &made.plan.target().gvk().to_string(),
        made.plan.target().namespace().unwrap_or("cluster"),
        made.plan.target().name(),
        made.dry_run,
        &acceptance,
        &made
            .plan
            .field_changes()
            .iter()
            .map(|change| change.path().to_owned())
            .collect::<Vec<_>>(),
    );
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
    /// Which REST collection serves the target, for the watch that verifies the change.
    resource: Resource,
    /// The scope the target was read in.
    scope: Scope,
    /// The `resourceVersion` of the last observation of the target, which a verification watch
    /// opens from so that nothing between that observation and the watch is missed (§19.1).
    observed_version: Option<String>,
    outcome: MutationOutcome,
    manager: FieldManager,
    forced_because: Option<String>,
    dry_run: bool,
    deletion: Option<Deletion>,
    verification: Option<Verification>,
    admission: Vec<String>,
    /// What the write made this session forget, where it was a write at all (§20.5).
    invalidated: Option<Invalidation>,
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
        refuse_a_denied_change(&planned.plan)?;
        let made = match self.writes {
            Writes::Fields => apply(client, self.endpoint, &planned, self.how),
            Writes::Object => delete(client, self.endpoint, &planned, self.how),
        }?;
        Ok(invalidate_what_the_write_reached(
            self.session,
            &planned,
            made,
        ))
    }
}

/// Stops a change the API server's own permission check has already refused (§21.2, §21.6).
///
/// **This is a safety rule of this package and not an authorization decision.** §21.1 leaves the
/// Kubernetes authorizer as the only authorizer, and nothing here evaluates RBAC: the sentence
/// below relays what the API server said seconds ago, in answer to a question about exactly this
/// verb on exactly this object. The refusal is `contribution.refused` for that reason — a denial
/// code would claim the cluster refused a write it never received.
///
/// Only an **explicit** denial stops anything. An authorizer with no opinion, an unserved review
/// API and a review the server would not answer are all `unknown / unchecked`, and every one of
/// them goes to the API server to be decided (§21.4). The check is made again on every
/// invocation and nothing about it is cached, so a grant that lands makes the same command work.
fn refuse_a_denied_change(plan: &Plan) -> Result<(), WireError> {
    let Preflight::Denied(reason) = plan.preflight() else {
        return Ok(());
    };
    Err(failure(
        planning::REFUSED_CODE,
        planning::REFUSED,
        format!(
            "the API server's own permission check says this identity may not `{}` `{}`: {reason}",
            plan.action().api_verb(),
            plan.target(),
        ),
        "The check is a `SelfSubjectAccessReview` this package sent a moment ago, and it is \
         advisory: the API server remains the authority and would decide again on the request \
         itself (§21.1, §21.2). It is relayed as a refusal rather than sent anyway because a \
         user should not have to make a write to find out, and because the answer names the \
         grant that is missing. Nothing is cached: the check runs again on the next \
         invocation, so the same command works as soon as the grant exists. `get k8s-plan` \
         describes the change either way.",
    ))
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
    let (verification, observed_version) = verify(client, planned, &outcome, None);
    Ok(Made {
        plan: planned.plan.clone(),
        resource: planned.resource.clone(),
        scope: planned.scope.clone(),
        observed_version,
        manager: options.manager().clone(),
        forced_because: options.forced_because().map(str::to_owned),
        dry_run: options.dry_run().is_dry_run(),
        outcome,
        deletion: None,
        verification,
        admission,
        invalidated: None,
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
    let (verification, observed_version) = verify(client, planned, &outcome, deletion.as_mut());
    Ok(Made {
        plan: planned.plan.clone(),
        resource: planned.resource.clone(),
        scope: planned.scope.clone(),
        observed_version,
        manager: FieldManager::ono(),
        forced_because: None,
        dry_run: options.dry_run().is_dry_run(),
        outcome,
        deletion,
        verification,
        admission: Vec::new(),
        invalidated: None,
    })
}

/// Invalidates what this session cached about the object the write changed (§20.5, §16.5).
///
/// **After the answer, and only for an answer that says something was written.** §16.5 of the
/// generic provider contract invalidates after a *successful* mutation, and the API server is the
/// only thing that knows whether there was one: a dry run persisted nothing, a conflict changed
/// nothing, a refusal never happened. Invalidating on the way in — before the request, on the
/// intent — would make every preview cost this session its caches, and would still be wrong,
/// because the write it was anticipating may not have happened.
///
/// **Before anything is presented as current, which here means before the record exists.** The
/// record this invocation emits is built from the value this returns, so there is no ordering in
/// which a caller could read a stale cache between the write and the invalidation. The one read
/// made in between is §46.3's verification, and it goes to the API server by name rather than
/// through any cache.
///
/// Nothing is written *into* the cache. What the API server returned is in the record and in the
/// verification; putting it into the object cache would make the next read of it a cached
/// observation of a write this provider made, which is the synthetic result §20.5 forbids.
fn invalidate_what_the_write_reached(
    session: &mut Session,
    planned: &Planned,
    mut made: Made,
) -> Made {
    if made.outcome.is_persisted() {
        made.invalidated = Some(session.mutated(
            planned.resource.gvr(),
            planned.scope.namespace(),
            planned.plan.target().name(),
        ));
    }
    made
}

/// Looks at the target once, and says what that look establishes about the change (§46.3).
///
/// Only after a write. A dry run persisted nothing, so there is nothing to look for; a refusal
/// did not happen, so there is nothing to verify. Looking anyway would spend a request to
/// discover that the object is as it was, and would tempt a reader into treating the answer as
/// being about a change that was never made.
///
/// The read is the first observation and the one the verification watch opens from: its
/// `resourceVersion` comes back beside the verdict so that [`converge`] can ask the API server
/// for every change *after* the state this look evaluated, and none of the ones before it.
fn verify<S: ByteStream>(
    client: &mut Client<S>,
    planned: &Planned,
    outcome: &MutationOutcome,
    deletion: Option<&mut Deletion>,
) -> (Option<Verification>, Option<String>) {
    if !outcome.requires_verification() {
        return (None, None);
    }
    let name = planned.plan.target().name();
    let mut observed_version = None;
    let (observation, now) = match client.get(planned.resource.gvr(), &planned.scope, name) {
        Ok(read) => {
            let now = read.freshness().observed_at();
            let (object, _) = read.into_parts();
            observed_version = object.resource_version().map(str::to_owned);
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
    // §46.4's window applies to the rules a watch can prove. An absence is established by a
    // read (§45.1) and a rule this provider does not have by nothing, so for those two the
    // immediate observation is the whole verification and the window is already over.
    let window = if watchable(planned.plan.verification_rule()) {
        verification_window()
    } else {
        Duration::ZERO
    };
    let deadline = Deadline::starting_at(now, window);
    (
        Some(Verification::of(
            &planned.plan,
            observation.as_observation(),
            &deadline,
            now,
        )),
        observed_version,
    )
}

/// Whether a watch over the target can prove this rule (§46.3).
fn watchable(rule: VerificationRule) -> bool {
    !matches!(
        rule,
        VerificationRule::Absence | VerificationRule::NoneKnown
    )
}

/// What watching for convergence came to.
enum Converged {
    /// The verdict the watch reached, or the named reason it could not (§46.4).
    Verified(Verification),
    /// The operator stopped the verification (§62.12); the change stands as the API server took
    /// it, and nothing is rolled back (§46.4, §26 of the generic contract).
    Cancelled,
}

/// Watches the target until the verification rule is decided or the window ends (§46.3, §46.4).
///
/// `None` where there is nothing to wait for: no write was made, the immediate read decided the
/// question, or the rule is one no watch can prove — an absence is read, and a rule this provider
/// does not have stays unproven however long anybody watches.
///
/// Two sources, in this order (ADR-0060):
///
/// 1. **the session's own watch**, where one is open and live over the target's collection: the
///    cache is polled through the session, and the watch another invocation is feeding is what
///    delivers the controller's progress (§20.3, §50.4);
/// 2. **a bounded watch of this invocation's own**, opened at the version the immediate read
///    observed and narrowed to the target by `fieldSelector=metadata.name`, consumed until the
///    rule is proven and released with the invocation.
///
/// Nothing here fabricates convergence. A gap, a partial observation, a window that ends and a
/// target that vanishes are each a named `Unfinished`, and every one of them is reported as
/// incomplete rather than as either verdict (§46.4).
fn converge(
    ctx: &mut Ctx<'_>,
    sessions: &Sessions,
    key: &Key,
    endpoint: &Endpoint,
    made: &Made,
) -> Option<Converged> {
    let first = made.verification.as_ref()?;
    if first.verdict() != Verdict::Pending {
        return None;
    }
    let rule = made.plan.verification_rule();
    let gvr = made.resource.gvr().clone();
    let scope = made.scope.clone();
    let name = made.plan.target().name().to_owned();
    let started = Instant::now();
    let window = verification_window();
    let mut last = first.clone();

    // 1. The session's own watch, where it is live over this collection and scope. It is fed by
    //    the invocation that opened it, which borrows the session per event (ADR-0058), so
    //    polling the cache through the session takes turns with it rather than starving it.
    loop {
        if ctx.cancelled() {
            return Some(Converged::Cancelled);
        }
        let (live, looked) = sessions.with(
            key,
            || endpoint.start_session(),
            |session| {
                (
                    session
                        .watch_stream(&gvr, &scope)
                        .is_some_and(WatchStream::absence_is_conclusive),
                    session.lookup(&gvr, &scope, scope.namespace(), &name),
                )
            },
        );
        if !live {
            break;
        }
        match looked {
            // The written object is quarantined until the event for the write arrives on the
            // session's watch (§20.5, ADR-0060); the stream is live, so it is coming.
            Lookup::NotWatched | Lookup::NotSynced(_) => {}
            Lookup::ConfirmedAbsent => {
                return Some(Converged::Verified(Verification::unfinished(
                    rule,
                    Unfinished::TargetGone,
                    Some(&last),
                )));
            }
            Lookup::Cached(read) => {
                let now = SystemClock.now();
                let deadline = Deadline::starting_at(read.freshness().observed_at(), window);
                let verification = Verification::of(
                    &made.plan,
                    Observation::Object(read.object()),
                    &deadline,
                    now,
                );
                if verification.verdict().is_decided() {
                    return Some(Converged::Verified(verification));
                }
                last = verification;
            }
        }
        if started.elapsed() >= window {
            return Some(Converged::Verified(Verification::unfinished(
                rule,
                window_ended(&last),
                Some(&last),
            )));
        }
        std::thread::sleep(CACHE_POLL);
    }

    // 2. A watch of this invocation's own, from the version the immediate read observed.
    let mut from = made.observed_version.clone();
    loop {
        if ctx.cancelled() {
            return Some(Converged::Cancelled);
        }
        let remaining = window.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Some(Converged::Verified(Verification::unfinished(
                rule,
                window_ended(&last),
                Some(&last),
            )));
        }
        let round = converse(
            ctx,
            endpoint,
            Converging {
                endpoint,
                plan: &made.plan,
                gvr: &gvr,
                scope: &scope,
                name: &name,
                from: from.as_deref(),
                deadline: started + window,
                last: &last,
            },
        );
        match round {
            Ok(Watched::Decided(verification)) => {
                return Some(Converged::Verified(verification));
            }
            Ok(Watched::Unfinished(reason, seen)) => {
                return Some(Converged::Verified(Verification::unfinished(
                    rule,
                    reason,
                    Some(seen.as_ref().unwrap_or(&last)),
                )));
            }
            // The body ended cleanly or the server went quiet past its own timeout: the
            // checkpoint still names a position it holds, so the watch reopens there (§19.5).
            Ok(Watched::Reopen(checkpoint, seen)) => {
                if let Some(seen) = seen {
                    last = seen;
                }
                if checkpoint.is_some() {
                    from = checkpoint;
                }
            }
            Err(error) => {
                if ctx.cancelled() {
                    return Some(Converged::Cancelled);
                }
                // The transport failed underneath the watch. That is a read nobody could make,
                // not a change that failed (§21.4, §46.4).
                let _ = error;
                return Some(Converged::Verified(Verification::unfinished(
                    rule,
                    Unfinished::WatchUnavailable(Coverage::RequestFailed),
                    Some(&last),
                )));
            }
        }
    }
}

/// Which of §46.4's unfinished answers a window that ended on this evidence is.
fn window_ended(last: &Verification) -> Unfinished {
    use ono_provider_kubernetes::condition::Stage;
    match last.reached() {
        None => Unfinished::WindowExpired,
        Some(Stage::ApiAccepted | Stage::SpecObserved) => Unfinished::GenerationNotObserved,
        Some(_) => Unfinished::ConditionsInconclusive,
    }
}

/// What one watch round of a verification came to.
enum Watched {
    /// The rule was proven or refuted by an observation on the watch.
    Decided(Verification),
    /// The watch could not go on, for this reason, with the last observation it made.
    Unfinished(Unfinished, Option<Verification>),
    /// The body ended and the checkpoint is still good: reopen from it, if the window allows.
    Reopen(Option<String>, Option<Verification>),
}

/// One bounded watch over the target, read frame by frame until the rule is decided (§46.3).
struct Converging<'a> {
    endpoint: &'a Endpoint,
    plan: &'a Plan,
    gvr: &'a Gvr,
    scope: &'a Scope,
    name: &'a str,
    from: Option<&'a str>,
    /// When the window ends, on the invocation's own clock.
    deadline: Instant,
    last: &'a Verification,
}

impl Conversation for Converging<'_> {
    type Answer = Watched;

    fn read_policy(&self) -> ReadPolicy {
        // A watch, so the read hands control back on silence: that is where the deadline and
        // the cancellation are noticed while the controller is taking its time (§62.12).
        ReadPolicy::watch()
    }

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        // One object rather than the collection: `metadata.name` is a field selector every
        // API server indexes, so the watch delivers the target's changes and nobody else's.
        let options = ListOptions::new().field_selector(format!("metadata.name={}", self.name));
        let request = self.endpoint.authorise(
            watch_request(self.gvr, self.scope, &options, self.from)
                .header("Accept", "application/json"),
        );
        let instance = client.provider_instance().to_owned();
        let mut decoder = WatchDecoder::new(instance);
        let mut stream = client
            .connection()
            .open(&request)
            .map_err(|error| transport_failure(self.gvr.path().as_str(), &error))?;
        let unavailable = match stream.status() {
            200 => None,
            // §19.4: the version the read observed is already gone from the server's history.
            // What happened between that read and now was not observed (Gate F).
            410 => Some(Unfinished::WatchGap),
            401 | 403 => Some(Unfinished::WatchUnavailable(Coverage::ReadDenied)),
            404 => Some(Unfinished::WatchUnavailable(Coverage::TypeNotServed)),
            _ => Some(Unfinished::WatchUnavailable(Coverage::RequestFailed)),
        };
        if let Some(reason) = unavailable {
            return Ok(Watched::Unfinished(reason, None));
        }

        let mut checkpoint = self.from.map(str::to_owned);
        let mut seen: Option<Verification> = None;
        loop {
            if Instant::now() >= self.deadline {
                let reason = window_ended(seen.as_ref().unwrap_or(self.last));
                return Ok(Watched::Unfinished(reason, seen));
            }
            let Some(chunk) = stream.next_chunk() else {
                return Ok(Watched::Reopen(checkpoint, seen));
            };
            let events = match chunk {
                Ok(chunk) => match decoder.decode(&chunk) {
                    Ok(events) => events,
                    // A frame that could not be read is an observation with a hole in it, and
                    // a hole is not evidence either way (§21.4, §46.4).
                    Err(_) => {
                        return Ok(Watched::Unfinished(
                            Unfinished::PartialCoverage(Coverage::RequestFailed),
                            seen,
                        ));
                    }
                },
                // Nothing this window. The deadline is checked at the top of the loop, and a
                // cancellation is noticed by the caller before the next round (§62.12).
                Err(ApiError::Quiet) => continue,
                Err(_) => return Ok(Watched::Reopen(checkpoint, seen)),
            };
            for event in events {
                match event {
                    WatchEvent::Added(object) | WatchEvent::Modified(object) => {
                        if let Some(version) = object.resource_version() {
                            checkpoint = Some(version.to_owned());
                        }
                        let now = SystemClock.now();
                        // The deadline the verdict is measured against is the window's own end,
                        // so a decisive observation is decisive whenever it arrives and an
                        // indecisive one stays pending until the window says otherwise.
                        let deadline = Deadline::starting_at(now, Duration::from_secs(1));
                        let verification = Verification::of(
                            self.plan,
                            Observation::Object(&object),
                            &deadline,
                            now,
                        );
                        if verification.verdict().is_decided() {
                            return Ok(Watched::Decided(verification));
                        }
                        seen = Some(verification);
                    }
                    WatchEvent::Deleted(_) => {
                        return Ok(Watched::Unfinished(Unfinished::TargetGone, seen));
                    }
                    WatchEvent::Bookmark(version) | WatchEvent::InitialEventsEnd(version) => {
                        checkpoint = Some(version.as_str().to_owned());
                    }
                    WatchEvent::Error(WatchFailure::Expired) => {
                        return Ok(Watched::Unfinished(Unfinished::WatchGap, seen));
                    }
                    WatchEvent::Error(WatchFailure::Denied) => {
                        return Ok(Watched::Unfinished(
                            Unfinished::WatchUnavailable(Coverage::ReadDenied),
                            seen,
                        ));
                    }
                    WatchEvent::Error(WatchFailure::Interrupted(_)) => {
                        return Ok(Watched::Reopen(checkpoint, seen));
                    }
                }
            }
        }
    }
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
        // §54.1's writers, §55.2's inventory and the plan's caveats reach the record of the
        // attempt as well as the record of the plan: a warning that only `get k8s-plan` showed
        // would be a warning `set k8s-resource --dry_run true` never printed (§46.1).
        other => planning::analysis_field(other, &made.plan),
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
    if let Some(invalidated) = &made.invalidated {
        lines.push(invalidated.describe());
        // §45.2 and §45.5 read as a cache rule: a cascading deletion reaches objects whose
        // identities are in neither the request nor the answer, so this session cannot name the
        // caches they would be in. What it holds about them is left exactly as it was — an
        // observation of a moment before the deletion, carrying that moment and saying it came
        // from a cache (§20.2) — and the alternative is to guess at a set of collections to
        // empty, which costs §50.2 for every one of them and is still a guess.
        if made
            .deletion
            .as_ref()
            .is_some_and(|deletion| deletion.propagation().removes_dependents())
        {
            lines.push(
                "the objects the collector removes along with this one are not named in the \
                 answer, so nothing this session may hold about them was invalidated: those \
                 remain observations of a moment before the deletion and say so"
                    .to_owned(),
            );
        }
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

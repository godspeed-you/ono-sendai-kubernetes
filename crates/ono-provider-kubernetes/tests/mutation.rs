//! What a mutation request says, what the answer to it means, and what it still does not prove.
//!
//! Specification §43 (mutation principles), §44 (server-side apply and field ownership), §45
//! (delete, finalizers and garbage collection), §46.3–§46.4 (verification and its timeouts), §56
//! (preconditions), Gate G (§62.7) and Gate H (§62.8).
//!
//! Two mistakes are being held off, and both look like success in a screenshot.
//!
//! The first is Gate G's: a `200 OK` on a Deployment update is the API server saying it wrote the
//! document, and rendering that as a finished rollout claims something no response carries (§4
//! invariant 18). The second is Gate H's: a delete that the server accepted is a deletion that has
//! *started*, and an object with a finalizer on it may sit terminating indefinitely.
//!
//! Every response here is recorded bytes fed to the fixture transport (§59.2). Nothing opens a
//! socket, and nothing in this file could reach a cluster if it wanted to.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::time::Duration;

use ono_provider_kubernetes::condition::Stage;
use ono_provider_kubernetes::coverage::Outcome;
use ono_provider_kubernetes::discovery::{Gvk, Gvr};
use ono_provider_kubernetes::mutation::{
    Acceptance, ApplyOptions, Deadline, DeleteOptions, Deletion, DeletionState, DryRun,
    FieldManager, MutationError, MutationOutcome, Observation, PreconditionKind, Resolution,
    Verdict, Verification, apply_document, apply_request, delete_request,
};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::plan::{Action, FieldChange, Plan, Propagation, Target};
use ono_provider_kubernetes::transport::{
    FixtureStream, HttpConnection, Method, ObservedAt, Request, Response,
};
use serde_json::{Value as Json, json};

const INSTANCE: &str = "kubernetes:prod-eu";
const HOST: &str = "kubernetes.default.svc";
const STARTED: u64 = 1_700_000_000_000;

const DEPLOYMENT: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{
    "name":"checkout","namespace":"shop","uid":"dep-uid-1","resourceVersion":"1041","generation":7
  },
  "spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"web","image":"shop/web:1.2.0"}]}}},
  "status":{"observedGeneration":7,"replicas":3,"updatedReplicas":3,"availableReplicas":3}
}"#;

/// The same Deployment as the server returns it after accepting the new image: the generation has
/// advanced and no controller has recorded seeing it (§37.3).
const DEPLOYMENT_ACCEPTED: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{
    "name":"checkout","namespace":"shop","uid":"dep-uid-1","resourceVersion":"1120","generation":8
  },
  "spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"web","image":"shop/web:1.3.0"}]}}},
  "status":{"observedGeneration":7,"replicas":3,"updatedReplicas":3,"availableReplicas":3}
}"#;

const DEPLOYMENT_CONVERGED: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{
    "name":"checkout","namespace":"shop","uid":"dep-uid-1","resourceVersion":"1180","generation":8
  },
  "spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"web","image":"shop/web:1.3.0"}]}}},
  "status":{
    "observedGeneration":8,"replicas":3,"updatedReplicas":3,"availableReplicas":3,
    "conditions":[{"type":"Progressing","status":"True","reason":"NewReplicaSetAvailable"}]
  }
}"#;

const DEPLOYMENT_FAILED: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{
    "name":"checkout","namespace":"shop","uid":"dep-uid-1","resourceVersion":"1190","generation":8
  },
  "spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"web","image":"shop/web:1.3.0"}]}}},
  "status":{
    "observedGeneration":8,"replicas":1,"updatedReplicas":1,"availableReplicas":1,
    "conditions":[{"type":"Progressing","status":"False","reason":"ProgressDeadlineExceeded"}]
  }
}"#;

const CLAIM: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{
    "name":"orders-data","namespace":"shop","uid":"pvc-uid-1","resourceVersion":"77",
    "finalizers":["kubernetes.io/pvc-protection"]
  },
  "spec":{"storageClassName":"fast"}
}"#;

/// The same claim as the server returns it from an accepted DELETE: terminating, not gone.
const CLAIM_TERMINATING: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{
    "name":"orders-data","namespace":"shop","uid":"pvc-uid-1","resourceVersion":"120",
    "deletionTimestamp":"2026-09-05T10:00:00Z",
    "finalizers":["kubernetes.io/pvc-protection"]
  },
  "spec":{"storageClassName":"fast"}
}"#;

const NODE: &str = r#"{
  "apiVersion":"v1","kind":"Node",
  "metadata":{"name":"node-a","uid":"node-uid-1","resourceVersion":"5"},
  "spec":{}
}"#;

fn object(json: &str) -> Object {
    Object::parse(INSTANCE, json).expect("the fixture is a Kubernetes object")
}

fn deployments() -> Gvr {
    Gvr::new("apps", "v1", "deployments")
}

fn claims() -> Gvr {
    Gvr::new("", "v1", "persistentvolumeclaims")
}

/// A set-image change. The container's `name` travels with it because it is the merge key of the
/// `containers` list: an apply document that names an index and not the key is one the server
/// merges against the wrong entry (§44.1).
fn image_change() -> Action {
    Action::apply(vec![
        FieldChange::set("/spec/template/spec/containers/0/name", json!("web")),
        FieldChange::change(
            "/spec/template/spec/containers/0/image",
            json!("shop/web:1.2.0"),
            json!("shop/web:1.3.0"),
        ),
    ])
}

fn rollout_plan() -> Plan {
    Plan::of(&object(DEPLOYMENT), image_change()).expect("a read object guards itself")
}

fn deletion_plan() -> Plan {
    Plan::of(&object(CLAIM), Action::delete(Propagation::Foreground)).expect("guarded")
}

/// A response with a `Content-Length` body, framed the way a server frames one.
fn http(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Sends the request into a fixture that replies with these recorded bytes (§59.2).
fn exchange(request: &Request, recorded: &str) -> Response {
    let mut connection = HttpConnection::new(FixtureStream::new(recorded), HOST);
    connection
        .send(request)
        .expect("the fixture is a well-formed HTTP response")
}

fn conflict_status() -> String {
    http(
        "409 Conflict",
        r#"{"kind":"Status","apiVersion":"v1","status":"Failure",
            "message":"Apply failed with 1 conflict: conflict with \"argocd-controller\" using apps/v1",
            "reason":"Conflict",
            "details":{"group":"apps","kind":"deployments","name":"checkout","causes":[
              {"reason":"FieldManagerConflict",
               "message":"conflict with \"argocd-controller\" using apps/v1",
               "field":".spec.template.spec.containers[name=\"web\"].image"}]},
            "code":409}"#,
    )
}

fn body_of(request: &Request) -> Json {
    let mut connection = HttpConnection::new(FixtureStream::new(""), HOST);
    let _ = connection.send(request);
    let written = connection.stream().written_text();
    let (_, body) = written
        .split_once("\r\n\r\n")
        .expect("a request with a body has a blank line before it");
    serde_json::from_str(body).expect("the request body is JSON")
}

// --- the request (§43.2, §44.1, §44.2, §56) ---------------------------------------------------

/// §44.1 and §44.2: an apply goes as a server-side apply patch under a stable field manager, so
/// that the server tracks who owns what. The plausible mistake is a plain `PUT` of the whole
/// object, which silently takes ownership of every field it happens to include.
#[test]
fn should_apply_as_a_server_side_apply_patch_under_a_named_field_manager() {
    let request = apply_request(
        &rollout_plan(),
        &deployments(),
        &ApplyOptions::new(FieldManager::ono()),
    )
    .expect("an apply plan builds an apply request");

    assert_eq!(request.method(), Method::Patch);
    assert_eq!(
        request.path(),
        "/apis/apps/v1/namespaces/shop/deployments/checkout"
    );
    assert!(request.target().contains("fieldManager=ono-sendai"));
    let text = {
        let mut connection = HttpConnection::new(FixtureStream::new(""), HOST);
        let _ = connection.send(&request);
        connection.stream().written_text()
    };
    assert!(text.contains("Content-Type: application/apply-patch+yaml"));
}

/// §44.3 and §44.4: `force` is never on by default and cannot be switched on without saying why.
/// A boolean parameter would make forcing a one-character edit, and the edit that makes an apply
/// stop failing is the one that gets made at the end of an incident.
#[test]
fn should_never_force_an_apply_unless_a_reason_was_stated() {
    let plain = ApplyOptions::new(FieldManager::ono());
    assert!(!plain.forces());
    let request = apply_request(&rollout_plan(), &deployments(), &plain).expect("builds");
    assert!(!request.target().contains("force"));

    let forced = ApplyOptions::new(FieldManager::ono())
        .force_conflicts_because("the owning controller was removed by the platform team");
    assert!(forced.forces());
    assert_eq!(
        forced.forced_because(),
        Some("the owning controller was removed by the platform team")
    );
    let request = apply_request(&rollout_plan(), &deployments(), &forced).expect("builds");
    assert!(request.target().contains("force=true"));
}

/// §56.1 and §56.3: the preconditions the plan carries reach the wire. For server-side apply that
/// is `metadata.resourceVersion` and `metadata.uid` in the applied document, which is where the
/// API server looks; a plan that holds preconditions and sends none guards nothing.
#[test]
fn should_send_the_preconditions_the_plan_carries() {
    let document =
        apply_document(&rollout_plan()).expect("an apply plan produces an apply document");

    assert_eq!(
        document.pointer("/metadata/resourceVersion"),
        Some(&json!("1041"))
    );
    assert_eq!(document.pointer("/metadata/uid"), Some(&json!("dep-uid-1")));
    assert_eq!(document.pointer("/metadata/name"), Some(&json!("checkout")));
    assert_eq!(
        document.pointer("/metadata/namespace"),
        Some(&json!("shop"))
    );
    assert_eq!(document.pointer("/apiVersion"), Some(&json!("apps/v1")));
    assert_eq!(document.pointer("/kind"), Some(&json!("Deployment")));
    assert_eq!(
        document.pointer("/spec/template/spec/containers/0/image"),
        Some(&json!("shop/web:1.3.0"))
    );
}

/// §45.2 and §56.3: a delete carries its propagation policy and its UID precondition in the
/// `DeleteOptions` body. Without the UID, an object recreated under the same name between the plan
/// and the request is the one that gets deleted (§16.3).
#[test]
fn should_send_the_propagation_policy_and_the_uid_precondition_on_a_delete() {
    let request = delete_request(&deletion_plan(), &claims(), &DeleteOptions::new())
        .expect("a delete plan builds a delete request");

    assert_eq!(request.method(), Method::Delete);
    let body = body_of(&request);
    assert_eq!(
        body.pointer("/propagationPolicy"),
        Some(&json!("Foreground"))
    );
    assert_eq!(
        body.pointer("/preconditions/uid"),
        Some(&json!("pvc-uid-1"))
    );
    assert_eq!(
        body.pointer("/preconditions/resourceVersion"),
        Some(&json!("77"))
    );
}

/// §44.5: a dry run is a separate request, marked as one, and the caller has to ask for it.
#[test]
fn should_mark_a_dry_run_request_as_one() {
    let request = apply_request(
        &rollout_plan(),
        &deployments(),
        &ApplyOptions::new(FieldManager::ono()).as_dry_run(),
    )
    .expect("builds");

    assert!(request.target().contains("dryRun=All"));
}

/// An apply request built from a deletion plan would send a body nobody planned. The mismatch is a
/// refusal rather than a best effort.
#[test]
fn should_refuse_to_build_an_apply_request_from_a_deletion_plan() {
    let refusal = apply_request(
        &deletion_plan(),
        &claims(),
        &ApplyOptions::new(FieldManager::ono()),
    )
    .expect_err("a deletion is not an apply");

    assert!(matches!(refusal, MutationError::ActionMismatch { .. }));
}

/// §44.2: the field manager is stable and identifiable, and an empty one is refused rather than
/// sent — an apply with no manager makes the server invent one per request, which loses the
/// ownership tracking the apply was chosen for.
#[test]
fn should_refuse_a_field_manager_that_identifies_nobody() {
    assert_eq!(FieldManager::ono().as_str(), "ono-sendai");
    assert!(FieldManager::named("ono-sendai-session-7").is_ok());
    assert!(matches!(
        FieldManager::named("  "),
        Err(MutationError::UnusableFieldManager(_))
    ));
}

// --- what an acceptance means (§43, Gate G) ----------------------------------------------------

/// Gate G (§62.7) and §4 invariant 18. The server accepted a new pod template and said so. That is
/// the *first* rung of §20.4's ladder and nothing above it: the controller has not been asked, no
/// pod has been created, and no request has been served by the new image. The outcome may not
/// report a stage it did not reach.
#[test]
fn should_not_report_an_accepted_deployment_update_as_a_completed_rollout() {
    let plan = rollout_plan();
    let response = exchange(
        &apply_request(
            &plan,
            &deployments(),
            &ApplyOptions::new(FieldManager::ono()),
        )
        .expect("builds"),
        &http("200 OK", DEPLOYMENT_ACCEPTED),
    );

    let outcome = MutationOutcome::read(&plan, DryRun::Off, &response);

    assert_eq!(outcome.acceptance(), &Acceptance::Persisted);
    assert_eq!(outcome.established_stage(), Some(Stage::ApiAccepted));
    assert!(outcome.requires_verification());
    let description = outcome.describe();
    assert!(description.contains("accepted"));
    assert!(description.contains("not evidence"));
}

/// §44.5: a successful dry run proves that admission would accept the document. It is not a write,
/// and it is not a prediction of what the controllers do afterwards.
#[test]
fn should_not_treat_a_successful_dry_run_as_a_persisted_change() {
    let plan = rollout_plan();
    let response = exchange(
        &apply_request(
            &plan,
            &deployments(),
            &ApplyOptions::new(FieldManager::ono()).as_dry_run(),
        )
        .expect("builds"),
        &http("200 OK", DEPLOYMENT_ACCEPTED),
    );

    let outcome = MutationOutcome::read(&plan, DryRun::Server, &response);

    assert_eq!(outcome.acceptance(), &Acceptance::DryRun);
    assert!(!outcome.is_persisted());
    assert_eq!(outcome.established_stage(), None);
    assert!(outcome.describe().contains("dry run"));
}

/// §44.6: admission and defaulting change the document on the way in, and a dry run is where that
/// becomes visible before the write. The difference is reported as fields, not as prose.
#[test]
fn should_report_the_fields_admission_changed_in_the_dry_run() {
    let plan = rollout_plan();
    let defaulted = DEPLOYMENT_ACCEPTED.replace(
        r#""image":"shop/web:1.3.0""#,
        r#""image":"registry.internal/shop/web:1.3.0""#,
    );
    let response = exchange(
        &apply_request(
            &plan,
            &deployments(),
            &ApplyOptions::new(FieldManager::ono()).as_dry_run(),
        )
        .expect("builds"),
        &http("200 OK", &defaulted),
    );
    let outcome = MutationOutcome::read(&plan, DryRun::Server, &response);

    let differences = outcome.admission_differences(&apply_document(&plan).expect("document"));

    assert_eq!(differences.len(), 1);
    assert_eq!(
        differences[0].path(),
        "/spec/template/spec/containers/0/image"
    );
    assert_eq!(
        differences[0].to(),
        Some(&json!("registry.internal/shop/web:1.3.0"))
    );
}

// --- conflicts (§44.3, §44.4, §60.7) -----------------------------------------------------------

/// §44.3 and Gate-adjacent §60.7: a conflict names the manager that owns the field, and that
/// evidence survives to whoever reads the outcome. A conflict rendered as "the change failed"
/// loses the only fact that decides what to do next — which is who owns the field and why.
#[test]
fn should_name_the_manager_that_owns_the_field_in_a_conflict() {
    let plan = rollout_plan();
    let response = exchange(
        &apply_request(
            &plan,
            &deployments(),
            &ApplyOptions::new(FieldManager::ono()),
        )
        .expect("builds"),
        &conflict_status(),
    );

    let outcome = MutationOutcome::read(&plan, DryRun::Off, &response);
    let conflict = outcome.conflict().expect("a 409 with field manager causes");

    assert_eq!(conflict.managers(), vec!["argocd-controller"]);
    assert_eq!(
        conflict.fields()[0].field(),
        r#".spec.template.spec.containers[name="web"].image"#
    );
    assert!(outcome.describe().contains("argocd-controller"));
}

/// §44.3, the sentence with teeth: Ono must not force ownership merely to make the action succeed.
/// The resolution of a conflict is a choice somebody makes, and the type says so rather than
/// offering a retry that quietly wins.
#[test]
fn should_not_offer_force_as_the_resolution_of_a_conflict() {
    let plan = rollout_plan();
    let response = exchange(
        &apply_request(
            &plan,
            &deployments(),
            &ApplyOptions::new(FieldManager::ono()),
        )
        .expect("builds"),
        &conflict_status(),
    );
    let outcome = MutationOutcome::read(&plan, DryRun::Off, &response);
    let conflict = outcome.conflict().expect("a conflict");

    assert_eq!(conflict.resolution(), Resolution::ExplicitChoiceRequired);
    assert!(!conflict.is_automatically_resolvable());
    assert!(!outcome.requires_verification());
    assert!(conflict.describe().contains("explicit"));
}

// --- preconditions that did not hold (§56) -----------------------------------------------------

/// §56.1: somebody else wrote first. This is a lost update prevented, which is the precondition
/// doing its job — and the answer is a re-plan, not a repeat of the same request.
#[test]
fn should_report_a_resource_version_precondition_failure_as_a_lost_update() {
    let plan = rollout_plan();
    let body = r#"{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Conflict",
        "message":"Operation cannot be fulfilled on deployments.apps \"checkout\": the object has been modified; please apply your changes to the latest version and try again",
        "code":409}"#;
    let response = exchange(
        &apply_request(
            &plan,
            &deployments(),
            &ApplyOptions::new(FieldManager::ono()),
        )
        .expect("builds"),
        &http("409 Conflict", body),
    );

    let outcome = MutationOutcome::read(&plan, DryRun::Off, &response);

    let failure = outcome
        .precondition_failure()
        .expect("a 409 that is not a field manager conflict");
    assert_eq!(failure.kind(), PreconditionKind::ResourceVersion);
    assert!(outcome.conflict().is_none());
}

/// §56.3 and §16.3: the UID precondition refused a delete because the name now holds a different
/// object. Without the precondition this delete would have succeeded — against an object nobody
/// planned to touch. The refusal has to say that, rather than reading as a transient conflict.
#[test]
fn should_report_a_uid_precondition_failure_as_a_different_object_lifetime() {
    let plan = deletion_plan();
    let body = r#"{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Conflict",
        "message":"Precondition failed: UID in precondition: pvc-uid-1, UID in object meta: pvc-uid-2",
        "code":409}"#;
    let response = exchange(
        &delete_request(&plan, &claims(), &DeleteOptions::new()).expect("builds"),
        &http("409 Conflict", body),
    );

    let outcome = Deletion::read(&plan, &DeleteOptions::new(), &response)
        .expect_err("the delete did not happen");

    let failure = outcome
        .precondition_failure()
        .expect("a precondition failure");
    assert_eq!(failure.kind(), PreconditionKind::Uid);
    assert!(failure.describe().contains("lifetime"));
}

// --- deletion (§45, Gate H) --------------------------------------------------------------------

/// Gate H (§62.8) and §45.1/§45.3: the server accepted the delete and returned the object with a
/// `deletionTimestamp` and a finalizer still on it. The object is terminating. Reporting "deleted"
/// here is the single most consequential lie this provider could tell, because the operator moves
/// on to the next step believing the resource is gone.
#[test]
fn should_report_a_deletion_with_a_finalizer_as_terminating_rather_than_deleted() {
    let plan = deletion_plan();
    let response = exchange(
        &delete_request(&plan, &claims(), &DeleteOptions::new()).expect("builds"),
        &http("200 OK", CLAIM_TERMINATING),
    );

    let deletion = Deletion::read(&plan, &DeleteOptions::new(), &response).expect("accepted");

    assert!(matches!(
        deletion.state(),
        DeletionState::Terminating { .. }
    ));
    assert_eq!(
        deletion.pending_finalizers(),
        vec!["kubernetes.io/pvc-protection".to_owned()]
    );
    assert!(!deletion.is_object_absent());
    let description = deletion.describe();
    assert!(description.contains("terminating"));
    assert!(!description.contains("deleted"));
}

/// §45.1: a `Status: Success` body says the request was accepted and nothing about what became of
/// the object. "Accepted" is its own state, and calling it absence is inventing an observation.
#[test]
fn should_report_an_accepted_delete_without_an_object_as_accepted_only() {
    let plan = deletion_plan();
    let response = exchange(
        &delete_request(&plan, &claims(), &DeleteOptions::new()).expect("builds"),
        &http(
            "200 OK",
            r#"{"kind":"Status","apiVersion":"v1","status":"Success","code":200}"#,
        ),
    );

    let deletion = Deletion::read(&plan, &DeleteOptions::new(), &response).expect("accepted");

    assert_eq!(deletion.state(), &DeletionState::Accepted);
    assert!(!deletion.is_object_absent());
}

/// §21.4 and §4 invariant 13: a follow-up read that RBAC refused says nothing about whether the
/// object is gone. Treating a failed read as absence is how a permission boundary becomes a
/// completed deletion.
#[test]
fn should_not_read_a_denied_follow_up_read_as_absence() {
    let plan = deletion_plan();
    let response = exchange(
        &delete_request(&plan, &claims(), &DeleteOptions::new()).expect("builds"),
        &http("200 OK", CLAIM_TERMINATING),
    );
    let mut deletion = Deletion::read(&plan, &DeleteOptions::new(), &response).expect("accepted");

    deletion.observe_absence(Outcome::ReadDenied);

    assert!(!deletion.is_object_absent());
    assert!(matches!(
        deletion.state(),
        DeletionState::Terminating { .. }
    ));
    assert!(deletion.describe().contains("read denied"));
}

/// §45.1 again, the end of the sequence (§60.6): the finalizer was removed and a later read found
/// nothing. Absence is now an observation — and the external effects §45.5 warns about are still
/// not something this provider has seen.
#[test]
fn should_report_absence_only_when_a_read_proves_it_and_still_not_claim_external_effects() {
    let plan = deletion_plan();
    let response = exchange(
        &delete_request(&plan, &claims(), &DeleteOptions::new()).expect("builds"),
        &http("200 OK", CLAIM_TERMINATING),
    );
    let mut deletion = Deletion::read(&plan, &DeleteOptions::new(), &response).expect("accepted");

    deletion.observe_absence(Outcome::Absent);

    assert_eq!(deletion.state(), &DeletionState::Absent);
    assert!(deletion.is_object_absent());
    assert!(deletion.describe().contains("external effects"));
}

// --- verification (§46.3, §46.4, Gate G) -------------------------------------------------------

fn deadline() -> Deadline {
    Deadline::starting_at(
        ObservedAt::from_unix_millis(STARTED),
        Duration::from_secs(300),
    )
}

fn at(offset_secs: u64) -> ObservedAt {
    ObservedAt::from_unix_millis(STARTED + offset_secs * 1_000)
}

/// Gate G and §46.4. Before the deadline the rollout is pending; after it, verification is
/// *incomplete*. §46.4 says in as many words that a timeout does not mean the change failed, and
/// it certainly does not mean it worked — so the inconclusive answer is its own verdict, and both
/// questions a renderer might ask of it answer no.
#[test]
fn should_answer_pending_before_the_deadline_and_inconclusive_after_it() {
    let plan = rollout_plan();
    let accepted = object(DEPLOYMENT_ACCEPTED);

    let early = Verification::of(&plan, Observation::Object(&accepted), &deadline(), at(30));
    assert_eq!(early.verdict(), Verdict::Pending);
    // The spec is on the object; the controller has not recorded seeing it (§37.3).
    assert_eq!(early.reached(), Some(Stage::SpecObserved));

    let late = Verification::of(&plan, Observation::Object(&accepted), &deadline(), at(600));
    assert_eq!(late.verdict(), Verdict::Inconclusive);
    assert!(!late.verdict().is_success());
    assert!(!late.verdict().is_failure());
    assert!(late.describe().contains("verification incomplete"));
    assert!(late.describe().contains("not"));
}

/// §46.3's scale/rollout rule, satisfied: the controller observed the generation and the replica
/// counts converged, so `condition.rs` calls it converged and the verification says confirmed —
/// reaching `StatusConverged` and no further. Externally healthy is not an API fact (§20.4).
#[test]
fn should_confirm_a_rollout_only_when_the_controller_converged() {
    let plan = rollout_plan();
    let converged = object(DEPLOYMENT_CONVERGED);

    let verification =
        Verification::of(&plan, Observation::Object(&converged), &deadline(), at(60));

    assert_eq!(verification.verdict(), Verdict::Confirmed);
    assert!(verification.verdict().is_success());
    assert_eq!(verification.reached(), Some(Stage::StatusConverged));
    assert_ne!(verification.reached(), Some(Stage::ExternallyHealthy));
    assert!(
        verification
            .reconciliation()
            .expect("the rule read the object")
            .citations()
            .iter()
            .any(|citation| citation.path() == "/status/observedGeneration")
    );
}

/// §37.5 and §46.3: the controller says it gave up. That is evidence of failure by a named rule,
/// which is the only thing that turns an incomplete verification into a failed one (§46.4).
#[test]
fn should_refute_a_rollout_when_the_controller_reports_failure() {
    let plan = rollout_plan();
    let failed = object(DEPLOYMENT_FAILED);

    let verification = Verification::of(&plan, Observation::Object(&failed), &deadline(), at(60));

    assert_eq!(verification.verdict(), Verdict::Refuted);
    assert!(verification.verdict().is_failure());
    assert!(verification.describe().contains("ProgressDeadlineExceeded"));
}

/// §21.4: verification needs evidence, and a read that was denied produced none. Neither the
/// deadline nor the change is the subject here — the answer is that nobody could look.
#[test]
fn should_answer_inconclusive_when_the_target_could_not_be_read() {
    let plan = rollout_plan();

    let verification = Verification::of(
        &plan,
        Observation::Unobservable(Outcome::ReadDenied),
        &deadline(),
        at(30),
    );

    assert_eq!(verification.verdict(), Verdict::Inconclusive);
    assert!(verification.describe().contains("read denied"));
}

/// §16.3: the name now holds a different lifetime, so nothing about this object answers the
/// question that was asked. Calling that a failure would blame the change; calling it a success
/// would verify against an object the plan never targeted.
#[test]
fn should_answer_inconclusive_when_the_name_holds_a_different_lifetime() {
    let plan = rollout_plan();
    let recreated =
        object(&DEPLOYMENT_ACCEPTED.replace(r#""uid":"dep-uid-1""#, r#""uid":"dep-uid-9""#));

    let verification =
        Verification::of(&plan, Observation::Object(&recreated), &deadline(), at(30));

    assert_eq!(verification.verdict(), Verdict::Inconclusive);
    assert!(verification.describe().contains("lifetime"));
}

/// §45.1 and §16.3: for a deletion, absence is the verification — and a same-name object with a
/// different UID proves the planned lifetime ended just as well as an empty read does.
#[test]
fn should_confirm_a_deletion_by_absence_or_by_a_new_lifetime_under_the_name() {
    let plan = deletion_plan();

    let gone = Verification::of(&plan, Observation::Absent, &deadline(), at(30));
    assert_eq!(gone.verdict(), Verdict::Confirmed);

    let recreated = object(&CLAIM.replace(r#""uid":"pvc-uid-1""#, r#""uid":"pvc-uid-2""#));
    let replaced = Verification::of(&plan, Observation::Object(&recreated), &deadline(), at(30));
    assert_eq!(replaced.verdict(), Verdict::Confirmed);

    let still_there = object(CLAIM_TERMINATING);
    let terminating = Verification::of(
        &plan,
        Observation::Object(&still_there),
        &deadline(),
        at(30),
    );
    assert_eq!(terminating.verdict(), Verdict::Pending);
}

/// §46.3's cordon rule: reading the field back is the whole verification, and the verdict says so
/// by reaching `SpecObserved` and no further. A confirmed field is not a converged controller.
#[test]
fn should_confirm_a_field_change_without_claiming_a_controller_acted() {
    let node = object(NODE);
    let plan = Plan::of(
        &node,
        Action::apply(vec![FieldChange::set("/spec/unschedulable", json!(true))]),
    )
    .expect("guarded");
    let cordoned = object(&NODE.replace(r#""spec":{}"#, r#""spec":{"unschedulable":true}"#));

    let verification = Verification::of(&plan, Observation::Object(&cordoned), &deadline(), at(10));

    assert_eq!(verification.verdict(), Verdict::Confirmed);
    assert_eq!(verification.reached(), Some(Stage::SpecObserved));
}

/// §46.3: a plan that says its outcome cannot be verified gets an inconclusive answer however long
/// anybody waits. The plausible mistake is falling back to the nearest rule that would pass.
#[test]
fn should_answer_inconclusive_where_the_plan_has_no_verification_rule() {
    let plan = rollout_plan().without_verification_rule();
    let converged = object(DEPLOYMENT_CONVERGED);

    let verification =
        Verification::of(&plan, Observation::Object(&converged), &deadline(), at(600));

    assert_eq!(verification.verdict(), Verdict::Inconclusive);
    assert_eq!(verification.reached(), None);
    assert!(verification.describe().contains("cannot be verified"));
}

/// A plan is not a mutation, and a target assembled by hand cannot become one by accident: the
/// unguarded path stays visible on the request it produces, so a reviewer reading the wire format
/// sees what a reviewer reading the plan saw.
#[test]
fn should_send_no_preconditions_for_an_unguarded_plan() {
    let plan = Plan::unguarded(
        Target::named(
            INSTANCE,
            Gvk::new("", "v1", "ConfigMap"),
            Some("shop"),
            "settings",
        ),
        Action::apply(vec![FieldChange::set("/data/level", json!("debug"))]),
        "the object is generated and has no stable resourceVersion",
    );

    let document = apply_document(&plan).expect("builds");

    assert!(document.pointer("/metadata/resourceVersion").is_none());
    assert!(document.pointer("/metadata/uid").is_none());
    assert!(!plan.is_precondition_guarded());
}

// --- §33.6 the status subresource ----------------------------------------------------------------

/// §33.6: "where a CRD separates `status`, the provider SHOULD preserve desired/observed semantics
/// and mutation boundaries". The read half was already held — `schema.rs` keeps `Intent::Desired`
/// and `Intent::Observed` apart — and the mutation half was missing entirely: `--set
/// '{"/status/phase": "Running"}'` was assembled into the object document like any other field.
///
/// This provider refuses the write rather than routing it to `/status`. Two things go wrong
/// otherwise, and the quiet one is worse. Sent to the object endpoint, a status field is dropped
/// by the API server wherever the subresource exists, and the request answers `200` — a change
/// that reports success for having done nothing. Sent to `/status`, it succeeds, and Ono has
/// written observed state: a value that is supposed to be a controller's report of what it saw
/// now says what Ono typed, which is exactly the desired/observed collapse Gate G (§62.7) exists
/// to prevent. Neither is a boundary "preserved".
#[test]
fn should_refuse_to_write_observed_state_through_an_object_apply() {
    let plan = Plan::of(
        &object(DEPLOYMENT),
        Action::apply(vec![FieldChange::set(
            "/status/availableReplicas",
            json!(9),
        )]),
    )
    .expect("guarded");
    let refusal =
        apply_document(&plan).expect_err("a write to observed state is refused rather than sent");

    assert_eq!(
        refusal,
        MutationError::ObservedStateNotWritable("/status/availableReplicas".to_owned())
    );
    let said = refusal.to_string();
    assert!(said.contains("status"));
    assert!(said.contains("controller"));
}

/// The boundary is the `status` tree and nothing wider: a CRD with a field called `statusPage` or
/// an object whose spec holds `/spec/statusCheck` is an ordinary desired-state field, and refusing
/// it would be this provider inventing a restriction the API server does not have.
#[test]
fn should_not_mistake_a_field_whose_name_begins_with_status_for_observed_state() {
    let plan = Plan::of(
        &object(DEPLOYMENT),
        Action::apply(vec![FieldChange::set("/spec/statusPage", json!("on"))]),
    )
    .expect("guarded");
    let document = apply_document(&plan)
        .expect("a desired-state field whose name starts with `status` is desired state");

    assert_eq!(document["spec"]["statusPage"], json!("on"));
}

// --- JSON pointer escaping (RFC 6901) -------------------------------------------------------------

/// A label key contains a slash — `app.kubernetes.io/name` is the convention §23.4 names — and a
/// JSON pointer spells a slash inside a key as `~1`. An apply document that took the escape
/// literally would create a field called `app.kubernetes.io~1name` beside the labels rather than
/// setting the label, and the request would succeed.
#[test]
fn should_write_an_escaped_pointer_segment_as_the_key_it_spells() {
    let plan = Plan::of(
        &object(DEPLOYMENT),
        Action::apply(vec![FieldChange::set(
            "/metadata/labels/app.kubernetes.io~1name",
            json!("checkout"),
        )]),
    )
    .expect("guarded");
    let document = apply_document(&plan).expect("builds");

    assert_eq!(
        document["metadata"]["labels"]["app.kubernetes.io/name"],
        json!("checkout")
    );
    assert!(
        document["metadata"]["labels"]
            .get("app.kubernetes.io~1name")
            .is_none()
    );
}

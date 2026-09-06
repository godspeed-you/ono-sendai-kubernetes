//! What a change says about itself before anyone is asked to approve it.
//!
//! Specification §46 (prospective change), §56 (mutation preconditions), §45.2–§45.5 (propagation,
//! finalizers, dependents, storage) and §24.4 (ownership edges are impact evidence, not an order
//! of deletion).
//!
//! The mistake these tests exist to catch is the one that reads as competence: a plan that lists
//! what will change, states that the change is reversible because an inverse API call exists, and
//! says nothing about the pods that were replaced, the requests that were in flight, or the volume
//! a controller may reclaim afterwards. §46.5 is explicit that reapplying a previous spec is not a
//! rollback, and a plan that cannot say so is worse than no plan, because it invites the approval
//! it was supposed to inform.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::coverage::{Coverage, Gap, Outcome, Scope};
use ono_provider_kubernetes::discovery::{Gvk, Gvr};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::plan::{
    Action, Caveat, EffectKind, FieldChange, MissingPrecondition, Plan, PlanRefusal, Preflight,
    Propagation, Reversibility, Staleness, Target, VerificationRule,
};
use serde_json::json;

const INSTANCE: &str = "kubernetes:prod-eu";

const DEPLOYMENT: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{
    "name":"checkout","namespace":"shop","uid":"dep-uid-1","resourceVersion":"1041",
    "generation":7,
    "managedFields":[
      {"manager":"kube-controller-manager","operation":"Update"},
      {"manager":"argocd-controller","operation":"Apply"}
    ]
  },
  "spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"web","image":"shop/web:1.2.0"}]}}},
  "status":{"observedGeneration":7,"replicas":3,"updatedReplicas":3,"availableReplicas":3}
}"#;

const CLAIM_WITH_FINALIZER: &str = r#"{
  "apiVersion":"v1","kind":"PersistentVolumeClaim",
  "metadata":{
    "name":"orders-data","namespace":"shop","uid":"pvc-uid-1","resourceVersion":"77",
    "finalizers":["kubernetes.io/pvc-protection"]
  },
  "spec":{"storageClassName":"fast"}
}"#;

const TERMINATING_POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{
    "name":"web-1","namespace":"shop","uid":"pod-uid-1","resourceVersion":"900",
    "deletionTimestamp":"2026-09-05T09:00:00Z","finalizers":["example.com/drain"]
  },
  "spec":{}
}"#;

const REPLICA_SET: &str = r#"{
  "apiVersion":"apps/v1","kind":"ReplicaSet",
  "metadata":{
    "name":"checkout-59f","namespace":"shop","uid":"rs-uid-1","resourceVersion":"1042",
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"Deployment","name":"checkout","uid":"dep-uid-1",
       "controller":true,"blockOwnerDeletion":true}
    ]
  },
  "spec":{"replicas":3}
}"#;

fn object(json: &str) -> Object {
    Object::parse(INSTANCE, json).expect("the fixture is a Kubernetes object")
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

/// §56.1 and §56.3: a plan built from an object that was read carries both preconditions without
/// anybody remembering to attach them. The plausible mistake is a builder that accepts a target
/// and leaves the preconditions to the caller, which makes the unguarded mutation the shorter
/// sentence to write.
#[test]
fn should_carry_the_preconditions_of_the_object_it_was_planned_from() {
    let plan = Plan::of(&object(DEPLOYMENT), image_change()).expect("a read object guards itself");

    assert_eq!(plan.preconditions().resource_version(), Some("1041"));
    assert_eq!(plan.preconditions().uid(), Some("dep-uid-1"));
    assert!(plan.preconditions().guards_lost_update());
    assert!(plan.preconditions().guards_recreation());
    assert!(plan.is_precondition_guarded());
    assert!(plan.preconditions().missing().is_empty());
}

/// §56.1: a plan whose target was never observed has no `resourceVersion` to compare against, so
/// applying it would overwrite whatever arrived in between. Refused rather than attempted, and
/// the refusal names the missing precondition instead of saying "invalid".
#[test]
fn should_refuse_an_update_whose_target_carries_no_resource_version() {
    let target = Target::named(
        INSTANCE,
        Gvk::new("apps", "v1", "Deployment"),
        Some("shop"),
        "checkout",
    );

    let refusal = Plan::targeting(target, image_change()).expect_err("no version, no update");

    assert_eq!(
        refusal,
        PlanRefusal::MissingPrecondition(MissingPrecondition::ResourceVersion)
    );
    assert!(refusal.to_string().contains("resourceVersion"));
}

/// §56.3: a destructive operation without a UID precondition can land on a same-name object that
/// was recreated after the plan was made — which is the deletion of an object nobody planned to
/// delete (§16.3, Gate C).
#[test]
fn should_refuse_a_deletion_whose_target_carries_no_uid() {
    let target = Target::named(INSTANCE, Gvk::new("", "v1", "Pod"), Some("shop"), "web-1")
        .at_resource_version("900");

    let refusal = Plan::targeting(target, Action::delete(Propagation::Background))
        .expect_err("no uid, no deletion");

    assert_eq!(
        refusal,
        PlanRefusal::MissingPrecondition(MissingPrecondition::Uid)
    );
}

/// §43.4 and §56.1: the expert path exists and says what it is. The mistake worth preventing is a
/// `force`-shaped escape hatch that is silent — a plan that is unguarded and reads like any other.
#[test]
fn should_mark_an_unguarded_plan_rather_than_hiding_it() {
    let target = Target::named(
        INSTANCE,
        Gvk::new("", "v1", "ConfigMap"),
        Some("shop"),
        "settings",
    );

    let plan = Plan::unguarded(
        target,
        Action::apply(vec![FieldChange::set("/data/level", json!("debug"))]),
        "the object is generated and has no stable resourceVersion",
    );

    assert!(!plan.is_precondition_guarded());
    assert!(plan.caveats().iter().any(|caveat| matches!(
        caveat,
        Caveat::NoPreconditionGuardsTheTarget(reason) if reason.contains("generated")
    )));
    assert!(plan.describe().contains("no precondition"));
}

/// §56.2: a plan built from `resourceVersion` X is stale once the object has moved on, and the
/// answer is a re-plan rather than an apply that silently carries the old assumption.
#[test]
fn should_call_a_plan_stale_when_the_target_moved_since_it_was_built() {
    let plan = Plan::of(&object(DEPLOYMENT), image_change()).expect("guarded");
    let moved =
        object(&DEPLOYMENT.replace(r#""resourceVersion":"1041""#, r#""resourceVersion":"1099""#));

    let staleness = plan.staleness(&moved);

    assert_eq!(
        staleness,
        Staleness::Changed {
            planned: "1041".to_owned(),
            observed: "1099".to_owned()
        }
    );
    assert!(!staleness.permits_apply());
}

/// §16.3 and §56.3: a same-name object with a different UID is a different lifetime, and calling
/// that "stale" would invite the same fix a stale plan gets — re-read and apply. The plan has to
/// say the target is gone.
#[test]
fn should_call_a_plan_replaced_when_the_name_now_holds_a_different_lifetime() {
    let plan = Plan::of(&object(DEPLOYMENT), image_change()).expect("guarded");
    let recreated = object(&DEPLOYMENT.replace(r#""uid":"dep-uid-1""#, r#""uid":"dep-uid-2""#));

    let staleness = plan.staleness(&recreated);

    assert_eq!(
        staleness,
        Staleness::TargetReplaced {
            planned: "dep-uid-1".to_owned(),
            observed: "dep-uid-2".to_owned()
        }
    );
    assert!(!staleness.permits_apply());
}

/// A plan built from the object it targets is fresh against that same object. Without this the
/// staleness check could be vacuously safe by refusing everything.
#[test]
fn should_call_a_plan_fresh_against_the_object_it_was_built_from() {
    let deployment = object(DEPLOYMENT);
    let plan = Plan::of(&deployment, image_change()).expect("guarded");

    assert_eq!(plan.staleness(&deployment), Staleness::Fresh);
    assert!(plan.staleness(&deployment).permits_apply());
}

/// §46.5, the heart of this module. A container image change is reversible *as configuration* and
/// irreversible in every other respect: the pods that served the previous image are gone, and the
/// requests they were serving went with them. A plan that reports "reversible" because the old
/// image can be reapplied has answered a different question from the one an operator asked.
#[test]
fn should_separate_configuration_reversibility_from_pod_and_traffic_effects() {
    let plan = Plan::of(&object(DEPLOYMENT), image_change()).expect("guarded");

    let kinds: Vec<EffectKind> = plan.effects().iter().map(|effect| effect.kind()).collect();
    assert!(kinds.contains(&EffectKind::ConfigurationChanged));
    assert!(kinds.contains(&EffectKind::PodsReplaced));
    assert!(kinds.contains(&EffectKind::TrafficDisrupted));

    let configuration = plan
        .effects()
        .iter()
        .find(|effect| effect.kind() == EffectKind::ConfigurationChanged)
        .expect("the spec change is an effect");
    assert_eq!(
        configuration.reversibility(),
        Reversibility::ConfigurationReapplicable
    );

    // The plan's own answer is the weakest of its effects, never the friendliest.
    assert_eq!(plan.reversibility(), Reversibility::Irreversible);

    let recovery = plan.recovery();
    assert!(
        recovery
            .restores()
            .contains(&EffectKind::ConfigurationChanged)
    );
    assert!(
        recovery
            .does_not_restore()
            .contains(&EffectKind::PodsReplaced)
    );
    assert!(
        recovery
            .does_not_restore()
            .contains(&EffectKind::TrafficDisrupted)
    );
    assert!(recovery.describe().contains("not a rollback"));
}

/// §46.5 and §16.3: deleting an object is not undone by creating one with the same name, because
/// the new object has a new UID and no history. The recovery statement must not offer it.
#[test]
fn should_not_offer_recreation_as_recovery_for_a_deletion() {
    let plan = Plan::of(
        &object(CLAIM_WITH_FINALIZER),
        Action::delete(Propagation::Background),
    )
    .expect("guarded");

    assert_eq!(plan.reversibility(), Reversibility::Irreversible);
    assert!(
        plan.recovery()
            .does_not_restore()
            .contains(&EffectKind::ObjectRemoved)
    );
    assert!(plan.recovery().restores().is_empty());
}

/// §45.3: finalizers decide when a deletion completes, and the plan says so before the delete is
/// issued rather than after the object sits in `Terminating` for an hour.
#[test]
fn should_state_that_deletion_completion_depends_on_finalizer_removal() {
    let plan = Plan::of(
        &object(CLAIM_WITH_FINALIZER),
        Action::delete(Propagation::Foreground),
    )
    .expect("guarded");

    assert!(plan.caveats().iter().any(|caveat| matches!(
        caveat,
        Caveat::FinalizersMustBeRemoved(names) if names == &["kubernetes.io/pvc-protection"]
    )));
    assert!(plan.describe().contains("kubernetes.io/pvc-protection"));
}

/// §45.5: a PVC deletion reaches storage this provider does not see and cannot promise anything
/// about. The plausible mistake is silence, which reads as "nothing else happens".
#[test]
fn should_refuse_to_promise_storage_reclaim_for_a_claim_deletion() {
    let plan = Plan::of(
        &object(CLAIM_WITH_FINALIZER),
        Action::delete(Propagation::Background),
    )
    .expect("guarded");

    let kinds: Vec<EffectKind> = plan.effects().iter().map(|effect| effect.kind()).collect();
    assert!(kinds.contains(&EffectKind::PersistentDataAtRisk));
    assert!(kinds.contains(&EffectKind::ExternalSideEffects));
    assert!(
        plan.caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::StorageReclaimNotPromised))
    );
}

/// §45.2 and §24.4: the plan states the propagation policy it selected, and states that ownership
/// edges are impact evidence rather than a guaranteed order of removal. Orphaning is a different
/// outcome from removal and must not be described with the same words.
#[test]
fn should_state_the_propagation_policy_without_promising_deletion_order() {
    let removed =
        Plan::of(&object(DEPLOYMENT), Action::delete(Propagation::Foreground)).expect("guarded");
    let orphaned =
        Plan::of(&object(DEPLOYMENT), Action::delete(Propagation::Orphan)).expect("guarded");

    assert_eq!(removed.propagation(), Some(Propagation::Foreground));
    assert!(removed.describe().contains("Foreground"));
    assert!(
        removed
            .caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::DependentOrderNotGuaranteed))
    );

    let kinds: Vec<EffectKind> = orphaned
        .effects()
        .iter()
        .map(|effect| effect.kind())
        .collect();
    assert!(kinds.contains(&EffectKind::DependentsOrphaned));
    assert!(!kinds.contains(&EffectKind::DependentsRemoved));
}

/// §45.4: a dependent preview built from a listing that was denied is incomplete, and the plan
/// says so. Presenting the dependents that could be listed as "the dependents" is §4 invariant 13
/// lost at exactly the moment it is most expensive.
#[test]
fn should_report_the_dependent_preview_as_incomplete_when_a_type_could_not_be_listed() {
    let deployment = object(DEPLOYMENT);
    let mut coverage = Coverage::complete(Scope::in_namespace("shop"));
    coverage.record(Gap::new(Scope::in_namespace("shop"), Outcome::ListDenied));

    let plan = Plan::of(&deployment, Action::delete(Propagation::Background))
        .expect("guarded")
        .with_dependents(vec![object(REPLICA_SET)], coverage);

    assert_eq!(plan.dependents().len(), 1);
    assert!(
        plan.caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::DependentPreviewIncomplete))
    );
    assert!(plan.describe().contains("incomplete"));
}

/// §23.2 and §24.1: a dependent is an object carrying an owner reference to this target. An object
/// that merely sits in the same namespace is not evidence of anything, and admitting it would make
/// the impact preview a guess wearing a provider-proven label.
#[test]
fn should_not_accept_a_dependent_without_an_owner_reference_to_the_target() {
    let unrelated = object(&REPLICA_SET.replace(r#""uid":"dep-uid-1""#, r#""uid":"other-uid""#));

    let plan = Plan::of(&object(DEPLOYMENT), Action::delete(Propagation::Background))
        .expect("guarded")
        .with_dependents(
            vec![unrelated],
            Coverage::complete(Scope::in_namespace("shop")),
        );

    assert!(plan.dependents().is_empty());
}

/// §46.2: the permission preflight is part of the plan, and "nobody asked" is not "allowed". The
/// mistake is a boolean that defaults to `true` because the check has not been written yet.
#[test]
fn should_not_report_permission_as_granted_when_no_preflight_ran() {
    let plan = Plan::of(&object(DEPLOYMENT), image_change()).expect("guarded");

    assert_eq!(plan.preflight(), &Preflight::NotChecked);
    assert!(!plan.preflight().permits());
    assert!(
        plan.caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::PermissionNotVerified))
    );

    let denied = Plan::of(&object(DEPLOYMENT), image_change())
        .expect("guarded")
        .with_preflight(Preflight::denied("patch deployments is not allowed"));
    assert!(!denied.preflight().permits());
    assert!(
        denied
            .describe()
            .contains("patch deployments is not allowed")
    );
}

/// §21.2 and §21.6: a `SelfSubjectAccessReview` that said yes is *advisory*, and the plan says so
/// rather than dropping the subject once the answer was pleasant. The mistake is a plan that
/// reports `allowed` and carries no caveat at all, which reads as a guarantee the API server never
/// gave — authorization can change between the check and the request (§21.1).
#[test]
fn should_report_an_allowed_preflight_as_advisory_rather_than_as_permission() {
    let review = json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectAccessReview",
        "status": {"allowed": true, "denied": false, "reason": "RBAC: allowed by ClusterRole/edit"},
    });
    let preflight = Preflight::from_review(&review);
    assert_eq!(preflight, Preflight::Allowed);
    assert!(preflight.permits());
    assert_eq!(preflight.to_string(), "allowed by preflight check");

    let plan = Plan::of(&object(DEPLOYMENT), image_change())
        .expect("guarded")
        .with_preflight(preflight);
    assert!(
        !plan
            .caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::PermissionNotVerified)),
        "a preflight ran and granted it, so `nobody asked` is no longer true"
    );
    assert!(
        plan.caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::PermissionCheckIsAdvisory)),
        "§21.2: the check is advisory and the API request remains authoritative: {:?}",
        plan.caveats()
    );
    assert!(
        plan.describe().contains("authorization"),
        "Appendix E gives a plan an AUTHORIZATION line: {}",
        plan.describe()
    );
}

/// §21.1 and §21.4: an authorizer that expressed no opinion said neither yes nor no, and turning
/// `allowed: false` into a denial is this provider deciding an authorization question the API
/// server declined to decide. `denied: true` is the only denial there is.
#[test]
fn should_not_read_an_authorizer_with_no_opinion_as_a_denial() {
    let no_opinion = Preflight::from_review(&json!({
        "kind": "SelfSubjectAccessReview",
        "status": {"allowed": false, "denied": false},
    }));
    assert!(!no_opinion.permits(), "nothing granted this");
    assert!(
        !matches!(no_opinion, Preflight::Denied(_)),
        "no authorizer denied it either: {no_opinion:?}"
    );
    assert!(
        no_opinion.to_string().starts_with("unknown / unchecked"),
        "§21.6's third word: {no_opinion}"
    );

    let incomplete = Preflight::from_review(&json!({
        "kind": "SelfSubjectAccessReview",
        "status": {"allowed": false, "evaluationError": "webhook authorizer timed out"},
    }));
    assert!(!matches!(incomplete, Preflight::Denied(_)));
    assert!(
        incomplete
            .to_string()
            .contains("webhook authorizer timed out"),
        "what kept the answer from being one is the answer: {incomplete}"
    );

    let denied = Preflight::from_review(&json!({
        "kind": "SelfSubjectAccessReview",
        "status": {"allowed": false, "denied": true, "reason": "no RBAC policy matched"},
    }));
    assert_eq!(
        denied,
        Preflight::denied("no RBAC policy matched"),
        "an explicit denial is the only denial"
    );
}

/// §21.6: three words reach a user, and every state of the check maps onto exactly one of them.
/// The mistake is a fourth word — "unavailable", "error", "skipped" — which a reader has to
/// decide the safety of on their own.
#[test]
fn should_state_a_preflight_in_the_three_words_of_section_21_6() {
    assert_eq!(Preflight::Allowed.to_string(), "allowed by preflight check");
    assert!(
        Preflight::denied("no RBAC policy matched")
            .to_string()
            .starts_with("denied by preflight check"),
        "a denial names the reason after the words, and never instead of them"
    );
    assert_eq!(Preflight::NotChecked.to_string(), "unknown / unchecked");
    assert!(
        Preflight::not_answered("this cluster serves no authorization.k8s.io API group")
            .to_string()
            .starts_with("unknown / unchecked"),
        "a cluster that does not serve the review is not queried, never denied and never allowed"
    );
    assert!(!Preflight::not_answered("unserved").permits());
}

/// §21.2 and §13.1: the review names the action the plan would actually take, in the API server's
/// own vocabulary — a server-side apply is a `patch`, and the collection is the GVR's plural
/// rather than the GVK's kind. A review that asks about the wrong verb answers a question nobody
/// asked, truthfully.
#[test]
fn should_ask_about_the_action_the_plan_would_take_in_the_api_servers_words() {
    let review_kind = Gvk::new("authorization.k8s.io", "v1", "SelfSubjectAccessReview");
    let deployments = Gvr::new("apps", "v1", "deployments");

    let apply = Plan::of(&object(DEPLOYMENT), image_change()).expect("guarded");
    let document = ono_provider_kubernetes::plan::access_review(&apply, &deployments, &review_kind);
    assert_eq!(document["apiVersion"], json!("authorization.k8s.io/v1"));
    assert_eq!(document["kind"], json!("SelfSubjectAccessReview"));
    let attributes = &document["spec"]["resourceAttributes"];
    assert_eq!(attributes["verb"], json!("patch"), "an apply is a PATCH");
    assert_eq!(attributes["group"], json!("apps"));
    assert_eq!(attributes["version"], json!("v1"));
    assert_eq!(
        attributes["resource"],
        json!("deployments"),
        "§13.1: the REST collection, not the kind"
    );
    assert_eq!(attributes["namespace"], json!("shop"));
    assert_eq!(attributes["name"], json!("checkout"));

    let removal =
        Plan::of(&object(DEPLOYMENT), Action::delete(Propagation::Background)).expect("guarded");
    let document =
        ono_provider_kubernetes::plan::access_review(&removal, &deployments, &review_kind);
    assert_eq!(
        document["spec"]["resourceAttributes"]["verb"],
        json!("delete")
    );
}

/// §21.1: a denied preflight is still a plan. The provider does not evaluate RBAC, so it reports
/// what the API server said and keeps describing the change — hiding it would leave a user with
/// no way to see what they are asking to be granted.
#[test]
fn should_still_describe_a_change_whose_preflight_denied_it() {
    let plan = Plan::of(&object(DEPLOYMENT), image_change())
        .expect("guarded")
        .with_preflight(Preflight::denied("no RBAC policy matched"));

    assert!(!plan.preflight().permits());
    assert!(
        plan.caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::PermissionDeniedByPreflight(_))),
        "the denial is a caveat of its own, not the absence of a grant: {:?}",
        plan.caveats()
    );
    let described = plan.describe();
    assert!(described.contains("no RBAC policy matched"));
    assert!(
        described.contains("shop/web:1.3.0"),
        "the change is still described: {described}"
    );
}

/// §46.3: verification rules match action semantics. A Deployment template change is verified
/// through a controller, a Node cordon is verified by reading one field back, and a deletion is
/// verified by absence. Naming one rule for all three is how "the field is set" comes to be
/// reported as "the rollout finished" (Gate G).
#[test]
fn should_name_a_verification_rule_that_matches_the_action() {
    let rollout = Plan::of(&object(DEPLOYMENT), image_change()).expect("guarded");
    assert_eq!(
        rollout.verification_rule(),
        VerificationRule::ControllerConvergence
    );

    let node = object(
        r#"{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-a","uid":"n-1","resourceVersion":"5"},"spec":{}}"#,
    );
    let cordon = Plan::of(
        &node,
        Action::apply(vec![FieldChange::set("/spec/unschedulable", json!(true))]),
    )
    .expect("guarded");
    assert_eq!(cordon.verification_rule(), VerificationRule::FieldObserved);

    let deletion =
        Plan::of(&object(DEPLOYMENT), Action::delete(Propagation::Background)).expect("guarded");
    assert_eq!(deletion.verification_rule(), VerificationRule::Absence);
}

/// §46.3 again, from the other side: where this provider has no rule for what the action's success
/// would look like, the plan says the outcome cannot be verified rather than choosing the nearest
/// rule that would pass.
#[test]
fn should_say_when_no_verification_is_possible() {
    let plan = Plan::of(&object(DEPLOYMENT), image_change())
        .expect("guarded")
        .without_verification_rule();

    assert_eq!(plan.verification_rule(), VerificationRule::NoneKnown);
    assert!(
        plan.caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::NoVerificationRule))
    );
    assert!(plan.describe().contains("cannot be verified"));
}

/// §44.3 and §54.1: the managers already recorded on the object are the ones an apply may conflict
/// with, and a GitOps controller among them means this change may be reverted minutes later. The
/// plan names them before the apply rather than letting the conflict be the first mention.
#[test]
fn should_name_the_field_managers_the_object_already_records() {
    let plan = Plan::of(&object(DEPLOYMENT), image_change()).expect("guarded");

    assert!(plan.caveats().iter().any(|caveat| matches!(
        caveat,
        Caveat::OtherFieldManagers(managers)
            if managers.contains(&"argocd-controller".to_owned())
    )));
}

/// A plan that changes nothing is not a plan. Accepting one would produce an apply request whose
/// only effect is to take field ownership away from whoever holds it.
#[test]
fn should_refuse_a_change_that_changes_nothing() {
    let refusal =
        Plan::of(&object(DEPLOYMENT), Action::apply(Vec::new())).expect_err("nothing to apply");

    assert_eq!(refusal, PlanRefusal::EmptyChange);
}

/// §45.1: an object already carrying a `deletionTimestamp` is mid-deletion, and a second delete
/// changes nothing about when it finishes. The plan says so rather than presenting the action as
/// the one that will remove it.
#[test]
fn should_note_that_the_target_is_already_terminating() {
    let plan = Plan::of(
        &object(TERMINATING_POD),
        Action::delete(Propagation::Background),
    )
    .expect("guarded");

    assert!(
        plan.caveats()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::TargetAlreadyTerminating))
    );
}

/// §4 invariant 18 and §44.5: a plan describes what is *intended*, and nothing in it is evidence
/// that the intention was reached. The rendering has to carry that sentence, because a plan is
/// read at the moment somebody is deciding to say yes.
#[test]
fn should_describe_a_plan_without_claiming_its_outcome() {
    let description = Plan::of(&object(DEPLOYMENT), image_change())
        .expect("guarded")
        .describe();

    assert!(description.contains("kubernetes:prod-eu"));
    assert!(description.contains("apps/v1/Deployment"));
    assert!(description.contains("shop/checkout"));
    assert!(description.contains("/spec/template/spec/containers/0/image"));
    assert!(description.contains("shop/web:1.3.0"));
    assert!(description.contains("prospective"));
    assert!(description.contains("not evidence"));
    // No admission preview has been run, so the defaulting this change may acquire is unknown.
    assert!(description.contains("dry run"));
}

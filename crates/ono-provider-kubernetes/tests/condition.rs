//! Conditions as observations, and reconciliation states that name their evidence.
//!
//! Specification §37, §20.4, §4 invariants 8 and 9. Gate G: a successful spec update cannot be
//! rendered as a successful rollout until verification evidence arrives.
//!
//! Two failures are being held off here. The first is the dashboard reflex — reduce a resource to
//! one green word and lose the reason for it, which is the only part an operator can act on. The
//! second is subtler and is what Gate G is about: `observedGeneration == generation` reads like
//! success, and it means no more than "a controller has seen this generation". Between those two
//! lies most of the distance between a status display and an honest one, so every derived state
//! below has to say which fields decided it.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::condition::{
    ConditionStatus, PodView, ReconciliationState, Stage, condition, conditions, reconciliation,
};
use ono_provider_kubernetes::object::Object;

const DEPLOYMENT_SPEC_CHANGED: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"checkout","namespace":"shop","uid":"dep-1","generation":4},
  "spec":{"replicas":3},
  "status":{
    "observedGeneration":3,"replicas":3,"updatedReplicas":3,"availableReplicas":3,
    "conditions":[
      {"type":"Available","status":"True","reason":"MinimumReplicasAvailable",
       "message":"Deployment has minimum availability.",
       "lastTransitionTime":"2026-02-10T08:00:00Z","observedGeneration":3}
    ]
  }
}"#;

const DEPLOYMENT_ROLLING: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"checkout","namespace":"shop","uid":"dep-1","generation":4},
  "spec":{"replicas":3},
  "status":{
    "observedGeneration":4,"replicas":4,"updatedReplicas":1,"availableReplicas":2,
    "readyReplicas":2,
    "conditions":[
      {"type":"Available","status":"True","reason":"MinimumReplicasAvailable",
       "message":"Deployment has minimum availability.",
       "lastTransitionTime":"2026-02-10T08:00:00Z"},
      {"type":"Progressing","status":"True","reason":"ReplicaSetUpdated",
       "message":"ReplicaSet \"checkout-8b21\" is progressing.",
       "lastTransitionTime":"2026-02-11T09:14:00Z"}
    ]
  }
}"#;

const DEPLOYMENT_CONVERGED: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"checkout","namespace":"shop","uid":"dep-1","generation":4},
  "spec":{"replicas":3},
  "status":{
    "observedGeneration":4,"replicas":3,"updatedReplicas":3,"availableReplicas":3,
    "readyReplicas":3,
    "conditions":[
      {"type":"Available","status":"True","reason":"MinimumReplicasAvailable",
       "lastTransitionTime":"2026-02-10T08:00:00Z"},
      {"type":"Progressing","status":"True","reason":"NewReplicaSetAvailable",
       "lastTransitionTime":"2026-02-11T09:20:00Z"}
    ]
  }
}"#;

const DEPLOYMENT_FAILED: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"checkout","namespace":"shop","uid":"dep-1","generation":4},
  "spec":{"replicas":3},
  "status":{
    "observedGeneration":4,"replicas":4,"updatedReplicas":1,"availableReplicas":2,
    "conditions":[
      {"type":"Available","status":"True","reason":"MinimumReplicasAvailable",
       "lastTransitionTime":"2026-02-10T08:00:00Z"},
      {"type":"Progressing","status":"False","reason":"ProgressDeadlineExceeded",
       "message":"ReplicaSet \"checkout-8b21\" has timed out progressing.",
       "lastTransitionTime":"2026-02-11T09:30:00Z"}
    ]
  }
}"#;

const WIDGET_OBSERVED: &str = r#"{
  "apiVersion":"example.com/v1","kind":"Widget",
  "metadata":{"name":"left","namespace":"shop","uid":"w-1","generation":7},
  "status":{
    "observedGeneration":7,
    "conditions":[{"type":"Ready","status":"True","reason":"AllGood"}]
  }
}"#;

const WIDGET_UNOBSERVED: &str = r#"{
  "apiVersion":"example.com/v1","kind":"Widget",
  "metadata":{"name":"right","namespace":"shop","uid":"w-2","generation":4},
  "status":{"observedGeneration":2}
}"#;

const WIDGET_WITHOUT_STATUS: &str = r#"{
  "apiVersion":"example.com/v1","kind":"Widget",
  "metadata":{"name":"quiet","namespace":"shop","uid":"w-3","generation":4}
}"#;

const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"checkout-7f9d","namespace":"shop","uid":"pod-1"},
  "status":{
    "phase":"Running",
    "conditions":[
      {"type":"Initialized","status":"True","lastTransitionTime":"2026-02-11T09:00:00Z"},
      {"type":"Ready","status":"False","reason":"ContainersNotReady",
       "message":"containers with unready status: [app]",
       "lastTransitionTime":"2026-02-11T09:05:00Z"}
    ],
    "containerStatuses":[
      {"name":"app","ready":false,"restartCount":7,
       "state":{"waiting":{"reason":"CrashLoopBackOff",
                           "message":"back-off 5m0s restarting failed container"}}},
      {"name":"sidecar","ready":false,"restartCount":1,
       "state":{"terminated":{"reason":"OOMKilled","exitCode":137}}}
    ]
  }
}"#;

fn parse(json: &str) -> Object {
    Object::parse("kubernetes:prod-eu", json).expect("the fixture is a Kubernetes object")
}

#[test]
fn should_present_conditions_as_structured_observations() {
    // §37.1 and §4 invariant 9. The opposite is the dashboard reflex: reduce the object to
    // "Progressing" and drop reason, message and the generation the observation belongs to —
    // which are the parts that say what to do next and whether the observation is even current.
    let object = parse(DEPLOYMENT_SPEC_CHANGED);
    let observed = conditions(&object);
    let available = condition(&observed, "Available").expect("the fixture has an Available");

    assert_eq!(available.type_name(), "Available");
    assert_eq!(available.status(), &ConditionStatus::True);
    assert_eq!(available.reason(), Some("MinimumReplicasAvailable"));
    assert_eq!(
        available.message(),
        Some("Deployment has minimum availability.")
    );
    assert_eq!(available.observed_generation(), Some(3));
    assert_eq!(
        available.last_transition_time(),
        Some("2026-02-10T08:00:00Z")
    );
}

#[test]
fn should_keep_conditions_of_the_same_status_distinguishable() {
    // §4 invariant 9. Two conditions can both be "True" and mean opposite things; folding them
    // into one status string loses that a Deployment is simultaneously available on the old
    // replicas and progressing towards new ones.
    let object = parse(DEPLOYMENT_ROLLING);
    let observed = conditions(&object);

    assert_eq!(observed.len(), 2);
    let reasons: Vec<Option<&str>> = observed.iter().map(|item| item.reason()).collect();
    assert_eq!(
        reasons,
        [Some("MinimumReplicasAvailable"), Some("ReplicaSetUpdated")],
        "each condition keeps its own reason"
    );
}

#[test]
fn should_report_optional_condition_fields_as_absent_rather_than_zero() {
    // AGENTS.md: unknown data is null, never fabricated and never zero. An `observedGeneration`
    // defaulted to 0 would read as "a controller observed generation 0", which is a claim the
    // object never made.
    let object = parse(WIDGET_OBSERVED);
    let observed = conditions(&object);
    let ready = condition(&observed, "Ready").expect("the fixture has a Ready");

    assert_eq!(ready.observed_generation(), None);
    assert_eq!(ready.last_transition_time(), None);
    assert_eq!(ready.message(), None);
}

#[test]
fn should_carry_an_unrecognised_condition_status_verbatim() {
    // §37.2: condition semantics are kind-specific, and so are the values a controller writes.
    // Coercing anything that is not "True" to false would turn a third-party controller's
    // vocabulary into a wrong answer rather than an unfamiliar one.
    let object = parse(
        r#"{"apiVersion":"example.com/v1","kind":"Widget",
            "metadata":{"name":"odd","namespace":"shop"},
            "status":{"conditions":[
              {"type":"Sync","status":"Unknown"},
              {"type":"Drift","status":"Degraded"}]}}"#,
    );
    let observed = conditions(&object);

    assert_eq!(observed[0].status(), &ConditionStatus::Unknown);
    assert_eq!(
        observed[1].status(),
        &ConditionStatus::Other("Degraded".to_owned())
    );
    assert_eq!(observed[1].status().as_str(), "Degraded");
    assert!(
        !observed[1].status().is_true(),
        "an unfamiliar value is not an affirmative one"
    );
}

#[test]
fn should_not_call_a_spec_change_a_rollout_until_the_controller_observed_it() {
    // Gate G and §20.4. `metadata.generation` moved because the API accepted a spec change; that
    // is the first stage of five and proves nothing about the four after it. Rendering the
    // accepted write as a finished rollout is the exact failure the gate names.
    let object = parse(DEPLOYMENT_SPEC_CHANGED);
    let derived = reconciliation(&object);

    assert_eq!(
        derived.state(),
        ReconciliationState::DesiredChangedNotObserved
    );
    assert!(!derived.state().is_verified_convergence());
    assert_eq!(
        derived.state().established_stage(),
        Some(Stage::SpecObserved)
    );
}

#[test]
fn should_keep_desired_and_observed_generation_separately_cited() {
    // §4 invariant 8 and §37.5. The state is only as trustworthy as the reader's ability to
    // check it, so the two numbers that disagree must both appear, from their own paths. A
    // derived state that cites nothing is a verdict, not an observation.
    let object = parse(DEPLOYMENT_SPEC_CHANGED);
    let derived = reconciliation(&object);
    let cited: Vec<(&str, Option<&str>)> = derived
        .citations()
        .iter()
        .map(|item| (item.path(), item.value()))
        .collect();

    assert!(cited.contains(&("/metadata/generation", Some("4"))));
    assert!(cited.contains(&("/status/observedGeneration", Some("3"))));
}

#[test]
fn should_report_convergence_pending_while_replicas_lag() {
    // §37.5. The controller has seen the generation, so the honest state is "observed,
    // convergence pending" — not converged. Treating the observation as the outcome is how a
    // half-rolled-out Deployment gets reported as done.
    let object = parse(DEPLOYMENT_ROLLING);
    let derived = reconciliation(&object);

    assert_eq!(
        derived.state(),
        ReconciliationState::ObservedConvergencePending
    );
    let paths: Vec<&str> = derived.citations().iter().map(|item| item.path()).collect();
    assert!(paths.contains(&"/status/updatedReplicas"));
    assert!(paths.contains(&"/spec/replicas"));
}

#[test]
fn should_report_convergence_only_with_the_replica_evidence_for_it() {
    // §37.5 permits "converged by provider-specific rule", and the rule has to be nameable so a
    // reader can decide whether they believe it. The mistake it guards against is calling the
    // rollout done because the newest ReplicaSet exists.
    let object = parse(DEPLOYMENT_CONVERGED);
    let derived = reconciliation(&object);

    assert_eq!(derived.state(), ReconciliationState::Converged);
    assert!(derived.state().is_verified_convergence());
    assert_eq!(derived.rule(), "deployment-generation-and-replicas");
    let paths: Vec<&str> = derived.citations().iter().map(|item| item.path()).collect();
    assert!(paths.contains(&"/status/availableReplicas"));
}

#[test]
fn should_report_failure_from_the_condition_that_says_so() {
    // §37.5. `ProgressDeadlineExceeded` is the controller stating that it gave up; without it,
    // a stalled rollout is indistinguishable from a slow one and would sit in "pending" forever.
    let object = parse(DEPLOYMENT_FAILED);
    let derived = reconciliation(&object);

    assert_eq!(derived.state(), ReconciliationState::Failed);
    let described = derived.describe();
    assert!(
        described.contains("ProgressDeadlineExceeded"),
        "the failure names the reason it read: {described}"
    );
}

#[test]
fn should_not_call_an_observed_generation_healthy() {
    // §37.3, stated almost verbatim: observed generation is evidence that a controller saw a
    // desired state, and MUST NOT by itself be labelled healthy or successful. The Widget below
    // even carries `Ready=True`, and this provider has no rule for what Ready means on a Widget
    // (§37.2), so the most it may say is that the generation was observed.
    let object = parse(WIDGET_OBSERVED);
    let derived = reconciliation(&object);

    assert_eq!(
        derived.state(),
        ReconciliationState::ObservedConvergencePending
    );
    assert!(!derived.state().is_verified_convergence());
    assert_eq!(derived.rule(), "generation-observed-only");
}

#[test]
fn should_report_an_unobserved_generation_for_any_kind() {
    // §14.4 and §37.3. A generation ahead of the observed one is kind-independent evidence: it
    // says the controller has not caught up, without claiming to know what catching up means for
    // this kind.
    let object = parse(WIDGET_UNOBSERVED);
    let derived = reconciliation(&object);

    assert_eq!(
        derived.state(),
        ReconciliationState::DesiredChangedNotObserved
    );
}

#[test]
fn should_report_unknown_when_the_object_offers_no_evidence() {
    // §37.5's last state, and the one a status display never has. A resource whose controller
    // writes no status is not converged and not broken; saying so is the only honest answer, and
    // the citation has to show that the fields were looked for and absent.
    let object = parse(WIDGET_WITHOUT_STATUS);
    let derived = reconciliation(&object);

    assert_eq!(
        derived.state(),
        ReconciliationState::UnknownInsufficientEvidence
    );
    assert_eq!(derived.state().established_stage(), None);
    let cited: Vec<(&str, Option<&str>)> = derived
        .citations()
        .iter()
        .map(|item| (item.path(), item.value()))
        .collect();
    assert!(
        cited.contains(&("/status/observedGeneration", None)),
        "the absent field is cited as absent: {cited:?}"
    );
}

#[test]
fn should_cite_fields_that_match_the_object_for_every_derived_state() {
    // §37.5, last line: every derived state MUST cite the fields it depends on. This is the
    // property that makes the other reconciliation tests worth anything — a citation that does
    // not match the object is a decoration, and a state without one is unfalsifiable.
    let fixtures = [
        DEPLOYMENT_SPEC_CHANGED,
        DEPLOYMENT_ROLLING,
        DEPLOYMENT_CONVERGED,
        DEPLOYMENT_FAILED,
        WIDGET_OBSERVED,
        WIDGET_WITHOUT_STATUS,
    ];
    let mut seen = Vec::new();

    for fixture in fixtures {
        let object = parse(fixture);
        let derived = reconciliation(&object);
        seen.push(derived.state());

        assert!(
            !derived.citations().is_empty(),
            "{} cited nothing",
            derived.state().as_str()
        );
        for citation in derived.citations() {
            let held = object.field(citation.path()).map(|value| {
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned)
            });
            assert_eq!(
                citation.value().map(str::to_owned),
                held,
                "citation {} does not match the object it claims to read",
                citation.path()
            );
        }
    }

    for state in [
        ReconciliationState::DesiredChangedNotObserved,
        ReconciliationState::ObservedConvergencePending,
        ReconciliationState::Converged,
        ReconciliationState::Failed,
        ReconciliationState::UnknownInsufficientEvidence,
    ] {
        assert!(
            seen.contains(&state),
            "{} was never exercised",
            state.as_str()
        );
    }
}

#[test]
fn should_never_claim_external_health_from_an_api_read() {
    // §20.4: the five stages are distinct and no one of them proves the next. "Workload
    // externally healthy" is the stage the API server cannot speak to — it needs a probe, a
    // request, a metric — so no state derived from an object may reach it.
    for state in [
        ReconciliationState::DesiredChangedNotObserved,
        ReconciliationState::ObservedConvergencePending,
        ReconciliationState::Converged,
        ReconciliationState::Failed,
        ReconciliationState::UnknownInsufficientEvidence,
    ] {
        assert_ne!(
            state.established_stage(),
            Some(Stage::ExternallyHealthy),
            "{} claimed external health",
            state.as_str()
        );
    }
    assert_eq!(
        ReconciliationState::Converged.established_stage(),
        Some(Stage::StatusConverged)
    );
}

#[test]
fn should_surface_pod_phase_without_hiding_the_container_failure() {
    // §37.4. `Running` is true and useless here: one container is crash-looping and another was
    // OOM-killed. A summary that stops at the phase is how a Pod gets called healthy while it
    // restarts every five minutes.
    let object = parse(POD);
    let view = PodView::of(&object).expect("the fixture is a Pod");
    let summary = view.summary_line();

    assert_eq!(view.phase(), Some("Running"));
    assert!(summary.contains("Running"), "{summary}");
    assert!(summary.contains("CrashLoopBackOff"), "{summary}");
    assert!(summary.contains("OOMKilled"), "{summary}");
    assert!(summary.contains("ContainersNotReady"), "{summary}");
}

#[test]
fn should_read_container_state_reason_and_restart_count() {
    // §37.4 asks for container status beside conditions when diagnosing failure. Restart count
    // and exit code are what separate "starting" from "failing repeatedly" and "killed for
    // memory" from "exited cleanly"; without them the reason word alone invites a guess.
    let object = parse(POD);
    let view = PodView::of(&object).expect("the fixture is a Pod");
    let containers = view.container_statuses();

    assert_eq!(containers[0].name(), "app");
    assert!(!containers[0].is_ready());
    assert_eq!(containers[0].restart_count(), Some(7));
    assert_eq!(containers[0].state(), Some("waiting"));
    assert_eq!(containers[0].reason(), Some("CrashLoopBackOff"));
    assert_eq!(containers[1].state(), Some("terminated"));
    assert_eq!(containers[1].exit_code(), Some(137));
    assert_eq!(view.ready_container_count(), 0);
}

#[test]
fn should_offer_a_pod_view_only_for_pods() {
    // §37.2. Phase is a Pod concept; a Deployment has none, and inventing one from its conditions
    // would be the provider assuming a vocabulary the kind does not use.
    assert!(PodView::of(&parse(DEPLOYMENT_ROLLING)).is_none());
}

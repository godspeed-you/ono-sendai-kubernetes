//! What `why` may say, and the sentence it has no way to construct.
//!
//! Specification §40 and §23.4, and §11.3 of the Cloud-Native Vision. The section is almost
//! entirely a list of refusals: a provider contributes evidence to Ono's causal model and does not
//! generate authoritative explanations from heuristics (§40.1); an owner reference is management
//! responsibility rather than cause (§40.4); and `why` must be allowed to conclude that the
//! evidence is insufficient (§40.5).
//!
//! The demonstration these tests are built around is the one the specification's readers reach for
//! first: a policy change observed at 14:21 and a readiness failure at 14:22. Two observations,
//! one clock, sixty seconds apart — and still nothing but a correlation. So the tests below check
//! that the strongest word available is `ASSERTED_BY_KUBERNETES`, that proximity can only ever
//! produce `CORRELATED_WITH`, and that no path through this module reaches a claim of causation.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::causal::{Claim, Finding, Support, Unproven, Why};
use ono_provider_kubernetes::condition::{condition, conditions};
use ono_provider_kubernetes::coverage::{Coverage, Gap, Outcome, Scope};
use ono_provider_kubernetes::events::Event;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::relationship::{Graph, Relation};
use ono_provider_kubernetes::temporal::{ClockSource, Observation, Stamp};
use ono_provider_kubernetes::transport::ObservedAt;

const INSTANCE: &str = "kubernetes:prod-eu";

const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{
    "name":"checkout-7f9d","namespace":"shop","uid":"pod-1",
    "labels":{"app":"checkout"},
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"ReplicaSet","name":"checkout-7f9d","uid":"rs-1",
       "controller":true,"blockOwnerDeletion":true}
    ]
  },
  "spec":{"nodeName":"worker-03"}
}"#;

const SERVICE: &str = r#"{
  "apiVersion":"v1","kind":"Service",
  "metadata":{"name":"checkout","namespace":"shop","uid":"svc-1"},
  "spec":{"selector":{"app":"checkout"}}
}"#;

/// A Deployment whose controller has caught up with the spec it was given.
const CURRENT_DEPLOYMENT: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"checkout","namespace":"shop","uid":"dep-1","generation":8},
  "status":{"conditions":[
    {"type":"Progressing","status":"True","observedGeneration":8,
     "lastTransitionTime":"2026-09-05T14:20:00Z"}
  ]}
}"#;

/// The same Deployment before its controller has seen the newest spec (§37.3).
const STALE_DEPLOYMENT: &str = r#"{
  "apiVersion":"apps/v1","kind":"Deployment",
  "metadata":{"name":"checkout","namespace":"shop","uid":"dep-1","generation":8},
  "status":{"conditions":[
    {"type":"Progressing","status":"True","observedGeneration":7,
     "lastTransitionTime":"2026-09-05T14:20:00Z"}
  ]}
}"#;

const EVENT: &str = r#"{
  "apiVersion":"events.k8s.io/v1","kind":"Event",
  "metadata":{"name":"checkout-7f9d.17c1","namespace":"shop","uid":"ev-1"},
  "eventTime":"2026-09-05T14:21:30.500000Z",
  "reportingController":"default-scheduler","reason":"FailedScheduling","type":"Warning",
  "regarding":{"apiVersion":"v1","kind":"Pod","namespace":"shop","name":"checkout-7f9d","uid":"pod-1"}
}"#;

fn object(json: &str) -> Object {
    Object::parse(INSTANCE, json).expect("the fixture is a well-formed object")
}

/// The policy change at 14:21 and the readiness failure at 14:22, both seen by this provider.
fn policy_change_and_failure() -> (Observation, Observation) {
    let pod = object(POD);
    (
        Observation::watched(
            pod.identity(),
            ObservedAt::from_unix_millis(1_757_082_060_000),
            "NetworkPolicy shop/deny-external modified",
        ),
        Observation::watched(
            pod.identity(),
            ObservedAt::from_unix_millis(1_757_082_120_000),
            "Pod shop/checkout-7f9d Ready=False",
        ),
    )
}

// --- proximity is never causation ------------------------------------------------------------------

#[test]
fn should_report_temporal_proximity_as_correlation_and_nothing_more() {
    // §23.4 of the generic contract: a provider MUST NOT infer causality solely from timestamp
    // proximity. The plausible mistake is the one every incident review makes out loud — the
    // change at 14:21 broke the thing at 14:22 — and the type is what stops it being written down
    // as a provider fact.
    let (change, failure) = policy_change_and_failure();
    let finding = Finding::proximity(object(POD).identity(), &change, &failure, 5 * 60 * 1_000);

    assert_eq!(finding.claim(), Claim::CorrelatedWith);
    assert_eq!(finding.claim().as_str(), "CORRELATED_WITH");
    assert_eq!(
        finding.support(),
        &Support::Sequence {
            clock: ClockSource::Provider,
            apart_millis: 60_000,
        }
    );
}

#[test]
fn should_never_return_anything_stronger_than_correlation_from_proximity() {
    // The structural half of the rule. `Finding::proximity` has two reachable outcomes and
    // neither of them climbs the ladder: however close two observations are, closeness is all
    // that is being reported.
    let (change, failure) = policy_change_and_failure();
    let subject = object(POD).identity();

    for window in [0, 1, 59_999, 60_000, u64::MAX] {
        let claim = Finding::proximity(subject.clone(), &change, &failure, window).claim();
        assert!(
            matches!(claim, Claim::CorrelatedWith | Claim::CausalityNotProven),
            "proximity produced {claim:?} at a window of {window}ms"
        );
    }
}

#[test]
fn should_refuse_to_correlate_observations_from_two_clocks() {
    // §39.2. Correlation needs a distance, a distance needs one clock, and a `creationTimestamp`
    // against this machine's acquisition time is skew plus elapsed time. The plausible mistake is
    // to parse both into milliseconds and subtract.
    let subject = object(POD).identity();
    let here = Observation::watched(
        subject.clone(),
        ObservedAt::from_unix_millis(1_757_082_060_000),
        "observed here",
    );
    let there = Observation::reported(
        subject.clone(),
        ono_provider_kubernetes::temporal::ReportedSource::ObjectMetadata,
        Stamp::api_server("2026-09-05T14:21:00Z"),
        "created",
    );

    let finding = Finding::proximity(subject, &here, &there, 5 * 60 * 1_000);
    assert_eq!(finding.claim(), Claim::CausalityNotProven);
    assert_eq!(
        finding.support(),
        &Support::Nothing(Unproven::ClocksDisagree)
    );
}

#[test]
fn should_report_order_on_one_clock_as_precedence_only() {
    // Precedence is a real and useful fact — it rules explanations out — and it is still not a
    // cause. Reporting it under a stronger word is how "A came first" becomes "A did it".
    let (change, failure) = policy_change_and_failure();
    let subject = object(POD).identity();

    let forwards = Finding::precedence(subject.clone(), &change, &failure);
    assert_eq!(forwards.claim(), Claim::PrecededBy);
    assert_eq!(forwards.claim().as_str(), "PRECEDED_BY");

    let backwards = Finding::precedence(subject, &failure, &change);
    assert_eq!(backwards.claim(), Claim::CausalityNotProven);
    assert_eq!(
        backwards.support(),
        &Support::Nothing(Unproven::NotInThatOrder),
        "the later observation did not precede the earlier one, and saying so is the answer"
    );
}

// --- a dependency path is possibility, not history ----------------------------------------------------

#[test]
fn should_report_a_dependency_path_as_influence_that_was_possible() {
    // §23 and §40.3. A path from a Pod to the Node it is scheduled on means influence could have
    // travelled; it says nothing about whether it did. The plausible mistake is to present a
    // reachable neighbour as the explanation because it is the only one on screen.
    let pod = object(POD);
    let path: Vec<_> = Graph::edges_of(&pod)
        .into_iter()
        .filter(|edge| edge.relation() == Relation::ScheduledOn)
        .collect();
    assert_eq!(path.len(), 1, "the fixture Pod is scheduled");

    let finding = Finding::dependency_path(pod.identity(), path);
    assert_eq!(finding.claim(), Claim::DependencyPathExists);
    assert_eq!(finding.claim().as_str(), "DEPENDENCY_PATH_EXISTS");
    assert!(
        finding.claim().means().contains("possible"),
        "the word must carry its own limit: {}",
        finding.claim().means()
    );
    assert!(finding.describe().contains("scheduled-on"));
}

#[test]
fn should_report_an_empty_path_as_not_proven() {
    // No edges, no claim. An empty path rendered as "no dependency" would be an assertion about
    // the cluster; it is an assertion about the traversal.
    let finding = Finding::dependency_path(object(POD).identity(), Vec::new());
    assert_eq!(finding.claim(), Claim::CausalityNotProven);
    assert_eq!(finding.support(), &Support::Nothing(Unproven::NoPath));
}

// --- what Kubernetes itself states ---------------------------------------------------------------------

#[test]
fn should_distinguish_a_kubernetes_assertion_from_a_derivation() {
    // §23.4 permits provider-native causality where the system actually asserts it. An
    // ownerReference is such an assertion; a selector this provider evaluated is not, however
    // confident the match. Collapsing the two is how a guess arrives in the shape of a fact
    // (§4 invariant 20).
    let pod = object(POD);
    let controller = Graph::edges_of(&pod)
        .into_iter()
        .find(|edge| edge.relation() == Relation::ControlledBy)
        .expect("the fixture Pod names a controller");
    let asserted = Finding::asserted(pod.identity(), &controller);
    assert_eq!(asserted.claim(), Claim::AssertedByKubernetes);
    assert_eq!(asserted.claim().as_str(), "ASSERTED_BY_KUBERNETES");

    let selected = Graph::selects(&object(SERVICE), std::slice::from_ref(&pod))
        .into_iter()
        .next()
        .expect("the fixture Service selects the fixture Pod");
    let derived = Finding::asserted(pod.identity(), &selected);
    assert_eq!(
        derived.claim(),
        Claim::CausalityNotProven,
        "a selector evaluation is this provider's work, not the API server's statement"
    );
    assert_eq!(derived.support(), &Support::Nothing(Unproven::NotAsserted));
}

#[test]
fn should_read_a_current_observed_generation_as_an_assertion_about_the_controller() {
    // §37.3 and §40.4. `observedGeneration` equal to `generation` is the API's own record that
    // this controller acted on this spec — a statement about responsibility that the provider did
    // not derive.
    let deployment = object(CURRENT_DEPLOYMENT);
    let found = conditions(&deployment);
    let progressing = condition(&found, "Progressing").expect("the fixture has one");

    let finding = Finding::controller_acknowledged(deployment.identity(), &deployment, progressing);
    assert_eq!(finding.claim(), Claim::AssertedByKubernetes);
    assert!(finding.describe().contains("observedGeneration"));
}

#[test]
fn should_read_a_stale_observed_generation_as_no_assertion_at_all() {
    // The controller has not seen generation 8, so nothing it wrote is about generation 8.
    // Treating a stale status as the controller's verdict on the current spec is §37.3's whole
    // warning, and it is the mistake that makes a rollout look finished.
    let deployment = object(STALE_DEPLOYMENT);
    let found = conditions(&deployment);
    let progressing = condition(&found, "Progressing").expect("the fixture has one");

    let finding = Finding::controller_acknowledged(deployment.identity(), &deployment, progressing);
    assert_eq!(finding.claim(), Claim::CausalityNotProven);
    assert_eq!(finding.support(), &Support::Nothing(Unproven::NotAsserted));
}

#[test]
fn should_read_an_events_regarding_as_an_assertion_and_a_foreign_event_as_none() {
    // §38.3. `regarding` is structure the API server carries, so which object a reporter acted
    // about is asserted rather than guessed. The reporter's *note* is not, and nothing here
    // promotes it.
    let pod = object(POD);
    let raw = object(EVENT);
    let event = Event::from_object(&raw).expect("the fixture is an Event");

    let about_it = Finding::event_regards(pod.identity(), &event);
    assert_eq!(about_it.claim(), Claim::AssertedByKubernetes);

    let other = object(
        r#"{"apiVersion":"v1","kind":"Pod",
            "metadata":{"name":"basket-1","namespace":"shop","uid":"pod-9"},"spec":{}}"#,
    );
    let about_other = Finding::event_regards(other.identity(), &event);
    assert_eq!(about_other.claim(), Claim::CausalityNotProven);
    assert_eq!(
        about_other.support(),
        &Support::Nothing(Unproven::NotAsserted)
    );
}

// --- the ladder, and its top ------------------------------------------------------------------------------

#[test]
fn should_stop_the_ladder_short_of_causation() {
    // The point of the whole module. Five rungs, and the highest is a statement that Kubernetes
    // makes about management responsibility — which §40.4 says is not necessarily the cause of
    // any particular state change. There is no sixth rung to reach for.
    let ladder = Claim::ladder();
    assert_eq!(ladder.len(), 5);
    assert_eq!(
        ladder.map(Claim::as_str),
        [
            "CAUSALITY_NOT_PROVEN",
            "CORRELATED_WITH",
            "PRECEDED_BY",
            "DEPENDENCY_PATH_EXISTS",
            "ASSERTED_BY_KUBERNETES",
        ]
    );
    for rung in ladder {
        let word = rung.as_str();
        assert!(
            !word.contains("CAUSED") && !word.contains("CAUSES"),
            "`{word}` reads as a claim of causation"
        );
    }
}

#[test]
fn should_have_no_vocabulary_for_causation_in_the_module_itself() {
    // A reviewer's attention is not a mechanism. This reads the module the way `tests/events.rs`
    // reads its own, so that a later variant called `Caused` fails here rather than in an incident
    // review — the discipline stays in the source, checked.
    let source = include_str!("../src/causal.rs");
    for forbidden in ["Caused", "Causes", "CAUSED_BY", "root_cause", "RootCause"] {
        assert!(
            !source.contains(forbidden),
            "`{forbidden}` appears in src/causal.rs; §40.1 leaves no room for it"
        );
    }
}

#[test]
fn should_report_the_strongest_available_claim_and_no_more() {
    // A `why` answer with four findings still tops out where the evidence does. The plausible
    // mistake is to let a pile of weak evidence add up to a strong conclusion.
    let pod = object(POD);
    let (change, failure) = policy_change_and_failure();
    let mut why = Why::about(
        pod.identity(),
        Coverage::complete(Scope::in_namespace("shop")),
    );

    why.add(Finding::proximity(
        pod.identity(),
        &change,
        &failure,
        5 * 60 * 1_000,
    ));
    why.add(Finding::precedence(pod.identity(), &change, &failure));
    why.add(Finding::dependency_path(
        pod.identity(),
        Graph::edges_of(&pod),
    ));

    assert_eq!(why.strongest_claim(), Claim::DependencyPathExists);
    assert!(!why.is_insufficient());

    let controller = Graph::edges_of(&pod)
        .into_iter()
        .find(|edge| edge.relation() == Relation::ControlledBy)
        .expect("the fixture Pod names a controller");
    why.add(Finding::asserted(pod.identity(), &controller));
    assert_eq!(why.strongest_claim(), Claim::AssertedByKubernetes);
    assert!(
        why.describe().contains("ASSERTED_BY_KUBERNETES"),
        "the answer names its own ceiling: {}",
        why.describe()
    );
}

#[test]
fn should_conclude_insufficient_evidence_rather_than_invent_an_explanation() {
    // §40.5 states this as a requirement, and calls the alternative — a plausible invented
    // explanation — worse. An empty `why` must therefore be answerable, not empty-looking.
    let pod = object(POD);
    let mut coverage = Coverage::complete(Scope::in_namespace("shop"));
    coverage.record(Gap::new(Scope::in_namespace("shop"), Outcome::ListDenied));
    let why = Why::about(pod.identity(), coverage);

    assert!(why.is_insufficient());
    assert_eq!(why.strongest_claim(), Claim::CausalityNotProven);
    assert!(why.describe().contains("insufficient evidence"));
    assert!(
        why.describe().contains("list denied"),
        "why the evidence is thin is part of the answer: {}",
        why.describe()
    );
}

#[test]
fn should_keep_findings_that_prove_nothing_rather_than_dropping_them() {
    // A refusal is evidence about the search. Dropping the findings that came back empty would
    // leave an answer that looks like nobody looked (§4 invariant 13, §21.4).
    let pod = object(POD);
    let mut why = Why::about(
        pod.identity(),
        Coverage::complete(Scope::in_namespace("shop")),
    );
    why.add(Finding::dependency_path(pod.identity(), Vec::new()));

    assert_eq!(why.findings().len(), 1);
    assert!(why.is_insufficient());
    assert_eq!(why.findings()[0].claim(), Claim::CausalityNotProven);
}

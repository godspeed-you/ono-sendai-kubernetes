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

use std::convert::Infallible;

use ono_provider_kubernetes::causal::{
    Claim, Expansion, Finding, Support, Unproven, Walk, WalkBounds, WalkError, Why,
};
use ono_provider_kubernetes::condition::{condition, conditions};
use ono_provider_kubernetes::coverage::{Coverage, Gap, Outcome, Scope};
use ono_provider_kubernetes::events::Event;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::relationship::{Edge, Graph, Relation, Target};
use ono_provider_kubernetes::temporal::{ClockSource, Observation, Stamp};
use ono_provider_kubernetes::transport::ObservedAt;
use ono_provider_kubernetes::workload::Workload;

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

// --- the walk: bounded, deterministic, and never round in circles ------------------------------------------

/// The ReplicaSet the fixture Pod names as its controller, which in turn names a Deployment —
/// and which, read from its own end, owns the Pod the walk started from.
const REPLICASET: &str = r#"{
  "apiVersion":"apps/v1","kind":"ReplicaSet",
  "metadata":{
    "name":"checkout-7f9d","namespace":"shop","uid":"rs-1",
    "ownerReferences":[
      {"apiVersion":"apps/v1","kind":"Deployment","name":"checkout","uid":"dep-1",
       "controller":true}
    ]
  },
  "spec":{"selector":{"matchLabels":{"app":"checkout"}}}
}"#;

/// The subject's own edges: two the API server asserts (its controller, its Node) and one this
/// provider derived (the Service whose selector it satisfies).
fn subject_edges() -> Vec<Edge> {
    let pod = object(POD);
    let mut edges = Graph::edges_of(&pod);
    edges.extend(Graph::selected_by(&pod, &[object(SERVICE)]));
    edges
}

/// What the graph beyond the Pod looks like: the ReplicaSet names its Deployment and owns the
/// Pod back; the Deployment and the Node have nothing further to say.
fn beyond(target: &Target) -> Result<Expansion, Infallible> {
    Ok(match target.kind() {
        "ReplicaSet" => {
            let replicaset = object(REPLICASET);
            let mut edges = Graph::edges_of(&replicaset);
            edges.extend(Workload::owns(&replicaset, &[object(POD)]));
            Expansion::Edges {
                edges,
                gaps: Vec::new(),
                unevaluated: Vec::new(),
            }
        }
        _ => Expansion::Edges {
            edges: Vec::new(),
            gaps: Vec::new(),
            unevaluated: Vec::new(),
        },
    })
}

fn walk(hops: usize, expand: impl FnMut(&Target) -> Result<Expansion, Infallible>) -> Walk {
    let bounds = WalkBounds::new(hops).expect("within the bound");
    match Walk::explore(&object(POD).identity(), bounds, subject_edges(), expand) {
        Ok(walk) => walk,
    }
}

/// The path findings of a walk, as the sentence each one prints.
fn paths(walk: &Walk) -> Vec<String> {
    walk.findings()
        .iter()
        .filter(|finding| finding.claim() == Claim::DependencyPathExists)
        .map(|finding| finding.support().describe())
        .collect()
}

#[test]
fn should_report_a_derived_edge_as_a_path_and_an_asserted_one_as_the_assertion() {
    // The first hop, on the rung each edge earned. An owner reference is something the API
    // server states, so it is reported as `ASSERTED_BY_KUBERNETES` and *not* also as a weaker
    // path beside it — one fact, one finding. A selector this provider evaluated is not an
    // assertion however confident the match (§23.3), and a path is exactly what it is.
    let walk = walk(1, beyond);
    let asserted: Vec<String> = walk
        .findings()
        .iter()
        .filter(|finding| finding.claim() == Claim::AssertedByKubernetes)
        .map(|finding| finding.support().describe())
        .collect();
    assert_eq!(
        asserted.len(),
        3,
        "controlled-by, owned-by, scheduled-on: {asserted:?}"
    );
    assert_eq!(
        paths(&walk),
        vec!["selected-by Service/checkout [selector]".to_owned()],
        "the one derived edge is the one path, and it names the class it rests on"
    );
    assert!(
        walk.findings()
            .iter()
            .all(|finding| finding.claim() != Claim::CausalityNotProven),
        "nothing here established nothing"
    );
    assert_eq!(walk.reads(), 0, "one hop reads no far end");
}

#[test]
fn should_stop_at_the_hop_bound_and_reach_further_when_asked() {
    // One hop is the subject's own edges; two hops reads the far ends and reports what lies
    // beyond them as paths that go through them. The Deployment is two owner references away.
    let one = walk(1, beyond);
    assert!(
        !paths(&one).iter().any(|path| path.contains("Deployment")),
        "one hop does not reach the Deployment: {:?}",
        paths(&one)
    );
    assert!(
        one.unexpanded() > 0,
        "the far ends were reached and not asked"
    );

    let two = walk(2, beyond);
    assert!(
        paths(&two).contains(
            &"controlled-by ReplicaSet/checkout-7f9d [owner-reference] -> controlled-by \
              Deployment/checkout [owner-reference]"
                .to_owned()
        ),
        "two hops reach the Deployment through the ReplicaSet, hop by hop: {:?}",
        paths(&two)
    );
    assert_eq!(
        two.reads(),
        3,
        "the ReplicaSet, the Node and the Service were each read once"
    );
}

#[test]
fn should_not_walk_a_cycle_and_should_report_each_object_once() {
    // The ReplicaSet owns the Pod the walk started from, so the graph has a cycle. The edge back
    // is seen and not followed, nothing is asked about the subject, and the walk ends. And the
    // Deployment is reachable along two owner references — `owned-by` and `controlled-by` — and
    // is reported along the first path found rather than once per route.
    let mut asked: Vec<String> = Vec::new();
    let three = walk(3, |target| {
        asked.push(format!("{}/{}", target.kind(), target.name()));
        beyond(target)
    });
    assert!(
        !asked.contains(&"Pod/checkout-7f9d".to_owned()),
        "the subject is never read as a far end: {asked:?}"
    );
    assert_eq!(
        asked
            .iter()
            .filter(|name| name.as_str() == "ReplicaSet/checkout-7f9d")
            .count(),
        1,
        "an object is read once however many edges reach it: {asked:?}"
    );
    assert!(
        !paths(&three)
            .iter()
            .any(|path| path.contains("Pod/checkout-7f9d")),
        "a path never leads back to where it started: {:?}",
        paths(&three)
    );
    assert_eq!(
        paths(&three)
            .iter()
            .filter(|path| path.ends_with("Deployment/checkout [owner-reference]"))
            .count(),
        1,
        "one object, one path: {:?}",
        paths(&three)
    );
}

#[test]
fn should_stop_at_the_read_bound_and_say_so_as_a_gap() {
    // §49.1 and §18.3: the walk may read this many far ends and no more, and a walk stopped by
    // that bound comes back with a gap rather than with a shorter answer that looks complete.
    // The first hop is never cut — it cost nothing to derive — and the far ends past the bound
    // are recorded as not queried, in their own scopes.
    let bounds = WalkBounds::new(2).expect("within the bound").with_reads(1);
    let Ok(walk) = Walk::explore(&object(POD).identity(), bounds, subject_edges(), beyond);
    assert_eq!(walk.reads(), 1);
    assert!(walk.was_cut_short());
    let first_hop = walk
        .findings()
        .iter()
        .filter(|finding| match finding.support() {
            Support::Path(edges) => edges.len() == 1,
            Support::Assertion { .. } => true,
            Support::Sequence { .. } | Support::Nothing(_) => false,
        })
        .count();
    assert_eq!(
        first_hop,
        4,
        "the first hop is whole whatever the read bound: {:?}",
        walk.findings()
    );
    assert!(
        walk.gaps()
            .iter()
            .any(|gap| gap.outcome() == Outcome::NotQueried),
        "what was not read is a gap, never an absence: {:?}",
        walk.gaps()
    );
    let unbounded = WalkBounds::new(2).expect("within the bound");
    let Ok(whole) = Walk::explore(&object(POD).identity(), unbounded, subject_edges(), beyond);
    assert!(!whole.was_cut_short());
    assert!(whole.gaps().is_empty());
}

#[test]
fn should_keep_the_evidence_of_every_hop_on_a_path() {
    // Gate D for a path: the edges travel whole, so a reader can check each hop against the
    // cluster, and the class of every hop is in the sentence because a path is as strong as its
    // weakest hop.
    let two = walk(2, beyond);
    let through = two
        .findings()
        .iter()
        .find(|finding| finding.support().describe().contains("Deployment/checkout"))
        .expect("the Deployment is reached");
    let Support::Path(edges) = through.support() else {
        panic!("a path finding carries its edges");
    };
    assert_eq!(edges.len(), 2);
    assert_eq!(edges[0].target().kind(), "ReplicaSet");
    assert_eq!(edges[0].evidence().class(), "owner-reference");
    assert_eq!(edges[1].target().kind(), "Deployment");
    assert_eq!(edges[1].target().uid(), Some("dep-1"));
    assert_eq!(through.claim(), Claim::DependencyPathExists);
}

#[test]
fn should_answer_the_same_paths_in_the_same_order_whatever_order_the_edges_arrived_in() {
    // §35.5's determinism, for a walk: a listing's order is the API server's business, and an
    // answer that depended on it would be a different answer twice.
    let bounds = WalkBounds::new(2).expect("within the bound");
    let forwards = subject_edges();
    let mut backwards = subject_edges();
    backwards.reverse();
    let Ok(one) = Walk::explore(&object(POD).identity(), bounds, forwards, beyond);
    let Ok(other) = Walk::explore(&object(POD).identity(), bounds, backwards, |target| {
        beyond(target).map(|expansion| match expansion {
            Expansion::Edges {
                mut edges,
                gaps,
                unevaluated,
            } => {
                edges.reverse();
                Expansion::Edges {
                    edges,
                    gaps,
                    unevaluated,
                }
            }
            other => other,
        })
    });
    let sentences =
        |walk: &Walk| -> Vec<String> { walk.findings().iter().map(Finding::describe).collect() };
    assert_eq!(sentences(&one), sentences(&other));
}

#[test]
fn should_keep_the_edge_to_an_unreadable_far_end_and_record_why_it_stopped_there() {
    // §21.4 at a far end: the edge to the ReplicaSet is a fact the Pod states, so it stands
    // whatever happened when the ReplicaSet itself was asked for. A denial is a gap on the
    // answer; an absence is an answer and no gap at all.
    let bounds = WalkBounds::new(2).expect("within the bound");
    let Ok(denied) = Walk::explore(&object(POD).identity(), bounds, subject_edges(), |target| {
        Ok::<_, Infallible>(match target.kind() {
            "ReplicaSet" => {
                Expansion::Unread(Gap::new(Scope::in_namespace("shop"), Outcome::ReadDenied))
            }
            _ => Expansion::Absent,
        })
    });
    assert!(
        denied.findings().iter().any(|finding| finding
            .support()
            .describe()
            .contains("ReplicaSet/checkout-7f9d")),
        "the edge the Pod states survives the far end being unreadable"
    );
    assert_eq!(denied.gaps().len(), 1);
    assert_eq!(denied.gaps()[0].outcome(), Outcome::ReadDenied);
    assert!(
        !paths(&denied)
            .iter()
            .any(|path| path.contains("Deployment")),
        "nothing beyond the denial is claimed"
    );
}

#[test]
fn should_refuse_a_walk_deeper_than_the_bound_rather_than_clamp_it() {
    // A question answered for a shallower depth than it asked is a wrong answer that looks right.
    assert_eq!(
        WalkBounds::new(WalkBounds::MAX_HOPS + 1),
        Err(WalkError::TooDeep {
            asked: WalkBounds::MAX_HOPS + 1,
            allowed: WalkBounds::MAX_HOPS,
        })
    );
    assert!(WalkBounds::new(WalkBounds::MAX_HOPS).is_ok());
    assert_eq!(WalkBounds::default().hops(), WalkBounds::DEFAULT_HOPS);
}

#[test]
fn should_carry_an_unevaluated_selector_as_a_refusal_of_its_own() {
    // ADR-0007 at a far end: a selector this provider does not evaluate leaves part of the
    // neighbourhood undetermined, and the walk says so rather than reporting the paths it could
    // find as if they were all of them.
    let bounds = WalkBounds::new(2).expect("within the bound");
    let Ok(walk) = Walk::explore(&object(POD).identity(), bounds, subject_edges(), |_| {
        Ok::<_, Infallible>(Expansion::Edges {
            edges: Vec::new(),
            gaps: Vec::new(),
            unevaluated: vec!["spec.podSelector.matchExpressions".to_owned()],
        })
    });
    assert!(!walk.unevaluated().is_empty());
    let refusal = Finding::nothing(object(POD).identity(), Unproven::NotEvaluated);
    assert!(
        refusal.describe().contains("does not evaluate"),
        "{}",
        refusal.describe()
    );
}

#[test]
fn should_not_make_the_same_finding_twice() {
    // A finding's identity is the object, the claim and what the claim rests on. Two conditions
    // that each carry no `observedGeneration` produce the same refusal, and it is one fact about
    // the object — an answer that listed it twice would be counting, which is the summation the
    // ladder refuses.
    let pod = object(POD);
    let mut why = Why::about(
        pod.identity(),
        Coverage::complete(Scope::in_namespace("shop")),
    );
    why.add(Finding::nothing(pod.identity(), Unproven::NotAsserted));
    why.add(Finding::nothing(pod.identity(), Unproven::NotAsserted));
    why.add(Finding::nothing(pod.identity(), Unproven::NoEvidence));
    assert_eq!(
        why.findings().len(),
        2,
        "two distinct refusals, and the repeated one once: {:?}",
        why.findings()
    );
}

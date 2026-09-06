//! What a result did and did not observe.
//!
//! Specification §18 (pagination), §21 (authorization and RBAC truth) and §4 invariant 13.
//! Gate E: a denied namespace or list scope must not render as empty or complete.
//!
//! This is the module the project's truth-first claim rests on. Eight different situations end
//! with "no objects came back", and collapsing them into an empty collection is how a permission
//! boundary gets read as "there is nothing there" — an answer that is wrong in the direction that
//! costs an operator the most, because it looks like information.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::coverage::{Coverage, Gap, Outcome, Scope};

#[test]
fn should_distinguish_the_eight_ways_a_query_can_come_back_without_objects() {
    // §21.4 lists them, and each calls for a different next step from the operator: ask someone
    // for access, install a CRD, check the name, retry, widen the scope.
    let named: Vec<&str> = vec![
        Outcome::Absent,
        Outcome::TypeNotServed,
        Outcome::NamespaceAbsent,
        Outcome::ReadDenied,
        Outcome::ListDenied,
        Outcome::Disconnected,
        Outcome::RequestFailed,
        Outcome::NotQueried,
    ]
    .into_iter()
    .map(Outcome::as_str)
    .collect();

    let mut unique = named.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        8,
        "each situation needs its own word, got {named:?}"
    );
}

#[test]
fn should_report_a_complete_query_as_complete() {
    let coverage = Coverage::complete(Scope::in_namespace("shop"));
    assert!(coverage.is_complete());
    assert!(coverage.gaps().is_empty());
    assert!(!coverage.is_empty_but_incomplete(0));
}

#[test]
fn should_not_let_a_denied_namespace_look_like_an_empty_one() {
    // Gate E. Zero objects and a denial is not zero objects.
    let mut coverage = Coverage::complete(Scope::all_namespaces());
    coverage.record(Gap::new(
        Scope::in_namespace("secret-ns"),
        Outcome::ListDenied,
    ));

    assert!(!coverage.is_complete());
    assert!(
        coverage.is_empty_but_incomplete(0),
        "no objects and a denied scope must be answerable as such"
    );
    let gap = &coverage.gaps()[0];
    assert_eq!(gap.outcome(), Outcome::ListDenied);
    assert_eq!(gap.scope().namespace(), Some("secret-ns"));
}

#[test]
fn should_keep_the_namespaces_it_did_see_when_one_is_denied() {
    // §21.5: partial visibility is partial, not total failure. The objects that arrived are real
    // and usable; what must not happen is presenting them as the whole picture.
    let mut coverage = Coverage::complete(Scope::all_namespaces());
    coverage.observed(Scope::in_namespace("shop"));
    coverage.observed(Scope::in_namespace("web"));
    coverage.record(Gap::new(Scope::in_namespace("vault"), Outcome::ListDenied));

    assert_eq!(coverage.observed_scopes().len(), 2);
    assert!(!coverage.is_complete());
    assert!(
        !coverage.is_empty_but_incomplete(12),
        "twelve objects arrived; the result is incomplete, not empty"
    );
    assert!(coverage.describe().contains("vault"));
}

#[test]
fn should_never_infer_that_an_unseen_namespace_is_empty() {
    // §21.5: "The provider MUST NOT infer that unseen namespaces are empty."
    let mut coverage = Coverage::complete(Scope::all_namespaces());
    coverage.record(Gap::new(Scope::in_namespace("unseen"), Outcome::NotQueried));
    assert!(!coverage.is_complete());
    assert_eq!(coverage.gaps()[0].outcome(), Outcome::NotQueried);
}

#[test]
fn should_mark_a_collection_incomplete_when_a_page_fails() {
    // §18.3: pages 1..N succeeded and N+1 failed. The values already received may be kept, and
    // the coverage must say the collection is partial — "a default table MUST NOT look identical
    // to a complete result".
    let mut coverage = Coverage::complete(Scope::in_namespace("shop"));
    coverage.record(Gap::new(
        Scope::in_namespace("shop"),
        Outcome::RequestFailed,
    ));
    assert!(!coverage.is_complete());
    assert!(coverage.describe().contains("failed"));
}

#[test]
fn should_treat_a_user_limit_as_a_choice_rather_than_incompleteness() {
    // §18.4: `... | first 20` stopping consumption is not provider incompleteness. The stream
    // still knows more may exist upstream, which is a different statement from a gap.
    let mut coverage = Coverage::complete(Scope::in_namespace("shop"));
    coverage.more_available();
    assert!(
        coverage.is_complete(),
        "stopping early is the pipeline's decision, not a hole in what was observed"
    );
    assert!(coverage.may_have_more());
}

#[test]
fn should_distinguish_a_type_the_cluster_does_not_serve() {
    // §11.5: an API the cluster never had is not an empty collection of it. This is what makes
    // `get widget` on a cluster without the CRD say something useful.
    let mut coverage = Coverage::complete(Scope::cluster());
    coverage.record(Gap::new(Scope::cluster(), Outcome::TypeNotServed));
    assert_eq!(coverage.gaps()[0].outcome(), Outcome::TypeNotServed);
    assert!(coverage.describe().contains("not served"));
}

#[test]
fn should_let_a_direct_read_succeed_while_the_listing_is_denied() {
    // §60.5, the canonical scenario: `get` on one Pod is allowed while `list` on the namespace is
    // not. Both facts are true at once, and a model that cannot hold both would have to discard
    // the one it can act on.
    let mut coverage = Coverage::complete(Scope::in_namespace("shop"));
    coverage.observed(Scope::in_namespace("shop"));
    coverage.record(Gap::new(Scope::in_namespace("shop"), Outcome::ListDenied));

    assert_eq!(coverage.observed_scopes().len(), 1);
    assert!(!coverage.is_complete());
    assert_eq!(coverage.gaps()[0].outcome(), Outcome::ListDenied);
}

#[test]
fn should_describe_a_gap_in_words_an_operator_can_act_on() {
    // A gap nobody can read is a gap nobody acts on. The description names the scope and what
    // happened, because "incomplete" alone does not say what to do next.
    let gap = Gap::new(Scope::in_namespace("vault"), Outcome::ListDenied);
    let described = gap.describe();
    assert!(described.contains("vault"), "got {described}");
    assert!(described.contains("denied"), "got {described}");
}

#[test]
fn should_carry_a_scope_that_says_what_was_asked() {
    assert_eq!(Scope::in_namespace("shop").to_string(), "namespace/shop");
    assert_eq!(Scope::all_namespaces().to_string(), "all-namespaces");
    assert_eq!(Scope::cluster().to_string(), "cluster");
    assert_eq!(Scope::in_namespace("shop").namespace(), Some("shop"));
    assert_eq!(Scope::cluster().namespace(), None);
}

#[test]
fn should_name_an_unreadable_api_group_apart_from_a_request_that_failed() {
    // §34.2: "Coverage SHOULD report the failed group/version separately." Appendix D.3 spells
    // the row out — `custom.metrics.k8s.io: unavailable`, standing beside the complete ones —
    // and §34.3 forbids attributing the failure generically to "the cluster". A group whose own
    // API server is down is a ninth situation beside §21.4's eight, and folding it into
    // `request failed` would lose the one thing an operator acts on: which group to go and fix.
    let gap = Gap::new(
        Scope::in_group_version("custom.metrics.k8s.io/v1beta1"),
        Outcome::Unavailable,
    );
    assert_eq!(gap.describe(), "custom.metrics.k8s.io/v1beta1: unavailable");
    assert_ne!(
        Outcome::Unavailable.as_str(),
        Outcome::RequestFailed.as_str()
    );
    assert_ne!(
        Outcome::Unavailable.as_str(),
        Outcome::TypeNotServed.as_str()
    );
    assert!(
        !Outcome::Unavailable.is_evidence_of_absence(),
        "a group that did not answer is not a group with nothing in it"
    );
}

#[test]
fn should_keep_a_group_version_scope_apart_from_a_namespace_of_the_same_name() {
    // §9.3: API group/version is a scope dimension of its own. A gap recorded against
    // `metrics.k8s.io/v1beta1` says the *type space* was not fully read, which is a different
    // claim from a namespace nobody could list — and a renderer must not confuse the two.
    let scope = Scope::in_group_version("metrics.k8s.io/v1beta1");
    assert_eq!(scope.to_string(), "metrics.k8s.io/v1beta1");
    assert_eq!(scope.group_version(), Some("metrics.k8s.io/v1beta1"));
    assert_eq!(scope.namespace(), None);
    assert_eq!(Scope::in_namespace("shop").group_version(), None);
    assert_ne!(Scope::in_group_version("shop"), Scope::in_namespace("shop"));
}

#[test]
fn should_not_read_an_unavailable_group_as_a_complete_answer() {
    // §48.6: an all-resource view spanning several GVRs may keep the resources that answered,
    // "with explicit incomplete coverage". Explicit is the operative word — the coverage has to
    // come back incomplete, and it has to name the group-version that did not answer.
    let mut coverage = Coverage::complete(Scope::cluster());
    coverage.observed(Scope::cluster());
    coverage.record(Gap::new(
        Scope::in_group_version("metrics.k8s.io/v1beta1"),
        Outcome::Unavailable,
    ));

    assert!(!coverage.is_complete());
    assert!(coverage.is_empty_but_incomplete(0));
    assert!(
        !coverage.is_empty_but_incomplete(3),
        "three resources answered; the view is partial rather than empty"
    );
    assert!(coverage.describe().contains("metrics.k8s.io/v1beta1"));
}

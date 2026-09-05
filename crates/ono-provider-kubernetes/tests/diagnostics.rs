//! What a provider instance can say about the cluster it is pointed at.
//!
//! Specification §8.5, §8.6, §10, §34.3. Nothing here contacts a cluster (§59.1): every input is
//! a recorded API response or a certificate generated inside the test, and every assertion is
//! about a distinction the provider must not collapse.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::time::Duration;

use ono_provider_kubernetes::coverage::Outcome;
use ono_provider_kubernetes::diagnostics::{
    Alias, ClusterDiagnostic, Fingerprint, Health, Identity, Impersonation, Known, Probe,
    ProbeStatus, ServerVersion, Signal, Subject, TlsPosture, normalised_origin,
    public_key_fingerprint,
};

/// A certificate for `name`, as DER, generated so that nothing here expires on a date nobody
/// chose.
fn certificate(name: &str) -> Vec<u8> {
    let params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

/// A certificate for `name` carrying `key`, so that two certificates can share one public key.
fn certificate_with(name: &str, key: &rcgen::KeyPair) -> Vec<u8> {
    let params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.self_signed(key).unwrap().der().to_vec()
}

// --- the fingerprint -----------------------------------------------------------------------------

#[test]
fn should_compose_a_fingerprint_from_the_signals_it_obtained_and_name_them() {
    // §10.2: no single optional signal may be treated as universally available, so a fingerprint
    // is a set of named signals rather than a value that is either there or missing.
    let full = Fingerprint::unknown()
        .with_origin(Known::Obtained("https://api.prod.example".to_owned()))
        .with_server_public_key(Known::Obtained("aa".repeat(32)))
        .with_kube_system_uid(Known::Obtained(
            "11111111-1111-1111-1111-111111111111".to_owned(),
        ));

    assert_eq!(
        full.obtained_signals(),
        vec![
            Signal::Origin,
            Signal::ServerPublicKey,
            Signal::KubeSystemUid
        ],
        "a fingerprint says which parts it has"
    );
    assert!(full.digest().is_some(), "and composes them into one token");
}

#[test]
fn should_still_have_a_fingerprint_when_only_one_signal_was_obtainable() {
    let partial = Fingerprint::unknown()
        .with_origin(Known::Obtained("https://api.prod.example".to_owned()))
        .with_server_public_key(Known::Unavailable(Outcome::NotQueried))
        .with_kube_system_uid(Known::Unavailable(Outcome::ReadDenied));

    assert_eq!(partial.obtained_signals(), vec![Signal::Origin]);
    assert!(
        partial.digest().is_some(),
        "one signal is a weaker fingerprint, not the absence of one"
    );
    assert_eq!(
        partial.signal(Signal::KubeSystemUid).outcome(),
        Some(Outcome::ReadDenied),
        "and a refused signal says it was refused, not that it does not exist"
    );
    assert_eq!(
        partial.signal(Signal::ServerPublicKey).outcome(),
        Some(Outcome::NotQueried),
        "a signal nobody asked for is distinct from one the cluster refused (§21.4)"
    );
}

#[test]
fn should_have_no_digest_at_all_when_nothing_was_obtained() {
    // A hash of nothing is a perfectly stable value that every unidentifiable cluster would
    // share, and two clusters that agree only in having said nothing are not an observed alias.
    assert!(Fingerprint::unknown().digest().is_none());
    assert!(Fingerprint::unknown().is_empty());
}

#[test]
fn should_give_two_different_clusters_different_fingerprints() {
    let production = Fingerprint::unknown()
        .with_origin(Known::Obtained("https://api.prod.example".to_owned()))
        .with_kube_system_uid(Known::Obtained(
            "11111111-1111-1111-1111-111111111111".to_owned(),
        ));
    let staging = Fingerprint::unknown()
        .with_origin(Known::Obtained("https://api.staging.example".to_owned()))
        .with_kube_system_uid(Known::Obtained(
            "22222222-2222-2222-2222-222222222222".to_owned(),
        ));

    assert_ne!(production.digest(), staging.digest());
    let verdict = production.compare(&staging);
    assert_eq!(verdict.verdict(), Alias::Distinct);
    assert_eq!(
        verdict.disagreed(),
        [Signal::Origin, Signal::KubeSystemUid],
        "the verdict names the evidence it rests on"
    );
}

#[test]
fn should_report_two_contexts_on_one_cluster_as_a_possible_alias_without_merging_them() {
    // §10.3: an alias may be *reported*; the two instances MUST NOT be merged, because their
    // credentials and effective permissions differ. Nothing on `Fingerprint` merges anything —
    // the strongest form that guarantee can take is that no such operation exists.
    let uid = "11111111-1111-1111-1111-111111111111".to_owned();
    let through_admin = Fingerprint::unknown()
        .with_origin(Known::Obtained("https://api.prod.example".to_owned()))
        .with_kube_system_uid(Known::Obtained(uid.clone()));
    let through_readonly = Fingerprint::unknown()
        .with_origin(Known::Obtained("https://api.prod.example".to_owned()))
        .with_kube_system_uid(Known::Obtained(uid));

    let verdict = through_admin.compare(&through_readonly);
    assert_eq!(verdict.verdict(), Alias::Possible);
    assert_eq!(
        verdict.agreed(),
        [Signal::Origin, Signal::KubeSystemUid],
        "and it says on what"
    );
    assert!(verdict.describe().contains("possible alias"));

    // Two instances, two identities, and the diagnostic keeps them apart even though the cluster
    // is one.
    let admin = ClusterDiagnostic::for_instance("kubernetes:prod-admin", TlsPosture::Verified)
        .with_fingerprint(through_admin);
    let readonly =
        ClusterDiagnostic::for_instance("kubernetes:prod-readonly", TlsPosture::Verified)
            .with_fingerprint(through_readonly);
    assert_ne!(
        admin.instance(),
        readonly.instance(),
        "the provider instance is what distinguishes them (§10.1), and it is not the cluster"
    );
    assert_eq!(
        admin.fingerprint().digest(),
        readonly.fingerprint().digest(),
        "while the cluster they point at is the same one"
    );
}

#[test]
fn should_not_conclude_different_clusters_merely_because_the_addresses_differ() {
    // One cluster reached through an internal address and an external one. A bastion, a load
    // balancer or a `port-forward` changes the origin without changing the cluster, so an origin
    // that disagrees is not evidence — while the `kube-system` UID that agrees is.
    let uid = "11111111-1111-1111-1111-111111111111".to_owned();
    let inside = Fingerprint::unknown()
        .with_origin(Known::Obtained("https://api.internal:6443".to_owned()))
        .with_kube_system_uid(Known::Obtained(uid.clone()));
    let outside = Fingerprint::unknown()
        .with_origin(Known::Obtained("https://api.example.com".to_owned()))
        .with_kube_system_uid(Known::Obtained(uid));

    let verdict = inside.compare(&outside);
    assert_eq!(verdict.verdict(), Alias::Possible);
    assert_eq!(verdict.agreed(), [Signal::KubeSystemUid]);
    assert_eq!(verdict.disagreed(), [Signal::Origin]);
}

#[test]
fn should_say_nothing_when_two_instances_share_no_signal() {
    let known = Fingerprint::unknown().with_kube_system_uid(Known::Obtained("11111111".to_owned()));
    let unknown =
        Fingerprint::unknown().with_origin(Known::Obtained("https://api.example.com".to_owned()));

    let verdict = known.compare(&unknown);
    assert_eq!(
        verdict.verdict(),
        Alias::Undetermined,
        "no shared evidence is not evidence of difference"
    );
    assert!(verdict.agreed().is_empty());
    assert!(verdict.disagreed().is_empty());
}

#[test]
fn should_normalise_an_origin_so_that_two_spellings_of_one_address_compare_equal() {
    assert_eq!(
        normalised_origin("HTTPS", "API.Example.COM.", 443),
        "https://api.example.com"
    );
    assert_eq!(
        normalised_origin("https", "api.example.com", 6443),
        "https://api.example.com:6443",
        "a port that is not the scheme's own stays"
    );
    assert_eq!(
        normalised_origin("http", "localhost", 80),
        "http://localhost"
    );
}

// --- the server certificate's public key ---------------------------------------------------------

#[test]
fn should_fingerprint_the_public_key_rather_than_the_certificate() {
    // §10.4: strong fingerprint evidence that changes means the cluster was replaced. An
    // ordinary certificate renewal is not a replacement, and fingerprinting the certificate
    // would report it as one.
    let key = rcgen::KeyPair::generate().unwrap();
    let first = certificate_with("api.example.com", &key);
    let renewed = certificate_with("api.example.com", &key);
    assert_ne!(first, renewed, "two certificates, not one");
    assert!(
        public_key_fingerprint(&first).is_some(),
        "a real certificate yields a fingerprint, so the equality below is not two `None`s"
    );
    assert_eq!(
        public_key_fingerprint(&first),
        public_key_fingerprint(&renewed),
        "the same key is the same cluster"
    );

    let elsewhere = certificate("api.other.example");
    assert_ne!(
        public_key_fingerprint(&first),
        public_key_fingerprint(&elsewhere),
        "and a different key is a different one"
    );
}

#[test]
fn should_report_no_fingerprint_for_bytes_that_are_not_a_certificate() {
    // A fingerprint that cannot be computed is a signal that was not obtained, never a failure
    // that stops a read (§8.6's rule, applied to every optional signal).
    assert!(public_key_fingerprint(b"").is_none());
    assert!(public_key_fingerprint(b"-----BEGIN CERTIFICATE-----").is_none());
    let truncated = certificate("api.example.com");
    assert!(public_key_fingerprint(&truncated[..truncated.len() / 2]).is_none());
}

// --- effective identity ---------------------------------------------------------------------------

#[test]
fn should_read_the_effective_identity_a_self_subject_review_reports() {
    let review = br#"{
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "SelfSubjectReview",
        "status": {"userInfo": {
            "username": "system:serviceaccount:demo:debugger",
            "uid": "9d7c",
            "groups": ["system:serviceaccounts", "system:authenticated"]
        }}
    }"#;
    let subject = Subject::from_self_subject_review(review).expect("a review reads");
    assert_eq!(subject.username(), "system:serviceaccount:demo:debugger");
    assert_eq!(subject.uid(), Some("9d7c"));
    assert_eq!(
        subject.groups(),
        ["system:serviceaccounts", "system:authenticated"]
    );
}

#[test]
fn should_read_no_identity_from_a_status_the_api_server_refused_with() {
    // The body of a refusal is a `Status`, and reading an identity out of one would invent a user
    // the API server never named. The status code says which of §21.4's states it was.
    let refusal = br#"{"kind": "Status", "status": "Failure", "code": 403,
                       "message": "selfsubjectreviews.authentication.k8s.io is forbidden"}"#;
    assert!(Subject::from_self_subject_review(refusal).is_none());
}

#[test]
fn should_keep_the_credential_identity_and_the_effective_identity_in_separate_fields() {
    // §8.5: the two MUST be impossible to confuse. Nothing sets impersonation yet, and the shape
    // is two fields all the same — the day it is set, every reader keeps meaning what it meant.
    let alice = Subject::new("alice@example.com", None, Vec::new());
    let debugger = Subject::new("system:serviceaccount:demo:debugger", None, Vec::new());
    let identity = Identity::unknown()
        .with_credential(Known::Obtained(alice.clone()))
        .with_effective(Known::Obtained(debugger.clone()))
        .with_impersonation(Impersonation::Active {
            user: debugger.username().to_owned(),
            groups: Vec::new(),
        });

    assert_eq!(identity.credential().obtained(), Some(&alice));
    assert_eq!(identity.effective().obtained(), Some(&debugger));
    assert!(identity.impersonation().is_active());
    assert_eq!(
        identity.impersonation().user(),
        Some("system:serviceaccount:demo:debugger")
    );
}

#[test]
fn should_carry_the_same_subject_in_both_fields_when_nothing_is_impersonated() {
    let alice = Subject::new("alice@example.com", None, Vec::new());
    let identity = Identity::unknown()
        .with_credential(Known::Obtained(alice.clone()))
        .with_effective(Known::Obtained(alice));
    assert!(!identity.impersonation().is_active());
    assert_eq!(identity.credential(), identity.effective());
}

// --- health ----------------------------------------------------------------------------------------

#[test]
fn should_keep_the_version_string_the_server_wrote() {
    // §5.3: an unfamiliar `gitVersion` never rejects a cluster, and the reliable way not to
    // reject one is not to interpret the string at all.
    let body = br#"{"major": "1", "minor": "34+", "gitVersion": "v1.34.2+k0s",
                    "platform": "linux/amd64"}"#;
    let version = ServerVersion::parse(body).expect("a version document reads");
    assert_eq!(version.git_version(), "v1.34.2+k0s");
    assert_eq!(version.minor(), Some("34+"), "`34+` is not a number");
    assert_eq!(version.platform(), Some("linux/amd64"));
    assert!(ServerVersion::parse(b"{}").is_none());
}

#[test]
fn should_call_a_cluster_reachable_only_when_something_answered() {
    let mut silent = Health::unknown();
    silent.record(Probe::new(
        "GET /version",
        ProbeStatus::DidNotAnswer(Outcome::Disconnected),
        None,
    ));
    assert!(!silent.is_reachable());

    let mut refusing = Health::unknown();
    refusing.record(Probe::new(
        "GET /version",
        ProbeStatus::Answered(403),
        Some(Duration::from_millis(4)),
    ));
    assert!(
        refusing.is_reachable(),
        "a server that refuses is a server that is there, and the two have different fixes"
    );
}

#[test]
fn should_name_the_source_and_the_latency_of_every_request_it_made() {
    // §34.3: per-request source and latency, rather than attributing every failure generically
    // to "the cluster".
    let mut health = Health::unknown();
    health.record(Probe::new(
        "GET /apis/metrics.k8s.io/v1beta1",
        ProbeStatus::DidNotAnswer(Outcome::RequestFailed),
        Some(Duration::from_millis(30)),
    ));
    let probe = &health.probes()[0];
    assert_eq!(probe.source(), "GET /apis/metrics.k8s.io/v1beta1");
    assert_eq!(probe.latency(), Some(Duration::from_millis(30)));
    assert!(probe.describe().contains("request failed"));
    assert!(probe.describe().contains("30 ms"));
}

// --- the whole answer ------------------------------------------------------------------------------

#[test]
fn should_list_everything_it_could_not_determine_with_the_reason_for_each() {
    let mut health = Health::unknown();
    health.record(Probe::new(
        "GET /version",
        ProbeStatus::Answered(200),
        Some(Duration::from_millis(2)),
    ));
    health.record(Probe::new(
        "GET /apis/authentication.k8s.io/v1",
        ProbeStatus::DidNotAnswer(Outcome::TypeNotServed),
        None,
    ));
    let diagnostic = ClusterDiagnostic::for_instance("kubernetes:prod", TlsPosture::Verified)
        .with_fingerprint(
            Fingerprint::unknown()
                .with_origin(Known::Obtained("https://api.prod.example".to_owned()))
                .with_kube_system_uid(Known::Unavailable(Outcome::ReadDenied)),
        )
        .with_identity(
            Identity::unknown()
                .with_effective(Known::Unavailable(Outcome::TypeNotServed))
                .with_credential(Known::Unavailable(Outcome::TypeNotServed)),
        )
        .with_health(health.with_version(Known::Obtained(
            ServerVersion::parse(br#"{"gitVersion": "v1.34.2"}"#).unwrap(),
        )));

    let unknowns: Vec<String> = diagnostic
        .unknowns()
        .iter()
        .map(|unknown| unknown.describe())
        .collect();
    assert!(
        unknowns.contains(&"cluster fingerprint: kube-system-uid: read denied".to_owned()),
        "a refused signal is named with the refusal: {unknowns:?}"
    );
    assert!(
        unknowns.contains(&"cluster fingerprint: server-public-key: not queried".to_owned()),
        "and one nobody asked for with that: {unknowns:?}"
    );
    assert!(
        unknowns.contains(&"effective identity: not served".to_owned()),
        "§8.6's absence is a stated unknown: {unknowns:?}"
    );
    assert!(
        !unknowns.iter().any(|unknown| unknown.contains("origin")),
        "and a signal that was obtained is not in the list: {unknowns:?}"
    );
    assert!(
        !unknowns
            .iter()
            .any(|unknown| unknown.contains("server version")),
        "nor a version that was read: {unknowns:?}"
    );
}

#[test]
fn should_state_an_insecure_session_rather_than_leaving_it_to_be_inferred() {
    // §8.4: the active insecure state MUST be visible in provider diagnostics.
    let insecure =
        ClusterDiagnostic::for_instance("kubernetes:lab", TlsPosture::InsecureSkipVerify);
    assert!(!insecure.tls().is_verified());
    assert_eq!(
        insecure.tls().as_str(),
        "insecure: certificate verification disabled"
    );
    assert_eq!(
        ClusterDiagnostic::for_instance("kubernetes:proxy", TlsPosture::None)
            .tls()
            .as_str(),
        "none: plain HTTP/1.1",
        "no TLS at all is a third state, not a kind of verified"
    );
}

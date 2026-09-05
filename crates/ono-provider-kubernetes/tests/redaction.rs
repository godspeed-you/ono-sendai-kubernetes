//! Secret payload stays unreadable, and everything else about a Secret stays useful.
//!
//! Specification §22, §29.2, §4 invariant 21 and §3.7. Gate I: the default list, detail and
//! navigation paths cannot reveal Secret payload values.
//!
//! The mistake these tests exist to prevent is the one that looks like diligence — a `redact()`
//! helper that a rendering path is supposed to remember to call. Redaction that depends on being
//! remembered fails on the first path nobody thought about, and `Object::field` plus
//! `Object::native` reach every byte the API server sent. So the tests below go at the payload
//! through the ordinary accessors, not through a rendering function, and expect to come back
//! empty-handed.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::redaction::{Guarded, RedactionError, RevealPolicy, RevealRefusal};

/// The base64 the API server sends for `password`.
const CIPHERTEXT: &str = "c3VwZXItc2VjcmV0";
/// What that base64 decodes to. Neither form may appear in anything the provider hands out.
const PLAINTEXT: &str = "super-secret";

const SECRET: &str = r#"{
  "apiVersion":"v1","kind":"Secret",
  "metadata":{
    "name":"db-credentials","namespace":"shop","uid":"sec-1","resourceVersion":"812",
    "creationTimestamp":"2026-02-11T09:14:03Z",
    "annotations":{
      "kubectl.kubernetes.io/last-applied-configuration":
        "{\"kind\":\"Secret\",\"data\":{\"password\":\"c3VwZXItc2VjcmV0\"}}"
    },
    "ownerReferences":[
      {"apiVersion":"v1","kind":"ServiceAccount","name":"checkout-sa","uid":"sa-1"}
    ]
  },
  "type":"Opaque",
  "data":{"password":"c3VwZXItc2VjcmV0","username":"YWRtaW4="}
}"#;

const SECRET_WITH_STRING_DATA: &str = r#"{
  "apiVersion":"v1","kind":"Secret",
  "metadata":{"name":"tls","namespace":"shop","uid":"sec-2"},
  "type":"kubernetes.io/tls",
  "stringData":{"tls.key":"-----BEGIN PRIVATE KEY-----super-secret"}
}"#;

const CONFIG_MAP: &str = r#"{
  "apiVersion":"v1","kind":"ConfigMap",
  "metadata":{"name":"checkout-config","namespace":"shop","uid":"cm-1"},
  "data":{"LOG_LEVEL":"debug"}
}"#;

const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"checkout-7f9d","namespace":"shop","uid":"pod-1"},
  "spec":{
    "volumes":[{"name":"creds","secret":{"secretName":"db-credentials"}}],
    "containers":[
      {"name":"app","image":"checkout:1",
       "env":[{"name":"PASSWORD","valueFrom":{"secretKeyRef":{"name":"db-credentials","key":"password"}}}]}
    ]
  }
}"#;

const SERVICE_ACCOUNT: &str = r#"{
  "apiVersion":"v1","kind":"ServiceAccount",
  "metadata":{"name":"checkout-sa","namespace":"shop","uid":"sa-1"},
  "secrets":[{"name":"checkout-sa-token"}],
  "imagePullSecrets":[{"name":"registry-pull"}]
}"#;

fn parse(json: &str) -> Object {
    Object::parse("kubernetes:prod-eu", json).expect("the fixture is a Kubernetes object")
}

fn hold(json: &str) -> Guarded {
    Guarded::hold(parse(json)).expect("holding an object never fails for a well-formed fixture")
}

#[test]
fn should_not_carry_secret_payload_in_the_object_it_hands_out() {
    // §22.2 and Gate I. The opposite mistake is the tempting one: keep the object whole and
    // redact when rendering. `Object::native` returns the document the server sent, so a whole
    // object handed to a renderer that forgot the call is a leak with no error to notice.
    let held = hold(SECRET);
    let rendered = held.object().native().to_string();

    assert!(
        !rendered.contains(CIPHERTEXT),
        "the encoded payload survived into the native object: {rendered}"
    );
    assert!(
        !rendered.contains(PLAINTEXT),
        "the decoded payload survived into the native object: {rendered}"
    );
}

#[test]
fn should_not_reveal_payload_through_the_json_pointer_accessor() {
    // §22.2. `Object::field` reaches anything by pointer, so a Secret held as an ordinary object
    // is one `/data/password` away from disclosure. The pointer must still resolve — hiding the
    // path would hide that the key exists — and must resolve to a marker.
    let held = hold(SECRET);
    let value = held
        .object()
        .field("/data/password")
        .and_then(serde_json::Value::as_str)
        .expect("the key is present, so the pointer resolves");

    assert_ne!(value, CIPHERTEXT);
    assert_ne!(value, PLAINTEXT);
    assert_eq!(value, ono_provider_kubernetes::redaction::REDACTED);
}

#[test]
fn should_still_report_which_keys_are_present() {
    // §22.2 lists "keys present" in the safe default view. Redacting the whole `data` map away
    // would be the over-correction: knowing that a Secret has a `password` key is what tells an
    // operator whether the Pod that wants one will start, and it is not knowing the password.
    let held = hold(SECRET);
    let secret = held.secret().expect("a Secret is held as a Secret");

    assert_eq!(secret.keys(), ["password", "username"]);
    assert!(secret.has_key("password"));
    assert!(!secret.has_key("token"));
}

#[test]
fn should_show_the_safe_metadata_a_default_view_needs() {
    // §22.2. A Secret is a normal participant in identity, navigation and ownership (§22.1);
    // protecting the payload must not turn it into an opaque blob with no name and no place.
    let held = hold(SECRET);
    let secret = held.secret().expect("a Secret is held as a Secret");

    assert_eq!(secret.name(), "db-credentials");
    assert_eq!(secret.namespace(), Some("shop"));
    assert_eq!(secret.secret_type(), Some("Opaque"));
    assert_eq!(
        secret.creation_timestamp(),
        Some("2026-02-11T09:14:03Z"),
        "creation time is safe metadata and §22.2 names it"
    );
    assert_eq!(secret.object().owner_references().len(), 1);
    assert_eq!(secret.object().uid(), Some("sec-1"));
    assert!(
        secret.object().identity().is_lifetime_stable(),
        "a redacted Secret is still identifiable across observations (§16.1)"
    );
}

#[test]
fn should_report_keys_declared_only_in_string_data() {
    // §22.2 names `stringData` beside `data`. A provider that redacts only `data` leaks every
    // write-only Secret, which is the form a human most often applies by hand.
    let held = hold(SECRET_WITH_STRING_DATA);
    let secret = held.secret().expect("a Secret is held as a Secret");

    assert_eq!(secret.keys(), ["tls.key"]);
    assert!(
        !held
            .object()
            .native()
            .to_string()
            .contains("BEGIN PRIVATE KEY"),
        "the private key material survived redaction"
    );
}

#[test]
fn should_redact_the_last_applied_configuration_annotation() {
    // §22.2 says "or equivalent secret payload", and this annotation is the equivalent that gets
    // missed: `kubectl apply` writes the whole submitted object, payload included, into
    // metadata. Redacting `data` while printing annotations verbatim leaks the same bytes one
    // field to the left.
    let held = hold(SECRET);
    let annotation = held
        .object()
        .annotation("kubectl.kubernetes.io/last-applied-configuration")
        .expect("the annotation is still visible as a fact about the object");

    assert!(
        !annotation.contains(CIPHERTEXT),
        "the last-applied annotation still carries the payload: {annotation}"
    );
    assert_eq!(annotation, ono_provider_kubernetes::redaction::REDACTED);
}

#[test]
fn should_leave_ordinary_objects_whole() {
    // §22.1 restricts the presentation of Secrets, not of everything that has a `data` map. A
    // ConfigMap whose values vanished would be the mirror-image failure: an operator debugging a
    // wrong log level would be told nothing and given no reason.
    let held = hold(CONFIG_MAP);

    assert!(!held.is_payload_protected());
    assert!(held.secret().is_none());
    assert_eq!(
        held.object()
            .field("/data/LOG_LEVEL")
            .and_then(serde_json::Value::as_str),
        Some("debug")
    );
}

#[test]
fn should_protect_a_custom_kind_named_secret() {
    // §33.1 makes CRDs normal resources, and §3.7 forbids making secret data easier to expose.
    // Recognising only `v1 Secret` by group would hand over the payload of anything a controller
    // author called Secret. Over-redaction costs a reader some detail; under-redaction cannot be
    // taken back.
    let held = hold(
        r#"{"apiVersion":"vault.example.com/v1","kind":"Secret",
            "metadata":{"name":"external","namespace":"shop"},
            "data":{"token":"c3VwZXItc2VjcmV0"}}"#,
    );

    assert!(held.is_payload_protected());
    assert!(!held.object().native().to_string().contains(CIPHERTEXT));
}

#[test]
fn should_hold_every_object_of_a_list_through_the_same_guard() {
    // Gate I names the list path beside detail and navigation. A list that renders raw objects
    // and a detail view that renders redacted ones is the classic split: the safe path gets the
    // review, the loop over a page does not.
    let objects = vec![parse(SECRET), parse(CONFIG_MAP), parse(POD)];
    let held = Guarded::hold_all(objects).expect("well-formed objects can be held");

    assert_eq!(held.len(), 3);
    let protected: Vec<bool> = held.iter().map(Guarded::is_payload_protected).collect();
    assert_eq!(protected, [true, false, false]);
    for item in &held {
        assert!(
            !item.object().native().to_string().contains(CIPHERTEXT),
            "an object on the list path carried the payload"
        );
    }
}

#[test]
fn should_keep_payload_out_of_rendered_and_logged_forms() {
    // §22.3: Secret bytes must not flow into ordinary command history, scrollback or provider
    // logs by default. A `Debug` impl derived over a struct that still owns the payload is
    // exactly how bytes reach a log line nobody meant to write.
    let held = hold(SECRET);
    let secret = held.secret().expect("a Secret is held as a Secret");

    let debug = format!("{held:?}");
    let display = secret.to_string();

    for rendering in [&debug, &display] {
        assert!(!rendering.contains(CIPHERTEXT), "payload in {rendering}");
        assert!(!rendering.contains(PLAINTEXT), "payload in {rendering}");
    }
    assert!(
        display.contains("password"),
        "the summary still names the keys present (§22.2): {display}"
    );
}

#[test]
fn should_refuse_a_reveal_under_the_default_host_policy() {
    // §22.3 and §3.7. Reveal is a capability that exists and is off: modelling it as "off" is
    // what makes the refusal inspectable instead of the feature simply being absent and getting
    // reinvented later without the friction.
    let held = hold(SECRET);
    let secret = held.secret().expect("a Secret is held as a Secret");
    let policy = RevealPolicy::host_default();

    assert!(!policy.permits_reveal());
    assert_eq!(
        secret.request_reveal("password", &policy),
        RevealRefusal::PolicyForbids
    );
}

#[test]
fn should_refuse_a_reveal_even_when_the_host_grants_one() {
    // §22.3. The point of destroying the payload at the boundary rather than filtering it at the
    // edge: a granted policy still cannot produce bytes from a value that never held them. A
    // reveal has to be a fresh, audited read against the API server, so no future policy change
    // can silently turn a held value into a disclosure.
    let held = hold(SECRET);
    let secret = held.secret().expect("a Secret is held as a Secret");
    let policy = RevealPolicy::host_granted("incident-4471");

    assert!(policy.permits_reveal());
    assert_eq!(
        secret.request_reveal("password", &policy),
        RevealRefusal::NoPayloadHeld
    );
}

#[test]
fn should_pin_the_redaction_boundary_at_the_guard() {
    // The boundary has to be somewhere, and stating where is worth more than pretending it is
    // nowhere. `Object::parse` is the wire decoder: it is inside the boundary, and it does hold
    // what the server sent. `Guarded::hold` is the boundary, and every list, detail and
    // navigation path takes its objects from there. This test fails the day someone moves the
    // boundary, which is the day the reasoning above stops being true.
    let raw = parse(SECRET);
    assert!(
        raw.native().to_string().contains(CIPHERTEXT),
        "the wire decoder is inside the boundary; if this changed, the doc comment is stale"
    );

    let held = Guarded::hold(raw).expect("holding never fails for a well-formed object");
    assert!(!held.object().native().to_string().contains(CIPHERTEXT));
}

#[test]
fn should_reject_redacting_something_that_is_not_a_secret() {
    // §22.1. The Secret wrapper makes a claim about what it holds; letting a Pod in would make
    // `keys()` mean nothing and would let a caller believe a redaction happened that did not.
    let error = ono_provider_kubernetes::redaction::Secret::redact(&parse(POD))
        .expect_err("a Pod is not a Secret");

    assert!(matches!(error, RedactionError::NotASecret { .. }));
}

#[test]
fn should_keep_pod_secret_references_useful_without_payload() {
    // §22.4 and §29.2. The relationship is the reason to look at a Secret at all: which workload
    // consumes it. Dropping the edges to protect the payload would protect nothing — the name of
    // a Secret is not its contents — and would cost the answer an operator came for.
    let references = ono_provider_kubernetes::redaction::secret_references(&parse(POD));
    let relations: Vec<&str> = references.iter().map(|item| item.relation()).collect();

    assert_eq!(relations, ["references-secret", "references-secret"]);
    for reference in &references {
        assert_eq!(reference.name(), "db-credentials");
        assert_eq!(reference.namespace(), Some("shop"));
        assert!(
            reference.path().starts_with("/spec/"),
            "the reference cites the field it was read from (§23): {}",
            reference.path()
        );
    }
}

#[test]
fn should_model_the_service_account_image_pull_secret_reference() {
    // §22.4 names this edge explicitly. An image-pull failure looks like a scheduling problem
    // until someone finds the pull secret, so the edge that leads there has to exist — and it is
    // derivable entirely from names, with no reason to read the payload.
    let references = ono_provider_kubernetes::redaction::secret_references(&parse(SERVICE_ACCOUNT));
    let described: Vec<String> = references
        .iter()
        .map(|item| format!("{} {} at {}", item.relation(), item.name(), item.path()))
        .collect();

    assert_eq!(
        described,
        [
            "uses-secret checkout-sa-token at /secrets/0/name",
            "uses-image-pull-secret registry-pull at /imagePullSecrets/0/name",
        ]
    );
}

#[test]
fn should_report_no_keys_for_a_secret_that_has_none() {
    // AGENTS.md: unknown data is null, never fabricated and never zero. An empty key list is a
    // fact about the object; inventing a placeholder key would be a lie in the direction of
    // looking complete.
    let held = hold(
        r#"{"apiVersion":"v1","kind":"Secret",
            "metadata":{"name":"empty","namespace":"shop"}}"#,
    );
    let secret = held.secret().expect("a Secret is held as a Secret");

    assert!(secret.keys().is_empty());
    assert_eq!(secret.secret_type(), None, "no type field means no type");
}

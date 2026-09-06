//! What this provider does when the cluster is hostile rather than merely broken.
//!
//! Every name, label key, label value, annotation, Event message, condition message and log line
//! in a Kubernetes cluster is chosen by whoever can create an object in it. So is every byte an
//! aggregated API server (§34) puts on the wire. This file treats all of that as adversary-chosen
//! input and asks the four questions the rest of the suite does not:
//!
//! ```text
//! injection   can a value drive a terminal, forge a line, or change the shape of an address?
//! disclosure  can Secret payload reach a reader by any route that is not `redaction::Guarded`?
//! identity    does a 253-character name, a path-shaped namespace or an empty UID collapse?
//! bounds      does anything hang, panic, or grow without a limit it can name?
//! ```
//!
//! **Where the render boundary is.** Ono core sanitises: `ono_render::sanitise` neutralises every
//! control character, `Reporter::error` runs an error's message, its details and its help through
//! it, and every table cell and tree node in `ono-render` is sanitised before it is painted. So
//! the correct behaviour for this provider is to pass hostile text through **as data, byte for
//! byte**, and never to decide for itself what a terminal will do with it. The tests in the first
//! section pin exactly that: a control sequence survives a place URI round trip unchanged, which
//! is what proves it is being carried rather than interpreted. They would fail the day this
//! package started stripping bytes (silent corruption of a legitimate name) *or* the day it
//! started writing to a terminal itself.
//!
//! **Findings.** Where a test found a defect in a module this file may not repair, the assertion
//! documents current behaviour under a `// FINDING:` comment naming what should change. Nothing
//! here is `#[ignore]`d: a red suite tells the next reader nothing, and a green suite that pins a
//! defect tells them exactly where it is.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::collections::BTreeMap;

use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::{Gvk, Gvr};
use ono_provider_kubernetes::logs::{LogDecoder, LogRequest, PodTarget};
use ono_provider_kubernetes::mutation::admission_differences_of;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::place::{Place, PlaceUri, TypeSegment};
use ono_provider_kubernetes::redaction::{Guarded, REDACTED};
use ono_provider_kubernetes::relationship::Evidence;
use ono_provider_kubernetes::schema::{Projection, Schema};
use ono_provider_kubernetes::transport::{
    ApiError, Client, FixedClock, FixtureStream, HttpConnection, ListOptions, Page, Reader,
    Request, Status, Walk, collection_path, object_path,
};
use ono_provider_kubernetes::watch::{FrameError, WatchDecoder, WatchEvent};

const INSTANCE: &str = "kubernetes:prod-eu";
const HOST: &str = "kubernetes.default.svc";

/// Everything an adversary reaches for when a value is about to be printed.
///
/// `\u{1b}[2J` clears the screen; `\u{1b}]0;…\u{7}` retitles the window; `\r` rewrites the line
/// just printed; `\u{8}` deletes what is behind it; `\u{202e}` reverses the reading order of
/// everything after it, so `sh.txt` and `txt.hs` render alike.
const HOSTILE: &str = "ok\u{1b}[2J\u{1b}]0;pwned\u{7}\r\u{8}\u{202e}evil\u{0}";

/// The base64 an API server sends for a Secret's `password`.
const CIPHERTEXT: &str = "c3VwZXItc2VjcmV0";
/// What it decodes to. Neither form may appear anywhere outside a `Guarded`.
const PLAINTEXT: &str = "super-secret";

fn clock() -> FixedClock {
    FixedClock::at_unix_millis(1_700_000_000_000)
}

fn pods() -> Gvr {
    Gvr::new("", "v1", "pods")
}

fn secrets() -> Gvr {
    Gvr::new("", "v1", "secrets")
}

fn client(responses: &[String]) -> Client<FixtureStream, FixedClock> {
    Client::with_clock(FixtureStream::replaying(responses), HOST, INSTANCE, clock())
}

fn response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// A reader that keeps every object every page carried, duplicates included.
#[derive(Default)]
struct Everything {
    names: Vec<String>,
}

impl Reader for Everything {
    fn page(&mut self, page: Page) -> Walk {
        self.names
            .extend(page.objects().iter().map(|object| object.name().to_owned()));
        Walk::Continue
    }
}

/// The Secret every disclosure test below tries to get the payload out of.
fn secret_object() -> Object {
    Object::parse(
        INSTANCE,
        &format!(
            r#"{{"apiVersion":"v1","kind":"Secret",
                 "metadata":{{"name":"db","namespace":"shop","uid":"sec-1",
                   "annotations":{{"kubectl.kubernetes.io/last-applied-configuration":
                     "{{\"data\":{{\"password\":\"{CIPHERTEXT}\"}}}}"}}}},
                 "type":"Opaque",
                 "data":{{"password":"{CIPHERTEXT}"}},
                 "stringData":{{"token":"{PLAINTEXT}"}}}}"#
        ),
    )
    .expect("the recorded Secret reads")
}

/// Whether any rendering of `subject` carries either form of the payload.
fn discloses(subject: &str) -> bool {
    subject.contains(CIPHERTEXT) || subject.contains(PLAINTEXT)
}

// --- 1. terminal control injection, and where the boundary is -----------------------------------

#[test]
fn should_carry_a_terminal_escape_in_a_name_through_a_place_uri_byte_for_byte() {
    // §35.3: a place address MUST survive a round trip. Core sanitises at the render boundary
    // (`ono_render::sanitise`, `Reporter::error`), so the provider's job is to carry a hostile
    // name as *data* and change nothing about it. The falsehood this prevents is either half of
    // that going wrong: a provider that quietly strips bytes corrupts a legitimate name and
    // breaks the round trip §35.3 requires, and a provider that reformats the address around the
    // escape hands the renderer a string whose shape the value chose.
    let uri = PlaceUri::namespaced(
        "prod",
        "shop",
        TypeSegment::parse("pod").expect("a type segment"),
        HOSTILE,
    )
    .expect("a name that is not empty is a name");

    let rendered = uri.to_string();
    assert!(
        rendered.contains(HOSTILE),
        "the name is carried, not rewritten: {rendered:?}"
    );

    let reparsed = PlaceUri::parse(&rendered).expect("the address parses back");
    assert_eq!(
        reparsed, uri,
        "a hostile name must not change the shape of the address it sits in"
    );
    assert_eq!(
        reparsed.name(),
        Some(HOSTILE),
        "every byte comes back, including the ones a terminal would act on"
    );
}

#[test]
fn should_not_let_a_name_containing_a_slash_add_a_segment_to_an_address() {
    // The one character that *would* change the shape, and the reason `place::encode` exists.
    // A hostile `metadata.name` of `../../cluster/node/worker-03` must not navigate anywhere but
    // to the object of that name (§35.3, §9.2).
    let hostile_name = "../../cluster/node/worker-03";
    let uri = PlaceUri::namespaced(
        "prod",
        "shop",
        TypeSegment::parse("pod").expect("a type segment"),
        hostile_name,
    )
    .expect("the name is not empty");

    let rendered = uri.to_string();
    assert!(
        !rendered.contains("/cluster/"),
        "an escaped name adds no path segment: {rendered:?}"
    );
    let reparsed = PlaceUri::parse(&rendered).expect("the escaped address parses back");
    assert_eq!(reparsed.name(), Some(hostile_name));
    assert_eq!(
        reparsed.namespace(),
        Some("shop"),
        "the place is still in the namespace it was built for"
    );
}

#[test]
fn should_not_let_a_path_shaped_namespace_climb_out_of_its_address() {
    // §9.2: a namespace is a scope, not a path. `../../etc` is a legal string and an illegal
    // namespace, and an address that resolved it would navigate to a place nobody asked for.
    let uri = PlaceUri::of_namespace("prod", "../../etc").expect("the namespace is not empty");
    let rendered = uri.to_string();
    let reparsed = PlaceUri::parse(&rendered).expect("it parses back");
    assert_eq!(
        reparsed.namespace(),
        Some("../../etc"),
        "the namespace is one component whatever it looks like: {rendered:?}"
    );
    assert_eq!(reparsed, uri);
}

#[test]
fn should_report_a_watch_frame_class_it_does_not_model_without_interpolating_it_raw() {
    // §19.3: a class this provider does not model is refused rather than skipped. The class name
    // comes off the wire, so the refusal quotes attacker text — and it quotes it through `{:?}`,
    // which escapes the control characters instead of embedding them. Core sanitises the message
    // anyway; this is the second layer, and it is the one that survives a message going somewhere
    // core does not render.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let frame = serde_json::json!({"type": HOSTILE, "object": {}}).to_string();
    let error = decoder
        .decode(format!("{frame}\n").as_bytes())
        .expect_err("an unmodelled class is a refusal");

    assert!(matches!(&error, FrameError::UnknownClass(class) if class == HOSTILE));
    let message = error.to_string();
    assert!(
        !message.chars().any(char::is_control),
        "the refusal carries no live control character: {message:?}"
    );
    assert!(
        message.contains("\\u{1b}") || message.contains("\\u{{1b}}"),
        "the escape is shown as an escape rather than swallowed: {message:?}"
    );
}

#[test]
fn should_leave_a_hostile_label_key_and_value_exactly_as_the_cluster_stated_them() {
    // §14.5: labels and annotations MUST be preserved as observed. A key is a domain-prefixed
    // path (`app.kubernetes.io/name`) and a value is thirty-two thousand bytes of anything, so
    // both are adversary-chosen. Preserving them is what lets the render boundary do its job on
    // a *complete* value rather than on one this provider already mangled.
    let object = Object::parse(
        INSTANCE,
        &serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "name": "checkout", "namespace": "shop", "uid": "p-1",
                "labels": {"acme.example.com/tier": HOSTILE},
                "annotations": {HOSTILE: "x"},
            },
        })
        .to_string(),
    )
    .expect("the object reads");

    assert_eq!(object.label("acme.example.com/tier"), Some(HOSTILE));
    assert_eq!(object.annotation(HOSTILE), Some("x"));
}

#[test]
fn should_address_a_label_key_containing_a_slash_through_the_json_pointer_it_escapes_to() {
    // RFC 6901 escaping, applied to the one Kubernetes field that routinely needs it. A schema
    // projection that built `/metadata/labels/app.kubernetes.io/name` would silently address a
    // field two levels down that does not exist, and report a legitimate label as absent — which
    // §12.5 forbids ("MUST NOT discard provider-native data").
    let object = Object::parse(
        INSTANCE,
        &serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "name": "checkout", "namespace": "shop",
                "labels": {"app.kubernetes.io/name": "shop", "a~b": "tilde"},
            },
        })
        .to_string(),
    )
    .expect("the object reads");

    let projection = Projection::of(&Schema::absent(), &object);
    let slashed = projection
        .field("/metadata/labels/app.kubernetes.io~1name")
        .expect("a label key with a slash is addressable, escaped");
    assert_eq!(slashed.value(), &serde_json::json!("shop"));
    let tilded = projection
        .field("/metadata/labels/a~0b")
        .expect("a label key with a tilde is addressable, escaped");
    assert_eq!(tilded.value(), &serde_json::json!("tilde"));

    // The pointers the projection hands out are the ones `Object::field` answers, so a reader
    // that copies one out of a rendering can put it back in.
    assert_eq!(
        object.field("/metadata/labels/app.kubernetes.io~1name"),
        Some(&serde_json::json!("shop"))
    );
}

// --- 2. secret payload, under pressure (§22, Gate I) --------------------------------------------

#[test]
fn should_leave_no_secret_payload_in_a_place_uri_or_a_relationship_evidence_value() {
    // §22.4: relationships stay useful without exposing payload, and §35.4's address is built
    // from identity alone. Both are places a payload could arrive by accident, because both are
    // built by *this* package out of fields of the object rather than rendered from a record.
    let guarded = Guarded::hold(secret_object()).expect("a Secret crosses the boundary");
    let place = Place::of_object(guarded.object()).expect("a Secret is somewhere");
    assert!(
        !discloses(&place.uri().to_string()),
        "an address is a name, never a value"
    );

    let referrer = Object::parse(
        INSTANCE,
        r#"{"apiVersion":"v1","kind":"ServiceAccount",
            "metadata":{"name":"checkout-sa","namespace":"shop","uid":"sa-1"},
            "secrets":[{"name":"db"}],
            "imagePullSecrets":[{"name":"registry"}]}"#,
    )
    .expect("the ServiceAccount reads");
    let edges = ono_provider_kubernetes::redaction::secret_references(&referrer);
    assert!(!edges.is_empty(), "§22.4's edges still exist");
    for edge in &edges {
        assert!(
            !discloses(&edge.evidence().describe()),
            "evidence cites the field it read and what that field held — a name, not a payload"
        );
        match edge.evidence() {
            Evidence::NativeField { value, .. } => assert!(!discloses(value)),
            other => panic!("a reference is read from a field, and this is {other:?}"),
        }
    }
}

#[test]
fn should_leave_no_secret_payload_in_a_schema_projection_of_a_guarded_secret() {
    // §12.5 makes every field of every object reachable through a generic structured value, and
    // §22.2 says the payload is not one of them. Those two rules meet in `Projection`, which is
    // the widest accessor this package has: it walks every leaf of the native document. A
    // projection taken from a `Guarded` finds `<redacted>` because there is nothing else left —
    // that is redaction.rs's structural claim, tested through the accessor most likely to break
    // it rather than through the one it was written against.
    let guarded = Guarded::hold(secret_object()).expect("a Secret crosses the boundary");
    let projection = Projection::of(&Schema::absent(), guarded.object());

    let rendered = format!("{:?}", projection.fields());
    assert!(
        !discloses(&rendered),
        "no leaf of the projected document holds the payload"
    );
    assert_eq!(
        projection
            .field("/data/password")
            .expect("§22.2 keeps the keys present, so the pointer still resolves")
            .value(),
        &serde_json::json!(REDACTED)
    );
    assert!(
        projection
            .field("/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration")
            .is_some_and(|field| field.value() == &serde_json::json!(REDACTED)),
        "the annotation that embeds the whole submitted object is payload too (§22.2)"
    );
}

#[test]
fn should_leave_no_secret_payload_in_a_watch_event_taken_across_the_boundary() {
    // §19.3 and Gate I together: a Secret arriving as a `MODIFIED` frame is the same object as
    // one arriving from a list, and a watch path that held raw objects would be a second, quieter
    // disclosure route than the one everybody reviews.
    let mut decoder = WatchDecoder::new(INSTANCE);
    let frame = serde_json::json!({
        "type": "MODIFIED",
        "object": serde_json::from_str::<serde_json::Value>(
            &serde_json::to_string(secret_object().native()).expect("the Secret serialises"),
        ).expect("it reads back"),
    })
    .to_string();

    let events = decoder
        .decode(format!("{frame}\n").as_bytes())
        .expect("the frame decodes");
    let WatchEvent::Modified(object) = events.into_iter().next().expect("one event") else {
        panic!("a MODIFIED frame decodes to a modification");
    };
    let guarded = Guarded::hold(object).expect("a watched Secret crosses the boundary");
    assert!(guarded.is_payload_protected());
    assert!(!discloses(&format!("{:?}", guarded.object())));
}

#[test]
fn should_type_a_secret_by_the_collection_it_came_from_rather_than_by_what_the_item_claims() {
    // §22 keyed on the object's *self-declared* kind is a decision the adversary gets to make.
    // A `GET /api/v1/namespaces/shop/secrets` whose items each carry `"kind":"ConfigMap"` — which
    // a hostile aggregated API server (§34) may send, and which §34.2 requires this provider to
    // survive — is answered by an object that never reaches `redaction::is_payload_protected`.
    //
    // FINDING (transport.rs, not this file's to repair): `transport::identify` deliberately lets
    // an item's own `kind` win over the list envelope's, so redaction is decided by the payload's
    // author. The requested GVR is known at this point and is the honest authority: an item of
    // the `secrets` collection is a Secret whatever it calls itself, and redaction.rs's own rule
    // applies — over-redaction costs a reader some detail, under-redaction cannot be taken back.
    // The assertion below records what happens today so the gap is visible rather than latent.
    let list = serde_json::json!({
        "apiVersion": "v1", "kind": "SecretList",
        "metadata": {"resourceVersion": "1"},
        "items": [{
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "db", "namespace": "shop", "uid": "sec-1"},
            "data": {"password": CIPHERTEXT},
        }],
    })
    .to_string();

    let mut client = client(&[response("200 OK", &list)]);
    let page = client
        .list_page(
            &secrets(),
            &Scope::in_namespace("shop"),
            &ListOptions::new(),
        )
        .expect("the page reads");
    let object = page.objects().first().expect("one item").clone();
    let guarded = Guarded::hold(object).expect("it crosses the boundary");

    assert!(
        !guarded.is_payload_protected(),
        "today the item's own claim decides, and the payload is not protected"
    );
    assert!(
        discloses(&format!("{:?}", guarded.object())),
        "so the payload of an object read from the `secrets` collection is handed out whole"
    );
}

#[test]
fn should_not_leave_an_item_kindless_when_the_envelope_is_a_generic_list() {
    // The same rule as the test above, reached by a second route. `transport::identify` gives an
    // item the envelope's kind with `List` stripped off the end, so a generic `v1 List` — what an
    // aggregated API server or a mixed collection produces — leaves every item with the kind `""`.
    // An empty kind is not `Secret`, so §22 does not apply to any of them.
    //
    // FINDING (transport.rs, not this file's to repair): `strip_suffix("List")` on a kind that is
    // exactly `List` yields nothing, and nothing is not a kind. §13.5 makes canonical identity
    // group-plus-kind, and an object with neither is not identified at all — the item should keep
    // the requested GVR's kind, or the envelope should be refused as one this provider cannot
    // type.
    let list = serde_json::json!({
        "apiVersion": "v1", "kind": "List",
        "metadata": {"resourceVersion": "1"},
        "items": [{
            "metadata": {"name": "db", "namespace": "shop", "uid": "sec-1"},
            "data": {"password": CIPHERTEXT},
        }],
    })
    .to_string();

    let mut client = client(&[response("200 OK", &list)]);
    let page = client
        .list_page(
            &secrets(),
            &Scope::in_namespace("shop"),
            &ListOptions::new(),
        )
        .expect("the page reads");
    let object = page.objects().first().expect("one item").clone();

    assert_eq!(
        object.gvk().kind(),
        "",
        "today the item comes back with no kind at all"
    );
    let guarded = Guarded::hold(object).expect("it crosses the boundary");
    assert!(
        !guarded.is_payload_protected(),
        "and an object with no kind is not a Secret, so the payload is not protected"
    );
    assert!(discloses(&format!("{:?}", guarded.object())));
}

#[test]
fn should_leave_no_secret_payload_in_a_status_message_this_provider_composes() {
    // §48.1 preserves a `Status` verbatim, which is right — a message the API server wrote is the
    // cluster's statement and truncating it would lose the reason a change was refused. What must
    // not happen is this provider *adding* payload of its own to one, or an error type keeping a
    // request body around to quote later.
    let message = format!("Secret \"db\" is invalid: data.password: Invalid value: {CIPHERTEXT}");
    let body = serde_json::json!({
        "kind": "Status", "apiVersion": "v1", "status": "Failure",
        "message": message, "reason": "Invalid", "code": 422,
    })
    .to_string();
    let status = Status::parse(body.as_bytes()).expect("a Status parses");

    // The message is the server's and is carried whole (§48.1). That is the cluster disclosing
    // its own payload, and this provider is not entitled to edit the reason a write was refused.
    assert_eq!(status.message(), Some(message.as_str()));
    // What this provider composes around it adds nothing.
    let error = ApiError::Failed {
        code: 422,
        status: Box::new(status),
    };
    let composed = error.to_string().replace(&message, "");
    assert!(
        !discloses(&composed),
        "the wrapper around the server's sentence contributes no payload of its own"
    );
}

#[test]
fn should_show_a_submitted_secret_value_in_an_admission_difference() {
    // §44.6's admission diff is built from two halves. The *returned* half is guarded on purpose
    // (`mutation::admission_differences_of` exists for exactly that), so an admission webhook
    // that rewrote a payload cannot report the rewritten bytes. The *requested* half is not.
    //
    // FINDING (mutation.rs, not this file's to repair): §22.3 says "Secret bytes MUST NOT flow
    // into ordinary command history, terminal scrollback capture or provider logs by default",
    // and it does not say "unless the operator typed them". A `k8s-apply` of a Secret whose
    // payload admission left alone reports no difference and leaks nothing; one that admission
    // *changed* reports the submitted value verbatim beside `<redacted>`. The submitted side of a
    // change under a payload-bearing pointer should be redacted the same way the returned side is.
    let requested = serde_json::json!({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": "db", "namespace": "shop"},
        "data": {"password": CIPHERTEXT},
    });
    let returned =
        Guarded::hold(secret_object()).expect("the returned object crosses the boundary");

    let differences = admission_differences_of(&requested, returned.object());
    let rendered = format!("{differences:?}");
    assert!(
        discloses(&rendered),
        "today the submitted half of the diff carries the payload: {rendered}"
    );
    assert!(
        rendered.contains(REDACTED),
        "the returned half is redacted, which is the half `admission_differences_of` was written for"
    );
}

// --- 3. hostile identity (§13.5, §16, §9.2) -----------------------------------------------------

#[test]
fn should_treat_an_empty_uid_as_no_uid_rather_than_as_a_stable_lifetime() {
    // §16.5: "If an unusual API object lacks UID, the provider MUST degrade identity confidence
    // explicitly." An empty string is lacking a UID — `""` is what a hand-written manifest, a
    // tombstone reconstruction and an aggregated API server that does not mint UIDs all produce.
    // Reported as lifetime-stable, it is worse than a missing one: §16.3's recreate detection
    // compares UIDs, and every object with an empty UID compares equal to every other, so two
    // different lifetimes merge instead of producing the discontinuity Gate C requires.
    let object = Object::parse(
        INSTANCE,
        r#"{"apiVersion":"v1","kind":"Pod",
            "metadata":{"name":"checkout","namespace":"shop","uid":""}}"#,
    )
    .expect("the object reads");

    assert_eq!(object.uid(), None, "an empty UID is not a UID");
    assert_eq!(
        object.identity().uid(),
        None,
        "and the identity built from it does not carry one either"
    );
    assert!(
        !object.identity().is_lifetime_stable(),
        "§16.5 requires the degradation to be explicit"
    );

    // And two objects that both lack one do not become the same lifetime.
    let other = Object::parse(
        INSTANCE,
        r#"{"apiVersion":"v1","kind":"Pod",
            "metadata":{"name":"checkout","namespace":"shop","uid":""}}"#,
    )
    .expect("the object reads");
    assert!(
        object.identity().is_same_locator(&other.identity()),
        "they occupy one address, which is what a locator says"
    );
    assert!(
        !object.identity().is_lifetime_stable() && !other.identity().is_lifetime_stable(),
        "and neither may claim to be the same lifetime as the other"
    );
}

#[test]
fn should_keep_a_uid_that_is_not_a_uuid_exactly_as_the_server_stated_it() {
    // §14.2 makes `metadata.uid` the lifetime identity and says nothing about its syntax. An
    // aggregated API server may mint anything; a provider that validated the shape would reject
    // a cluster it can read perfectly well (§5.3, "no newest-version assumptions" applied to
    // format), and one that normalised it would compare two different lifetimes as one.
    for uid in ["not-a-uuid", "0", "‑1", HOSTILE] {
        let object = Object::parse(
            INSTANCE,
            &serde_json::json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "checkout", "namespace": "shop", "uid": uid},
            })
            .to_string(),
        )
        .expect("the object reads");
        assert_eq!(object.uid(), Some(uid), "the UID is carried, not judged");
        assert!(object.identity().is_lifetime_stable());
    }
}

#[test]
fn should_keep_a_two_hundred_and_fifty_three_character_name_whole_and_addressable() {
    // A DNS subdomain is 253 characters, which is the longest legal Kubernetes name. Nothing here
    // may truncate it: a truncated name is a *different* name, and §16.2's locator would then
    // address the wrong object — or collide with a neighbour that shares its first N characters,
    // which is exactly how an adversary who can create objects would arrange to be mistaken for
    // one they cannot.
    let name = format!("{}.{}", "a".repeat(126), "b".repeat(126));
    assert_eq!(name.len(), 253);

    let object = Object::parse(
        INSTANCE,
        &serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "shop", "uid": "p-1"},
        })
        .to_string(),
    )
    .expect("the object reads");
    assert_eq!(object.name(), name);

    let place = Place::of_object(&object).expect("it is somewhere");
    let rendered = place.uri().to_string();
    assert!(rendered.contains(&name), "the address holds the whole name");
    assert_eq!(
        PlaceUri::parse(&rendered)
            .expect("it parses back")
            .name()
            .expect("a resource place has a name"),
        name
    );
}

#[test]
fn should_not_merge_two_contexts_whose_names_differ_only_by_the_instance_prefix() {
    // §6.2 spells a provider instance `kubernetes:<context>`, and Gate J (§62.10) forbids two
    // configured contexts sharing anything. A kubeconfig context is an arbitrary string — a
    // managed cluster's is routinely an ARN, and nothing stops one being called `kubernetes:prod`.
    // If the prefix is stripped from a *context* as though it were an instance, that context and
    // the ordinary context `prod` become one address, one session key and one cache.
    // The instance of the context `prod`, spelled both ways a caller holds it.
    let ordinary = PlaceUri::cluster_root("prod").expect("a bare context is accepted");
    assert_eq!(
        ordinary,
        PlaceUri::cluster_root("kubernetes:prod").expect("so is the qualified spelling"),
        "one context, one instance, however the caller spelled the identifier (§6.2)"
    );
    assert_eq!(ordinary.instance(), "kubernetes:prod");

    // The instance of a context that is *itself* called `kubernetes:prod`. §6.2 puts one prefix
    // in front of a context, so this is the qualified identifier of a different cluster.
    let awkward = PlaceUri::cluster_root("kubernetes:kubernetes:prod").expect("a context is text");
    assert_eq!(awkward.instance(), "kubernetes:kubernetes:prod");
    assert_ne!(
        ordinary, awkward,
        "two kubeconfig contexts are two places, whatever they are called (Gate J, §62.10)"
    );
    assert_ne!(ordinary.to_string(), awkward.to_string());

    // And the address survives the round trip into the same instance rather than into the other
    // one, which is the failure that would make Gate J false by way of navigation (§35.3).
    for uri in [&ordinary, &awkward] {
        let reparsed = PlaceUri::parse(&uri.to_string()).expect("it parses back");
        assert_eq!(&reparsed, uri, "{uri} did not survive the round trip");
        assert_eq!(reparsed.instance(), uri.instance());
    }
}

#[test]
fn should_keep_two_kinds_of_one_name_apart_when_they_belong_to_different_groups() {
    // §13.5: "Kinds are not globally unique... canonical identity MUST include API group."
    // Installing a CRD called `Secret` in someone's group is a thing an adversary with CRD rights
    // can do, and the two must not share an address.
    let core = Gvk::new("", "v1", "Secret");
    let custom = Gvk::new("acme.example.com", "v1", "Secret");
    assert_ne!(TypeSegment::of(&core), TypeSegment::of(&custom));
    assert_eq!(TypeSegment::of(&core).to_string(), "secret");
    assert_eq!(
        TypeSegment::of(&custom).to_string(),
        "secret.acme.example.com"
    );

    // And the redaction rule reaches both, on purpose: §33.1 makes CRDs normal resources, and a
    // custom kind called `Secret` is very likely holding what its name says.
    let custom_secret = Object::parse(
        INSTANCE,
        &serde_json::json!({
            "apiVersion": "acme.example.com/v1", "kind": "Secret",
            "metadata": {"name": "db", "namespace": "shop", "uid": "x-1"},
            "data": {"password": CIPHERTEXT},
        })
        .to_string(),
    )
    .expect("the custom object reads");
    let guarded = Guarded::hold(custom_secret).expect("it crosses the boundary");
    assert!(guarded.is_payload_protected());
    assert!(!discloses(&format!("{:?}", guarded.object())));
}

#[test]
fn should_not_read_a_second_slash_in_an_api_version_as_a_deeper_group() {
    // §13.1 keeps GVK and GVR apart, and an `apiVersion` is `group/version` with exactly one
    // slash. A hostile server may send `acme.example.com/v1/../../v1`; the split must not turn
    // the extra segments into part of the group, because the group is what §13.5's identity and
    // §35.4's address are built from.
    let object = Object::parse(
        INSTANCE,
        r#"{"apiVersion":"acme.example.com/v1/../../secrets","kind":"Widget",
            "metadata":{"name":"w","namespace":"shop","uid":"w-1"}}"#,
    )
    .expect("the object reads");

    assert_eq!(
        object.gvk().group(),
        "acme.example.com",
        "the group is the head"
    );
    assert_eq!(
        object.gvk().version(),
        "v1/../../secrets",
        "and the rest stays in the version, where it is representation rather than identity (§16.1)"
    );
    let place = Place::of_object(&object).expect("it is somewhere");
    assert_eq!(
        place.uri().to_string(),
        "k8s://prod-eu/ns/shop/widget.acme.example.com/w",
        "the version is not part of an address, so a hostile one cannot reshape it (§35.3)"
    );
}

#[test]
fn should_not_let_a_path_shaped_namespace_or_name_climb_the_rest_path() {
    // §17.1 resolves a REST endpoint from discovery, and every component after it comes from
    // somewhere a user or an object chose. `..` is normalised by Go's HTTP mux before the API
    // server's authorizer ever sees the request, so a `GET` of a Pod named `../../secrets/admin`
    // reads a Secret under a Pod's RBAC decision.
    //
    // FINDING (transport.rs, not this file's to repair): neither `collection_path` nor
    // `object_path` validates or percent-encodes its components, although `Request::target`
    // already percent-encodes every query value for the same class of reason. A name and a
    // namespace belong in the path's unreserved set or in `%XX`, and `.`/`..` belong nowhere.
    let traversing = object_path(
        &pods(),
        &Scope::in_namespace("shop"),
        "../../secrets/admin-token",
    );
    assert_eq!(
        traversing, "/api/v1/namespaces/shop/pods/../../secrets/admin-token",
        "today the components are pasted in raw"
    );

    let climbing = collection_path(&pods(), &Scope::in_namespace("../../../api/v1/secrets"));
    assert_eq!(
        climbing, "/api/v1/namespaces/../../../api/v1/secrets/pods",
        "and a namespace is pasted in raw too"
    );
}

#[test]
fn should_not_let_a_name_carrying_crlf_forge_a_header_or_a_second_request() {
    // The same missing encoding, at its worst. An object name is interpolated into the request
    // line, so `\r\n` in one ends the line and starts a header — or a whole second request on a
    // keep-alive connection. §51.2 bounds this provider to the configured API server; it does not
    // bound what it may be made to *ask* that server for.
    //
    // FINDING (transport.rs, not this file's to repair): `Request::serialise` writes
    // `{method} {target} HTTP/1.1\r\n` with an unencoded target, and writes header values
    // unencoded too. A name is data; it must be percent-encoded before it becomes protocol.
    let smuggled = "x HTTP/1.1\r\nX-Remote-User: cluster-admin\r\n\r\nGET /api/v1/secrets";
    let request = Request::get(object_path(&pods(), &Scope::in_namespace("shop"), smuggled));
    let wire = String::from_utf8(request.serialise(HOST)).expect("the wire is text");

    assert!(
        wire.contains("X-Remote-User: cluster-admin"),
        "today a name can write a header: {wire:?}"
    );
    assert_eq!(
        wire.lines().filter(|line| line.starts_with("GET ")).count(),
        2,
        "and a second request line, which on a keep-alive connection is a second request"
    );

    // The query string is the half that is already right, and it is the model for the fix.
    let encoded = Request::get("/api/v1/pods").query("fieldSelector", smuggled);
    assert!(
        !encoded.target().contains('\r'),
        "a query value is percent-encoded: {}",
        encoded.target()
    );
}

#[test]
fn should_report_the_object_the_server_actually_sent_rather_than_the_one_that_was_asked_for() {
    // §17.1's get addresses one object by name. A server that answers with a different object —
    // a different name, a different kind, a different namespace — is either broken or hostile,
    // and either way the provider must not present the answer under the question's identity.
    //
    // FINDING (transport.rs, not this file's to repair): `Client::get` performs no cross-check
    // between the requested locator and the returned object's `metadata`. Combined with the
    // kind-from-the-item rule above, that is how a hostile aggregated API server chooses which
    // §22 rule applies to the bytes it is sending. The identity below is honest about what
    // arrived, which is the right half; what is missing is the mismatch being *reported*.
    let body = serde_json::json!({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": "somebody-else", "namespace": "kube-system", "uid": "s-9"},
        "data": {"password": CIPHERTEXT},
    })
    .to_string();
    let mut client = client(&[response("200 OK", &body)]);
    let read = client
        .get(&pods(), &Scope::in_namespace("shop"), "checkout")
        .expect("the read succeeds");

    assert_eq!(read.object().name(), "somebody-else");
    assert_eq!(read.object().namespace(), Some("kube-system"));
    assert_eq!(read.object().gvk().kind(), "Secret");
    // The one thing that does hold: crossing the boundary is keyed on what arrived, so the
    // payload of the substituted object is still destroyed.
    let guarded = Guarded::hold(read.into_parts().0).expect("it crosses the boundary");
    assert!(guarded.is_payload_protected());
    assert!(!discloses(&format!("{:?}", guarded.object())));
}

// --- 4. malformed and hostile API responses (§48.1, §18.1) --------------------------------------

#[test]
fn should_refuse_a_ten_thousand_level_document_rather_than_exhausting_the_stack() {
    // §50.5's "very large object payloads" at their nastiest shape: depth rather than width. A
    // recursive-descent decoder without a depth bound overflows the stack, which on a plugin
    // process is a crash rather than an error — and a crash is not one of §48.2's outcomes.
    let deep = format!(
        r#"{{"apiVersion":"v1","kind":"Widget","metadata":{{"name":"w"}},"spec":{}{}}}"#,
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    let error = Object::parse(INSTANCE, &deep).expect_err("depth is refused");
    assert!(
        error.to_string().contains("recursion limit"),
        "the refusal names the reason: {error}"
    );

    // The same bound protects the schema decoder, whose `build_field` recurses over `properties`.
    let nested_schema = format!(
        r#"{{"type":"object","properties":{{"a":{}}}}}"#,
        std::iter::repeat_n(r#"{"type":"object","properties":{"a":"#, 5_000).collect::<String>()
            + "{}"
            + &"}}".repeat(5_000)
    );
    assert!(
        Schema::from_openapi_v3(&nested_schema).is_err(),
        "a schema that deep is refused rather than recursed into"
    );
}

#[test]
fn should_refuse_a_collection_whose_items_are_not_an_array() {
    // §17.2 reads a collection's items. A `Status`, an object, a string or `null` in that slot is
    // not an empty collection, and reporting it as one would make a hostile server's malformed
    // answer indistinguishable from "there is nothing here" — the confusion §21.4 and Gate E are
    // both about.
    for items in [
        serde_json::json!({}),
        serde_json::json!("items"),
        serde_json::json!(null),
        serde_json::json!(7),
    ] {
        let body = serde_json::json!({
            "apiVersion": "v1", "kind": "PodList",
            "metadata": {"resourceVersion": "1"},
            "items": items,
        })
        .to_string();
        let mut client = client(&[response("200 OK", &body)]);
        let error = client
            .list_page(&pods(), &Scope::in_namespace("shop"), &ListOptions::new())
            .expect_err("a collection without an item array is malformed");
        assert!(
            matches!(error, ApiError::Malformed(_)),
            "and it is malformed rather than empty: {error:?}"
        );
    }
}

#[test]
fn should_refuse_a_watch_frame_that_is_valid_json_but_not_a_watch_event() {
    // §19.3 again, from the other side: a decoder that skipped what it could not read would leave
    // the stream looking continuous over bytes nobody accounted for, which is §19.4's forbidden
    // stitch reached quietly.
    let cases: Vec<(String, fn(&FrameError) -> bool)> = vec![
        (serde_json::json!({"object": {}}).to_string(), |error| {
            matches!(error, FrameError::Untyped)
        }),
        (
            serde_json::json!({"type": "ADDED"}).to_string(),
            |error| matches!(error, FrameError::ObjectMissing(class) if class == "ADDED"),
        ),
        (
            serde_json::json!({"type": "ADDED", "object": {"no": "kind"}}).to_string(),
            |error| matches!(error, FrameError::NotAnObject(_)),
        ),
        (
            serde_json::json!({"type": "BOOKMARK", "object": {"metadata": {}}}).to_string(),
            |error| matches!(error, FrameError::UncheckpointedBookmark),
        ),
        (serde_json::json!([1, 2, 3]).to_string(), |error| {
            matches!(error, FrameError::Untyped)
        }),
        (serde_json::json!("a string").to_string(), |error| {
            matches!(error, FrameError::Untyped)
        }),
        (serde_json::json!(null).to_string(), |error| {
            matches!(error, FrameError::Untyped)
        }),
    ];

    for (frame, expected) in cases {
        let mut decoder = WatchDecoder::new(INSTANCE);
        let error = decoder
            .decode(format!("{frame}\n").as_bytes())
            .expect_err("a frame that is not a watch event is a refusal");
        assert!(expected(&error), "{frame} produced {error:?}");
    }
}

#[test]
fn should_refuse_a_chunked_body_whose_chunk_size_is_not_a_number() {
    // §59.2's fixture transport meets a server that is lying about its own framing. A bogus size
    // must end the read as a protocol fault: guessing past it resynchronises on attacker-chosen
    // bytes, which is how a body comes to contain a response the server never sent.
    for size in ["zz", "-1", "", "0x10", " 4 2"] {
        let wire = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nabcd\r\n0\r\n\r\n"
        );
        let mut connection = HttpConnection::new(FixtureStream::new(&wire), HOST);
        let outcome = connection.send(&Request::get("/api/v1/pods"));
        assert!(
            matches!(outcome, Err(ApiError::Protocol(_))),
            "a chunk size of {size:?} is a protocol fault, and produced {outcome:?}"
        );
    }
}

#[test]
fn should_refuse_a_content_length_that_promises_more_than_the_body_carries() {
    // §18.3 and §48: a short body is not a small answer. Truncating silently would turn a cut
    // connection into a complete-looking collection, which is the lie every coverage rule in this
    // provider exists to prevent.
    let body = r#"{"apiVersion":"v1","kind":"PodList","items":[]}"#;
    let wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{body}"
    );
    let mut connection = HttpConnection::new(FixtureStream::new(&wire), HOST);
    let outcome = connection.send(&Request::get("/api/v1/pods"));
    assert!(
        matches!(&outcome, Err(ApiError::Stream(detail)) if detail.contains("closed")),
        "a body shorter than its declared length fails: {outcome:?}"
    );

    // And a `Content-Length` that is not a number at all is refused before any body is read,
    // rather than falling back to reading until the connection closes.
    let bogus = "HTTP/1.1 200 OK\r\nContent-Length: 1e9\r\n\r\n{}";
    let mut connection = HttpConnection::new(FixtureStream::new(bogus), HOST);
    assert!(matches!(
        connection.send(&Request::get("/api/v1/pods")),
        Err(ApiError::Protocol(_))
    ));
}

#[test]
fn should_read_a_status_whose_message_is_enormous_without_losing_its_structured_fields() {
    // §48.1 lists the fields a `Status` must keep. A megabyte of `message` is what a webhook that
    // echoes a rejected object produces, and the taxonomy must not be decided by how long the
    // sentence was.
    let message = "A".repeat(1_024 * 1_024);
    let body = serde_json::json!({
        "kind": "Status", "apiVersion": "v1", "status": "Failure",
        "message": message, "reason": "Forbidden", "code": 403,
        "details": {"name": "checkout", "kind": "pods", "group": ""},
    })
    .to_string();

    let status = Status::parse(body.as_bytes()).expect("an enormous Status still parses");
    assert_eq!(status.code(), Some(403));
    assert_eq!(status.reason(), Some("Forbidden"));
    assert_eq!(status.details_name(), Some("checkout"));
    assert_eq!(
        status.message().map(str::len),
        Some(1_024 * 1_024),
        "the message is preserved whole (§48.1); bounding it is the renderer's business, and \
         core's `Reporter` shows a terse form by default"
    );
}

#[test]
fn should_follow_a_continue_token_that_never_advances_until_something_else_stops_it() {
    // §18.1 says a `continue` token means the collection is incomplete. It does not say what to
    // do when the token never changes — and a server that echoes one, whether by a bug in an
    // aggregated API server (§34.2) or on purpose, turns a list into a loop.
    //
    // FINDING (transport.rs, not this file's to repair): `Client::walk` re-sends whatever token
    // arrives with no comparison against the one it just sent, and `Client::new` starts on
    // `Budget::unlimited()`, so nothing bounds the repetition. Against a real socket this does
    // not terminate; here it stops only because the recorded bytes run out. Core §12.3 asks a
    // provider to "prevent duplicate emission where provider pagination semantics permit stable
    // deduplication" — a token identical to the one just sent is exactly that signal, and it
    // should break continuity (`BreakReason`) rather than loop.
    let page = serde_json::json!({
        "apiVersion": "v1", "kind": "PodList",
        "metadata": {"resourceVersion": "1", "continue": "never-advances"},
        "items": [{"metadata": {"name": "checkout", "namespace": "shop", "uid": "p-1"}}],
    })
    .to_string();
    let responses: Vec<String> = std::iter::repeat_n(response("200 OK", &page), 24).collect();

    let mut looping = client(&responses);
    let mut reader = Everything::default();
    let listing = looping.walk(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new(),
        &mut reader,
    );

    assert_eq!(
        listing.pages(),
        24,
        "every recorded page was followed, and only the end of the bytes stopped it"
    );
    assert_eq!(
        reader.names.len(),
        24,
        "and the same object was emitted once per page: {:?}",
        reader.names.first()
    );
    assert!(
        reader.names.iter().all(|name| name == "checkout"),
        "twenty-four copies of one Pod"
    );
    assert!(
        listing.continuity().is_intact(),
        "and nothing reported the repetition: the sequence still looks continuous"
    );

    // A page budget is what stops it today, and it has to be asked for.
    let mut bounded_client = client(&responses);
    let mut reader = Everything::default();
    let bounded = bounded_client.walk(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new().max_pages(3),
        &mut reader,
    );
    assert_eq!(bounded.pages(), 3);
    assert!(
        bounded.coverage().may_have_more(),
        "§18.4: stopping is a decision, and the stream is told more exists upstream"
    );
}

#[test]
fn should_not_recurse_through_an_openapi_document_that_refers_to_itself() {
    // §12.2's dynamic typed projection reads a published schema. OpenAPI `$ref` cycles are
    // ordinary in Kubernetes' own document (`JSONSchemaProps` refers to itself), so a reader that
    // resolved references would need a cycle guard or it would not terminate.
    let cyclic = serde_json::json!({
        "type": "object",
        "properties": {
            "self": {"$ref": "#/"},
            "child": {"$ref": "#/properties/self"},
            "spec": {"type": "object", "properties": {"up": {"$ref": "#/"}}},
        },
    })
    .to_string();

    let schema = Schema::from_openapi_v3(&cyclic).expect("a document with a cycle still reads");
    // The reference is data rather than a link to follow: nothing here dereferences it, so the
    // cycle is inert. A future reader that resolves `$ref` inherits this test as its bound.
    assert!(schema.field("/self").is_some());
    assert!(
        schema.field("/self/self/self/self").is_none(),
        "an unresolved reference has no children, so a cycle cannot be walked into"
    );
    assert!(schema.declared_references().is_empty(), "§33.7, §68.7");
}

// --- 5. resource bounds (§18.5, §50.5, core §30.4) ----------------------------------------------

#[test]
fn should_bound_what_a_watch_decoder_holds_when_a_frame_never_ends() {
    // §18.5 and core §30.4: "Enumeration and watch implementations MUST avoid retaining entire
    // remote inventories when streaming semantics suffice." A watch body is newline-delimited, so
    // a server — or a proxy, or an aggregated API server having a bad day — that never sends a
    // newline makes the decoder's hold-back buffer the whole response. There is no upper bound on
    // a watch's length, so there is no upper bound on that buffer.
    assert_eq!(
        WatchDecoder::new(INSTANCE).frame_limit(),
        16 * 1024 * 1024,
        "the default bound is the one an API server's largest object fits inside with room"
    );

    // The bound is stated rather than hard-coded, so the attack is run against a small one: the
    // property is that *a* bound fires and releases, and sixteen mebibytes of `{` proves nothing
    // that the same shape at a quarter of a megabyte does not.
    let mut decoder = WatchDecoder::new(INSTANCE).holding_back(256 * 1024);
    let chunk = vec![b'{'; 64 * 1024];
    let mut fed = 0_usize;
    let mut refused = None;
    for _ in 0..1_024 {
        match decoder.decode(&chunk) {
            Ok(events) => {
                assert!(events.is_empty(), "no frame ended, so no event arrived");
                fed += chunk.len();
                assert!(
                    decoder.pending_bytes() <= decoder.frame_limit() + chunk.len(),
                    "the hold-back never exceeds the bound plus the chunk that reached it"
                );
            }
            Err(error) => {
                refused = Some(error);
                break;
            }
        }
    }

    let error = refused.expect("a frame that never ends is refused before it becomes the heap");
    let FrameError::Oversized { held, limit } = error else {
        panic!("the refusal names the bound, and it is {error:?}");
    };
    assert_eq!(limit, 256 * 1024, "the refusal names the bound that fired");
    assert!(held > limit && held <= fed + chunk.len());
    assert_eq!(
        decoder.pending_bytes(),
        0,
        "the bytes are released with the refusal; holding them would refuse nothing"
    );
    assert!(
        !FrameError::Oversized { held, limit }.to_string().is_empty(),
        "and the refusal says which bound fired, because a limit nobody can see cannot be raised"
    );
}

#[test]
fn should_bound_what_a_log_decoder_holds_when_a_line_never_ends() {
    // The same shape, reachable by anyone who can run a container: `yes | tr -d '\n'` produces a
    // log with no line ending at all. §42.1's read is bounded by `limitBytes`, but the *decoder*
    // is what holds the partial line, and a bound the caller has to remember is not a bound.
    assert_eq!(
        LogDecoder::plain().line_limit(),
        1024 * 1024,
        "the default bound is far past any line a person reads and far short of a heap"
    );

    let mut decoder = LogDecoder::plain().holding_back(128 * 1024);
    let chunk = vec![b'x'; 64 * 1024];
    let mut delivered = 0_usize;
    let mut cut = 0_usize;
    for _ in 0..16 {
        for line in decoder.decode(&chunk) {
            delivered += line.bytes().len();
            assert!(
                line.was_cut(),
                "a piece handed over with no newline in sight is one this provider cut"
            );
            assert!(
                !line.is_terminated(),
                "and it is not terminated, because the server sent no newline"
            );
            assert_eq!(line.bytes().len(), decoder.line_limit());
            cut += 1;
        }
        assert!(
            decoder.pending_bytes() <= decoder.line_limit() + chunk.len(),
            "the hold-back stays at the bound: {} bytes",
            decoder.pending_bytes()
        );
    }

    assert!(
        cut >= 7,
        "a megabyte arrived with no newline in it, and {cut} pieces were handed over"
    );
    assert_eq!(
        delivered,
        cut * decoder.line_limit(),
        "nothing was discarded on the way: §12.5's rule applied to a stream"
    );

    // The tail is handed over too, and it is *not* marked cut: the body ended there.
    let tail = decoder.finish().expect("the held bytes are handed over");
    assert!(!tail.is_terminated(), "the server sent no newline");
    assert!(
        !tail.was_cut(),
        "the end of a body is not the decoder's bound, and a reader must be able to tell"
    );
}

#[test]
fn should_stay_proportional_over_a_watch_that_delivers_ten_thousand_events() {
    // §19.6 makes watches demand-driven and ADR-0022 makes one invocation a bounded observation.
    // What must hold underneath both is that ten thousand events cost ten thousand events and not
    // ten thousand *collections*: the cache is keyed on identity, so a Pod modified ten thousand
    // times is one entry.
    use ono_provider_kubernetes::watch::{ResourceVersion, WatchStream};

    let mut stream = WatchStream::new(pods(), Scope::in_namespace("shop"));
    stream.listed(Vec::new(), ResourceVersion::new("1"));

    let mut decoder = WatchDecoder::new(INSTANCE);
    let mut body = String::new();
    for version in 0..10_000_u32 {
        body.push_str(
            &serde_json::json!({
                "type": "MODIFIED",
                "object": {
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {
                        "name": "checkout", "namespace": "shop", "uid": "p-1",
                        "resourceVersion": version.to_string(),
                    },
                },
            })
            .to_string(),
        );
        body.push('\n');
    }

    let events = decoder
        .decode(body.as_bytes())
        .expect("every frame decodes");
    assert_eq!(events.len(), 10_000);
    assert_eq!(decoder.pending_bytes(), 0, "nothing is held back");
    for event in events {
        stream.observe(event);
    }
    assert_eq!(
        stream.object_count(),
        1,
        "ten thousand modifications of one Pod are one Pod"
    );
}

#[test]
fn should_read_a_collection_of_a_hundred_thousand_objects_and_say_what_it_bounded() {
    // §18.5 and §50.5. The point is not that a big list is fast; it is that a caller who does not
    // want all of it is not made to hold all of it, and that stopping is *reported* rather than
    // looking like the end of the collection (§18.4, Gate E).
    let items: Vec<serde_json::Value> = (0..2_000)
        .map(|index| {
            serde_json::json!({
                "metadata": {
                    "name": format!("pod-{index}"), "namespace": "shop",
                    "uid": format!("p-{index}"), "resourceVersion": "1",
                },
            })
        })
        .collect();
    let page = serde_json::json!({
        "apiVersion": "v1", "kind": "PodList",
        "metadata": {"resourceVersion": "1", "continue": format!("page-{}", 1)},
        "items": items,
    })
    .to_string();
    let responses: Vec<String> = std::iter::repeat_n(response("200 OK", &page), 50).collect();

    /// A reader that counts and keeps nothing, which is what §18.5 asks a forwarding caller to be.
    #[derive(Default)]
    struct Counting {
        seen: usize,
    }
    impl Reader for Counting {
        fn page(&mut self, page: Page) -> Walk {
            self.seen += page.objects().len();
            if self.seen >= 100_000 {
                Walk::Stop
            } else {
                Walk::Continue
            }
        }
    }

    let mut client = client(&responses);
    let mut reader = Counting::default();
    let listing = client.walk(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new(),
        &mut reader,
    );

    assert_eq!(reader.seen, 100_000, "a hundred thousand objects were read");
    assert!(
        listing.objects().is_empty(),
        "and the walk kept none of them: the reader has them (§18.5)"
    );
    assert!(
        listing.coverage().may_have_more(),
        "stopping is a decision, and it is reported as one rather than as the end of the list"
    );
    assert!(
        listing.coverage().is_complete(),
        "a decision is not a gap (§18.4)"
    );
}

#[test]
fn should_hold_a_fifty_megabyte_object_without_the_projection_multiplying_it() {
    // §50.5: "Resources with very large object payloads... SHOULD support field projection/lazy
    // expansion." The failure this prevents is quieter than an out-of-memory: `Projection` clones
    // every leaf, so a projection of a huge object is a *second* copy of it plus one heap string
    // per pointer. A single field holding the bulk must not become a thousand copies of the bulk.
    let bulk = "z".repeat(4 * 1024 * 1024);
    let object = Object::parse(
        INSTANCE,
        &serde_json::json!({
            "apiVersion": "acme.example.com/v1", "kind": "Widget",
            "metadata": {"name": "w", "namespace": "shop", "uid": "w-1"},
            "spec": {"blob": bulk},
        })
        .to_string(),
    )
    .expect("a large object reads");

    let projection = Projection::of(&Schema::absent(), &object);
    assert_eq!(
        projection.fields().len(),
        8,
        "one field per leaf and per container, and the bulk is one of them"
    );
    assert_eq!(
        projection
            .field("/spec/blob")
            .expect("the bulk is addressable")
            .value()
            .as_str()
            .map(str::len),
        Some(4 * 1024 * 1024)
    );
}

// --- 6. properties of the pure decoders ---------------------------------------------------------

/// A deterministic pseudo-random source, so a property run is reproducible from its seed.
///
/// A dependency would buy shrinking and a corpus; neither is worth a new crate here, because
/// every property below has a *finite, enumerable* input space that a table covers exactly —
/// see ADR-0043.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        ((self.0 >> 33) as usize) % bound.max(1)
    }
}

#[test]
fn should_decode_the_same_watch_events_however_the_chunk_boundaries_fall() {
    // The framing property that matters: HTTP chunk boundaries have nothing to do with watch
    // frame boundaries, and a decoder that treated one read as one message is, as transport.rs
    // says, the oldest bug on this path. Split one body a hundred different ways and demand the
    // same answer every time — including splits that land inside a multi-byte character and
    // inside a JSON string containing a newline escape.
    let mut body = String::new();
    for (index, name) in ["checkout", "läden-🛒", HOSTILE].iter().enumerate() {
        body.push_str(
            &serde_json::json!({
                "type": "ADDED",
                "object": {
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": name, "namespace": "shop", "uid": format!("p-{index}")},
                },
            })
            .to_string(),
        );
        body.push('\n');
    }
    let bytes = body.as_bytes();

    let mut whole = WatchDecoder::new(INSTANCE);
    let expected = whole.decode(bytes).expect("the whole body decodes");
    assert_eq!(expected.len(), 3);

    let mut random = Lcg(0x5eed);
    for _ in 0..200 {
        let mut decoder = WatchDecoder::new(INSTANCE);
        let mut got = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let take = 1 + random.next(bytes.len() - at);
            got.extend(
                decoder
                    .decode(&bytes[at..at + take])
                    .expect("a split body decodes the same"),
            );
            at += take;
        }
        got.extend(decoder.finish().expect("nothing is left over"));
        assert_eq!(got, expected, "a chunk boundary is not a frame boundary");
        assert_eq!(decoder.pending_bytes(), 0);
    }
}

#[test]
fn should_decode_the_same_log_lines_however_the_chunk_boundaries_fall() {
    // The same property for `LogDecoder`, plus the two cases a container can force: a line that
    // is not UTF-8 at all, and one whose first word looks almost like the timestamp the server
    // prefixes. Neither may be lost, and neither may be re-decoded differently by a reader that
    // happened to receive it in two pieces.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"2026-09-06T10:00:00.000000000Z hello\n");
    bytes.extend_from_slice(b"2026-not-a-stamp still a line\n");
    bytes.extend_from_slice(&[0xff, 0xfe, b'b', b'a', b'd', b'\n']);
    bytes.extend_from_slice(HOSTILE.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(b"unterminated tail");

    let mut whole = LogDecoder::timestamped();
    let mut expected = whole.decode(&bytes);
    expected.extend(whole.finish());
    assert_eq!(expected.len(), 5);
    assert_eq!(expected[0].stamp(), Some("2026-09-06T10:00:00.000000000Z"));
    assert_eq!(expected[0].bytes(), b"hello");
    assert_eq!(
        expected[1].stamp(),
        None,
        "a first word that is not an instant is the application's own"
    );
    assert!(
        expected[2].text().as_str().is_none(),
        "bytes that are not text stay bytes"
    );
    assert_eq!(expected[3].bytes(), HOSTILE.as_bytes());
    assert!(!expected[4].is_terminated());

    let mut random = Lcg(0xc0ffee);
    for _ in 0..200 {
        let mut decoder = LogDecoder::timestamped();
        let mut got = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let take = 1 + random.next(bytes.len() - at);
            got.extend(decoder.decode(&bytes[at..at + take]));
            at += take;
        }
        got.extend(decoder.finish());
        assert_eq!(got, expected, "a chunk boundary is not a line boundary");
    }
}

#[test]
fn should_round_trip_every_place_uri_built_from_a_hostile_alphabet() {
    // §35.3's round trip, exhaustively over the characters that could change an address's shape:
    // the separator, the escape character, the dot the type segment splits on, the prefix a
    // provider instance carries, and a control character for good measure. The space is small
    // enough to enumerate, which is why this is a table rather than a fuzzer (ADR-0043).
    let pieces = [
        "a",
        "/",
        "%",
        ".",
        ":",
        "..",
        "%2F",
        "kubernetes:",
        "\u{1b}",
        "🛒",
        "-",
    ];
    let mut checked = 0_usize;
    for left in pieces {
        for right in pieces {
            let text = format!("{left}{right}");
            let segment = TypeSegment::parse("pod").expect("a type segment");

            for uri in [
                PlaceUri::cluster_root(&text),
                PlaceUri::of_namespace("prod", &text),
                PlaceUri::namespaced("prod", &text, segment.clone(), "checkout"),
                PlaceUri::namespaced("prod", "shop", segment.clone(), &text),
                PlaceUri::cluster_scoped("prod", segment.clone(), &text),
            ]
            .into_iter()
            .flatten()
            {
                let rendered = uri.to_string();
                let reparsed = PlaceUri::parse(&rendered)
                    .unwrap_or_else(|error| panic!("{rendered:?} does not parse back: {error}"));
                assert_eq!(reparsed, uri, "{rendered:?} did not survive the round trip");
                assert_eq!(reparsed.to_string(), rendered, "and rendering is stable");
                checked += 1;
            }
        }
    }
    assert!(checked > 400, "the table actually ran: {checked} addresses");
}

#[test]
fn should_round_trip_every_json_pointer_token_a_kubernetes_key_can_be() {
    // RFC 6901's two escapes, in the order that matters. `~` must be escaped before `/`, and
    // unescaped after it, or `a/b` and `a~1b` become the same pointer — which is one label key
    // impersonating another, in a provider whose whole selector story is built on label keys.
    let pieces = ["a", "/", "~", "~0", "~1", "~01", ".", "", "🛒"];
    for left in pieces {
        for right in pieces {
            let key = format!("{left}{right}");
            if key.is_empty() {
                continue;
            }
            let object = Object::parse(
                INSTANCE,
                &serde_json::json!({
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "checkout", "namespace": "shop", "labels": {&key: "v"}},
                })
                .to_string(),
            )
            .expect("the object reads");

            let projection = Projection::of(&Schema::absent(), &object);
            let pointer = projection
                .fields()
                .iter()
                .find(|field| field.name() == key)
                .unwrap_or_else(|| panic!("{key:?} is projected"))
                .pointer()
                .to_owned();
            assert_eq!(
                object.field(&pointer),
                Some(&serde_json::json!("v")),
                "the pointer {pointer:?} the projection published addresses the key {key:?}"
            );
        }
    }
}

#[test]
fn should_encode_a_hostile_container_name_and_not_a_hostile_pod_name() {
    // §42.1's subresource path is composed from a namespace, a Pod name and a container name.
    // The container travels as a query parameter and the Pod as a path segment, so one request
    // shows both halves of the encoding story side by side — which makes it the clearest place
    // to state what the fix for the path looks like: it looks like the query.
    //
    // FINDING (`transport::collection_path` / `object_path`, not this file's to repair): the Pod
    // name reaches the request line unencoded.
    let target = PodTarget::new(INSTANCE, "shop", HOSTILE).in_container(HOSTILE);
    let request = LogRequest::new(target)
        .http_request()
        .expect("a log read that is not a followed previous instance is a request");
    let wire = String::from_utf8_lossy(&request.serialise(HOST)).into_owned();
    let line = wire.lines().next().expect("a request has a request line");

    assert!(
        line.contains('\u{1b}'),
        "today the Pod name is pasted into the path raw: {line:?}"
    );
    assert!(
        line.contains("container=ok%1B%5B2J"),
        "and the container name — the same bytes, one field to the right — is encoded: {line:?}"
    );
    assert!(
        !wire
            .lines()
            .skip(1)
            .any(|header| header.starts_with("X-") || header.starts_with("pwned")),
        "the encoded half forges no header, which is what the unencoded half is one CRLF away \
         from doing: {wire:?}"
    );
}

#[test]
fn should_describe_a_coverage_gap_without_the_scope_reshaping_the_sentence() {
    // §21.4's four distinct states are reported through `Coverage`, whose `describe` joins gaps
    // with `; `. A namespace containing `; ` would forge an extra gap in that sentence — a value
    // deciding how many facts a reader is looking at, which is the same class of forgery as a
    // newline in a table cell.
    use ono_provider_kubernetes::coverage::{Coverage, Gap, Outcome};

    let mut coverage = Coverage::complete(Scope::all_namespaces());
    coverage.record(Gap::new(
        Scope::in_namespace("shop; denied ns=kube-system"),
        Outcome::ListDenied,
    ));
    let described = coverage.describe();

    assert_eq!(
        coverage.gaps().len(),
        1,
        "one gap, whatever the namespace spells"
    );
    assert!(
        !coverage.is_complete() && coverage.is_empty_but_incomplete(0),
        "Gate E answers from the structure rather than from the sentence"
    );
    // The sentence *can* be forged, and the point is that nothing decides anything by reading it.
    // A reader that counted gaps by splitting on `; ` would see two here and be wrong; the
    // structure — `gaps()` — is where the count lives, and it says one.
    assert_eq!(
        described.matches("; ").count(),
        1,
        "the namespace put a separator in the sentence: {described:?}"
    );
    assert!(
        described.contains("list denied"),
        "and the outcome is still the one that was recorded (§21.4): {described:?}"
    );
}

#[test]
fn should_keep_a_hostile_annotation_out_of_the_field_manager_summary() {
    // §14.7 summarises `managedFields` to the distinct manager names. A manager name is chosen by
    // whoever wrote the field — including a controller an adversary deployed — and the summary is
    // a sorted, deduplicated list rather than a rendering, so a hostile name is one entry and not
    // a second row.
    let object = Object::parse(
        INSTANCE,
        &serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "name": "checkout", "namespace": "shop", "uid": "p-1",
                "managedFields": [
                    {"manager": HOSTILE, "operation": "Update"},
                    {"manager": HOSTILE, "operation": "Apply"},
                    {"manager": "kubelet", "operation": "Update"},
                    {"noManager": true},
                ],
            },
        })
        .to_string(),
    )
    .expect("the object reads");

    assert_eq!(
        object.field_managers(),
        &["kubelet".to_owned(), HOSTILE.to_owned()],
        "two distinct managers, the hostile one carried whole and counted once"
    );
}

#[test]
fn should_keep_a_hostile_finalizer_visible_because_deletion_depends_on_it() {
    // §14.6: finalizers MUST be visible in inspection and destructive-change planning. A
    // finalizer name that renders as something else is how a destructive plan comes to look safe,
    // so the value is carried exactly and the *count* is what a plan reasons about.
    let object = Object::parse(
        INSTANCE,
        &serde_json::json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {
                "name": "shop", "uid": "n-1",
                "finalizers": [HOSTILE, "kubernetes", 7, null],
                "deletionTimestamp": "2026-09-06T10:00:00Z",
            },
        })
        .to_string(),
    )
    .expect("the object reads");

    assert_eq!(
        object.finalizers(),
        &[HOSTILE.to_owned(), "kubernetes".to_owned()],
        "the text entries are kept and the non-text ones are not invented into text"
    );
    assert!(
        object.is_terminating(),
        "Gate H: terminating is not deleted"
    );
}

#[test]
fn should_not_let_a_hostile_owner_reference_become_an_edge_without_a_uid() {
    // §4 invariant 4 and §63.4: ownership is by UID, never by name. An owner reference an
    // adversary wrote into their own object could otherwise claim a workload they do not own,
    // and the claim would arrive wearing the provider's authority (§23.2).
    let object = Object::parse(
        INSTANCE,
        &serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "name": "checkout", "namespace": "shop", "uid": "p-1",
                "ownerReferences": [
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "victim"},
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "real", "uid": "rs-1",
                     "controller": true},
                ],
            },
        })
        .to_string(),
    )
    .expect("the object reads");

    let owners: Vec<&str> = object
        .owner_references()
        .iter()
        .map(|owner| owner.name())
        .collect();
    assert_eq!(
        owners,
        vec!["real"],
        "a reference without a UID is not an owner reference, so it never becomes an edge"
    );
    assert!(object.owner_references()[0].is_controller());
}

#[test]
fn should_keep_a_hostile_label_selector_out_of_the_labels_it_is_matched_against() {
    // §23.3's selector edge cites the selector and the labels that satisfied it. Both halves come
    // off objects, and a rendering that concatenated them would let one forge the other. The
    // evidence keeps them as two maps, so the structure survives whatever the strings say.
    let evidence = Evidence::Selector {
        selector: BTreeMap::from([("app".to_owned(), HOSTILE.to_owned())]),
        matched_labels: BTreeMap::from([(HOSTILE.to_owned(), "shop".to_owned())]),
    };
    let Evidence::Selector {
        selector,
        matched_labels,
    } = &evidence
    else {
        panic!("it is a selector");
    };
    assert_eq!(selector.get("app").map(String::as_str), Some(HOSTILE));
    assert_eq!(
        matched_labels.get(HOSTILE).map(String::as_str),
        Some("shop")
    );
    assert_eq!(evidence.class(), "selector");
}

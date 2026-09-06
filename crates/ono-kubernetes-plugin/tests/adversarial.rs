//! The package, driven end to end against an API server that is hostile rather than merely broken.
//!
//! `tests/adversarial.rs` in `ono-provider-kubernetes` attacks the domain layer directly. This
//! file asks the same questions of the whole package — the real binary, over the host's brokered
//! connection, under the deterministic test host — because the boundary is where a rule that is
//! true inside a module stops being true:
//!
//! ```text
//! disclosure  a Secret's payload, sought in every emitted event rather than in one field
//! injection   a name, a label and an annotation full of terminal escapes, carried as data
//! identity    an item that claims to be a kind other than the one its collection serves
//! liveness    a server that lies about its own framing, and an invocation that must still end
//! scope       a namespace argument shaped like a path, and where it arrives
//! ```
//!
//! **The recorded server writes down every request head it received**, which is the only place a
//! path this package composed can be observed rather than inferred. Everything a test asserts
//! about disclosure is asserted against the *whole* event stream — `{:?}` over every value the
//! invocation emitted — rather than against a field somebody remembered to check, because a leak
//! that arrives through a field nobody named is exactly the leak this file is for.
//!
//! Findings that belong to a module this worker may not repair are marked `// FINDING:` at the
//! assertion that documents them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::sync::{Arc, Mutex};

use ono_kuang_sdk::protocol::{Capability, InvokeStatus};
use ono_kuang_supervisor::{Connection, HostError, HostServices, LiveStream, StreamEvent};
use ono_kuang_testhost::TestHost;
use ono_kubernetes_plugin::broker::encode_hex;
use ono_value::{RecordValue, Value};
use serde_json::{Map as JsonMap, Value as Json, json};
use tokio::sync::mpsc;

const PLUGIN: &str = env!("CARGO_BIN_EXE_ono-kubernetes");
const MANIFEST: &str = include_str!("../../../package/manifest.yaml");

/// Everything an adversary reaches for when a value is about to be printed: clear the screen,
/// retitle the window, rewrite the line, delete backwards, reverse the reading order, and end.
const HOSTILE: &str = "ok\u{1b}[2J\u{1b}]0;pwned\u{7}\r\u{8}\u{202e}evil";

/// The base64 an API server sends for a Secret's `password`, and what it decodes to. Neither form
/// may appear in anything this package emits (§22.2, Gate I).
const CIPHERTEXT: &str = "c3VwZXItc2VjcmV0";
const PLAINTEXT: &str = "super-secret";

/// How a recorded cluster answers the collection a test is about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Answers {
    /// Ordinary documents: one Pod and one Secret, both with hostile metadata.
    Honestly,
    /// The `secrets` collection returns items that each claim to be a `ConfigMap`.
    WithItemsThatClaimAnotherKind,
    /// The Pod list arrives with a `Transfer-Encoding: chunked` body whose chunk size is not a
    /// number — a server lying about its own framing.
    WithBrokenFraming,
    /// Every page of the Pod list carries the same `continue` token, so the sequence never ends.
    WithAContinueTokenThatNeverAdvances,
}

/// One recorded API server, and the request heads it received.
#[derive(Debug)]
struct Cluster {
    answers: Answers,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Cluster {
    fn new(answers: Answers) -> Arc<Self> {
        Arc::new(Self {
            answers,
            heads: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Every request line this server received — `GET /api/v1/... HTTP/1.1`.
    fn request_lines(&self) -> Vec<String> {
        self.heads
            .lock()
            .map(|heads| {
                heads
                    .iter()
                    .filter_map(|head| head.lines().next().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn ok(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn not_found(path: &str) -> Vec<u8> {
        let body = json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": format!("no such path: {path}"), "reason": "NotFound", "code": 404,
        })
        .to_string();
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// A Pod whose every human-readable field was chosen by whoever created it.
    fn hostile_pod() -> Json {
        json!({
            "metadata": {
                "name": HOSTILE,
                "namespace": "shop",
                "uid": "aaaaaaaa-1111-1111-1111-111111111111",
                "resourceVersion": "9000",
                "creationTimestamp": "2026-09-01T09:00:00Z",
                "labels": {"app.kubernetes.io/name": HOSTILE},
                "annotations": {"acme.example.com/note": HOSTILE},
            },
            "spec": {"containers": [{"name": "app", "image": HOSTILE}], "nodeName": HOSTILE},
            "status": {
                "phase": "Running",
                "conditions": [{
                    "type": "Ready", "status": "False",
                    "reason": HOSTILE, "message": HOSTILE,
                }],
            },
        })
    }

    fn secret_items(&self) -> Vec<Json> {
        let kind = match self.answers {
            Answers::WithItemsThatClaimAnotherKind => Some("ConfigMap"),
            Answers::Honestly
            | Answers::WithBrokenFraming
            | Answers::WithAContinueTokenThatNeverAdvances => None,
        };
        let mut item = json!({
            "metadata": {
                "name": HOSTILE,
                "namespace": "shop",
                "uid": "bbbbbbbb-2222-2222-2222-222222222222",
                "resourceVersion": "9001",
                "creationTimestamp": "2026-09-01T09:00:00Z",
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration":
                        format!(r#"{{"data":{{"password":"{CIPHERTEXT}"}}}}"#),
                },
            },
            "type": "Opaque",
            "data": {"password": CIPHERTEXT},
            "stringData": {"token": PLAINTEXT},
        });
        if let (Some(kind), Some(object)) = (kind, item.as_object_mut()) {
            object.insert("apiVersion".to_owned(), json!("v1"));
            object.insert("kind".to_owned(), json!(kind));
        }
        vec![item]
    }

    fn document(&self, method: &str, path: &str) -> Vec<u8> {
        let bare = path.split('?').next().unwrap_or(path);
        let body = match (method, bare) {
            ("GET", "/version") => json!({
                "major": "1", "minor": "34", "gitVersion": "v1.34.2+k0s",
            }),
            ("GET", "/api") => json!({"kind": "APIVersions", "versions": ["v1"]}),
            ("GET", "/apis") => json!({"kind": "APIGroupList", "groups": []}),
            ("GET", "/api/v1") => json!({
                "kind": "APIResourceList",
                "groupVersion": "v1",
                "resources": [
                    {"name": "namespaces", "kind": "Namespace", "namespaced": false,
                     "verbs": ["get", "list", "watch"]},
                    {"name": "pods", "kind": "Pod", "namespaced": true,
                     "verbs": ["get", "list", "watch"]},
                    {"name": "secrets", "kind": "Secret", "namespaced": true,
                     "verbs": ["get", "list", "watch"]},
                ],
            }),
            ("GET", "/api/v1/namespaces/kube-system") => json!({
                "kind": "Namespace", "apiVersion": "v1",
                "metadata": {
                    "name": "kube-system",
                    "uid": "cccccccc-3333-3333-3333-333333333333",
                    "creationTimestamp": "2026-01-01T00:00:00Z",
                },
                "status": {"phase": "Active"},
            }),
            ("GET", "/api/v1/namespaces/shop/pods") => {
                if self.answers == Answers::WithBrokenFraming {
                    // A server lying about its own framing: the head promises chunked transfer
                    // and the first chunk size is not a hexadecimal number. §48 has a word for
                    // this and it is not "hang".
                    return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Transfer-Encoding: chunked\r\n\r\nnot-a-size\r\n{}\r\n0\r\n\r\n"
                        .to_vec();
                }
                let mut metadata = json!({"resourceVersion": "9000"});
                if self.answers == Answers::WithAContinueTokenThatNeverAdvances
                    && let Some(map) = metadata.as_object_mut()
                {
                    map.insert("continue".to_owned(), json!("never-advances"));
                    map.insert("remainingItemCount".to_owned(), json!(9_000_000));
                }
                json!({
                    "kind": "PodList", "apiVersion": "v1",
                    "metadata": metadata,
                    "items": [Self::hostile_pod()],
                })
            }
            ("GET", "/api/v1/namespaces/shop/secrets") => json!({
                "kind": "SecretList", "apiVersion": "v1",
                "metadata": {"resourceVersion": "9001"},
                "items": self.secret_items(),
            }),
            _ => return Self::not_found(bare),
        };
        Self::ok(&body.to_string())
    }
}

/// Splits whatever has arrived into whole requests, honouring `Content-Length`.
fn requests(buffered: &mut Vec<u8>) -> Vec<(String, String, String)> {
    let mut taken = Vec::new();
    while let Some(at) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
        let head = String::from_utf8_lossy(&buffered[..at]).into_owned();
        let length: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .unwrap_or(0);
        if buffered.len() < at + 4 + length {
            break;
        }
        buffered.drain(..at + 4 + length);
        let mut words = head.split_whitespace();
        let method = words.next().unwrap_or("GET").to_owned();
        let path = words.next().unwrap_or("/").to_owned();
        taken.push((method, path, head));
    }
    taken
}

#[async_trait::async_trait]
impl HostServices for Cluster {
    async fn network_connect(
        &self,
        _host: String,
        _port: u16,
        _protocol: String,
    ) -> Result<Connection, HostError> {
        let (inbound, incoming) = mpsc::channel(64);
        let (outgoing, mut written) = mpsc::channel::<Vec<u8>>(64);
        let answers = self.answers;
        let heads = Arc::clone(&self.heads);
        tokio::spawn(async move {
            let cluster = Cluster {
                answers,
                heads: Arc::clone(&heads),
            };
            let mut buffered: Vec<u8> = Vec::new();
            while let Some(bytes) = written.recv().await {
                buffered.extend(bytes);
                let mut replies: Vec<Vec<u8>> = Vec::new();
                for (method, path, head) in requests(&mut buffered) {
                    if let Ok(mut recorded) = heads.lock() {
                        recorded.push(head);
                    }
                    replies.push(cluster.document(&method, &path));
                }
                if replies.is_empty() {
                    continue;
                }
                let chunk = json!({"bytes": {"$bytes": encode_hex(&replies.concat())}});
                if inbound.send(Ok(chunk)).await.is_err() {
                    return;
                }
            }
        });
        Ok(Connection { incoming, outgoing })
    }

    async fn object_get(&self, _id: Json) -> Result<Json, HostError> {
        Err(HostError::unavailable("objects"))
    }
    async fn object_query(&self, _query: Json) -> Result<LiveStream, HostError> {
        Err(HostError::unavailable("objects"))
    }
    async fn object_resolve(
        &self,
        _target: String,
        _selector: Json,
    ) -> Result<Vec<Json>, HostError> {
        Err(HostError::unavailable("objects"))
    }
    async fn object_snapshot(&self, _query: Json) -> Result<LiveStream, HostError> {
        Err(HostError::unavailable("objects"))
    }
    async fn object_subscribe(
        &self,
        _query: Json,
        _overflow: Option<String>,
    ) -> Result<LiveStream, HostError> {
        Err(HostError::unavailable("objects"))
    }
    async fn object_watch(&self, _query: Json, _policy: Json) -> Result<LiveStream, HostError> {
        Err(HostError::unavailable("objects"))
    }
    async fn relations_query(
        &self,
        _from: Option<Json>,
        _to: Option<Json>,
        _relations: Option<Vec<String>>,
        _depth: Option<u64>,
    ) -> Result<LiveStream, HostError> {
        Err(HostError::unavailable("relations"))
    }
    async fn relations_contribute(
        &self,
        _package: &str,
        _edges: Vec<Json>,
    ) -> Result<u64, HostError> {
        Err(HostError::unavailable("relations"))
    }
    async fn history_query(
        &self,
        _window: Option<String>,
        _filter: Option<Json>,
    ) -> Result<LiveStream, HostError> {
        Err(HostError::unavailable("history"))
    }
    async fn history_append(&self, _package: &str, _entry: Json) -> Result<(), HostError> {
        Err(HostError::unavailable("history"))
    }
    async fn process_signal(&self, _object: Json, _signal: String) -> Result<Json, HostError> {
        Err(HostError::unavailable("process control"))
    }
    async fn process_exec(
        &self,
        _package: &str,
        _program: String,
        _arguments: Vec<String>,
        _environment: Vec<(String, String)>,
    ) -> Result<LiveStream, HostError> {
        Err(HostError::unavailable("program execution"))
    }
    async fn network_listen(
        &self,
        _port: u16,
        _protocol: String,
    ) -> Result<mpsc::Receiver<(String, Connection)>, HostError> {
        Err(HostError::unavailable("network"))
    }
    async fn secret_request(
        &self,
        _package: &str,
        _name: &str,
        _purpose: &str,
    ) -> Result<(), HostError> {
        Err(HostError::unavailable("secret store"))
    }
}

fn options(pairs: &[(&str, Json)]) -> JsonMap<String, Json> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn at(namespace: &str) -> JsonMap<String, Json> {
    options(&[
        ("host", json!("prod.test")),
        ("port", json!(8001)),
        ("context", json!("prod")),
        ("namespace", json!(namespace)),
    ])
}

/// The whole answer of one query: every event, and the records among them.
struct Answer {
    events: Vec<StreamEvent>,
    status: InvokeStatus,
    /// How it ended, where it ended badly — the sentence an operator reads.
    error: String,
}

impl Answer {
    fn records(&self) -> Vec<Arc<RecordValue>> {
        self.events
            .iter()
            .filter_map(|event| match event {
                StreamEvent::Value(Value::Record(record)) => Some(Arc::clone(record)),
                _ => None,
            })
            .collect()
    }

    /// Every byte of every event, as one string. What a leak test is asserted against, because a
    /// leak that arrives through a field nobody named is the leak worth looking for.
    fn everything(&self) -> String {
        format!("{:?} {}", self.events, self.error)
    }
}

async fn ask(cluster: &Arc<Cluster>, target: &str, options: JsonMap<String, Json>) -> Answer {
    let plugin = TestHost::new(PLUGIN, MANIFEST)
        .host(Arc::clone(cluster) as Arc<dyn HostServices>)
        .grant(Capability::NetworkConnect)
        .load()
        .await
        .expect("the package loads under its own manifest");
    let invocation = plugin
        .query(target, options)
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    Answer {
        events,
        status: result.status,
        error: format!("{:?}", result.error),
    }
}

fn text_of(record: &RecordValue, field: &str) -> Option<String> {
    match record.get(field) {
        Some(Value::String(text)) => Some(text.to_string()),
        Some(Value::Null) | None => None,
        other => panic!("`{field}` is text or null, and it is {other:?}"),
    }
}

// --- disclosure (§22, Gate I) -------------------------------------------------------------------

#[tokio::test]
async fn should_answer_a_secret_query_with_no_payload_anywhere_in_the_stream() {
    // Gate I (§62.9): "Default list/detail/navigation paths cannot reveal Secret payload values."
    // Asserted against every emitted event rather than against the fields the schema names,
    // because §22.2's "or equivalent secret payload" is precisely the class of route that a
    // per-field check misses — the `last-applied-configuration` annotation below is one such
    // route, and it embeds the whole submitted object one field to the left of `data`.
    let cluster = Cluster::new(Answers::Honestly);
    let answer = ask(&cluster, "k8s-secret", at("shop")).await;

    assert_eq!(answer.status, InvokeStatus::Completed);
    let everything = answer.everything();
    assert!(
        !everything.contains(CIPHERTEXT),
        "the encoded payload reached the stream"
    );
    assert!(
        !everything.contains(PLAINTEXT),
        "the decoded payload reached the stream"
    );

    // And what §22.2 *does* keep is there, so this is redaction rather than refusal.
    let records = answer.records();
    assert_eq!(records.len(), 1, "one Secret, one record");
    records[0]
        .validate()
        .expect("the record conforms to the schema it carries");
    assert_eq!(
        text_of(&records[0], "secret_type").as_deref(),
        Some("Opaque"),
        "§22.2 keeps the type"
    );
    let keys = format!("{:?}", records[0].get("keys"));
    assert!(
        keys.contains("password") && keys.contains("token"),
        "§22.2 keeps which keys are present, from `data` and `stringData` both: {keys}"
    );
}

#[tokio::test]
async fn should_refuse_a_secret_collection_whose_items_claim_another_kind() {
    // Gate I, at the one place it was defeated. §22's protection is keyed on the object's kind,
    // and the kind is a field the payload's author writes — so a `GET .../secrets` whose items
    // each carry `"kind":"ConfigMap"`, which is what a hostile aggregated API server sends and
    // what §34.2 requires this provider to survive, used to reach a user as a completed listing
    // with the plaintext in the record.
    //
    // The collection decides now. This test asserts the *outcome a user sees*, not the mechanism:
    // whatever else changes, a default listing of Secrets may not complete carrying a payload.
    let cluster = Cluster::new(Answers::WithItemsThatClaimAnotherKind);
    let answer = ask(&cluster, "k8s-secret", at("shop")).await;

    let everything = answer.everything();
    assert!(
        !everything.contains(CIPHERTEXT),
        "no route out of a `secrets` collection may carry the payload: {everything}"
    );
    assert_ne!(
        answer.status,
        InvokeStatus::Completed,
        "and a server contradicting itself about the page is not a page that answered: \
         {everything}"
    );
}

// --- injection (§14.5, and where the render boundary is) ----------------------------------------

#[tokio::test]
async fn should_carry_a_hostile_pod_name_across_the_boundary_as_data_and_not_as_shape() {
    // Core sanitises what it renders — `ono_render::sanitise` neutralises every control
    // character, and `Reporter::error` runs a message, its details and its help through it — so
    // this package's obligation is to hand over the value *whole* and let the host decide what a
    // terminal may do with it. §14.5 requires labels and annotations to be preserved as observed.
    //
    // Two failures this pins. A package that stripped bytes would silently corrupt a legitimate
    // name and break the identity every later assertion rests on. A package that let the value
    // choose the *shape* of the answer — an extra record, a different schema, a field name taken
    // from the data — would put the forgery below the render boundary, where sanitising cannot
    // reach it.
    let cluster = Cluster::new(Answers::Honestly);
    let answer = ask(&cluster, "k8s-pod", at("shop")).await;

    assert_eq!(answer.status, InvokeStatus::Completed);
    let records = answer.records();
    assert_eq!(
        records.len(),
        1,
        "one Pod, one record: the value did not forge a second row"
    );
    let record = &records[0];
    record
        .validate()
        .expect("the record conforms to the schema it carries");

    assert_eq!(
        text_of(record, "name").as_deref(),
        Some(HOSTILE),
        "every byte the cluster stated, including the ones a terminal would act on"
    );
    assert_eq!(
        record.schema_id().to_string(),
        "io.github.godspeed-you.kubernetes.pod/1",
        "the schema is the package's, never the data's"
    );

    let labels = format!("{:?}", record.get("labels"));
    assert!(
        labels.contains("pwned"),
        "the label value is carried whole (§14.5): {labels}"
    );

    // The place URI is composed by this package rather than rendered from a record, so it is the
    // one string here that a hostile name could have reshaped. It did not: `/ns/shop/pod/` is
    // still four segments, and the name is still one of them.
    let place = text_of(record, "place").or_else(|| text_of(record, "uri"));
    if let Some(place) = place {
        assert!(
            place.starts_with("k8s://prod/ns/shop/pod/"),
            "the address's shape is the grammar's, not the value's: {place:?}"
        );
        assert!(
            place.contains("pwned"),
            "and the name is carried inside it rather than stripped: {place:?}"
        );
    }
}

// --- liveness: nothing may hang (§48, core §30.3) -----------------------------------------------

#[tokio::test]
async fn should_end_an_invocation_whose_server_lies_about_its_own_framing() {
    // §48.2 has a word for every way a request can fail and none of them is "the shell did not
    // come back". A `Transfer-Encoding: chunked` body whose first chunk size is `not-a-size` is a
    // protocol fault: the read must end, the invocation must end, and the coverage must say the
    // collection was not read rather than that it was empty (§21.4, Gate E).
    let cluster = Cluster::new(Answers::WithBrokenFraming);
    let answer = ask(&cluster, "k8s-pod", at("shop")).await;

    assert!(
        matches!(
            answer.status,
            InvokeStatus::Completed | InvokeStatus::Failed
        ),
        "the invocation ended, which is the whole point: {:?}",
        answer.status
    );
    assert!(
        answer.records().is_empty() || answer.status != InvokeStatus::Completed,
        "a body that could not be read is not a collection of no Pods (§21.4)"
    );
    assert!(
        !cluster.request_lines().is_empty(),
        "the server was reached, so the failure is the framing rather than the connection"
    );
}

// --- scope: where a namespace argument arrives (§9.2, §17.1) ------------------------------------

#[tokio::test]
async fn should_not_let_a_namespace_argument_climb_the_rest_path() {
    // A namespace reaches this package as a query argument and leaves it as a path component.
    // Go's HTTP mux resolves `..` before the API server's authorizer sees the request, so a list
    // of Pods in namespace `../../../api/v1/secrets` is a request for the cluster's Secrets
    // carried by a Pod-shaped RBAC decision.
    //
    // The component is percent-encoded, so it stays one segment and the mux has nothing to
    // resolve. A namespace that is not a DNS label is still not refused here — the API server is
    // the authority on what its names are (§21.1) — but it can no longer be structure.
    let cluster = Cluster::new(Answers::Honestly);
    let answer = ask(&cluster, "k8s-pod", at("../../../api/v1/secrets")).await;

    let lines = cluster.request_lines();
    assert!(
        !lines.iter().any(|line| line.contains("/namespaces/../")),
        "no request climbs out of the collection it named: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("/namespaces/..%2F..%2F..%2Fapi%2Fv1%2Fsecrets/pods")),
        "the argument travels as one segment's worth of text: {lines:?}"
    );
    assert!(
        answer.records().is_empty(),
        "and there is no such namespace, so nothing was found"
    );
}

#[tokio::test]
async fn should_send_a_hostile_namespace_as_one_request_rather_than_as_two() {
    // The same missing encoding at its worst: CRLF in a path component ends the request line and
    // begins a header — or, on the keep-alive connection this package uses for a whole session, a
    // second request the operator never asked for.
    //
    // The assertion counts what the server *saw*, which is the only place this could be checked
    // honestly: a unit test of the encoder proves the encoder, and what matters is that nothing
    // between the argument and the socket puts the bytes back.
    let cluster = Cluster::new(Answers::Honestly);
    let smuggled = "shop\r\nX-Remote-User: cluster-admin";
    let _ = ask(&cluster, "k8s-pod", at(smuggled)).await;

    let heads = cluster
        .heads
        .lock()
        .map(|heads| heads.join("\n---\n"))
        .unwrap_or_default();
    assert!(
        !heads
            .lines()
            .any(|line| line.trim_start().starts_with("X-Remote-User")),
        "a namespace argument may not write a header: {heads}"
    );
    assert!(
        heads.contains("shop%0D%0AX-Remote-User"),
        "it arrives as text in the path instead, which is what it always was: {heads}"
    );
}

// --- what the recorded server was actually asked ------------------------------------------------

#[tokio::test]
async fn should_ask_only_about_the_namespace_the_query_named() {
    // §9.4: no silent all-namespace fan-out. The positive control for the two findings above —
    // an ordinary namespace produces exactly one collection path, and that path is the one the
    // query named. Without this, a fix that started encoding path components could quietly send
    // requests somewhere else and every assertion above would still pass.
    let cluster = Cluster::new(Answers::Honestly);
    let answer = ask(&cluster, "k8s-pod", at("shop")).await;
    assert_eq!(answer.status, InvokeStatus::Completed);

    let lines = cluster.request_lines();
    let collections: Vec<&String> = lines.iter().filter(|line| line.contains("/pods")).collect();
    assert!(
        !collections.is_empty(),
        "the collection was read: {lines:?}"
    );
    for line in &collections {
        assert!(
            line.contains("/api/v1/namespaces/shop/pods"),
            "every Pod request names the namespace the query did: {line}"
        );
    }
    assert!(
        !lines.iter().any(|line| line.contains("/api/v1/pods")),
        "and none of them is the all-namespace collection (§9.4): {lines:?}"
    );
}

#[tokio::test]
async fn should_end_an_invocation_whose_server_never_stops_paginating() {
    // §18.1 makes a `continue` token mean "there is more". It says nothing about a server that
    // sends the *same* token forever, and Kubernetes' own contract that tokens advance is a
    // promise a hostile or broken aggregated API server (§34.2) does not keep. A provider that
    // followed it would never come back, and §50.1 makes an unresponsive shell a defect.
    //
    // What stops it is `transport::walk` recognising the repetition: a page that answers with the
    // token that asked for it breaks continuity (§18.2), so the walk ends at the second page
    // rather than at the sixteenth that §49.5's query budget would otherwise allow. Core §12.3
    // asks a provider to "prevent duplicate emission where provider pagination semantics permit
    // stable deduplication", and this is that: the repeated page is refused instead of delivered
    // as a second copy of the first.
    let cluster = Cluster::new(Answers::WithAContinueTokenThatNeverAdvances);
    let answer = ask(&cluster, "k8s-pod", at("shop")).await;

    // It ends as a *failure* rather than as a short list, which is ADR-0004's rule: a value
    // stream cannot carry coverage, so a read that stopped short ends the invocation instead of
    // handing back a truncated collection that looks complete (§18.3, Gate E).
    assert_eq!(
        answer.status,
        InvokeStatus::Failed,
        "the invocation ended, which is the requirement (§50.1)"
    );
    let pages = cluster
        .request_lines()
        .iter()
        .filter(|line| line.contains("/pods"))
        .count();
    assert_eq!(
        pages, 2,
        "the repetition ended it on the second page, with no budget involved"
    );

    assert!(
        answer.error.contains("continuity"),
        "and it says why it stopped rather than simply stopping: {}",
        answer.error
    );
}

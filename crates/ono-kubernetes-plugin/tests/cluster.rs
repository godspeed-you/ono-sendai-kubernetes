//! `get k8s-cluster` under the deterministic test host: which cluster is this, can it be reached,
//! who am I to it, and what could not be determined.
//!
//! The real binary, over the host's brokered connection, against a recorded API server (§59.1).
//! Nothing here contacts a cluster, and the four things proved are the four §61.1's last
//! requirement rests on: a full identity when everything answers, a *partial* one when
//! `SelfSubjectReview` is refused with ordinary reads still working (§8.6), two clusters with
//! different fingerprints, and one cluster reached through two contexts reported as a possible
//! alias and never merged (§10.3).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::sync::Arc;

use ono_kuang_sdk::protocol::{Capability, InvokeStatus, ShutdownReason};
use ono_kuang_supervisor::{Connection, HostError, HostServices, LiveStream, StreamEvent};
use ono_kuang_testhost::TestHost;
use ono_kubernetes_plugin::broker::encode_hex;
use ono_value::{RecordValue, Value};
use serde_json::{Map as JsonMap, Value as Json, json};
use tokio::sync::mpsc;

const PLUGIN: &str = env!("CARGO_BIN_EXE_ono-kubernetes");
const MANIFEST: &str = include_str!("../../../package/manifest.yaml");

/// How the recorded API server answers `SelfSubjectReview`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Review {
    /// It answers with the identity of the request that created it.
    Answers,
    /// RBAC refuses the create. A cluster where this is the case is entirely ordinary.
    Forbids,
    /// The group is not served at all — a cluster before 1.27, or one with it disabled.
    Unserved,
}

fn options(pairs: &[(&str, Json)]) -> JsonMap<String, Json> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn records(events: &[StreamEvent]) -> Vec<Arc<RecordValue>> {
    events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::Value(Value::Record(record)) => Some(Arc::clone(record)),
            StreamEvent::Value(other) => {
                panic!("a provider answers records, and this is {other:?}")
            }
            StreamEvent::Failed(_) => None,
        })
        .collect()
}

fn text_of(record: &RecordValue, field: &str) -> Option<String> {
    match record.get(field) {
        Some(Value::String(text)) => Some(text.to_string()),
        Some(Value::Null) | None => None,
        other => panic!("`{field}` is text or null, and it is {other:?}"),
    }
}

fn list_of(record: &RecordValue, field: &str) -> Vec<String> {
    match record.get(field) {
        Some(Value::List(entries)) => entries
            .iter()
            .map(|entry| match entry {
                Value::String(text) => text.to_string(),
                other => panic!("a list entry is text, and it is {other:?}"),
            })
            .collect(),
        Some(Value::Null) | None => Vec::new(),
        other => panic!("`{field}` is a list or null, and it is {other:?}"),
    }
}

// --- the recorded cluster ----------------------------------------------------------------------

/// An API server that answers the diagnostic's questions from recorded documents.
#[derive(Clone, Debug)]
struct RecordedCluster {
    /// The UID of its `kube-system` namespace — §10.2's strongest identifying signal, and what
    /// makes two of these different clusters rather than one.
    kube_system_uid: &'static str,
    /// How it answers `SelfSubjectReview`.
    review: Review,
    /// Whether it may be reached at all.
    reachable: bool,
}

impl RecordedCluster {
    fn new(kube_system_uid: &'static str, review: Review) -> Arc<Self> {
        Arc::new(Self {
            kube_system_uid,
            review,
            reachable: true,
        })
    }

    fn unreachable() -> Arc<Self> {
        Arc::new(Self {
            kube_system_uid: "unreachable",
            review: Review::Unserved,
            reachable: false,
        })
    }
}

fn ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn created(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn status(code: u16, reason: &str, message: &str) -> Vec<u8> {
    let body = json!({
        "kind": "Status", "apiVersion": "v1", "status": "Failure",
        "message": message, "code": code,
    })
    .to_string();
    format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// One answer, chosen by method and path.
fn document(method: &str, path: &str, cluster: &RecordedCluster) -> Vec<u8> {
    let path = path.split('?').next().unwrap_or(path);
    let body = match (method, path) {
        ("GET", "/version") => json!({
            "major": "1", "minor": "34", "gitVersion": "v1.34.2+k0s",
            "platform": "linux/amd64",
        }),
        ("GET", "/api") => json!({"kind": "APIVersions", "versions": ["v1"]}),
        ("GET", "/apis") if cluster.review == Review::Unserved => {
            json!({"kind": "APIGroupList", "groups": []})
        }
        ("GET", "/apis") => json!({
            "kind": "APIGroupList",
            "groups": [{
                "name": "authentication.k8s.io",
                "versions": [{"groupVersion": "authentication.k8s.io/v1", "version": "v1"}],
                "preferredVersion": {
                    "groupVersion": "authentication.k8s.io/v1", "version": "v1",
                },
            }],
        }),
        ("GET", "/api/v1") => json!({
            "kind": "APIResourceList",
            "groupVersion": "v1",
            "resources": [
                {"name": "namespaces", "kind": "Namespace", "namespaced": false,
                 "verbs": ["get", "list", "watch"]},
                {"name": "pods", "kind": "Pod", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
            ],
        }),
        ("GET", "/apis/authentication.k8s.io/v1") => json!({
            "kind": "APIResourceList",
            "groupVersion": "authentication.k8s.io/v1",
            "resources": [
                {"name": "selfsubjectreviews", "kind": "SelfSubjectReview",
                 "namespaced": false, "verbs": ["create"]},
            ],
        }),
        ("GET", "/api/v1/namespaces/kube-system") => json!({
            "kind": "Namespace",
            "apiVersion": "v1",
            "metadata": {
                "name": "kube-system",
                "uid": cluster.kube_system_uid,
                "creationTimestamp": "2026-01-01T00:00:00Z",
            },
            "status": {"phase": "Active"},
        }),
        // An ordinary read, so that a refused `SelfSubjectReview` can be shown not to have
        // stopped one (§8.6).
        ("GET", "/api/v1/namespaces/default/pods") => json!({
            "kind": "PodList",
            "apiVersion": "v1",
            "metadata": {"resourceVersion": "9000"},
            "items": [{
                "metadata": {
                    "name": "api-1", "namespace": "default",
                    "uid": "aaaaaaaa-1111-1111-1111-111111111111",
                    "creationTimestamp": "2026-09-01T09:00:00Z",
                },
                "spec": {"containers": [{"name": "api"}]},
                "status": {"phase": "Running"},
            }],
        }),
        ("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews") => {
            if cluster.review == Review::Forbids {
                return status(
                    403,
                    "Forbidden",
                    "selfsubjectreviews.authentication.k8s.io is forbidden",
                );
            }
            return created(
                &json!({
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "SelfSubjectReview",
                    "status": {"userInfo": {
                        "username": "operator@example.com",
                        "uid": "u-4711",
                        "groups": ["system:authenticated", "readers"],
                    }},
                })
                .to_string(),
            );
        }
        _ => return status(404, "Not Found", &format!("no such path: {path}")),
    };
    ok(&body.to_string())
}

/// Splits whatever has arrived into whole requests, honouring `Content-Length` so that a `POST`
/// body is consumed rather than read as the head of the next request.
fn requests(buffered: &mut Vec<u8>) -> Vec<(String, String)> {
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
        taken.push((method, path));
    }
    taken
}

#[async_trait::async_trait]
impl HostServices for RecordedCluster {
    async fn network_connect(
        &self,
        _host: String,
        _port: u16,
        _protocol: String,
    ) -> Result<Connection, HostError> {
        if !self.reachable {
            return Err(HostError::unavailable(
                "the recorded cluster is not listening",
            ));
        }
        let (inbound, incoming) = mpsc::channel(64);
        let (outgoing, mut written) = mpsc::channel::<Vec<u8>>(64);
        let cluster = self.clone();
        tokio::spawn(async move {
            let mut buffered: Vec<u8> = Vec::new();
            while let Some(bytes) = written.recv().await {
                buffered.extend(bytes);
                let replies: Vec<Vec<u8>> = requests(&mut buffered)
                    .iter()
                    .map(|(method, path)| document(method, path, &cluster))
                    .collect();
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

/// A loaded package pointed at `cluster`.
async fn loaded(cluster: Arc<RecordedCluster>) -> ono_kuang_supervisor::LoadedPlugin {
    TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(cluster as Arc<dyn HostServices>)
        .load()
        .await
        .expect("the package loads under its own manifest")
}

/// The options that point a query at a recorded cluster under a named context.
fn at(host: &str, context: &str) -> JsonMap<String, Json> {
    options(&[
        ("host", json!(host)),
        ("port", json!(8001)),
        ("context", json!(context)),
    ])
}

/// Runs `get k8s-cluster` and returns the one record it answers.
async fn diagnostic(
    plugin: &ono_kuang_supervisor::LoadedPlugin,
    host: &str,
    context: &str,
) -> Arc<RecordValue> {
    let invocation = plugin
        .query("k8s-cluster", at(host, context))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "a diagnostic completes even when the cluster does not cooperate: {:?}",
        result.error
    );
    let records = records(&events);
    assert_eq!(records.len(), 1, "one provider instance, one record");
    records[0]
        .validate()
        .expect("the record conforms to the schema it carries");
    Arc::clone(&records[0])
}

// --- the tests -------------------------------------------------------------------------------

#[tokio::test]
async fn should_say_which_cluster_this_is_and_who_the_provider_is_to_it() {
    let plugin = loaded(RecordedCluster::new(
        "11111111-1111-1111-1111-111111111111",
        Review::Answers,
    ))
    .await;
    let record = diagnostic(&plugin, "prod.test", "prod").await;

    assert_eq!(
        text_of(&record, "uid").as_deref(),
        Some("kubernetes:prod"),
        "identity is the provider instance of §10.1, never the cluster (§10.3)"
    );
    assert_eq!(record.get("reachable"), Some(&Value::Bool(true)));
    assert_eq!(
        text_of(&record, "server_version").as_deref(),
        Some("v1.34.2+k0s"),
        "the version string the server wrote, uninterpreted (§5.3)"
    );
    assert_eq!(
        text_of(&record, "server").as_deref(),
        Some("http://prod.test:8001")
    );
    assert_eq!(
        text_of(&record, "kube_system_uid").as_deref(),
        Some("11111111-1111-1111-1111-111111111111")
    );
    assert_eq!(
        text_of(&record, "effective_identity").as_deref(),
        Some("operator@example.com"),
        "who the API server says the request is (§8.6)"
    );
    assert_eq!(text_of(&record, "effective_uid").as_deref(), Some("u-4711"));
    assert_eq!(
        list_of(&record, "effective_groups"),
        ["system:authenticated", "readers"]
    );
    assert_eq!(
        text_of(&record, "credential_identity").as_deref(),
        Some("operator@example.com"),
        "with nothing impersonated the two identities agree — and are still two fields (§8.5)"
    );
    assert_eq!(record.get("impersonating"), Some(&Value::Bool(false)));
    assert_eq!(record.get("impersonated_user"), Some(&Value::Null));

    assert_eq!(
        list_of(&record, "fingerprint_signals"),
        ["origin", "kube-system-uid"],
        "the fingerprint says which parts it has (§10.2)"
    );
    assert!(
        text_of(&record, "fingerprint").is_some(),
        "and composes them into one token"
    );

    // §34.3: per-request source and latency, so a slow endpoint is not reported as "the cluster".
    let Some(Value::Map(probes)) = record.get("probes") else {
        panic!("`probes` is a map");
    };
    assert!(
        probes.get("GET /version").is_some(),
        "every request is recorded by source: {probes:?}"
    );
    assert!(
        probes
            .get("POST /apis/authentication.k8s.io/v1/selfsubjectreviews")
            .is_some(),
        "the review included: {probes:?}"
    );
    let Some(Value::Map(latency)) = record.get("latency_ms") else {
        panic!("`latency_ms` is a map");
    };
    assert_eq!(latency.len(), probes.len(), "each with how long it took");

    // The one thing this build cannot obtain, said rather than omitted.
    let unknowns = list_of(&record, "unknowns");
    assert_eq!(
        unknowns,
        ["cluster fingerprint: server-public-key: not queried"],
        "what could not be determined, and nothing else: {unknowns:?}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_answer_a_partial_identity_when_the_cluster_refuses_a_self_subject_review() {
    // §8.6: failure to obtain the effective identity MUST NOT block ordinary read operations. So
    // the diagnostic still answers, the identity is null rather than invented, the *reason* is
    // stated in §21.4's vocabulary — and a pod listing on the same cluster still works.
    let cluster = RecordedCluster::new("22222222-2222-2222-2222-222222222222", Review::Forbids);
    let plugin = loaded(Arc::clone(&cluster)).await;
    let record = diagnostic(&plugin, "locked.test", "locked").await;

    assert_eq!(
        record.get("effective_identity"),
        Some(&Value::Null),
        "unknown is null, never a guessed username"
    );
    assert_eq!(record.get("effective_groups"), Some(&Value::Null));
    assert_eq!(record.get("credential_identity"), Some(&Value::Null));
    assert!(
        list_of(&record, "unknowns").contains(&"effective identity: read denied".to_owned()),
        "a refusal is a refusal, not an absence: {:?}",
        list_of(&record, "unknowns")
    );
    assert!(
        !list_of(&record, "unknowns").contains(&"effective identity: not served".to_owned()),
        "and it is distinguishable from a cluster that serves no review at all"
    );
    assert_eq!(
        record.get("reachable"),
        Some(&Value::Bool(true)),
        "a server that refuses is a server that is there"
    );
    assert_eq!(
        text_of(&record, "kube_system_uid").as_deref(),
        Some("22222222-2222-2222-2222-222222222222"),
        "and the signals it did allow are still obtained"
    );

    // The read that §8.6 says must not be blocked.
    let invocation = plugin
        .query("k8s-pod", at("locked.test", "locked"))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "a refused identity review does not stop an ordinary read: {:?}",
        result.error
    );
    assert_eq!(records(&events).len(), 1);
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_say_the_review_is_not_served_where_the_cluster_serves_no_such_group() {
    // Three states, not two: served and refused, served and answered, and never served at all.
    let plugin = loaded(RecordedCluster::new(
        "33333333-3333-3333-3333-333333333333",
        Review::Unserved,
    ))
    .await;
    let record = diagnostic(&plugin, "old.test", "old").await;

    assert_eq!(record.get("effective_identity"), Some(&Value::Null));
    assert!(
        list_of(&record, "unknowns").contains(&"effective identity: not served".to_owned()),
        "a cluster before 1.27 does not refuse the review; it has none: {:?}",
        list_of(&record, "unknowns")
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_give_two_different_clusters_two_different_fingerprints() {
    let production = loaded(RecordedCluster::new(
        "11111111-1111-1111-1111-111111111111",
        Review::Answers,
    ))
    .await;
    let staging = loaded(RecordedCluster::new(
        "99999999-9999-9999-9999-999999999999",
        Review::Answers,
    ))
    .await;

    let first = diagnostic(&production, "prod.test", "prod").await;
    let second = diagnostic(&staging, "staging.test", "staging").await;

    assert_ne!(
        text_of(&first, "fingerprint"),
        text_of(&second, "fingerprint"),
        "two clusters are two fingerprints — this is what makes context aliasing detectable"
    );
    assert_ne!(
        text_of(&first, "kube_system_uid"),
        text_of(&second, "kube_system_uid")
    );
    production.shutdown(ShutdownReason::Unload).await;
    staging.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_report_one_cluster_reached_through_two_contexts_without_merging_the_instances() {
    // §10.3: an alias may be reported; the instances MUST NOT be merged, because their
    // credentials and effective permissions differ. Two records, two identities, one fingerprint.
    let plugin = loaded(RecordedCluster::new(
        "11111111-1111-1111-1111-111111111111",
        Review::Answers,
    ))
    .await;

    let admin = diagnostic(&plugin, "prod.test", "prod-admin").await;
    let readonly = diagnostic(&plugin, "prod.test", "prod-readonly").await;

    assert_eq!(
        text_of(&admin, "fingerprint"),
        text_of(&readonly, "fingerprint"),
        "the same cluster fingerprints the same way, which is what makes the alias observable"
    );
    assert_eq!(
        text_of(&admin, "uid").as_deref(),
        Some("kubernetes:prod-admin")
    );
    assert_eq!(
        text_of(&readonly, "uid").as_deref(),
        Some("kubernetes:prod-readonly"),
        "and the two remain two provider instances, never one"
    );
    assert_ne!(
        text_of(&admin, "uid"),
        text_of(&readonly, "uid"),
        "identity is the instance, so nothing downstream can fold them together"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_answer_that_a_cluster_cannot_be_reached_rather_than_failing_the_query() {
    // The health half of the question. `get k8s-cluster` has to work precisely when the cluster
    // does not, so an unreachable API server is a record that says so.
    let plugin = loaded(RecordedCluster::unreachable()).await;
    let record = diagnostic(&plugin, "gone.test", "gone").await;

    assert_eq!(record.get("reachable"), Some(&Value::Bool(false)));
    assert_eq!(record.get("server_version"), Some(&Value::Null));
    assert_eq!(record.get("kube_system_uid"), Some(&Value::Null));
    assert_eq!(
        text_of(&record, "server").as_deref(),
        Some("http://gone.test:8001"),
        "the origin is configuration, so it survives a cluster that never answered (§10.2)"
    );
    let unknowns = list_of(&record, "unknowns");
    assert!(
        unknowns
            .iter()
            .any(|unknown| unknown.ends_with("disconnected")),
        "and everything the cluster would have said is `disconnected`: {unknowns:?}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

//! The canonical scenarios in which a watch, a cache, a relationship and its evidence have to
//! agree with one another, driven through the provider boundary (§60.3, §41.3, §23.6, §19.2).
//!
//! `tests/query.rs` proves the watch and the relationship derivation separately; `ADR-0058` made
//! them meet, and this file is where the meeting is checked. Every test here holds a
//! `k8s-change` invocation open in one thread of the test host while other invocations of the
//! same provider instance are answered beside it, which is the shape §60.3 describes and the
//! shape that was unreachable while a watch held its session for its whole life.
//!
//! Nothing here talks to a cluster (§59.1). The recorded server plays one script per test and
//! delivers its watch frames only when the test releases them, so "the watch observed the change"
//! is a fact about ordering rather than about timing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ono_kuang_sdk::protocol::{Capability, InvokeStatus, ShutdownReason};
use ono_kuang_supervisor::{
    Connection, HostError, HostLimits, HostServices, LiveStream, StreamEvent,
};
use ono_kuang_testhost::TestHost;
use ono_kubernetes_plugin::broker::encode_hex;
use ono_value::{RecordValue, Value};
use serde_json::{Map as JsonMap, Value as Json, json};
use tokio::sync::mpsc;

const PLUGIN: &str = env!("CARGO_BIN_EXE_ono-kubernetes");
const MANIFEST: &str = include_str!("../../../package/manifest.yaml");

/// How long a record is waited for before the test decides nothing is coming.
const SOON: Duration = Duration::from_secs(20);

const PODS: &str = "/api/v1/namespaces/default/pods";

fn options(pairs: &[(&str, Json)]) -> JsonMap<String, Json> {
    let mut map: JsonMap<String, Json> = [
        ("host".to_owned(), json!("cluster.test")),
        ("port".to_owned(), json!(8001)),
        ("context".to_owned(), json!("recorded")),
    ]
    .into_iter()
    .collect();
    for (key, value) in pairs {
        map.insert((*key).to_owned(), value.clone());
    }
    map
}

fn records(events: &[StreamEvent]) -> Vec<Arc<RecordValue>> {
    events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::Value(Value::Record(record)) => Some(Arc::clone(record)),
            StreamEvent::Value(other) => panic!("a provider answers records, and not {other:?}"),
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

fn map_entry(record: &RecordValue, field: &str, key: &str) -> Option<String> {
    match record.get(field) {
        Some(Value::Map(map)) => match map.get(key) {
            Some(Value::String(text)) => Some(text.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn origin_of(record: &RecordValue) -> String {
    record.provenance().source().unwrap_or_default().to_owned()
}

// --- the recorded server ------------------------------------------------------------------------

/// A Pod as the API server sends it, with the label a Service selects on.
fn pod(name: &str, uid: &str, resource_version: &str, app: &str) -> Json {
    json!({
        "metadata": {
            "name": name,
            "namespace": "default",
            "uid": uid,
            "resourceVersion": resource_version,
            "creationTimestamp": "2026-09-01T09:00:00Z",
            "labels": {"app": app},
        },
        "spec": {"nodeName": "node-a", "containers": [{"name": "app"}]},
        "status": {"phase": "Running", "podIP": "10.1.2.3"},
    })
}

fn pod_a() -> Json {
    pod("pair-a", "u-a", "4001", "pair")
}

/// Pod B, before and after its label changed under the watch (§60.3 step 2).
fn pod_b(relabelled: bool) -> Json {
    if relabelled {
        pod("pair-b", "u-b", "4010", "off")
    } else {
        pod("pair-b", "u-b", "4002", "pair")
    }
}

fn pod_c() -> Json {
    pod("other", "u-c", "4003", "other")
}

fn service() -> Json {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "pair", "namespace": "default", "resourceVersion": "5100",
            "uid": "svc-pair", "creationTimestamp": "2026-08-20T08:00:00Z",
        },
        "spec": {"selector": {"app": "pair"}, "ports": [{"port": 80}]},
    })
}

fn standalone(mut object: Json, api_version: &str, kind: &str) -> Json {
    if let Some(map) = object.as_object_mut() {
        map.insert("apiVersion".to_owned(), json!(api_version));
        map.insert("kind".to_owned(), json!(kind));
    }
    object
}

fn collection(kind: &str, api_version: &str, resource_version: &str, items: &[Json]) -> Json {
    json!({
        "kind": format!("{kind}List"),
        "apiVersion": api_version,
        "metadata": {"resourceVersion": resource_version},
        "items": items,
    })
}

fn group(name: &str, version: &str) -> Json {
    let group_version = format!("{name}/{version}");
    json!({
        "name": name,
        "versions": [{"groupVersion": group_version, "version": version}],
        "preferredVersion": {"groupVersion": group_version, "version": version},
    })
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
        "message": format!("the recorded cluster serves no {path}"),
        "reason": "NotFound", "code": 404,
    })
    .to_string();
    format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A chunked `200 OK` whose body has not ended and will not: the head of a watch.
fn held_open() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
        .to_vec()
}

fn chunk_of(frame: &str) -> String {
    format!("{:x}\r\n{frame}\r\n", frame.len())
}

fn frame(class: &str, object: &Json) -> String {
    format!(
        "{}\n",
        json!({"type": class, "object": standalone(object.clone(), "v1", "Pod")})
    )
}

/// An API server serving one namespace with a Service and the three Pods §60.3 needs.
#[derive(Clone)]
struct Cluster {
    /// Every request head the server received, so a test can count what travelled.
    heads: Arc<std::sync::Mutex<Vec<String>>>,
    /// The gate each watch frame waits at before it goes on the wire.
    release: Arc<tokio::sync::Notify>,
    /// Whether Pod B's label has changed — flipped when the frame that says so is released, so
    /// a direct read afterwards agrees with what the watch delivered.
    relabelled: Arc<AtomicBool>,
    /// How many watches have been opened.
    watches: Arc<AtomicUsize>,
}

impl std::fmt::Debug for Cluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cluster").finish()
    }
}

impl Cluster {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            heads: Arc::default(),
            release: Arc::default(),
            relabelled: Arc::default(),
            watches: Arc::default(),
        })
    }

    fn heads(&self) -> Vec<String> {
        self.heads
            .lock()
            .map(|heads| heads.clone())
            .unwrap_or_default()
    }

    /// How many times the server was asked for `path`, whatever the query string was.
    fn asked_for(&self, path: &str) -> usize {
        self.heads()
            .iter()
            .filter(|head| {
                head.split_whitespace()
                    .nth(1)
                    .is_some_and(|target| target.split('?').next() == Some(path))
            })
            .count()
    }

    /// Releases the next watch frame, and records what it says about the cluster.
    fn relabel_pod_b(&self) {
        self.relabelled.store(true, Ordering::SeqCst);
        self.release.notify_one();
    }

    fn document(&self, path: &str) -> Vec<u8> {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        if route == PODS && query.contains("watch=true") {
            self.watches.fetch_add(1, Ordering::SeqCst);
            return held_open();
        }
        let relabelled = self.relabelled.load(Ordering::SeqCst);
        if route == PODS {
            let all = [pod_a(), pod_b(relabelled), pod_c()];
            let items: Vec<Json> = match query
                .split('&')
                .find_map(|pair| pair.strip_prefix("labelSelector="))
            {
                None => all.to_vec(),
                Some("app%3Dpair") => all
                    .iter()
                    .filter(|item| item["metadata"]["labels"]["app"] == "pair")
                    .cloned()
                    .collect(),
                Some(_) => Vec::new(),
            };
            let version = if relabelled { "9200" } else { "9100" };
            return ok(&collection("Pod", "v1", version, &items).to_string());
        }
        let body = match route {
            "/api" => json!({"kind": "APIVersions", "versions": ["v1"]}),
            "/apis" => json!({
                "kind": "APIGroupList",
                "groups": [group("discovery.k8s.io", "v1"), group("networking.k8s.io", "v1")],
            }),
            "/api/v1" => json!({
                "kind": "APIResourceList",
                "groupVersion": "v1",
                "resources": [
                    {"name": "namespaces", "kind": "Namespace", "namespaced": false,
                     "verbs": ["get", "list", "watch"]},
                    {"name": "pods", "kind": "Pod", "namespaced": true,
                     "verbs": ["get", "list", "watch"]},
                    {"name": "services", "kind": "Service", "namespaced": true,
                     "verbs": ["get", "list", "watch"]},
                ],
            }),
            "/apis/discovery.k8s.io/v1" => json!({
                "kind": "APIResourceList",
                "groupVersion": "discovery.k8s.io/v1",
                "resources": [{"name": "endpointslices", "kind": "EndpointSlice",
                               "namespaced": true, "verbs": ["get", "list", "watch"]}],
            }),
            "/apis/networking.k8s.io/v1" => json!({
                "kind": "APIResourceList",
                "groupVersion": "networking.k8s.io/v1",
                "resources": [
                    {"name": "ingresses", "kind": "Ingress", "namespaced": true,
                     "verbs": ["get", "list", "watch"]},
                    {"name": "networkpolicies", "kind": "NetworkPolicy", "namespaced": true,
                     "verbs": ["get", "list", "watch"]},
                ],
            }),
            "/api/v1/namespaces/default/services/pair" => service(),
            "/api/v1/namespaces/default/services" => {
                collection("Service", "v1", "5100", &[service()])
            }
            "/api/v1/namespaces/default/pods/pair-a" => standalone(pod_a(), "v1", "Pod"),
            "/api/v1/namespaces/default/pods/pair-b" => standalone(pod_b(relabelled), "v1", "Pod"),
            "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices" => {
                collection("EndpointSlice", "discovery.k8s.io/v1", "5200", &[])
            }
            "/apis/networking.k8s.io/v1/namespaces/default/ingresses" => {
                collection("Ingress", "networking.k8s.io/v1", "5300", &[])
            }
            "/apis/networking.k8s.io/v1/namespaces/default/networkpolicies" => {
                collection("NetworkPolicy", "networking.k8s.io/v1", "5400", &[])
            }
            _ => return not_found(route),
        };
        ok(&body.to_string())
    }
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
        let cluster = self.clone();
        tokio::spawn(async move {
            let mut buffered: Vec<u8> = Vec::new();
            while let Some(bytes) = written.recv().await {
                buffered.extend(bytes);
                let mut replies: Vec<Vec<u8>> = Vec::new();
                while let Some(at) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buffered[..at]).into_owned();
                    buffered.drain(..at + 4);
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    if let Ok(mut heads) = cluster.heads.lock() {
                        heads.push(head.clone());
                    }
                    replies.push(cluster.document(&path));
                    // A watch answers with its head here and with its frames later, each one
                    // when the test releases it: the second listing of Pod B's state does not
                    // exist on the wire until the test has decided it should.
                    if path.starts_with(PODS) && path.contains("watch=true") {
                        let sender = inbound.clone();
                        let gate = Arc::clone(&cluster.release);
                        tokio::spawn(async move {
                            gate.notified().await;
                            let bytes = chunk_of(&frame("MODIFIED", &pod_b(true))).into_bytes();
                            let chunk = json!({"bytes": {"$bytes": encode_hex(&bytes)}});
                            let _ = sender.send(Ok(chunk)).await;
                        });
                    }
                }
                let outbound = replies.concat();
                if outbound.is_empty() {
                    continue;
                }
                let chunk = json!({"bytes": {"$bytes": encode_hex(&outbound)}});
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

async fn loaded(cluster: Arc<Cluster>) -> ono_kuang_supervisor::LoadedPlugin {
    // A relationship query beside an open watch is two invocations and several round trips each;
    // the host's default five-second call deadline is for a machine nobody else is using.
    let limits = HostLimits {
        call_deadline_ms: 120_000,
        ..HostLimits::default()
    };
    TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(cluster as Arc<dyn HostServices>)
        .limits(limits)
        .load()
        .await
        .expect("the package loads under its own manifest")
}

async fn next_record(
    invocation: &mut ono_kuang_supervisor::RunningInvocation,
    what: &str,
) -> Arc<RecordValue> {
    let event = tokio::time::timeout(SOON, invocation.next())
        .await
        .unwrap_or_else(|_| panic!("{what}: nothing arrived before the test gave up"))
        .unwrap_or_else(|| panic!("{what}: the stream ended instead of answering"));
    match event {
        StreamEvent::Value(Value::Record(record)) => record,
        StreamEvent::Value(other) => panic!("{what}: a provider answers records, not {other:?}"),
        StreamEvent::Failed(error) => panic!("{what}: the invocation failed: {error:?}"),
    }
}

/// Waits until `path` has been asked for `count` times, or gives up.
async fn asked_for_at_least(cluster: &Cluster, path: &str, count: usize) {
    let deadline = Instant::now() + SOON;
    while cluster.asked_for(path) < count {
        assert!(
            Instant::now() < deadline,
            "{path} was asked for {} times and the test wanted {count}: {:?}",
            cluster.asked_for(path),
            cluster.heads()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Every edge of one relationship word `k8s-relation` answers about one object.
async fn edges(
    plugin: &ono_kuang_supervisor::LoadedPlugin,
    extra: &[(&str, Json)],
    relation: &str,
) -> Vec<Arc<RecordValue>> {
    let (events, result) = plugin
        .query("k8s-relation", options(extra))
        .await
        .expect("the query starts")
        .collect()
        .await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "coverage is complete, so the answer is a complete one: {:?}",
        result.error
    );
    records(&events)
        .into_iter()
        .filter(|record| text_of(record, "relation").as_deref() == Some(relation))
        .collect()
}

fn targets(edges: &[Arc<RecordValue>]) -> Vec<String> {
    let mut names: Vec<String> = edges
        .iter()
        .filter_map(|edge| text_of(edge, "target_name"))
        .collect();
    names.sort();
    names
}

// --- §60.3: selector changes ---------------------------------------------------------------------

#[tokio::test]
async fn should_drop_the_selects_edge_the_watch_saw_a_label_change_take_away() {
    // §60.3, step by step, through the provider boundary:
    //
    //   1. Service selects Pods A/B.
    //   2. Change label on B.
    //   3. Watch update.
    //   4. Verify `selects` edge disappears with evidence change.
    //
    // The watch is a `k8s-change` invocation held open for the length of the test; the two
    // relationship queries are answered beside it, from the index over the cache it keeps true
    // (§50.4, ADR-0058). What is asserted is the whole composition: the edges before, the
    // evidence on them, the event the watch delivered, the index moving with it, the edge that
    // disappeared, the one that stayed, the coverage that stayed complete, and that nothing was
    // answered from a listing the cache had made unnecessary.
    let cluster = Cluster::new();
    let plugin = loaded(Arc::clone(&cluster)).await;
    let mut watch = plugin
        .query("k8s-change", options(&[("kind", json!("Pod"))]))
        .await
        .expect("the watch starts");
    for _ in 0..3 {
        let listed = next_record(&mut watch, "the acquisition").await;
        assert_eq!(text_of(&listed, "change").as_deref(), Some("listed"));
    }
    asked_for_at_least(&cluster, PODS, 2).await;
    let listed_and_watched = cluster.asked_for(PODS);

    // (1) The Service selects A and B, (2) with the selector and the matched labels as evidence.
    let before = edges(
        &plugin,
        &[("kind", json!("Service")), ("name", json!("pair"))],
        "selects",
    )
    .await;
    assert_eq!(targets(&before), vec!["pair-a", "pair-b"]);
    for edge in &before {
        assert_eq!(text_of(edge, "evidence_class").as_deref(), Some("selector"));
        assert_eq!(
            text_of(edge, "evidence").as_deref(),
            Some("selector {app=pair} matched labels {app=pair}"),
            "§23.3: the selector and the observed label set are the evidence"
        );
        assert!(
            origin_of(edge).contains("origin=cache"),
            "the Pods came from the cache the watch keeps true, and the edge says so (§20.2): {}",
            origin_of(edge)
        );
        assert_eq!(
            map_entry(edge, "observed_resource_versions", "pod").as_deref(),
            Some("9100"),
            "§23.6: the Pod source is the collection at the version the watch synchronised at"
        );
    }

    // (3) B's label changes, and (4) the watch observes the MODIFIED event.
    cluster.relabel_pod_b();
    let modified = next_record(&mut watch, "the label change").await;
    assert_eq!(text_of(&modified, "change").as_deref(), Some("modified"));
    assert_eq!(text_of(&modified, "name").as_deref(), Some("pair-b"));
    assert_eq!(
        text_of(&modified, "resource_version").as_deref(),
        Some("4010")
    );
    assert_eq!(text_of(&modified, "sync_state").as_deref(), Some("live"));
    assert_eq!(modified.get("continuous"), Some(&Value::Bool(true)));

    // (5) The index moved with the event, (6) the edge to B is gone, (7) A remains, and
    // (8) coverage is still complete — `edges` asserts the invocation completed.
    let after = edges(
        &plugin,
        &[("kind", json!("Service")), ("name", json!("pair"))],
        "selects",
    )
    .await;
    assert_eq!(
        targets(&after),
        vec!["pair-a"],
        "(9) the edge to B was once observed, and that is not a reason for it to survive"
    );
    assert!(origin_of(&after[0]).contains("origin=cache"));
    assert_eq!(
        map_entry(&after[0], "observed_resource_versions", "pod").as_deref(),
        Some("4010"),
        "the Pod source now names the version the change was observed at, never the old one"
    );
    assert_eq!(
        cluster.asked_for(PODS),
        listed_and_watched,
        "neither question listed the Pods: the listing and the watch were the only two \
         requests, and the change reached the answer through the watch: {:?}",
        cluster.heads()
    );

    // The same fact from B's end, read directly rather than from the cache: nothing selects it
    // any more, so the two directions agree (Appendix B's `selected-by`).
    let from_b = edges(
        &plugin,
        &[("kind", json!("Pod")), ("name", json!("pair-b"))],
        "selected-by",
    )
    .await;
    assert!(
        from_b.is_empty(),
        "B's labels no longer satisfy the selector, from either end: {:?}",
        targets(&from_b)
    );

    watch.cancel().await;
    let result = tokio::time::timeout(SOON, watch.finish())
        .await
        .expect("a cancelled watch terminates");
    assert_eq!(result.status, InvokeStatus::Cancelled);
    plugin.shutdown(ShutdownReason::Unload).await;
}

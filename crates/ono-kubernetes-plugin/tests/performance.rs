//! What the package costs when the cluster is large, measured through the real test host.
//!
//! Specification §17.6 (query planning), §18.1 to §18.5 (pagination and memory bounds), §19.6
//! (watch fan-out), §41.4 (what a view may call itself), §49.1 and §49.5 (respecting the API
//! server), §50.1 to §50.6 (performance requirements) and §62.12 (Gate L, cancellation).
//! `ADR-0044` records the numbers and says which are contracts and which are observations.
//!
//! The provider crate's `tests/performance.rs` measures what the *provider* retains, in process.
//! This file measures what the *package* costs against a server: how many requests travelled, how
//! long a cancellation takes to be observed, and what a reader is told when a bound truncated the
//! view. Both are needed — a request count asserted inside the crate cannot see the discovery the
//! plugin does before it, and a cancellation is a host concept that has no meaning below the
//! broker.
//!
//! The recorded server here is deliberately smaller than the one in `query.rs`: it serves one
//! group, one kind and one log, and everything it serves it can serve at any size. Nothing here
//! talks to a cluster (§59.1). The fixtures are generated per request rather than checked in.
//!
//! Two of the numbers below are wall-clock, and both are cancellation latencies. They are
//! asserted against a ceiling of five seconds — loose enough that a loaded CI machine cannot
//! reach it, and tight enough to catch the regression that matters, which is a cancellation
//! noticed only when the read deadline expires.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use ono_kuang_sdk::protocol::{Capability, InvokeStatus, ShutdownReason};
use ono_kuang_supervisor::{Connection, HostError, HostServices, LiveStream, StreamEvent};
use ono_kuang_testhost::TestHost;
use ono_kubernetes_plugin::broker::encode_hex;
use ono_value::{RecordValue, Value};
use serde_json::{Map as JsonMap, Value as Json, json};
use tokio::sync::mpsc;

const PLUGIN: &str = env!("CARGO_BIN_EXE_ono-kubernetes");
const MANIFEST: &str = include_str!("../../../package/manifest.yaml");

/// The ceiling every wall-clock assertion in this file is made against.
///
/// Seconds rather than milliseconds, because the question is whether cancellation is observed
/// between reads or at a deadline, and those two answers are thirty seconds apart.
const PROMPTLY: Duration = Duration::from_secs(5);

/// How long a record is waited for before the test decides nothing is coming.
const SOON: Duration = Duration::from_secs(20);

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

fn int_of(record: &RecordValue, field: &str) -> Option<i128> {
    match record.get(field) {
        Some(Value::Int(value)) => Some(*value),
        Some(Value::Null) | None => None,
        other => panic!("`{field}` is an integer or null, and it is {other:?}"),
    }
}

// --- a recorded server of any size ---------------------------------------------------------------

/// An API server that serves one namespace of Pods, in as many pages as the test asks for.
#[derive(Clone)]
struct Cluster {
    /// How many pages the Pod collection comes in.
    pages: usize,
    /// How many Pods each page holds.
    per_page: usize,
    /// Whether every page after the first waits at the gate before it goes on the wire.
    ///
    /// The instrument for cancelling a listing mid-flight: a listing whose next page never
    /// arrives is one that is genuinely still running when the cancellation reaches it, which is
    /// the only state in which §62.12's promptness means anything.
    paced: bool,
    /// Whether the Pod collection serves a watch, and a body that never ends.
    watch: bool,
    /// Whether a followed log is served, one line per release, over a body that never ends.
    logs: bool,
    /// Every request head the server received, so a test can count what travelled (§50.2).
    heads: Arc<std::sync::Mutex<Vec<String>>>,
    /// The gate a paced page, watch frame or log line waits at.
    release: Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for Cluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cluster")
            .field("pages", &self.pages)
            .field("per_page", &self.per_page)
            .finish()
    }
}

impl Cluster {
    fn listing(pages: usize, per_page: usize) -> Arc<Self> {
        Arc::new(Self {
            pages,
            per_page,
            paced: false,
            watch: false,
            logs: false,
            heads: Arc::default(),
            release: Arc::default(),
        })
    }

    /// The same collection, with every page after the first held at the gate.
    fn paced(pages: usize, per_page: usize) -> Arc<Self> {
        Arc::new(Self {
            paced: true,
            ..Self::listing(pages, per_page).as_ref().clone()
        })
    }

    /// A collection that is also watched, over a body that never ends.
    fn watched(pages: usize, per_page: usize) -> Arc<Self> {
        Arc::new(Self {
            watch: true,
            ..Self::listing(pages, per_page).as_ref().clone()
        })
    }

    /// One Pod, and a log of it that can be followed.
    fn logging() -> Arc<Self> {
        Arc::new(Self {
            logs: true,
            ..Self::listing(1, 1).as_ref().clone()
        })
    }

    fn heads(&self) -> Vec<String> {
        self.heads
            .lock()
            .map(|heads| heads.clone())
            .unwrap_or_default()
    }

    /// How many times the server was asked for `path`, whatever the query string was.
    ///
    /// Counted at the far end, because §50.2 is a claim about round trips and what the package
    /// believes it sent is the thing under test.
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
}

const PODS: &str = "/api/v1/namespaces/default/pods";

fn pod(index: usize) -> Json {
    json!({
        "metadata": {
            "name": format!("api-{index:06}"),
            "namespace": "default",
            "uid": format!("00000000-0000-0000-0000-{index:012}"),
            "resourceVersion": format!("{}", 100_000 + index),
            "creationTimestamp": "2026-09-01T09:00:00Z",
            "labels": {"app": "api"},
        },
        "spec": {"nodeName": "node-a", "containers": [{"name": "api"}]},
        "status": {"phase": "Running", "podIP": "10.1.2.3"},
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

/// One chunked `200 OK` whose body has not ended and will not — a watch, or a followed log.
fn held_open(content_type: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n")
        .into_bytes()
}

fn chunk_of(frame: &str) -> String {
    format!("{:x}\r\n{frame}\r\n", frame.len())
}

/// Which page of the Pod collection a request asks for, from its `continue` token.
fn page_of(query: &str) -> usize {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("continue=page-"))
        .and_then(|token| token.parse().ok())
        .unwrap_or(0)
}

fn pod_page(cluster: &Cluster, query: &str) -> Vec<u8> {
    let page = page_of(query);
    let first = page * cluster.per_page;
    let items: Vec<Json> = (first..first + cluster.per_page).map(pod).collect();
    let mut metadata = json!({"resourceVersion": "90210"});
    if page + 1 < cluster.pages
        && let Some(map) = metadata.as_object_mut()
    {
        map.insert("continue".to_owned(), json!(format!("page-{}", page + 1)));
        map.insert("remainingItemCount".to_owned(), json!(1));
    }
    ok(&json!({
        "kind": "PodList",
        "apiVersion": "v1",
        "metadata": metadata,
        "items": items,
    })
    .to_string())
}

/// What the recorded server answers, for the handful of paths it serves.
fn document(cluster: &Cluster, path: &str) -> Vec<u8> {
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    if cluster.watch && route == PODS && query.contains("watch=true") {
        return held_open("application/json");
    }
    if cluster.logs && route.ends_with("/log") && query.contains("follow=true") {
        return held_open("text/plain");
    }
    if route == PODS {
        return pod_page(cluster, query);
    }
    // One Pod by name, which is what a followed log resolves before it opens the stream.
    if let Some(name) = route.strip_prefix(&format!("{PODS}/"))
        && !name.contains('/')
        && let Some(index) = name
            .strip_prefix("api-")
            .and_then(|digits| digits.parse().ok())
        && index < cluster.pages * cluster.per_page
    {
        let mut object = pod(index);
        if let Some(map) = object.as_object_mut() {
            map.insert("apiVersion".to_owned(), json!("v1"));
            map.insert("kind".to_owned(), json!("Pod"));
        }
        return ok(&object.to_string());
    }
    let body = match route {
        "/api" => json!({"kind": "APIVersions", "versions": ["v1"]}),
        // No named groups at all: this server is one namespace of Pods, and a group it does not
        // serve is a resource list this package must never ask for.
        "/apis" => json!({"kind": "APIGroupList", "groups": []}),
        "/api/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "v1",
            "resources": [
                {"name": "namespaces", "kind": "Namespace", "namespaced": false,
                 "verbs": ["get", "list", "watch"], "shortNames": ["ns"]},
                {"name": "pods", "kind": "Pod", "namespaced": true,
                 "verbs": ["get", "list", "watch"], "shortNames": ["po"]},
                {"name": "pods/log", "kind": "Pod", "namespaced": true, "verbs": ["get"]},
            ],
        }),
        "/api/v1/namespaces" => json!({
            "kind": "NamespaceList",
            "apiVersion": "v1",
            "metadata": {"resourceVersion": "9000"},
            "items": [{
                "metadata": {
                    "name": "default",
                    "uid": "33333333-3333-3333-3333-333333333333",
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "status": {"phase": "Active"},
            }],
        }),
        _ => return not_found(route),
    };
    ok(&body.to_string())
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
                    // A paced collection does not answer its continued pages at all until the
                    // test says so. A listing waiting here is one that is genuinely in flight.
                    if cluster.paced && path.contains("continue=") {
                        cluster.release.notified().await;
                    }
                    replies.push(document(&cluster, &path));
                    // A followed log delivers its lines from here, one per release, so the body
                    // is still open while the test takes the record the first one produced.
                    if cluster.logs && path.contains("follow=true") {
                        let sender = inbound.clone();
                        let gate = Arc::clone(&cluster.release);
                        tokio::spawn(async move {
                            for line in ["the first line\n", "the second line\n"] {
                                gate.notified().await;
                                let bytes = chunk_of(line).into_bytes();
                                let chunk = json!({"bytes": {"$bytes": encode_hex(&bytes)}});
                                if sender.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
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
    TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(cluster as Arc<dyn HostServices>)
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
///
/// A watch and a held page are both states the package reaches *after* the record that proves it
/// got there, so there is nothing to synchronise on but the server's own record of what arrived.
/// Polling is honest here in a way a sleep is not: the wait ends when the request exists.
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

// --- §50.2: what discovery and a listing cost in round trips -------------------------------------

#[tokio::test]
async fn should_pay_for_discovery_once_and_one_request_per_page_for_four_hundred_objects() {
    // §50.2: "Discovery and OpenAPI loading SHOULD be cached and incrementally refreshed rather
    // than downloaded before every query." §49.1: "Ono is an interactive shell, not a load
    // generator."
    //
    // There is a test in `query.rs` that proves discovery is paid for once — over a cluster
    // holding two Pods, where a per-object round trip and a per-query one are the same number.
    // This is the same claim at a size where they are not: four hundred objects, and the whole
    // conversation is eleven requests. The count is asserted as a *number* rather than as a
    // relation, because the regression worth catching is a request that scales with the
    // collection, and only an absolute number catches that on the first run.
    let cluster = Cluster::listing(200, 100);
    let plugin = loaded(Arc::clone(&cluster)).await;
    let bounded = options(&[("max_pages", json!(4))]);

    for attempt in 0..2 {
        let (events, result) = plugin
            .query("k8s-pod", bounded.clone())
            .await
            .expect("the query starts")
            .collect()
            .await;
        assert_eq!(
            result.status,
            InvokeStatus::Completed,
            "attempt {attempt}: {:?}",
            result.error
        );
        assert_eq!(
            records(&events).len(),
            400,
            "attempt {attempt}: four pages of a hundred objects each"
        );
    }

    assert_eq!(
        (
            cluster.asked_for("/api"),
            cluster.asked_for("/apis"),
            cluster.asked_for("/api/v1"),
        ),
        (1, 1, 1),
        "what the cluster *is* was learned once, for both queries (§50.2, §6.3): {:?}",
        cluster.heads()
    );
    assert_eq!(
        cluster.asked_for(PODS),
        8,
        "and what is *in* it was read every time, one request per page and none per object"
    );
    assert_eq!(
        cluster.heads().len(),
        11,
        "eight hundred objects crossed in eleven requests, and that total is the contract: {:?}",
        cluster.heads()
    );
}

#[tokio::test]
async fn should_stop_a_two_hundred_page_collection_at_the_default_page_budget_and_say_what_stopped_it()
 {
    // §18.5: "The provider SHOULD stream pages into the Ono pipeline rather than buffering entire
    // large clusters." §49.5: "The provider SHOULD expose configurable query concurrency/QPS/burst
    // policy with conservative defaults aligned with interactive use."
    //
    // This is the number those two sentences come to for a query nobody configured: sixteen
    // pages, which is `Budget::interactive`'s page bound, over a collection that offers two
    // hundred. What matters as much as the bound is that the answer says a *policy* stopped it —
    // the recorded server answered every request it was sent perfectly, and reporting this as a
    // cluster fault would send an operator to look at a control plane that is fine (§48.2).
    let cluster = Cluster::listing(200, 50);
    let plugin = loaded(Arc::clone(&cluster)).await;

    let (events, result) = plugin
        .query("k8s-pod", options(&[]))
        .await
        .expect("the query starts")
        .collect()
        .await;

    assert_eq!(
        cluster.asked_for(PODS),
        16,
        "sixteen pages is what an unconfigured interactive query pays for"
    );
    assert_eq!(
        records(&events).len(),
        800,
        "and the eight hundred objects it did read are true and they stand (§18.3)"
    );
    assert_eq!(
        result.status,
        InvokeStatus::Failed,
        "a listing that stopped short must not look like a whole one"
    );
    let error = result.error.expect("a failed invocation carries an error");
    let said = format!("{} {}", error.message, error.help.unwrap_or_default());
    assert!(
        said.contains("pages budget exceeded") && said.contains("16 pages allowed"),
        "the refusal names the bound it reached rather than blaming a cluster that answered \
         every request it was sent: {said}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

// --- §18.5 and §41.4: what a reader is told when a view is bounded --------------------------------

#[tokio::test]
async fn should_bound_a_watched_collection_at_the_view_capacity_and_report_the_rest_as_withheld() {
    // §18.5's memory bound where a reader meets it, and §41.4's rule that a bounded view must
    // never read as a complete one. The package's live view holds two thousand rows; this
    // collection holds two thousand one hundred, so the first record a reader is handed has to
    // say that a hundred objects were not admitted.
    //
    // `max_changes` is one, deliberately: the assertion is about what the *first* record says,
    // and emitting two thousand one hundred of them would measure the emission path rather than
    // the bound.
    let cluster = Cluster::watched(21, 100);
    let plugin = loaded(Arc::clone(&cluster)).await;
    let mut invocation = plugin
        .query(
            "k8s-change",
            options(&[("kind", json!("Pod")), ("max_changes", json!(1))]),
        )
        .await
        .expect("the watch starts");

    let first = next_record(&mut invocation, "the acquisition's first record").await;
    assert_eq!(
        int_of(&first, "withheld"),
        Some(100),
        "two thousand one hundred objects into a two-thousand-row view leaves a hundred \
         withheld, and every record says so"
    );
    let (_, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    assert_eq!(
        cluster.asked_for(PODS),
        21,
        "the acquisition read the collection in twenty-one pages and the watch had not opened yet"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

// --- §62.12, Gate L: how long a cancellation takes to be observed ---------------------------------

/// Cancels `invocation` and returns how long the whole termination took.
async fn cancelled_in(
    invocation: ono_kuang_supervisor::RunningInvocation,
) -> (Duration, InvokeStatus) {
    let started = Instant::now();
    invocation.cancel().await;
    let result = tokio::time::timeout(SOON, invocation.finish())
        .await
        .expect("a cancelled invocation terminates rather than hanging");
    (started.elapsed(), result.status)
}

#[tokio::test]
async fn should_terminate_a_large_listing_within_seconds_of_being_cancelled_while_it_is_answering()
{
    // §62.12, Gate L: "Large list, watch, log-follow and verification operations terminate
    // promptly under Ono cancellation semantics." §50.1: "All remote work MUST be
    // asynchronous/cancellable according to Ono host semantics."
    //
    // `query.rs` proves that a cancelled listing ends `Cancelled`. What it does not prove is
    // *when*, and a package that noticed cancellation only when a read deadline expired would
    // pass that test while freezing a shell for thirty seconds. This is the case where the
    // cluster is answering — two hundred pages available as fast as they are asked for — and the
    // invocation is somewhere between a page and an emission when the operator stops it.
    let cluster = Cluster::listing(200, 10);
    let plugin = loaded(Arc::clone(&cluster)).await;
    let mut invocation = plugin
        .query("k8s-pod", options(&[]))
        .await
        .expect("the query starts");
    for _ in 0..3 {
        next_record(&mut invocation, "the first records").await;
    }

    let (elapsed, status) = cancelled_in(invocation).await;
    println!("cancelled listing (server answering) terminated in {elapsed:?}");
    assert_eq!(status, InvokeStatus::Cancelled);
    assert!(
        elapsed < PROMPTLY,
        "a cancelled listing terminates between reads rather than at a deadline: {elapsed:?}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_terminate_a_listing_blocked_on_a_silent_server_rather_than_hanging_on_it() {
    // The other half of §62.12, and the one nothing measured. A large listing spends its time
    // waiting for the first byte of the next page, and a cluster under load takes its time about
    // that byte — so the state a cancellation most often arrives in is "blocked in a read that
    // has been given nothing yet". The recorded server here holds every continued page and never
    // releases it, which is that state made deterministic.
    //
    // The invocation does terminate, and it is `Cancelled` rather than a fault: the operator
    // stopped it, and reporting a cluster failure for that would be a lie about a server that is
    // behaving. That is what this test asserts, and the ceiling is loose enough to hold whatever
    // the deadline is.
    let cluster = Cluster::paced(200, 10);
    let plugin = loaded(Arc::clone(&cluster)).await;
    let mut invocation = plugin
        .query("k8s-pod", options(&[]))
        .await
        .expect("the query starts");
    // The whole first page, because the walk asks for the second only once the reader has taken
    // the first — which is §18.5's streaming, proved elsewhere and relied on here.
    for _ in 0..10 {
        next_record(&mut invocation, "the first page's records").await;
    }
    asked_for_at_least(&cluster, PODS, 2).await;
    assert_eq!(
        cluster.asked_for(PODS),
        2,
        "the second page was asked for and is being held, so the listing is blocked on a server \
         that has gone quiet"
    );

    let started = Instant::now();
    invocation.cancel().await;
    let result = tokio::time::timeout(Duration::from_secs(30), invocation.finish())
        .await
        .expect("a cancelled listing terminates rather than hanging on a silent server");
    let elapsed = started.elapsed();
    println!("cancelled listing (server silent) terminated in {elapsed:?}");
    assert_eq!(result.status, InvokeStatus::Cancelled);

    // This took sixty seconds when it was written — two windows of what was then a
    // thirty-second `ReadPolicy::request`, measured at 59.99s. A listing parked in
    // `BrokeredStream::read` cannot be told the operator stopped it until the `streams.next` it
    // is inside returns, and one constant was serving as both the liveness deadline and the
    // cancellation window; the cancellation was not observed in the window it arrived in, so it
    // cost two. §62.12's "terminate promptly" held for the watch and the followed log, which had
    // the short window, and not for the operation Gate L names *first*.
    //
    // The window is a quarter of a second on every path now, and the ninety seconds of patience
    // a silent API server is given is a separate number. The ceiling below stays far above the
    // measurement on purpose — it is a guard against "never terminates" rather than a latency
    // budget, and a machine under load may take several windows.
    assert!(
        elapsed < Duration::from_secs(5),
        "a cancelled listing terminates in the window the cancellation arrived in, not when the \
         connection dies: {elapsed:?}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_terminate_a_live_watch_within_seconds_of_being_cancelled() {
    // §62.12 on the operation that has no other ending. A watch runs until the operator stops it,
    // so cancellation is how almost every watch finishes, and the body it is waiting on never
    // ends — the recorded server sends the head of the response and no terminating chunk, ever.
    let cluster = Cluster::watched(1, 1);
    let plugin = loaded(Arc::clone(&cluster)).await;
    let mut invocation = plugin
        .query("k8s-change", options(&[("kind", json!("Pod"))]))
        .await
        .expect("the watch starts");
    next_record(&mut invocation, "the acquisition").await;
    // The watch opens after the acquisition's records, and its body never delivers anything, so
    // the request itself is the only evidence that the package is inside the read being cancelled.
    asked_for_at_least(&cluster, PODS, 2).await;

    let (elapsed, status) = cancelled_in(invocation).await;
    println!("cancelled watch terminated in {elapsed:?}");
    assert_eq!(status, InvokeStatus::Cancelled);
    assert!(
        elapsed < PROMPTLY,
        "a cancelled watch terminates between chunks rather than at the end of a body that never \
         comes: {elapsed:?}"
    );
    assert!(
        cluster
            .heads()
            .iter()
            .any(|head| head.contains("watch=true")),
        "the watch really was open, which is what there was to cancel: {:?}",
        cluster.heads()
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_terminate_a_followed_log_within_seconds_of_being_cancelled() {
    // §62.12 on the last of the four operations it names. A followed log has no natural end
    // either, and the shape of the failure is the same: a package that could only notice a
    // cancellation when the body ended would wait for a body that never does.
    let cluster = Cluster::logging();
    let plugin = loaded(Arc::clone(&cluster)).await;
    let mut invocation = plugin
        .query(
            "k8s-log",
            options(&[
                ("name", json!("api-000000")),
                ("container", json!("api")),
                ("follow", json!(true)),
            ]),
        )
        .await
        .expect("the follow starts");
    cluster.release.notify_one();
    next_record(&mut invocation, "the first line").await;

    let (elapsed, status) = cancelled_in(invocation).await;
    println!("cancelled log follow terminated in {elapsed:?}");
    assert_eq!(status, InvokeStatus::Cancelled);
    assert!(
        elapsed < PROMPTLY,
        "a cancelled follow terminates between chunks rather than at the read deadline: \
         {elapsed:?}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

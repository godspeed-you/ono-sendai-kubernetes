//! The mutation tranche at the boundary: a plan a user can ask for, and a change a user can make.
//!
//! Everything here runs the real binary under the deterministic test host of spec §31.73, against
//! an API server that answers from recorded bytes over the host's own `network.connect`. Nothing
//! contacts a cluster (§59.1), and the awkward answers — an apply conflict naming another
//! manager, a deletion a finalizer holds, a dry run that writes nothing — are ordinary fixtures.
//!
//! The recorded server here reads request *bodies*, which `tests/query.rs`'s does not: every read
//! this package made until now was a `GET` with no body, and an apply is a `PATCH` with one. That
//! body is also evidence: `bodies()` is how the tests assert that a `resourceVersion` and a UID
//! travelled with the change rather than being described in a plan and dropped on the way to the
//! wire (§56).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::sync::Arc;

use ono_kuang_sdk::protocol::{Capability, InvokeStatus};
use ono_kuang_supervisor::{Connection, HostError, HostServices, LiveStream, StreamEvent};
use ono_kuang_testhost::TestHost;
use ono_kubernetes_plugin::broker::encode_hex;
use ono_value::{RecordValue, Value};
use serde_json::{Map as JsonMap, Value as Json, json};
use tokio::sync::mpsc;

const PLUGIN: &str = env!("CARGO_BIN_EXE_ono-kubernetes");
const MANIFEST: &str = include_str!("../../../package/manifest.yaml");
const SET: &str = "io.github.godspeed-you.kubernetes.command.set-k8s-resource";
const REMOVE: &str = "io.github.godspeed-you.kubernetes.command.remove-k8s-resource";

/// The manager the recorded cluster says owns the container image.
const OTHER_MANAGER: &str = "argocd-controller";

// --- options -----------------------------------------------------------------------------------

fn options(pairs: &[(&str, Json)]) -> JsonMap<String, Json> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

/// The options that point an invocation at the recorded cluster.
fn at_cluster(extra: &[(&str, Json)]) -> JsonMap<String, Json> {
    let mut map = options(&[
        ("host", json!("cluster.test")),
        ("port", json!(8001)),
        ("context", json!("recorded")),
    ]);
    for (key, value) in extra {
        map.insert((*key).to_owned(), value.clone());
    }
    map
}

/// The arguments that scale the recorded Deployment down to one replica.
fn scale_down(extra: &[(&str, Json)]) -> JsonMap<String, Json> {
    let mut map = at_cluster(&[
        ("kind", json!("Deployment")),
        ("name", json!("api")),
        ("namespace", json!("default")),
        ("set", json!({"/spec/replicas": 1})),
    ]);
    for (key, value) in extra {
        map.insert((*key).to_owned(), value.clone());
    }
    map
}

// --- reading what came back ----------------------------------------------------------------------

fn records(events: &[StreamEvent]) -> Vec<Arc<RecordValue>> {
    events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::Value(Value::Record(record)) => Some(Arc::clone(record)),
            StreamEvent::Value(other) => {
                panic!("this package answers records, and it answered {other:?}")
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

fn text(record: &RecordValue, field: &str) -> String {
    text_of(record, field).unwrap_or_else(|| panic!("`{field}` is not null on this record"))
}

fn bool_of(record: &RecordValue, field: &str) -> bool {
    match record.get(field) {
        Some(Value::Bool(answer)) => *answer,
        other => panic!("`{field}` is a boolean, and it is {other:?}"),
    }
}

fn list_of(record: &RecordValue, field: &str) -> Vec<String> {
    match record.get(field) {
        Some(Value::List(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => text.to_string(),
                other => format!("{other:?}"),
            })
            .collect(),
        Some(Value::Null) | None => Vec::new(),
        other => panic!("`{field}` is a list or null, and it is {other:?}"),
    }
}

/// Every entry of a `list<map>` field, rendered as text, so a test can assert on one line.
fn maps_of(record: &RecordValue, field: &str) -> Vec<String> {
    match record.get(field) {
        Some(Value::List(items)) => items.iter().map(ToString::to_string).collect(),
        Some(Value::Null) | None => Vec::new(),
        other => panic!("`{field}` is a list of maps or null, and it is {other:?}"),
    }
}

/// One field rendered as text, whatever its shape.
fn rendered(record: &RecordValue, field: &str) -> String {
    record
        .get(field)
        .map_or_else(|| "<absent>".to_owned(), ToString::to_string)
}

// --- the recorded cluster ------------------------------------------------------------------------

/// Which scenario the recorded API server plays.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Scenario {
    /// The Deployment applies cleanly; the follow-up read shows a controller that has not caught
    /// up. Gate G's case.
    #[default]
    Accepted,
    /// Another field manager owns the field the apply sets (§44.3, §60.7).
    Conflict,
    /// A mutating webhook rewrites the image registry on the way in (§44.6).
    Admission,
}

/// An API server that answers from recorded documents, reached through `network.connect`.
#[derive(Clone, Default)]
struct RecordedCluster {
    scenario: Scenario,
    /// How many times the Deployment has been read, so the read *after* the write can show what
    /// the write did without the read *before* it having shown it already.
    reads: Arc<std::sync::atomic::AtomicUsize>,
    /// How many times the ConfigMap has been read, so the read after a delete can be a `404`.
    configmap_reads: Arc<std::sync::atomic::AtomicUsize>,
    /// Whether the claim's delete has been accepted, so the read after it shows the object the
    /// API server has begun to remove rather than the one it held before.
    claim_deleting: Arc<std::sync::atomic::AtomicBool>,
    /// Every request the server received, head and body, so a test can assert what travelled.
    exchanges: Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl std::fmt::Debug for RecordedCluster {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordedCluster")
            .field("scenario", &self.scenario)
            .finish()
    }
}

impl RecordedCluster {
    fn playing(scenario: Scenario) -> Arc<Self> {
        Arc::new(Self {
            scenario,
            ..Self::default()
        })
    }

    /// The request heads the server received, in order.
    fn heads(&self) -> Vec<String> {
        self.exchanges
            .lock()
            .map(|held| held.iter().map(|(head, _)| head.clone()).collect())
            .unwrap_or_default()
    }

    /// The head and body of every request whose head starts with `method`.
    fn requests(&self, method: &str) -> Vec<(String, String)> {
        self.exchanges
            .lock()
            .map(|held| {
                held.iter()
                    .filter(|(head, _)| head.starts_with(method))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn http(status_line: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn ok(body: &Json) -> Vec<u8> {
    http("200 OK", &body.to_string())
}

fn not_found(path: &str) -> Vec<u8> {
    http(
        "404 Not Found",
        &json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": format!("the recorded cluster serves no {path}"),
            "reason": "NotFound", "code": 404,
        })
        .to_string(),
    )
}

/// The Deployment, before and after the change. `generation` advances and `observedGeneration`
/// does not: the controller has not caught up, which is exactly the state Gate G is about.
fn deployment(applied: bool) -> Json {
    let replicas = if applied { 1 } else { 3 };
    let generation = if applied { 8 } else { 7 };
    let resource_version = if applied { "4712" } else { "4711" };
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "api",
            "namespace": "default",
            "uid": "66666666-6666-6666-6666-666666666666",
            "resourceVersion": resource_version,
            "generation": generation,
            "creationTimestamp": "2026-08-20T08:00:00Z",
            "managedFields": [{"manager": OTHER_MANAGER, "operation": "Apply"}],
        },
        "spec": {
            "replicas": replicas,
            "template": {"spec": {"containers": [{"name": "web", "image": "registry.io/web:1"}]}},
        },
        "status": {"readyReplicas": 3, "replicas": 3, "observedGeneration": 7},
    })
}

/// The Deployment as a mutating webhook returned it: an admission policy clamped the replica
/// count the request asked for, and added an annotation saying it had.
///
/// The clamp is the point. §44.6's diff is over the fields the *request* set, because those are
/// the ones whose fate the caller asked about — a webhook that rewrote a field nobody sent is a
/// difference between two server-side states rather than between what was asked and what was
/// accepted, and reporting it as the latter would be a claim about the request that is not true.
fn defaulted_deployment() -> Json {
    let mut object = deployment(true);
    object["spec"]["replicas"] = json!(2);
    object["metadata"]["annotations"] = json!({"policy.example.io/mutated": "true"});
    object
}

/// A PersistentVolumeClaim a finalizer holds, before and after the delete was accepted.
fn claim(terminating: bool) -> Json {
    let mut object = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": "data",
            "namespace": "default",
            "uid": "88888888-8888-8888-8888-888888888888",
            "resourceVersion": "5000",
            "creationTimestamp": "2026-08-01T00:00:00Z",
            "finalizers": ["kubernetes.io/pvc-protection"],
        },
        "spec": {"storageClassName": "fast"},
        "status": {"phase": "Bound"},
    });
    if terminating {
        object["metadata"]["deletionTimestamp"] = json!("2026-09-06T12:00:00Z");
    }
    object
}

/// A ConfigMap nothing holds: its deletion finishes, and a later read establishes that.
fn configmap() -> Json {
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "settings",
            "namespace": "default",
            "uid": "99999999-9999-9999-9999-999999999999",
            "resourceVersion": "5100",
            "creationTimestamp": "2026-08-01T00:00:00Z",
        },
        "data": {"level": "info"},
    })
}

/// A ConfigMap the API server gave no `resourceVersion`, so no precondition can be built from it.
fn unversioned_configmap() -> Json {
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "legacy",
            "namespace": "default",
            "uid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "creationTimestamp": "2026-08-01T00:00:00Z",
        },
        "data": {"level": "info"},
    })
}

fn conflict() -> Vec<u8> {
    http(
        "409 Conflict",
        &json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": format!("Apply failed with 1 conflict: conflict with \"{OTHER_MANAGER}\""),
            "reason": "Conflict",
            "details": {"group": "apps", "kind": "deployments", "name": "api", "causes": [{
                "reason": "FieldManagerConflict",
                "message": format!("conflict with \"{OTHER_MANAGER}\" using apps/v1"),
                "field": ".spec.replicas",
            }]},
            "code": 409,
        })
        .to_string(),
    )
}

/// What the recorded server answers one request with.
fn document(method: &str, path: &str, cluster: &RecordedCluster) -> Vec<u8> {
    let dry_run = path.contains("dryRun=All");
    let path_only = path.split('?').next().unwrap_or(path);
    const DEPLOYMENT: &str = "/apis/apps/v1/namespaces/default/deployments/api";
    const CLAIM: &str = "/api/v1/namespaces/default/persistentvolumeclaims/data";
    const CONFIGMAP: &str = "/api/v1/namespaces/default/configmaps/settings";
    const LEGACY: &str = "/api/v1/namespaces/default/configmaps/legacy";

    match (method, path_only) {
        ("GET", "/api") => ok(&json!({"kind": "APIVersions", "versions": ["v1"]})),
        ("GET", "/apis") => ok(&json!({
            "kind": "APIGroupList",
            "groups": [{
                "name": "apps",
                "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
            }],
        })),
        ("GET", "/api/v1") => ok(&json!({
            "kind": "APIResourceList",
            "groupVersion": "v1",
            "resources": [
                {"name": "configmaps", "kind": "ConfigMap", "namespaced": true,
                 "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["cm"]},
                {"name": "persistentvolumeclaims", "kind": "PersistentVolumeClaim",
                 "namespaced": true,
                 "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["pvc"]},
                // Served, readable, and not patchable or deletable by anyone: §11.5's third
                // state, and the one a refusal has to name rather than call a denial.
                {"name": "nodes", "kind": "Node", "namespaced": false,
                 "verbs": ["get", "list", "watch"], "shortNames": ["no"]},
            ],
        })),
        ("GET", "/apis/apps/v1") => ok(&json!({
            "kind": "APIResourceList",
            "groupVersion": "apps/v1",
            "resources": [{
                "name": "deployments", "kind": "Deployment", "namespaced": true,
                "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["deploy"],
            }],
        })),
        ("GET", "/api/v1/nodes/node-a") => ok(&json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "node-a", "uid": "44444444-4444-4444-4444-444444444444",
                         "resourceVersion": "4000"},
        })),
        ("GET", DEPLOYMENT) => {
            let seen = cluster
                .reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ok(&deployment(seen > 0))
        }
        ("PATCH", DEPLOYMENT) => match cluster.scenario {
            Scenario::Conflict => conflict(),
            Scenario::Admission if dry_run => ok(&defaulted_deployment()),
            _ => ok(&deployment(true)),
        },
        ("GET", CLAIM) => ok(&claim(
            cluster
                .claim_deleting
                .load(std::sync::atomic::Ordering::Relaxed),
        )),
        // A delete the API server accepted, answering with the object it has begun to remove:
        // the `deletionTimestamp` is set and the finalizer is still there (Gate H).
        ("DELETE", CLAIM) => {
            cluster
                .claim_deleting
                .store(true, std::sync::atomic::Ordering::Relaxed);
            ok(&claim(true))
        }
        ("GET", CONFIGMAP) => {
            let seen = cluster
                .configmap_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if seen > 0 {
                return not_found(path_only);
            }
            ok(&configmap())
        }
        ("DELETE", CONFIGMAP) => ok(&json!({
            "kind": "Status", "apiVersion": "v1", "status": "Success",
            "details": {"name": "settings", "kind": "configmaps"},
        })),
        ("GET", LEGACY) => ok(&unversioned_configmap()),
        _ => not_found(path_only),
    }
}

#[async_trait::async_trait]
impl HostServices for RecordedCluster {
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
                // A head ends at the blank line, and a mutation carries a body after it. The
                // body is read by `Content-Length`, which is what this package writes.
                while let Some(at) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buffered[..at]).into_owned();
                    let length = content_length(&head);
                    if buffered.len() < at + 4 + length {
                        break;
                    }
                    let body =
                        String::from_utf8_lossy(&buffered[at + 4..at + 4 + length]).into_owned();
                    buffered.drain(..at + 4 + length);
                    let mut words = head.split_whitespace();
                    let method = words.next().unwrap_or("GET").to_owned();
                    let path = words.next().unwrap_or("/").to_owned();
                    if let Ok(mut held) = cluster.exchanges.lock() {
                        held.push((head.clone(), body));
                    }
                    replies.push(document(&method, &path, &cluster));
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

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

/// A loaded instance against a recorded cluster, with the grant the operator makes.
async fn loaded(cluster: &Arc<RecordedCluster>) -> ono_kuang_supervisor::LoadedPlugin {
    TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(Arc::clone(cluster) as Arc<dyn HostServices>)
        .load()
        .await
        .expect("the package loads under its own manifest")
}

// --- what a user may ask before anything happens -------------------------------------------------

#[tokio::test]
async fn should_answer_what_a_change_would_do_without_making_it() {
    // §46.1: a change is understood before it is made. The plan is a *target* rather than a
    // command because it is read-only — and the assertion that matters is the last one, which
    // reads the request heads and finds no write among them.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .query(
            "k8s-plan",
            at_cluster(&[
                ("kind", json!("Deployment")),
                ("name", json!("api")),
                ("namespace", json!("default")),
                ("set", json!({"/spec/replicas": 1})),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "a plan is answerable: {:?}",
        result.error
    );
    let records = records(&events);
    assert_eq!(records.len(), 1, "one plan, for one prospective change");
    let plan = &records[0];

    assert_eq!(
        plan.schema_id().to_string(),
        "io.github.godspeed-you.kubernetes.plan/1"
    );
    assert_eq!(text(plan, "kind"), "Deployment");
    assert_eq!(text(plan, "name"), "api");
    assert_eq!(text(plan, "action"), "apply");
    assert_eq!(
        text(plan, "uid"),
        "66666666-6666-6666-6666-666666666666",
        "§56.3: the plan carries the lifetime it is aimed at"
    );
    assert_eq!(
        text(plan, "resource_version"),
        "4711",
        "§56.1: the plan carries the continuity token it was built at"
    );
    assert!(
        bool_of(plan, "precondition_guarded"),
        "a plan built from an object that was read is guarded"
    );
    assert_eq!(
        list_of(plan, "changes"),
        vec!["/spec/replicas: 3 -> 1"],
        "the plan states the field, what it holds and what it would hold (§46.2)"
    );
    assert_eq!(
        text(plan, "verification"),
        "a controller observes the generation and converges",
        "§46.3: the verification rule matches the action's semantics and is chosen beforehand"
    );

    let effects = maps_of(plan, "effects");
    assert!(
        effects
            .iter()
            .any(|effect| effect.contains("pods stopped")
                || effect.contains("running pods are stopped")),
        "scaling down stops pods, and the plan says so before anybody agrees to it: {effects:?}"
    );
    assert!(
        effects.iter().any(|effect| effect.contains("irreversible")),
        "§46.5: an effect carries its own reversibility: {effects:?}"
    );
    assert_eq!(
        text(plan, "reversibility"),
        "irreversible",
        "the plan reports the weakest of its effects, never the friendliest"
    );

    let caveats = list_of(plan, "caveats");
    assert!(
        caveats.iter().any(|caveat| caveat.contains(OTHER_MANAGER)),
        "§44.3 and §54.1: the managers already on the object are named before the apply, not at \
         the conflict: {caveats:?}"
    );
    assert!(
        caveats.iter().any(|caveat| caveat.contains("dry run")),
        "no server dry run was made, so admission and defaulting are unpreviewed: {caveats:?}"
    );
    assert!(
        text(plan, "prediction").contains("static provider metadata"),
        "§21.4 of the generic contract: a prediction says where it comes from"
    );
    assert!(
        text(plan, "statement").contains("not evidence"),
        "§4 invariant 18: nothing in a plan says the change was made"
    );

    // The point of the target: it is read-only, and this is what proves it rather than says it.
    let heads = cluster.heads();
    assert!(
        heads.iter().all(|head| head.starts_with("GET ")),
        "asking what a change would do must change nothing: {heads:?}"
    );
}

#[tokio::test]
async fn should_refuse_a_plan_whose_target_carries_no_precondition() {
    // §56.1 at the boundary. The object the API server returned has no `resourceVersion`, so
    // there is nothing to guard the change against a concurrent write — and `plan.rs` refuses
    // rather than building a plan with a warning on it. There is deliberately no argument by
    // which a caller could supply the missing token by hand.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .query(
            "k8s-plan",
            at_cluster(&[
                ("kind", json!("ConfigMap")),
                ("name", json!("legacy")),
                ("namespace", json!("default")),
                ("set", json!({"/data/level": "debug"})),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Failed);
    assert!(records(&events).is_empty(), "no plan was built");
    let error = result.error.expect("a refusal carries an error");
    assert!(
        error.message.contains("resourceVersion"),
        "the refusal names the precondition that is missing: {}",
        error.message
    );
    assert!(
        error.message.contains("overwritten"),
        "and what it would have prevented: {}",
        error.message
    );
}

// --- what a user may not do by accident ----------------------------------------------------------

#[tokio::test]
async fn should_refuse_a_mutation_the_operator_granted_no_capability_for() {
    // §31.19's floor, on the write path: deny by default. The command declares the capability it
    // needs, the host checks it at invocation, and nothing this package does is reached — which
    // is why the recorded cluster saw no request at all.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = TestHost::new(PLUGIN, MANIFEST)
        .host(Arc::clone(&cluster) as Arc<dyn HostServices>)
        .load()
        .await
        .expect("the package loads under its own manifest");
    let refusal = plugin
        .invoke(SET, scale_down(&[]))
        .await
        .expect_err("a mutation without the grant is refused");
    assert_eq!(
        refusal.name, "capability.denied",
        "a denial is a refusal that names the decision, not a failure part-way through: {refusal:?}"
    );
    assert!(
        refusal.message.contains("network.connect"),
        "the refusal names the capability the operator has to grant: {}",
        refusal.message
    );
    assert!(
        cluster.heads().is_empty(),
        "the refusal came before any byte reached the cluster: {:?}",
        cluster.heads()
    );
}

#[tokio::test]
async fn should_not_reach_a_mutation_through_a_read_verb() {
    // §4 invariant 22 and §21.2 of the generic contract: `get` is a read verb, and a mutation is
    // not a `get`. The words this package answers `provider.query` for are all read-only, and
    // the two that write are commands with a declared risk and a declared capability.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    // The read path cannot reach either writing word: `provider.query` resolves against the
    // contributed *targets*, and neither command is one. The refusal comes from the host's own
    // resolution, before any of this package's code runs.
    for command in [SET, REMOVE] {
        let refusal = plugin
            .query(command, scale_down(&[]))
            .await
            .expect_err("a command is not a target");
        assert_eq!(refusal.name, "resolve.target_not_found");
    }
    assert!(
        cluster.heads().is_empty(),
        "and nothing reached the cluster on the way to finding out: {:?}",
        cluster.heads()
    );
    let set = plugin
        .commands()
        .iter()
        .find(|command| command.contribution.id == SET)
        .expect("the package contributes `set k8s-resource`");
    assert_eq!(set.contribution.verb, "set");
    assert_eq!(
        set.contribution.risk.as_deref(),
        Some("mutate"),
        "§31.75: a mutating command declares its risk, so host policy can apply its own \
         confirmation rules (§21.5 of the generic contract)"
    );
    assert_eq!(set.contribution.capabilities, vec!["network.connect"]);

    let remove = plugin
        .commands()
        .iter()
        .find(|command| command.contribution.id == REMOVE)
        .expect("the package contributes `remove k8s-resource`");
    assert_eq!(remove.contribution.verb, "remove");
    assert_eq!(
        remove.contribution.risk.as_deref(),
        Some("destructive"),
        "a deletion may cause irreversible loss, and the risk descriptor says so"
    );
}

// --- the dry run is the easy path ------------------------------------------------------------------

#[tokio::test]
async fn should_predict_rather_than_write_unless_the_caller_says_otherwise() {
    // §44.5: server-side dry run where the API offers it, and labelled as a prediction rather
    // than an observation (§21.4 of the generic contract). It is the *default* because the
    // shortest sentence a user can write must not be the one that changes a cluster.
    let cluster = RecordedCluster::playing(Scenario::Admission);
    let plugin = loaded(&cluster).await;
    let invocation = plugin.invoke(SET, scale_down(&[])).await.expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    assert_eq!(records.len(), 1);
    let outcome = &records[0];

    assert!(bool_of(outcome, "dry_run"));
    assert_eq!(text(outcome, "acceptance"), "dry run");
    assert!(
        text(outcome, "prediction").contains("dry run"),
        "§21.4: the record labels where the prediction came from: {}",
        text(outcome, "prediction")
    );
    assert_eq!(
        text_of(outcome, "stage"),
        None,
        "a dry run establishes no rung of the ladder: nothing was written (§44.5)"
    );
    assert!(
        text(outcome, "statement").contains("not a proof"),
        "a successful dry run is not a proof of post-apply convergence: {}",
        text(outcome, "statement")
    );
    assert!(
        list_of(outcome, "admission_differences")
            .iter()
            .any(|difference| difference.contains("/spec/replicas") && difference.contains("2")),
        "§44.6: an admission policy took the request's own field and gave it a different value, \
         which is what a dry run is worth reading for: {:?}",
        list_of(outcome, "admission_differences")
    );

    let patches = cluster.requests("PATCH");
    assert_eq!(patches.len(), 1, "one apply, and it was the dry run");
    assert!(
        patches[0].0.contains("dryRun=All"),
        "the server was asked to run admission and write nothing: {}",
        patches[0].0
    );
}

#[tokio::test]
async fn should_send_the_preconditions_the_plan_carries() {
    // §56 on the wire. The plan holds a `resourceVersion` and a UID because the object was read;
    // this is the assertion that they travelled rather than being described and dropped.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(SET, scale_down(&[("dry_run", json!(false))]))
        .await
        .expect("it runs");
    let (_, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let patches = cluster.requests("PATCH");
    assert_eq!(patches.len(), 1);
    let body: Json = serde_json::from_str(&patches[0].1).expect("the apply document is JSON");
    assert_eq!(body["metadata"]["resourceVersion"], json!("4711"));
    assert_eq!(
        body["metadata"]["uid"],
        json!("66666666-6666-6666-6666-666666666666")
    );
    assert_eq!(body["spec"]["replicas"], json!(1));
    assert!(
        patches[0].0.contains("fieldManager=ono-sendai"),
        "§44.2: a stable, identifiable field manager: {}",
        patches[0].0
    );
    assert!(
        !patches[0].0.contains("force"),
        "§44.3: an apply that nobody asked to force carries no `force` at all: {}",
        patches[0].0
    );
    assert!(
        patches[0].0.contains("application/apply-patch+yaml"),
        "§44.1: server-side apply, so field ownership is tracked: {}",
        patches[0].0
    );
}

// --- Gate G ----------------------------------------------------------------------------------------

#[tokio::test]
async fn should_not_report_an_accepted_deployment_update_as_a_completed_rollout() {
    // Gate G (§62.7) and §4 invariant 18. The API server accepted the change and returned the
    // object with the new spec on it. That is one rung of §20.4's ladder and no more: the
    // controller has not observed the generation, so nothing here may read as a rollout.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(SET, scale_down(&[("dry_run", json!(false))]))
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    assert_eq!(records.len(), 1);
    let outcome = &records[0];

    assert_eq!(text(outcome, "acceptance"), "persisted");
    assert_eq!(
        text(outcome, "stage"),
        "API accepted desired-state change",
        "the furthest rung an acceptance establishes"
    );
    assert_eq!(
        text(outcome, "verdict"),
        "inconclusive",
        "one immediate observation found nothing decisive, and that is neither success nor \
         failure (§46.4)"
    );
    let detail = text(outcome, "verification_detail");
    assert!(
        detail.contains("not evidence that the change failed")
            && detail.contains("not evidence that it succeeded"),
        "§46.4's fourth answer, in as many words: {detail}"
    );
    let statement = text(outcome, "statement");
    for forbidden in ["rolled out", "rollout succeeded", "converged", "healthy"] {
        assert!(
            !statement.contains(forbidden),
            "Gate G: an acceptance must not read as `{forbidden}`: {statement}"
        );
    }
    assert!(
        statement.contains("acceptance is not evidence"),
        "and it says so rather than leaving it to be inferred: {statement}"
    );
    let reconciliation = rendered(outcome, "reconciliation");
    assert!(
        reconciliation.contains("desired") || reconciliation.contains("not observed"),
        "the state arrives with the rule that derived it (§37.5): {reconciliation}"
    );
}

// --- conflicts -------------------------------------------------------------------------------------

#[tokio::test]
async fn should_name_the_owning_manager_on_a_conflict_and_never_force() {
    // §44.3: an apply conflict is surfaced with ownership evidence, and Ono MUST NOT force
    // ownership merely to make the action succeed. The second half is what the request count
    // proves: there is one `PATCH`, and no second one with `force=true` behind it.
    let cluster = RecordedCluster::playing(Scenario::Conflict);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(SET, scale_down(&[("dry_run", json!(false))]))
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "a conflict is an answer about the cluster, not a failure of the invocation: {:?}",
        result.error
    );
    let records = records(&events);
    assert_eq!(records.len(), 1);
    let outcome = &records[0];

    assert_eq!(text(outcome, "acceptance"), "conflict");
    assert_eq!(
        text_of(outcome, "stage"),
        None,
        "nothing was written, so no rung was reached"
    );
    assert_eq!(list_of(outcome, "conflict_managers"), vec![OTHER_MANAGER]);
    assert!(
        list_of(outcome, "conflict_fields")
            .iter()
            .any(|field| field.contains("replicas")),
        "the field that could not be taken travels with the conflict"
    );
    assert!(
        text(outcome, "resolution").contains("explicit choice"),
        "§44.4: the resolution is a person's, and there is no automatic one: {}",
        text(outcome, "resolution")
    );
    assert!(!bool_of(outcome, "forced"));

    let patches = cluster.requests("PATCH");
    assert_eq!(
        patches.len(),
        1,
        "a conflict is not retried, with or without force: {patches:?}"
    );
    assert!(
        !patches[0].0.contains("force"),
        "nothing forced: {}",
        patches[0].0
    );
}

#[tokio::test]
async fn should_force_only_when_a_reason_was_given() {
    // §44.4: forcing, where it is exposed at all, is a separate explicit choice — so the
    // argument is a *reason* rather than a flag. There is no `force: true` to set.
    let cluster = RecordedCluster::playing(Scenario::Conflict);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            scale_down(&[
                ("dry_run", json!(false)),
                (
                    "force_because",
                    json!("the controller was decommissioned this morning"),
                ),
            ]),
        )
        .await
        .expect("it runs");
    let (events, _) = invocation.collect().await;
    let records = records(&events);
    let outcome = &records[0];
    assert!(bool_of(outcome, "forced"));
    assert_eq!(
        text(outcome, "forced_because"),
        "the controller was decommissioned this morning",
        "the reason is what a reviewer reads later, so it is kept rather than counted"
    );
    let patches = cluster.requests("PATCH");
    assert_eq!(
        patches.len(),
        1,
        "still one apply, and it stated its reason"
    );
    assert!(patches[0].0.contains("force=true"), "{}", patches[0].0);
}

// --- Gate H ------------------------------------------------------------------------------------------

#[tokio::test]
async fn should_report_a_deletion_with_a_finalizer_as_terminating_rather_than_deleted() {
    // Gate H (§62.8) and §45.1. The API server accepted the delete and answered with the object:
    // a `deletionTimestamp` is set and a finalizer is still holding it. The object is *there*.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            REMOVE,
            at_cluster(&[
                ("kind", json!("PersistentVolumeClaim")),
                ("name", json!("data")),
                ("namespace", json!("default")),
                ("dry_run", json!(false)),
            ]),
        )
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    assert_eq!(records.len(), 1);
    let outcome = &records[0];

    assert_eq!(text(outcome, "action"), "delete");
    assert_eq!(
        text(outcome, "deletion_state"),
        "terminating; deletion is pending",
        "Gate H: accepted with a finalizer is terminating, never deleted"
    );
    assert_eq!(
        list_of(outcome, "finalizers"),
        vec!["kubernetes.io/pvc-protection"],
        "§45.3: what deletion is waiting for"
    );
    let statement = text(outcome, "statement");
    assert!(
        !statement.contains("deleted"),
        "Gate H: the word this must not produce: {statement}"
    );
    assert!(
        statement.contains("external effects outside the API server are unknown"),
        "§45.5: no promise about the volume behind the claim: {statement}"
    );
    assert_eq!(
        text(outcome, "verdict"),
        "inconclusive",
        "the object is still present, so absence has not been established — and one immediate \
         look is not a wait, so this is not `pending` either (§46.4)"
    );
    assert!(
        text(outcome, "verification_detail").contains("finalizer"),
        "and the evidence says what is holding it: {}",
        text(outcome, "verification_detail")
    );
    let deletes = cluster.requests("DELETE");
    assert_eq!(deletes.len(), 1);
    let body: Json = serde_json::from_str(&deletes[0].1).expect("DeleteOptions is JSON");
    assert_eq!(
        body["preconditions"]["uid"],
        json!("88888888-8888-8888-8888-888888888888"),
        "§56.3: a UID precondition stops a delete landing on a recreated object of the same name"
    );
    assert_eq!(body["propagationPolicy"], json!("Background"));
}

#[tokio::test]
async fn should_call_an_object_absent_only_when_a_read_established_it() {
    // The other half of §45.1: a delete nothing holds, followed by a read that finds the object
    // gone. `Absent` is the only state a *read* may set, and the verification rule for a
    // deletion is exactly that.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            REMOVE,
            at_cluster(&[
                ("kind", json!("ConfigMap")),
                ("name", json!("settings")),
                ("namespace", json!("default")),
                ("dry_run", json!(false)),
            ]),
        )
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let outcome = &records(&events)[0];
    assert_eq!(
        text(outcome, "deletion_state"),
        "the object is absent from the API"
    );
    assert_eq!(text(outcome, "verdict"), "confirmed");
    assert!(
        text(outcome, "verification_detail").contains("effects outside it are unobserved"),
        "an absent object is not a reclaimed volume: {}",
        text(outcome, "verification_detail")
    );
}

#[tokio::test]
async fn should_refuse_a_mutation_the_cluster_does_not_offer_on_that_resource() {
    // §11.5's third state, on the write path: the cluster serves Nodes and offers no `patch` on
    // them. That is not a permission denial and not an absent object, and the refusal says which
    // verb is missing rather than which grant somebody should look for.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("Node")),
                ("name", json!("node-a")),
                ("set", json!({"/spec/unschedulable": true})),
            ]),
        )
        .await
        .expect("it runs");
    let (_, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a refusal carries an error");
    assert!(
        error.message.contains("patch"),
        "the refusal names the verb the cluster does not offer: {}",
        error.message
    );
    assert!(
        cluster.requests("PATCH").is_empty(),
        "and nothing was sent to find out"
    );
}

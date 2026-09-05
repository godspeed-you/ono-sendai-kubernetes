//! The package under the deterministic test host of spec §31.73: a `provider.query` in, records
//! out, over the host's brokered connection.
//!
//! Nothing here talks to a cluster (§59.1). The recorded API server below is a `HostServices`
//! implementation whose `network.connect` hands back a connection that replays bytes — the same
//! path a production host wires to a socket, with the socket replaced. So the whole chain is
//! exercised for real: the handshake, the capability broker, `network.connect`, `streams.emit`
//! and `streams.next` as a byte stream, HTTP/1.1 over it, discovery, the list, the redaction
//! boundary, and the host's own stamp on the provenance of every record it accepts.

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
const PACKAGE: &str = "io.github.godspeed-you.kubernetes";

/// The base64 a Secret's payload is carried in. It must never appear in anything emitted.
const TOKEN_PAYLOAD: &str = "c3VwZXItc2VjcmV0LXRva2Vu";

fn options(pairs: &[(&str, Json)]) -> JsonMap<String, Json> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

/// The options that point a query at the recorded cluster.
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

fn records(events: &[StreamEvent]) -> Vec<Arc<RecordValue>> {
    events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::Value(Value::Record(record)) => Some(Arc::clone(record)),
            StreamEvent::Value(other) => {
                panic!("a provider answers records, and this one answered {other:?}")
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

// --- a certificate authority, and TLS on the wire ----------------------------------------------

/// A certificate authority and the server certificate it signed, generated for the test.
///
/// Generated rather than checked in, so nothing here expires on a date nobody chose.
struct Authority {
    ca_pem: String,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl Authority {
    /// An authority that vouches for `server_name` and nothing else.
    fn issuing(server_name: &str) -> Self {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "recorded cluster authority");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let params = rcgen::CertificateParams::new(vec![server_name.to_owned()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &ca, &ca_key).unwrap();

        Self {
            ca_pem: ca.pem(),
            chain: vec![certificate.der().clone()],
            key: rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        }
    }

    /// The authority as a kubeconfig writes it: base64 of the PEM.
    fn certificate_authority_data(&self) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            self.ca_pem.as_bytes(),
        )
    }

    fn server_config(&self) -> rustls::ServerConfig {
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(self.chain.clone(), self.key.clone_key())
        .unwrap()
    }
}

/// Feeds received TLS bytes into the server session and returns whatever plaintext came out.
fn decrypt(connection: &mut rustls::ServerConnection, bytes: &[u8]) -> Vec<u8> {
    use std::io::Read as _;
    let mut cursor = bytes;
    while !cursor.is_empty() {
        match connection.read_tls(&mut cursor) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if connection.process_new_packets().is_err() {
            return Vec::new();
        }
    }
    let mut plaintext = Vec::new();
    // `WouldBlock` is "nothing decrypted yet", which is every byte of the handshake.
    let _ = connection.reader().read_to_end(&mut plaintext);
    plaintext
}

/// Encrypts the replies and whatever handshake the session still owes.
fn encrypt(connection: &mut rustls::ServerConnection, replies: &[Vec<u8>]) -> Vec<u8> {
    use std::io::Write as _;
    for reply in replies {
        connection.writer().write_all(reply).unwrap();
    }
    let mut outbound = Vec::new();
    while connection.wants_write() {
        if connection.write_tls(&mut outbound).is_err() {
            break;
        }
    }
    outbound
}

/// Writes a kubeconfig into a directory of its own and hands back both paths.
///
/// A real file, because the host reads it through `filesystem.read` against the real filesystem —
/// which is the capability boundary this test exists to exercise.
fn kubeconfig_at(name: &str, document: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "ono-kubernetes-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&directory).expect("the test may write a temporary directory");
    let path = directory.join("config");
    std::fs::write(&path, document).expect("the kubeconfig is written");
    (directory, path)
}

/// A `filesystem.read` grant scoped to one directory, the way an operator scopes one.
fn readable(directory: &std::path::Path) -> JsonMap<String, Json> {
    options(&[("paths", json!([format!("{}/**", directory.display())]))])
}

// --- the recorded cluster ----------------------------------------------------------------------

/// An API server that answers from recorded documents, reached the way a real one is: through
/// the host's `network.connect`.
#[derive(Clone, Default)]
struct RecordedCluster {
    /// How many pods the `default` namespace holds. Two for the ordinary cases; many when a
    /// test needs an answer long enough to cancel in the middle of.
    pods: usize,
    /// Whether the server serves the `apps` group at all. A cluster without it is not an
    /// unusual cluster — it is any cluster whose API surface this build has never seen.
    apps: bool,
    /// The TLS identity this server presents, where it speaks HTTPS at all. `None` is the plain
    /// HTTP/1.1 an API server behind `kubectl proxy` speaks.
    tls: Option<Arc<rustls::ServerConfig>>,
    /// Every request head the server received, so a test can assert what travelled — including
    /// the `Authorization` header, which is the only proof that a credential left the package.
    heads: Arc<std::sync::Mutex<Vec<String>>>,
}

impl std::fmt::Debug for RecordedCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordedCluster")
            .field("pods", &self.pods)
            .field("apps", &self.apps)
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

impl RecordedCluster {
    fn with_pods(pods: usize) -> Arc<Self> {
        Arc::new(Self {
            pods,
            apps: true,
            ..Self::default()
        })
    }

    /// A server that serves no `apps` group, so nothing serves a Deployment.
    fn without_apps() -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: false,
            ..Self::default()
        })
    }

    /// A server that speaks TLS, presenting `authority`'s certificate.
    fn over_tls(authority: &Authority) -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: true,
            tls: Some(Arc::new(authority.server_config())),
            heads: Arc::default(),
        })
    }

    /// Every request head the server has received.
    fn heads(&self) -> Vec<String> {
        self.heads
            .lock()
            .map(|heads| heads.clone())
            .unwrap_or_default()
    }
}

/// One HTTP/1.1 response with a stated length, as a keep-alive connection delivers it.
fn response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn not_found(path: &str) -> Vec<u8> {
    let body = json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Failure",
        "message": format!("the recorded cluster serves no {path}"),
        "reason": "NotFound",
        "code": 404,
    })
    .to_string();
    format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn pod(index: usize) -> Json {
    if index == 0 {
        return json!({
            "metadata": {
                "name": "api-7d9f-abc",
                "namespace": "default",
                "uid": "11111111-1111-1111-1111-111111111111",
                "resourceVersion": "4711",
                "creationTimestamp": "2026-09-01T09:00:00Z",
                "labels": {"app": "api"},
            },
            "spec": {
                "nodeName": "node-a",
                "containers": [{"name": "api"}, {"name": "sidecar"}],
            },
            "status": {
                "phase": "Running",
                "podIP": "10.1.2.3",
                "containerStatuses": [
                    {"name": "api", "restartCount": 2},
                    {"name": "sidecar", "restartCount": 1},
                ],
            },
        });
    }
    json!({
        "metadata": {
            "name": format!("worker-{index}"),
            "namespace": "default",
            "uid": format!("22222222-2222-2222-2222-{index:012}"),
            "resourceVersion": "4712",
            "creationTimestamp": "2026-09-01T09:05:00Z",
            "deletionTimestamp": "2026-09-01T09:06:00Z",
        },
        // Deliberately no `spec.nodeName`, no `status.containerStatuses`: an unscheduled pod has
        // not restarted zero times, it has restarted an unknown number of times.
        "spec": {"containers": [{"name": "worker"}]},
        "status": {"phase": "Pending"},
    })
}

fn document(path: &str, cluster: &RecordedCluster) -> Vec<u8> {
    let pods = cluster.pods;
    let path = path.split('?').next().unwrap_or(path);
    let body = match path {
        "/api" => json!({"kind": "APIVersions", "versions": ["v1"]}),
        "/apis" if !cluster.apps => json!({"kind": "APIGroupList", "groups": []}),
        "/apis" => json!({
            "kind": "APIGroupList",
            "groups": [{
                "name": "apps",
                "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
            }],
        }),
        "/api/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "v1",
            "resources": [
                {"name": "namespaces", "kind": "Namespace", "namespaced": false,
                 "verbs": ["get", "list", "watch"], "shortNames": ["ns"]},
                {"name": "nodes", "kind": "Node", "namespaced": false,
                 "verbs": ["get", "list", "watch"], "shortNames": ["no"]},
                {"name": "pods", "kind": "Pod", "namespaced": true,
                 "verbs": ["get", "list", "watch"], "shortNames": ["po"]},
                {"name": "pods/log", "kind": "Pod", "namespaced": true, "verbs": ["get"]},
                {"name": "secrets", "kind": "Secret", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
            ],
        }),
        "/apis/apps/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "apps/v1",
            "resources": [
                {"name": "deployments", "kind": "Deployment", "namespaced": true,
                 "verbs": ["get", "list", "watch"], "shortNames": ["deploy"]},
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
        "/api/v1/nodes" => json!({
            "kind": "NodeList",
            "apiVersion": "v1",
            "metadata": {"resourceVersion": "9001"},
            "items": [{
                "metadata": {
                    "name": "node-a",
                    "uid": "44444444-4444-4444-4444-444444444444",
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "spec": {},
                "status": {
                    "conditions": [
                        {"type": "MemoryPressure", "status": "False"},
                        {"type": "Ready", "status": "True"},
                    ],
                    "addresses": [
                        {"type": "Hostname", "address": "node-a"},
                        {"type": "InternalIP", "address": "10.0.0.7"},
                    ],
                    "nodeInfo": {"kubeletVersion": "v1.34.2+k0s"},
                },
            }],
        }),
        "/api/v1/namespaces/default/pods" => json!({
            "kind": "PodList",
            "apiVersion": "v1",
            "metadata": {"resourceVersion": "9002"},
            "items": (0..pods).map(pod).collect::<Vec<_>>(),
        }),
        // A second namespace, so that a namespace coming from a kubeconfig context can be told
        // apart from the one a query would have defaulted to (§7.5).
        "/api/v1/namespaces/shop/pods" => json!({
            "kind": "PodList",
            "apiVersion": "v1",
            "metadata": {"resourceVersion": "9005"},
            "items": [{
                "metadata": {
                    "name": "shop-till",
                    "namespace": "shop",
                    "uid": "77777777-7777-7777-7777-777777777777",
                    "resourceVersion": "4713",
                    "creationTimestamp": "2026-09-01T10:00:00Z",
                },
                "spec": {"nodeName": "node-a", "containers": [{"name": "till"}]},
                "status": {"phase": "Running", "podIP": "10.1.2.9"},
            }],
        }),
        "/api/v1/namespaces/default/secrets" => json!({
            "kind": "SecretList",
            "apiVersion": "v1",
            "metadata": {"resourceVersion": "9003"},
            "items": [{
                "metadata": {
                    "name": "api-token",
                    "namespace": "default",
                    "uid": "55555555-5555-5555-5555-555555555555",
                    "creationTimestamp": "2026-08-15T12:00:00Z",
                },
                "type": "Opaque",
                "data": {"token": TOKEN_PAYLOAD, "ca.crt": "Y2EtY2VydA=="},
            }],
        }),
        "/apis/apps/v1/namespaces/default/deployments" => json!({
            "kind": "DeploymentList",
            "apiVersion": "apps/v1",
            "metadata": {"resourceVersion": "9004"},
            "items": [{
                "metadata": {
                    "name": "api",
                    "namespace": "default",
                    "uid": "66666666-6666-6666-6666-666666666666",
                    "generation": 7,
                    "creationTimestamp": "2026-08-20T08:00:00Z",
                },
                "spec": {"replicas": 3},
                "status": {"readyReplicas": 2, "observedGeneration": 6},
            }],
        }),
        _ => return not_found(path),
    };
    response(&body.to_string())
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
            // A TLS server where the cluster has an identity, and nothing at all where it does
            // not. The handshake runs here rather than in a fixture, so the package's own
            // `rustls` session is what is on the other end of it.
            let mut session = cluster.tls.as_ref().map(|config| {
                rustls::ServerConnection::new(Arc::clone(config))
                    .expect("the recorded server configuration is usable")
            });
            let mut buffered: Vec<u8> = Vec::new();
            while let Some(bytes) = written.recv().await {
                let plaintext = match &mut session {
                    None => bytes,
                    Some(connection) => decrypt(connection, &bytes),
                };
                buffered.extend(plaintext);
                let mut replies: Vec<Vec<u8>> = Vec::new();
                // A request head ends at the blank line, and a `GET` carries no body — which is
                // every request this provider makes.
                while let Some(at) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buffered[..at]).into_owned();
                    buffered.drain(..at + 4);
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    if let Ok(mut heads) = cluster.heads.lock() {
                        heads.push(head);
                    }
                    replies.push(document(&path, &cluster));
                }
                let outbound = match &mut session {
                    None => replies.concat(),
                    Some(connection) => encrypt(connection, &replies),
                };
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

/// A loaded instance of the package against a cluster holding `pods` pods.
async fn loaded(pods: usize) -> ono_kuang_supervisor::LoadedPlugin {
    TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(RecordedCluster::with_pods(pods))
        .load()
        .await
        .expect("the package loads under its own manifest")
}

// --- the tests -----------------------------------------------------------------------------

#[tokio::test]
async fn should_answer_a_pod_query_with_records_of_the_declared_schema_and_host_provenance() {
    let plugin = loaded(2).await;
    let invocation = plugin
        .query("k8s-pod", at_cluster(&[]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "a complete listing completes: {:?}",
        result.error
    );
    let records = records(&events);
    assert_eq!(records.len(), 2, "both pods of the namespace arrived");
    for record in &records {
        assert_eq!(
            record.schema_id().to_string(),
            "io.github.godspeed-you.kubernetes.pod/1",
            "the host validates contributed output against the target's declared schema"
        );
        assert_eq!(
            record.provenance().provider(),
            format!("plugin:{PACKAGE}"),
            "provenance is the host's stamp; a package cannot claim another source (§31.80)"
        );
        record
            .validate()
            .expect("the record conforms to the schema it carries");
    }

    let running = &records[0];
    assert_eq!(
        text_of(running, "uid").as_deref(),
        Some("11111111-1111-1111-1111-111111111111"),
        "identity is the uid, not the name (§16.1)"
    );
    assert_eq!(text_of(running, "name").as_deref(), Some("api-7d9f-abc"));
    assert_eq!(text_of(running, "namespace").as_deref(), Some("default"));
    assert_eq!(text_of(running, "api_version").as_deref(), Some("v1"));
    assert_eq!(text_of(running, "kind").as_deref(), Some("Pod"));
    assert_eq!(text_of(running, "phase").as_deref(), Some("Running"));
    assert_eq!(text_of(running, "node").as_deref(), Some("node-a"));
    assert_eq!(text_of(running, "pod_ip").as_deref(), Some("10.1.2.3"));
    assert_eq!(
        running.get("restarts"),
        Some(&Value::Int(3)),
        "the restart count is the sum the object states"
    );
    assert_eq!(
        running.get("terminating"),
        Some(&Value::Bool(false)),
        "no deletion timestamp means deletion was never accepted"
    );

    let pending = &records[1];
    assert_eq!(
        pending.get("node"),
        Some(&Value::Null),
        "an unscheduled pod has no node, and null is what that is"
    );
    assert_eq!(
        pending.get("restarts"),
        Some(&Value::Null),
        "no container statuses means the restart count is unknown, never zero (§4)"
    );
    assert_eq!(
        pending.get("terminating"),
        Some(&Value::Bool(true)),
        "a deletion timestamp means terminating — still there, not deleted (Gate H)"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_answer_every_wired_target_from_the_collection_discovery_names() {
    let plugin = loaded(2).await;
    for (target, schema, expected) in [
        (
            "k8s-namespace",
            "io.github.godspeed-you.kubernetes.namespace/1",
            1,
        ),
        ("k8s-node", "io.github.godspeed-you.kubernetes.node/1", 1),
        ("k8s-pod", "io.github.godspeed-you.kubernetes.pod/1", 2),
        (
            "k8s-deployment",
            "io.github.godspeed-you.kubernetes.deployment/1",
            1,
        ),
        (
            "k8s-secret",
            "io.github.godspeed-you.kubernetes.secret/1",
            1,
        ),
    ] {
        let invocation = plugin
            .query(target, at_cluster(&[]))
            .await
            .unwrap_or_else(|error| panic!("`{target}` is a contributed target: {error:?}"));
        let (events, result) = invocation.collect().await;
        assert_eq!(
            result.status,
            InvokeStatus::Completed,
            "`{target}`: {:?}",
            result.error
        );
        let records = records(&events);
        assert_eq!(records.len(), expected, "`{target}` answered");
        for record in &records {
            assert_eq!(record.schema_id().to_string(), schema);
            record.validate().expect("the record conforms");
        }
    }

    // A cluster-scoped kind is read at cluster scope even though the query named no namespace,
    // and a namespaced one is not: §9.2 forbids inventing a namespace for the first.
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_answer_a_secret_query_with_key_names_and_no_payload_anywhere() {
    let plugin = loaded(2).await;
    let invocation = plugin
        .query("k8s-secret", at_cluster(&[]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed);
    let records = records(&events);
    assert_eq!(records.len(), 1);
    let secret = &records[0];
    assert_eq!(text_of(secret, "name").as_deref(), Some("api-token"));
    assert_eq!(text_of(secret, "secret_type").as_deref(), Some("Opaque"));
    assert_eq!(
        secret.get("keys"),
        Some(&Value::List(
            [
                Value::String("ca.crt".into()),
                Value::String("token".into()),
            ]
            .into()
        )),
        "the key names, sorted, and nothing about their values (§22.2)"
    );

    let rendered = ono_value::to_json_string(&Value::Record(Arc::clone(secret)))
        .expect("a record renders as JSON");
    assert!(
        !rendered.contains(TOKEN_PAYLOAD),
        "the payload must not survive anywhere in the record: {rendered}"
    );
    assert!(
        !rendered.contains("Y2EtY2VydA=="),
        "and neither must the other key's: {rendered}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_refuse_a_query_that_names_no_api_server_rather_than_invent_one() {
    let plugin = loaded(2).await;
    let invocation = plugin
        .query("k8s-pod", options(&[]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert!(records(&events).is_empty(), "nothing was fabricated");
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a structured refusal");
    assert_eq!(error.name, "provider.unavailable");
    assert!(
        error.help.unwrap_or_default().contains("kubectl proxy"),
        "the refusal says what would make the query work"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_stop_promptly_when_the_host_cancels_a_query() {
    // §62.12: a cancelled query terminates promptly. A listing long enough to still be running
    // when the cancellation arrives is the only way to observe that.
    let plugin = loaded(400).await;
    let mut invocation = plugin
        .query("k8s-pod", at_cluster(&[]))
        .await
        .expect("the query starts");
    for _ in 0..3 {
        assert!(
            invocation.next().await.is_some(),
            "the query is answering when it is cancelled"
        );
    }
    invocation.cancel().await;
    let result = invocation.finish().await;
    assert_eq!(
        result.status,
        InvokeStatus::Cancelled,
        "cancellation is observed and answered, never a stream that simply stops (§31.14)"
    );

    // The instance survived its cancellation and still serves.
    let invocation = plugin
        .query("k8s-namespace", at_cluster(&[]))
        .await
        .expect("a later query still works");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed);
    assert_eq!(records(&events).len(), 1);
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_report_an_unserved_api_rather_than_guess_its_collection_path() {
    // §4 invariants 1-2 and §5.2: discovery is authoritative. A build that fell back to
    // `/apis/apps/v1/namespaces/default/deployments` would be making a claim about a cluster it
    // has never seen — and §21.4 keeps "not served" apart from "none exist".
    let plugin = TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(RecordedCluster::without_apps())
        .load()
        .await
        .expect("loads");
    let invocation = plugin
        .query("k8s-deployment", at_cluster(&[]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert!(records(&events).is_empty(), "nothing was invented");
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a structured refusal");
    assert_eq!(error.name, "provider.unsupported");
    assert!(
        error.message.contains("apps"),
        "the refusal names the group nothing serves: {}",
        error.message
    );

    // The pods of the same cluster are still readable: an unserved group is one gap, not a
    // broken provider.
    let invocation = plugin
        .query("k8s-pod", at_cluster(&[]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed);
    assert_eq!(records(&events).len(), 2);
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_refuse_to_reach_the_cluster_without_a_network_connect_grant() {
    // §31.19's floor: deny by default. A provider that could read a cluster without the grant
    // would make the broker decorative.
    let plugin = TestHost::new(PLUGIN, MANIFEST)
        .host(RecordedCluster::with_pods(2))
        .load()
        .await
        .expect("the package loads degraded rather than refusing");
    let invocation = plugin
        .query("k8s-pod", at_cluster(&[]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert!(records(&events).is_empty());
    assert_eq!(result.status, InvokeStatus::Failed);
    assert_eq!(
        result.error.expect("a structured denial").name,
        "capability.denied"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

// --- the kubeconfig path -----------------------------------------------------------------------

#[tokio::test]
async fn should_resolve_a_named_context_through_the_kubeconfig_and_speak_tls_to_its_server() {
    // The whole connection path in one test: a context name in, a kubeconfig read through the
    // host's `filesystem.read`, its server and namespace and certificate authority taken from
    // the file, a real TLS handshake against the certificate that authority signed, and the
    // bearer token on every request that went out (§7.1, §7.4, §7.5, §8.1, §8.4).
    let authority = Authority::issuing("cluster.test");
    let (directory, path) = kubeconfig_at(
        "context",
        &format!(
            r#"
apiVersion: v1
kind: Config
current-context: recorded
clusters:
  - name: recorded
    cluster:
      server: https://cluster.test:6443
      certificate-authority-data: {}
users:
  - {{name: operator, user: {{token: recorded-token}}}}
contexts:
  - {{name: recorded, context: {{cluster: recorded, user: operator, namespace: shop}}}}
"#,
            authority.certificate_authority_data()
        ),
    );
    let cluster = RecordedCluster::over_tls(&authority);
    let plugin = TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .grant_scoped(Capability::FilesystemRead, readable(&directory))
        .host(Arc::clone(&cluster) as Arc<dyn HostServices>)
        .load()
        .await
        .expect("the package loads");

    let invocation = plugin
        .query(
            "k8s-pod",
            options(&[
                ("context", json!("recorded")),
                ("kubeconfig", json!(path.display().to_string())),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    let records = records(&events);

    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    assert_eq!(
        records.len(),
        1,
        "the context's namespace decided what was listed, and `shop` holds one pod"
    );
    assert_eq!(text_of(&records[0], "name").as_deref(), Some("shop-till"));
    assert_eq!(text_of(&records[0], "namespace").as_deref(), Some("shop"));

    let heads = cluster.heads();
    assert!(
        heads.iter().any(|head| head.starts_with("GET /api ")),
        "discovery is asked for first, and it arrived decrypted: {heads:?}"
    );
    assert!(
        heads
            .iter()
            .all(|head| head.contains("Authorization: Bearer recorded-token")),
        "every request carries the context's credential, discovery included: {heads:?}"
    );
    assert!(
        heads
            .iter()
            .any(|head| head.contains("/api/v1/namespaces/shop/pods")),
        "the namespace came from the context rather than from a default: {heads:?}"
    );

    plugin.shutdown(ShutdownReason::Unload).await;
    let _ = std::fs::remove_dir_all(&directory);
}

#[tokio::test]
async fn should_say_that_a_denied_kubeconfig_read_is_a_capability_decision() {
    // §21.4's distinction, applied to configuration: "the host would not let me read the file"
    // and "the file has no such context" are different states, and a refusal that blurs them
    // sends the operator to edit a file that was never opened.
    let (directory, path) = kubeconfig_at(
        "denied",
        r#"
apiVersion: v1
kind: Config
clusters:
  - {name: recorded, cluster: {server: http://cluster.test:8001}}
users:
  - {name: operator, user: {token: t}}
contexts:
  - {name: recorded, context: {cluster: recorded, user: operator}}
"#,
    );
    let plugin = TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(RecordedCluster::with_pods(2))
        .load()
        .await
        .expect("the package loads");

    let invocation = plugin
        .query(
            "k8s-pod",
            options(&[
                ("context", json!("recorded")),
                ("kubeconfig", json!(path.display().to_string())),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;

    assert!(records(&events).is_empty(), "nothing was invented");
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a structured refusal");
    assert_eq!(error.name, "provider.unavailable");
    assert!(
        error.message.contains("refused to read"),
        "the refusal must be about the read, got {}",
        error.message
    );
    assert!(
        !error.message.contains("defines no context"),
        "a denied read is not a missing context, got {}",
        error.message
    );
    assert!(
        error.help.unwrap_or_default().contains("filesystem.read"),
        "the refusal names the capability the operator has to grant"
    );

    plugin.shutdown(ShutdownReason::Unload).await;
    let _ = std::fs::remove_dir_all(&directory);
}

#[tokio::test]
async fn should_refuse_a_context_the_kubeconfig_does_not_define_and_name_the_ones_it_does() {
    let (directory, path) = kubeconfig_at(
        "missing",
        r#"
apiVersion: v1
kind: Config
clusters:
  - {name: recorded, cluster: {server: http://cluster.test:8001}}
users:
  - {name: operator, user: {token: t}}
contexts:
  - {name: recorded, context: {cluster: recorded, user: operator}}
"#,
    );
    let plugin = TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .grant_scoped(Capability::FilesystemRead, readable(&directory))
        .host(RecordedCluster::with_pods(2))
        .load()
        .await
        .expect("the package loads");

    let invocation = plugin
        .query(
            "k8s-pod",
            options(&[
                ("context", json!("staging")),
                ("kubeconfig", json!(path.display().to_string())),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;

    assert!(records(&events).is_empty());
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a structured refusal");
    assert!(
        error.message.contains("staging"),
        "the refusal names the context that was asked for, got {}",
        error.message
    );
    assert!(
        error.help.unwrap_or_default().contains("recorded"),
        "and the ones the file does define"
    );

    plugin.shutdown(ShutdownReason::Unload).await;
    let _ = std::fs::remove_dir_all(&directory);
}

#[tokio::test]
async fn should_refuse_a_context_that_authenticates_through_an_exec_credential_plugin() {
    // §8.2: an exec plugin runs only under an explicit process-execution capability, and the
    // host must honour its interaction mode. This package has neither, so it refuses instead of
    // connecting anonymously — a wrong identity reads as a permission problem on the cluster,
    // and the operator debugs RBAC for something that was never sent.
    let (directory, path) = kubeconfig_at(
        "exec",
        r#"
apiVersion: v1
kind: Config
clusters:
  - {name: managed, cluster: {server: http://cluster.test:8001}}
users:
  - name: managed
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: aws
        args: [eks, get-token]
        interactiveMode: IfAvailable
contexts:
  - {name: managed, context: {cluster: managed, user: managed}}
"#,
    );
    let plugin = TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .grant_scoped(Capability::FilesystemRead, readable(&directory))
        .host(RecordedCluster::with_pods(2))
        .load()
        .await
        .expect("the package loads");

    let invocation = plugin
        .query(
            "k8s-pod",
            options(&[
                ("context", json!("managed")),
                ("kubeconfig", json!(path.display().to_string())),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;

    assert!(records(&events).is_empty(), "nothing was read as somebody");
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a structured refusal");
    assert_eq!(error.name, "provider.unsupported");
    assert!(
        error.message.contains("exec"),
        "the refusal names what it will not do, got {}",
        error.message
    );

    plugin.shutdown(ShutdownReason::Unload).await;
    let _ = std::fs::remove_dir_all(&directory);
}

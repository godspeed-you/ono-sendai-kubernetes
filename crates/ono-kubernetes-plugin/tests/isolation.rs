//! Gate J (§62.10): two kubeconfig contexts, queried **concurrently**, with no cache, credential
//! or namespace crossover.
//!
//! §6.5 is the requirement underneath it: multiple provider instances MUST coexist without
//! resource identity collision, cache collision, watch checkpoint collision, credential leakage
//! or accidental namespace carry-over. Two things now make that worth proving rather than
//! assuming. The package holds a session across invocations (ADR-0021), so there *is* something
//! two queries could share; and since `ADR-0586 (core)` a package answers more than one
//! invocation at a time, so two queries can be inside it at once — which is the word §62.10 uses
//! and the one this file used to be unable to honour.
//!
//! **So this file is written to fail the day a session is keyed on the wrong thing, or reached by
//! two threads that can see each other's.** Two recorded clusters, two certificate authorities,
//! two bearer tokens, two default namespaces and two `kube-system` UIDs, reached through two
//! contexts of one kubeconfig by one loaded instance of the package. Every assertion below is
//! about something a shared, wrongly-keyed cache would break:
//!
//! ```text
//! records          each answer holds only its own cluster's object
//! credentials      each server saw only its own token, and never the other's
//! namespaces       each server was asked only about its own default namespace
//! trust            each session verified against only its own authority — a real handshake
//! identity         each answer is its own provider instance, with its own fingerprint
//! order            querying one context does not change what the other answers afterwards
//! overlap          neither invocation could finish before the other had started
//! ```
//!
//! **"At the same time" is a fact here rather than a hope about scheduling.** The credit window
//! is one value, so an invocation that still owes records is stopped inside `emit` and cannot
//! end until this test consumes what it has already sent. Alpha is put in that state *before*
//! beta is asked anything, so beta's whole conversation with its own API server happens inside
//! alpha's invocation — and [`Overlap`], the transcript both recorded servers write to, holds
//! the line-by-line evidence that it did. A package that had gone back to answering one
//! invocation at a time would not pass by luck: it would refuse the second query with
//! `runtime.concurrency_limit` while the first was open.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::sync::{Arc, Mutex};

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

// --- one certificate authority per cluster -----------------------------------------------------

/// An authority that vouches for one server name and nothing else.
///
/// Two of them, one per cluster, so that a session opened against the wrong anchors fails the
/// handshake rather than quietly succeeding. Trust is the part of a provider instance it is
/// easiest to share by accident and hardest to notice having shared.
struct Authority {
    ca_pem: String,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl Authority {
    fn issuing(server_name: &str) -> Self {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("{server_name} authority"),
        );
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

    fn certificate_authority_data(&self) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            self.ca_pem.as_bytes(),
        )
    }

    fn server_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .unwrap(),
        )
    }
}

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
    let _ = connection.reader().read_to_end(&mut plaintext);
    plaintext
}

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

// --- watching two invocations overlap ----------------------------------------------------------

/// One transcript across both recorded servers, with the test's own markers in the same line.
///
/// §62.10 asks for two contexts queried *concurrently*, and `tokio::join!` over two `collect()`
/// calls would only ask the scheduler nicely: the first invocation may finish before the second
/// is dispatched, and the test would pass for a package that answers one invocation at a time.
/// So the overlap is *held* by the credit window (see
/// `should_answer_two_contexts_queried_at_the_same_time_without_crossover`) and *observed* here:
/// every request either server was asked, in order, interleaved with the moments the test
/// reached. A beta request recorded between "alpha delivered its first record" and "alpha
/// delivered its last" happened while alpha's invocation was open, and no scheduling accident
/// can produce that line.
#[derive(Debug, Default)]
struct Overlap {
    entries: Mutex<Vec<String>>,
}

impl Overlap {
    fn note(&self, entry: String) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(entry);
        }
    }

    fn entries(&self) -> Vec<String> {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .unwrap_or_default()
    }

    /// Where `entry` sits in the transcript, for an assertion about what happened before what.
    fn at(entries: &[String], entry: &str) -> usize {
        entries
            .iter()
            .position(|line| line == entry)
            .unwrap_or_else(|| panic!("`{entry}` is not in the transcript: {entries:?}"))
    }
}

// --- two recorded clusters -------------------------------------------------------------------

/// One recorded API server, with everything about it different from the other one's.
struct Cluster {
    /// The name its certificate is issued for, and the host a query connects to.
    server_name: &'static str,
    /// Its `kube-system` namespace UID — §10.2's strongest identifying signal.
    kube_system_uid: &'static str,
    /// Who the API server says the caller is (§8.6).
    identity: &'static str,
    /// The namespace its context defaults to. A query that reached the other cluster's would be
    /// §6.5's "accidental namespace carry-over".
    namespace: &'static str,
    /// The Pods it holds, named so that an answer from the wrong cluster is unmistakable.
    ///
    /// More than one where a test needs the answer to be *held open*: a handler that still owes
    /// records is an invocation that cannot end until the host grants it credit, which is how
    /// this file keeps two of them open at the same time without a clock.
    pods: &'static [&'static str],
    /// The bearer token its context carries. It must never appear on the other server.
    token: &'static str,
    tls: Arc<rustls::ServerConfig>,
    /// Every request head this server received, decrypted — the only place a leaked credential
    /// or a carried-over namespace can be observed rather than inferred.
    heads: Arc<Mutex<Vec<String>>>,
    /// The transcript both servers share, when a test needs to see the two queries overlap.
    watching: Option<Arc<Overlap>>,
}

impl Cluster {
    fn heads(&self) -> Vec<String> {
        self.heads
            .lock()
            .map(|heads| heads.clone())
            .unwrap_or_default()
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

    /// What this server answers, which mentions nothing about the other one.
    fn document(&self, method: &str, path: &str) -> Vec<u8> {
        let path = path.split('?').next().unwrap_or(path);
        let pods = format!("/api/v1/namespaces/{}/pods", self.namespace);
        let body = match (method, path) {
            ("GET", "/version") => json!({
                "major": "1", "minor": "34", "gitVersion": "v1.34.2+k0s",
            }),
            ("GET", "/api") => json!({"kind": "APIVersions", "versions": ["v1"]}),
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
                    "uid": self.kube_system_uid,
                    "creationTimestamp": "2026-01-01T00:00:00Z",
                },
                "status": {"phase": "Active"},
            }),
            ("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews") => {
                return Self::created(
                    &json!({
                        "apiVersion": "authentication.k8s.io/v1",
                        "kind": "SelfSubjectReview",
                        "status": {"userInfo": {
                            "username": self.identity,
                            "groups": ["system:authenticated"],
                        }},
                    })
                    .to_string(),
                );
            }
            ("GET", other) if other == pods => json!({
                "kind": "PodList",
                "apiVersion": "v1",
                "metadata": {"resourceVersion": "9000"},
                "items": self.pods.iter().map(|pod| json!({
                    "metadata": {
                        "name": pod,
                        "namespace": self.namespace,
                        "uid": format!("{}-{pod}", self.kube_system_uid),
                        "creationTimestamp": "2026-09-01T09:00:00Z",
                    },
                    "spec": {"containers": [{"name": "app"}]},
                    "status": {"phase": "Running"},
                })).collect::<Vec<_>>(),
            }),
            _ => return Self::not_found(path),
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

/// Two clusters behind one host, told apart by the name the query connected to.
///
/// A single `HostServices`, because Gate J is about one *session* reaching two clusters. Two test
/// hosts would prove that two processes do not share state, which nobody doubted.
#[derive(Clone)]
struct Fleet {
    clusters: Vec<Arc<Cluster>>,
}

impl std::fmt::Debug for Fleet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fleet")
            .field(
                "clusters",
                &self
                    .clusters
                    .iter()
                    .map(|cluster| cluster.server_name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[async_trait::async_trait]
impl HostServices for Fleet {
    async fn network_connect(
        &self,
        host: String,
        _port: u16,
        _protocol: String,
    ) -> Result<Connection, HostError> {
        let Some(cluster) = self
            .clusters
            .iter()
            .find(|cluster| cluster.server_name == host)
            .map(Arc::clone)
        else {
            return Err(HostError::unavailable(
                "no recorded cluster at that address",
            ));
        };
        let (inbound, incoming) = mpsc::channel(64);
        let (outgoing, mut written) = mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            let mut session = rustls::ServerConnection::new(Arc::clone(&cluster.tls))
                .expect("the recorded server configuration is usable");
            let mut buffered: Vec<u8> = Vec::new();
            while let Some(bytes) = written.recv().await {
                buffered.extend(decrypt(&mut session, &bytes));
                let mut replies: Vec<Vec<u8>> = Vec::new();
                for (method, path, head) in requests(&mut buffered) {
                    if let Ok(mut heads) = cluster.heads.lock() {
                        heads.push(head);
                    }
                    if let Some(watching) = &cluster.watching {
                        // Recorded rather than withheld. A server that held its answer back until
                        // the other cluster had been asked would be the obvious way to force an
                        // overlap, and it deadlocks the host: `host_streams_next` fills a brokered
                        // read inside the supervisor's own actor loop, so an unanswered read
                        // stalls every other invocation's host calls too. The credit window holds
                        // the invocations open instead, and this transcript watches it happen.
                        watching.note(format!(
                            "{} asked {}",
                            cluster.server_name,
                            path.split('?').next().unwrap_or(&path)
                        ));
                    }
                    replies.push(cluster.document(&method, &path));
                }
                let outbound = encrypt(&mut session, &replies);
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

// --- the fleet, and the kubeconfig that names it -----------------------------------------------

/// Everything two contexts need to be genuinely two: two authorities, two servers, two tokens,
/// two namespaces, two `kube-system` UIDs and one kubeconfig naming both.
struct Fixture {
    fleet: Fleet,
    alpha: Arc<Cluster>,
    beta: Arc<Cluster>,
    directory: std::path::PathBuf,
    kubeconfig: std::path::PathBuf,
    /// The kubeconfig this fixture wrote, kept so that a test can ask whether the file on disk
    /// is still the one it wrote rather than another fixture's.
    document: String,
    /// The transcript the two clusters share, when this fixture was built to watch two
    /// invocations overlap.
    watching: Option<Arc<Overlap>>,
}

impl Fixture {
    fn build() -> Self {
        Self::build_with(false)
    }

    /// A fixture whose servers share one transcript and hold three Pods each.
    ///
    /// Three rather than one because that is what makes an invocation *holdable*: under a credit
    /// window of one, a handler that still owes records is stopped inside `emit` until the host
    /// grants demand, and demand is granted by consumption. So the test decides when each
    /// invocation may finish, and can decide that neither may until both have started.
    fn watched() -> Self {
        Self::build_with(true)
    }

    fn build_with(watched: bool) -> Self {
        let watching = watched.then(|| Arc::new(Overlap::default()));
        let alpha_authority = Authority::issuing("alpha.test");
        let beta_authority = Authority::issuing("beta.test");
        let alpha = Arc::new(Cluster {
            server_name: "alpha.test",
            kube_system_uid: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            identity: "alice@alpha.example",
            namespace: "shop",
            pods: if watched {
                &["alpha-till", "alpha-scanner", "alpha-scales"]
            } else {
                &["alpha-till"]
            },
            token: "alpha-token",
            tls: alpha_authority.server_config(),
            heads: Arc::default(),
            watching: watching.clone(),
        });
        let beta = Arc::new(Cluster {
            server_name: "beta.test",
            kube_system_uid: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            identity: "bob@beta.example",
            namespace: "warehouse",
            pods: if watched {
                &["beta-forklift", "beta-pallet", "beta-crane"]
            } else {
                &["beta-forklift"]
            },
            token: "beta-token",
            tls: beta_authority.server_config(),
            heads: Arc::default(),
            watching: watching.clone(),
        });

        let document = format!(
            r#"
apiVersion: v1
kind: Config
clusters:
  - name: alpha
    cluster:
      server: https://alpha.test:6443
      certificate-authority-data: {}
  - name: beta
    cluster:
      server: https://beta.test:6443
      certificate-authority-data: {}
users:
  - {{name: alice, user: {{token: {}}}}}
  - {{name: bob, user: {{token: {}}}}}
contexts:
  - {{name: alpha, context: {{cluster: alpha, user: alice, namespace: {}}}}}
  - {{name: beta, context: {{cluster: beta, user: bob, namespace: {}}}}}
"#,
            alpha_authority.certificate_authority_data(),
            beta_authority.certificate_authority_data(),
            alpha.token,
            beta.token,
            alpha.namespace,
            beta.namespace,
        );
        let directory = std::env::temp_dir().join(temporary_directory_name());
        // `create_dir` rather than `create_dir_all`: the name has to be this fixture's alone, and
        // the difference between the two is whether that is checked or assumed. `create_dir_all`
        // accepts a directory somebody else already made, which is how a name collision turns
        // into two tests sharing one kubeconfig instead of into a failure that names itself.
        std::fs::create_dir(&directory)
            .expect("the temporary directory of this fixture is not another fixture's");
        let kubeconfig = directory.join("config");
        std::fs::write(&kubeconfig, &document).expect("the kubeconfig is written");

        Self {
            fleet: Fleet {
                clusters: vec![Arc::clone(&alpha), Arc::clone(&beta)],
            },
            alpha,
            beta,
            directory,
            kubeconfig,
            document,
            watching,
        }
    }

    /// Writes the test's own marker into the transcript the two servers are writing.
    fn note(&self, entry: &str) {
        if let Some(watching) = &self.watching {
            watching.note(entry.to_owned());
        }
    }

    /// Every request either server was asked, and every marker the test wrote, in order.
    fn transcript(&self) -> Vec<String> {
        self.watching
            .as_ref()
            .map(|watching| watching.entries())
            .unwrap_or_default()
    }

    async fn loaded(&self) -> ono_kuang_supervisor::LoadedPlugin {
        self.loaded_with_credit(HostLimits::default().queue_depth)
            .await
    }

    /// The same instance under a credit window of one value.
    ///
    /// This is the mechanism §62.10's "concurrently" rests on. With one value of credit a handler
    /// emits one record and then waits inside `emit` for demand, holding no host call open while
    /// it waits — so the supervisor stays free to dispatch the *other* invocation, and the test
    /// decides when either may finish (`ADR-0586 (core)` §1, §5).
    async fn loaded_holding_records(&self) -> ono_kuang_supervisor::LoadedPlugin {
        self.loaded_with_credit(1).await
    }

    async fn loaded_with_credit(&self, queue_depth: u32) -> ono_kuang_supervisor::LoadedPlugin {
        let readable = options(&[("paths", json!([format!("{}/**", self.directory.display())]))]);
        // The default host call deadline is five seconds, and this suite reads a recorded
        // cluster over several round trips. Under a loaded machine — the whole workspace suite
        // running beside it — a call can exceed that, the `kube-system` read fails, and the
        // cluster diagnostic correctly degrades its fingerprint signal to unavailable. That is
        // the product behaving as §10.2 requires, and it makes this test measure the machine
        // rather than the isolation it exists to prove. A generous deadline removes the timing
        // from the question; nothing here is testing how fast a host answers.
        let limits = HostLimits {
            call_deadline_ms: 120_000,
            queue_depth,
            ..HostLimits::default()
        };
        TestHost::new(PLUGIN, MANIFEST)
            .grant(Capability::NetworkConnect)
            .grant_scoped(Capability::FilesystemRead, readable)
            .host(Arc::new(self.fleet.clone()) as Arc<dyn HostServices>)
            .limits(limits)
            .load()
            .await
            .expect("the package loads under its own manifest")
    }

    /// The options that reach one cluster through its own context and nothing else.
    fn context(&self, name: &str) -> JsonMap<String, Json> {
        options(&[
            ("context", json!(name)),
            ("kubeconfig", json!(self.kubeconfig.display().to_string())),
        ])
    }

    fn discard(&self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// A directory name no other fixture in this process can take.
///
/// It used to be the process id and a nanosecond clock reading, and that is not a unique name.
/// The three tests in this file run on three threads of *one* process, so the process id tells
/// them apart not at all, and `SystemTime` is only as fine as the host's clock: on a Hyper-V
/// guest it advances in steps of 100 nanoseconds, and two fixtures that reach this line in the
/// same step get the same name. Both then wrote their kubeconfig to the same path, and whichever
/// test read it afterwards got the *other* test's certificate authority — issued for the same
/// server name, so carrying the same issuer name, and holding a different key. The handshake
/// that followed failed with `BadSignature` in a test that had nothing wrong with it, one run in
/// four under a loaded machine. A counter cannot tie, so it is the counter that makes the name
/// unique; the clock and the process id stay only to keep a leftover directory from an earlier
/// run out of the way.
fn temporary_directory_name() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "ono-kubernetes-isolation-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}

/// Whatever `cluster` was asked, as one blob a test can search for what should not be in it.
fn transcript(cluster: &Cluster) -> String {
    cluster.heads().join("\n")
}

// --- the tests ---------------------------------------------------------------------------------

/// The three tests below build their fixtures on three threads at once, and each fixture's
/// kubeconfig must survive that.
///
/// This is a regression test with a history. The temporary directory used to be named after the
/// process id and a nanosecond clock reading; the process id is the same for all three tests,
/// and the clock on a Hyper-V guest advances in steps of 100 nanoseconds, so two fixtures
/// regularly got the same name. Both wrote `config` there, and the test that read it afterwards
/// got the other one's `certificate-authority-data`: a different key under the same issuer name,
/// because [`Authority::issuing`] names its authority after the server. The handshake then failed
/// with `invalid peer certificate: BadSignature` — in whichever test lost the race, against a
/// cluster that was serving a perfectly valid certificate, about one full-workspace run in four.
///
/// So the assertion is the invariant that was broken rather than the symptom it produced: names
/// that cannot collide, and a kubeconfig on disk that is still the one this fixture wrote.
#[test]
fn should_give_every_fixture_a_kubeconfig_no_other_fixture_can_overwrite() {
    const THREADS: usize = 3;
    const NAMES_PER_THREAD: usize = 200;

    // The names first, and many of them, because one name per thread would only have caught the
    // old scheme a few runs in a hundred. Three threads asking for two hundred names each
    // collided dozens of times on every measured run.
    let naming: Vec<Vec<String>> = (0..THREADS)
        .map(|_| {
            std::thread::spawn(|| {
                (0..NAMES_PER_THREAD)
                    .map(|_| temporary_directory_name())
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| thread.join().expect("the naming thread finishes"))
        .collect();
    let names: std::collections::HashSet<&String> = naming.iter().flatten().collect();
    assert_eq!(
        names.len(),
        THREADS * NAMES_PER_THREAD,
        "two concurrent fixtures were given the same temporary directory, and the second one \
         to write its kubeconfig there would decide which certificate authority the first \
         one trusts"
    );

    // And then the thing that actually matters: a fixture's kubeconfig is still its own.
    let fixtures: Vec<Fixture> = (0..THREADS)
        .map(|_| std::thread::spawn(Fixture::build))
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| thread.join().expect("the fixture builds"))
        .collect();
    for fixture in &fixtures {
        let on_disk = std::fs::read_to_string(&fixture.kubeconfig).expect("the kubeconfig is read");
        assert_eq!(
            on_disk, fixture.document,
            "another fixture wrote over this one's kubeconfig, so the certificate authority \
             it names is not the one this fixture's servers are issued by"
        );
    }
    for fixture in fixtures {
        fixture.discard();
    }
}

#[tokio::test]
async fn should_answer_two_contexts_queried_at_the_same_time_without_crossover() {
    // Gate J (§62.10) as worded, and §6.5 underneath it: two contexts, **concurrently**, on one
    // loaded instance of the package.
    //
    // **What makes this concurrent rather than hopeful.** The credit window is one value, so a
    // handler that has emitted a record and still owes two is stopped inside `emit` until the
    // host grants demand — and demand is granted by consumption, which this test controls. So
    // alpha is *held open* before beta is asked for anything: its invocation cannot end, and it
    // holds no host call open while it waits, which is what leaves the supervisor free to
    // dispatch beta at all (`ADR-0586 (core)` §1). Beta's entire conversation with its own API
    // server therefore happens inside alpha's invocation, and the transcript both servers share
    // says so line by line.
    //
    // A recorded server that withheld its answer until both clusters had been asked would be the
    // more obvious way to force the overlap, and it does not work: `host_streams_next` fills a
    // brokered read inside the supervisor's own actor loop, so a read nobody answers stalls every
    // other invocation's host calls with it. Credit is the mechanism that holds an invocation
    // open *without* holding the host.
    //
    // What the package brings to the overlap is one session registry reached by two workers at
    // once. The registry is locked to look a session up and unlocked before the invocation uses
    // it, so two queries genuinely overlap; each session is then locked by the invocation that
    // claimed it, and the key that finds it is the provider instance, the resolved endpoint and
    // the transport posture (ADR-0021). Two threads cannot reach one session by two keys, which
    // is what "no cache crossover" means once there are threads.
    let fixture = Fixture::watched();
    let plugin = fixture.loaded_holding_records().await;

    let mut alpha = plugin
        .query("k8s-pod", fixture.context("alpha"))
        .await
        .expect("the alpha query starts");
    let alpha_first = alpha
        .next()
        .await
        .expect("alpha delivers a record, so its invocation is running");
    fixture.note("alpha delivered its first record");

    // Alpha is now open and cannot close: it owes records it has no credit to send. Everything
    // beta does from here happens while alpha's invocation is alive.
    let mut beta = plugin
        .query("k8s-pod", fixture.context("beta"))
        .await
        .expect("a second invocation is accepted while the first one is still open");
    let beta_first = beta
        .next()
        .await
        .expect("beta delivers a record while alpha is still holding its own");
    fixture.note("beta delivered its first record");

    let ((alpha_rest, alpha_result), (beta_rest, beta_result)) =
        tokio::join!(alpha.collect(), beta.collect());
    let alpha_events: Vec<StreamEvent> = std::iter::once(alpha_first).chain(alpha_rest).collect();
    let beta_events: Vec<StreamEvent> = std::iter::once(beta_first).chain(beta_rest).collect();
    assert_eq!(
        alpha_result.status,
        InvokeStatus::Completed,
        "{:?}",
        alpha_result.error
    );
    assert_eq!(
        beta_result.status,
        InvokeStatus::Completed,
        "{:?}",
        beta_result.error
    );

    // --- overlap: beta was asked and answered inside alpha's invocation ---
    let seen = fixture.transcript();
    let alpha_holding = Overlap::at(&seen, "alpha delivered its first record");
    let beta_holding = Overlap::at(&seen, "beta delivered its first record");
    let beta_asked: Vec<usize> = seen
        .iter()
        .enumerate()
        .filter_map(|(at, line)| line.starts_with("beta.test asked").then_some(at))
        .collect();
    assert!(
        !beta_asked.is_empty(),
        "beta's server was never asked anything: {seen:?}"
    );
    assert!(
        beta_asked.iter().all(|at| *at > alpha_holding),
        "beta's requests were expected inside alpha's invocation, and one of them is not: {seen:?}"
    );
    assert!(
        beta_asked.iter().all(|at| *at < beta_holding),
        "beta answered before it asked, which is not a transcript of a query: {seen:?}"
    );
    assert_eq!(
        records(&alpha_events).len(),
        3,
        "alpha delivered every record it owed, so it was still owing them — still open — while \
         beta was being asked and answered"
    );

    // --- records: each answer is its own cluster's ---
    let alpha_records = records(&alpha_events);
    let beta_records = records(&beta_events);
    assert_eq!(alpha_records.len(), 3, "alpha holds three pods");
    assert_eq!(beta_records.len(), 3, "beta holds three pods");
    let names = |answer: &[Arc<RecordValue>]| {
        let mut names: Vec<String> = answer
            .iter()
            .filter_map(|record| text_of(record, "name"))
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        names(&alpha_records),
        vec![
            "alpha-scales".to_owned(),
            "alpha-scanner".to_owned(),
            "alpha-till".to_owned(),
        ],
    );
    assert_eq!(
        names(&beta_records),
        vec![
            "beta-crane".to_owned(),
            "beta-forklift".to_owned(),
            "beta-pallet".to_owned(),
        ],
    );
    for record in &alpha_records {
        assert_eq!(
            text_of(record, "namespace").as_deref(),
            Some("shop"),
            "each context's own default namespace decided its scope (§7.5)"
        );
    }
    for record in &beta_records {
        assert_eq!(text_of(record, "namespace").as_deref(), Some("warehouse"));
    }
    let identities = |answer: &[Arc<RecordValue>]| {
        answer
            .iter()
            .filter_map(|record| text_of(record, "uid"))
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert!(
        identities(&alpha_records).is_disjoint(&identities(&beta_records)),
        "§6.5: no resource identity collision between two instances"
    );

    // --- provenance: each record says which provider instance observed it ---
    for (answer, instance) in [
        (&alpha_records, "kubernetes:alpha"),
        (&beta_records, "kubernetes:beta"),
    ] {
        for record in answer.iter() {
            let source = record.provenance().source().unwrap_or_default().to_owned();
            assert!(
                source.contains(&format!("provider_instance={instance}")),
                "a record carries the instance that read it, so two answers cannot be confused \
                 downstream: {source}"
            );
        }
    }

    // --- credentials: §6.5's "credential leakage", observed rather than argued ---
    let alpha_seen = transcript(&fixture.alpha);
    let beta_seen = transcript(&fixture.beta);
    assert!(
        alpha_seen.contains("Authorization: Bearer alpha-token"),
        "alpha was reached with alpha's credential: {alpha_seen}"
    );
    assert!(
        beta_seen.contains("Authorization: Bearer beta-token"),
        "beta was reached with beta's credential: {beta_seen}"
    );
    assert!(
        !alpha_seen.contains("beta-token"),
        "beta's credential must never reach alpha's API server: {alpha_seen}"
    );
    assert!(
        !beta_seen.contains("alpha-token"),
        "and alpha's must never reach beta's: {beta_seen}"
    );

    // Every request head, not merely one of them. This is the assertion two invocations at once
    // could break that one invocation could not: each request each server saw was authorised
    // with that context's own credential, so no invocation was answered with a credential
    // another invocation had resolved (§8.1).
    for (name, cluster, token) in [
        ("alpha", &fixture.alpha, "alpha-token"),
        ("beta", &fixture.beta, "beta-token"),
    ] {
        for head in cluster.heads() {
            assert!(
                head.contains(&format!("Authorization: Bearer {token}")),
                "{name} saw a request with no credential of its own on it while two invocations \
                 were open: {head}"
            );
        }
    }

    // --- namespaces: §6.5's "accidental namespace carry-over" ---
    assert!(
        alpha_seen.contains("/api/v1/namespaces/shop/pods"),
        "alpha was asked about its own namespace: {alpha_seen}"
    );
    assert!(
        !alpha_seen.contains("warehouse"),
        "and never about beta's: {alpha_seen}"
    );
    assert!(
        beta_seen.contains("/api/v1/namespaces/warehouse/pods"),
        "beta was asked about its own namespace: {beta_seen}"
    );
    assert!(
        !beta_seen.contains("shop"),
        "and never about alpha's: {beta_seen}"
    );

    // --- trust: each handshake happened, against that cluster's own authority ---
    // A decrypted request head is proof of a completed handshake: nothing readable arrives
    // through a session that was never established. Two authorities means a session opened with
    // the wrong anchors would have produced no transcript at all.
    assert!(
        !fixture.alpha.heads().is_empty() && !fixture.beta.heads().is_empty(),
        "both sessions verified their own server against their own context's authority"
    );

    // --- no object of one cluster appears anywhere in the other's answer ---
    // Field by field rather than through the fields this test happens to name: a crossover that
    // put one of beta's pods into an alpha record would be caught wherever in the record it
    // landed.
    let alpha_text = format!("{alpha_records:?}");
    let beta_text = format!("{beta_records:?}");
    for (name, answer, foreign) in [
        (
            "alpha",
            &alpha_text,
            ["beta-forklift", "warehouse", "bbbbbbbb"],
        ),
        ("beta", &beta_text, ["alpha-till", "shop", "aaaaaaaa"]),
    ] {
        for word in foreign {
            assert!(
                !answer.contains(word),
                "`{word}` is the other cluster's and it reached {name}'s answer: {answer}"
            );
        }
    }

    // --- afterwards: a concurrent partner leaves nothing behind ---
    // The two invocations shared a process, a registry and a moment. Asked again on its own,
    // each context answers exactly what it answered while the other one was running — §6.5 put
    // as a question about time rather than about structure.
    for (context, expected) in [
        ("alpha", names(&alpha_records)),
        ("beta", names(&beta_records)),
    ] {
        let (events, result) = plugin
            .query("k8s-pod", fixture.context(context))
            .await
            .expect("the query starts")
            .collect()
            .await;
        assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
        assert_eq!(
            names(&records(&events)),
            expected,
            "`{context}` answers what it answered beside another context, and nothing the other \
             one read"
        );
    }

    plugin.shutdown(ShutdownReason::Unload).await;
    fixture.discard();
}

#[tokio::test]
async fn should_give_each_context_its_own_instance_identity_and_cluster_fingerprint() {
    // §10.1 and §10.3 under Gate J: the diagnostic is what makes isolation *inspectable* rather
    // than merely true. Two contexts, two identities, two fingerprints, and no operation
    // anywhere that would fold them into one.
    //
    // One at a time, deliberately, and the reason is worth writing down. A diagnostic answers
    // exactly one record, so there is no second record for a credit window to hold it on — the
    // mechanism that makes `should_answer_two_contexts_queried_at_the_same_time_without_crossover`
    // provably concurrent does not reach this shape of answer. Two `k8s-cluster` queries of one
    // *instance* would also be two invocations of one session, and those take turns by design
    // (ADR-0026). What this test is for is what the two answers *say*, and that does not depend
    // on when they were read.
    let fixture = Fixture::build();
    let plugin = fixture.loaded().await;

    let mut answers = Vec::new();
    for context in ["alpha", "beta"] {
        let invocation = plugin
            .query("k8s-cluster", fixture.context(context))
            .await
            .expect("the query starts");
        let (events, result) = invocation.collect().await;
        assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
        let records = records(&events);
        assert_eq!(records.len(), 1, "one provider instance, one record");
        answers.push(Arc::clone(&records[0]));
    }

    let (alpha, beta) = (&answers[0], &answers[1]);
    assert_eq!(text_of(alpha, "uid").as_deref(), Some("kubernetes:alpha"));
    assert_eq!(text_of(beta, "uid").as_deref(), Some("kubernetes:beta"));
    assert_eq!(
        text_of(alpha, "kube_system_uid").as_deref(),
        Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        "each instance read its own cluster's identifying signal"
    );
    assert_eq!(
        text_of(beta, "kube_system_uid").as_deref(),
        Some("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    );
    assert_ne!(
        text_of(alpha, "fingerprint"),
        text_of(beta, "fingerprint"),
        "two clusters fingerprint differently — a shared, wrongly-keyed cache would show here \
         first (§10.4)"
    );
    assert_eq!(
        text_of(alpha, "effective_identity").as_deref(),
        Some("alice@alpha.example"),
        "each session is who its own credential is (§8.6)"
    );
    assert_eq!(
        text_of(beta, "effective_identity").as_deref(),
        Some("bob@beta.example")
    );
    assert_eq!(
        text_of(alpha, "server").as_deref(),
        Some("https://alpha.test:6443")
    );
    assert_eq!(
        text_of(beta, "server").as_deref(),
        Some("https://beta.test:6443")
    );

    plugin.shutdown(ShutdownReason::Unload).await;
    fixture.discard();
}

#[tokio::test]
async fn should_answer_a_context_the_same_way_whatever_ran_before_it() {
    // The shape a cache bug takes: the first query fills something, and the second reads it. So
    // the same question is asked twice with the other cluster's query in between, and the two
    // answers have to be identical — including the identity, which is where a cache keyed on the
    // kind rather than on the provider instance would go wrong (§6.5, §12.4, §20.1).
    let fixture = Fixture::build();
    let plugin = fixture.loaded().await;

    let mut alpha_answers = Vec::new();
    for context in ["alpha", "beta", "alpha"] {
        let invocation = plugin
            .query("k8s-pod", fixture.context(context))
            .await
            .expect("the query starts");
        let (events, result) = invocation.collect().await;
        assert_eq!(
            result.status,
            InvokeStatus::Completed,
            "`{context}`: {:?}",
            result.error
        );
        let records = records(&events);
        assert_eq!(records.len(), 1);
        if context == "alpha" {
            alpha_answers.push((
                text_of(&records[0], "name"),
                text_of(&records[0], "namespace"),
                text_of(&records[0], "uid"),
            ));
        }
    }

    assert_eq!(
        alpha_answers[0], alpha_answers[1],
        "alpha answers the same before and after beta was queried"
    );
    assert_eq!(
        alpha_answers[0].0.as_deref(),
        Some("alpha-till"),
        "and it is alpha's own object rather than whatever ran last"
    );
    assert!(
        !transcript(&fixture.alpha).contains("beta-token"),
        "no credential survived the query that used it"
    );

    plugin.shutdown(ShutdownReason::Unload).await;
    fixture.discard();
}

/// How many times `cluster` was asked for `path`.
fn asked_for(cluster: &Cluster, path: &str) -> usize {
    cluster
        .heads()
        .iter()
        .filter(|head| {
            head.split_whitespace()
                .nth(1)
                .is_some_and(|target| target.split('?').next() == Some(path))
        })
        .count()
}

#[tokio::test]
async fn should_hold_one_session_per_context_and_nothing_between_two() {
    // §6.5 with a session in the picture, which is the case this file was written to fail on.
    // Until now nothing was shared between two queries, so nothing *could* cross over; the
    // package now keeps discovery, the published schemas, the cluster fingerprint and the watch
    // registry across invocations, and every one of those is a thing that crosses if it is keyed
    // on the wrong noun.
    //
    // Three queries — alpha, beta, alpha — and the questions the servers were asked are the
    // evidence. Alpha's second query costs it no discovery, so a session exists; beta's first
    // query costs it a full discovery even though alpha had just paid for one, so the session is
    // alpha's rather than the package's.
    let fixture = Fixture::build();
    let plugin = fixture.loaded().await;

    for context in ["alpha", "beta", "alpha"] {
        let (events, result) = plugin
            .query("k8s-pod", fixture.context(context))
            .await
            .expect("the query starts")
            .collect()
            .await;
        assert_eq!(
            result.status,
            InvokeStatus::Completed,
            "`{context}`: {:?}",
            result.error
        );
        assert_eq!(records(&events).len(), 1, "`{context}` holds one pod");
    }

    for (name, cluster, pods) in [("alpha", &fixture.alpha, 2), ("beta", &fixture.beta, 1)] {
        assert_eq!(
            asked_for(cluster, "/api"),
            1,
            "{name} was asked what it serves once, however many queries it answered — the \
             session is keyed on the provider instance and survives the invocation (§6.3, §50.2)"
        );
        assert_eq!(
            asked_for(cluster, "/api/v1"),
            1,
            "{name}'s resource list likewise"
        );
        assert_eq!(
            asked_for(
                cluster,
                &format!("/api/v1/namespaces/{}/pods", cluster.namespace)
            ),
            pods,
            "{name}'s objects are read every time it is asked, because a session caches what a \
             cluster is and never what is in it"
        );
    }

    // The discovery beta paid for is beta's: alpha's session did not answer it, and alpha's
    // session was not filled by it. The strongest form of that here is that beta was asked at
    // all — a shared, wrongly-keyed cache would have answered beta from alpha's snapshot, and
    // beta's server would show no discovery request whatsoever.
    assert!(
        asked_for(&fixture.beta, "/api") == 1 && asked_for(&fixture.beta, "/apis") == 1,
        "beta discovered its own cluster rather than inheriting alpha's snapshot (§6.5)"
    );

    // §8.1 and §6.5's credential prohibition, now that something *does* live across a call: the
    // credential is not one of the things that does. Every request alpha's server saw carries
    // alpha's own token, including the ones from the second query, which proves the credential
    // was resolved again from the kubeconfig rather than taken from a session.
    for (name, cluster, token, other) in [
        ("alpha", &fixture.alpha, "alpha-token", "beta-token"),
        ("beta", &fixture.beta, "beta-token", "alpha-token"),
    ] {
        for head in cluster.heads() {
            assert!(
                head.contains(&format!("Authorization: Bearer {token}")),
                "{name} saw a request with no credential of its own on it, so something is \
                 answering from state instead of from the operator's configuration: {head}"
            );
            assert!(
                !head.contains(other),
                "{name} saw the other context's credential: {head}"
            );
        }
    }

    plugin.shutdown(ShutdownReason::Unload).await;
    fixture.discard();
}

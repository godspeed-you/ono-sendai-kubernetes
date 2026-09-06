//! Gate J (§62.10): two kubeconfig contexts, queried in one session, with no cache, credential
//! or namespace crossover.
//!
//! §6.5 is the requirement underneath it: multiple provider instances MUST coexist without
//! resource identity collision, cache collision, watch checkpoint collision, credential leakage
//! or accidental namespace carry-over. Today nothing is shared between two queries of this
//! package — each opens its own connection, resolves its own context and builds its own
//! discovery snapshot — so nothing *can* cross over. That is a good state and a weak proof: an
//! architecture in which crossover is impossible looks exactly like one in which it merely has
//! not happened yet, and §12.4's schema cache and §20's informer cache are both on the roadmap.
//!
//! **So this file is written to fail the day one appears and is keyed on the wrong thing.** Two
//! recorded clusters, two certificate authorities, two bearer tokens, two default namespaces and
//! two `kube-system` UIDs, reached through two contexts of one kubeconfig by one loaded instance
//! of the package. Every assertion below is about something a shared, wrongly-keyed cache would
//! break:
//!
//! ```text
//! records          each answer holds only its own cluster's object
//! credentials      each server saw only its own token, and never the other's
//! namespaces       each server was asked only about its own default namespace
//! trust            each session verified against only its own authority — a real handshake
//! identity         each answer is its own provider instance, with its own fingerprint
//! order            querying one context does not change what the other answers afterwards
//! ```
//!
//! What it does **not** prove is stated where it is proven, in
//! `should_answer_two_contexts_in_one_session_without_crossover`: the KUANG/11 SDK serves one
//! request at a time, so §62.10's word "concurrently" is not reachable against one package
//! instance today. Two queries in one session is the strongest form the protocol allows, and it
//! is the form every shared-state defect would show up in anyway.

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
    /// The one Pod it holds, named so that an answer from the wrong cluster is unmistakable.
    pod: &'static str,
    /// The bearer token its context carries. It must never appear on the other server.
    token: &'static str,
    tls: Arc<rustls::ServerConfig>,
    /// Every request head this server received, decrypted — the only place a leaked credential
    /// or a carried-over namespace can be observed rather than inferred.
    heads: Arc<Mutex<Vec<String>>>,
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
                "items": [{
                    "metadata": {
                        "name": self.pod,
                        "namespace": self.namespace,
                        "uid": format!("{}-pod", self.kube_system_uid),
                        "creationTimestamp": "2026-09-01T09:00:00Z",
                    },
                    "spec": {"containers": [{"name": "app"}]},
                    "status": {"phase": "Running"},
                }],
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
}

impl Fixture {
    fn build() -> Self {
        let alpha_authority = Authority::issuing("alpha.test");
        let beta_authority = Authority::issuing("beta.test");
        let alpha = Arc::new(Cluster {
            server_name: "alpha.test",
            kube_system_uid: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            identity: "alice@alpha.example",
            namespace: "shop",
            pod: "alpha-till",
            token: "alpha-token",
            tls: alpha_authority.server_config(),
            heads: Arc::default(),
        });
        let beta = Arc::new(Cluster {
            server_name: "beta.test",
            kube_system_uid: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            identity: "bob@beta.example",
            namespace: "warehouse",
            pod: "beta-forklift",
            token: "beta-token",
            tls: beta_authority.server_config(),
            heads: Arc::default(),
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
        }
    }

    async fn loaded(&self) -> ono_kuang_supervisor::LoadedPlugin {
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
async fn should_answer_two_contexts_in_one_session_without_crossover() {
    // Gate J (§62.10) and §6.5, on one loaded instance of the package.
    //
    // **What "concurrently" can mean here, measured rather than assumed.** The KUANG/11 SDK
    // serves one request at a time: `Plugin::run_io` reads an envelope, answers it, and reads
    // the next. Opening a second `provider.query` before the first has been drained was tried
    // and does not work — the supervisor quarantines the instance with
    // `runtime.protocol_violation`, because the second request arrives where the package is
    // waiting for the response to one of its own host calls. So two queries against one instance
    // are *sequential in one session*, and that is the strongest form of §62.10 the protocol
    // currently allows. The finding is on the board rather than pinned here, because a test that
    // asserted the violation would make it the contract.
    //
    // The isolation this test proves is therefore about shared state between two reads in one
    // process, which is what §6.5's five prohibitions are about, and it would fail the day a
    // cache, a session or a credential is held across queries and keyed on anything but the
    // provider instance.
    let fixture = Fixture::build();
    let plugin = fixture.loaded().await;

    let (alpha_events, alpha_result) = plugin
        .query("k8s-pod", fixture.context("alpha"))
        .await
        .expect("the alpha query starts")
        .collect()
        .await;
    let (beta_events, beta_result) = plugin
        .query("k8s-pod", fixture.context("beta"))
        .await
        .expect("the beta query starts in the same session")
        .collect()
        .await;
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

    // --- records: each answer is its own cluster's ---
    let alpha_records = records(&alpha_events);
    let beta_records = records(&beta_events);
    assert_eq!(alpha_records.len(), 1, "alpha holds one pod");
    assert_eq!(beta_records.len(), 1, "beta holds one pod");
    assert_eq!(
        text_of(&alpha_records[0], "name").as_deref(),
        Some("alpha-till")
    );
    assert_eq!(
        text_of(&beta_records[0], "name").as_deref(),
        Some("beta-forklift")
    );
    assert_eq!(
        text_of(&alpha_records[0], "namespace").as_deref(),
        Some("shop"),
        "each context's own default namespace decided its scope (§7.5)"
    );
    assert_eq!(
        text_of(&beta_records[0], "namespace").as_deref(),
        Some("warehouse")
    );
    assert_ne!(
        text_of(&alpha_records[0], "uid"),
        text_of(&beta_records[0], "uid"),
        "§6.5: no resource identity collision between two instances"
    );

    // --- provenance: each record says which provider instance observed it ---
    for (record, instance) in [
        (&alpha_records[0], "kubernetes:alpha"),
        (&beta_records[0], "kubernetes:beta"),
    ] {
        let source = record.provenance().source().unwrap_or_default().to_owned();
        assert!(
            source.contains(&format!("provider_instance={instance}")),
            "a record carries the instance that read it, so two answers cannot be confused \
             downstream: {source}"
        );
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

    plugin.shutdown(ShutdownReason::Unload).await;
    fixture.discard();
}

#[tokio::test]
async fn should_give_each_context_its_own_instance_identity_and_cluster_fingerprint() {
    // §10.1 and §10.3 under Gate J: the diagnostic is what makes isolation *inspectable* rather
    // than merely true. Two contexts, two identities, two fingerprints, and no operation
    // anywhere that would fold them into one.
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

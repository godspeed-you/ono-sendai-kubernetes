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
    /// Whether the server serves the two invented API groups of the dynamic tests. Off for the
    /// curated tests, so that adding a CRD to this fixture cannot change what they prove.
    custom: bool,
    /// Whether RBAC refuses `list` on the Pod collection while `get` on one Pod stays allowed.
    /// §60.5's canonical scenario, and the reason a direct lookup is a different request rather
    /// than a shortcut through the listing.
    deny_pod_list: bool,
    /// Whether RBAC refuses `get` on one Pod, which is a refused read and never an absence.
    deny_pod_get: bool,
    /// Whether the server serves the whole Tier 1 operational set of §15.2, rather than the
    /// five kinds the earlier tests need. Off by default so that adding a kind to this fixture
    /// cannot change what those tests prove.
    tier_one: bool,
    /// Whether the objects are the richer ones the relationship tests read: a Pod that states
    /// an owner, a node, an account, a config and a secret, and a second Pod the Service's
    /// selector deliberately excludes. Layered over `tier_one` rather than replacing it, and off
    /// by default so that giving the Pod an owner cannot change what the projection tests prove.
    relations: bool,
    /// Which watch script this server plays, where it serves a watch at all (§19).
    watch: Watching,
    /// How many times the Pod collection has been listed, so that a re-acquisition after a gap
    /// answers with the state the cluster reached while nobody was observing it (§19.4 step 4).
    lists: Arc<std::sync::atomic::AtomicUsize>,
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

/// Which watch script a recorded server plays.
///
/// Two scripts rather than one, because the case §19 is really about is not the one where events
/// arrive. `Expiry` is Gate F: a `410` that arrives as an ERROR frame *inside* a `200 OK` stream,
/// which is how a real expiry arrives and which an implementation that classifies HTTP codes
/// never sees.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Watching {
    /// The server offers no watch script; the collection is only ever listed.
    #[default]
    NotOffered,
    /// One arrival and one change, and then the response ends.
    Changes,
    /// One change, and then `410 Gone` as an ERROR frame in a successful stream (§19.4).
    Expiry,
}

/// One Pod as the watch fixtures use it: a name, a lifetime and a version, and nothing else.
fn watched_pod(name: &str, uid: &str, resource_version: &str) -> Json {
    json!({
        "metadata": {
            "name": name,
            "namespace": "default",
            "uid": uid,
            "resourceVersion": resource_version,
            "creationTimestamp": "2026-09-03T08:00:00Z",
        },
        "spec": {"containers": [{"name": "app"}]},
        "status": {"phase": "Running"},
    })
}

/// One object as a watch frame, with the newline that ends it.
///
/// The object carries its own `apiVersion` and `kind`, as a watch frame's does: a frame is not a
/// list item, so there is no envelope above it to take them from.
fn frame(class: &str, object: &Json) -> String {
    format!(
        "{}\n",
        json!({"type": class, "object": standalone(object.clone(), "v1", "Pod")})
    )
}

/// A chunked `200 OK`, framed the way a real watch response is.
///
/// Chunked on purpose: HTTP's framing and the newline framing of a watch body are unrelated, and
/// a fixture that delivered one frame per chunk would never exercise the decoder that holds a
/// frame split across two of them.
fn chunked(frames: &[String]) -> Vec<u8> {
    let mut wire = String::from(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    for frame in frames {
        wire.push_str(&format!("{:x}\r\n{frame}\r\n", frame.len()));
    }
    wire.push_str("0\r\n\r\n");
    wire.into_bytes()
}

/// What the recorded server sends down an open watch.
fn watch_body(cluster: &RecordedCluster) -> Vec<u8> {
    let expired = json!({
        "kind": "Status", "apiVersion": "v1", "status": "Failure",
        "message": "too old resource version: 9100 (9400)",
        "reason": "Expired", "code": 410,
    });
    match cluster.watch {
        Watching::NotOffered => not_found("a watch"),
        Watching::Changes => chunked(&[
            frame("ADDED", &watched_pod("two", "u-2", "4002")),
            frame("MODIFIED", &watched_pod("one", "u-1", "4003")),
        ]),
        // The `410` arrives *inside* a stream the server opened with `200 OK`, which is the case
        // §19.4 is about and the one a fixture answering `410 Gone` as a status code would miss.
        // The ERROR frame's payload is a `Status` rather than an object, so it goes in as it
        // stands rather than through `frame`, which dresses an object for a mutation frame.
        Watching::Expiry => chunked(&[
            frame("MODIFIED", &watched_pod("one", "u-1", "4003")),
            format!("{}\n", json!({"type": "ERROR", "object": expired})),
        ]),
    }
}

/// The Pod collection as the watch fixtures list it, which is not the same set twice.
///
/// The second listing is what a re-acquisition after a gap sees: `one` has moved on and `three`
/// has appeared, and nobody observed either happening. That is the whole point of §19.4 — the
/// state after the break is *inferred from a snapshot* rather than reached by observed changes.
fn watch_listing(cluster: &RecordedCluster) -> Json {
    let seen = cluster
        .lists
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if seen == 0 {
        return json!({
            "kind": "PodList", "apiVersion": "v1",
            "metadata": {"resourceVersion": "9100"},
            "items": [watched_pod("one", "u-1", "4001")],
        });
    }
    json!({
        "kind": "PodList", "apiVersion": "v1",
        "metadata": {"resourceVersion": "9200"},
        "items": [
            watched_pod("one", "u-1", "4003"),
            watched_pod("three", "u-3", "4004"),
        ],
    })
}

impl RecordedCluster {
    /// A server that serves a watch on its Pod collection, playing `script`.
    fn watching(script: Watching) -> Arc<Self> {
        Arc::new(Self {
            pods: 1,
            apps: true,
            watch: script,
            ..Self::default()
        })
    }

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

    /// A server serving two API groups this package has never heard of, both of which offer a
    /// kind of the same name.
    ///
    /// Nothing about them is compiled into the provider — the group names, the kind, its plural,
    /// its short name and its fields exist only in this file and in the bytes below (Gate A).
    fn with_custom_resources() -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: true,
            custom: true,
            ..Self::default()
        })
    }

    /// A server whose RBAC allows `get` on one Pod and refuses `list` on the collection — the
    /// scenario §60.5 names, and the one that decides whether `get` is its own request.
    fn denying_pod_list() -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: true,
            deny_pod_list: true,
            ..Self::default()
        })
    }

    /// A server whose RBAC refuses `get` on one Pod. A refused read is not an absent object.
    fn denying_pod_get() -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: true,
            deny_pod_get: true,
            ..Self::default()
        })
    }

    /// A server whose objects carry the references §23 to §32 derive relationships from.
    fn with_relations() -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: true,
            tier_one: true,
            relations: true,
            ..Self::default()
        })
    }

    /// The same server, refusing to enumerate the Pods a Service's selector is evaluated against.
    fn with_relations_denying_pod_list() -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: true,
            tier_one: true,
            relations: true,
            deny_pod_list: true,
            ..Self::default()
        })
    }

    /// A server serving every kind of §15.2's Tier 1 operational set.
    fn with_tier_one() -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: true,
            tier_one: true,
            ..Self::default()
        })
    }

    /// A server that speaks TLS, presenting `authority`'s certificate.
    fn over_tls(authority: &Authority) -> Arc<Self> {
        Arc::new(Self {
            pods: 2,
            apps: true,
            tls: Some(Arc::new(authority.server_config())),
            ..Self::default()
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

/// One `403`, as the API server writes a refusal: a `Status` naming the verb it refused.
fn denied(path: &str, verb: &str) -> Vec<u8> {
    let body = json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Failure",
        "message": format!("pods is forbidden: cannot {verb} resource at {path}"),
        "reason": "Forbidden",
        "code": 403,
    })
    .to_string();
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// One object as the *object* endpoint sends it, which states its own `apiVersion` and `kind`.
///
/// A collection states them once in its envelope; a single object states them itself. The two
/// endpoints therefore hand the provider different documents for the same object, and this is
/// the fixture half of that.
fn standalone(mut object: Json, api_version: &str, kind: &str) -> Json {
    if let Some(map) = object.as_object_mut() {
        map.insert("apiVersion".to_owned(), json!(api_version));
        map.insert("kind".to_owned(), json!(kind));
    }
    object
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
                // The four §14.1 fields the boundary used to drop. They are here rather than in
                // a fixture of their own because they are ordinary metadata: every object may
                // carry them, and a projection that reads them only for a special case is the
                // projection §14.1 forbids.
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": "{}",
                    "deployment.kubernetes.io/revision": "4",
                },
                "finalizers": ["example.com/drain-connections"],
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9f",
                    "uid": "a1a1a1a1-0000-0000-0000-000000000001",
                    "controller": true, "blockOwnerDeletion": true,
                }],
                "managedFields": [
                    {"manager": "kube-controller-manager", "operation": "Update",
                     "apiVersion": "v1", "fieldsType": "FieldsV1",
                     "fieldsV1": {"f:metadata": {"f:labels": {}}}},
                    {"manager": "kubelet", "operation": "Update", "subresource": "status",
                     "apiVersion": "v1", "fieldsType": "FieldsV1",
                     "fieldsV1": {"f:status": {"f:phase": {}}}},
                    {"manager": "kubelet", "operation": "Update",
                     "apiVersion": "v1", "fieldsType": "FieldsV1",
                     "fieldsV1": {"f:metadata": {}}},
                ],
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

/// One object of the invented kind, as its server sends it.
///
/// Its fields are invented too: nothing in the provider knows what a `teeth` is, and the only
/// reason the record below carries an instant rather than a string is that the schema document
/// says `format: date-time` (Gate B).
fn custom_object(index: usize) -> Json {
    json!({
        "apiVersion": "menagerie.example/v1",
        "kind": "Sprocket",
        "metadata": {
            "name": format!("sprocket-{index}"),
            "namespace": "default",
            "uid": format!("aaaaaaaa-aaaa-aaaa-aaaa-{index:012}"),
            "resourceVersion": "5100",
            "creationTimestamp": "2026-09-02T07:00:00Z",
            "labels": {"line": "north"},
            // The same four fields on a kind nothing compiled in. §14's projection is common to
            // every Kubernetes object, and a CRD is a normal resource (§33.1).
            "annotations": {"menagerie.example/calibrated-by": "bench-3"},
            "finalizers": ["menagerie.example/release-bench"],
            "ownerReferences": [{
                "apiVersion": "menagerie.example/v1", "kind": "Bench", "name": "bench-3",
                "uid": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "controller": false, "blockOwnerDeletion": false,
            }],
            "managedFields": [
                {"manager": "menagerie-operator", "operation": "Apply", "apiVersion":
                 "menagerie.example/v1", "fieldsType": "FieldsV1", "fieldsV1": {"f:spec": {}}},
            ],
        },
        "spec": {
            "teeth": 24,
            "renewAt": "2026-12-24T18:00:00Z",
            "mode": "idle",
            "tolerances": [{"axis": "x", "microns": 5}],
        },
        "status": {
            "phase": "Spinning",
            "observedTeeth": 24,
        },
    })
}

/// The API server's OpenAPI v3 document for the invented group.
///
/// The component key is deliberately not derived from the group or the kind: the provider finds
/// the component by what it *declares* in `x-kubernetes-group-version-kind` (§13.2), which is
/// the only rule that works for an arbitrary CRD.
fn custom_openapi() -> Json {
    json!({
        "openapi": "3.0.0",
        "components": {"schemas": {
            "some.vendors.own.naming.Convention": {
                "type": "object",
                "x-kubernetes-group-version-kind": [
                    {"group": "menagerie.example", "version": "v1", "kind": "Sprocket"},
                ],
                "properties": {
                    "spec": {
                        "type": "object",
                        "required": ["teeth"],
                        "properties": {
                            "teeth": {"type": "integer", "description": "How many."},
                            "renewAt": {"type": "string", "format": "date-time"},
                            "mode": {"type": "string"},
                            "tolerances": {"type": "array", "items": {
                                "type": "object",
                                "properties": {
                                    "axis": {"type": "string"},
                                    "microns": {"type": "integer"},
                                },
                            }},
                        },
                    },
                    "status": {
                        "type": "object",
                        "properties": {
                            "phase": {"type": "string"},
                            "observedTeeth": {"type": "integer"},
                        },
                    },
                },
            },
        }},
    })
}

/// What a cluster with two invented API groups answers, where it differs from the plain one.
///
/// `None` falls through to the ordinary document, so the core group, the pods and the secret of
/// every other test are unchanged and a dynamic query reaches them by the same route.
fn custom_document(path: &str) -> Option<Json> {
    Some(match path {
        "/apis" => json!({
            "kind": "APIGroupList",
            "groups": [
                {
                    "name": "apps",
                    "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
                },
                {
                    "name": "menagerie.example",
                    "versions": [{"groupVersion": "menagerie.example/v1", "version": "v1"}],
                    "preferredVersion": {
                        "groupVersion": "menagerie.example/v1", "version": "v1",
                    },
                },
                {
                    "name": "industrial.example",
                    "versions": [{"groupVersion": "industrial.example/v1", "version": "v1"}],
                    "preferredVersion": {
                        "groupVersion": "industrial.example/v1", "version": "v1",
                    },
                },
            ],
        }),
        "/apis/menagerie.example/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "menagerie.example/v1",
            "resources": [
                {"name": "sprockets", "kind": "Sprocket", "namespaced": true,
                 "verbs": ["get", "list", "watch"], "shortNames": ["spr"]},
                // Served, and not listable: §11.5's third state, which is neither "no such
                // resource" nor "an empty collection".
                {"name": "escapements", "kind": "Escapement", "namespaced": true,
                 "verbs": ["get"]},
            ],
        }),
        // The same kind, in a second group, at cluster scope — so that a kind on its own is
        // genuinely ambiguous (§13.5) and the scope of the answer is not a coincidence.
        "/apis/industrial.example/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "industrial.example/v1",
            "resources": [
                {"name": "sprockets", "kind": "Sprocket", "namespaced": false,
                 "verbs": ["get", "list"], "shortNames": ["spr"]},
            ],
        }),
        "/openapi/v3/apis/menagerie.example/v1" => custom_openapi(),
        // This group publishes no schema document at all, which is §12.3's gap rather than a
        // broken server.
        "/apis/menagerie.example/v1/namespaces/default/sprockets" => json!({
            "kind": "SprocketList",
            "apiVersion": "menagerie.example/v1",
            "metadata": {"resourceVersion": "9100"},
            "items": [custom_object(1), custom_object(2)],
        }),
        "/apis/industrial.example/v1/sprockets" => json!({
            "kind": "SprocketList",
            "apiVersion": "industrial.example/v1",
            "metadata": {"resourceVersion": "9101"},
            "items": [{
                "apiVersion": "industrial.example/v1",
                "kind": "Sprocket",
                "metadata": {
                    "name": "heavy",
                    "uid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    "creationTimestamp": "2026-09-02T08:00:00Z",
                },
                "spec": {"teeth": 96, "renewAt": "2027-01-01T00:00:00Z"},
                "payload": {"note": "not under spec, and still here"},
            }],
        }),
        _ => return None,
    })
}

/// A cluster serving the whole Tier 1 set of §15.2, where it differs from the plain one.
///
/// Every object below is written so that a projection reading the wrong field is visible rather
/// than merely wrong: counts differ from one another, one claim is deliberately unbound, one
/// endpoint deliberately has no target reference, and one controller is deliberately behind its
/// own generation.
fn tier_one_document(path: &str) -> Option<Json> {
    Some(match path {
        "/apis" => json!({
            "kind": "APIGroupList",
            "groups": [
                group("apps"),
                group("batch"),
                group("discovery.k8s.io"),
                group("networking.k8s.io"),
                group("storage.k8s.io"),
            ],
        }),
        "/api/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "v1",
            "resources": [
                {"name": "namespaces", "kind": "Namespace", "namespaced": false,
                 "verbs": ["get", "list", "watch"]},
                {"name": "nodes", "kind": "Node", "namespaced": false,
                 "verbs": ["get", "list", "watch"]},
                {"name": "pods", "kind": "Pod", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "services", "kind": "Service", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "secrets", "kind": "Secret", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "configmaps", "kind": "ConfigMap", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "serviceaccounts", "kind": "ServiceAccount", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "persistentvolumeclaims", "kind": "PersistentVolumeClaim",
                 "namespaced": true, "verbs": ["get", "list", "watch"]},
                {"name": "persistentvolumes", "kind": "PersistentVolume", "namespaced": false,
                 "verbs": ["get", "list", "watch"]},
            ],
        }),
        "/apis/apps/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "apps/v1",
            "resources": [
                {"name": "deployments", "kind": "Deployment", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "replicasets", "kind": "ReplicaSet", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "statefulsets", "kind": "StatefulSet", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "daemonsets", "kind": "DaemonSet", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
            ],
        }),
        "/apis/batch/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "batch/v1",
            "resources": [
                {"name": "jobs", "kind": "Job", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
                {"name": "cronjobs", "kind": "CronJob", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
            ],
        }),
        "/apis/discovery.k8s.io/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "discovery.k8s.io/v1",
            "resources": [
                {"name": "endpointslices", "kind": "EndpointSlice", "namespaced": true,
                 "verbs": ["get", "list", "watch"]},
            ],
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
        "/apis/storage.k8s.io/v1" => json!({
            "kind": "APIResourceList",
            "groupVersion": "storage.k8s.io/v1",
            "resources": [
                {"name": "storageclasses", "kind": "StorageClass", "namespaced": false,
                 "verbs": ["get", "list", "watch"]},
            ],
        }),

        "/apis/apps/v1/namespaces/default/replicasets" => collection(
            "ReplicaSet",
            "apps/v1",
            &[json!({
                "metadata": {
                    "name": "api-7d9f", "namespace": "default",
                    "uid": "a1a1a1a1-0000-0000-0000-000000000001",
                    "generation": 3,
                    "creationTimestamp": "2026-08-20T08:00:00Z",
                    "ownerReferences": [
                        {"apiVersion": "apps/v1", "kind": "Deployment", "name": "api",
                         "uid": "66666666-6666-6666-6666-666666666666", "controller": true},
                    ],
                },
                "spec": {"replicas": 3},
                "status": {"replicas": 3, "readyReplicas": 2, "availableReplicas": 2,
                           "observedGeneration": 3},
            })],
        ),
        "/apis/apps/v1/namespaces/default/statefulsets" => collection(
            "StatefulSet",
            "apps/v1",
            &[json!({
                "metadata": {
                    "name": "ledger", "namespace": "default",
                    "uid": "a2a2a2a2-0000-0000-0000-000000000001",
                    "generation": 5,
                    "creationTimestamp": "2026-08-20T08:00:00Z",
                },
                "spec": {
                    "replicas": 3,
                    "serviceName": "ledger-headless",
                    "volumeClaimTemplates": [
                        {"metadata": {"name": "data"},
                         "spec": {"storageClassName": "fast",
                                  "accessModes": ["ReadWriteOnce"],
                                  "resources": {"requests": {"storage": "10Gi"}}}},
                    ],
                },
                // Behind its own generation: the controller has not seen the latest spec, which
                // §37.5 calls "desired state changed; controller not yet observed".
                "status": {"replicas": 3, "readyReplicas": 3, "updatedReplicas": 1,
                           "currentRevision": "ledger-6f4", "updateRevision": "ledger-9ab",
                           "observedGeneration": 4},
            })],
        ),
        "/apis/apps/v1/namespaces/default/daemonsets" => collection(
            "DaemonSet",
            "apps/v1",
            &[json!({
                "metadata": {
                    "name": "node-agent", "namespace": "default",
                    "uid": "a3a3a3a3-0000-0000-0000-000000000001",
                    "generation": 2,
                    "creationTimestamp": "2026-08-20T08:00:00Z",
                },
                "spec": {},
                "status": {"desiredNumberScheduled": 5, "currentNumberScheduled": 5,
                           "numberReady": 4, "updatedNumberScheduled": 3,
                           "numberAvailable": 4, "numberMisscheduled": 1,
                           "observedGeneration": 2},
            })],
        ),
        "/api/v1/namespaces/default/services" => collection(
            "Service",
            "v1",
            &[
                json!({
                    "metadata": {
                        "name": "api", "namespace": "default",
                        "uid": "a4a4a4a4-0000-0000-0000-000000000001",
                        "creationTimestamp": "2026-08-20T08:00:00Z",
                    },
                    "spec": {
                        "type": "LoadBalancer",
                        "clusterIP": "10.96.0.42",
                        "selector": {"app": "api"},
                        "ports": [
                            {"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"},
                            {"port": 443, "targetPort": 8443, "protocol": "TCP"},
                        ],
                    },
                    "status": {"loadBalancer": {"ingress": [{"hostname": "lb.example"}]}},
                }),
                // A headless, selector-less Service: §26.1's "no guessed Pod edges" case.
                json!({
                    "metadata": {
                        "name": "ledger-headless", "namespace": "default",
                        "uid": "a4a4a4a4-0000-0000-0000-000000000002",
                        "creationTimestamp": "2026-08-20T08:00:00Z",
                    },
                    "spec": {"type": "ClusterIP", "clusterIP": "None"},
                    "status": {"loadBalancer": {}},
                }),
            ],
        ),
        "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices" => collection(
            "EndpointSlice",
            "discovery.k8s.io/v1",
            &[json!({
                "metadata": {
                    "name": "api-x7k2", "namespace": "default",
                    "uid": "a5a5a5a5-0000-0000-0000-000000000001",
                    "labels": {"kubernetes.io/service-name": "api"},
                    "creationTimestamp": "2026-08-20T08:00:00Z",
                },
                "addressType": "IPv4",
                "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
                "endpoints": [
                    {"addresses": ["10.1.2.3"], "conditions": {"ready": true},
                     "targetRef": {"kind": "Pod", "name": "api-7d9f-abc",
                                   "uid": "11111111-1111-1111-1111-111111111111"}},
                    {"addresses": ["10.1.2.4"], "conditions": {"ready": false},
                     "targetRef": {"kind": "Pod", "name": "api-7d9f-def",
                                   "uid": "11111111-1111-1111-1111-111111111112"}},
                    // §26.4: an external endpoint with no target reference stays an endpoint
                    // fact rather than being forced into a Pod relationship.
                    {"addresses": ["203.0.113.9"], "conditions": {"ready": true}},
                ],
            })],
        ),
        "/apis/networking.k8s.io/v1/namespaces/default/ingresses" => collection(
            "Ingress",
            "networking.k8s.io/v1",
            &[json!({
                "metadata": {
                    "name": "public", "namespace": "default",
                    "uid": "a6a6a6a6-0000-0000-0000-000000000001",
                    "creationTimestamp": "2026-08-20T08:00:00Z",
                },
                "spec": {
                    "ingressClassName": "nginx",
                    "tls": [{"hosts": ["shop.example"], "secretName": "shop-tls"}],
                    "rules": [{
                        "host": "shop.example",
                        "http": {"paths": [
                            {"path": "/", "pathType": "Prefix",
                             "backend": {"service": {"name": "api", "port": {"number": 80}}}},
                            {"path": "/static", "pathType": "Prefix",
                             "backend": {"service": {"name": "assets", "port": {"name": "http"}}}},
                        ]},
                    }],
                },
                "status": {"loadBalancer": {"ingress": [{"ip": "198.51.100.7"}]}},
            })],
        ),
        "/apis/batch/v1/namespaces/default/jobs" => collection(
            "Job",
            "batch/v1",
            &[json!({
                "metadata": {
                    "name": "nightly-28291", "namespace": "default",
                    "uid": "a7a7a7a7-0000-0000-0000-000000000001",
                    "generation": 1,
                    "creationTimestamp": "2026-09-01T02:00:00Z",
                    "ownerReferences": [
                        {"apiVersion": "batch/v1", "kind": "CronJob", "name": "nightly",
                         "uid": "a8a8a8a8-0000-0000-0000-000000000001", "controller": true},
                    ],
                },
                "spec": {"completions": 1, "parallelism": 1},
                "status": {
                    "succeeded": 1,
                    "startTime": "2026-09-01T02:00:01Z",
                    "completionTime": "2026-09-01T02:03:11Z",
                    "conditions": [{"type": "Complete", "status": "True"}],
                    "observedGeneration": 1,
                },
            })],
        ),
        "/apis/batch/v1/namespaces/default/cronjobs" => collection(
            "CronJob",
            "batch/v1",
            &[json!({
                "metadata": {
                    "name": "nightly", "namespace": "default",
                    "uid": "a8a8a8a8-0000-0000-0000-000000000001",
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "spec": {"schedule": "0 2 * * *", "suspend": false,
                         "concurrencyPolicy": "Forbid"},
                "status": {
                    "lastScheduleTime": "2026-09-01T02:00:00Z",
                    "lastSuccessfulTime": "2026-09-01T02:03:11Z",
                    "active": [{"kind": "Job", "name": "nightly-28291", "namespace": "default"}],
                },
            })],
        ),
        "/api/v1/namespaces/default/configmaps" => collection(
            "ConfigMap",
            "v1",
            &[json!({
                "metadata": {
                    "name": "api-config", "namespace": "default",
                    "uid": "a9a9a9a9-0000-0000-0000-000000000001",
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "immutable": true,
                "data": {"log_level": "info", "endpoint": "https://upstream.example"},
                "binaryData": {"seed.bin": "AAECAw=="},
            })],
        ),
        "/api/v1/namespaces/default/serviceaccounts" => collection(
            "ServiceAccount",
            "v1",
            &[json!({
                "metadata": {
                    "name": "api", "namespace": "default",
                    "uid": "b1b1b1b1-0000-0000-0000-000000000001",
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "secrets": [{"name": "api-token"}],
                "imagePullSecrets": [{"name": "registry-pull"}],
                "automountServiceAccountToken": false,
            })],
        ),
        "/api/v1/namespaces/default/persistentvolumeclaims" => collection(
            "PersistentVolumeClaim",
            "v1",
            &[
                json!({
                    "metadata": {
                        "name": "data-ledger-0", "namespace": "default",
                        "uid": "b2b2b2b2-0000-0000-0000-000000000001",
                        "creationTimestamp": "2026-08-01T00:00:00Z",
                    },
                    "spec": {"volumeName": "pv-0001", "storageClassName": "fast",
                             "volumeMode": "Filesystem", "accessModes": ["ReadWriteOnce"],
                             "resources": {"requests": {"storage": "10Gi"}}},
                    "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}},
                }),
                // §30.2: Pending, with no `volumeName`. It must not read as bound.
                json!({
                    "metadata": {
                        "name": "data-ledger-1", "namespace": "default",
                        "uid": "b2b2b2b2-0000-0000-0000-000000000002",
                        "creationTimestamp": "2026-08-01T00:00:00Z",
                    },
                    "spec": {"storageClassName": "fast", "accessModes": ["ReadWriteOnce"],
                             "resources": {"requests": {"storage": "10Gi"}}},
                    "status": {"phase": "Pending"},
                }),
            ],
        ),
        "/api/v1/persistentvolumes" => collection(
            "PersistentVolume",
            "v1",
            &[json!({
                "metadata": {
                    "name": "pv-0001",
                    "uid": "b3b3b3b3-0000-0000-0000-000000000001",
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "spec": {
                    "capacity": {"storage": "10Gi"},
                    "storageClassName": "fast",
                    "volumeMode": "Filesystem",
                    "accessModes": ["ReadWriteOnce"],
                    "persistentVolumeReclaimPolicy": "Retain",
                    "claimRef": {"kind": "PersistentVolumeClaim", "namespace": "default",
                                 "name": "data-ledger-0"},
                    "csi": {"driver": "ebs.csi.aws.com", "volumeHandle": "vol-0abc"},
                },
                "status": {"phase": "Bound"},
            })],
        ),
        "/apis/storage.k8s.io/v1/storageclasses" => collection(
            "StorageClass",
            "storage.k8s.io/v1",
            &[json!({
                "metadata": {
                    "name": "fast",
                    "uid": "b4b4b4b4-0000-0000-0000-000000000001",
                    "annotations": {"storageclass.kubernetes.io/is-default-class": "true"},
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "provisioner": "ebs.csi.aws.com",
                "reclaimPolicy": "Delete",
                "volumeBindingMode": "WaitForFirstConsumer",
                "allowVolumeExpansion": true,
                "parameters": {"type": "gp3", "iops": "3000"},
            })],
        ),
        "/apis/networking.k8s.io/v1/namespaces/default/networkpolicies" => collection(
            "NetworkPolicy",
            "networking.k8s.io/v1",
            &[json!({
                "metadata": {
                    "name": "api-ingress", "namespace": "default",
                    "uid": "b5b5b5b5-0000-0000-0000-000000000001",
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "spec": {
                    "podSelector": {"matchLabels": {"app": "api"}},
                    "policyTypes": ["Ingress"],
                    "ingress": [{
                        "from": [
                            {"namespaceSelector": {"matchLabels": {"tier": "edge"}}},
                            {"ipBlock": {"cidr": "10.0.0.0/8", "except": ["10.9.0.0/16"]}},
                        ],
                        "ports": [{"protocol": "TCP", "port": 8080}],
                    }],
                },
            })],
        ),
        _ => return None,
    })
}

/// The Pod every relationship test starts at.
///
/// One object carrying one instance of each evidence class §23 defines that a single object can
/// state about itself: an owner reference with the controller flag, and four native fields
/// pointing at four different kinds — one of them cluster-scoped, so that a namespace copied onto
/// it would be visible (§9.2, §24.2).
fn related_pod() -> Json {
    json!({
        "metadata": {
            "name": "api-7d9f-abc",
            "namespace": "default",
            "uid": "11111111-1111-1111-1111-111111111111",
            "resourceVersion": "4711",
            "creationTimestamp": "2026-09-01T09:00:00Z",
            "labels": {"app": "api"},
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9f",
                 "uid": "a1a1a1a1-0000-0000-0000-000000000001", "controller": true},
            ],
        },
        "spec": {
            "nodeName": "node-a",
            "serviceAccountName": "api",
            "containers": [{
                "name": "api",
                "envFrom": [{"configMapRef": {"name": "api-config"}}],
            }],
            "volumes": [{"name": "token", "secret": {"secretName": "api-token"}}],
        },
        "status": {"phase": "Running", "podIP": "10.1.2.3"},
    })
}

/// A Pod in the same namespace that the Service's selector deliberately does not match.
///
/// Without it a selector that matched everything would pass every assertion below, and the edge
/// would be reporting the namespace rather than the labels.
fn unselected_pod() -> Json {
    json!({
        "metadata": {
            "name": "worker-1",
            "namespace": "default",
            "uid": "22222222-2222-2222-2222-000000000001",
            "resourceVersion": "4712",
            "creationTimestamp": "2026-09-01T09:05:00Z",
            "labels": {"app": "worker"},
        },
        "spec": {"nodeName": "node-a", "containers": [{"name": "worker"}]},
        "status": {"phase": "Running"},
    })
}

/// The Service whose selector the relationship tests evaluate.
fn related_service() -> Json {
    json!({
        "metadata": {
            "name": "api",
            "namespace": "default",
            "uid": "a4a4a4a4-0000-0000-0000-000000000001",
            "creationTimestamp": "2026-08-20T08:00:00Z",
        },
        "spec": {
            "type": "LoadBalancer",
            "clusterIP": "10.96.0.42",
            "selector": {"app": "api"},
            "ports": [{"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"}],
        },
        "status": {"loadBalancer": {"ingress": [{"hostname": "lb.example"}]}},
    })
}

/// What a cluster whose objects state relationships answers, where it differs from Tier 1.
///
/// Every path here is an *object* endpoint except the two collections a derivation reads: the
/// Pods a Service's selector is evaluated against, and the slices its service-name label points
/// at. That is the fixture half of §26.1 — a selector edge needs two objects, and one of them is
/// a second read that can be denied.
fn relations_document(path: &str) -> Option<Json> {
    Some(match path {
        "/api/v1/namespaces/default/pods" => {
            collection("Pod", "v1", &[related_pod(), unselected_pod()])
        }
        "/api/v1/namespaces/default/pods/api-7d9f-abc" => standalone(related_pod(), "v1", "Pod"),
        "/api/v1/namespaces/default/services" => collection("Service", "v1", &[related_service()]),
        "/api/v1/namespaces/default/services/api" => standalone(related_service(), "v1", "Service"),
        "/apis/networking.k8s.io/v1/namespaces/default/ingresses/public" => standalone(
            json!({
                "metadata": {
                    "name": "public", "namespace": "default",
                    "uid": "a6a6a6a6-0000-0000-0000-000000000001",
                    "creationTimestamp": "2026-08-20T08:00:00Z",
                },
                "spec": {
                    "ingressClassName": "nginx",
                    "tls": [{"hosts": ["shop.example"], "secretName": "shop-tls"}],
                    "rules": [{
                        "host": "shop.example",
                        "http": {"paths": [
                            {"path": "/", "pathType": "Prefix",
                             "backend": {"service": {"name": "api", "port": {"number": 80}}}},
                        ]},
                    }],
                },
                "status": {"loadBalancer": {"ingress": [{"ip": "198.51.100.7"}]}},
            }),
            "networking.k8s.io/v1",
            "Ingress",
        ),
        "/apis/apps/v1/namespaces/default/deployments/api" => standalone(
            json!({
                "metadata": {
                    "name": "api", "namespace": "default",
                    "uid": "66666666-6666-6666-6666-666666666666",
                    "generation": 7,
                    "creationTimestamp": "2026-08-20T08:00:00Z",
                },
                "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "api"}}},
                "status": {"readyReplicas": 2, "observedGeneration": 6},
            }),
            "apps/v1",
            "Deployment",
        ),
        "/api/v1/namespaces/default/configmaps/api-config" => standalone(
            json!({
                "metadata": {
                    "name": "api-config", "namespace": "default",
                    "uid": "a9a9a9a9-0000-0000-0000-000000000001",
                    "creationTimestamp": "2026-08-01T00:00:00Z",
                },
                "data": {"log_level": "info"},
            }),
            "v1",
            "ConfigMap",
        ),
        _ => return None,
    })
}

/// One API group with a single preferred version.
fn group(name: &str) -> Json {
    json!({
        "name": name,
        "versions": [{"groupVersion": format!("{name}/v1"), "version": "v1"}],
        "preferredVersion": {"groupVersion": format!("{name}/v1"), "version": "v1"},
    })
}

/// A collection envelope, as the API server sends one.
fn collection(kind: &str, api_version: &str, items: &[Json]) -> Json {
    json!({
        "kind": format!("{kind}List"),
        "apiVersion": api_version,
        "metadata": {"resourceVersion": "9100"},
        "items": items,
    })
}

fn document(path: &str, cluster: &RecordedCluster) -> Vec<u8> {
    let pods = cluster.pods;
    // Read before the query string is dropped, because `watch=true` is the whole difference
    // between reading a collection and observing it, and it lives nowhere else in the request.
    if cluster.watch != Watching::NotOffered && path.contains("watch=true") {
        return watch_body(cluster);
    }
    let path = path.split('?').next().unwrap_or(path);
    if cluster.watch != Watching::NotOffered && path == "/api/v1/namespaces/default/pods" {
        return response(&watch_listing(cluster).to_string());
    }
    // §60.5's refusal, before any of the layered fixtures answer for the same path: a derivation
    // that reads the Pod collection must be able to meet it too, and not only a Pod query.
    if cluster.deny_pod_list && path == "/api/v1/namespaces/default/pods" {
        return denied(path, "list");
    }
    if cluster.custom
        && let Some(body) = custom_document(path)
    {
        return response(&body.to_string());
    }
    if cluster.relations
        && let Some(body) = relations_document(path)
    {
        return response(&body.to_string());
    }
    if cluster.tier_one
        && let Some(body) = tier_one_document(path)
    {
        return response(&body.to_string());
    }
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
        // Reached only when the cluster serves no custom groups: `custom_document` answers
        // `/apis` before this does, because the group list has to name them.
        "/openapi/v3/api/v1" | "/openapi/v3/apis/apps/v1" => return not_found(path),
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
        // §60.5: `list` refused while `get` on one object of the same collection is allowed.
        "/api/v1/namespaces/default/pods" if cluster.deny_pod_list => {
            return denied(path, "list");
        }
        "/api/v1/namespaces/default/pods/api-7d9f-abc" if cluster.deny_pod_get => {
            return denied(path, "get");
        }
        // The canonical REST endpoint of one object (§17.1). It is deliberately a different
        // route from the collection above, so a provider that reached it by listing and
        // filtering would be visible in the request heads.
        "/api/v1/namespaces/default/pods/api-7d9f-abc" => standalone(pod(0), "v1", "Pod"),
        "/api/v1/namespaces/shop/pods/shop-till" => standalone(
            json!({
                "metadata": {
                    "name": "shop-till",
                    "namespace": "shop",
                    "uid": "77777777-7777-7777-7777-777777777777",
                    "resourceVersion": "4713",
                    "creationTimestamp": "2026-09-01T10:00:00Z",
                },
                "spec": {"nodeName": "node-a", "containers": [{"name": "till"}]},
                "status": {"phase": "Running", "podIP": "10.1.2.9"},
            }),
            "v1",
            "Pod",
        ),
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

// --- get: one object by name (§17.1) -----------------------------------------------------------

/// The package loaded against a cluster the test built.
async fn loaded_against(cluster: Arc<RecordedCluster>) -> ono_kuang_supervisor::LoadedPlugin {
    TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(cluster as Arc<dyn HostServices>)
        .load()
        .await
        .expect("the package loads under its own manifest")
}

#[tokio::test]
async fn should_read_one_object_by_name_through_the_canonical_object_endpoint() {
    // §17.1: a direct lookup uses the canonical REST resource endpoint resolved from discovery.
    // Listing the collection and filtering it would answer the same question with a different
    // request — one that needs `list` permission and reads every object in the namespace — so
    // the request heads are what this test is really about.
    let cluster = RecordedCluster::with_pods(2);
    let plugin = loaded_against(Arc::clone(&cluster)).await;
    let invocation = plugin
        .query("k8s-pod", at_cluster(&[("name", json!("api-7d9f-abc"))]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);

    let records = records(&events);
    assert_eq!(records.len(), 1, "a get answers one object or none");
    let pod = &records[0];
    assert_eq!(
        pod.schema_id().to_string(),
        "io.github.godspeed-you.kubernetes.pod/1",
        "a get answers records of the same schema the listing does"
    );
    pod.validate().expect("the record conforms");
    assert_eq!(
        text_of(pod, "uid").as_deref(),
        Some("11111111-1111-1111-1111-111111111111"),
        "identity is the uid even when the query spelled a name (§16.1, §16.2)"
    );
    assert_eq!(text_of(pod, "phase").as_deref(), Some("Running"));

    let heads = cluster.heads();
    assert!(
        heads
            .iter()
            .any(|head| head.starts_with("GET /api/v1/namespaces/default/pods/api-7d9f-abc ")),
        "the object's own endpoint answered: {heads:?}"
    );
    assert!(
        !heads
            .iter()
            .any(|head| head.starts_with("GET /api/v1/namespaces/default/pods ")),
        "the collection was never asked for: a get that lists is a get that needs `list` \
         permission it was never granted: {heads:?}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_read_one_object_by_name_where_the_collection_is_denied() {
    // §60.5, end to end: allow `get` on one Pod, deny `list` on Pods, and check that the direct
    // read succeeds while the inventory reports a denial. This is the whole reason `get` is a
    // requirement of its own and not a convenience over the listing.
    let cluster = RecordedCluster::denying_pod_list();
    let plugin = loaded_against(Arc::clone(&cluster)).await;

    let invocation = plugin
        .query("k8s-pod", at_cluster(&[]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert!(records(&events).is_empty(), "nothing was invented");
    assert_eq!(
        result.status,
        InvokeStatus::Failed,
        "a denied listing is not an empty namespace (§4 invariant 13, §21.4)"
    );
    let error = result.error.expect("a structured refusal");
    assert!(
        error.message.contains("list denied"),
        "the refusal names the coverage outcome, and `list denied` is not `read denied`: {}",
        error.message
    );

    let invocation = plugin
        .query("k8s-pod", at_cluster(&[("name", json!("api-7d9f-abc"))]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "the direct read is a different request and RBAC answers it differently: {:?}",
        result.error
    );
    assert_eq!(records(&events).len(), 1, "the object itself is readable");
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_say_a_named_object_that_is_not_there_is_absent_rather_than_unserved() {
    // §21.4 through the `404` that means two different things. On a collection a `404` is an
    // unserved API — a fact about what the cluster can answer at all — and the query fails.
    // On one object it is absence, which is a fact about the cluster and the only outcome in
    // §21.4's vocabulary that is evidence of absence. So the first refuses and the second
    // completes with nothing, and a reader can tell them apart.
    let plugin = loaded_with_custom_resources().await;

    let invocation = plugin
        .query("k8s-pod", at_cluster(&[("name", json!("no-such-pod"))]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "an object that is not there is an answer, not a failure: {:?}",
        result.error
    );
    assert!(
        records(&events).is_empty(),
        "and the answer is that there is nothing"
    );

    let invocation = plugin
        .query(
            "k8s-resource",
            at_cluster(&[("kind", json!("Flywheel")), ("name", json!("no-such-pod"))]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert!(records(&events).is_empty());
    assert_eq!(
        result.status,
        InvokeStatus::Failed,
        "a kind the cluster does not serve is not an absent object of that kind"
    );
    assert_eq!(
        result.error.expect("a structured refusal").name,
        "provider.unsupported"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_say_a_denied_get_is_a_refused_read_rather_than_an_absence() {
    // The mistake §21.4 exists to prevent, in its most expensive form: a `403` rendered as "not
    // there" tells an operator the object was deleted.
    let cluster = RecordedCluster::denying_pod_get();
    let plugin = loaded_against(cluster).await;
    let invocation = plugin
        .query("k8s-pod", at_cluster(&[("name", json!("api-7d9f-abc"))]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;

    assert!(records(&events).is_empty());
    assert_eq!(
        result.status,
        InvokeStatus::Failed,
        "a refused read is not an empty answer"
    );
    let error = result.error.expect("a structured refusal");
    assert!(
        error.message.contains("read denied"),
        "the refusal names §21.4's outcome, and it is not `absent`: {}",
        error.message
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_carry_the_freshness_a_read_is_required_to_state() {
    // §17.1: a get result MUST carry `observed_at`, `resourceVersion`, `provider_instance`,
    // `scope`, the source endpoint category and its freshness. `resourceVersion` is a field of
    // the record; the rest belong to the observation rather than to the object, and provenance
    // is where the value model keeps those — so `inspect` shows them and a pipeline can read
    // them without this package inventing a second place for them.
    let plugin = loaded(2).await;
    for options in [
        at_cluster(&[]),
        at_cluster(&[("name", json!("api-7d9f-abc"))]),
    ] {
        let invocation = plugin
            .query("k8s-pod", options)
            .await
            .expect("the query starts");
        let (events, result) = invocation.collect().await;
        assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
        let records = records(&events);
        let provenance = records[0].provenance();
        assert!(
            provenance.observed().is_some(),
            "the read states when it was observed"
        );
        let source = provenance.source().unwrap_or_default().to_owned();
        for expected in [
            "provider_instance=kubernetes:recorded",
            "scope=namespace/default",
            "endpoint=core",
            "origin=direct-read",
        ] {
            assert!(
                source.contains(expected),
                "the read states `{expected}`, and it says `{source}`"
            );
        }
    }
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

// --- a resource this package has never heard of (Gates A and B) --------------------------------

/// The package loaded against a cluster serving two invented API groups.
async fn loaded_with_custom_resources() -> ono_kuang_supervisor::LoadedPlugin {
    TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(RecordedCluster::with_custom_resources())
        .load()
        .await
        .expect("the package loads under its own manifest")
}

fn map_of<'record>(record: &'record RecordValue, field: &str) -> &'record ono_value::MapValue {
    match record.get(field) {
        Some(Value::Map(map)) => map,
        other => panic!("`{field}` is a map, and it is {other:?}"),
    }
}

#[tokio::test]
async fn should_read_a_kind_this_package_has_never_heard_of() {
    // Gate A (§62.1), as far as a test without a cluster can carry it: the kind, its group, its
    // plural, its short name and every one of its fields exist only in this file. Nothing was
    // recompiled to reach it — the same binary that answers `k8s-pod` answers this.
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query(
            "k8s-resource",
            at_cluster(&[
                ("kind", json!("Sprocket")),
                ("group", json!("menagerie.example")),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);

    let records = records(&events);
    assert_eq!(records.len(), 2, "both objects of the collection arrived");
    let first = &records[0];
    assert_eq!(
        first.schema_id().to_string(),
        "io.github.godspeed-you.kubernetes.resource/1",
        "a record may only claim a schema the package contributed, and a schema named after a \
         kind invented later could never have been contributed (ADR-0010)"
    );
    assert_eq!(
        first.provenance().provider(),
        format!("plugin:{PACKAGE}"),
        "provenance is the host's stamp on a dynamic record like any other (§31.80)"
    );
    first
        .validate()
        .expect("a dynamic record conforms to the one schema it claims");

    // §13.2: one schema for every kind means the Kubernetes type identity has to live in the
    // record, or it is lost.
    assert_eq!(text_of(first, "kind").as_deref(), Some("Sprocket"));
    assert_eq!(
        text_of(first, "api_group").as_deref(),
        Some("menagerie.example")
    );
    assert_eq!(
        text_of(first, "api_version").as_deref(),
        Some("menagerie.example/v1")
    );
    assert_eq!(
        text_of(first, "resource_name").as_deref(),
        Some("sprockets"),
        "the plural discovery named, which is a GVR's part and never a kind (§13.1)"
    );
    assert_eq!(text_of(first, "scope").as_deref(), Some("namespaced"));
    assert_eq!(text_of(first, "namespace").as_deref(), Some("default"));
    assert_eq!(
        text_of(first, "uid").as_deref(),
        Some("aaaaaaaa-aaaa-aaaa-aaaa-000000000001"),
        "identity is the uid for a custom resource exactly as for a Pod (§16.1)"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_type_an_unknown_kind_from_the_schema_the_cluster_publishes() {
    // Gate B (§62.2): where the server publishes a schema, the resource is typed structure
    // rather than raw JSON — and the typing came from the cluster, because this build has never
    // seen the field names it is typing.
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query(
            "k8s-resource",
            at_cluster(&[
                ("kind", json!("Sprocket")),
                ("group", json!("menagerie.example")),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    let record = &records[0];

    assert_eq!(
        text_of(record, "schema_source").as_deref(),
        Some("openapi-v3"),
        "the record says where its typing came from (§12.1)"
    );
    assert_eq!(
        text_of(record, "precision").as_deref(),
        Some("structural"),
        "a structural schema reaches every content field"
    );
    assert_eq!(
        record.get("untyped"),
        Some(&Value::List([].into())),
        "nothing is undescribed, and the empty list says so rather than null"
    );

    let spec = map_of(record, "spec");
    assert_eq!(spec.get("teeth"), Some(&Value::Int(24)));
    assert_eq!(
        spec.get("mode"),
        Some(&Value::String("idle".into())),
        "a described string is a string"
    );
    assert!(
        matches!(spec.get("renewAt"), Some(Value::Timestamp(_))),
        "the schema's `format: date-time` is what makes this an instant rather than text: {:?}",
        spec.get("renewAt")
    );
    let Some(Value::List(tolerances)) = spec.get("tolerances") else {
        panic!("a described list of objects survives as a list");
    };
    let Some(Value::Map(entry)) = tolerances.first() else {
        panic!("its entries survive as maps");
    };
    assert_eq!(entry.get("microns"), Some(&Value::Int(5)));

    // §4 invariant 8 and §33.6: what was asked for and what was observed are never merged.
    let status = map_of(record, "status");
    assert_eq!(status.get("observedTeeth"), Some(&Value::Int(24)));
    assert_eq!(
        spec.get("observedTeeth"),
        None,
        "the observed count is not in the spec, and the spec's is not in the status"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_keep_every_field_of_an_unknown_kind_the_cluster_describes_nowhere() {
    // Gate B's second half (§12.3, §12.5): a schema gap degrades precision and never removes a
    // field. The second invented group publishes no OpenAPI document at all.
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query(
            "k8s-resource",
            at_cluster(&[
                ("kind", json!("Sprocket")),
                ("group", json!("industrial.example")),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    record
        .validate()
        .expect("an undescribed record still conforms");

    assert_eq!(
        text_of(record, "schema_source").as_deref(),
        Some("absent"),
        "nothing described this resource, and the record says so rather than implying typing"
    );
    assert_eq!(text_of(record, "precision").as_deref(), Some("unknown"));
    assert_eq!(
        text_of(record, "scope").as_deref(),
        Some("cluster"),
        "the scope is the server's declaration, and this group's Sprocket is cluster-scoped"
    );
    assert_eq!(
        record.get("namespace"),
        Some(&Value::Null),
        "§9.2: a cluster-scoped object has no namespace rather than an invented one"
    );

    let spec = map_of(record, "spec");
    assert_eq!(
        spec.get("teeth"),
        Some(&Value::Int(96)),
        "the field is present and valued with no schema in sight (§12.5)"
    );
    assert_eq!(
        spec.get("renewAt"),
        Some(&Value::String("2027-01-01T00:00:00Z".into())),
        "and it is text, because nothing claimed it was an instant — precision degraded, the \
         field did not"
    );
    let Some(Value::List(untyped)) = record.get("untyped") else {
        panic!("the undescribed fields are named");
    };
    assert!(
        untyped.contains(&Value::String("/spec/renewAt".into())),
        "each undescribed field is addressable by pointer: {untyped:?}"
    );

    // §12.5 again, for a kind whose content is neither desired nor observed state.
    let other = map_of(record, "other");
    assert!(
        other.get("payload").is_some(),
        "a top-level field outside spec and status is kept rather than dropped: {other:?}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_refuse_an_ambiguous_kind_and_name_the_candidates() {
    // §35.8: a name several types share must not resolve by an arbitrary type priority. Two
    // invented groups both serve a `Sprocket`, and neither of them wins.
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query("k8s-resource", at_cluster(&[("kind", json!("Sprocket"))]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;

    assert!(
        records(&events).is_empty(),
        "nothing was answered from a group nobody chose"
    );
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a structured refusal");
    assert_eq!(error.name, "resolve.ambiguous");
    let help = error.help.unwrap_or_default();
    assert!(
        help.contains("menagerie.example") && help.contains("industrial.example"),
        "the refusal carries the candidates, because `be more specific` without them is a dead \
         end: {help}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_resolve_a_short_name_the_cluster_offers_once_the_group_settles_it() {
    // §13.5: a short name is a typing convenience, and it becomes usable exactly when it is
    // unambiguous — never by this provider picking a winner for it.
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query(
            "k8s-resource",
            at_cluster(&[
                ("resource", json!("spr")),
                ("group", json!("menagerie.example")),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    assert_eq!(records(&events).len(), 2);
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_say_a_kind_is_not_served_rather_than_answer_with_nothing() {
    // §11.5 and §21.4: an unserved resource and an empty collection are different states, and a
    // provider that returned an empty stream would be claiming the cluster has none of them.
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query("k8s-resource", at_cluster(&[("kind", json!("Flywheel"))]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;

    assert!(records(&events).is_empty());
    assert_eq!(
        result.status,
        InvokeStatus::Failed,
        "an unserved kind is a refusal, not a complete answer of length zero"
    );
    let error = result.error.expect("a structured refusal");
    assert_eq!(error.name, "provider.unsupported");
    assert!(
        error.message.contains("Flywheel"),
        "the refusal quotes what was asked for: {}",
        error.message
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_say_a_served_resource_that_cannot_be_listed_is_not_an_empty_collection() {
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query("k8s-resource", at_cluster(&[("kind", json!("Escapement"))]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;

    assert!(records(&events).is_empty());
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a structured refusal");
    assert_eq!(error.name, "provider.unsupported");
    assert!(
        error.message.contains("list"),
        "the refusal says which verb the server does not offer: {}",
        error.message
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_answer_a_query_that_names_no_kind_with_the_cluster_s_own_catalogue() {
    // The honest answer to "which resource?" from a provider that compiles in no list of them:
    // ask the cluster. §15.5 wants what is readable stated rather than assumed.
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query("k8s-resource", at_cluster(&[]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;

    assert!(records(&events).is_empty());
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a structured refusal");
    assert_eq!(error.name, "resolve.ambiguous");
    let help = error.help.unwrap_or_default();
    assert!(
        help.contains("Sprocket") && help.contains("Pod"),
        "the catalogue is the cluster's, and it holds the invented kind beside the built-in \
         one: {help}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_keep_the_redaction_boundary_on_the_dynamic_route() {
    // Gate I is about *every* read path, and a new one is exactly where a payload leaks. A
    // Secret reached generically goes through the same `Guarded` as one reached by name, so
    // there is nothing left to find by the time a record is built (§22, ADR-0003).
    let plugin = loaded_with_custom_resources().await;
    let invocation = plugin
        .query(
            "k8s-resource",
            at_cluster(&[("kind", json!("Secret")), ("group", json!(""))]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    assert_eq!(records.len(), 1);

    let rendered = ono_value::to_json_string(&Value::Record(Arc::clone(&records[0])))
        .expect("a record renders as JSON");
    assert!(
        !rendered.contains(TOKEN_PAYLOAD),
        "the payload must not survive the generic route either: {rendered}"
    );
    assert!(
        rendered.contains("api-token"),
        "the Secret is still readable as an object; it is the values that are gone: {rendered}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[test]
fn should_name_the_invented_kind_nowhere_in_the_implementation() {
    // The claim the tests above rest on: the provider reaches this kind because it is data, not
    // because anything recognises it (§33.1, Gate A). The moment someone special-cases it, this
    // fails.
    for (file, source) in [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("contributions.rs", include_str!("../src/contributions.rs")),
        ("dynamic.rs", include_str!("../src/dynamic.rs")),
        ("query.rs", include_str!("../src/query.rs")),
        ("records.rs", include_str!("../src/records.rs")),
        ("broker.rs", include_str!("../src/broker.rs")),
    ] {
        let code = source.split("#[cfg(test)]").next().unwrap_or_default();
        for invented in [
            "Sprocket",
            "menagerie.example",
            "industrial.example",
            "teeth",
        ] {
            assert!(
                !code.contains(invented),
                "`{file}` names `{invented}`, which exists only in this test: a kind reached by \
                 recognition is not a kind reached dynamically"
            );
        }
    }
}

// --- the Tier 1 operational set of §15.2 -------------------------------------------------------

/// The package loaded against a cluster serving every kind of §15.2's Tier 1 set.
async fn loaded_with_tier_one() -> ono_kuang_supervisor::LoadedPlugin {
    TestHost::new(PLUGIN, MANIFEST)
        .grant(Capability::NetworkConnect)
        .host(RecordedCluster::with_tier_one())
        .load()
        .await
        .expect("the package loads under its own manifest")
}

/// Every record one target answers, with the schema and the conformance already checked.
async fn answered(
    plugin: &ono_kuang_supervisor::LoadedPlugin,
    target: &str,
    schema: &str,
) -> Vec<Arc<RecordValue>> {
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
    assert!(!records.is_empty(), "`{target}` answered nothing");
    for record in &records {
        assert_eq!(
            record.schema_id().to_string(),
            schema,
            "`{target}` answers records of the schema it declared"
        );
        record
            .validate()
            .unwrap_or_else(|error| panic!("`{target}` record does not conform: {error:?}"));
    }
    records
}

fn list_of(record: &RecordValue, field: &str) -> Option<Vec<String>> {
    match record.get(field) {
        Some(Value::List(entries)) => Some(
            entries
                .iter()
                .map(|entry| match entry {
                    Value::String(text) => text.to_string(),
                    other => panic!("a list entry is text, and it is {other:?}"),
                })
                .collect(),
        ),
        Some(Value::Null) | None => None,
        other => panic!("`{field}` is a list or null, and it is {other:?}"),
    }
}

#[tokio::test]
async fn should_answer_for_every_kind_of_the_tier_one_operational_set() {
    // §15.2 names nineteen resources as the first complete operational target, and ADR-0005 held
    // fourteen of them back because a declared schema nothing emits is a promise the package
    // cannot keep. This is the test that makes the promise keepable: every declared word answers
    // records of the schema it declared, over discovery, against one recorded cluster.
    let plugin = loaded_with_tier_one().await;
    for (target, schema) in [
        ("k8s-namespace", "namespace"),
        ("k8s-node", "node"),
        ("k8s-pod", "pod"),
        ("k8s-deployment", "deployment"),
        ("k8s-replicaset", "replicaset"),
        ("k8s-statefulset", "statefulset"),
        ("k8s-daemonset", "daemonset"),
        ("k8s-service", "service"),
        ("k8s-endpointslice", "endpointslice"),
        ("k8s-ingress", "ingress"),
        ("k8s-job", "job"),
        ("k8s-cronjob", "cronjob"),
        ("k8s-configmap", "configmap"),
        ("k8s-secret", "secret"),
        ("k8s-serviceaccount", "serviceaccount"),
        ("k8s-persistentvolumeclaim", "persistentvolumeclaim"),
        ("k8s-persistentvolume", "persistentvolume"),
        ("k8s-storageclass", "storageclass"),
        ("k8s-networkpolicy", "networkpolicy"),
    ] {
        answered(
            &plugin,
            target,
            &format!("io.github.godspeed-you.kubernetes.{schema}/1"),
        )
        .await;
    }
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_name_the_controller_above_a_replica_set_from_its_owner_reference() {
    // §25.2 and §24.3: the owner reference marked `controller: true` is the canonical evidence
    // for which Deployment controls this ReplicaSet — the strongest evidence class §23 defines,
    // and never a guess from a shared name prefix.
    let plugin = loaded_with_tier_one().await;
    let records = answered(
        &plugin,
        "k8s-replicaset",
        "io.github.godspeed-you.kubernetes.replicaset/1",
    )
    .await;
    let replicaset = &records[0];
    assert_eq!(text_of(replicaset, "controller").as_deref(), Some("api"));
    assert_eq!(
        text_of(replicaset, "controller_kind").as_deref(),
        Some("Deployment"),
        "an owner reference names a kind, and the record does not assume which"
    );
    assert_eq!(replicaset.get("desired_replicas"), Some(&Value::Int(3)));
    assert_eq!(replicaset.get("ready_replicas"), Some(&Value::Int(2)));
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_state_a_reconciliation_with_the_rule_and_the_fields_it_rests_on() {
    // Gate G and §37.5: a derived state arrives with the rule that derived it and the fields that
    // rule read. §37.3 is the sharper half — the StatefulSet below has a controller *behind* its
    // own generation, and the Job has none of the evidence a convergence rule would need.
    let plugin = loaded_with_tier_one().await;
    let records = answered(
        &plugin,
        "k8s-statefulset",
        "io.github.godspeed-you.kubernetes.statefulset/1",
    )
    .await;
    let set = &records[0];
    let Some(Value::Map(reconciliation)) = set.get("reconciliation") else {
        panic!("`reconciliation` is a map");
    };
    assert_eq!(
        reconciliation.get("state"),
        Some(&Value::String(
            "desired state changed; controller not yet observed".into()
        )),
        "observedGeneration 4 is behind generation 5, and that is what the state says"
    );
    assert_eq!(
        reconciliation.get("rule"),
        Some(&Value::String("generation-ahead-of-observed".into())),
        "the rule is named so a reader can look it up and disagree with it"
    );
    assert_eq!(
        reconciliation.get("verified_convergence"),
        Some(&Value::Bool(false)),
        "§37.3: nothing here is a claim of health"
    );
    let Some(Value::List(evidence)) = reconciliation.get("evidence") else {
        panic!("the evidence is a list of citations");
    };
    assert!(
        evidence
            .iter()
            .any(|entry| matches!(entry, Value::String(text)
                if text.contains("/metadata/generation"))),
        "every field the rule read is cited: {evidence:?}"
    );
    assert!(
        !evidence.is_empty(),
        "§37.5 forbids a derived state with no citations"
    );

    // The rollout state an operator actually reads, beside it.
    assert_eq!(
        text_of(set, "current_revision").as_deref(),
        Some("ledger-6f4")
    );
    assert_eq!(
        text_of(set, "update_revision").as_deref(),
        Some("ledger-9ab"),
        "different from the current revision means a rollout is in progress"
    );
    assert_eq!(
        text_of(set, "service_name").as_deref(),
        Some("ledger-headless"),
        "§25.3's governing Service, from `spec.serviceName` and never from the set's own name"
    );
    assert_eq!(
        list_of(set, "claim_templates"),
        Some(vec!["data".to_owned()]),
        "template intent, which §25.3 requires to stay distinguishable from materialised claims"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_count_a_daemon_set_per_node_rather_than_per_replica() {
    // §25.4: a DaemonSet's rollout is measured across nodes. Every count below is deliberately
    // different from every other, so a projection reading the wrong field is visible.
    let plugin = loaded_with_tier_one().await;
    let records = answered(
        &plugin,
        "k8s-daemonset",
        "io.github.godspeed-you.kubernetes.daemonset/1",
    )
    .await;
    let daemonset = &records[0];
    assert_eq!(daemonset.get("desired_scheduled"), Some(&Value::Int(5)));
    assert_eq!(daemonset.get("current_scheduled"), Some(&Value::Int(5)));
    assert_eq!(daemonset.get("ready_scheduled"), Some(&Value::Int(4)));
    assert_eq!(
        daemonset.get("updated_scheduled"),
        Some(&Value::Int(3)),
        "how far the rollout has reached across the fleet"
    );
    assert_eq!(
        daemonset.get("misscheduled"),
        Some(&Value::Int(1)),
        "running where it should no longer be, which is the signal a selector change leaves"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_keep_a_service_s_ports_structured_and_its_absent_selector_null() {
    // §31.4 asks for fields a later layer can relate to a socket or a load balancer, so the ports
    // stay structured rather than becoming `http 80/TCP`. §26.1 is the other half: a
    // selector-less Service must produce no guessed Pod edges, so its selector is null rather
    // than an empty map that reads as "selects nothing in particular".
    let plugin = loaded_with_tier_one().await;
    let records = answered(
        &plugin,
        "k8s-service",
        "io.github.godspeed-you.kubernetes.service/1",
    )
    .await;
    let api = &records[0];
    assert_eq!(
        text_of(api, "service_type").as_deref(),
        Some("LoadBalancer")
    );
    assert_eq!(text_of(api, "cluster_ip").as_deref(), Some("10.96.0.42"));
    assert_eq!(
        list_of(api, "load_balancer"),
        Some(vec!["lb.example".to_owned()]),
        "an entry states an `ip` or a `hostname`, and whichever it states is what is recorded"
    );
    let ports = map_of(api, "ports");
    let Some(Value::Map(http)) = ports.get("http") else {
        panic!(
            "a named port is keyed by its name, and it is {:?}",
            ports.get("http")
        );
    };
    assert_eq!(http.get("port"), Some(&Value::Int(80)));
    assert_eq!(http.get("targetPort"), Some(&Value::Int(8080)));
    assert!(
        ports.get("443").is_some(),
        "an unnamed port is keyed by its number rather than dropped: {ports:?}"
    );
    let selector = map_of(api, "selector");
    assert_eq!(selector.get("app"), Some(&Value::String("api".into())));

    let headless = &records[1];
    assert_eq!(
        headless.get("selector"),
        Some(&Value::Null),
        "§26.1: a selector-less Service creates no guessed edges, and the null is what says so"
    );
    assert_eq!(
        text_of(headless, "cluster_ip").as_deref(),
        Some("None"),
        "a headless Service is a deliberate configuration, not a missing address"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_keep_an_endpoint_without_a_target_reference_an_endpoint_fact() {
    // §26.4: an endpoint with no `targetRef` is an address that answers, and forcing it into a
    // Pod relationship would invent one. So `addresses` is longer than `targets`, and the
    // difference is exactly the external endpoint.
    let plugin = loaded_with_tier_one().await;
    let records = answered(
        &plugin,
        "k8s-endpointslice",
        "io.github.godspeed-you.kubernetes.endpointslice/1",
    )
    .await;
    let slice = &records[0];
    assert_eq!(text_of(slice, "address_type").as_deref(), Some("IPv4"));
    assert_eq!(
        text_of(slice, "service_name").as_deref(),
        Some("api"),
        "§26.2's standard label, which is convention evidence rather than API structure"
    );
    assert_eq!(slice.get("endpoint_count"), Some(&Value::Int(3)));
    assert_eq!(
        slice.get("ready_endpoints"),
        Some(&Value::Int(2)),
        "an endpoint that states `ready: false` is not ready, and one that states nothing is not \
         counted ready either"
    );
    assert_eq!(
        list_of(slice, "addresses"),
        Some(vec![
            "10.1.2.3".to_owned(),
            "10.1.2.4".to_owned(),
            "203.0.113.9".to_owned(),
        ])
    );
    assert_eq!(
        list_of(slice, "targets"),
        Some(vec!["api-7d9f-abc".to_owned(), "api-7d9f-def".to_owned()]),
        "the external address contributes no target rather than a blank one"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_report_every_service_an_ingress_routes_to_and_the_secrets_it_terminates_with() {
    // §27.1: routes-to, uses-tls-secret and the load-balancer address. Both backends are found —
    // the default backend and every rule path — so an ingress with two services does not report
    // one.
    let plugin = loaded_with_tier_one().await;
    let records = answered(
        &plugin,
        "k8s-ingress",
        "io.github.godspeed-you.kubernetes.ingress/1",
    )
    .await;
    let ingress = &records[0];
    assert_eq!(text_of(ingress, "ingress_class").as_deref(), Some("nginx"));
    assert_eq!(
        list_of(ingress, "hosts"),
        Some(vec!["shop.example".to_owned()])
    );
    assert_eq!(
        list_of(ingress, "services"),
        Some(vec!["api".to_owned(), "assets".to_owned()]),
        "every rule path's backend, in the order the rules list them"
    );
    assert_eq!(
        list_of(ingress, "tls_secrets"),
        Some(vec!["shop-tls".to_owned()])
    );
    assert_eq!(
        list_of(ingress, "load_balancer"),
        Some(vec!["198.51.100.7".to_owned()])
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_say_what_a_job_completed_and_which_cron_job_created_it() {
    // §25.5's ownership, and the desired-versus-observed pair a job actually has: what it was
    // asked to complete beside what it has.
    let plugin = loaded_with_tier_one().await;
    let jobs = answered(
        &plugin,
        "k8s-job",
        "io.github.godspeed-you.kubernetes.job/1",
    )
    .await;
    let job = &jobs[0];
    assert_eq!(job.get("completions"), Some(&Value::Int(1)));
    assert_eq!(job.get("succeeded"), Some(&Value::Int(1)));
    assert_eq!(
        job.get("failed"),
        Some(&Value::Null),
        "the status is silent about failures, and that is unknown rather than zero"
    );
    assert_eq!(
        text_of(job, "complete").as_deref(),
        Some("True"),
        "the condition's status verbatim: `True`, `False` and `Unknown` are three states"
    );
    assert_eq!(job.get("failure_reason"), Some(&Value::Null));
    assert!(matches!(job.get("start_time"), Some(Value::Timestamp(_))));
    assert_eq!(text_of(job, "controller").as_deref(), Some("nightly"));
    assert_eq!(text_of(job, "controller_kind").as_deref(), Some("CronJob"));

    let cronjobs = answered(
        &plugin,
        "k8s-cronjob",
        "io.github.godspeed-you.kubernetes.cronjob/1",
    )
    .await;
    let cronjob = &cronjobs[0];
    assert_eq!(text_of(cronjob, "schedule").as_deref(), Some("0 2 * * *"));
    assert_eq!(cronjob.get("suspend"), Some(&Value::Bool(false)));
    assert_eq!(
        list_of(cronjob, "active_jobs"),
        Some(vec!["nightly-28291".to_owned()]),
        "the live set, and never a history §25.5 forbids reconstructing"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_not_treat_a_pending_claim_with_no_volume_name_as_bound() {
    // §30.2, stated as a null rather than as prose: the second claim is Pending and names no
    // volume, and nothing fills that gap from its phase or its storage class.
    let plugin = loaded_with_tier_one().await;
    let claims = answered(
        &plugin,
        "k8s-persistentvolumeclaim",
        "io.github.godspeed-you.kubernetes.persistentvolumeclaim/1",
    )
    .await;
    let bound = &claims[0];
    assert_eq!(text_of(bound, "phase").as_deref(), Some("Bound"));
    assert_eq!(text_of(bound, "volume_name").as_deref(), Some("pv-0001"));
    assert_eq!(
        text_of(bound, "requested_storage").as_deref(),
        Some("10Gi"),
        "what was asked for"
    );
    assert_eq!(
        text_of(bound, "bound_capacity").as_deref(),
        Some("10Gi"),
        "and what it got, kept apart because they can differ"
    );

    let pending = &claims[1];
    assert_eq!(text_of(pending, "phase").as_deref(), Some("Pending"));
    assert_eq!(
        pending.get("volume_name"),
        Some(&Value::Null),
        "§30.2: a Pending claim with no volumeName MUST NOT be treated as bound"
    );
    assert_eq!(pending.get("bound_capacity"), Some(&Value::Null));

    // The other end of the binding, and what deleting it would do to the storage (§30.5).
    let volumes = answered(
        &plugin,
        "k8s-persistentvolume",
        "io.github.godspeed-you.kubernetes.persistentvolume/1",
    )
    .await;
    let volume = &volumes[0];
    assert_eq!(
        volume.get("namespace"),
        None,
        "a PersistentVolume is cluster-scoped, so its schema has no namespace at all (§9.2)"
    );
    assert_eq!(
        text_of(volume, "claim").as_deref(),
        Some("default/data-ledger-0")
    );
    assert_eq!(text_of(volume, "reclaim_policy").as_deref(), Some("Retain"));
    assert_eq!(
        text_of(volume, "csi_driver").as_deref(),
        Some("ebs.csi.aws.com"),
        "the driver name only: resolving it to a cloud disk belongs to a cross-system resolver \
         and would link this package to a cloud SDK (§30.4, Gate K)"
    );

    let classes = answered(
        &plugin,
        "k8s-storageclass",
        "io.github.godspeed-you.kubernetes.storageclass/1",
    )
    .await;
    let class = &classes[0];
    assert_eq!(
        text_of(class, "volume_binding_mode").as_deref(),
        Some("WaitForFirstConsumer"),
        "which is why a Pending claim can be entirely correct"
    );
    assert_eq!(
        text_of(class, "reclaim_policy").as_deref(),
        Some("Delete"),
        "a StorageClass states it at the top level where a volume states it under `spec`"
    );
    assert_eq!(class.get("is_default"), Some(&Value::Bool(true)));
    assert_eq!(
        map_of(class, "parameters").get("type"),
        Some(&Value::String("gp3".into())),
        "the driver's own vocabulary, uninterpreted"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_keep_a_network_policy_s_peers_in_the_structure_the_api_states_them() {
    // §31.2: the peers combine namespace selectors, pod selectors and IP blocks, and MUST NOT be
    // reduced to a misleading boolean. §31.3: the object is intent, and no field here claims the
    // installed network implementation enforces it.
    let plugin = loaded_with_tier_one().await;
    let records = answered(
        &plugin,
        "k8s-networkpolicy",
        "io.github.godspeed-you.kubernetes.networkpolicy/1",
    )
    .await;
    let policy = &records[0];
    assert_eq!(
        list_of(policy, "policy_types"),
        Some(vec!["Ingress".to_owned()])
    );
    let selector = map_of(policy, "pod_selector");
    let Some(Value::Map(labels)) = selector.get("matchLabels") else {
        panic!("the selector keeps its native structure");
    };
    assert_eq!(labels.get("app"), Some(&Value::String("api".into())));

    let rules = map_of(policy, "rules");
    let Some(Value::List(ingress)) = rules.get("ingress") else {
        panic!("the ingress rules survive as a list");
    };
    let Some(Value::Map(rule)) = ingress.first() else {
        panic!("each rule survives as a map");
    };
    let Some(Value::List(from)) = rule.get("from") else {
        panic!("the peers survive");
    };
    assert_eq!(
        from.len(),
        2,
        "a namespace selector and an IP block, both kept"
    );
    let Some(Value::Map(block)) = from.get(1) else {
        panic!("the IP block survives as a map");
    };
    let Some(Value::Map(cidr)) = block.get("ipBlock") else {
        panic!("with its cidr and its exceptions");
    };
    assert_eq!(
        cidr.get("cidr"),
        Some(&Value::String("10.0.0.0/8".into())),
        "the exceptions are what a boolean summary would lose (§31.2)"
    );
    assert_eq!(
        rules.get("egress"),
        None,
        "a policy with no egress block states none"
    );

    let rendered = ono_value::to_json_string(&Value::Record(Arc::clone(policy)))
        .expect("a record renders as JSON");
    assert!(
        !rendered.contains("enforced") && !rendered.contains("internet_access"),
        "§31.3: nothing here claims the network plugin enforces this policy: {rendered}"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_answer_a_config_map_with_its_key_names_and_whether_it_may_still_change() {
    // §29.4: the immutable flag decides whether a prospective change is possible at all. And the
    // keys come across the same boundary a Secret's do, because a schema whose shape depended on
    // whether the payload is sensitive would make redaction a per-kind decision (ADR-0003).
    let plugin = loaded_with_tier_one().await;
    let records = answered(
        &plugin,
        "k8s-configmap",
        "io.github.godspeed-you.kubernetes.configmap/1",
    )
    .await;
    let configmap = &records[0];
    assert_eq!(
        list_of(configmap, "keys"),
        Some(vec!["endpoint".to_owned(), "log_level".to_owned()]),
        "sorted, because a JSON object states no order"
    );
    assert_eq!(
        list_of(configmap, "binary_keys"),
        Some(vec!["seed.bin".to_owned()]),
        "binary and text entries are consumed differently, so they are two fields"
    );
    assert_eq!(configmap.get("immutable"), Some(&Value::Bool(true)));

    let accounts = answered(
        &plugin,
        "k8s-serviceaccount",
        "io.github.godspeed-you.kubernetes.serviceaccount/1",
    )
    .await;
    let account = &accounts[0];
    assert_eq!(
        list_of(account, "secrets"),
        Some(vec!["api-token".to_owned()])
    );
    assert_eq!(
        list_of(account, "image_pull_secrets"),
        Some(vec!["registry-pull".to_owned()]),
        "§32.1's image-pull relationship, as names and never as payload"
    );
    assert_eq!(
        account.get("automount_token"),
        Some(&Value::Bool(false)),
        "what the account asked for, which a pod spec may still override either way"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_read_any_tier_one_kind_by_name_as_well_as_by_collection() {
    // §17.1 across the kinds this session wired: `--name` is an option on every one of them,
    // not on the five that happened to exist first.
    let cluster = RecordedCluster::with_tier_one();
    let plugin = loaded_against(Arc::clone(&cluster)).await;
    let invocation = plugin
        .query("k8s-service", at_cluster(&[("name", json!("api"))]))
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    // The recorded server has no object endpoint for it, so the answer is the honest one: the
    // object is not there. What this test pins is that the *route* is the object endpoint.
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    assert!(records(&events).is_empty());
    assert!(
        cluster
            .heads()
            .iter()
            .any(|head| head.starts_with("GET /api/v1/namespaces/default/services/api ")),
        "the service's own endpoint was asked, not the collection: {:?}",
        cluster.heads()
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

// --- relationships, and the evidence under each one (§23–§32, Gate D) --------------------------

/// The package loaded against a cluster whose objects state relationships.
async fn loaded_with_relations() -> ono_kuang_supervisor::LoadedPlugin {
    loaded_for_relations(RecordedCluster::with_relations()).await
}

/// One relationship query costs more round trips than a listing does: the two discovery
/// documents, a resource list per served group, the object's own endpoint, and a collection for
/// every derivation that needs a second reading. The host's default call deadline is five seconds
/// and this suite runs beside the whole workspace, so a loaded machine can starve one of those
/// calls — and the failure would then be about the machine rather than about the relationships
/// this file exists to prove. `tests/isolation.rs` records the same reasoning for the same
/// reason; nothing here is testing how fast a host answers.
async fn loaded_for_relations(cluster: Arc<RecordedCluster>) -> ono_kuang_supervisor::LoadedPlugin {
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

/// Every edge `k8s-relation` answers about one object, with the schema already checked.
async fn edges(
    plugin: &ono_kuang_supervisor::LoadedPlugin,
    extra: &[(&str, Json)],
) -> Vec<Arc<RecordValue>> {
    let invocation = plugin
        .query("k8s-relation", at_cluster(extra))
        .await
        .expect("`k8s-relation` is a contributed target");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "an object whose every derivation was readable answers completely: {:?}",
        result.error
    );
    let records = records(&events);
    for record in &records {
        assert_eq!(
            record.schema_id().to_string(),
            "io.github.godspeed-you.kubernetes.relation/1",
            "an edge carries the one schema the package declares for edges"
        );
        record
            .validate()
            .expect("the record conforms to the schema it carries");
    }
    records
}

/// The one edge of that relation to that target, or a failure naming what did arrive.
fn edge<'a>(
    records: &'a [Arc<RecordValue>],
    relation: &str,
    target_name: &str,
) -> &'a Arc<RecordValue> {
    records
        .iter()
        .find(|record| {
            text_of(record, "relation").as_deref() == Some(relation)
                && text_of(record, "target_name").as_deref() == Some(target_name)
        })
        .unwrap_or_else(|| {
            let seen: Vec<String> = records
                .iter()
                .map(|record| {
                    format!(
                        "{} -> {}",
                        text_of(record, "relation").unwrap_or_default(),
                        text_of(record, "target_name").unwrap_or_default()
                    )
                })
                .collect();
            panic!("no `{relation}` edge to `{target_name}`; the edges are {seen:?}")
        })
}

#[tokio::test]
async fn should_answer_what_a_pod_is_related_to_with_the_evidence_under_each_edge() {
    // Gate D (§62.4) end to end: every edge a Pod states about itself reaches a user, and each
    // one says which of §23's six classes it came from and which field decided it.
    let plugin = loaded_with_relations().await;
    let records = edges(
        &plugin,
        &[("kind", json!("Pod")), ("name", json!("api-7d9f-abc"))],
    )
    .await;

    let relations: Vec<String> = records
        .iter()
        .map(|record| text_of(record, "relation").unwrap_or_default())
        .collect();
    for expected in [
        "owned-by",
        "controlled-by",
        "scheduled-on",
        "runs-as",
        "references-config",
        "references-secret",
    ] {
        assert!(
            relations.contains(&expected.to_owned()),
            "the Pod states a `{expected}` relationship, and the edges are {relations:?}"
        );
    }

    for record in &records {
        assert_eq!(
            text_of(record, "uid").as_deref(),
            Some("11111111-1111-1111-1111-111111111111"),
            "an edge is a fact about the object it starts at, and identity is its uid (§16.1)"
        );
        assert_eq!(text_of(record, "name").as_deref(), Some("api-7d9f-abc"));
        assert_eq!(text_of(record, "kind").as_deref(), Some("Pod"));
        assert_eq!(
            text_of(record, "source").as_deref(),
            Some("k8s://recorded/ns/default/pod/api-7d9f-abc"),
            "the near end is a place, built by the place grammar rather than formatted (§35.4)"
        );
        assert!(
            text_of(record, "evidence").is_some_and(|evidence| !evidence.is_empty()),
            "Gate D: an edge that cannot say what it rests on is one a user has to trust"
        );
    }

    // §28.1: a native field decided it, and the record names the pointer that was read.
    let node = edge(&records, "scheduled-on", "node-a");
    assert_eq!(
        text_of(node, "evidence_class").as_deref(),
        Some("native-field")
    );
    assert_eq!(
        text_of(node, "evidence_path").as_deref(),
        Some("/spec/nodeName"),
        "Gate D asks for the source fields used, and a class without a pointer is half an answer"
    );
    assert_eq!(
        text_of(node, "evidence").as_deref(),
        Some("/spec/nodeName = node-a")
    );
    assert_eq!(
        node.get("asserted"),
        Some(&Value::Bool(true)),
        "the API server states `spec.nodeName`; this provider only read it"
    );
    assert_eq!(
        text_of(node, "target").as_deref(),
        Some("k8s://recorded/cluster/node/node-a"),
        "a Node is cluster-scoped, so the address has no namespace slot (§9.2, ADR-0008)"
    );
    assert_eq!(
        node.get("target_namespace"),
        Some(&Value::Null),
        "the Pod's namespace is not copied onto a cluster-scoped target (§24.2)"
    );
    assert_eq!(
        list_of(node, "target_roles"),
        Some(vec!["compute-node".to_owned()]),
        "§36.2's role overlay travels with the far end, and the native kind stays beside it"
    );

    // §29.1 and §29.2: a config and a secret reference are two edges, each citing the container
    // path that carries it.
    let config = edge(&records, "references-config", "api-config");
    assert_eq!(
        text_of(config, "evidence_path").as_deref(),
        Some("/spec/containers/0/envFrom/0/configMapRef/name"),
        "the edge retains how the ConfigMap is consumed (§29.1)"
    );
    let secret = edge(&records, "references-secret", "api-token");
    assert_eq!(
        text_of(secret, "evidence_path").as_deref(),
        Some("/spec/volumes/0/secret/secretName")
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_keep_an_edge_whose_target_was_never_read() {
    // §24.1: a relationship whose far end nobody looked at is a relationship, not a broken edge.
    // The Node, the ServiceAccount and the ConfigMap below were never fetched, and every one of
    // them is still addressable — with the lifetime identity left absent rather than invented.
    let plugin = loaded_with_relations().await;
    let records = edges(
        &plugin,
        &[("kind", json!("Pod")), ("name", json!("api-7d9f-abc"))],
    )
    .await;
    let node = edge(&records, "scheduled-on", "node-a");
    assert_eq!(
        node.get("target_resolved"),
        Some(&Value::Bool(false)),
        "nothing read the Node, and the edge says so rather than disappearing"
    );
    assert_eq!(
        node.get("target_uid"),
        Some(&Value::Null),
        "an unread target has no lifetime identity, and null is what that is (§16.1)"
    );
    assert_eq!(text_of(node, "target_kind").as_deref(), Some("Node"));

    // An owner reference is the opposite case: it carries the owner's UID without the owner
    // having been read, which is what makes the far end provable rather than a name match.
    let owner = edge(&records, "owned-by", "api-7d9f");
    assert_eq!(
        text_of(owner, "target_uid").as_deref(),
        Some("a1a1a1a1-0000-0000-0000-000000000001"),
        "§24.1: a dangling edge keeps its target identity evidence"
    );
    assert_eq!(
        owner.get("target_resolved"),
        Some(&Value::Bool(false)),
        "carrying a UID is not the same as having read the object it names"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_say_an_owner_reference_names_the_controller_where_it_does() {
    // §24.3: `controller: true` earns the stronger word while generic `owned-by` is preserved,
    // so a caller that wants all ownership does not have to know which of the two to ask for.
    let plugin = loaded_with_relations().await;
    let records = edges(
        &plugin,
        &[("kind", json!("Pod")), ("name", json!("api-7d9f-abc"))],
    )
    .await;
    for relation in ["owned-by", "controlled-by"] {
        let owner = edge(&records, relation, "api-7d9f");
        assert_eq!(
            text_of(owner, "evidence_class").as_deref(),
            Some("owner-reference")
        );
        assert_eq!(
            text_of(owner, "evidence").as_deref(),
            Some("metadata.ownerReferences with controller: true"),
            "§23.2 requires the controller flag to be preserved, not only the reference"
        );
        assert_eq!(
            owner.get("asserted"),
            Some(&Value::Bool(true)),
            "the API server maintains `metadata.ownerReferences`"
        );
        assert_eq!(text_of(owner, "target_kind").as_deref(), Some("ReplicaSet"));
        assert_eq!(
            text_of(owner, "target_namespace").as_deref(),
            Some("default"),
            "a namespaced dependent's owner is namespace-local (§24.2)"
        );
    }
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_derive_a_service_s_selection_from_labels_and_say_that_it_derived_it() {
    // §23.3 and §26.1: the API server states a selector and it states some labels, and it is
    // *this provider* that evaluated one against the other. A record that lost that distinction
    // would let a derivation read as an assertion (§4 invariant 20).
    let plugin = loaded_with_relations().await;
    let records = edges(
        &plugin,
        &[("kind", json!("Service")), ("name", json!("api"))],
    )
    .await;

    let selected = edge(&records, "selects", "api-7d9f-abc");
    assert_eq!(
        text_of(selected, "evidence_class").as_deref(),
        Some("selector")
    );
    assert_eq!(
        selected.get("asserted"),
        Some(&Value::Bool(false)),
        "a selector edge is derived; nothing in the API states it"
    );
    assert_eq!(
        text_of(selected, "evidence").as_deref(),
        Some("selector {app=api} matched labels {app=api}"),
        "§23.3: the selector and the observed label set are the evidence, and both are named"
    );
    assert_eq!(
        selected.get("target_resolved"),
        Some(&Value::Bool(true)),
        "the Pod was read, so the far end carries its lifetime identity"
    );
    assert_eq!(
        text_of(selected, "target_uid").as_deref(),
        Some("11111111-1111-1111-1111-111111111111")
    );

    assert!(
        !records
            .iter()
            .any(|record| text_of(record, "target_name").as_deref() == Some("worker-1")),
        "the second Pod's labels do not satisfy the selector, and a namespace is not a selector"
    );

    // §26.2: the slice is reached by the standard service-name label, which is a convention
    // rather than API structure — and the edge says which.
    let slice = edge(&records, "represented-by", "api-x7k2");
    assert_eq!(
        text_of(slice, "evidence_class").as_deref(),
        Some("convention"),
        "§23.4: a well-known label is not the same evidence as a field the API maintains"
    );
    assert_eq!(
        text_of(slice, "evidence").as_deref(),
        Some("kubernetes.io/service-name = api")
    );
    assert_eq!(slice.get("asserted"), Some(&Value::Bool(false)));
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_keep_the_host_and_path_of_a_routing_edge_attached_to_it() {
    // §27.1: "which Service" without "for which URL" answers a question nobody asked, so the
    // host, path and port stay on the edge as evidence that qualifies it rather than decides it.
    let plugin = loaded_with_relations().await;
    let records = edges(
        &plugin,
        &[("kind", json!("Ingress")), ("name", json!("public"))],
    )
    .await;
    let route = edge(&records, "routes-to", "api");
    let supporting = list_of(route, "supporting").expect("a routing edge carries its qualifiers");
    let joined = supporting.join(" | ");
    for expected in ["shop.example", "/"] {
        assert!(
            joined.contains(expected),
            "the route's `{expected}` stays attached to the edge: {supporting:?}"
        );
    }
    let tls = edge(&records, "uses-tls-secret", "shop-tls");
    assert_eq!(
        text_of(tls, "evidence_class").as_deref(),
        Some("native-field")
    );
    let class = edge(&records, "uses-ingress-class", "nginx");
    assert_eq!(
        class.get("target_namespace"),
        Some(&Value::Null),
        "an IngressClass is cluster-scoped (§9.5)"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_never_present_an_inference_as_a_relationship() {
    // §23.5 and §4 invariant 20: name similarity, IP matching and human convention are not
    // promoted to verified relationships. Nothing in this provider produces the class at all,
    // and this is the assertion that would fail the day something did.
    let plugin = loaded_with_relations().await;
    for (kind, name) in [
        ("Pod", "api-7d9f-abc"),
        ("Service", "api"),
        ("Ingress", "public"),
        ("ConfigMap", "api-config"),
    ] {
        let records = edges(&plugin, &[("kind", json!(kind)), ("name", json!(name))]).await;
        for record in &records {
            let class = text_of(record, "evidence_class").unwrap_or_default();
            assert_ne!(
                class, "inference",
                "`{kind}/{name}` produced an inferred edge, which §23.5 forbids"
            );
            assert!(
                [
                    "native-field",
                    "owner-reference",
                    "selector",
                    "convention",
                    "adapter-derivation",
                ]
                .contains(&class.as_str()),
                "every edge names one of Gate D's classes, and this one names `{class}`"
            );
        }
    }
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_answer_one_relation_word_when_the_query_names_one() {
    // §35.7: `follow` traverses a named relationship type, and the word it takes is the word
    // the record carries. A word this provider does not know is refused rather than answered
    // with nothing, because silence would read as "there are no such edges".
    let plugin = loaded_with_relations().await;
    let scheduled = edges(
        &plugin,
        &[
            ("kind", json!("Pod")),
            ("name", json!("api-7d9f-abc")),
            ("relation", json!("scheduled-on")),
        ],
    )
    .await;
    assert_eq!(scheduled.len(), 1, "one Pod is scheduled on one Node");
    assert_eq!(
        text_of(&scheduled[0], "relation").as_deref(),
        Some("scheduled-on")
    );

    let invocation = plugin
        .query(
            "k8s-relation",
            at_cluster(&[
                ("kind", json!("Pod")),
                ("name", json!("api-7d9f-abc")),
                ("relation", json!("sits-near")),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Failed,
        "a relationship word nobody defines is not an empty answer"
    );
    assert!(records(&events).is_empty());
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_refuse_a_relationship_query_that_names_no_object() {
    // A relationship is a fact about one object. Asking for the edges of a whole collection
    // without naming the object would fan out reads nobody asked for, and answering nothing
    // would say the object has no relationships.
    let plugin = loaded_with_relations().await;
    let invocation = plugin
        .query("k8s-relation", at_cluster(&[("kind", json!("Pod"))]))
        .await
        .expect("the query starts");
    let (_, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Failed);
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_say_a_derivation_that_could_not_read_is_a_gap_rather_than_an_absence() {
    // §4 invariant 13 and §21.4 on the derived half of the graph. A Service's `selects` edges are
    // evaluated against the Pods of its namespace; when that enumeration is refused, the edges
    // that *were* derived are true and cross, and the invocation then fails naming what was
    // missing. Answering the readable edges and completing would say the Service selects nothing,
    // which is the one thing a refusal never means (ADR-0004, ADR-0007).
    let plugin = loaded_for_relations(RecordedCluster::with_relations_denying_pod_list()).await;
    let invocation = plugin
        .query(
            "k8s-relation",
            at_cluster(&[("kind", json!("Service")), ("name", json!("api"))]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Failed,
        "a derivation that could not read everything it needed is not a complete answer"
    );
    let message = result
        .error
        .as_ref()
        .map(|error| error.message.clone())
        .unwrap_or_default();
    assert!(
        message.contains("list denied"),
        "the failure names §21.4's outcome rather than only that something went wrong: {message}"
    );

    let answered = records(&events);
    assert!(
        answered
            .iter()
            .any(|record| text_of(record, "relation").as_deref() == Some("represented-by")),
        "the edges the provider could derive are true and still cross"
    );
    assert!(
        !answered
            .iter()
            .any(|record| text_of(record, "relation").as_deref() == Some("selects")),
        "a selector evaluated against a collection nobody could read is not a selector that \
         matched nothing"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_read_ownership_downwards_and_say_the_reversal_is_a_derivation() {
    // §25.1: the owner-reference chain is canonical for the ReplicaSets a Deployment controls,
    // and the record of that reference lives on the *child*. Reading it from the owner's end is
    // this provider's doing, so the edge keeps the owner reference as its deciding evidence and
    // says in `supporting` that the direction was reversed — §23 does not let a derivation pass
    // as something the object stated.
    let plugin = loaded_with_relations().await;
    let records = edges(
        &plugin,
        &[("kind", json!("Deployment")), ("name", json!("api"))],
    )
    .await;
    for relation in ["owns", "controls"] {
        let child = edge(&records, relation, "api-7d9f");
        assert_eq!(
            text_of(child, "evidence_class").as_deref(),
            Some("owner-reference"),
            "the reference the child carries is what decides the edge"
        );
        assert_eq!(
            child.get("target_resolved"),
            Some(&Value::Bool(true)),
            "the child was read, so the far end carries its lifetime identity"
        );
        assert_eq!(
            text_of(child, "target_uid").as_deref(),
            Some("a1a1a1a1-0000-0000-0000-000000000001"),
            "ownership is matched by UID: a Deployment recreated under one name is a second \
             lifetime and does not inherit the first one's children (§16.3)"
        );
        let supporting =
            list_of(child, "supporting").expect("the reversal is stated rather than assumed");
        assert!(
            supporting
                .iter()
                .any(|entry| entry.starts_with("adapter-derivation:")
                    && entry.contains("owner-reference reversal")),
            "the direction is this provider's derivation, and it says so: {supporting:?}"
        );
    }
    plugin.shutdown(ShutdownReason::Unload).await;
}

// --- §14.1's last four fields, at the boundary --------------------------------------------------

/// One entry of a `map` field, as text.
fn map_entry(record: &RecordValue, field: &str, key: &str) -> Option<String> {
    match record.get(field) {
        Some(Value::Map(map)) => match map.get(key) {
            Some(Value::String(text)) => Some(text.to_string()),
            Some(Value::Null) | None => None,
            other => panic!("`{field}.{key}` is text, and it is {other:?}"),
        },
        Some(Value::Null) | None => None,
        other => panic!("`{field}` is a map or null, and it is {other:?}"),
    }
}

/// The `owner_references` list, each reference as its own map.
fn owner_references(record: &RecordValue) -> Vec<std::sync::Arc<ono_value::MapValue>> {
    match record.get("owner_references") {
        Some(Value::List(entries)) => entries
            .iter()
            .map(|entry| match entry {
                Value::Map(map) => std::sync::Arc::clone(map),
                other => panic!("an owner reference is a map, and it is {other:?}"),
            })
            .collect(),
        other => panic!("`owner_references` is a list, and it is {other:?}"),
    }
}

/// Asserts everything §14.5, §14.6 and §14.7 require of one record's metadata.
///
/// Written once and used for a curated kind and a discovered one, because that is the claim:
/// §14's projection is common to every Kubernetes object, so a CRD nobody compiled in reaches its
/// annotations by exactly the route a Pod does (§33.1, Gate A).
fn assert_metadata_projection(
    record: &RecordValue,
    annotation: (&str, &str),
    finalizer: &str,
    owner: (&str, &str, bool),
    managers: &[&str],
) {
    // §14.5: a structured map, not a rendered string. The assertion is on one key, because
    // reading one key is what a map is for and what text would take away.
    assert_eq!(
        map_entry(record, "annotations", annotation.0).as_deref(),
        Some(annotation.1),
        "§14.5: annotations are a map with keys in it, not one flattened string"
    );
    // §14.6: what is holding the deletion open, beside the fact that one was accepted.
    assert_eq!(
        list_of(record, "finalizers").as_deref(),
        Some([finalizer.to_owned()].as_slice()),
        "§14.6: the finalizers are what decide whether a deletion completes (Gate H)"
    );

    let references = owner_references(record);
    assert_eq!(references.len(), 1, "the object states one owner");
    let reference = &references[0];
    assert_eq!(
        reference.get("kind"),
        Some(&Value::String(owner.0.into())),
        "an owner reference keeps its kind"
    );
    assert_eq!(
        reference.get("name"),
        Some(&Value::String(owner.1.into())),
        "and its name"
    );
    assert_eq!(
        reference.get("controller"),
        Some(&Value::Bool(owner.2)),
        "and the flag §24.3 turns into the difference between `owned-by` and `controlled-by` — \
         a list of names would drop it"
    );
    assert!(
        matches!(reference.get("block_owner_deletion"), Some(Value::Bool(_))),
        "and the flag that decides whether the owner's deletion waits"
    );

    // §14.7: the managers, summarised. The same manager twice is one manager, and the order is
    // this package's rather than the server's, so two reads of one object agree.
    let managers_seen = list_of(record, "field_managers");
    assert_eq!(
        managers_seen.as_deref(),
        Some(
            managers
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
                .as_slice()
        ),
        "§14.7: `managedFields` is summarised as its distinct managers, sorted"
    );
}

#[tokio::test]
async fn should_carry_every_metadata_field_the_projection_names_for_a_curated_kind() {
    // §14.1 names twelve fields and says a provider MUST NOT pretend the data is absent. Four of
    // them — annotations, finalizers, ownerReferences, managedFields — were projected by the
    // domain layer, declared by no schema, and therefore reached nobody. This is the boundary
    // half of §14.5, §14.6 and §14.7, and it is the last requirement K1 waited on.
    let plugin = loaded(2).await;
    let (events, result) = plugin
        .query("k8s-pod", at_cluster(&[]))
        .await
        .expect("the query starts")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    let held = &records[0];
    held.validate()
        .expect("the record conforms to the schema it carries");

    assert_metadata_projection(
        held,
        ("deployment.kubernetes.io/revision", "4"),
        "example.com/drain-connections",
        ("ReplicaSet", "api-7d9f", true),
        &["kube-controller-manager", "kubelet"],
    );

    // And the other side of every one of them: an object that states none of the four says so
    // with null rather than with an empty list nobody wrote (§4, unknown is null).
    let bare = &records[1];
    assert_eq!(bare.get("annotations"), Some(&Value::Null));
    assert_eq!(bare.get("finalizers"), Some(&Value::Null));
    assert_eq!(bare.get("owner_references"), Some(&Value::Null));
    assert_eq!(bare.get("field_managers"), Some(&Value::Null));
    assert_eq!(
        bare.get("terminating"),
        Some(&Value::Bool(true)),
        "a deletion accepted with no finalizer holding it is still terminating, and the two \
         fields are what tell those cases apart (Gate H)"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_carry_every_metadata_field_the_projection_names_for_a_kind_nobody_compiled_in() {
    // The same four fields on a kind whose group, name and fields exist only in this file. §14's
    // projection is common to every object, so there is one route rather than two — which is the
    // difference between §33.1's "CRDs are normal resources" and the typed-builtins-raw-JSON
    // split it calls non-conformant.
    let plugin = loaded_with_custom_resources().await;
    let (events, result) = plugin
        .query(
            "k8s-resource",
            at_cluster(&[
                ("kind", json!("Sprocket")),
                ("group", json!("menagerie.example")),
            ]),
        )
        .await
        .expect("the query starts")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    let held = &records[0];
    held.validate()
        .expect("the record conforms to the schema it carries");

    assert_metadata_projection(
        held,
        ("menagerie.example/calibrated-by", "bench-3"),
        "menagerie.example/release-bench",
        ("Bench", "bench-3", false),
        &["menagerie-operator"],
    );

    // The dynamic record's `other` map is still content rather than metadata: §14's twelve
    // fields are named fields of the schema, and repeating them inside the payload would report
    // one fact twice under two names with two precisions.
    assert!(
        !matches!(held.get("other"), Some(Value::Map(map)) if map.get("metadata").is_some()),
        "metadata is projected, never dropped into the untyped payload"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

// --- §6.3's session, and §50.2's cost ------------------------------------------------------------

/// How many times the recorded server was asked for `path`.
///
/// Counted off the request heads the server kept, so it is what travelled rather than what the
/// package believes it sent. §50.2 is a claim about round trips, and the only honest way to check
/// one is to count them at the far end.
fn asked_for(cluster: &RecordedCluster, path: &str) -> usize {
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
async fn should_not_run_discovery_again_for_a_second_query_in_one_session() {
    // §50.2 and §6.3. Before the session was wired, every invocation re-resolved the endpoint,
    // re-ran discovery over `/api` and `/apis` and re-read the resource list — three round trips
    // before the first object, every time, against a cluster whose answer to all three had not
    // changed since the previous query a second earlier.
    //
    // The assertion is on what the *server* saw, because that is what §50.2 is about. Two things
    // have to hold at once and the second is the one that makes this a session rather than a
    // cache of answers: discovery is paid for once, and the list is paid for every time — a query
    // that stopped asking the cluster what is in a collection would be answering from a snapshot
    // nobody is keeping true (§20.3).
    let cluster = RecordedCluster::with_pods(2);
    let plugin = loaded_against(Arc::clone(&cluster)).await;

    let (_, first) = plugin
        .query("k8s-pod", at_cluster(&[]))
        .await
        .expect("the first query starts")
        .collect()
        .await;
    assert_eq!(first.status, InvokeStatus::Completed, "{:?}", first.error);
    let discovery_after_one = (
        asked_for(&cluster, "/api"),
        asked_for(&cluster, "/apis"),
        asked_for(&cluster, "/api/v1"),
    );
    assert_eq!(
        discovery_after_one,
        (1, 1, 1),
        "the first query pays for discovery, because nothing knew this cluster yet"
    );

    let (events, second) = plugin
        .query("k8s-pod", at_cluster(&[]))
        .await
        .expect("the second query starts in the same session")
        .collect()
        .await;
    assert_eq!(second.status, InvokeStatus::Completed, "{:?}", second.error);
    assert_eq!(
        (
            asked_for(&cluster, "/api"),
            asked_for(&cluster, "/apis"),
            asked_for(&cluster, "/api/v1"),
        ),
        discovery_after_one,
        "the second query in one session asks the cluster nothing about its own API surface \
         again — that is §6.3's session and §50.2's requirement"
    );
    assert_eq!(
        asked_for(&cluster, "/api/v1/namespaces/default/pods"),
        2,
        "and the objects are read every time: a session caches what the cluster *is*, never \
         what is in it, because nothing here is keeping that true (§20.3)"
    );
    assert_eq!(
        records(&events).len(),
        2,
        "the second answer is a whole answer rather than a cheaper one"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_read_the_published_schema_once_for_two_queries_of_one_kind() {
    // §12.4's cache, which had no reader at all: the OpenAPI v3 document for a group-version is
    // the most expensive thing this provider fetches, and it was fetched per query. §50.3 asks
    // for lazy schema loading; a schema loaded lazily and then thrown away is the same cost with
    // a better name.
    let cluster = RecordedCluster::with_custom_resources();
    let plugin = loaded_against(Arc::clone(&cluster)).await;
    let options = at_cluster(&[
        ("kind", json!("Sprocket")),
        ("group", json!("menagerie.example")),
    ]);

    for attempt in 0..2 {
        let (events, result) = plugin
            .query("k8s-resource", options.clone())
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
        let records = records(&events);
        assert_eq!(
            text_of(&records[0], "schema_source").as_deref(),
            Some("openapi-v3"),
            "attempt {attempt}: the typing is the cluster's own, cached or not — a cache that \
             degraded the answer would be worse than no cache"
        );
        assert!(
            matches!(
                records[0].get("spec"),
                Some(Value::Map(spec)) if matches!(spec.get("renewAt"), Some(Value::Timestamp(_))),
            ),
            "attempt {attempt}: and it still turns a described `date-time` into an instant"
        );
    }
    assert_eq!(
        asked_for(&cluster, "/openapi/v3/apis/menagerie.example/v1"),
        1,
        "the published schema is read once per session and remembered by GVK (§12.4)"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

// --- §19's watch, and the gap it is really about ------------------------------------------------

/// The `change`, `segment` and `continuous` of every record, in the order they were emitted.
///
/// The order matters here and nowhere else in this file: §19.4's prohibition is about a *history*,
/// and a history is a sequence.
fn observed(records: &[Arc<RecordValue>]) -> Vec<(String, i128, bool)> {
    records
        .iter()
        .map(|record| {
            let Some(Value::Int(segment)) = record.get("segment") else {
                panic!("every change record states its observation period");
            };
            let Some(Value::Bool(continuous)) = record.get("continuous") else {
                panic!("every change record says whether observation has been unbroken");
            };
            (
                text_of(record, "change").expect("every change record states what it is"),
                *segment,
                *continuous,
            )
        })
        .collect()
}

async fn watched(script: Watching) -> (Arc<RecordedCluster>, ono_kuang_supervisor::LoadedPlugin) {
    let cluster = RecordedCluster::watching(script);
    let plugin = loaded_against(Arc::clone(&cluster)).await;
    (cluster, plugin)
}

#[tokio::test]
async fn should_deliver_what_changed_while_it_was_watching() {
    // §19.1 end to end, and the first time anything in this package opens a watch at all. The
    // sequence is the requirement: the collection is listed, the watch opens from the version
    // *that listing* returned, and the changes that follow are the ones since it. A watch opened
    // without that version would start at the present moment and silently lose everything that
    // already existed, which is why the acquisition is not an optimisation.
    let (cluster, plugin) = watched(Watching::Changes).await;
    let (events, result) = plugin
        .query("k8s-change", at_cluster(&[("kind", json!("Pod"))]))
        .await
        .expect("the query starts")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);

    let records = records(&events);
    for record in &records {
        record
            .validate()
            .expect("the record conforms to the schema it carries");
    }
    assert_eq!(
        observed(&records),
        vec![
            ("listed".to_owned(), 1, true),
            ("added".to_owned(), 1, true),
            ("modified".to_owned(), 1, true),
        ],
        "the state at acquisition, then the changes since it, all in one unbroken period"
    );
    assert_eq!(
        text_of(&records[1], "name").as_deref(),
        Some("two"),
        "an arrival is the object that arrived"
    );
    assert_eq!(
        text_of(&records[2], "resource_version").as_deref(),
        Some("4003"),
        "and a change carries the version it was observed at (§14.3), never a timestamp"
    );
    for record in &records {
        assert_eq!(
            text_of(record, "sync_state").as_deref(),
            Some("live"),
            "the stream listed and is watching, which is the one state that entitles anybody to \
             read an absence as an absence (§20.3, §41.4)"
        );
        assert_eq!(
            text_of(record, "resource").as_deref(),
            Some("/v1/pods"),
            "the record names the REST collection — a GVR, never a GVK (§13.1)"
        );
    }

    // §20.2's third origin, which nothing could produce before a watch existed: an object that
    // was listed was read, and an object that arrived on the stream was pushed.
    let origin = |record: &RecordValue| record.provenance().source().unwrap_or_default().to_owned();
    assert!(
        origin(&records[0]).contains("origin=direct-read"),
        "the acquisition is a read: {}",
        origin(&records[0])
    );
    assert!(
        origin(&records[1]).contains("origin=watch-event"),
        "and what the server pushed says so, because a reader decides how much to trust a record \
         by how it was come by: {}",
        origin(&records[1])
    );

    assert_eq!(
        asked_for(&cluster, "/api/v1/namespaces/default/pods"),
        2,
        "one listing and one watch, both on the collection endpoint — the watch is the same \
         path with `watch=true` on it"
    );
    assert!(
        cluster
            .heads()
            .iter()
            .any(|head| head.contains("watch=true") && head.contains("resourceVersion=9100")),
        "the watch opened from the version the listing returned, never from `now` (§19.1): {:?}",
        cluster.heads()
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_make_a_watch_gap_visible_rather_than_stitching_a_history_over_it() {
    // Gate F (§62.6) and §4 invariant 14, end to end for the first time. A `410 Gone` arrives as
    // an ERROR frame inside a stream the server opened with `200 OK` — which is how an expiry
    // actually arrives, and what an implementation that classifies HTTP status codes never sees.
    //
    // What must reach a user is not that the watch failed. It is that a *period* was not
    // observed: `one` moved from version 4003 and `three` appeared, and nobody saw either happen.
    // The records on the far side of the gap are therefore a second history rather than the
    // continuation of the first, and three fields say so — the word `gap`, the segment, and
    // `continuous`.
    let (cluster, plugin) = watched(Watching::Expiry).await;
    let (events, result) = plugin
        .query("k8s-change", at_cluster(&[("kind", json!("Pod"))]))
        .await
        .expect("the query starts")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);

    let records = records(&events);
    let sequence = observed(&records);
    assert_eq!(
        sequence,
        vec![
            ("listed".to_owned(), 1, true),
            ("modified".to_owned(), 1, true),
            ("gap".to_owned(), 1, false),
            ("listed".to_owned(), 2, false),
            ("listed".to_owned(), 2, false),
        ],
        "the break is a record of its own, and everything after it is a second period: {sequence:?}"
    );

    let gap = &records[2];
    assert_eq!(
        text_of(gap, "gap_reason").as_deref(),
        Some("watch_expired_410"),
        "the reason is the one Appendix D.4 names, and it is not a generic failure"
    );
    assert!(
        text_of(gap, "gap_detail").is_some_and(|detail| detail.contains("gap after 4003")),
        "the gap names the last version observed before it — 4003, the change that was seen, and \
         not 9100, the version the watch opened at — so a reader can place an observation on the \
         correct side of the break: {:?}",
        text_of(gap, "gap_detail")
    );
    assert_eq!(
        gap.get("uid"),
        Some(&Value::Null),
        "a gap is an observation of a period, so there is no object in it and null says so"
    );
    assert_eq!(
        text_of(gap, "sync_state").as_deref(),
        Some("gap detected"),
        "and while the gap stands, the cache may not answer absence at all (§20.3)"
    );

    // The prohibition itself: nothing before the break and nothing after it shares a period, so
    // no consumer can concatenate them into an ordered history that reads as complete.
    let before: Vec<_> = sequence
        .iter()
        .take(3)
        .map(|(.., segment, _)| segment)
        .collect();
    let after: Vec<_> = sequence
        .iter()
        .skip(3)
        .map(|(.., segment, _)| segment)
        .collect();
    assert!(
        before.iter().all(|segment| **segment == 1) && after.iter().all(|segment| **segment == 2),
        "pre-gap and post-gap observation are two histories (§4 invariant 14): {sequence:?}"
    );
    assert!(
        records
            .iter()
            .skip(3)
            .all(|record| record.get("continuous") == Some(&Value::Bool(false))),
        "and `continuous` never goes back to true: closing a gap says observation continues, \
         never that the unobserved period was filled in (§19.4)"
    );
    // The state on the far side was inferred from a snapshot rather than reached by observed
    // changes, and this is what that costs: `three` exists and nothing ever reported it arriving.
    let names: Vec<_> = records
        .iter()
        .skip(3)
        .filter_map(|record| text_of(record, "name"))
        .collect();
    assert_eq!(names, vec!["one".to_owned(), "three".to_owned()]);
    assert!(
        !records.iter().any(
            |record| text_of(record, "change").as_deref() == Some("added")
                && text_of(record, "name").as_deref() == Some("three")
        ),
        "`three` is never reported as having arrived, because nobody observed it arriving"
    );

    assert_eq!(
        asked_for(&cluster, "/api/v1/namespaces/default/pods"),
        3,
        "one acquisition, one watch, and one re-acquisition on the far side of the gap (§19.4)"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

#[tokio::test]
async fn should_answer_a_watched_object_from_the_cache_and_say_that_is_where_it_came_from() {
    // §20.2's `MUST`, which had only one origin to report until a watch existed. A read has to
    // state whether it is a direct observation or something a cache remembered, and the whole
    // point of stating it is that a reader decides how much to trust the record by it.
    //
    // Two queries in one session: the first opens a watch, which leaves the session with a cache
    // a watch is keeping true; the second asks for one object by name and is answered from it.
    // The proof is at the far end of the wire — the object endpoint is never asked at all.
    let (cluster, plugin) = watched(Watching::Changes).await;
    let (_, acquired) = plugin
        .query("k8s-change", at_cluster(&[("kind", json!("Pod"))]))
        .await
        .expect("the watch starts")
        .collect()
        .await;
    assert_eq!(
        acquired.status,
        InvokeStatus::Completed,
        "{:?}",
        acquired.error
    );

    let (events, result) = plugin
        .query("k8s-pod", at_cluster(&[("name", json!("two"))]))
        .await
        .expect("the read starts")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let held = records(&events);
    assert_eq!(held.len(), 1, "one object was asked for and one arrived");
    assert_eq!(text_of(&held[0], "uid").as_deref(), Some("u-2"));

    let source = held[0].provenance().source().unwrap_or_default().to_owned();
    assert!(
        source.contains("origin=cache"),
        "a record a cache remembered says so, and never that it is a direct read (§20.2): \
         {source}"
    );
    assert_eq!(
        asked_for(&cluster, "/api/v1/namespaces/default/pods/two"),
        0,
        "the object endpoint was never asked, which is what makes this a cache rather than a \
         faster way of spelling the same request (§50.2)"
    );

    // And the answer is only ever given while the watch entitles it to be: an object that is not
    // in a live cache is read from the cluster rather than reported as absent (§20.3, §4
    // invariant 13). `absent-one` is in neither, so this is the refusal rather than the hit.
    let (events, result) = plugin
        .query("k8s-pod", at_cluster(&[("name", json!("nowhere"))]))
        .await
        .expect("the read starts")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    assert!(
        records(&events).is_empty(),
        "a synchronised cache that is being watched may report an absence as an absence, and \
         this is the one state in which it may (§20.3)"
    );
    plugin.shutdown(ShutdownReason::Unload).await;
}

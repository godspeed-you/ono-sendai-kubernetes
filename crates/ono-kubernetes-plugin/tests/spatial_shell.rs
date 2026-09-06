//! `enter`, `near`, `follow` and `up`, driven through the real `ono` binary (§35.2–§35.6, §62.1).
//!
//! Everything else in this suite drives the package under the deterministic test host, which is
//! the right instrument for what the *package* answers. It cannot answer the question these tests
//! ask, because the four words above are the **shell's** and the shell is what decides whether a
//! contributed target became a kind of place and a declared shape became a relation. So this file
//! lays the package out in a scratch plugin home the way an operator installs one, points it at a
//! recorded API server on a real socket, and reads what `ono` printed — the shape
//! `crates/ono-cli/tests/spatial_contributed_targets.rs` uses in core, for the same reason.
//!
//! **Nothing here contacts a cluster** (§59.1). The API server below is a `TcpListener` in this
//! process answering from recorded documents, and the shell's `network.connect` reaches it the
//! way it reaches any endpoint an operator names.
//!
//! **The binary is not this repository's to build**, and that is why these tests skip rather than
//! fail when it is absent. `ono` is built from core, this repository pins core as a git
//! dependency, and a test that built a whole second workspace to run would make `cargo test`
//! here depend on a checkout nobody promised is present. `ONO_BINARY` names it, and a sibling
//! `ono-sendai` checkout is tried after that. What is skipped is printed, because a test that
//! quietly does nothing is worse than one that is not there (AGENTS.md §7's rule for anything
//! outside the deterministic path).
//!
//! The host must carry `ADR-0584 (core)` and `ADR-0585 (core)`. Against an older `ono` these
//! tests fail rather than skip, and that is deliberate: an `ono` that has the binary but not the
//! mechanism is a real disagreement between this package and the shell it plugs into.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value as Json, json};

const PLUGIN: &str = env!("CARGO_BIN_EXE_ono-kubernetes");
const PACKAGE: &str = "io.github.godspeed-you.kubernetes";
const MANIFEST: &str = include_str!("../../../package/manifest.yaml");
const TARGETS: &str = include_str!("../../../package/contributions/targets.yaml");
const SCHEMAS: &str = include_str!("../../../package/contributions/schemas.yaml");
const COMMANDS: &str = include_str!("../../../package/contributions/commands.yaml");

/// The lifetime identity of the second of the two Pods that share the name `checkout`.
const SECOND_POD: &str = "pod-uid-2";

// --- the shell -----------------------------------------------------------------------------------

/// The `ono` binary, or [`None`] with the reason printed.
fn ono() -> Option<PathBuf> {
    if let Some(named) = std::env::var_os("ONO_BINARY") {
        let path = PathBuf::from(named);
        if path.is_file() {
            return Some(path);
        }
        panic!(
            "`ONO_BINARY` names `{}`, which is not a file",
            path.display()
        );
    }
    // A sibling checkout, which is how the two repositories sit on a development machine.
    let sibling = workspace()
        .parent()
        .map(|parent| parent.join("ono-sendai/target/debug/ono"));
    match sibling {
        Some(path) if path.is_file() => Some(path),
        _ => {
            eprintln!(
                "skipped: no `ono` binary. `ono` is built from the core repository, which this \
                 one pins as a git dependency rather than checks out. Set `ONO_BINARY`, or put a \
                 built core checkout beside this one, to run the spatial outcome tests."
            );
            None
        }
    }
}

/// This repository's root.
fn workspace() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ono-kubernetes-spatial-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&path).expect("the test may write a temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Lays this repository's package out the way an operator installs one.
///
/// The documents are the real ones, byte for byte: `contributions.relations` is read from
/// `package/manifest.yaml` and the schema ids its shapes name are read from
/// `package/contributions/targets.yaml`, which is exactly the pair the host settles against each
/// other at load (`ADR-0585 (core)`). A fixture manifest here would prove something about the
/// fixture.
fn plugin_home(name: &str) -> Scratch {
    let scratch = Scratch::new(name);
    let package = scratch.path().join("plugins").join(PACKAGE);
    std::fs::create_dir_all(package.join("runtime")).expect("the runtime directory");
    std::fs::create_dir_all(package.join("contributions")).expect("the contributions directory");
    std::fs::write(package.join("manifest.yaml"), MANIFEST).expect("the manifest");
    std::fs::write(package.join("contributions/targets.yaml"), TARGETS).expect("the targets");
    std::fs::write(package.join("contributions/schemas.yaml"), SCHEMAS).expect("the schemas");
    std::fs::write(package.join("contributions/commands.yaml"), COMMANDS).expect("the commands");
    std::fs::copy(PLUGIN, package.join("runtime/ono-kubernetes")).expect("the package binary");
    for directory in ["home", "state", "config/ono"] {
        std::fs::create_dir_all(scratch.path().join(directory)).expect("the scratch directories");
    }
    scratch
}

/// What one `ono -c` run printed.
struct Run {
    stdout: String,
    stderr: String,
}

impl Run {
    /// The last JSON document on stdout, for a script whose earlier statements printed prose.
    fn last_json(&self) -> Json {
        let line = self
            .stdout
            .lines()
            .rev()
            .find(|line| line.starts_with('[') || line.starts_with('{'))
            .unwrap_or_else(|| panic!("a `to json` document on stdout, got {self:?}"));
        serde_json::from_str(line).unwrap_or_else(|error| panic!("{error}: {line}"))
    }

    fn rows(&self) -> Vec<Json> {
        match self.last_json() {
            Json::Array(rows) => rows,
            other => panic!("a sequence of records, got {other}"),
        }
    }
}

impl std::fmt::Debug for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout, self.stderr
        )
    }
}

/// Runs one script under `ono`, with the scratch home as the whole of its world.
fn shell(binary: &Path, home: &Scratch, script: &str) -> Run {
    let root = home.path();
    let output = Command::new(binary)
        .args(["-c", script])
        .env("ONO_PLUGIN_PATH", root.join("plugins"))
        .env("HOME", root.join("home"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("ONO_CONFIG_DIR", root.join("config/ono"))
        .output()
        .expect("the shell runs");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// The `load plugin` line, with the grants a test wants.
fn load(grants: &[&str]) -> String {
    let grants: String = grants
        .iter()
        .map(|grant| format!(" --grant {grant}"))
        .collect();
    format!("load plugin {PACKAGE}{grants}")
}

/// The two grants an operator gives before any of this is reachable.
const SPATIAL_GRANTS: &[&str] = &["network.connect", "clock.read", "relation.write"];

// --- the recorded API server ---------------------------------------------------------------------

/// An API server on a real socket, answering from recorded documents.
///
/// A socket rather than a fixture because the point of these tests is the whole chain: the
/// shell's own `network.connect`, brokered to the package, HTTP/1.1 spoken by the package over
/// it, and the records coming back through the shell's spatial layer. It speaks HTTP/1.1 with
/// keep-alive, because the package holds one connection open for a whole conversation.
struct RecordedCluster {
    port: u16,
}

impl RecordedCluster {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("the address").port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || serve(stream));
            }
        });
        Self { port }
    }
}

fn serve(mut stream: TcpStream) {
    let peer = stream.try_clone().expect("the stream clones");
    let mut reader = BufReader::new(peer);
    loop {
        let mut request = String::new();
        if reader.read_line(&mut request).unwrap_or(0) == 0 {
            return;
        }
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            if header == "\r\n" || header == "\n" {
                break;
            }
        }
        let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
        let path = path.split('?').next().unwrap_or("/").to_owned();
        let (status, body) = match document(&path) {
            Some(document) => ("200 OK", document.to_string()),
            None => (
                "404 Not Found",
                json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 404})
                    .to_string(),
            ),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if stream.write_all(response.as_bytes()).is_err() {
            return;
        }
        let _ = stream.flush();
    }
}

fn metadata(name: &str, uid: &str, namespace: Option<&str>) -> Json {
    let mut map = json!({
        "name": name,
        "uid": uid,
        "resourceVersion": "101",
        "creationTimestamp": "2026-01-01T00:00:00Z",
    });
    if let Some(namespace) = namespace {
        map["namespace"] = json!(namespace);
    }
    map
}

/// One of the two Pods called `checkout`. Two lifetimes, one name — which is §35.4's whole point.
fn pod(uid: &str) -> Json {
    let mut metadata = metadata("checkout", uid, Some("shop"));
    metadata["labels"] = json!({"app": "checkout"});
    metadata["ownerReferences"] = json!([{
        "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "checkout-7d9f",
        "uid": "rs-uid-1", "controller": true,
    }]);
    json!({
        "apiVersion": "v1", "kind": "Pod", "metadata": metadata,
        "spec": {
            "nodeName": "worker-03",
            "serviceAccountName": "shop-sa",
            "containers": [{"name": "app", "image": "nginx"}],
        },
        "status": {"phase": "Running", "podIP": "10.1.2.3"},
    })
}

fn collection(kind: &str, api_version: &str, items: Vec<Json>) -> Json {
    json!({
        "apiVersion": api_version,
        "kind": format!("{kind}List"),
        "metadata": {"resourceVersion": "200"},
        "items": items,
    })
}

fn document(path: &str) -> Option<Json> {
    Some(match path {
        "/api" => json!({"kind": "APIVersions", "versions": ["v1"]}),
        "/apis" => json!({"kind": "APIGroupList", "groups": [{
            "name": "apps",
            "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
            "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
        }]}),
        "/api/v1" => json!({"kind": "APIResourceList", "groupVersion": "v1", "resources": [
            {"name": "pods", "singularName": "pod", "namespaced": true, "kind": "Pod",
             "verbs": ["get", "list", "watch"], "shortNames": ["po"]},
            {"name": "namespaces", "singularName": "namespace", "namespaced": false,
             "kind": "Namespace", "verbs": ["get", "list"]},
            {"name": "nodes", "singularName": "node", "namespaced": false, "kind": "Node",
             "verbs": ["get", "list"]},
            {"name": "services", "singularName": "service", "namespaced": true, "kind": "Service",
             "verbs": ["get", "list"]},
            {"name": "serviceaccounts", "singularName": "serviceaccount", "namespaced": true,
             "kind": "ServiceAccount", "verbs": ["get", "list"]},
        ]}),
        "/apis/apps/v1" => json!({
            "kind": "APIResourceList", "groupVersion": "apps/v1", "resources": [
                {"name": "replicasets", "singularName": "replicaset", "namespaced": true,
                 "kind": "ReplicaSet", "verbs": ["get", "list"]},
                {"name": "deployments", "singularName": "deployment", "namespaced": true,
                 "kind": "Deployment", "verbs": ["get", "list"]},
            ],
        }),
        "/api/v1/namespaces" => collection(
            "Namespace",
            "v1",
            vec![json!({
                "apiVersion": "v1", "kind": "Namespace",
                "metadata": metadata("shop", "ns-uid-1", None),
                "status": {"phase": "Active"},
            })],
        ),
        "/api/v1/nodes" => collection(
            "Node",
            "v1",
            vec![json!({
                "apiVersion": "v1", "kind": "Node",
                "metadata": metadata("worker-03", "node-uid-1", None),
                "spec": {},
                "status": {
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "addresses": [{"type": "Hostname", "address": "worker-03"}],
                    "nodeInfo": {"kubeletVersion": "v1.34.0"},
                },
            })],
        ),
        "/api/v1/namespaces/shop/pods" => {
            collection("Pod", "v1", vec![pod("pod-uid-1"), pod(SECOND_POD)])
        }
        "/api/v1/namespaces/shop/services" => collection(
            "Service",
            "v1",
            vec![json!({
                "apiVersion": "v1", "kind": "Service",
                "metadata": metadata("checkout", "svc-uid-1", Some("shop")),
                "spec": {
                    "type": "ClusterIP", "clusterIP": "10.96.0.9",
                    "selector": {"app": "checkout"},
                    "ports": [{"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"}],
                },
                "status": {},
            })],
        ),
        "/api/v1/namespaces/shop/serviceaccounts" => collection(
            "ServiceAccount",
            "v1",
            vec![json!({
                "apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": metadata("shop-sa", "sa-uid-1", Some("shop")),
            })],
        ),
        "/apis/apps/v1/namespaces/shop/replicasets" => collection(
            "ReplicaSet",
            "apps/v1",
            vec![json!({
                "apiVersion": "apps/v1", "kind": "ReplicaSet",
                "metadata": metadata("checkout-7d9f", "rs-uid-1", Some("shop")),
                "spec": {"replicas": 2, "selector": {"matchLabels": {"app": "checkout"}}},
                "status": {"readyReplicas": 2, "observedGeneration": 1},
            })],
        ),
        "/apis/apps/v1/namespaces/shop/deployments" => {
            collection("Deployment", "apps/v1", Vec::new())
        }
        _ => return None,
    })
}

/// The script prefix every test shares: the package loaded, and the shell standing on the second
/// of the two Pods that share a name.
fn standing_on_the_pod(cluster: &RecordedCluster, grants: &[&str], then: &str) -> String {
    format!(
        "{}; get k8s-pod --host 127.0.0.1 --port {} --namespace shop \
         | where uid == \"{SECOND_POD}\" | enter; {then}",
        load(grants),
        cluster.port
    )
}

// --- the tests -----------------------------------------------------------------------------------

#[test]
fn should_enter_a_kubernetes_object_as_a_place_bound_to_its_lifetime() {
    // Gate A's "entered", and §35.4. The place carries `identity: {uid: …}` and an
    // `identity_tier` of `lifetime`, so the shell is standing on one resource lifetime rather
    // than on the word `checkout` — and `look` reports it as *there*, which needs the re-read of
    // §33.2 to have found it (ADR-0027).
    let Some(binary) = ono() else { return };
    let cluster = RecordedCluster::start();
    let home = plugin_home("enter");
    let run = shell(
        &binary,
        &home,
        &standing_on_the_pod(
            &cluster,
            &["network.connect", "clock.read"],
            "look | to json",
        ),
    );
    let here = run.rows();
    assert_eq!(here.len(), 1, "`look` reports one place, got {run:?}");
    let place = &here[0]["place"];
    assert_eq!(
        place["object_type"].as_str(),
        Some("io.github.godspeed-you.kubernetes.pod/1"),
        "the kind of place is the schema the package declared, got {place}"
    );
    assert_eq!(
        place["identity"]["uid"].as_str(),
        Some(SECOND_POD),
        "the place is bound to the Pod's lifetime identity, got {place}"
    );
    assert_eq!(place["identity_tier"].as_str(), Some("lifetime"));
    assert_eq!(
        place["canonical_ref"]["uid"].as_str(),
        Some(SECOND_POD),
        "and an action can revalidate through it (§33.2), got {place}"
    );
    assert!(
        place["tombstone"].is_null(),
        "a Pod the cluster is still serving is not reported as gone, got {place}"
    );
}

#[test]
fn should_keep_two_pods_of_one_name_apart_as_two_places() {
    // §4 invariants 4–5 and §35.4, at the one boundary where they could still have been lost: a
    // shell that bound a place to a display name would answer with one place here, because both
    // Pods are called `checkout`.
    let Some(binary) = ono() else { return };
    let cluster = RecordedCluster::start();
    let home = plugin_home("identity");
    let run = shell(
        &binary,
        &home,
        &format!(
            "{}; get k8s-pod --host 127.0.0.1 --port {} --namespace shop | enter; \
             find place --type KubernetesPod | to json",
            load(&["network.connect", "clock.read"]),
            cluster.port
        ),
    );
    let found = run.rows();
    let identities: Vec<&str> = found
        .iter()
        .filter_map(|place| place["identity"]["uid"].as_str())
        .collect();
    assert!(
        identities.contains(&"pod-uid-1") && identities.contains(&SECOND_POD),
        "two resources of one name are two places, got {run:?}"
    );
    let addresses: Vec<&str> = found
        .iter()
        .filter_map(|place| place["spatial_id"].as_str())
        .collect();
    let mut unique = addresses.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        addresses.len(),
        "and they are two addresses, got {run:?}"
    );
}

#[test]
fn should_answer_near_with_the_neighbours_this_package_contributes() {
    // §35.5 and §36.1, through the shell rather than through the package's own answer: `near`
    // reaches the Node the Pod runs on, the ReplicaSet that controls it, the account it runs as,
    // the Service that selects it and the namespace it is in — each of them a place with its own
    // lifetime identity, along a relation this package's manifest declared.
    let Some(binary) = ono() else { return };
    let cluster = RecordedCluster::start();
    let home = plugin_home("near");
    let run = shell(
        &binary,
        &home,
        &standing_on_the_pod(&cluster, SPATIAL_GRANTS, "near | to json"),
    );
    let neighbours = run.rows();
    let by_relation = |word: &str| -> Option<Json> {
        neighbours
            .iter()
            .find(|row| row["provider_relation"].as_str() == Some(word))
            .cloned()
    };

    let node = by_relation("scheduled-on")
        .unwrap_or_else(|| panic!("the Node the Pod runs on is a neighbour, got {run:?}"));
    assert_eq!(
        node["relation"].as_str(),
        Some("io.github.godspeed-you.kubernetes.pod_to_node"),
        "along the relation the manifest's shape registered, got {node}"
    );
    assert_eq!(
        node["object_type"].as_str(),
        Some("io.github.godspeed-you.kubernetes.node/1")
    );
    assert_eq!(
        node["identity"]["uid"].as_str(),
        Some("node-uid-1"),
        "and the neighbour is bound to the Node's lifetime, not to `worker-03`, got {node}"
    );
    assert_eq!(
        node["provider"].as_str(),
        Some(PACKAGE),
        "the package that asserted the edge is on it (§53, §31.64), got {node}"
    );
    assert_eq!(
        node["evidence"]["origin"].as_str(),
        Some(PACKAGE),
        "and so is the origin of the evidence, got {node}"
    );
    assert_ne!(
        node["confidence"].as_str(),
        Some("exact"),
        "the host did not observe this edge, so it is never `exact` (§22.2, §36.2), got {node}"
    );

    for word in ["controlled-by", "runs-as", "in-namespace"] {
        assert!(
            by_relation(word).is_some(),
            "`{word}` is among the exits of a Pod, got {run:?}"
        );
    }
    let selected = by_relation("selects")
        .unwrap_or_else(|| panic!("the Service that selects the Pod is a neighbour, got {run:?}"));
    assert_eq!(
        selected["object_type"].as_str(),
        Some("io.github.godspeed-you.kubernetes.service/1"),
        "an edge that arrives at a place is a neighbour of it too, got {selected}"
    );
}

#[test]
fn should_follow_a_contributed_relation_to_the_node_a_pod_runs_on() {
    // §6.4 and §35.7: `follow` traverses one named relationship and leaves the session standing
    // on the far end. The word is the relation the shape registered, because `ADR-0585 (core)`
    // gives a contributed relation no shorter name of its own.
    let Some(binary) = ono() else { return };
    let cluster = RecordedCluster::start();
    let home = plugin_home("follow");
    let run = shell(
        &binary,
        &home,
        &standing_on_the_pod(
            &cluster,
            SPATIAL_GRANTS,
            "follow io.github.godspeed-you.kubernetes.pod_to_node; look | to json",
        ),
    );
    let here = run.rows();
    assert_eq!(here.len(), 1, "`look` reports one place, got {run:?}");
    let place = &here[0]["place"];
    assert_eq!(
        place["object_type"].as_str(),
        Some("io.github.godspeed-you.kubernetes.node/1"),
        "the traversal arrived at a Node, got {place}"
    );
    assert_eq!(
        place["identity"]["uid"].as_str(),
        Some("node-uid-1"),
        "bound to the Node's lifetime identity, got {place}"
    );
}

#[test]
fn should_reach_the_namespace_a_pod_is_in_without_routing_it_through_the_owner() {
    // §35.6: "a namespace is a Pod's spatial parent even though a ReplicaSet owns it". The two
    // are separate shapes, so following the containment relation lands on the namespace and
    // following the ownership relation lands on the ReplicaSet — and neither is a rename of the
    // other.
    let Some(binary) = ono() else { return };
    let cluster = RecordedCluster::start();
    let home = plugin_home("containment");
    let run = shell(
        &binary,
        &home,
        &standing_on_the_pod(
            &cluster,
            SPATIAL_GRANTS,
            "follow io.github.godspeed-you.kubernetes.pod_to_namespace; look | to json",
        ),
    );
    let place = &run.rows()[0]["place"];
    assert_eq!(
        place["object_type"].as_str(),
        Some("io.github.godspeed-you.kubernetes.namespace/1"),
        "the spatial parent is the namespace, got {place}"
    );
    assert_eq!(place["identity"]["uid"].as_str(), Some("ns-uid-1"));

    let owner = shell(
        &binary,
        &home,
        &standing_on_the_pod(
            &cluster,
            SPATIAL_GRANTS,
            "follow io.github.godspeed-you.kubernetes.pod_to_replicaset; look | to json",
        ),
    );
    let place = &owner.rows()[0]["place"];
    assert_eq!(
        place["object_type"].as_str(),
        Some("io.github.godspeed-you.kubernetes.replicaset/1"),
        "and what owns the Pod is somewhere else entirely, got {place}"
    );
}

#[test]
fn should_say_why_up_has_nowhere_to_go_from_a_kubernetes_place() {
    // The honest negative. `place.rs::up` computes the spatial parent and the shell has nowhere
    // to put it: landing `up` on a place needs the plugin-defined aggregate space of §36.4, which
    // `docs/contracts/kuang/contributions.v1.yaml` gives a package no way to declare
    // (`ADR-0584 (core)`). What matters is that the refusal says *that* rather than claiming the
    // user has reached the top of this host — a place in a cluster is not the top of a laptop.
    let Some(binary) = ono() else { return };
    let cluster = RecordedCluster::start();
    let home = plugin_home("up");
    let run = shell(
        &binary,
        &home,
        &standing_on_the_pod(&cluster, SPATIAL_GRANTS, "up"),
    );
    let said = format!("{}{}", run.stdout, run.stderr);
    assert!(
        said.contains("spatial.no_parent"),
        "`up` refuses rather than inventing a parent, got {run:?}"
    );
    assert!(
        said.contains("aggregate space"),
        "and the refusal names what is missing, got {run:?}"
    );
}

#[test]
fn should_open_no_exit_from_a_kubernetes_place_without_the_relation_write_grant() {
    // §35.5 puts the capability filter before the merge, and §31.19 never grants
    // `relation.write` by default. So the same `near` that answered above answers with nothing
    // here — and the difference between "no edges" and "not allowed to contribute edges" is one
    // the *shell* does not draw, because a package without the grant is never asked. The package
    // draws it where it can: invoking the contribution directly is `capability.denied` naming
    // `relation.write`, which `tests/query.rs` holds.
    let Some(binary) = ono() else { return };
    let cluster = RecordedCluster::start();
    let home = plugin_home("ungranted");
    let run = shell(
        &binary,
        &home,
        &standing_on_the_pod(
            &cluster,
            &["network.connect", "clock.read"],
            "near | to json",
        ),
    );
    assert!(
        run.rows().is_empty(),
        "without the grant the package contributes no relation, so the place has no exits: \
         {run:?}"
    );
}

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
    /// One namespaced collection refuses to be listed, so a namespace-deletion inventory has a
    /// hole in it that must be reported as a hole (§55.2, §55.4, §21.4).
    DeniedInventory,
}

/// What the recorded API server's `SelfSubjectAccessReview` says, and whether it serves one.
///
/// A third member rather than an `Option<bool>`, because §21.4 keeps "denied" and "not queried"
/// apart and a cluster that serves no `authorization.k8s.io` has answered neither way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Authorization {
    /// The review says the identity may make the change (§21.2).
    #[default]
    Allowed,
    /// The review explicitly denies it, with the reason the authorizer gave.
    Denied,
    /// The cluster serves no `authorization.k8s.io` group at all.
    Unserved,
}

/// The reason the recorded authorizer gives when it denies.
const DENIAL: &str = "no RBAC policy matched for user \"deploy-bot\"";

/// An API server that answers from recorded documents, reached through `network.connect`.
#[derive(Clone, Default)]
struct RecordedCluster {
    scenario: Scenario,
    authorization: Authorization,
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
            .field("authorization", &self.authorization)
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

    /// The same cluster, answering a permission check in a particular way.
    fn authorising(authorization: Authorization) -> Arc<Self> {
        Arc::new(Self {
            authorization,
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

/// The CustomResourceDefinition behind `example.io/v1 Widget`.
///
/// A write to this object is a write to what the cluster serves, which is the one mutation whose
/// blast radius reaches the discovery snapshot rather than an object cache (§33.2).
fn crd() -> Json {
    json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": "widgets.example.io",
            "uid": "77777777-7777-7777-7777-777777777777",
            "resourceVersion": "6000",
            "creationTimestamp": "2026-08-01T00:00:00Z",
            "labels": {"team": "platform"},
        },
        "spec": {
            "group": "example.io",
            "names": {"kind": "Widget", "plural": "widgets", "singular": "widget"},
            "scope": "Namespaced",
            "versions": [{"name": "v1", "served": true, "storage": true}],
        },
    })
}

/// The autoscaler that governs the recorded Deployment (§54.2).
fn autoscaler() -> Json {
    json!({
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {
            "name": "api", "namespace": "default",
            "uid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "resourceVersion": "7000", "creationTimestamp": "2026-08-01T00:00:00Z",
        },
        "spec": {
            "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "api"},
            "minReplicas": 2, "maxReplicas": 10,
        },
        "status": {"desiredReplicas": 4},
    })
}

/// A Namespace with a finalizer, which is the deletion §55.2 singles out.
fn namespace() -> Json {
    json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": "staging", "uid": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "resourceVersion": "8000", "creationTimestamp": "2026-07-01T00:00:00Z",
            "finalizers": ["kubernetes"],
        },
        "spec": {"finalizers": ["kubernetes"]},
        "status": {"phase": "Active"},
    })
}

/// A collection answer with the items it holds, framed as the API server frames one.
fn collection(api_version: &str, kind: &str, items: Vec<Json>) -> Vec<u8> {
    ok(&json!({
        "apiVersion": api_version,
        "kind": format!("{kind}List"),
        "metadata": {"resourceVersion": "9000"},
        "items": items,
    }))
}

fn denied(path: &str) -> Vec<u8> {
    http(
        "403 Forbidden",
        &json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": format!("no RBAC policy matched for {path}"),
            "reason": "Forbidden", "code": 403,
        })
        .to_string(),
    )
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
    const CRD: &str = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.io";

    match (method, path_only) {
        ("GET", "/api") => ok(&json!({"kind": "APIVersions", "versions": ["v1"]})),
        ("GET", "/apis") => {
            let mut groups = vec![
                json!({
                    "name": "apps",
                    "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
                }),
                json!({
                    "name": "autoscaling",
                    "versions": [{"groupVersion": "autoscaling/v2", "version": "v2"}],
                    "preferredVersion": {"groupVersion": "autoscaling/v2", "version": "v2"},
                }),
                json!({
                    "name": "apiextensions.k8s.io",
                    "versions": [{
                        "groupVersion": "apiextensions.k8s.io/v1", "version": "v1",
                    }],
                    "preferredVersion": {
                        "groupVersion": "apiextensions.k8s.io/v1", "version": "v1",
                    },
                }),
            ];
            // §5.2: what the cluster serves is learnt rather than assumed, and a cluster that
            // serves no review API is an ordinary cluster rather than an error.
            if cluster.authorization != Authorization::Unserved {
                groups.push(json!({
                    "name": "authorization.k8s.io",
                    "versions": [{"groupVersion": "authorization.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {
                        "groupVersion": "authorization.k8s.io/v1", "version": "v1",
                    },
                }));
            }
            ok(&json!({"kind": "APIGroupList", "groups": groups}))
        }
        ("GET", "/apis/authorization.k8s.io/v1")
            if cluster.authorization != Authorization::Unserved =>
        {
            ok(&json!({
                "kind": "APIResourceList",
                "groupVersion": "authorization.k8s.io/v1",
                "resources": [{
                    "name": "selfsubjectaccessreviews", "kind": "SelfSubjectAccessReview",
                    // Cluster-scoped, and `create` is the only verb it offers: the review is a
                    // question posed as a POST and the API server stores nothing (§21.2).
                    "namespaced": false, "verbs": ["create"],
                }],
            }))
        }
        ("POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews") => {
            let status = match cluster.authorization {
                Authorization::Allowed => json!({
                    "allowed": true, "denied": false,
                    "reason": "RBAC: allowed by ClusterRoleBinding/deployers",
                }),
                Authorization::Denied => json!({
                    "allowed": false, "denied": true, "reason": DENIAL,
                }),
                Authorization::Unserved => return not_found(path_only),
            };
            ok(&json!({
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SelfSubjectAccessReview",
                "status": status,
            }))
        }
        ("GET", "/api/v1") => ok(&json!({
            "kind": "APIResourceList",
            "groupVersion": "v1",
            "resources": [
                {"name": "configmaps", "kind": "ConfigMap", "namespaced": true,
                 "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["cm"]},
                {"name": "persistentvolumeclaims", "kind": "PersistentVolumeClaim",
                 "namespaced": true,
                 "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["pvc"]},
                {"name": "nodes", "kind": "Node", "namespaced": false,
                 "verbs": ["get", "list", "watch", "patch"], "shortNames": ["no"]},
                {"name": "namespaces", "kind": "Namespace", "namespaced": false,
                 "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["ns"]},
                {"name": "pods", "kind": "Pod", "namespaced": true,
                 "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["po"]},
                // Served, readable, and not patchable or deletable by anyone: §11.5's third
                // state, and the one a refusal has to name rather than call a denial.
                {"name": "componentstatuses", "kind": "ComponentStatus", "namespaced": false,
                 "verbs": ["get", "list"], "shortNames": ["cs"]},
            ],
        })),
        ("GET", "/apis/apiextensions.k8s.io/v1") => ok(&json!({
            "kind": "APIResourceList",
            "groupVersion": "apiextensions.k8s.io/v1",
            "resources": [{
                "name": "customresourcedefinitions", "kind": "CustomResourceDefinition",
                "namespaced": false,
                "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["crd"],
            }],
        })),
        ("GET", CRD) => ok(&crd()),
        ("PATCH", CRD) => ok(&crd()),
        ("GET", "/apis/apps/v1") => ok(&json!({
            "kind": "APIResourceList",
            "groupVersion": "apps/v1",
            "resources": [
                {"name": "deployments", "kind": "Deployment", "namespaced": true,
                 "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["deploy"]},
                // §33.5 and §33.6 as discovery spells them: the subresources hang off the
                // collection and are learnt rather than assumed.
                {"name": "deployments/status", "kind": "Deployment", "namespaced": true,
                 "verbs": ["get", "patch", "update"]},
                {"name": "deployments/scale", "kind": "Scale", "namespaced": true,
                 "verbs": ["get", "patch", "update"]},
            ],
        })),
        ("GET", "/apis/autoscaling/v2") => ok(&json!({
            "kind": "APIResourceList",
            "groupVersion": "autoscaling/v2",
            "resources": [{
                "name": "horizontalpodautoscalers", "kind": "HorizontalPodAutoscaler",
                "namespaced": true,
                "verbs": ["get", "list", "watch", "patch", "delete"], "shortNames": ["hpa"],
            }],
        })),
        ("GET", "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers") => collection(
            "autoscaling/v2",
            "HorizontalPodAutoscaler",
            vec![autoscaler()],
        ),
        ("GET", "/apis/autoscaling/v2/namespaces/staging/horizontalpodautoscalers") => {
            collection("autoscaling/v2", "HorizontalPodAutoscaler", Vec::new())
        }
        ("GET", "/api/v1/namespaces/staging") => ok(&namespace()),
        ("DELETE", "/api/v1/namespaces/staging") => ok(&namespace()),
        ("GET", "/api/v1/namespaces/staging/pods") => collection(
            "v1",
            "Pod",
            (0..3)
                .map(|index| {
                    json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {
                            "name": format!("worker-{index}"), "namespace": "staging",
                            "uid": format!("pod-{index}"), "resourceVersion": "9001",
                        },
                    })
                })
                .collect(),
        ),
        ("GET", "/api/v1/namespaces/staging/persistentvolumeclaims") => collection(
            "v1",
            "PersistentVolumeClaim",
            vec![json!({
                "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {
                    "name": "archive", "namespace": "staging", "uid": "pvc-archive",
                    "resourceVersion": "9002",
                },
            })],
        ),
        // §55.2's second bullet: a type that cannot be listed. The inventory has to report it as
        // not listed rather than as a count of zero.
        ("GET", "/api/v1/namespaces/staging/configmaps")
            if cluster.scenario == Scenario::DeniedInventory =>
        {
            denied(path_only)
        }
        ("GET", "/api/v1/namespaces/staging/configmaps") => {
            collection("v1", "ConfigMap", Vec::new())
        }
        ("GET", "/apis/apps/v1/namespaces/staging/deployments") => {
            collection("apps/v1", "Deployment", Vec::new())
        }
        ("GET", "/api/v1/nodes/node-a") => ok(&json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "node-a", "uid": "44444444-4444-4444-4444-444444444444",
                         "resourceVersion": "4000"},
            "spec": {},
        })),
        ("PATCH", "/api/v1/nodes/node-a") => ok(&json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "node-a", "uid": "44444444-4444-4444-4444-444444444444",
                         "resourceVersion": "4001"},
            "spec": {"unschedulable": true},
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

/// How many times the recorded server was asked for one exact path.
fn asked_for(cluster: &RecordedCluster, path: &str) -> usize {
    cluster
        .heads()
        .iter()
        .filter(|head| head.split_whitespace().nth(1) == Some(path))
        .count()
}

/// The arguments that label the recorded CustomResourceDefinition.
fn label_the_crd(extra: &[(&str, Json)]) -> JsonMap<String, Json> {
    let mut map = at_cluster(&[
        ("kind", json!("CustomResourceDefinition")),
        ("name", json!("widgets.example.io")),
        ("set", json!({"/metadata/labels/team": "storage"})),
    ]);
    for (key, value) in extra {
        map.insert((*key).to_owned(), value.clone());
    }
    map
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
    // The one request that is not a `GET` is §21.2's `SelfSubjectAccessReview` — a create by the
    // REST verb, a question by its semantics, and a request the API server answers without
    // storing anything. Nothing else may be write-shaped on this path.
    let heads = cluster.heads();
    assert!(
        heads.iter().all(|head| head.starts_with("GET ")
            || head.starts_with("POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews")),
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

// --- the authorization preflight (§21.2, §21.6, §46.2, Appendix E) --------------------------------

#[tokio::test]
async fn should_ask_the_api_server_whether_a_change_is_allowed_before_describing_it() {
    // §21.2, §46.2 and Appendix E's `AUTHORIZATION` block. The review is resolved through
    // discovery like every other resource — no compile-time assumption that this cluster serves
    // `authorization.k8s.io/v1` — and it asks about the verb the API server would see, which for
    // a server-side apply is `patch` rather than the word this package reports the action under.
    let cluster = RecordedCluster::authorising(Authorization::Allowed);
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
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let records = records(&events);
    let plan = &records[0];

    assert_eq!(
        text(plan, "preflight"),
        "allowed by preflight check",
        "§21.6's first word, verbatim"
    );
    let caveats = list_of(plan, "caveats");
    assert!(
        caveats.iter().any(|caveat| caveat.contains("advisory")),
        "§21.2: a grant is advisory and the API server decides on the request: {caveats:?}"
    );
    assert!(
        !caveats
            .iter()
            .any(|caveat| caveat.contains("no permission preflight granted this")),
        "a preflight ran, so the plan no longer says nobody asked: {caveats:?}"
    );
    assert!(
        text(plan, "statement").contains("authorization:"),
        "Appendix E gives a plan an AUTHORIZATION line: {}",
        text(plan, "statement")
    );

    let posts = cluster.requests("POST");
    assert_eq!(posts.len(), 1, "one review, for one prospective change");
    let (head, body) = &posts[0];
    assert!(
        head.starts_with("POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews "),
        "the review is created at the collection discovery named: {head}"
    );
    let review: Json = serde_json::from_str(body).expect("the review is JSON");
    let attributes = &review["spec"]["resourceAttributes"];
    assert_eq!(
        attributes["verb"],
        json!("patch"),
        "a server-side apply is a PATCH, and that is the verb an authorizer has an opinion on"
    );
    assert_eq!(attributes["group"], json!("apps"));
    assert_eq!(
        attributes["resource"],
        json!("deployments"),
        "§13.1: the review names the REST collection, not the kind"
    );
    assert_eq!(attributes["namespace"], json!("default"));
    assert_eq!(attributes["name"], json!("api"));
}

#[tokio::test]
async fn should_describe_a_change_the_preflight_denied_rather_than_hiding_it() {
    // §21.1: a denied preflight is still a plan. Ono runs no RBAC evaluator, so what it has is
    // one API server's answer — and a user who cannot see the change they are asking to be
    // granted has no way to ask for the right grant.
    let cluster = RecordedCluster::authorising(Authorization::Denied);
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
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let plan = &records(&events)[0];

    let preflight = text(plan, "preflight");
    assert!(
        preflight.starts_with("denied by preflight check"),
        "§21.6's second word: {preflight}"
    );
    assert!(
        preflight.contains(DENIAL),
        "with the reason the API server gave (§46.2): {preflight}"
    );
    assert_eq!(
        list_of(plan, "changes"),
        vec!["/spec/replicas: 3 -> 1"],
        "the change is still described"
    );
    assert!(
        cluster.requests("PATCH").is_empty(),
        "and describing it still wrote nothing: {:?}",
        cluster.heads()
    );
}

#[tokio::test]
async fn should_refuse_a_change_the_api_server_says_this_identity_may_not_make() {
    // §21.2 is advisory and §21.1 keeps the API server the authority, so this refusal is this
    // package's own safety rule rather than an authorization decision: it relays the answer the
    // API server gave a moment ago. What it buys is that nobody has to send a write to find out
    // — and it is `contribution.refused`, the code this package refuses under, rather than a
    // denial code that would claim the cluster refused the write it never received.
    let cluster = RecordedCluster::authorising(Authorization::Denied);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(SET, scale_down(&[("dry_run", json!(false))]))
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;

    assert_eq!(result.status, InvokeStatus::Failed);
    assert!(records(&events).is_empty(), "no change was made");
    let error = result.error.expect("a refusal carries an error");
    assert_eq!(error.name, "contribution.refused");
    assert!(
        error.message.contains(DENIAL),
        "the refusal carries the reason the API server gave: {}",
        error.message
    );
    assert!(
        cluster.requests("PATCH").is_empty(),
        "and nothing write-shaped but the review reached the cluster: {:?}",
        cluster.heads()
    );
}

#[tokio::test]
async fn should_not_report_a_permission_as_denied_when_the_cluster_serves_no_review() {
    // §21.4 and §5.2: an API the cluster does not serve is `not queried`. It is never `denied`
    // and never `allowed` — and it must not stop a change either, because a provider that
    // refused every write against a cluster without `authorization.k8s.io` would have made its
    // own advisory check into the authorizer §21.1 forbids.
    let cluster = RecordedCluster::authorising(Authorization::Unserved);
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
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let plan = &records(&events)[0];
    let preflight = text(plan, "preflight");
    assert!(
        preflight.starts_with("unknown / unchecked"),
        "§21.6's third word: {preflight}"
    );
    assert!(
        preflight.contains("authorization.k8s.io"),
        "and what could not be asked: {preflight}"
    );
    assert!(
        list_of(plan, "caveats")
            .iter()
            .any(|caveat| caveat.contains("no permission preflight granted this")),
        "nobody granted this, and the plan says so"
    );

    let invocation = plugin
        .invoke(SET, scale_down(&[("dry_run", json!(false))]))
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(
        result.status,
        InvokeStatus::Completed,
        "an unanswered check is not a refusal: {:?}",
        result.error
    );
    assert_eq!(records(&events).len(), 1);
    assert_eq!(
        cluster.requests("PATCH").len(),
        1,
        "the API server decides, which is exactly §21.1"
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
    // §11.5's third state, on the write path: the cluster serves ComponentStatuses and offers no
    // `patch` on them. That is not a permission denial and not an absent object, and the refusal
    // says which verb is missing rather than which grant somebody should look for.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("ComponentStatus")),
                ("name", json!("scheduler")),
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

// --- §20.5, §11.4 and §33.2: what a write makes this session ask again ---------------------------

#[tokio::test]
async fn should_ask_what_the_cluster_serves_again_after_it_wrote_a_custom_resource_definition() {
    // §20.5 and §16.5 of the generic provider contract at the boundary: after a successful
    // mutation the provider invalidates the cached facts the change could have reached. For every
    // other kind that is an object cache; for a `CustomResourceDefinition` it is also the
    // discovery snapshot, because what the cluster serves is a cached fact (§20.1) and this write
    // is part of the answer to it.
    //
    // The proof is at the far end of the wire, which is the only place a cache can be caught
    // answering: `/apis` is asked once per invocation that still has to learn what is served, so
    // asking it twice across two invocations means the first invocation's write invalidated what
    // the first invocation had learnt. §11.4's "without restarting Ono" is this, seen from the
    // one process that never restarted.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;

    let (events, result) = plugin
        .invoke(SET, label_the_crd(&[("dry_run", json!(false))]))
        .await
        .expect("it runs")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    assert_eq!(text(&records(&events)[0], "acceptance"), "persisted");
    assert_eq!(
        asked_for(&cluster, "/apis"),
        1,
        "the first invocation learnt what the cluster serves"
    );

    let (_, second) = plugin
        .invoke(SET, label_the_crd(&[("dry_run", json!(false))]))
        .await
        .expect("it runs")
        .collect()
        .await;
    assert_eq!(second.status, InvokeStatus::Completed, "{:?}", second.error);

    assert_eq!(
        asked_for(&cluster, "/apis"),
        2,
        "and the second asked again, because the first one changed what the answer is about"
    );
}

#[tokio::test]
async fn should_not_ask_what_the_cluster_serves_again_after_a_dry_run() {
    // The narrow half, and the one that keeps §50.2 from being paid twice for nothing. A dry run
    // persisted nothing, so no cached fact of this session became wrong — and §16.5 invalidates
    // after a *successful mutation* rather than after every attempt at one. An implementation
    // that invalidated on the way *in*, before knowing what the API server did with the request,
    // would spend three round trips on every preview.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;

    for _ in 0..2 {
        let (events, result) = plugin
            .invoke(SET, label_the_crd(&[]))
            .await
            .expect("it runs")
            .collect()
            .await;
        assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
        assert_eq!(text(&records(&events)[0], "acceptance"), "dry run");
    }

    assert_eq!(
        asked_for(&cluster, "/apis"),
        1,
        "the second preview answered from what the first one learnt"
    );
}

#[tokio::test]
async fn should_declare_what_a_deletion_invalidated_and_what_it_could_not_name() {
    // §16.5 of the generic provider contract invalidates "according to declared impact", and this
    // is the declaration. A cascading deletion reaches objects the API server names in neither the
    // request nor the answer, so this session cannot say which of its caches hold one — and the
    // honest move is to leave those caches exactly as they are, still carrying their own
    // `observed_at` and still saying they came from a cache (§20.2), while saying out loud that
    // they were not invalidated. The alternative is to empty every cache in the session on the
    // chance, which pays §50.2 for collections the write demonstrably did not touch and is still
    // a guess (§45.2, §45.5).
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let (events, result) = plugin
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
        .expect("it runs")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let statement = text(&records(&events)[0], "statement");

    assert!(
        statement.contains("invalidated"),
        "a write that persisted says what it made this session forget: {statement}"
    );
    assert!(
        statement.contains("not named in the answer"),
        "and it says what it could not reach rather than implying it reached everything: \
         {statement}"
    );
}

#[tokio::test]
async fn should_declare_no_invalidation_for_a_change_that_was_never_made() {
    // The control, and the sentence that would be a lie: a dry run persisted nothing, so nothing
    // this session holds became wrong and there is nothing to have invalidated.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let (events, result) = plugin
        .invoke(SET, scale_down(&[]))
        .await
        .expect("it runs")
        .collect()
        .await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let statement = text(&records(&events)[0], "statement");

    assert!(
        !statement.contains("invalidated"),
        "nothing was written, so nothing was invalidated: {statement}"
    );
}

// --- §43.3's curated actions, reached without knowing a JSON pointer -------------------------------

#[tokio::test]
async fn should_scale_a_workload_without_the_user_naming_a_json_pointer() {
    // §43.3 names seven candidate actions and the first of them is "scale workload". Every one of
    // them reduces to the bounded field change this package already had; what was missing is that
    // a user had to know that the field is `/spec/replicas` on a Deployment and a StatefulSet and
    // that a JSON pointer is how it is spelled. §52 calls that discoverability, and a bounded
    // action surface nobody can find is §43.4's escape hatch wearing §43.3's name.
    //
    // The word is `set` and there is no new one: the action is an *argument* of the verb the
    // shell already has, which is how this stays short of the Kubernetes mini-shell §35.1 and §4
    // invariant 22 forbid.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("Deployment")),
                ("name", json!("api")),
                ("namespace", json!("default")),
                ("replicas", json!(1)),
                ("dry_run", json!(false)),
            ]),
        )
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let outcome = &records(&events)[0];

    assert_eq!(text(outcome, "action"), "scale");
    assert!(
        list_of(outcome, "changes")
            .iter()
            .any(|change| change.contains("/spec/replicas")),
        "the pointer is still what travels; it is just not what a user has to write: {:?}",
        list_of(outcome, "changes")
    );
    assert!(
        text(outcome, "verification").contains("controller"),
        "§46.3's first worked example: {}",
        text(outcome, "verification")
    );
    let patches = cluster.requests("PATCH");
    assert_eq!(patches.len(), 1);
    let body: Json = serde_json::from_str(&patches[0].1).expect("JSON");
    assert_eq!(body["spec"]["replicas"], json!(1));
}

#[tokio::test]
async fn should_cordon_a_node_by_its_schedulability_and_verify_it_as_one() {
    // §43.3's "cordon / uncordon node", and §46.3's third worked example — `Node.spec.unschedulable
    // == true`. The mission's sharp end: a cordon whose verification rule is the same as an
    // apply's is not a curated action. It is also the action whose *effects* a field list cannot
    // show, because `unschedulable: true` reads as an ordinary boolean and what it does is take a
    // node out of scheduling without moving anything already on it.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("Node")),
                ("name", json!("node-a")),
                ("schedulable", json!(false)),
                ("dry_run", json!(false)),
            ]),
        )
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let outcome = &records(&events)[0];

    assert_eq!(text(outcome, "action"), "cordon");
    assert!(
        text(outcome, "verification").contains("unschedulable"),
        "§46.3: the rule is the node's own field, not an apply's: {}",
        text(outcome, "verification")
    );
    assert!(
        text(outcome, "verification").contains("neither stopped nor moved"),
        "cordoning is not draining, and the plan says which of the two it is: {}",
        text(outcome, "verification")
    );
    let body: Json =
        serde_json::from_str(&cluster.requests("PATCH")[0].1).expect("the apply document is JSON");
    assert_eq!(body["spec"]["unschedulable"], json!(true));
}

#[tokio::test]
async fn should_set_an_image_by_container_name_rather_than_by_list_position() {
    // §43.3's "set image". The container is named because §44.1 merges list entries by key rather
    // than by position: a user who writes `--image web=...` never learns that the container is at
    // index 0, and the apply document carries the `name` beside the `image` so that the server
    // merges against the entry that was meant.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("Deployment")),
                ("name", json!("api")),
                ("namespace", json!("default")),
                ("image", json!(["web=registry.io/web:2"])),
                ("dry_run", json!(false)),
            ]),
        )
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let outcome = &records(&events)[0];

    assert_eq!(text(outcome, "action"), "set-image");
    assert!(
        text(outcome, "verification").contains("ReplicaSet"),
        "§46.3's second worked example, not the first: {}",
        text(outcome, "verification")
    );
    let body: Json =
        serde_json::from_str(&cluster.requests("PATCH")[0].1).expect("the apply document is JSON");
    let container = &body["spec"]["template"]["spec"]["containers"][0];
    assert_eq!(container["name"], json!("web"));
    assert_eq!(container["image"], json!("registry.io/web:2"));
}

#[tokio::test]
async fn should_refuse_an_image_for_a_container_the_object_does_not_have() {
    // The other half of naming the container: a name that matches nothing is a refusal that says
    // which containers there are, rather than an apply document that adds a container.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("Deployment")),
                ("name", json!("api")),
                ("namespace", json!("default")),
                ("image", json!(["sidecar=registry.io/sidecar:1"])),
            ]),
        )
        .await
        .expect("it runs");
    let (_, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a refusal carries an error");
    assert!(error.message.contains("sidecar"), "{}", error.message);
    assert!(error.message.contains("web"), "{}", error.message);
    assert!(cluster.requests("PATCH").is_empty());
}

#[tokio::test]
async fn should_restart_a_rollout_through_the_pod_template_rather_than_by_removing_pods() {
    // §43.3's "restart rollout through an explicit supported mechanism". The mechanism is a pod
    // template annotation: changing the template is what makes a controller roll, and it is a
    // change the API server and the controller both already understand. Deleting pods would be a
    // second mechanism this provider invented, with no plan and no verification rule behind it.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("Deployment")),
                ("name", json!("api")),
                ("namespace", json!("default")),
                ("restart_rollout", json!(true)),
                ("dry_run", json!(false)),
            ]),
        )
        .await
        .expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let outcome = &records(&events)[0];

    assert_eq!(text(outcome, "action"), "restart-rollout");
    let body: Json =
        serde_json::from_str(&cluster.requests("PATCH")[0].1).expect("the apply document is JSON");
    let annotations = &body["spec"]["template"]["metadata"]["annotations"];
    // The marker is the `resourceVersion` the restart was planned against: an opaque continuity
    // token used as an opaque token (§14.3), which makes the annotation say *which observation*
    // this restart was made from and needs no clock to be deterministic.
    assert_eq!(
        annotations["ono-sendai.io/restarted-from-resource-version"],
        json!("4711")
    );
    assert!(
        text(outcome, "verification").contains("ReplicaSet"),
        "a restart is verified as a rollout rather than as a field that was set (§46.3): {}",
        text(outcome, "verification")
    );
    assert!(
        cluster.requests("DELETE").is_empty(),
        "nothing was deleted to make a rollout happen"
    );
}

#[tokio::test]
async fn should_refuse_more_than_one_curated_action_in_one_change() {
    // One plan describes one transition, because §46.3 gives one verification rule per action and
    // §46.2 one set of effects. Two curated arguments in one invocation would produce a plan whose
    // rule belongs to one of them and whose effects belong to both.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("Deployment")),
                ("name", json!("api")),
                ("namespace", json!("default")),
                ("replicas", json!(2)),
                ("restart_rollout", json!(true)),
            ]),
        )
        .await
        .expect("it runs");
    let (_, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a refusal carries an error");
    assert!(error.message.contains("replicas"), "{}", error.message);
    assert!(
        error.message.contains("restart_rollout"),
        "{}",
        error.message
    );
    assert!(cluster.requests("PATCH").is_empty());
}

// --- §43.4: the escape hatch says which one it is -------------------------------------------------

#[tokio::test]
async fn should_label_the_raw_pointer_apply_as_low_level_where_a_user_meets_it() {
    // §43.4: the generic raw mutation "MUST be explicitly low-level" and "MUST NOT become the
    // default UX simply because it is easy to implement". Planning and confirmation were already
    // integrated; the labelling was not, and the JSON-pointer apply was simultaneously §43.3's
    // bounded change and the only apply there was.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin.invoke(SET, scale_down(&[])).await.expect("it runs");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let outcome = &records(&events)[0];

    assert_eq!(text(outcome, "action"), "apply");
    assert!(
        list_of(outcome, "caveats")
            .iter()
            .any(|caveat| caveat.contains("low-level")),
        "the record says which of §43.3 and §43.4 this is: {:?}",
        list_of(outcome, "caveats")
    );
    assert!(
        list_of(outcome, "caveats")
            .iter()
            .any(|caveat| caveat.contains("scale") && caveat.contains("cordon")),
        "and it names the curated path a reader should prefer: {:?}",
        list_of(outcome, "caveats")
    );

    // And the same sentence is in `help`, before anybody has run anything.
    let command = ono_kubernetes_plugin::contributions::command("set-k8s-resource")
        .expect("the package contributes it");
    assert!(
        command.summary.contains("low-level") || command.summary.contains("expert"),
        "the summary a user reads first distinguishes the two paths: {}",
        command.summary
    );
    let set = command
        .options()
        .into_iter()
        .find(|option| option.name == "set")
        .expect("the raw path is an option of the curated command");
    assert!(
        set.doc.to_lowercase().contains("low-level"),
        "§43.4, in the one line a user reads before writing it: {}",
        set.doc
    );
}

// --- §33.6: a write to observed state ----------------------------------------------------------

#[tokio::test]
async fn should_refuse_a_change_that_writes_the_status_subresource() {
    // §33.6: preserve desired/observed semantics *and* mutation boundaries. The read half was
    // held; the write half was absent, and `--set '{"/status/phase": "x"}'` was assembled into the
    // object document like any other field. Refused rather than routed to `/status`: writing
    // observed state is a controller's job, and a provider that did it would be answering "what
    // did the controller see" with "what somebody typed" (Gate G).
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .invoke(
            SET,
            at_cluster(&[
                ("kind", json!("Deployment")),
                ("name", json!("api")),
                ("namespace", json!("default")),
                ("set", json!({"/status/availableReplicas": 9})),
            ]),
        )
        .await
        .expect("it runs");
    let (_, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Failed);
    let error = result.error.expect("a refusal carries an error");
    assert!(error.message.contains("status"), "{}", error.message);
    assert!(
        error.message.contains("controller") || error.message.contains("observed"),
        "the refusal says why rather than only that: {}",
        error.message
    );
    assert!(
        cluster.requests("PATCH").is_empty(),
        "and nothing was sent to find out"
    );
}

// --- §54: a competing desired-state writer ------------------------------------------------------

#[tokio::test]
async fn should_warn_when_an_autoscaler_governs_the_replica_count_being_changed() {
    // §54.2: "a plan for a direct replica change SHOULD warn when an HPA targets the same
    // workload", and "the provider MUST NOT claim durable effect merely because the Deployment
    // accepted `spec.replicas`". The `MUST NOT` half already held through `Verdict::Inconclusive`;
    // the warning was missing, and `grep HorizontalPodAutoscaler crates/` found nothing.
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
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let plan = &records(&events)[0];

    assert!(
        list_of(plan, "caveats")
            .iter()
            .any(|caveat| caveat.contains("HorizontalPodAutoscaler") && caveat.contains("api")),
        "§54.2's warning: {:?}",
        list_of(plan, "caveats")
    );
    assert!(
        maps_of(plan, "competing_writers")
            .iter()
            .any(|writer| writer.contains("scaleTargetRef")),
        "§54.1 keeps the sources apart, and this one is the HPA target: {:?}",
        maps_of(plan, "competing_writers")
    );
    assert!(
        maps_of(plan, "competing_writers")
            .iter()
            .any(|writer| writer.contains("managedFields")),
        "§54.1's first source is in the same list: {:?}",
        maps_of(plan, "competing_writers")
    );
    assert!(
        !cluster
            .heads()
            .iter()
            .any(|head| head.starts_with("PATCH") || head.starts_with("DELETE")),
        "asking is still a read"
    );
}

#[tokio::test]
async fn should_not_look_for_an_autoscaler_for_a_change_that_is_not_a_replica_change() {
    // §54.2 is about a *direct replica change*. A label change on the same Deployment is not one,
    // and a provider that listed every namespace's autoscalers on every plan would be paying
    // §50.2 for a warning that could not apply.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .query(
            "k8s-plan",
            at_cluster(&[
                ("kind", json!("Deployment")),
                ("name", json!("api")),
                ("namespace", json!("default")),
                ("set", json!({"/metadata/labels/tier": "edge"})),
            ]),
        )
        .await
        .expect("the query starts");
    let (_, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    assert_eq!(
        asked_for(
            &cluster,
            "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers"
        ),
        0
    );
}

// --- §55.2: deleting a Namespace ------------------------------------------------------------------

#[tokio::test]
async fn should_enumerate_what_a_namespace_deletion_would_remove() {
    // §55.2: "deleting a Namespace is a high-impact destructive operation and MUST receive
    // enhanced prospective analysis", with six bullets. Before this, a Namespace deletion plan was
    // indistinguishable from a ConfigMap's but for two generic flags.
    let cluster = RecordedCluster::playing(Scenario::Accepted);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .query(
            "k8s-plan",
            at_cluster(&[
                ("kind", json!("Namespace")),
                ("name", json!("staging")),
                ("action", json!("delete")),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let plan = &records(&events)[0];

    // The first bullet: counts by GVR.
    let contained = maps_of(plan, "contained");
    assert!(
        contained.iter().any(|entry| entry.contains("v1/pods")),
        "{contained:?}"
    );
    assert!(
        contained
            .iter()
            .any(|entry| entry.contains("persistentvolumeclaims")),
        "{contained:?}"
    );
    let caveats = list_of(plan, "caveats");
    // The third bullet: the namespace's finalizers.
    assert!(
        caveats.iter().any(|caveat| caveat.contains("kubernetes")),
        "{caveats:?}"
    );
    // The fourth: the PVC implication, named rather than left as one more count.
    assert!(
        caveats
            .iter()
            .any(|caveat| caveat.contains("PersistentVolumeClaim")),
        "{caveats:?}"
    );
    // The sixth: external effects may outlive the deletion.
    assert!(
        caveats.iter().any(|caveat| caveat.contains("outlive")),
        "{caveats:?}"
    );
    // The fifth is the authorization line every plan already carries.
    assert!(!text(plan, "preflight").is_empty());
}

#[tokio::test]
async fn should_report_a_namespace_type_that_could_not_be_listed_as_not_listed() {
    // §55.2's second bullet, §55.4 and §45.4 in one sentence: what could not be listed is reported
    // as not listed. A count of zero for a collection nobody was allowed to read is the single
    // most dangerous number a namespace-deletion plan could print.
    let cluster = RecordedCluster::playing(Scenario::DeniedInventory);
    let plugin = loaded(&cluster).await;
    let invocation = plugin
        .query(
            "k8s-plan",
            at_cluster(&[
                ("kind", json!("Namespace")),
                ("name", json!("staging")),
                ("action", json!("delete")),
            ]),
        )
        .await
        .expect("the query starts");
    let (events, result) = invocation.collect().await;
    assert_eq!(result.status, InvokeStatus::Completed, "{:?}", result.error);
    let plan = &records(&events)[0];

    assert!(
        !maps_of(plan, "contained")
            .iter()
            .any(|entry| entry.contains("configmaps")),
        "a collection that would not be listed is not a collection of zero: {:?}",
        maps_of(plan, "contained")
    );
    assert!(
        text(plan, "contained_coverage").contains("denied"),
        "{}",
        text(plan, "contained_coverage")
    );
    assert!(
        list_of(plan, "caveats")
            .iter()
            .any(|caveat| caveat.contains("not listed")),
        "{:?}",
        list_of(plan, "caveats")
    );
}

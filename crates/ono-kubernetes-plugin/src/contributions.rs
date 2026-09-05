//! What this package declares before any of its code runs: the targets it answers for, and the
//! schemas their records carry (spec §31.23, §31.68).
//!
//! The table below is the single place the two halves of a declaration come from. A package
//! states what it contributes twice — once in `package/contributions/*.yaml`, so the host can
//! register a placeholder without starting anything, and once across the handshake, when the
//! instance loads. Deriving both from one table is what stops them disagreeing about what the
//! package contributes; `tests/contributions.rs` holds them to it.
//!
//! Each entry also carries the **group and kind** the target reads. Deliberately not a GVR: which
//! REST collection serves a kind, and at which version, is discovery's answer and never a
//! compile-time assumption (§4 invariants 1–2, §5.2, §13.1). A group and a kind are GVK identity,
//! which is stable across the versions a server happens to serve, so naming them here decides
//! nothing discovery is entitled to decide.

use ono_kuang_sdk::protocol::{SchemaContribution, SchemaFieldContribution, TargetContribution};

/// One field of a contributed schema, as the table spells it.
///
/// `required` is the only flag because ADR-0012 §8 makes the two mutually exclusive: a field is
/// required or it is nullable, and a table with both would be able to say something the contract
/// refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// The field name, as the record carries it.
    pub name: &'static str,
    /// The registry type name, e.g. `string`, `int`, `list<string>`, `map`, `timestamp`.
    pub field_type: &'static str,
    /// Whether the field is always known. Everything else is nullable, and null means unknown.
    pub required: bool,
}

impl Field {
    /// A field that is always known.
    const fn required(name: &'static str, field_type: &'static str) -> Self {
        Self {
            name,
            field_type,
            required: true,
        }
    }

    /// A field that may be absent, in which case it is null and never a default.
    const fn nullable(name: &'static str, field_type: &'static str) -> Self {
        Self {
            name,
            field_type,
            required: false,
        }
    }
}

/// One noun this package answers for, with everything needed to declare it and to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// The target word, as `get k8s-pod` spells it.
    pub name: &'static str,
    /// The schema id the target's records carry.
    pub schema: &'static str,
    /// The schema's display name.
    pub schema_name: &'static str,
    /// One line: what an object of this schema is.
    pub schema_summary: &'static str,
    /// One line, for `help` and completion.
    pub summary: &'static str,
    /// What makes two observations the same object, in prose.
    pub identity_doc: &'static str,
    /// The API group the kind lives in; empty for the core group (§13.3).
    pub group: &'static str,
    /// The kind, as `apiVersion`/`kind` spells it. Half of a GVK, never a GVR (§13.1).
    pub kind: &'static str,
    /// The schema's fields, in declaration order.
    pub fields: &'static [Field],
}

impl Target {
    /// The schema as the handshake carries it.
    #[must_use]
    pub fn schema_contribution(&self) -> SchemaContribution {
        SchemaContribution {
            id: self.schema.to_owned(),
            name: self.schema_name.to_owned(),
            summary: self.schema_summary.to_owned(),
            identity: vec![IDENTITY.to_owned()],
            fields: self
                .fields
                .iter()
                .map(|field| SchemaFieldContribution {
                    name: field.name.to_owned(),
                    field_type: field.field_type.to_owned(),
                    required: field.required,
                    nullable: !field.required,
                })
                .collect(),
        }
    }

    /// The target as the handshake carries it.
    #[must_use]
    pub fn target_contribution(&self) -> TargetContribution {
        TargetContribution {
            name: self.name.to_owned(),
            schema: self.schema.to_owned(),
            summary: self.summary.to_owned(),
            identity_doc: self.identity_doc.to_owned(),
        }
    }
}

/// The identity field of every Kubernetes schema, without exception.
///
/// `metadata.uid` is what the API server guarantees about one object's life; a name is a label a
/// human reuses (§16.1, §4 invariants 4–5). A schema keyed on the name would let a recreated Pod
/// inherit the history of the one it replaced, which is precisely the discontinuity §16.3 exists
/// to make visible.
pub const IDENTITY: &str = "uid";

/// The metadata every Kubernetes object carries, projected the same way for every kind (§14).
///
/// Repeated per schema rather than shared through composition because `SchemaContribution` has no
/// notion of a mixin: the wire shape is a flat field list, and a reader of one schema should see
/// all of it in one place.
const fn common(namespaced: bool) -> &'static [Field] {
    if namespaced {
        NAMESPACED_METADATA
    } else {
        CLUSTER_METADATA
    }
}

const CLUSTER_METADATA: &[Field] = &[
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::nullable("resource_version", "string"),
    Field::nullable("created", "timestamp"),
    Field::nullable("labels", "map"),
    Field::required("terminating", "bool"),
];

const NAMESPACED_METADATA: &[Field] = &[
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("namespace", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::nullable("resource_version", "string"),
    Field::nullable("created", "timestamp"),
    Field::nullable("labels", "map"),
    Field::required("terminating", "bool"),
];

/// Concatenates the shared metadata with a kind's own fields, at compile time.
///
/// A `const fn` rather than a macro so that the field order a schema declares — and therefore the
/// order a record stores its fields in — is visible in the table itself.
const fn with_metadata<const N: usize>(namespaced: bool, own: &'static [Field]) -> [Field; N] {
    let shared = common(namespaced);
    let mut fields = [Field::required("", ""); N];
    let mut at = 0;
    while at < shared.len() {
        fields[at] = shared[at];
        at += 1;
    }
    let mut own_at = 0;
    while own_at < own.len() {
        fields[at] = own[own_at];
        at += 1;
        own_at += 1;
    }
    fields
}

const NAMESPACE_FIELDS: [Field; 9] = with_metadata(false, &[Field::nullable("phase", "string")]);

const NODE_FIELDS: [Field; 12] = with_metadata(
    false,
    &[
        Field::nullable("ready", "string"),
        Field::nullable("unschedulable", "bool"),
        Field::nullable("kubelet_version", "string"),
        Field::nullable("internal_ip", "string"),
    ],
);

const POD_FIELDS: [Field; 14] = with_metadata(
    true,
    &[
        Field::nullable("phase", "string"),
        Field::nullable("node", "string"),
        Field::nullable("pod_ip", "string"),
        Field::nullable("containers", "list<string>"),
        Field::nullable("restarts", "int"),
    ],
);

const DEPLOYMENT_FIELDS: [Field; 15] = with_metadata(
    true,
    &[
        Field::nullable("desired_replicas", "int"),
        Field::nullable("ready_replicas", "int"),
        Field::nullable("updated_replicas", "int"),
        Field::nullable("available_replicas", "int"),
        Field::nullable("generation", "int"),
        Field::nullable("observed_generation", "int"),
    ],
);

const SECRET_FIELDS: [Field; 11] = with_metadata(
    true,
    &[
        Field::nullable("secret_type", "string"),
        Field::nullable("keys", "list<string>"),
    ],
);

/// The targets this package answers for today.
///
/// Five of the nineteen nouns `package/contributions/targets.yaml` declares. The other fourteen
/// are placeholders §31.68 already gives help and completion for; wiring a schema for a target
/// nothing answers would be a claim the package cannot keep. Each of the five proves something
/// the others do not: `k8s-namespace` is the scope dimension, `k8s-node` is cluster-scoped so
/// both scope shapes are exercised, `k8s-pod` is the noun the milestone names, `k8s-deployment`
/// carries the desired-versus-observed pair of §14.4, and `k8s-secret` is where §22's redaction
/// boundary is demonstrated rather than asserted.
pub static TARGETS: &[Target] = &[
    Target {
        name: "k8s-namespace",
        schema: "io.github.godspeed-you.kubernetes.namespace/1",
        schema_name: "KubernetesNamespace",
        schema_summary: "A namespace, the primary scope dimension of a cluster.",
        summary: "Namespaces, the primary scope dimension of a cluster.",
        identity_doc: "Two observations are the same namespace when their `metadata.uid` matches.",
        group: "",
        kind: "Namespace",
        fields: &NAMESPACE_FIELDS,
    },
    Target {
        name: "k8s-node",
        schema: "io.github.godspeed-you.kubernetes.node/1",
        schema_name: "KubernetesNode",
        schema_summary: "A node, and what the kubelet on it reports about itself.",
        summary: "Nodes, and the cloud instances underneath them.",
        identity_doc: "Two observations are the same node when their `metadata.uid` matches; a \
                       name reused after deletion is a new node.",
        group: "",
        kind: "Node",
        fields: &NODE_FIELDS,
    },
    Target {
        name: "k8s-pod",
        schema: "io.github.godspeed-you.kubernetes.pod/1",
        schema_name: "KubernetesPod",
        schema_summary: "A pod, the workload that actually runs.",
        summary: "Pods, the workload that actually runs.",
        identity_doc: "Two observations are the same pod when their `metadata.uid` matches. A \
                       recreated pod with the same name is a different pod.",
        group: "",
        kind: "Pod",
        fields: &POD_FIELDS,
    },
    Target {
        name: "k8s-deployment",
        schema: "io.github.godspeed-you.kubernetes.deployment/1",
        schema_name: "KubernetesDeployment",
        schema_summary: "A deployment, with what was asked of it beside what has been observed.",
        summary: "Deployments, and the ReplicaSets they control.",
        identity_doc: "Two observations are the same deployment when their `metadata.uid` \
                       matches.",
        group: "apps",
        kind: "Deployment",
        fields: &DEPLOYMENT_FIELDS,
    },
    Target {
        name: "k8s-secret",
        schema: "io.github.godspeed-you.kubernetes.secret/1",
        schema_name: "KubernetesSecret",
        schema_summary: "A secret's metadata — which keys exist, never what they hold (§22).",
        summary: "Secret metadata — which keys exist and what mounts them, never the values \
                  (specification section 22).",
        identity_doc: "Two observations are the same secret when their `metadata.uid` matches.",
        group: "",
        kind: "Secret",
        fields: &SECRET_FIELDS,
    },
];

/// The target of that name, where this package answers for one.
#[must_use]
pub fn target(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|target| target.name == name)
}

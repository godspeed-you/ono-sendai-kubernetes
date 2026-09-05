//! What this package declares before any of its code runs: the targets it answers for, and the
//! schemas their records carry (spec §31.23, §31.68).
//!
//! The table below is the single place the two halves of a declaration come from. A package
//! states what it contributes twice — once in `package/contributions/*.yaml`, so the host can
//! register a placeholder without starting anything, and once across the handshake, when the
//! instance loads. Deriving both from one table is what stops them disagreeing about what the
//! package contributes; `tests/contributions.rs` holds them to it.
//!
//! Each entry also carries **what it reads** — [`Reads`]. For a curated noun that is a group and
//! a kind. Deliberately not a GVR: which REST collection serves a kind, and at which version, is
//! discovery's answer and never a compile-time assumption (§4 invariants 1–2, §5.2, §13.1). A
//! group and a kind are GVK identity, which is stable across the versions a server happens to
//! serve, so naming them here decides nothing discovery is entitled to decide.
//!
//! For `k8s-resource` it is [`Reads::Discovered`]: the kind is named by the *query* and resolved
//! against the cluster's own discovery, so a CRD invented after this table was written is
//! reachable without recompiling anything (§15.1, §33.1, Gate A). A document written before the
//! package runs cannot name a kind invented after it, so the noun names the *shape* of the
//! question instead of the answer — ADR-0010.

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

/// What a target reads, which is either one named kind or whatever the query names.
///
/// An enum rather than an optional group and kind, so that the two cases cannot be confused by a
/// caller who forgets to check: a curated noun always has a kind and the dynamic noun never has
/// one, and there is no third state in which a table entry is half-specified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reads {
    /// One kind, named in this table (§15.2's curated tier).
    Kind {
        /// The API group the kind lives in; empty for the core group (§13.3).
        group: &'static str,
        /// The kind, as `apiVersion`/`kind` spells it. Half of a GVK, never a GVR (§13.1).
        kind: &'static str,
    },
    /// Whatever kind the query names, resolved against the cluster's discovery (§15.1, §33.1).
    ///
    /// The one route by which a resource this package has never heard of is readable. It carries
    /// no group and no kind because it has none until a query supplies them, and a default here
    /// would be this package choosing a kind on the operator's behalf.
    Discovered,
    /// No Kubernetes object at all: the provider instance itself (§8.6, §10, §61.1).
    ///
    /// The diagnostic reads `/version`, the discovery documents, the `kube-system` namespace and
    /// a `SelfSubjectReview` — none of which is a collection of objects, and all of which are
    /// facts about the session rather than about anything in the cluster. A group and a kind here
    /// would name a collection nobody lists.
    Instance,
}

impl Reads {
    /// The API group, where the table names one.
    #[must_use]
    pub const fn group(self) -> Option<&'static str> {
        match self {
            Self::Kind { group, .. } => Some(group),
            Self::Discovered | Self::Instance => None,
        }
    }

    /// The kind, where the table names one.
    #[must_use]
    pub const fn kind(self) -> Option<&'static str> {
        match self {
            Self::Kind { kind, .. } => Some(kind),
            Self::Discovered | Self::Instance => None,
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
    /// Which resource the target reads, and whether the table or the query names it.
    pub reads: Reads,
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

/// The one schema every dynamically discovered resource's records carry.
///
/// **Why one schema and not one per kind.** A record may only claim a schema the package
/// contributed at load, and the contributions are fixed before the package has spoken to any
/// cluster — so there is no moment at which a schema named after a CRD could be declared. The
/// host enforces this twice over: a record whose schema id is not in the handshake's registry
/// does not decode at all, and one that decodes but does not match the target's declared schema
/// is a `runtime.schema_violation`. A dynamic record therefore carries
/// `io.github.godspeed-you.kubernetes.resource/1` whatever kind it holds, and says which
/// Kubernetes type it *is* in its fields rather than in its schema id (§13.2). ADR-0010.
///
/// The fields after the shared metadata are three claims:
///
/// - **what this is** — `api_group`, `resource_name`, `scope`, which is §13.2's canonical host
///   type, so that identity survives the flattening of every kind onto one schema;
/// - **how well it is known** — `schema_source` and `precision`, because a projection that does
///   not say where its typing came from invites the reader to trust all of it equally (§12.3);
/// - **what it holds** — `spec`, `status` and `other`, kept apart because desired and observed
///   state are different claims (§4 invariant 8, §33.6), plus `untyped`, the pointers of the
///   fields no schema described. Those fields are *in* `spec`, `status` and `other` all the
///   same: §12.5 preserves them, and `untyped` says which they are rather than hiding them.
const RESOURCE_FIELDS: [Field; 18] = with_metadata(
    true,
    &[
        Field::required("api_group", "string"),
        Field::required("resource_name", "string"),
        Field::required("scope", "enum<namespaced|cluster>"),
        Field::required("schema_source", "enum<openapi-v3|crd-structural|absent>"),
        Field::required("precision", "enum<structural|loose|unknown>"),
        Field::nullable("spec", "map"),
        Field::nullable("status", "map"),
        Field::nullable("other", "map"),
        Field::required("untyped", "list<string>"),
    ],
);

/// What `k8s-cluster` answers: which cluster this is, whether it answers, and who the provider is
/// to it (§8.5, §8.6, §10, §34.3, §61.1).
///
/// The shared metadata of every other schema is deliberately absent. There is no
/// `metadata.uid` here because there is no Kubernetes object: the identity is the *provider
/// instance* of §10.1 — `kubernetes:<context>` — which is what stays stable across reconnects and
/// what two instances pointed at one cluster differ in. Keying this record on the cluster
/// fingerprint instead would merge exactly the two instances §10.3 says MUST NOT be merged.
///
/// Four groups of fields, and the boundaries between them are the point:
///
/// - **which cluster** — `server`, `kube_system_uid`, `server_key_fingerprint` are §10.2's
///   signals one by one, and `fingerprint` plus `fingerprint_signals` are what they compose to.
///   A signal that was not obtained is `null` and names its reason in `unknowns`, so a fingerprint
///   built from one signal is visibly weaker than one built from three;
/// - **whether it answers** — `reachable`, `server_version`, `tls`, and the per-request `probes`
///   and `latency_ms` §34.3 asks for, so that a slow aggregated API is not reported as "the
///   cluster";
/// - **who the provider is to it** — `credential_identity` and `effective_identity` are two
///   fields rather than one, because §8.5 requires them to be impossible to confuse the day
///   impersonation exists. `impersonating` says whether they can differ;
/// - **what it could not determine** — `unknowns`, each entry naming a subject and one of §21.4's
///   eight outcomes, so a field the cluster refused reads differently from one it does not have.
const CLUSTER_FIELDS: &[Field] = &[
    Field::required("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("server", "string"),
    Field::required("reachable", "bool"),
    Field::nullable("server_version", "string"),
    Field::required("tls", "string"),
    Field::nullable("fingerprint", "string"),
    Field::required("fingerprint_signals", "list<string>"),
    Field::nullable("kube_system_uid", "string"),
    Field::nullable("server_key_fingerprint", "string"),
    Field::nullable("credential_identity", "string"),
    Field::nullable("effective_identity", "string"),
    Field::nullable("effective_uid", "string"),
    Field::nullable("effective_groups", "list<string>"),
    Field::required("impersonating", "bool"),
    Field::nullable("impersonated_user", "string"),
    Field::required("unknowns", "list<string>"),
    Field::required("probes", "map"),
    Field::required("latency_ms", "map"),
];

/// The targets this package answers for today.
///
/// Five curated nouns and one dynamic one, of the twenty `package/contributions/targets.yaml`
/// declares. The other fourteen are placeholders §31.68 already gives help and completion for;
/// wiring a schema for a target nothing answers would be a claim the package cannot keep.
///
/// Each of the five curated ones proves something the others do not: `k8s-namespace` is the
/// scope dimension, `k8s-node` is cluster-scoped so both scope shapes are exercised, `k8s-pod`
/// is the noun the milestone names, `k8s-deployment` carries the desired-versus-observed pair of
/// §14.4, and `k8s-secret` is where §22's redaction boundary is demonstrated rather than
/// asserted.
///
/// `k8s-resource` is the floor beneath all of them (§15.1): it reads whatever the cluster serves
/// and this package never heard of, so a curated noun is a *better* answer for a kind rather
/// than the only answer for it. A curated noun that is deleted from this table costs its user a
/// more verbose spelling and nothing else.
pub static TARGETS: &[Target] = &[
    Target {
        name: "k8s-namespace",
        schema: "io.github.godspeed-you.kubernetes.namespace/1",
        schema_name: "KubernetesNamespace",
        schema_summary: "A namespace, the primary scope dimension of a cluster.",
        summary: "Namespaces, the primary scope dimension of a cluster.",
        identity_doc: "Two observations are the same namespace when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "",
            kind: "Namespace",
        },
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
        reads: Reads::Kind {
            group: "",
            kind: "Node",
        },
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
        reads: Reads::Kind {
            group: "",
            kind: "Pod",
        },
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
        reads: Reads::Kind {
            group: "apps",
            kind: "Deployment",
        },
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
        reads: Reads::Kind {
            group: "",
            kind: "Secret",
        },
        fields: &SECRET_FIELDS,
    },
    Target {
        name: "k8s-resource",
        schema: "io.github.godspeed-you.kubernetes.resource/1",
        schema_name: "KubernetesResource",
        schema_summary: "Any resource the cluster serves, typed by the schema the cluster \
                         publishes for it.",
        summary: "Any resource this cluster serves, named by `kind` and `group` \
                  (specification section 15.1).",
        identity_doc: "Two observations are the same object when their `metadata.uid` matches, \
                       whatever kind they are.",
        reads: Reads::Discovered,
        fields: &RESOURCE_FIELDS,
    },
    Target {
        name: "k8s-cluster",
        schema: "io.github.godspeed-you.kubernetes.cluster/1",
        schema_name: "KubernetesCluster",
        schema_summary: "One provider instance: which cluster it reaches, whether it answers, \
                         and who it is to it.",
        summary: "Which cluster this is, whether it can be reached, and who you are to it.",
        identity_doc: "Two observations are the same provider instance when their `uid` — \
                       `kubernetes:<context>` — matches. Two instances that reach one cluster \
                       share a fingerprint and are never one instance (specification section \
                       10.3).",
        reads: Reads::Instance,
        fields: CLUSTER_FIELDS,
    },
];

/// The target of that name, where this package answers for one.
#[must_use]
pub fn target(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|target| target.name == name)
}

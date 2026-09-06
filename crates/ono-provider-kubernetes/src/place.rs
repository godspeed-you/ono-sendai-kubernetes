//! Kubernetes as places in Ono's world: addresses you can enter, a spatial parent, the neighbours
//! that matter operationally, and named relations to walk along.
//!
//! Specification §9 (scope model), §35 (spatial mapping) and §36 (semantic roles). Everything here
//! is pure: nothing in this module reads a cluster, and nothing here decides *what* is near — it
//! decides how what a caller has already observed is addressed and ordered.
//!
//! **This contributes places, not a mode** (§35.1). A place URI is an absolute, instance-qualified
//! address that Ono's existing spatial verbs consume; the vocabulary this module adds is a set of
//! relationship *names* for `follow`, and it deliberately refuses imperative words. `k8s> get pods`
//! cannot grow out of a grammar that has no verbs in it.
//!
//! **Beside [`Locator`](crate::object::Locator), not on top of it.** A locator already renders
//! `provider_instance/group/version/Kind/namespace/name`, and it is the right shape for what it is
//! for: human lookup of one object by its type. It is the wrong shape for a place, for three
//! reasons that would each have to be worked around. Its type component expands to three
//! slash-separated fields, so a reader cannot tell where the type ends and the namespace begins.
//! Its namespace is positional and optional, so `.../Node/worker-03` and `.../shop/checkout` are
//! the same grammar — which is exactly the confusion §9.2 forbids, where a cluster-scoped resource
//! acquires a namespace. And it renders only: there is no parser, and §35.3 requires an address
//! that survives a round trip. So a [`PlaceUri`] is built here with its own grammar, in which
//! cluster scope and namespace scope are two different shapes, and a locator stays what it is.
//!
//! **A place binds a lifetime, not just a name** (§35.4). Where the object behind a place has been
//! read, the place carries its [`Identity`] — so two Pods that occupied one address in sequence are
//! two places, and the recreate discontinuity of §16.3 is visible spatially as well as temporally.
//!
//! **Semantic roles are overlays** (§36.1). A [`SemanticRole`] is added next to the native GVK and
//! never in place of it: the address names the Kubernetes type, the role is a second index for
//! cross-provider discovery. §36.3's warning applies inside Kubernetes too — a Pod and a Deployment
//! are both `workload` and are not interchangeable.

use std::fmt;

use crate::discovery::{Gvk, Scope};
use crate::object::{Identity, Object};
use crate::relationship::{Edge, Evidence, Relation, Target};

/// The URI scheme every place of this provider uses.
pub const SCHEME: &str = "k8s";

/// The prefix a provider instance identifier carries (§6.2).
///
/// It is redundant inside a `k8s://` URI — the scheme already said which provider — so the
/// authority carries the context alone, exactly as §35.2's `k8s://prod/` shows, and parsing puts
/// the prefix back.
const INSTANCE_PREFIX: &str = "kubernetes:";

/// What stopped a place from being formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaceError {
    /// A component of the address was empty, and an empty component is not an address.
    EmptyComponent {
        /// Which component: `instance`, `namespace`, `name` or `type`.
        component: &'static str,
    },
    /// The text does not follow the place grammar.
    Malformed {
        /// The text as given.
        text: String,
        /// What about it did not fit.
        reason: &'static str,
    },
    /// Discovery's scope for the kind and the object's own metadata disagree (§9.2).
    ScopeConflict {
        /// The kind the conflict concerns.
        kind: String,
        /// What discovery says the kind's scope is.
        scope: Scope,
        /// The namespace the object carried, where it carried one.
        namespace: Option<String>,
    },
}

impl fmt::Display for PlaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyComponent { component } => {
                write!(f, "a place needs a {component}, and this one is empty")
            }
            Self::Malformed { text, reason } => {
                write!(f, "`{text}` is not a place URI: {reason}")
            }
            Self::ScopeConflict {
                kind,
                scope: Scope::Cluster,
                namespace,
            } => write!(
                f,
                "{kind} is cluster-scoped, so it has no namespace, but this object carries `{}`. \
                 A cluster-scoped resource is never given a namespace (§9.2)",
                namespace.as_deref().unwrap_or("")
            ),
            Self::ScopeConflict {
                kind,
                scope: Scope::Namespaced,
                ..
            } => write!(
                f,
                "{kind} is namespaced, and this object carries no `metadata.namespace`, so it \
                 cannot be addressed at cluster scope (§9.2)"
            ),
        }
    }
}

impl std::error::Error for PlaceError {}

/// Which of the four place shapes an address has.
///
/// Four shapes rather than one shape with optional parts, because §9.2 turns on the difference
/// between "has no namespace" and "has an empty namespace slot".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlaceShape {
    /// The cluster root of one provider instance: `k8s://prod/` (§35.2).
    Cluster,
    /// A namespace: `k8s://prod/ns/production/` (§35.3).
    Namespace,
    /// A namespaced resource: `k8s://prod/ns/production/pod/checkout-7c9d` (§35.4).
    NamespacedResource,
    /// A cluster-scoped resource: `k8s://prod/cluster/node/worker-03` (§35.4).
    ClusterResource,
}

/// The URI segment that names a resource's type.
///
/// The lower-cased kind — `pod`, `node` — as §35.4's examples spell it, with the API group
/// appended whenever there is one: `deployment.apps`, `widget.acme.example.com`. That is
/// `kubectl`'s own disambiguation form, and it is applied unconditionally rather than only on a
/// collision, because §13.5 makes uniqueness a property of *this cluster's* discovery. An address
/// whose shape depended on which CRDs happened to be installed would not be the stable identity
/// §35.3 requires — installing an unrelated operator would silently rewrite it.
///
/// The version is deliberately absent. It is representation, not identity (§16.1), and a place
/// whose address changed when a group's preferred version rolled over would not be stable either.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeSegment {
    kind: String,
    group: String,
}

impl TypeSegment {
    /// The segment for a type.
    #[must_use]
    pub fn of(gvk: &Gvk) -> Self {
        Self {
            kind: gvk.kind().to_lowercase(),
            group: gvk.group().to_owned(),
        }
    }

    /// Reads a segment back.
    ///
    /// # Errors
    ///
    /// [`PlaceError::EmptyComponent`] when the segment, or the kind part of it, is empty.
    pub fn parse(segment: &str) -> Result<Self, PlaceError> {
        let (kind, group) = segment.split_once('.').unwrap_or((segment, ""));
        if kind.is_empty() {
            return Err(PlaceError::EmptyComponent { component: "type" });
        }
        Ok(Self {
            kind: kind.to_lowercase(),
            group: group.to_owned(),
        })
    }

    /// The kind, lower-cased as the address spells it.
    ///
    /// Not the canonical `Kind`: case is not recoverable from an address, and recovering the
    /// canonical spelling is discovery's job (§13.2). A place built from an object keeps the full
    /// [`Gvk`] alongside for exactly that reason.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The API group, empty for the core group.
    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }

    /// Whether this segment addresses that type.
    #[must_use]
    pub fn matches(&self, gvk: &Gvk) -> bool {
        self.kind.eq_ignore_ascii_case(gvk.kind()) && self.group == gvk.group()
    }
}

impl fmt::Display for TypeSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.group.is_empty() {
            write!(f, "{}", self.kind)
        } else {
            write!(f, "{}.{}", self.kind, self.group)
        }
    }
}

/// The address of a place: stable, absolute and machine-parseable (§35.3).
///
/// The instance is part of the address rather than ambient session state, which is what makes
/// `k8s://prod/ns/shop/pod/api` and `k8s://dev/ns/shop/pod/api` two different places even though
/// every other component matches (Gate J, §62.10).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlaceUri {
    instance: String,
    namespace: Option<String>,
    resource: Option<(TypeSegment, String)>,
}

impl PlaceUri {
    /// The root place of one provider instance (§9.1, §35.2).
    ///
    /// # Errors
    ///
    /// [`PlaceError::EmptyComponent`] when the instance names no context.
    pub fn cluster_root(instance: &str) -> Result<Self, PlaceError> {
        Ok(Self {
            instance: normalise_instance(instance)?,
            namespace: None,
            resource: None,
        })
    }

    /// A namespace place (§35.3).
    ///
    /// # Errors
    ///
    /// [`PlaceError::EmptyComponent`] when the instance or the namespace is empty.
    pub fn of_namespace(instance: &str, namespace: &str) -> Result<Self, PlaceError> {
        Ok(Self {
            instance: normalise_instance(instance)?,
            namespace: Some(non_empty(namespace, "namespace")?),
            resource: None,
        })
    }

    /// A namespaced resource place (§35.4).
    ///
    /// # Errors
    ///
    /// [`PlaceError::EmptyComponent`] when any component is empty.
    pub fn namespaced(
        instance: &str,
        namespace: &str,
        type_segment: TypeSegment,
        name: &str,
    ) -> Result<Self, PlaceError> {
        Ok(Self {
            instance: normalise_instance(instance)?,
            namespace: Some(non_empty(namespace, "namespace")?),
            resource: Some((type_segment, non_empty(name, "name")?)),
        })
    }

    /// A cluster-scoped resource place (§35.4).
    ///
    /// Structurally unable to carry a namespace, which is how §9.2 is enforced rather than
    /// remembered.
    ///
    /// # Errors
    ///
    /// [`PlaceError::EmptyComponent`] when the instance or the name is empty.
    pub fn cluster_scoped(
        instance: &str,
        type_segment: TypeSegment,
        name: &str,
    ) -> Result<Self, PlaceError> {
        Ok(Self {
            instance: normalise_instance(instance)?,
            namespace: None,
            resource: Some((type_segment, non_empty(name, "name")?)),
        })
    }

    /// Reads an address back into a place (§35.3).
    ///
    /// A trailing slash is accepted on every shape and rendered only on the two container shapes,
    /// so an address a user re-types with or without it lands in the same place. Anything else that
    /// does not fit the grammar is rejected rather than guessed: a near-miss silently resolved is
    /// navigation to a cluster nobody asked for.
    ///
    /// # Errors
    ///
    /// [`PlaceError::Malformed`] when the scheme, the segment count or a percent escape does not
    /// fit, and [`PlaceError::EmptyComponent`] when a component is present but empty.
    pub fn parse(text: &str) -> Result<Self, PlaceError> {
        let prefix = format!("{SCHEME}://");
        let rest = text.strip_prefix(&prefix).ok_or(PlaceError::Malformed {
            text: text.to_owned(),
            reason: "a place URI begins with `k8s://`",
        })?;

        let mut segments: Vec<&str> = rest.split('/').collect();
        if segments.last() == Some(&"") {
            segments.pop();
        }
        let mut segments = segments.into_iter();
        let authority = segments.next().unwrap_or_default();
        let instance = normalise_instance(&decode(authority, text)?)?;
        let tail: Vec<String> = segments
            .map(|segment| decode(segment, text))
            .collect::<Result<_, _>>()?;

        let shape = tail.iter().map(String::as_str).collect::<Vec<_>>();
        match shape.as_slice() {
            [] => Ok(Self {
                instance,
                namespace: None,
                resource: None,
            }),
            ["ns", namespace] => Ok(Self {
                instance,
                namespace: Some(non_empty(namespace, "namespace")?),
                resource: None,
            }),
            ["ns", namespace, type_segment, name] => Ok(Self {
                instance,
                namespace: Some(non_empty(namespace, "namespace")?),
                resource: Some((TypeSegment::parse(type_segment)?, non_empty(name, "name")?)),
            }),
            ["cluster", type_segment, name] => Ok(Self {
                instance,
                namespace: None,
                resource: Some((TypeSegment::parse(type_segment)?, non_empty(name, "name")?)),
            }),
            _ => Err(PlaceError::Malformed {
                text: text.to_owned(),
                reason: "the path is `/`, `/ns/<namespace>/`, `/ns/<namespace>/<type>/<name>` or \
                         `/cluster/<type>/<name>`",
            }),
        }
    }

    /// The provider instance this place belongs to, as `kubernetes:<context>` (§6.2).
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// The kubeconfig context alone — what the URI authority carries.
    #[must_use]
    pub fn context(&self) -> &str {
        self.instance
            .strip_prefix(INSTANCE_PREFIX)
            .unwrap_or(&self.instance)
    }

    /// The namespace, absent for the cluster root and for cluster-scoped resources (§9.2).
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The type segment, absent for the two container shapes.
    #[must_use]
    pub fn type_segment(&self) -> Option<&TypeSegment> {
        self.resource.as_ref().map(|(segment, _)| segment)
    }

    /// The resource name, absent for the two container shapes.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.resource.as_ref().map(|(_, name)| name.as_str())
    }

    /// Which shape this address has.
    #[must_use]
    pub fn shape(&self) -> PlaceShape {
        match (&self.namespace, &self.resource) {
            (None, None) => PlaceShape::Cluster,
            (Some(_), None) => PlaceShape::Namespace,
            (Some(_), Some(_)) => PlaceShape::NamespacedResource,
            (None, Some(_)) => PlaceShape::ClusterResource,
        }
    }

    /// The address one step up, spatially (§35.6). [`None`] at the cluster root.
    #[must_use]
    fn parent(&self) -> Option<Self> {
        match self.shape() {
            PlaceShape::Cluster => None,
            PlaceShape::Namespace | PlaceShape::ClusterResource => Some(Self {
                instance: self.instance.clone(),
                namespace: None,
                resource: None,
            }),
            PlaceShape::NamespacedResource => Some(Self {
                instance: self.instance.clone(),
                namespace: self.namespace.clone(),
                resource: None,
            }),
        }
    }
}

impl fmt::Display for PlaceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}://{}", encode(self.context()))?;
        match (&self.namespace, &self.resource) {
            (None, None) => write!(f, "/"),
            (Some(namespace), None) => write!(f, "/ns/{}/", encode(namespace)),
            (Some(namespace), Some((segment, name))) => {
                write!(f, "/ns/{}/{segment}/{}", encode(namespace), encode(name))
            }
            (None, Some((segment, name))) => write!(f, "/cluster/{segment}/{}", encode(name)),
        }
    }
}

/// A place: an address, the native type behind it, the lifetime it holds, and its role overlays.
///
/// Equality is the whole of that, not the address alone. Two Pods that occupied one address in
/// sequence are two places, which is how §16.3's recreate discontinuity stays visible to anything
/// navigating; [`Place::is_same_address`] is there for the question "is this the same spot".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    uri: PlaceUri,
    gvk: Option<Gvk>,
    identity: Option<Identity>,
    roles: &'static [SemanticRole],
}

impl Place {
    /// A place known only by its address — parsed from text, or named before anything was read.
    #[must_use]
    pub fn at(uri: PlaceUri) -> Self {
        Self {
            uri,
            gvk: None,
            identity: None,
            roles: &[],
        }
    }

    /// The place of an object that has been read, binding its lifetime identity (§35.4).
    ///
    /// Scope comes from `metadata.namespace`, which is what the object itself says. Where the
    /// caller knows what discovery says — and discovery is the authority (§11.1) — use
    /// [`Self::of_object_with_scope`], which reports the disagreement instead of resolving it.
    ///
    /// A Namespace object becomes the namespace place of §35.3 rather than a second address of the
    /// form `/cluster/namespace/<name>`. One thing with two addresses is not stable identity, and
    /// §35.3 names this address for it.
    ///
    /// # Errors
    ///
    /// [`PlaceError::EmptyComponent`] when the object's name or namespace is empty.
    pub fn of_object(object: &Object) -> Result<Self, PlaceError> {
        Self::of_identity(&object.identity())
    }

    /// The place of an identity, for an object read at the far end of an edge (§35.4).
    ///
    /// An identity carries everything an address needs — instance, kind, namespace, name — so a
    /// neighbour that reaches *in* to a place is addressable from the edge alone. That is the
    /// same address [`Self::of_object`] produces, and it is produced here so the two cannot
    /// drift apart.
    ///
    /// # Errors
    ///
    /// [`PlaceError::EmptyComponent`] when the identity's name or namespace is empty.
    pub fn of_identity(identity: &Identity) -> Result<Self, PlaceError> {
        let gvk = identity.gvk().clone();
        let uri = if is_namespace_kind(&gvk) && identity.namespace().is_none() {
            PlaceUri::of_namespace(identity.provider_instance(), identity.name())?
        } else if let Some(namespace) = identity.namespace() {
            PlaceUri::namespaced(
                identity.provider_instance(),
                namespace,
                TypeSegment::of(&gvk),
                identity.name(),
            )?
        } else {
            PlaceUri::cluster_scoped(
                identity.provider_instance(),
                TypeSegment::of(&gvk),
                identity.name(),
            )?
        };
        Ok(Self {
            uri,
            roles: roles_of(&gvk),
            gvk: Some(gvk),
            identity: Some(identity.clone()),
        })
    }

    /// The place of an object whose scope discovery has stated.
    ///
    /// # Errors
    ///
    /// [`PlaceError::ScopeConflict`] when the kind's scope and the object's metadata disagree — a
    /// cluster-scoped object carrying a namespace, or a namespaced one carrying none. Neither is
    /// resolved by preferring one source: a fabricated namespace is exactly what §9.2 forbids, and
    /// a namespaced object addressed at cluster scope would collide with every namesake in every
    /// other namespace.
    pub fn of_object_with_scope(object: &Object, scope: Scope) -> Result<Self, PlaceError> {
        match (scope, object.namespace()) {
            (Scope::Cluster, Some(namespace)) => Err(PlaceError::ScopeConflict {
                kind: object.gvk().kind().to_owned(),
                scope,
                namespace: Some(namespace.to_owned()),
            }),
            (Scope::Namespaced, None) => Err(PlaceError::ScopeConflict {
                kind: object.gvk().kind().to_owned(),
                scope,
                namespace: None,
            }),
            _ => Self::of_object(object),
        }
    }

    /// The place an edge points at.
    ///
    /// The instance is the source's: relationships do not cross clusters (§9.6), so an edge's far
    /// end is in the same provider instance as its near end, and taking it from the source is what
    /// keeps Gate J true for a target that carries no instance of its own.
    ///
    /// The target's namespace decides the shape, so a Pod's `scheduled-on` Node stays cluster-
    /// scoped even though the Pod is not. The lifetime identity is bound only where something
    /// actually resolved the target: an unresolved edge is a relationship whose far end nobody has
    /// read, and inventing an identity for it would be a claim the provider cannot make (§24.1).
    ///
    /// # Errors
    ///
    /// [`PlaceError::EmptyComponent`] when the target names no resource.
    pub fn of_target(instance: &str, target: &Target) -> Result<Self, PlaceError> {
        let (group, version) = target.api_version().map_or(("", ""), |api_version| {
            api_version.split_once('/').unwrap_or(("", api_version))
        });
        let gvk = Gvk::new(group, version, target.kind());
        let uri = match target.namespace() {
            Some(namespace) => {
                PlaceUri::namespaced(instance, namespace, TypeSegment::of(&gvk), target.name())?
            }
            None => PlaceUri::cluster_scoped(instance, TypeSegment::of(&gvk), target.name())?,
        };
        Ok(Self {
            uri,
            roles: roles_of(&gvk),
            gvk: Some(gvk),
            identity: target.identity().cloned(),
        })
    }

    /// The address.
    #[must_use]
    pub fn uri(&self) -> &PlaceUri {
        &self.uri
    }

    /// The native Kubernetes type, where the place was formed from something that stated one.
    ///
    /// Always available next to [`Self::roles`]: the role is the overlay, this is the truth
    /// underneath it (§36.1).
    #[must_use]
    pub fn gvk(&self) -> Option<&Gvk> {
        self.gvk.as_ref()
    }

    /// The lifetime identity of whatever occupies the place, where it has been read (§35.4).
    #[must_use]
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Whether this place is pinned to one resource lifetime rather than only to a name.
    ///
    /// False for an address alone, and false for an object the server gave no UID (§16.5) — in
    /// both cases the place follows the name, and a caller that assumed otherwise would merge a
    /// recreated resource into its predecessor.
    #[must_use]
    pub fn is_lifetime_bound(&self) -> bool {
        self.identity
            .as_ref()
            .is_some_and(Identity::is_lifetime_stable)
    }

    /// The resource name, absent for the cluster root and for a namespace place.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.uri.name()
    }

    /// The generic roles this place also answers to (§36.2). Empty for a kind with no mapping.
    #[must_use]
    pub fn roles(&self) -> &[SemanticRole] {
        self.roles
    }

    /// Whether the place carries a role.
    #[must_use]
    pub fn has_role(&self, role: SemanticRole) -> bool {
        self.roles.contains(&role)
    }

    /// The place one step up, spatially (§35.6).
    ///
    /// The namespace above a namespaced resource, the cluster root above a namespace or a
    /// cluster-scoped resource, and nothing above the cluster root — above that, the host's world
    /// continues, and a provider that invented a root of its own would be the beginning of the
    /// separate `k8s>` world §35.1 forbids.
    ///
    /// Explicitly not the owner. A Pod's Deployment owns it through a ReplicaSet; that is
    /// `follow owned-by`, and routing `up` through it would make `up` land somewhere different
    /// depending on which controller happened to create the object.
    #[must_use]
    pub fn up(&self) -> Option<Self> {
        self.uri.parent().map(Self::at)
    }

    /// Whether two places are the same spot, regardless of who occupies it.
    #[must_use]
    pub fn is_same_address(&self, other: &Self) -> bool {
        self.uri == other.uri
    }
}

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uri)
    }
}

/// A generic role a Kubernetes kind also answers to, for cross-provider discovery (§36.2).
///
/// An overlay, never a replacement: the native kind stays canonical (§36.1) and stays in the
/// address. Two kinds sharing a role are not equivalent — §36.3's Deployment and Auto Scaling
/// Group, and, closer to home, a Pod and a Deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SemanticRole {
    /// Something that runs containers, or manages something that does.
    Workload,
    /// A machine that runs workloads.
    ComputeNode,
    /// A stable network identity traffic is addressed to.
    NetworkEndpoint,
    /// The concrete backends behind a network endpoint.
    ServiceEndpoint,
    /// Non-secret configuration data.
    Configuration,
    /// Secret material, which stays redacted wherever it appears (§22).
    Secret,
    /// A principal, or a grant to one.
    Identity,
    /// Persistent storage, or a claim on it.
    Storage,
    /// A constraint on what is allowed.
    Policy,
}

impl SemanticRole {
    /// The role's generic name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::ComputeNode => "compute-node",
            Self::NetworkEndpoint => "network-endpoint",
            Self::ServiceEndpoint => "service-endpoint",
            Self::Configuration => "configuration",
            Self::Secret => "secret",
            Self::Identity => "identity",
            Self::Storage => "storage",
            Self::Policy => "policy",
        }
    }
}

impl fmt::Display for SemanticRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The role overlay, as data (§36.2): group, kind, and the roles that kind also answers to.
///
/// A table rather than a rule, because there is no rule — the mapping is a curated judgement about
/// each kind, and a heuristic over names would be the guessing §36.3 warns against. A kind absent
/// from the table has no role: a wrong overlay is worse than none, since a cross-provider query
/// would then act on it.
const ROLE_OVERLAY: &[(&str, &str, &[SemanticRole])] = &[
    ("", "Pod", &[SemanticRole::Workload]),
    ("apps", "Deployment", &[SemanticRole::Workload]),
    ("apps", "ReplicaSet", &[SemanticRole::Workload]),
    ("apps", "StatefulSet", &[SemanticRole::Workload]),
    ("apps", "DaemonSet", &[SemanticRole::Workload]),
    ("batch", "Job", &[SemanticRole::Workload]),
    ("batch", "CronJob", &[SemanticRole::Workload]),
    ("", "Node", &[SemanticRole::ComputeNode]),
    ("", "Service", &[SemanticRole::NetworkEndpoint]),
    (
        "networking.k8s.io",
        "Ingress",
        &[SemanticRole::NetworkEndpoint],
    ),
    (
        "gateway.networking.k8s.io",
        "Gateway",
        &[SemanticRole::NetworkEndpoint],
    ),
    (
        "gateway.networking.k8s.io",
        "HTTPRoute",
        &[SemanticRole::NetworkEndpoint],
    ),
    ("", "Endpoints", &[SemanticRole::ServiceEndpoint]),
    (
        "discovery.k8s.io",
        "EndpointSlice",
        &[SemanticRole::ServiceEndpoint],
    ),
    ("", "ConfigMap", &[SemanticRole::Configuration]),
    ("", "Secret", &[SemanticRole::Secret]),
    ("", "ServiceAccount", &[SemanticRole::Identity]),
    (
        "rbac.authorization.k8s.io",
        "Role",
        &[SemanticRole::Identity],
    ),
    (
        "rbac.authorization.k8s.io",
        "ClusterRole",
        &[SemanticRole::Identity],
    ),
    (
        "rbac.authorization.k8s.io",
        "RoleBinding",
        &[SemanticRole::Identity],
    ),
    (
        "rbac.authorization.k8s.io",
        "ClusterRoleBinding",
        &[SemanticRole::Identity],
    ),
    ("", "PersistentVolumeClaim", &[SemanticRole::Storage]),
    ("", "PersistentVolume", &[SemanticRole::Storage]),
    ("storage.k8s.io", "StorageClass", &[SemanticRole::Storage]),
    (
        "networking.k8s.io",
        "NetworkPolicy",
        &[SemanticRole::Policy],
    ),
    ("policy", "PodDisruptionBudget", &[SemanticRole::Policy]),
    ("", "ResourceQuota", &[SemanticRole::Policy]),
    ("", "LimitRange", &[SemanticRole::Policy]),
];

/// The roles a type answers to, empty for a kind this provider has no judgement about.
///
/// Group and kind must both match. A `Widget` served by `acme.example.com` is not the `Widget` of
/// some other group, and matching on kind alone is how an unrelated custom resource inherits an
/// overlay that was never meant for it (§13.5).
#[must_use]
pub fn roles_of(gvk: &Gvk) -> &'static [SemanticRole] {
    ROLE_OVERLAY
        .iter()
        .find(|(group, kind, _)| *group == gvk.group() && *kind == gvk.kind())
        .map_or(&[], |(_, _, roles)| *roles)
}

/// A named relationship you can walk along with `follow` (§35.7).
///
/// The five words §35.7 spells out are all here, plus the ones this provider's relationship model
/// produces. That second half is the rule rather than an accident: a [`Relation`] this provider
/// can extract and a user cannot name is a relationship they have to already know about, so every
/// relation has a word here and [`Self::from_relation`] is total.
///
/// Every word is a *relationship*: there is no `get`, no `describe`, no `logs`. A traversal
/// vocabulary that accepted verbs would be the `k8s>` sub-shell of §35.1 arriving one word at a
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Waypoint {
    /// The object is owned by the neighbour (§24.1).
    OwnedBy,
    /// The neighbour is the controlling owner (§24.3).
    ControlledBy,
    /// The neighbour is owned by this object — `owned-by` from the owner's end (§25.1).
    Owns,
    /// The neighbour is controlled by this object (§24.3).
    Controls,
    /// A Pod is placed on a Node (§28.1).
    ScheduledOn,
    /// A selector of this object matches the neighbour's labels (§26.1).
    Selects,
    /// A workload controller's selector fits the neighbour without owning it (§23.3).
    SelectorMatches,
    /// The neighbour routes traffic here — Ingress, Gateway, HTTPRoute (§27).
    RoutesTo,
    /// A route attaches to a Gateway (§27.3).
    AttachesTo,
    /// A claim and what satisfies it (§30.2).
    BoundTo,
    /// The class a claim or a volume names (§30.1, §30.3).
    UsesStorageClass,
    /// The endpoint objects that carry this endpoint's addresses (§26.2).
    ///
    /// The navigation word for [`Relation::RepresentedBy`]: §35.5 names the EndpointSlices of a
    /// Service as something to walk to, §26.2 names the edge that gets there, and one edge with
    /// two followable words would split the vocabulary for no gain.
    HasEndpoints,
    /// What stands behind one endpoint of a slice (§26.2).
    EndpointFor,
    /// The governing Service of a StatefulSet (§25.3).
    UsesService,
    /// The Secret a route terminates TLS with (§27.1).
    UsesTlsSecret,
    /// The IngressClass that handles an Ingress (§27.2).
    UsesIngressClass,
    /// The GatewayClass that implements a Gateway (§27.3).
    UsesGatewayClass,
    /// A Pod runs under a ServiceAccount (§32.1).
    RunsAs,
    /// A Pod mounts a claim (§30.1).
    Mounts,
    /// A reference to configuration data (§29.1).
    ReferencesConfig,
    /// A reference to secret material (§29.2).
    ReferencesSecret,
    /// A Secret a ServiceAccount carries (§22.4).
    UsesSecret,
    /// A Secret images are pulled with (§22.4, §32.1).
    UsesImagePullSecret,
    /// A policy that applies here (§31.1).
    ConstrainedBy,
    /// Nothing more than living in the same namespace.
    ///
    /// Not a relationship, and named so that it cannot be mistaken for one: §35.5 exists precisely
    /// to keep arbitrary namespace co-tenants out of the front of `near`.
    SharesNamespace,
}

impl Waypoint {
    /// Every waypoint, so callers and tests can enumerate the vocabulary.
    pub const ALL: &'static [Self] = &[
        Self::OwnedBy,
        Self::ControlledBy,
        Self::Owns,
        Self::Controls,
        Self::ScheduledOn,
        Self::Selects,
        Self::SelectorMatches,
        Self::RoutesTo,
        Self::AttachesTo,
        Self::BoundTo,
        Self::UsesStorageClass,
        Self::HasEndpoints,
        Self::EndpointFor,
        Self::UsesService,
        Self::UsesTlsSecret,
        Self::UsesIngressClass,
        Self::UsesGatewayClass,
        Self::RunsAs,
        Self::Mounts,
        Self::ReferencesConfig,
        Self::ReferencesSecret,
        Self::UsesSecret,
        Self::UsesImagePullSecret,
        Self::ConstrainedBy,
        Self::SharesNamespace,
    ];

    /// The word a user types after `follow`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnedBy => "owned-by",
            Self::ControlledBy => "controlled-by",
            Self::Owns => "owns",
            Self::Controls => "controls",
            Self::ScheduledOn => "scheduled-on",
            Self::Selects => "selects",
            Self::SelectorMatches => "selector-matches",
            Self::RoutesTo => "routes-to",
            Self::AttachesTo => "attaches-to",
            Self::BoundTo => "bound-to",
            Self::UsesStorageClass => "uses-storage-class",
            Self::HasEndpoints => "has-endpoints",
            Self::EndpointFor => "endpoint-for",
            Self::UsesService => "uses-service",
            Self::UsesTlsSecret => "uses-tls-secret",
            Self::UsesIngressClass => "uses-ingress-class",
            Self::UsesGatewayClass => "uses-gateway-class",
            Self::RunsAs => "runs-as",
            Self::Mounts => "mounts",
            Self::ReferencesConfig => "references-config",
            Self::ReferencesSecret => "references-secret",
            Self::UsesSecret => "uses-secret",
            Self::UsesImagePullSecret => "uses-image-pull-secret",
            Self::ConstrainedBy => "constrained-by",
            Self::SharesNamespace => "shares-namespace",
        }
    }

    /// Reads a word, or [`None`] when it names no relationship this provider knows.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|waypoint| waypoint.as_str() == word)
    }

    /// The waypoint an extracted relationship travels along.
    ///
    /// Total, and that is the point: every relationship this provider can extract is one a user
    /// can name. A relation with no word would arrive in `near` and be unfollowable.
    #[must_use]
    pub fn from_relation(relation: Relation) -> Self {
        match relation {
            Relation::OwnedBy => Self::OwnedBy,
            Relation::ControlledBy => Self::ControlledBy,
            Relation::Owns => Self::Owns,
            Relation::Controls => Self::Controls,
            Relation::ScheduledOn => Self::ScheduledOn,
            Relation::Selects => Self::Selects,
            Relation::SelectorMatches => Self::SelectorMatches,
            Relation::RoutesTo => Self::RoutesTo,
            Relation::AttachesTo => Self::AttachesTo,
            Relation::BoundTo => Self::BoundTo,
            Relation::UsesStorageClass => Self::UsesStorageClass,
            Relation::RepresentedBy => Self::HasEndpoints,
            Relation::EndpointFor => Self::EndpointFor,
            Relation::UsesService => Self::UsesService,
            Relation::UsesTlsSecret => Self::UsesTlsSecret,
            Relation::UsesIngressClass => Self::UsesIngressClass,
            Relation::UsesGatewayClass => Self::UsesGatewayClass,
            Relation::RunsAs => Self::RunsAs,
            Relation::Mounts => Self::Mounts,
            Relation::ReferencesConfig => Self::ReferencesConfig,
            Relation::ReferencesSecret => Self::ReferencesSecret,
            Relation::UsesSecret => Self::UsesSecret,
            Relation::UsesImagePullSecret => Self::UsesImagePullSecret,
        }
    }

    /// The extracted relationship this waypoint corresponds to, where there is one.
    ///
    /// [`None`] for `constrained-by`: §35.5 names policies as something a user navigates to, and
    /// the relationship model derives a NetworkPolicy's reach as `selects` (§31.1) rather than as
    /// a word of its own. A caller that has read the policy supplies such a neighbour explicitly
    /// with [`Neighbourhood::with`] and its evidence, so the gap is visible rather than silently
    /// rendered as "no neighbours". [`None`] for `shares-namespace` because co-location is not a
    /// relationship at all.
    #[must_use]
    pub fn relation(self) -> Option<Relation> {
        match self {
            Self::OwnedBy => Some(Relation::OwnedBy),
            Self::ControlledBy => Some(Relation::ControlledBy),
            Self::Owns => Some(Relation::Owns),
            Self::Controls => Some(Relation::Controls),
            Self::ScheduledOn => Some(Relation::ScheduledOn),
            Self::Selects => Some(Relation::Selects),
            Self::SelectorMatches => Some(Relation::SelectorMatches),
            Self::RoutesTo => Some(Relation::RoutesTo),
            Self::AttachesTo => Some(Relation::AttachesTo),
            Self::BoundTo => Some(Relation::BoundTo),
            Self::UsesStorageClass => Some(Relation::UsesStorageClass),
            Self::HasEndpoints => Some(Relation::RepresentedBy),
            Self::EndpointFor => Some(Relation::EndpointFor),
            Self::UsesService => Some(Relation::UsesService),
            Self::UsesTlsSecret => Some(Relation::UsesTlsSecret),
            Self::UsesIngressClass => Some(Relation::UsesIngressClass),
            Self::UsesGatewayClass => Some(Relation::UsesGatewayClass),
            Self::RunsAs => Some(Relation::RunsAs),
            Self::Mounts => Some(Relation::Mounts),
            Self::ReferencesConfig => Some(Relation::ReferencesConfig),
            Self::ReferencesSecret => Some(Relation::ReferencesSecret),
            Self::UsesSecret => Some(Relation::UsesSecret),
            Self::UsesImagePullSecret => Some(Relation::UsesImagePullSecret),
            Self::ConstrainedBy | Self::SharesNamespace => None,
        }
    }

    /// How near this waypoint's neighbours count as, from the `PROXIMITY` table.
    #[must_use]
    pub fn proximity(self) -> Proximity {
        PROXIMITY
            .iter()
            .find(|(waypoint, _)| *waypoint == self)
            .map_or(Proximity::Ambient, |(_, proximity)| *proximity)
    }
}

impl fmt::Display for Waypoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How operationally near a neighbour is, nearest first.
///
/// The declaration order *is* the ranking — [`Ord`] is derived from it — and the first four
/// classes are §35.5's list for a Service, in the order the specification gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proximity {
    /// What this object selects, or what selects it: the Pods behind a Service.
    Selected,
    /// The endpoint objects that carry the addresses.
    Endpoint,
    /// What routes traffic here.
    Route,
    /// What constrains traffic here.
    Policy,
    /// Where it is running.
    Placement,
    /// What owns it, or what it owns.
    Lineage,
    /// What it needs to run: configuration, secrets, storage, identity.
    Dependency,
    /// Nothing but a shared namespace.
    Ambient,
}

/// The `near` prioritisation, as data (§35.5).
///
/// A table so that adding a relationship is a decision about *where it ranks*, made in one visible
/// place, rather than a new arm in a sort function. Anything missing from the table falls to
/// [`Proximity::Ambient`], which is the safe direction: an unranked relationship appears at the
/// end of `near` instead of displacing something the specification named.
const PROXIMITY: &[(Waypoint, Proximity)] = &[
    (Waypoint::Selects, Proximity::Selected),
    (Waypoint::SelectorMatches, Proximity::Selected),
    (Waypoint::EndpointFor, Proximity::Selected),
    (Waypoint::HasEndpoints, Proximity::Endpoint),
    (Waypoint::RoutesTo, Proximity::Route),
    (Waypoint::AttachesTo, Proximity::Route),
    (Waypoint::ConstrainedBy, Proximity::Policy),
    (Waypoint::ScheduledOn, Proximity::Placement),
    (Waypoint::ControlledBy, Proximity::Lineage),
    (Waypoint::OwnedBy, Proximity::Lineage),
    (Waypoint::Controls, Proximity::Lineage),
    (Waypoint::Owns, Proximity::Lineage),
    (Waypoint::BoundTo, Proximity::Dependency),
    (Waypoint::UsesStorageClass, Proximity::Dependency),
    (Waypoint::Mounts, Proximity::Dependency),
    (Waypoint::ReferencesConfig, Proximity::Dependency),
    (Waypoint::ReferencesSecret, Proximity::Dependency),
    (Waypoint::RunsAs, Proximity::Dependency),
    (Waypoint::UsesSecret, Proximity::Dependency),
    (Waypoint::UsesImagePullSecret, Proximity::Dependency),
    (Waypoint::UsesService, Proximity::Dependency),
    (Waypoint::UsesTlsSecret, Proximity::Dependency),
    // The class an Ingress or Gateway names is what implements it, so it ranks with the other
    // things the object needs to work rather than with the traffic arriving at it.
    (Waypoint::UsesIngressClass, Proximity::Dependency),
    (Waypoint::UsesGatewayClass, Proximity::Dependency),
    (Waypoint::SharesNamespace, Proximity::Ambient),
];

/// One neighbour of a place, and why it counts as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    place: Place,
    via: Waypoint,
    evidence: Evidence,
    inbound: bool,
}

impl Neighbour {
    /// Where the neighbour is.
    #[must_use]
    pub fn place(&self) -> &Place {
        &self.place
    }

    /// The relationship that reached it.
    #[must_use]
    pub fn via(&self) -> Waypoint {
        self.via
    }

    /// Which way the relationship runs.
    ///
    /// True where the edge points *at* the focus: the neighbour is the source and this place is
    /// the target. The word is the same either way — a relationship is one fact — but which end
    /// asserts it is not, and a renderer that read `owned-by` off an inbound edge would say the
    /// owner is owned by its own child.
    #[must_use]
    pub fn is_inbound(&self) -> bool {
        self.inbound
    }

    /// What makes the relationship checkable (Gate D).
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// How near it counts as.
    #[must_use]
    pub fn proximity(&self) -> Proximity {
        self.via.proximity()
    }
}

/// What is around a place, and in what order (§35.5).
///
/// A neighbourhood holds only what a caller observed. Nothing here queries, and nothing here
/// enumerates a namespace: §35.5 asks for graph neighbours "rather than arbitrary objects in the
/// same namespace", and a `near` that filled itself from the namespace would answer that question
/// backwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbourhood {
    focus: Place,
    neighbours: Vec<Neighbour>,
}

impl Neighbourhood {
    /// An empty neighbourhood around a place.
    #[must_use]
    pub fn around(focus: Place) -> Self {
        Self {
            focus,
            neighbours: Vec::new(),
        }
    }

    /// Adds the neighbours the focus's edges reach, in either direction.
    ///
    /// An edge leaving the focus contributes its target; an edge arriving at the focus
    /// contributes its source, marked [`Neighbour::is_inbound`] so the direction survives the
    /// trip. Both ends are addressable — a target carries its namespace and a source is an
    /// [`Identity`], which carries one too — and a `near` that reported only outbound edges would
    /// tell a Pod nothing about the Service in front of it.
    ///
    /// An edge with neither end at the focus is skipped rather than adopted, so that passing a
    /// whole graph cannot quietly attribute a stranger's relationships to this place. A focus
    /// that is only an address, with no identity bound, cannot be matched against an edge's
    /// source, so its edges are taken as the caller offered them: outbound.
    #[must_use]
    pub fn reached(mut self, edges: &[Edge]) -> Self {
        for edge in edges {
            let instance = edge.source().provider_instance();
            let outbound = self
                .focus
                .identity()
                .is_none_or(|identity| identity == edge.source());
            if outbound {
                if let Ok(place) = Place::of_target(instance, edge.target()) {
                    self.push(place, edge, false);
                }
                continue;
            }
            let reaches_focus = Place::of_target(instance, edge.target())
                .is_ok_and(|target| target.is_same_address(&self.focus));
            if reaches_focus && let Ok(place) = Place::of_identity(edge.source()) {
                self.push(place, edge, true);
            }
        }
        self
    }

    /// Records one end of an edge as a neighbour.
    fn push(&mut self, place: Place, edge: &Edge, inbound: bool) {
        self.neighbours.push(Neighbour {
            place,
            via: Waypoint::from_relation(edge.relation()),
            evidence: edge.evidence().clone(),
            inbound,
        });
    }

    /// Adds a neighbour the caller established, with the evidence for it.
    ///
    /// The way in for a relationship this provider does not extract from an object — a
    /// NetworkPolicy's `constrained-by` (§31.1), a correlation a cross-system resolver drew — and
    /// for a neighbour whose edge the caller does not have in hand. The evidence is required, so
    /// an added neighbour is as checkable as an extracted one (Gate D). Use
    /// [`Self::with_inbound`] where the relationship points at the focus.
    #[must_use]
    pub fn with(mut self, via: Waypoint, place: Place, evidence: Evidence) -> Self {
        self.neighbours.push(Neighbour {
            place,
            via,
            evidence,
            inbound: false,
        });
        self
    }

    /// Adds a neighbour whose relationship points at the focus rather than away from it.
    ///
    /// The same as [`Self::with`] except for what [`Neighbour::is_inbound`] then reports. A
    /// caller that read the object at the other end knows which way the edge runs, and saying so
    /// is what keeps the relationship word from being rendered backwards.
    #[must_use]
    pub fn with_inbound(mut self, via: Waypoint, place: Place, evidence: Evidence) -> Self {
        self.neighbours.push(Neighbour {
            place,
            via,
            evidence,
            inbound: true,
        });
        self
    }

    /// The place everything here is near.
    #[must_use]
    pub fn focus(&self) -> &Place {
        &self.focus
    }

    /// Every neighbour, in the order it was observed.
    #[must_use]
    pub fn neighbours(&self) -> &[Neighbour] {
        &self.neighbours
    }

    /// The neighbours in priority order (§35.5).
    ///
    /// Three keys, in this order. **Proximity class** first, from the `PROXIMITY` table — this is the
    /// specification's own ordering, and for a Service it produces selected Pods, then
    /// EndpointSlices, then routes, then policies. **Evidence strength** second: within one class,
    /// what the API server states outranks what this provider derived from two observations, so a
    /// selector evaluation never displaces a native field (§23.3). **Address** last, so that the
    /// answer is deterministic instead of depending on the order things were observed in.
    #[must_use]
    pub fn ranked(&self) -> Vec<&Neighbour> {
        let mut ranked: Vec<&Neighbour> = self.neighbours.iter().collect();
        ranked.sort_by_key(|neighbour| {
            (
                neighbour.proximity(),
                !neighbour.evidence.is_asserted_by_provider(),
                neighbour.place.uri().to_string(),
            )
        });
        ranked
    }

    /// Walks one named relationship (§35.7).
    ///
    /// One relationship, not all of them: a `follow` that returned everything would be `near`
    /// under another name, and the point of naming a relation is to say which of a place's several
    /// stories you want.
    ///
    /// # Errors
    ///
    /// [`FollowError::UnknownRelation`] when the word names no relationship. An unknown word is
    /// refused rather than treated as "nothing there", because the two answers would otherwise be
    /// indistinguishable — and a misspelled relation that renders as an empty result reads as
    /// evidence about the cluster.
    pub fn follow(&self, word: &str) -> Result<Vec<&Neighbour>, FollowError> {
        let waypoint = Waypoint::parse(word).ok_or_else(|| FollowError::UnknownRelation {
            word: word.to_owned(),
        })?;
        Ok(self
            .ranked()
            .into_iter()
            .filter(|neighbour| neighbour.via == waypoint)
            .collect())
    }
}

/// Why a `follow` did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowError {
    /// The word names no relationship this provider traverses.
    UnknownRelation {
        /// The word as typed.
        word: String,
    },
}

impl fmt::Display for FollowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::UnknownRelation { word } = self;
        let known: Vec<&str> = Waypoint::ALL.iter().map(|way| way.as_str()).collect();
        write!(
            f,
            "`{word}` is not a relationship this provider traverses. Known relationships: {}",
            known.join(", ")
        )
    }
}

impl std::error::Error for FollowError {}

/// What entering a bare name in a place resolves to (§35.8).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one resolved place per user navigation; boxing it would cost the caller a \
              dereference to save bytes nothing here allocates in bulk"
)]
pub enum NameEntry {
    /// Exactly one resource here carries the name.
    One(Place),
    /// Several types carry it, and the choice belongs to the user (§35.8).
    Ambiguous(Vec<Place>),
    /// Nothing observed here carries it.
    ///
    /// Distinct from ambiguity, and distinct from "not allowed to look" — a denied read is not an
    /// absence (§21.4), and it is the caller's business, not this function's, because nothing here
    /// queries anything.
    None,
}

/// Resolves a bare name typed in a place against what has been observed there (§35.8).
///
/// Where several types share the name, every candidate is reported and none is chosen. There is
/// deliberately no type priority: preferring Deployment over Service, or the alphabetically first,
/// would silently take the user somewhere they did not ask for, and the specification requires the
/// disambiguation to be asked for instead. Candidates come back in address order, which is a
/// stable presentation and not a ranking.
///
/// Scope is the place the name was typed in: the same provider instance (Gate J) and the same
/// namespace (§9.4). A namesake in another context or another namespace is not a candidate, and a
/// flat name index that forgot where each entry came from is how it becomes one.
#[must_use]
pub fn enter_by_name(within: &PlaceUri, name: &str, present: &[Place]) -> NameEntry {
    let mut candidates: Vec<Place> = present
        .iter()
        .filter(|place| {
            place.uri.instance() == within.instance()
                && place.uri.namespace() == within.namespace()
                && place.uri.name() == Some(name)
        })
        .cloned()
        .collect();
    candidates.sort_by_key(|place| place.uri.to_string());

    if candidates.len() > 1 {
        return NameEntry::Ambiguous(candidates);
    }
    candidates.pop().map_or(NameEntry::None, NameEntry::One)
}

/// Whether a type is the core `Namespace` kind, which has a place of its own (§35.3).
fn is_namespace_kind(gvk: &Gvk) -> bool {
    gvk.group().is_empty() && gvk.kind() == "Namespace"
}

/// Normalises a provider instance to `kubernetes:<context>` (§6.2).
fn normalise_instance(instance: &str) -> Result<String, PlaceError> {
    let context = instance.strip_prefix(INSTANCE_PREFIX).unwrap_or(instance);
    if context.is_empty() {
        return Err(PlaceError::EmptyComponent {
            component: "instance",
        });
    }
    Ok(format!("{INSTANCE_PREFIX}{context}"))
}

fn non_empty(value: &str, component: &'static str) -> Result<String, PlaceError> {
    if value.is_empty() {
        return Err(PlaceError::EmptyComponent { component });
    }
    Ok(value.to_owned())
}

/// Percent-escapes what would otherwise change the shape of the address.
///
/// Only `/` and `%` need it, and only really for kubeconfig context names: a managed cluster's
/// context is often an ARN with a slash in it, and rendered raw it would add path segments and
/// stop parsing — an address that does not round-trip is not an identity (§35.3). Kubernetes names
/// and namespaces are DNS labels and pass through untouched.
fn encode(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for character in segment.chars() {
        match character {
            '%' => encoded.push_str("%25"),
            '/' => encoded.push_str("%2F"),
            _ => encoded.push(character),
        }
    }
    encoded
}

fn decode(segment: &str, text: &str) -> Result<String, PlaceError> {
    let mut decoded = String::with_capacity(segment.len());
    let mut characters = segment.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            decoded.push(character);
            continue;
        }
        let high = characters.next().and_then(|digit| digit.to_digit(16));
        let low = characters.next().and_then(|digit| digit.to_digit(16));
        let (Some(high), Some(low)) = (high, low) else {
            return Err(PlaceError::Malformed {
                text: text.to_owned(),
                reason: "a percent escape needs two hexadecimal digits",
            });
        };
        let byte = high * 16 + low;
        let Some(character) = char::from_u32(byte) else {
            return Err(PlaceError::Malformed {
                text: text.to_owned(),
                reason: "a percent escape did not decode to a character",
            });
        };
        decoded.push(character);
    }
    Ok(decoded)
}

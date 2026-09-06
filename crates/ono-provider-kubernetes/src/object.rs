//! A Kubernetes object as this provider holds it: native content, projected metadata, and an
//! identity that survives a name being reused.
//!
//! Specification §14 and §16. Two rules shape everything here.
//!
//! **A name is not an identity** (§4 invariants 4 and 5). `metadata.uid` is what Kubernetes
//! guarantees about one object's life; the name is a label a human reuses, and treating the two
//! alike is how a recreated Pod inherits the history of the one it replaced (Gate C).
//!
//! **Nothing is dropped for being unrecognised** (§12.5, §4 invariant 17). The projection names
//! the metadata every object carries, and the object underneath stays whole and reachable, so a
//! cluster this provider has never seen is not silently reduced to the parts it knows.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value as Json;

use crate::discovery::Gvk;

/// What went wrong reading an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectError {
    /// The bytes are not JSON.
    Malformed(String),
    /// The document is JSON but not a Kubernetes object.
    NotAnObject(String),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "the object does not read as JSON: {detail}"),
            Self::NotAnObject(detail) => write!(
                f,
                "the document is not a Kubernetes object: {detail}. Every object carries \
                 `apiVersion` and `kind`"
            ),
        }
    }
}

impl std::error::Error for ObjectError {}

/// One owner reference, with the flag that says whether the owner is the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerReference {
    api_version: String,
    kind: String,
    name: String,
    uid: String,
    controller: bool,
    block_owner_deletion: bool,
}

impl OwnerReference {
    /// The owner's `apiVersion`.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// The owner's kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The owner's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owner's UID, which is what makes the edge resolvable rather than a name match.
    #[must_use]
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// Whether this owner is the controller (§24.3).
    #[must_use]
    pub fn is_controller(&self) -> bool {
        self.controller
    }

    /// Whether deleting the owner is blocked until this dependent goes.
    #[must_use]
    pub fn blocks_owner_deletion(&self) -> bool {
        self.block_owner_deletion
    }
}

/// What makes two observations the same object over its lifetime (§16.1).
///
/// The provider instance is part of it, so an object in one cluster cannot equal one in another
/// whose UID happens to match (Gate J). The name is *not* part of it, which is the whole point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    provider_instance: String,
    gvk: Gvk,
    uid: Option<String>,
    namespace: Option<String>,
    name: String,
}

impl Identity {
    /// The provider instance the object was observed through.
    #[must_use]
    pub fn provider_instance(&self) -> &str {
        &self.provider_instance
    }

    /// What the object is.
    #[must_use]
    pub fn gvk(&self) -> &Gvk {
        &self.gvk
    }

    /// The object's lifetime identity, where the server gave one.
    #[must_use]
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }

    /// The namespace the object was observed in, absent where its kind is cluster-scoped.
    ///
    /// Part of the identity because it is part of the locator (§16.2): two objects of one kind
    /// may share a name in different namespaces and are not the same object. Exposing it is what
    /// lets an identity be turned back into an address (§35.4) — without it, an edge's far end
    /// could be compared but never navigated to.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The object's name, as `metadata.name` stated it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this identity survives the name being reused.
    ///
    /// False for an object the server gave no UID (§16.5). Such an identity falls back to the
    /// locator, which cannot tell a recreation from a change, and it must say so rather than
    /// letting a caller assume otherwise.
    #[must_use]
    pub fn is_lifetime_stable(&self) -> bool {
        self.uid.is_some()
    }

    /// Whether two identities name the same place in the cluster.
    ///
    /// Distinct from equality, and the distinction is what makes a recreation reportable: same
    /// locator with a different UID is the discontinuity, and an identity that could not say
    /// "these occupy the same name" would have nothing to report it against (§16.3).
    #[must_use]
    pub fn is_same_locator(&self, other: &Self) -> bool {
        self.provider_instance == other.provider_instance
            && self.gvk == other.gvk
            && self.namespace == other.namespace
            && self.name == other.name
    }
}

/// How a human looks an object up (§16.2).
///
/// Not an identity: a locator is stable across a delete and recreate, which is exactly when the
/// identity changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Locator {
    provider_instance: String,
    gvk: Gvk,
    namespace: Option<String>,
    name: String,
}

impl fmt::Display for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.provider_instance, self.gvk)?;
        if let Some(namespace) = &self.namespace {
            write!(f, "/{namespace}")?;
        }
        write!(f, "/{}", self.name)
    }
}

/// A Kubernetes object, projected but not reduced.
#[derive(Debug, Clone, PartialEq)]
pub struct Object {
    provider_instance: String,
    gvk: Gvk,
    name: String,
    namespace: Option<String>,
    uid: Option<String>,
    resource_version: Option<String>,
    generation: Option<i64>,
    creation_timestamp: Option<String>,
    deletion_timestamp: Option<String>,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
    finalizers: Vec<String>,
    owner_references: Vec<OwnerReference>,
    field_managers: Vec<String>,
    native: Json,
}

impl Object {
    /// Reads one object as the API server sent it.
    ///
    /// # Errors
    ///
    /// [`ObjectError::Malformed`] when the bytes are not JSON, and [`ObjectError::NotAnObject`]
    /// when they are JSON without the `apiVersion` and `kind` every object carries.
    pub fn parse(provider_instance: &str, json: &str) -> Result<Self, ObjectError> {
        let native: Json = serde_json::from_str(json)
            .map_err(|error| ObjectError::Malformed(error.to_string()))?;
        Self::from_json(provider_instance, native)
    }

    /// Reads one object already decoded.
    ///
    /// # Errors
    ///
    /// [`ObjectError::NotAnObject`] when `apiVersion` or `kind` is missing.
    pub fn from_json(provider_instance: &str, native: Json) -> Result<Self, ObjectError> {
        let api_version = native
            .get("apiVersion")
            .and_then(Json::as_str)
            .ok_or_else(|| ObjectError::NotAnObject("no `apiVersion`".to_owned()))?;
        let kind = native
            .get("kind")
            .and_then(Json::as_str)
            .ok_or_else(|| ObjectError::NotAnObject("no `kind`".to_owned()))?;
        let (group, version) = api_version.split_once('/').unwrap_or(("", api_version));

        let metadata = native.get("metadata");
        let name = metadata
            .and_then(|meta| meta.get("name"))
            .and_then(Json::as_str)
            // An empty name is not a name: §16.2's locator is built from it, and an object
            // addressed as `.../pods/` is addressed at its collection.
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ObjectError::NotAnObject("no `metadata.name`".to_owned()))?
            .to_owned();

        Ok(Self {
            provider_instance: provider_instance.to_owned(),
            gvk: Gvk::new(group, version, kind),
            name,
            namespace: text(metadata, "namespace"),
            uid: text(metadata, "uid"),
            resource_version: text(metadata, "resourceVersion"),
            generation: metadata
                .and_then(|meta| meta.get("generation"))
                .and_then(Json::as_i64),
            creation_timestamp: text(metadata, "creationTimestamp"),
            deletion_timestamp: text(metadata, "deletionTimestamp"),
            labels: string_map(metadata, "labels"),
            annotations: string_map(metadata, "annotations"),
            finalizers: string_list(metadata, "finalizers"),
            owner_references: owner_references(metadata),
            field_managers: field_managers(metadata),
            native,
        })
    }

    /// What the object is.
    #[must_use]
    pub fn gvk(&self) -> &Gvk {
        &self.gvk
    }

    /// `metadata.name`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `metadata.namespace`, absent for a cluster-scoped object (§9.2).
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// `metadata.uid`, the canonical lifetime identity (§14.2).
    #[must_use]
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }

    /// `metadata.resourceVersion`, as the string the server sent.
    ///
    /// An opaque continuity token (§14.3). It is not a timestamp, not comparable across
    /// resources, and not a clock, so it is returned as text and nothing here offers to order it.
    #[must_use]
    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    /// `metadata.generation`, which counts spec changes and is not `resourceVersion` (§14.4).
    #[must_use]
    pub fn generation(&self) -> Option<i64> {
        self.generation
    }

    /// `metadata.creationTimestamp`.
    #[must_use]
    pub fn creation_timestamp(&self) -> Option<&str> {
        self.creation_timestamp.as_deref()
    }

    /// `metadata.deletionTimestamp`, present once deletion was accepted.
    #[must_use]
    pub fn deletion_timestamp(&self) -> Option<&str> {
        self.deletion_timestamp.as_deref()
    }

    /// Whether deletion was accepted and has not completed (Gate H).
    ///
    /// An object with a deletion timestamp is terminating, never deleted: it is still there, still
    /// answers, and may be held by a finalizer indefinitely.
    #[must_use]
    pub fn is_terminating(&self) -> bool {
        self.deletion_timestamp.is_some()
    }

    /// `metadata.labels`, whole.
    #[must_use]
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    /// One label.
    #[must_use]
    pub fn label(&self, key: &str) -> Option<&str> {
        self.labels.get(key).map(String::as_str)
    }

    /// `metadata.annotations`, whole.
    #[must_use]
    pub fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }

    /// One annotation.
    #[must_use]
    pub fn annotation(&self, key: &str) -> Option<&str> {
        self.annotations.get(key).map(String::as_str)
    }

    /// `metadata.finalizers`, which decide whether a deletion completes (§14.6).
    #[must_use]
    pub fn finalizers(&self) -> &[String] {
        &self.finalizers
    }

    /// `metadata.ownerReferences`.
    #[must_use]
    pub fn owner_references(&self) -> &[OwnerReference] {
        &self.owner_references
    }

    /// The distinct managers named in `metadata.managedFields`, sorted (§14.7).
    ///
    /// The summary rather than the structure: the full record is large and rarely wanted, and it
    /// stays reachable through [`Self::field`] for the apply-conflict case that needs it.
    #[must_use]
    pub fn field_managers(&self) -> &[String] {
        &self.field_managers
    }

    /// The object as the server sent it.
    #[must_use]
    pub fn native(&self) -> &Json {
        &self.native
    }

    /// Any field by JSON pointer, including ones no projection names (§12.5).
    #[must_use]
    pub fn field(&self, pointer: &str) -> Option<&Json> {
        self.native.pointer(pointer)
    }

    /// What makes this the same object across observations (§16.1).
    #[must_use]
    pub fn identity(&self) -> Identity {
        Identity {
            provider_instance: self.provider_instance.clone(),
            gvk: self.gvk.clone(),
            uid: self.uid.clone(),
            namespace: self.namespace.clone(),
            name: self.name.clone(),
        }
    }

    /// How a human looks this object up (§16.2).
    #[must_use]
    pub fn locator(&self) -> Locator {
        Locator {
            provider_instance: self.provider_instance.clone(),
            gvk: self.gvk.clone(),
            namespace: self.namespace.clone(),
            name: self.name.clone(),
        }
    }
}

/// One metadata string, where the object states one.
///
/// **An empty string is not a value.** The API server writes `""` where a field does not apply —
/// `metadata.namespace` on a cluster-scoped object is the everyday case — and a hand-written
/// manifest, a tombstone reconstruction or an aggregated API server that mints no UIDs produces
/// the same shape for the rest. Reading `""` as present is worse than reading it as absent in
/// every case this projection covers:
///
/// - `uid`: §16.5 requires an object without one to degrade identity confidence *explicitly*. An
///   empty UID reported as lifetime-stable is not merely wrong, it collides — §16.3's recreate
///   detection compares UIDs, so every such object would compare equal to every other and two
///   lifetimes would merge instead of producing the discontinuity Gate C requires.
/// - `namespace`: §9.2 turns on "has no namespace" versus "has an empty namespace slot", and an
///   empty one makes the object unaddressable rather than cluster-scoped (§35.4).
/// - `resourceVersion`: §14.3's continuity token. An empty one is not a position to resume from.
/// - `deletionTimestamp`: Gate H reads its presence as "terminating". An empty one is not a
///   deletion that was accepted.
fn text(metadata: Option<&Json>, key: &str) -> Option<String> {
    metadata?
        .get(key)?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn string_map(metadata: Option<&Json>, key: &str) -> BTreeMap<String, String> {
    let Some(map) = metadata
        .and_then(|meta| meta.get(key))
        .and_then(Json::as_object)
    else {
        return BTreeMap::new();
    };
    map.iter()
        .filter_map(|(name, value)| Some((name.clone(), value.as_str()?.to_owned())))
        .collect()
}

fn string_list(metadata: Option<&Json>, key: &str) -> Vec<String> {
    let Some(list) = metadata
        .and_then(|meta| meta.get(key))
        .and_then(Json::as_array)
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn owner_references(metadata: Option<&Json>) -> Vec<OwnerReference> {
    let Some(list) = metadata
        .and_then(|meta| meta.get("ownerReferences"))
        .and_then(Json::as_array)
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|entry| {
            Some(OwnerReference {
                api_version: entry.get("apiVersion")?.as_str()?.to_owned(),
                kind: entry.get("kind")?.as_str()?.to_owned(),
                name: entry.get("name")?.as_str()?.to_owned(),
                uid: entry.get("uid")?.as_str()?.to_owned(),
                controller: entry
                    .get("controller")
                    .and_then(Json::as_bool)
                    .unwrap_or(false),
                block_owner_deletion: entry
                    .get("blockOwnerDeletion")
                    .and_then(Json::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

fn field_managers(metadata: Option<&Json>) -> Vec<String> {
    let Some(list) = metadata
        .and_then(|meta| meta.get("managedFields"))
        .and_then(Json::as_array)
    else {
        return Vec::new();
    };
    let mut managers: Vec<String> = list
        .iter()
        .filter_map(|entry| entry.get("manager")?.as_str().map(str::to_owned))
        .collect();
    managers.sort();
    managers.dedup();
    managers
}

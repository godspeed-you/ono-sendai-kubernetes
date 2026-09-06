//! What the connected API server actually serves.
//!
//! Specification §11 and §13. Nothing here names a Kubernetes kind: the resources this provider
//! can answer for are the ones the server reports, which is what lets a CRD invented after the
//! build be queried without recompiling (§4 invariant 2, Gate A).
//!
//! The distinction the whole module is arranged around is §13.1. A [`Gvk`] identifies an object
//! and its schema; a [`Gvr`] identifies the REST collection it lives in. They are different
//! strings answering different questions — `Endpoints` lives in `endpoints`, `Scale` hangs off
//! `deployments/scale` — so they are different types here, and no code can pass one where the
//! other belongs.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

/// What went wrong reading a discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// A resource list did not read.
    ResourceList(String),
    /// The group list did not read.
    GroupList(String),
    /// The core version list did not read.
    CoreVersions(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceList(detail) => {
                write!(f, "an API resource list does not read: {detail}")
            }
            Self::GroupList(detail) => write!(f, "the API group list does not read: {detail}"),
            Self::CoreVersions(detail) => {
                write!(f, "the core API version list does not read: {detail}")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Whether a resource lives in a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The resource is namespaced.
    Namespaced,
    /// The resource is cluster-scoped and must never be given a fake namespace (§9.2).
    Cluster,
}

/// A verb the server says it supports for a resource.
///
/// Kept as a small closed set for the verbs this provider reasons about, with everything else
/// preserved verbatim, so an unfamiliar verb is neither dropped nor mistaken for a known one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verb {
    /// Read one object.
    Get,
    /// Enumerate a collection.
    List,
    /// Observe changes.
    Watch,
    /// Make a new object.
    Create,
    /// Replace an object.
    Update,
    /// Change part of an object.
    Patch,
    /// Remove an object.
    Delete,
}

impl Verb {
    /// The verb this word names, where it is one this provider reasons about.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "get" => Self::Get,
            "list" => Self::List,
            "watch" => Self::Watch,
            "create" => Self::Create,
            "update" => Self::Update,
            "patch" => Self::Patch,
            "delete" => Self::Delete,
            _ => return None,
        })
    }
}

/// Group, version and kind: what an object *is* (§13.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gvk {
    group: String,
    version: String,
    kind: String,
}

impl Gvk {
    /// Builds an identity. An empty `group` is the core group, which is a group and not a gap.
    #[must_use]
    pub fn new(
        group: impl Into<String>,
        version: impl Into<String>,
        kind: impl Into<String>,
    ) -> Self {
        Self {
            group: group.into(),
            version: version.into(),
            kind: kind.into(),
        }
    }

    /// The API group, empty for the core group.
    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }

    /// The API version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
}

impl fmt::Display for Gvk {
    /// `group/version/Kind`, with the core group's empty name kept rather than elided.
    ///
    /// `/v1/Pod` rather than `v1/Pod`: the leading separator is what stops a core kind from being
    /// read as a group named `v1`, and it makes the core group visible instead of implied (§13.3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.group, self.version, self.kind)
    }
}

/// Group, version and resource: where a collection *lives* (§13.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gvr {
    group: String,
    version: String,
    resource: String,
}

impl Gvr {
    /// Builds a collection identity.
    #[must_use]
    pub fn new(
        group: impl Into<String>,
        version: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            group: group.into(),
            version: version.into(),
            resource: resource.into(),
        }
    }

    /// The API group, empty for the core group.
    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }

    /// The API version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The plural REST resource name.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// The collection's path on the API server.
    ///
    /// The core group lives under `/api`, every named group under `/apis` — a split in the REST
    /// surface that no amount of type identity removes.
    #[must_use]
    pub fn path(&self) -> String {
        if self.group.is_empty() {
            format!("/api/{}/{}", self.version, self.resource)
        } else {
            format!("/apis/{}/{}/{}", self.group, self.version, self.resource)
        }
    }
}

impl fmt::Display for Gvr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.group, self.version, self.resource)
    }
}

/// One resource the server serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    gvk: Gvk,
    gvr: Gvr,
    scope: Scope,
    verbs: Vec<Verb>,
    other_verbs: Vec<String>,
    short_names: Vec<String>,
    subresources: Vec<String>,
}

impl Resource {
    /// What an object of this resource is.
    #[must_use]
    pub fn gvk(&self) -> &Gvk {
        &self.gvk
    }

    /// Where the collection lives.
    #[must_use]
    pub fn gvr(&self) -> &Gvr {
        &self.gvr
    }

    /// The API group, empty for the core group.
    #[must_use]
    pub fn group(&self) -> &str {
        self.gvk.group()
    }

    /// The API version.
    #[must_use]
    pub fn version(&self) -> &str {
        self.gvk.version()
    }

    /// The kind an object of this resource carries.
    #[must_use]
    pub fn kind(&self) -> &str {
        self.gvk.kind()
    }

    /// The plural REST resource name.
    #[must_use]
    pub fn plural(&self) -> &str {
        self.gvr.resource()
    }

    /// Whether objects live in a namespace.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Whether the server declares this verb for the resource.
    #[must_use]
    pub fn supports(&self, verb: Verb) -> bool {
        self.verbs.contains(&verb)
    }

    /// Verbs the server declared that this provider does not model.
    ///
    /// Kept rather than dropped: a verb nobody recognises is still something the server said, and
    /// discarding it would turn an unfamiliar capability into an absent one.
    #[must_use]
    pub fn unmodelled_verbs(&self) -> &[String] {
        &self.other_verbs
    }

    /// The short names the server offers for typing, sorted.
    #[must_use]
    pub fn short_names(&self) -> &[String] {
        &self.short_names
    }

    /// The subresources that hang off this resource, sorted.
    #[must_use]
    pub fn subresources(&self) -> &[String] {
        &self.subresources
    }
}

/// What one API server serves, as one observation of it.
#[derive(Debug, Clone, Default)]
pub struct Discovery {
    /// Keyed by `groupVersion` then plural resource name.
    resources: BTreeMap<String, BTreeMap<String, Resource>>,
    versions: BTreeMap<String, Vec<String>>,
    preferred: BTreeMap<String, String>,
}

impl Discovery {
    /// Starts a snapshot.
    #[must_use]
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// One resource by group-version and plural name, where the server serves it.
    ///
    /// `None` means *not served*, which §11.5 and §21.4 keep distinct from "none exist".
    #[must_use]
    pub fn resource(&self, group_version: &str, plural: &str) -> Option<&Resource> {
        self.resources.get(group_version)?.get(plural)
    }

    /// One resource by group-version and kind.
    ///
    /// A different question from [`Self::resource`], and deliberately a different method: passing
    /// a plural where a kind belongs is the mistake §13.1 exists to prevent, so it answers `None`
    /// rather than quietly matching.
    #[must_use]
    pub fn by_kind(&self, group_version: &str, kind: &str) -> Option<&Resource> {
        self.resources
            .get(group_version)?
            .values()
            .find(|resource| resource.kind() == kind)
    }

    /// The first resource offering this short name.
    ///
    /// Short names are a typing convenience and never identity (§13.5). Two groups may offer the
    /// same one, which is why this is not a resolution strategy on its own.
    #[must_use]
    pub fn by_short_name(&self, short: &str) -> Option<&Resource> {
        self.resources
            .values()
            .flat_map(BTreeMap::values)
            .find(|resource| resource.short_names.iter().any(|name| name == short))
    }

    /// Every resource a user can enumerate: served, listable and not a subresource.
    pub fn listable(&self) -> impl Iterator<Item = &Resource> {
        self.resources
            .values()
            .flat_map(BTreeMap::values)
            .filter(|resource| resource.supports(Verb::List))
    }

    /// Every resource the snapshot holds.
    pub fn all(&self) -> impl Iterator<Item = &Resource> {
        self.resources.values().flat_map(BTreeMap::values)
    }

    /// Whether the server serves this group-version at all.
    #[must_use]
    pub fn serves_group_version(&self, group_version: &str) -> bool {
        self.resources.contains_key(group_version)
    }

    /// Every API group the server serves, the core group's empty name included (§13.3).
    ///
    /// The other accessors answer questions *about* a group whose name the caller already has.
    /// This one exists for the query that names a kind and no group: the group is then the
    /// answer rather than the question, and finding it means asking the server which groups it
    /// serves rather than consulting a list compiled into this crate (§4 invariants 1–2, §11.1).
    /// The empty name is yielded like any other, because the core group is a group (§13.3).
    pub fn groups(&self) -> impl Iterator<Item = &str> {
        self.versions.keys().map(String::as_str)
    }

    /// Every version the server serves for a group.
    #[must_use]
    pub fn versions_of(&self, group: &str) -> Vec<String> {
        self.versions.get(group).cloned().unwrap_or_default()
    }

    /// The version the server prefers for a group, which is a default and not the only one (§13.4).
    #[must_use]
    pub fn preferred_version(&self, group: &str) -> Option<&str> {
        self.preferred.get(group).map(String::as_str)
    }
}

/// Accumulates the documents one discovery pass reads.
#[derive(Debug, Default)]
pub struct Builder {
    discovery: Discovery,
}

impl Builder {
    /// Reads `/api`, the core group's version list.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::CoreVersions`] when the document does not read.
    pub fn core_versions(mut self, json: &str) -> Result<Self, DiscoveryError> {
        let parsed: RawVersions = serde_json::from_str(json)
            .map_err(|error| DiscoveryError::CoreVersions(error.to_string()))?;
        self.discovery
            .versions
            .entry(String::new())
            .or_default()
            .extend(parsed.versions.clone());
        if let Some(first) = parsed.versions.first() {
            self.discovery
                .preferred
                .entry(String::new())
                .or_insert_with(|| first.clone());
        }
        Ok(self)
    }

    /// Reads `/apis`, the named group list.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::GroupList`] when the document does not read.
    pub fn groups(mut self, json: &str) -> Result<Self, DiscoveryError> {
        let parsed: RawGroupList = serde_json::from_str(json)
            .map_err(|error| DiscoveryError::GroupList(error.to_string()))?;
        for group in parsed.groups {
            let versions: Vec<String> = group
                .versions
                .iter()
                .map(|entry| entry.version.clone())
                .collect();
            self.discovery.versions.insert(group.name.clone(), versions);
            if let Some(preferred) = group.preferred_version {
                self.discovery
                    .preferred
                    .insert(group.name, preferred.version);
            }
        }
        Ok(self)
    }

    /// Reads one `APIResourceList`, from `/api/v1` or `/apis/<group>/<version>`.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::ResourceList`] when the document does not read.
    pub fn resources(mut self, json: &str) -> Result<Self, DiscoveryError> {
        self.add_resources(json)?;
        Ok(self)
    }

    /// Reads one `APIResourceList` into the snapshot being built, keeping the builder either way.
    ///
    /// The same reading as [`Self::resources`], for the caller that must survive one of the
    /// documents not reading. §34.2 forbids one API group's failure from becoming the whole
    /// provider's, and a builder consumed by the error of the group that failed leaves that
    /// caller with nowhere to put the groups that answered.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::ResourceList`] when the document does not read. The builder is
    /// unchanged: the document is parsed before anything is inserted.
    pub fn add_resources(&mut self, json: &str) -> Result<(), DiscoveryError> {
        let parsed: RawResourceList = serde_json::from_str(json)
            .map_err(|error| DiscoveryError::ResourceList(error.to_string()))?;
        let (group, version) = split_group_version(&parsed.group_version);

        // Two passes, because a subresource must reach the resource it hangs off and the server
        // does not guarantee an order in which the parent arrives first.
        let entry = self
            .discovery
            .resources
            .entry(parsed.group_version.clone())
            .or_default();
        for raw in &parsed.resources {
            if raw.name.contains('/') {
                continue;
            }
            let mut verbs = Vec::new();
            let mut other = Vec::new();
            for word in &raw.verbs {
                match Verb::from_word(word) {
                    Some(verb) => verbs.push(verb),
                    None => other.push(word.clone()),
                }
            }
            verbs.sort_unstable();
            verbs.dedup();
            let mut short_names = raw.short_names.clone();
            short_names.sort();
            entry.insert(
                raw.name.clone(),
                Resource {
                    gvk: Gvk::new(group, version, &raw.kind),
                    gvr: Gvr::new(group, version, &raw.name),
                    scope: if raw.namespaced {
                        Scope::Namespaced
                    } else {
                        Scope::Cluster
                    },
                    verbs,
                    other_verbs: other,
                    short_names,
                    subresources: Vec::new(),
                },
            );
        }
        for raw in &parsed.resources {
            let Some((parent, sub)) = raw.name.split_once('/') else {
                continue;
            };
            if let Some(resource) = entry.get_mut(parent) {
                resource.subresources.push(sub.to_owned());
                resource.subresources.sort();
                resource.subresources.dedup();
            }
        }
        Ok(())
    }

    /// The snapshot.
    #[must_use]
    pub fn build(self) -> Discovery {
        self.discovery
    }
}

/// `apps/v1` into `("apps", "v1")`; a bare `v1` into `("", "v1")` (§13.3).
fn split_group_version(group_version: &str) -> (&str, &str) {
    group_version.split_once('/').unwrap_or(("", group_version))
}

// --- the documents as the server writes them -------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawVersions {
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawGroupList {
    #[serde(default)]
    groups: Vec<RawGroup>,
}

#[derive(Debug, Deserialize)]
struct RawGroup {
    name: String,
    #[serde(default)]
    versions: Vec<RawGroupVersion>,
    #[serde(rename = "preferredVersion")]
    preferred_version: Option<RawGroupVersion>,
}

#[derive(Debug, Deserialize)]
struct RawGroupVersion {
    version: String,
}

#[derive(Debug, Deserialize)]
struct RawResourceList {
    #[serde(rename = "groupVersion")]
    group_version: String,
    #[serde(default)]
    resources: Vec<RawResource>,
}

#[derive(Debug, Deserialize)]
struct RawResource {
    name: String,
    kind: String,
    #[serde(default)]
    namespaced: bool,
    #[serde(default)]
    verbs: Vec<String>,
    #[serde(rename = "shortNames", default)]
    short_names: Vec<String>,
}

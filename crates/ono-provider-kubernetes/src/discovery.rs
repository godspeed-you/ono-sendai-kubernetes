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

use std::collections::{BTreeMap, BTreeSet};
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
    /// An aggregated discovery document did not read (§11.2).
    Aggregated(String),
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
            Self::Aggregated(detail) => {
                write!(
                    f,
                    "the aggregated discovery document does not read: {detail}"
                )
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
    /// The group-versions aggregated discovery marked `Stale` (§11.2, §34.2).
    ///
    /// Only ever written by [`Builder::aggregated`], because only the aggregated document has a
    /// word for it. The legacy path learns the same fact from a `503` on the group's own resource
    /// list, which is a coverage outcome rather than a property of the snapshot.
    stale: BTreeSet<String>,
    /// What §11.3 requires the snapshot to say about itself.
    ///
    /// `None` where nothing observed a cluster — a builder fed a fixture document, which has a
    /// served surface and no provenance because no pass happened.
    provenance: Option<Provenance>,
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

    /// What this snapshot is a fact about, where a pass produced it (§11.3).
    ///
    /// `None` is §21.4's *not queried*: this surface was assembled from documents rather than
    /// observed from a cluster, and answering with a made-up instance and the current time would
    /// be the exact substitution §4 forbids.
    #[must_use]
    pub fn provenance(&self) -> Option<&Provenance> {
        self.provenance.as_ref()
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

    /// Whether aggregated discovery reported this group-version as `Stale` (§11.2, §34.2).
    ///
    /// The aggregation layer's own word for "the API server behind this group did not answer, so
    /// what I am telling you about it is what I remembered". An empty resource list under that
    /// mark is nobody having been able to ask, and reading it as a group that serves nothing is
    /// §4 invariant 13's collapse reached through content negotiation.
    #[must_use]
    pub fn is_stale(&self, group_version: &str) -> bool {
        self.stale.contains(group_version)
    }

    /// Every group-version the snapshot holds an inventory for.
    pub fn group_versions(&self) -> impl Iterator<Item = &str> {
        self.resources.keys().map(String::as_str)
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

    /// Reads one aggregated discovery document, from `/api` or `/apis` (§11.2).
    ///
    /// **One document instead of one per group-version, and nothing is inferred to get there.**
    /// `APIGroupDiscoveryList` states every field §11.1 requires — groups, versions, resources,
    /// scope, verbs, kind identity and subresources — so this reads them all rather than taking
    /// the groups and asking each one again, which would negotiate a capability and keep paying
    /// the cost it exists to remove.
    ///
    /// **The version order is the preference order.** The aggregated document has no
    /// `preferredVersion` field: it lists a group's versions in priority order instead, so the
    /// first is what §13.4 calls preferred. Anything else here would be this crate inventing a
    /// preference the server did not state.
    ///
    /// **`freshness` is kept rather than flattened.** A group-version the aggregation layer could
    /// not refresh arrives marked `Stale`, usually with an empty resource list. That is §34.2's
    /// failure with the server's own word on it, and dropping the word would turn "nobody could
    /// ask" into "this group serves nothing".
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::Aggregated`] when the document does not read as an
    /// `APIGroupDiscoveryList`. It must be an error rather than an empty snapshot: the fallback
    /// §11.2 and §5.3 both require is only reachable if a server that ignored the negotiation is
    /// distinguishable from a cluster that serves nothing.
    pub fn aggregated(mut self, json: &str) -> Result<Self, DiscoveryError> {
        self.add_aggregated(json)?;
        Ok(self)
    }

    /// Reads one aggregated discovery document into the snapshot being built (§11.2).
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::Aggregated`] as [`Self::aggregated`]. The builder is unchanged: the
    /// document is parsed before anything is inserted.
    pub fn add_aggregated(&mut self, json: &str) -> Result<(), DiscoveryError> {
        let parsed: RawAggregatedList = serde_json::from_str(json)
            .map_err(|error| DiscoveryError::Aggregated(error.to_string()))?;
        if parsed.kind.as_deref() != Some("APIGroupDiscoveryList") {
            return Err(DiscoveryError::Aggregated(format!(
                "the document is a `{}`, not an `APIGroupDiscoveryList`",
                parsed.kind.as_deref().unwrap_or("document with no kind")
            )));
        }
        for group in parsed.items {
            let name = group.metadata.name;
            for (at, version) in group.versions.iter().enumerate() {
                let group_version = if name.is_empty() {
                    version.version.clone()
                } else {
                    format!("{name}/{}", version.version)
                };
                self.discovery
                    .versions
                    .entry(name.clone())
                    .or_default()
                    .push(version.version.clone());
                // The order the server listed them in is the priority order it means.
                if at == 0 {
                    self.discovery
                        .preferred
                        .insert(name.clone(), version.version.clone());
                }
                if version.freshness.as_deref() == Some("Stale") {
                    self.discovery.stale.insert(group_version.clone());
                }
                let entry = self.discovery.resources.entry(group_version).or_default();
                for raw in &version.resources {
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
                    let mut subresources: Vec<String> = raw
                        .subresources
                        .iter()
                        .map(|sub| sub.subresource.clone())
                        .collect();
                    subresources.sort();
                    subresources.dedup();
                    // §13.1 again: the kind comes from `responseKind` and the collection name
                    // from `resource`, and the group and version of the *identity* are the ones
                    // the server wrote beside the kind rather than the ones the envelope implies.
                    entry.insert(
                        raw.resource.clone(),
                        Resource {
                            gvk: Gvk::new(
                                raw.response_kind.group.clone(),
                                if raw.response_kind.version.is_empty() {
                                    version.version.clone()
                                } else {
                                    raw.response_kind.version.clone()
                                },
                                &raw.response_kind.kind,
                            ),
                            gvr: Gvr::new(&name, &version.version, &raw.resource),
                            scope: if raw.scope == "Cluster" {
                                Scope::Cluster
                            } else {
                                Scope::Namespaced
                            },
                            verbs,
                            other_verbs: other,
                            short_names,
                            subresources,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    /// Copies one group-version's inventory out of a snapshot that already holds it (§11.2).
    ///
    /// What makes an aggregated snapshot worth negotiating: a search over the group-versions it
    /// already answered for makes no further request at all. Nothing is merged — a group-version
    /// this builder already holds keeps what it has, so a legacy read of the same group cannot be
    /// silently overwritten by a stale aggregated one.
    pub fn adopt(&mut self, snapshot: &Discovery, group_version: &str) {
        let Some(resources) = snapshot.resources.get(group_version) else {
            return;
        };
        self.discovery
            .resources
            .entry(group_version.to_owned())
            .or_insert_with(|| resources.clone());
        let (group, version) = split_group_version(group_version);
        let versions = self.discovery.versions.entry(group.to_owned()).or_default();
        if !versions.iter().any(|held| held == version) {
            versions.push(version.to_owned());
        }
        if let Some(preferred) = snapshot.preferred.get(group) {
            self.discovery
                .preferred
                .entry(group.to_owned())
                .or_insert_with(|| preferred.clone());
        }
    }

    /// Records what §11.3 requires the snapshot to carry.
    ///
    /// Separate from the documents, and taken last, because the five fields are facts about the
    /// *pass* rather than about any one document it read: which instance asked, when, of what
    /// server, how completely, and by which route.
    #[must_use]
    pub fn observed(mut self, provenance: Provenance) -> Self {
        self.discovery.provenance = Some(provenance);
        self
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

/// `APIGroupDiscoveryList`, as an API server offering aggregated discovery writes it (§11.2).
#[derive(Debug, Deserialize)]
struct RawAggregatedList {
    kind: Option<String>,
    #[serde(default)]
    items: Vec<RawAggregatedGroup>,
}

#[derive(Debug, Deserialize)]
struct RawAggregatedGroup {
    #[serde(default)]
    metadata: RawAggregatedMetadata,
    #[serde(default)]
    versions: Vec<RawAggregatedVersion>,
}

#[derive(Debug, Default, Deserialize)]
struct RawAggregatedMetadata {
    /// Empty for the core group, which is a group and not a gap (§13.3).
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct RawAggregatedVersion {
    version: String,
    #[serde(default)]
    resources: Vec<RawAggregatedResource>,
    /// `Current` or `Stale`; absent on a server that publishes neither.
    #[serde(default)]
    freshness: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAggregatedResource {
    resource: String,
    #[serde(rename = "responseKind", default)]
    response_kind: RawResponseKind,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    verbs: Vec<String>,
    #[serde(rename = "shortNames", default)]
    short_names: Vec<String>,
    #[serde(default)]
    subresources: Vec<RawSubresource>,
}

#[derive(Debug, Default, Deserialize)]
struct RawResponseKind {
    #[serde(default)]
    group: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct RawSubresource {
    subresource: String,
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

// --- §11.3: a discovery snapshot is a provider fact -----------------------------------------------

/// How a discovery snapshot was read (§11.2, §11.3's "source endpoint / mechanism").
///
/// Two mechanisms and a mixture, because §11.2's fallback is per-document rather than per-pass: a
/// cluster can answer `/apis` with an aggregated document and `/api` with a legacy one, and a
/// snapshot that reported either word alone would be describing a pass that never happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// The stable aggregated Discovery API answered (§11.2).
    Aggregated,
    /// The per-group `APIResourceList` documents answered, which is the compatible fallback.
    Legacy,
    /// One root document arrived each way.
    Mixed,
}

impl Mechanism {
    /// The word a record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aggregated => "aggregated",
            Self::Legacy => "legacy",
            Self::Mixed => "mixed",
        }
    }

    /// The mechanism of a pass that read one document each way.
    #[must_use]
    pub fn combined(first: Self, second: Self) -> Self {
        if first == second { first } else { Self::Mixed }
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a snapshot came from: the mechanism, and the endpoints it was actually read at.
///
/// The endpoints are kept beside the mechanism rather than derived from it. `aggregated` says how
/// the server was asked; it does not say *what was asked*, and a reader deciding whether a
/// snapshot could have contained a kind needs the second. They are the request paths, so a
/// snapshot assembled from `/api` and `/apis` says so in the two strings an operator would have
/// typed themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    mechanism: Mechanism,
    endpoints: Vec<String>,
}

impl Source {
    /// A source, from the mechanism and the paths read.
    #[must_use]
    pub fn new(mechanism: Mechanism, endpoints: Vec<String>) -> Self {
        Self {
            mechanism,
            endpoints,
        }
    }

    /// How the server was asked.
    #[must_use]
    pub fn mechanism(&self) -> Mechanism {
        self.mechanism
    }

    /// The request paths the snapshot was read from.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }
}

/// What §11.3 requires a discovery snapshot to carry.
///
/// The five fields are the difference between a snapshot and a lookup table. Without them a
/// [`Discovery`] answers "does this cluster serve `widgets`?" with a bare yes, and a reader has
/// no way to ask *which* cluster, *when*, *how completely*, or *by what route* — which is the
/// shape of every mistake §4's invariants are arranged against. A stale snapshot read from one
/// cluster answering for another is indistinguishable from a live one, unless the snapshot says.
///
/// It is deliberately optional on [`Discovery`]. A builder fed a fixture document has not
/// observed a cluster, and giving it a provenance would be inventing one: §21.4 keeps "not
/// queried" apart from every other non-answer, and a `None` here is that word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    provider_instance: String,
    observed_at: crate::transport::ObservedAt,
    api_server: String,
    coverage: crate::coverage::Coverage,
    source: Source,
}

impl Provenance {
    /// A provenance for one pass over one API server.
    #[must_use]
    pub fn new(
        provider_instance: impl Into<String>,
        observed_at: crate::transport::ObservedAt,
        api_server: impl Into<String>,
        coverage: crate::coverage::Coverage,
        source: Source,
    ) -> Self {
        Self {
            provider_instance: provider_instance.into(),
            observed_at,
            api_server: api_server.into(),
            coverage,
            source,
        }
    }

    /// Which provider instance observed it (§6.2).
    #[must_use]
    pub fn provider_instance(&self) -> &str {
        &self.provider_instance
    }

    /// When it was observed (§17.1).
    #[must_use]
    pub fn observed_at(&self) -> crate::transport::ObservedAt {
        self.observed_at
    }

    /// Which API server answered — the authority, never a name a kubeconfig gave it.
    #[must_use]
    pub fn api_server(&self) -> &str {
        &self.api_server
    }

    /// What the pass covered, and what it could not (§21.4, §34.2).
    #[must_use]
    pub fn coverage(&self) -> &crate::coverage::Coverage {
        &self.coverage
    }

    /// How and where it was read (§11.2).
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.source
    }
}

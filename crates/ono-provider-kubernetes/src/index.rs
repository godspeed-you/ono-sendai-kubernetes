//! Relationship indexes over a synchronised watch cache, and the selector they are queried by
//! (§50.4, §20.3, §23.3, §17.3; §30.5 of the generic provider contract).
//!
//! §50.4 allows selector and owner-reference relationships to "use indexes maintained over
//! active caches", and attaches one `MUST` to the permission: "Indexes MUST track cache
//! sync/freshness. An incomplete index MUST not return an unqualified complete-looking graph."
//! §30.5 of the inherited contract adds the other: "index size and invalidation MUST be bounded
//! and observable."
//!
//! Three decisions shape this module.
//!
//! **An index is a property of one watch stream and lives exactly as long as it does.** It is
//! built when a listing synchronises the cache, updated by every event the stream applies, and
//! dropped with the stream. It never outlives the observation that made it true, so there is no
//! second invalidation rule to get wrong: whatever the session does to the watch — a `410`, a
//! write to the collection, a cluster replacement — it does to the index by construction.
//!
//! **An index answers only while absence in its cache is conclusive.** A synchronised, live
//! stream is entitled to say a name is not in the cluster (§20.3), and only then is the set of
//! objects matching a selector a *complete* set rather than the subset that happened to be seen.
//! [`IndexState::usable`] is that rule, and the reason travels with the answer so a caller falls
//! back to the API server for a stated reason rather than a silent one.
//!
//! **The bound is a number, and crossing it makes the index say so rather than shed entries.** An
//! index that silently dropped postings past a capacity would answer a selector with a subset
//! that looks whole — the exact failure §50.4's `MUST` names. Above [`INDEX_CAPACITY`] the tables
//! are emptied, the state reports `over capacity`, and every derivation goes to the API server
//! with its selector pushed down instead.
//!
//! The selector half is here because it is the question an index is asked. [`LabelSelector`] is
//! the upstream `metav1.LabelSelector` — `matchLabels` and the four `matchExpressions` operators
//! — rendered the way upstream's `LabelSelectorAsSelector` renders it, so the string an API
//! server receives and the predicate the index evaluates are one translation, pinned by one set
//! of tests. It is the *rule's* selector — a Service's `spec.selector`, a controller's
//! `spec.selector`, a policy's `spec.podSelector` — never the caller's, which ADR-0049 keeps
//! verbatim and untranslated.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::Value as Json;

use crate::object::Object;
use crate::watch::SyncState;

/// How many objects one index will hold before it declares itself unusable (§30.5 core, §18.5).
///
/// Fifty thousand, and the number is an argument rather than a round figure. A synchronised
/// informer cache of twenty thousand Pods measures around ten megabytes (ADR-0044's
/// observations); the index over it posts each object once per label and once per owner, so a
/// cache at this bound costs a few more megabytes of keys. Above it, a namespace is large enough
/// that the API server's own label index answers a selector faster than a client-side walk
/// would, and the honest thing is to say the index does not cover it.
pub const INDEX_CAPACITY: usize = 50_000;

/// How a cached object is addressed: the namespace and the name a human looks it up with.
pub type ObjectKey = (Option<String>, String);

/// Why a label selector could not be read (§23.3, ADR-0007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorError {
    /// `matchExpressions` names an operator upstream does not define.
    UnknownOperator(String),
    /// An `In` or `NotIn` requirement carries no values, which upstream rejects.
    NoValues(String),
    /// An `Exists` or `DoesNotExist` requirement carries values, which upstream rejects.
    UnexpectedValues(String),
    /// A requirement names no key.
    MissingKey,
    /// The selector is not an object.
    NotAnObject,
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOperator(operator) => write!(
                f,
                "`matchExpressions` uses the operator `{operator}`, which is not one upstream \
                 defines (In, NotIn, Exists, DoesNotExist)"
            ),
            Self::NoValues(key) => write!(
                f,
                "the requirement on `{key}` uses In or NotIn and names no values"
            ),
            Self::UnexpectedValues(key) => write!(
                f,
                "the requirement on `{key}` uses Exists or DoesNotExist and names values"
            ),
            Self::MissingKey => f.write_str("a requirement of `matchExpressions` names no key"),
            Self::NotAnObject => f.write_str("the selector is not an object"),
        }
    }
}

impl std::error::Error for SelectorError {}

/// One requirement of a label selector, in upstream's four operators plus equality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    /// `matchLabels`' `key: value`, which upstream renders as `key=value`.
    Equals(String, String),
    /// `key in (a,b)`.
    In(String, Vec<String>),
    /// `key notin (a,b)`.
    NotIn(String, Vec<String>),
    /// `key`: the label is present with any value.
    Exists(String),
    /// `!key`: the label is absent.
    DoesNotExist(String),
}

impl Requirement {
    /// Whether this requirement holds for one label set.
    fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        match self {
            Self::Equals(key, wanted) => labels.get(key) == Some(wanted),
            Self::In(key, values) => labels.get(key).is_some_and(|held| values.contains(held)),
            // Upstream: a `notin` requirement is satisfied by an object that lacks the key.
            Self::NotIn(key, values) => labels.get(key).is_none_or(|held| !values.contains(held)),
            Self::Exists(key) => labels.contains_key(key),
            Self::DoesNotExist(key) => !labels.contains_key(key),
        }
    }

    /// The requirement as upstream's `labels.Requirement.String` renders it.
    fn render(&self) -> String {
        match self {
            Self::Equals(key, value) => format!("{key}={value}"),
            Self::In(key, values) => format!("{key} in ({})", values.join(",")),
            Self::NotIn(key, values) => format!("{key} notin ({})", values.join(",")),
            Self::Exists(key) => key.clone(),
            Self::DoesNotExist(key) => format!("!{key}"),
        }
    }
}

/// A `metav1.LabelSelector`, read once and used twice: as a query string and as a predicate.
///
/// The translation is upstream's own (`LabelSelectorAsSelector` in `apimachinery`), which is
/// what makes pushing it to the API server exact rather than approximate: the server evaluates
/// the same expression a client-go controller would have evaluated to decide what it adopts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSelector {
    requirements: Vec<Requirement>,
}

impl LabelSelector {
    /// A selector of equalities alone: a Service's `spec.selector`, an EndpointSlice's label.
    #[must_use]
    pub fn equalities(labels: &BTreeMap<String, String>) -> Self {
        Self {
            requirements: labels
                .iter()
                .map(|(key, value)| Requirement::Equals(key.clone(), value.clone()))
                .collect(),
        }
    }

    /// A `metav1.LabelSelector` — `matchLabels` and `matchExpressions` — as upstream reads it.
    ///
    /// # Errors
    ///
    /// [`SelectorError`] for an expression upstream would refuse: an operator it does not
    /// define, `In`/`NotIn` with no values, `Exists`/`DoesNotExist` with values. None of those is
    /// evaluated approximately; a selector that cannot be read is not pushed anywhere.
    pub fn from_json(selector: &Json) -> Result<Self, SelectorError> {
        let Some(map) = selector.as_object() else {
            return Err(SelectorError::NotAnObject);
        };
        let mut requirements = Vec::new();
        if let Some(labels) = map.get("matchLabels").and_then(Json::as_object) {
            // A BTreeMap so the rendering is deterministic: upstream sorts requirements by key
            // as well, and a query string that differed between two runs would be two requests
            // an operator cannot compare.
            let labels: BTreeMap<String, String> = labels
                .iter()
                .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
                .collect();
            requirements.extend(
                labels
                    .into_iter()
                    .map(|(key, value)| Requirement::Equals(key, value)),
            );
        }
        for expression in map
            .get("matchExpressions")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            let key = expression
                .get("key")
                .and_then(Json::as_str)
                .filter(|key| !key.is_empty())
                .ok_or(SelectorError::MissingKey)?
                .to_owned();
            let operator = expression
                .get("operator")
                .and_then(Json::as_str)
                .unwrap_or_default();
            let mut values: Vec<String> = expression
                .get("values")
                .and_then(Json::as_array)
                .into_iter()
                .flatten()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect();
            values.sort();
            values.dedup();
            let requirement = match operator {
                "In" | "NotIn" if values.is_empty() => {
                    return Err(SelectorError::NoValues(key));
                }
                "In" => Requirement::In(key, values),
                "NotIn" => Requirement::NotIn(key, values),
                "Exists" | "DoesNotExist" if !values.is_empty() => {
                    return Err(SelectorError::UnexpectedValues(key));
                }
                "Exists" => Requirement::Exists(key),
                "DoesNotExist" => Requirement::DoesNotExist(key),
                other => return Err(SelectorError::UnknownOperator(other.to_owned())),
            };
            requirements.push(requirement);
        }
        Ok(Self { requirements })
    }

    /// Whether the selector states no requirement at all.
    ///
    /// What that *means* is the caller's: for a Service it selects nothing (§26.1), for a
    /// NetworkPolicy it selects every Pod of the namespace, and for a controller upstream reads
    /// it as matching everything. The selector itself only says that it is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }

    /// The requirements, in the order they are rendered.
    #[must_use]
    pub fn requirements(&self) -> &[Requirement] {
        &self.requirements
    }

    /// The `labelSelector` query value upstream would send, or nothing for an empty selector.
    ///
    /// `None` rather than an empty string: an API server reads an absent `labelSelector` and an
    /// empty one identically, and sending `labelSelector=` would make a rule that filters
    /// nothing look like a filter in every request log an operator later reads (ADR-0049).
    #[must_use]
    pub fn to_query(&self) -> Option<String> {
        if self.requirements.is_empty() {
            return None;
        }
        Some(
            self.requirements
                .iter()
                .map(Requirement::render)
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    /// Whether every requirement holds for one object's labels.
    #[must_use]
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.requirements
            .iter()
            .all(|requirement| requirement.matches(labels))
    }
}

/// Why an index is not entitled to answer, in words a fallback can report (§50.4, §20.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// The stream behind it is not live, so a name missing from the cache is unobserved rather
    /// than absent (§20.3). The state says which of §41.4's words applies.
    NotSynced(SyncState),
    /// The cache holds more objects than [`INDEX_CAPACITY`], so nothing was indexed.
    OverCapacity,
    /// This session wrote to an object of the collection and has not seen its event yet, so
    /// the cache is missing an object it will hold again in a moment (§20.5).
    PendingWrite,
}

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSynced(state) => write!(f, "the watch behind the index is {state}"),
            Self::OverCapacity => f.write_str("the cache holds more objects than the index bound"),
            Self::PendingWrite => f.write_str(
                "an object of the collection was written by this session and its event has not \
                 arrived",
            ),
        }
    }
}

/// What one index is, observably (§30.5 core): its size, its bound, and whether it may answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexState {
    sync_state: SyncState,
    gap_free: bool,
    objects: usize,
    capacity: usize,
    unusable: Option<Unusable>,
}

impl IndexState {
    /// The sync state of the stream the index is maintained over (§41.4).
    #[must_use]
    pub fn sync_state(&self) -> SyncState {
        self.sync_state
    }

    /// Whether one unbroken period covers everything the stream has observed (§19.4).
    #[must_use]
    pub fn is_gap_free(&self) -> bool {
        self.gap_free
    }

    /// How many objects the index covers.
    #[must_use]
    pub fn objects(&self) -> usize {
        self.objects
    }

    /// The bound on how many it will cover.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether a derivation may answer from this index rather than from the API server.
    #[must_use]
    pub fn usable(&self) -> bool {
        self.unusable.is_none()
    }

    /// Why it may not, where it may not.
    #[must_use]
    pub fn unusable(&self) -> Option<Unusable> {
        self.unusable
    }

    /// The state in one line, for a diagnostic.
    #[must_use]
    pub fn describe(&self) -> String {
        let verdict = match self.unusable {
            None => "usable".to_owned(),
            Some(reason) => format!("unusable: {reason}"),
        };
        format!(
            "{verdict}; {} of at most {} objects indexed; watch {}{}",
            self.objects,
            self.capacity,
            self.sync_state,
            if self.gap_free { "" } else { ", with gaps" }
        )
    }
}

/// What one object contributed to the index, kept so a change can retract exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Posted {
    namespace: Option<String>,
    labels: BTreeMap<String, String>,
    owners: BTreeSet<String>,
}

/// The tables §50.4 names, over the objects of one watched collection.
///
/// Three, and each one is consumed by a derivation that exists: the label postings answer a
/// Service's, a NetworkPolicy's and an EndpointSlice's selector; the owner table answers a
/// controller's `owns`; the namespace table answers the rules that read every object of one
/// namespace — a Pod's `selected-by` and `protected-by`, a Service's `routed-from`. Nothing is
/// indexed on speculation: a UID table, a Node table or a StorageClass table would be maintained
/// for a derivation nobody has written (AGENTS.md §4 in core).
#[derive(Debug, Clone, Default)]
pub struct RelationshipIndex {
    capacity: usize,
    over_capacity: bool,
    entries: BTreeMap<ObjectKey, Posted>,
    by_namespace: BTreeMap<Option<String>, BTreeSet<ObjectKey>>,
    by_label: BTreeMap<(Option<String>, String, String), BTreeSet<ObjectKey>>,
    by_owner: BTreeMap<String, BTreeSet<ObjectKey>>,
}

impl RelationshipIndex {
    /// An empty index bounded at [`INDEX_CAPACITY`].
    #[must_use]
    pub fn new() -> Self {
        Self::bounded(INDEX_CAPACITY)
    }

    /// An empty index with a bound of the caller's choosing, so the bound can be tested.
    #[must_use]
    pub fn bounded(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    /// Rebuilds the tables from a synchronised cache, replacing whatever was indexed before.
    pub fn rebuild<'a>(&mut self, objects: impl IntoIterator<Item = &'a Object>) {
        self.clear();
        for object in objects {
            self.insert(object);
            if self.over_capacity {
                return;
            }
        }
    }

    /// Indexes one object, replacing what an earlier version of it posted.
    ///
    /// Past the bound the tables are emptied and the index stays unusable until the next
    /// rebuild: a partial index is exactly the complete-looking incomplete graph §50.4 forbids.
    pub fn insert(&mut self, object: &Object) {
        if self.over_capacity {
            return;
        }
        let key = key_of(object);
        self.remove(&key);
        if self.entries.len() >= self.capacity {
            self.clear();
            self.over_capacity = true;
            return;
        }
        let posted = Posted {
            namespace: object.namespace().map(str::to_owned),
            labels: object.labels().clone(),
            owners: object
                .owner_references()
                .iter()
                .map(|owner| owner.uid().to_owned())
                .collect(),
        };
        self.by_namespace
            .entry(posted.namespace.clone())
            .or_default()
            .insert(key.clone());
        for (label, value) in &posted.labels {
            self.by_label
                .entry((posted.namespace.clone(), label.clone(), value.clone()))
                .or_default()
                .insert(key.clone());
        }
        for owner in &posted.owners {
            self.by_owner
                .entry(owner.clone())
                .or_default()
                .insert(key.clone());
        }
        self.entries.insert(key, posted);
    }

    /// Retracts whatever one object posted.
    pub fn remove(&mut self, key: &ObjectKey) {
        let Some(posted) = self.entries.remove(key) else {
            return;
        };
        if let Some(members) = self.by_namespace.get_mut(&posted.namespace) {
            members.remove(key);
            if members.is_empty() {
                self.by_namespace.remove(&posted.namespace);
            }
        }
        for (label, value) in &posted.labels {
            let posting = (posted.namespace.clone(), label.clone(), value.clone());
            if let Some(members) = self.by_label.get_mut(&posting) {
                members.remove(key);
                if members.is_empty() {
                    self.by_label.remove(&posting);
                }
            }
        }
        for owner in &posted.owners {
            if let Some(members) = self.by_owner.get_mut(owner) {
                members.remove(key);
                if members.is_empty() {
                    self.by_owner.remove(owner);
                }
            }
        }
    }

    /// Empties every table and forgets an earlier overflow.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_namespace.clear();
        self.by_label.clear();
        self.by_owner.clear();
        self.over_capacity = false;
    }

    /// How many objects are indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The bound this index was built with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether the cache outgrew the bound, in which case nothing is indexed.
    #[must_use]
    pub fn is_over_capacity(&self) -> bool {
        self.over_capacity
    }

    /// The observable state of this index over a stream in `sync_state` (§30.5 core, §50.4).
    #[must_use]
    pub fn state(
        &self,
        sync_state: SyncState,
        gap_free: bool,
        pending_writes: usize,
    ) -> IndexState {
        let unusable = if self.over_capacity {
            Some(Unusable::OverCapacity)
        } else if sync_state != SyncState::Live {
            Some(Unusable::NotSynced(sync_state))
        } else if pending_writes > 0 {
            Some(Unusable::PendingWrite)
        } else {
            None
        };
        IndexState {
            sync_state,
            gap_free,
            objects: self.entries.len(),
            capacity: self.capacity,
            unusable,
        }
    }

    /// Every indexed object of one namespace — or of the whole collection for `None`.
    #[must_use]
    pub fn in_namespace(&self, namespace: Option<&str>) -> Vec<ObjectKey> {
        self.by_namespace
            .get(&namespace.map(str::to_owned))
            .map(|members| members.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The objects of one namespace whose labels satisfy `selector`, in full (§23.3).
    ///
    /// The equality postings narrow the candidates; every requirement — including the four
    /// expression operators, which no posting answers — is then evaluated against the object's
    /// whole label set, so the answer is the selector's and never a superset of it (ADR-0007).
    #[must_use]
    pub fn matching(&self, namespace: Option<&str>, selector: &LabelSelector) -> Vec<ObjectKey> {
        let namespace = namespace.map(str::to_owned);
        let mut candidates: Option<BTreeSet<ObjectKey>> = None;
        for requirement in &selector.requirements {
            let Requirement::Equals(key, value) = requirement else {
                continue;
            };
            let posting = self
                .by_label
                .get(&(namespace.clone(), key.clone(), value.clone()))
                .cloned()
                .unwrap_or_default();
            candidates = Some(match candidates {
                None => posting,
                Some(held) => held.intersection(&posting).cloned().collect(),
            });
        }
        let candidates = candidates.unwrap_or_else(|| {
            self.by_namespace
                .get(&namespace)
                .cloned()
                .unwrap_or_default()
        });
        candidates
            .into_iter()
            .filter(|key| {
                self.entries
                    .get(key)
                    .is_some_and(|posted| selector.matches(&posted.labels))
            })
            .collect()
    }

    /// The objects whose `metadata.ownerReferences` name `owner_uid` (§24.1, §25).
    #[must_use]
    pub fn children_of(&self, owner_uid: &str) -> Vec<ObjectKey> {
        self.by_owner
            .get(owner_uid)
            .map(|members| members.iter().cloned().collect())
            .unwrap_or_default()
    }
}

fn key_of(object: &Object) -> ObjectKey {
    (
        object.namespace().map(str::to_owned),
        object.name().to_owned(),
    )
}

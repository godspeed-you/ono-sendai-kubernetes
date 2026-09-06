//! What one provider instance holds between two invocations (§6.3).
//!
//! Specification §6.3 (session), §6.4 (lazy connection), §6.5 (multiple clusters), §10.1 and
//! §10.4 (cluster identity and replacement), §12.4 (schema cache invalidation), §19.6 and §19.7
//! (demand-driven watches and their lifecycle), §20.1–§20.3 (cache classes, object freshness,
//! informer-style cache) and §50.2 (discovery is not free).
//!
//! Everything else in this crate is a function of bytes already received. A session is the one
//! place that is deliberately *stateful*, because the questions §6.3 asks — which endpoint, as
//! whom, what does this server serve, what is cached, what is being watched — are exactly the
//! questions whose answers must survive a call. Without it every invocation re-resolved the
//! endpoint, re-ran discovery and re-fetched the OpenAPI document; the schema cache had no owner;
//! §10.4 had no cache to invalidate; and §20.2's "cached or direct?" was unanswerable because
//! nothing was ever cached.
//!
//! It still performs no I/O. A caller reads bytes with [`crate::transport`] and hands the results
//! here — a [`crate::transport::Listing`] to synchronise a cache, watch bytes to apply, a
//! [`Fingerprint`] to compare. That keeps the awkward sequences — a cluster replaced behind an
//! unchanged configuration name, an expiry mid-stream, a partial listing that must not become a
//! cache — ordinary tests rather than a cluster somebody has to break on purpose.
//!
//! **One session owns its state and shares none of it.** §6.5 forbids identity, cache, watch
//! checkpoint, credential and namespace crossover between provider instances, and every one of
//! those is a consequence of where the state lives. It lives in the value, so two sessions cannot
//! collide without somebody deliberately passing one's contents to the other.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use crate::coverage::Scope;
use crate::diagnostics::{Alias, ClusterDiagnostic, Fingerprint, Identity, TlsPosture};
use crate::discovery::{Discovery, Gvk, Gvr};
use crate::kubeconfig::{Connection, Credential, Secret};
use crate::schema::{Schema, SchemaCache};
use crate::tls::TlsSettings;
use crate::transport::{
    Clock, EndpointCategory, Freshness, Listing, ObservedAt, Read, SystemClock,
};
use crate::watch::{FrameError, Reception, ResourceVersion, SyncState, WatchDecoder, WatchStream};

/// An optional server behaviour this session agreed with the cluster it is connected to (§6.3).
///
/// Absent by default, and that is the point. §19.2 requires a streaming list to be
/// capability-negotiated with a list/watch fallback, and §11.2 makes aggregated discovery
/// something a server either offers or does not. A capability that defaults to available sends
/// the request anyway, fails against a cluster one version older, and never exercises the
/// fallback that was supposed to make it safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// Aggregated discovery, which answers the whole resource inventory in one round trip
    /// (§11.2).
    AggregatedDiscovery,
    /// `allowWatchBookmarks`, which lets a reconnect resume from a checkpoint instead of
    /// relisting (§19.1).
    WatchBookmarks,
    /// Streaming lists / initial events, which trade a snapshot for lower memory pressure
    /// (§19.2).
    StreamingLists,
    /// `SelfSubjectAccessReview`, which answers "may this identity do that" authoritatively
    /// (§21.2).
    SubjectAccessReview,
}

impl Capability {
    /// The word this capability is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AggregatedDiscovery => "aggregated-discovery",
            Self::WatchBookmarks => "watch-bookmarks",
            Self::StreamingLists => "streaming-lists",
            Self::SubjectAccessReview => "subject-access-review",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What comparing a freshly observed cluster fingerprint against the session's concluded (§10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterChange {
    /// The session had no fingerprint yet, so there was nothing to compare against.
    FirstObserved,
    /// The evidence agrees: the same cluster, and the session's caches are still about it.
    Same,
    /// A decisive signal changed. §10.4's `MUST`: a different cluster is answering to the same
    /// configuration name, and everything the session cached about the previous one has been
    /// invalidated.
    Replaced,
    /// The two fingerprints share no signal, so nothing can be concluded either way.
    ///
    /// Deliberately not treated as a replacement. §10.2 says no single signal is universally
    /// available, so "I could not compare" is the ordinary case for an identity that may not read
    /// `kube-system` — and rendering it as a cluster replacement would empty the caches on a
    /// permission failure.
    Undetermined,
}

impl ClusterChange {
    /// Whether this conclusion invalidated the session's caches.
    #[must_use]
    pub fn invalidated(self) -> bool {
        matches!(self, Self::Replaced)
    }
}

/// Why a listing may not become a synchronised cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncRefused {
    /// The listing carries no collection `resourceVersion`, so no watch can open from it (§19.1).
    NoCollectionVersion,
    /// The listing did not cover the scope it was asked about — a denied page, an unserved type,
    /// a budget that stopped the walk (§18.3, §21.4).
    IncompleteCoverage,
    /// The pages of the listing do not belong to one snapshot, so the set they form was never
    /// true at any moment (§18.2).
    BrokenContinuity,
}

impl fmt::Display for SyncRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCollectionVersion => f.write_str(
                "the listing carries no collection resourceVersion, so a watch opened from it \
                 would start from now and miss everything that already exists",
            ),
            Self::IncompleteCoverage => f.write_str(
                "the listing did not cover its scope, so a cache seeded from it would report \
                 what it was never allowed to read as absent",
            ),
            Self::BrokenContinuity => f.write_str(
                "the pages of the listing are from different snapshots, so the set they form was \
                 never true at once",
            ),
        }
    }
}

impl std::error::Error for SyncRefused {}

/// What the session's caches can say about one name (§20.2, §20.3).
///
/// Four answers rather than `Option`, because §4 invariant 13 is about exactly this collapse: an
/// object that is cached, an object observed not to exist, a collection nobody is watching and a
/// cache that has not finished synchronising are four different states, and a `None` shared by
/// the last three is how "nobody looked" comes to render as "it is not there".
#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    /// The cache holds it, and the [`Read`] says so: its freshness carries
    /// [`crate::transport::Origin::Cache`] and the moment of the read that filled the cache.
    Cached(Box<Read>),
    /// The cache is synchronised and live, and the name is not in it. Evidence of absence
    /// upstream (§20.3).
    ConfirmedAbsent,
    /// No watch covers this collection and scope, so this session knows nothing about it.
    NotWatched,
    /// A watch covers it and is not currently entitled to answer: still syncing, reconnecting,
    /// past a gap, or denied. The state says which (§19.4, §20.3, §21.4).
    NotSynced(SyncState),
}

impl Lookup {
    /// Whether this lookup answered the question at all.
    ///
    /// A caller that treats every non-[`Lookup::Cached`] result as an absence has undone §20.3
    /// in one line, so the distinction is available without a match.
    #[must_use]
    pub fn is_answer(&self) -> bool {
        matches!(self, Self::Cached(_) | Self::ConfirmedAbsent)
    }

    /// The object, where one was cached.
    #[must_use]
    pub fn read(&self) -> Option<&Read> {
        match self {
            Self::Cached(read) => Some(read),
            _ => None,
        }
    }
}

/// How long a discovery document this session holds may keep answering for the cluster (§11.4).
///
/// **The window is the refresh.** §11.4 requires discovery invalidation and refresh *without
/// restarting Ono*, and until this constant existed the only thing that dropped a discovery
/// document was a cluster *replacement* (§10.4) — so a CRD installed while a shell session was
/// live stayed invisible for the life of the process, and the remedy was the restart §11.4 names
/// as the thing that must not be necessary. §16.2 of the generic provider contract asks every
/// cache for explicit invalidation *and expiry* semantics; this is the expiry half, and
/// [`Session::group_version_changed`] and friends are the other.
///
/// **Thirty seconds, and the number is an argument rather than a round figure.** §50.2 asks for
/// discovery to be "cached and incrementally refreshed rather than downloaded before every
/// query", so the window has to be long enough that a burst of invocations — a pipeline, a
/// completion, a place being drawn — pays §50.2's three round trips once. It also bounds how long
/// this session may be wrong about what the cluster serves, and being wrong about that is not a
/// slow answer but a wrong one: a kind the cluster serves reported as not served. Half a minute
/// is under the time it takes an operator to install a CRD and ask about it, and it costs at most
/// three small `GET`s per half-minute of *active* use — nothing at all for a session nobody is
/// using, because the refresh happens when a question needs discovery rather than on a timer
/// (§19.6's rule about work nobody asked for, applied to discovery).
pub const DISCOVERY_VALIDITY: Duration = Duration::from_secs(30);

/// One discovery document, and what this session knows about how true it still is.
///
/// The text is kept even once it may no longer be served, which is the difference between
/// *invalidating* a cache and *marking it stale* (§16.5 of the generic contract offers both). A
/// dropped document answers nothing and says nothing; a stale one answers nothing and is still
/// the only baseline against which the refreshed document can say what changed — which group
/// stopped being served, which kind the server now describes differently (§33.2, §12.4).
#[derive(Debug, Clone)]
struct Document {
    text: String,
    /// When this session read it, on its own clock.
    observed_at: ObservedAt,
    /// Whether something this session did or observed has already made it a claim about a
    /// cluster that has moved on, before the validity window ran out.
    stale: bool,
}

/// What one successful mutation invalidated in this session's caches (§20.5, generic §16.5).
///
/// Returned rather than silently done, because "what a write is allowed to make this session
/// forget" is a decision with two failure modes and a value is what makes both assertable: too
/// little and a pre-change object is served as a confirmed observation, too much and every write
/// pays §50.2's cost for every unrelated collection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Invalidation {
    collections: Vec<(Gvr, Scope)>,
    discovery: bool,
}

impl Invalidation {
    /// The watched collections whose caches this write dropped.
    #[must_use]
    pub fn collections(&self) -> &[(Gvr, Scope)] {
        &self.collections
    }

    /// Whether the write also made what the cluster serves a question again (§33.2).
    #[must_use]
    pub fn invalidated_discovery(&self) -> bool {
        self.discovery
    }

    /// What was invalidated, in a sentence a record can carry.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut said = match self.collections.len() {
            0 => "this session was holding no cache of that object, so nothing about it was \
                  invalidated"
                .to_owned(),
            1 => "the one cached collection this session held that object in was invalidated, so \
                  the next read of it observes rather than recalls"
                .to_owned(),
            count => format!(
                "the {count} cached collections this session held that object in were \
                 invalidated, so the next read of it observes rather than recalls"
            ),
        };
        if self.discovery {
            said.push_str(
                "; and what the cluster serves is asked again, because this change is part of \
                 the answer to it",
            );
        }
        said
    }
}

/// One watched collection: its cache, the decoder feeding it, and when it last observed anything.
#[derive(Debug, Clone)]
struct Watched {
    stream: WatchStream,
    decoder: WatchDecoder,
    /// When the read that filled or last updated this cache was made.
    ///
    /// Per stream rather than per object, and that is the honest reading: a synchronised informer
    /// cache is current as of its last observation for *every* object in it, because the watch
    /// would have said otherwise. Stamping each entry with the time it was written would make an
    /// unchanged object look stale and a changed one look fresher than its neighbours, when in
    /// fact they are known to the same instant (§20.2, §20.3).
    observed_at: ObservedAt,
}

/// The live state of one provider instance (§6.3).
pub struct Session<C: Clock = SystemClock> {
    /// The kubeconfig context this session was resolved from, where one was.
    ///
    /// Optional because §7.3 admits an endpoint named directly — a `kubectl proxy`, an
    /// automation host, a test cluster — and such a session has no context, no trust anchors and
    /// no credential to hand back. Modelling that as an absent connection rather than as an
    /// invented one keeps [`Self::credential_material`] from ever answering with something the
    /// operator did not configure.
    connection: Option<Connection>,
    instance: String,
    endpoint: String,
    namespace: Option<String>,
    credential: Credential,
    tls: Option<TlsSettings>,
    identity: Identity,
    fingerprint: Fingerprint,
    discovery: Option<Discovery>,
    documents: BTreeMap<String, Document>,
    schemas: SchemaCache,
    watches: BTreeMap<(Gvr, Scope), Watched>,
    capabilities: BTreeSet<Capability>,
    clock: C,
}

impl Session<SystemClock> {
    /// A session for one resolved connection, on the wall clock.
    ///
    /// Nothing is contacted. §6.4 forbids discovering the package from reaching every configured
    /// cluster, and the strongest form of that guarantee is a constructor that has no way to:
    /// what a cluster would tell the session arrives later, through [`Self::discovered`],
    /// [`Self::identified`] and [`Self::observed_fingerprint`].
    #[must_use]
    pub fn new(connection: Connection) -> Self {
        Self::with_clock(connection, SystemClock)
    }

    /// A session for an endpoint the caller named directly, with no kubeconfig behind it (§7.3).
    ///
    /// The counterpart of [`Self::new`] for the configuration §7.3 allows: an operator who names
    /// an API server rather than a context still has a provider instance, and that instance still
    /// pays §50.2's discovery cost once per session rather than once per call.
    ///
    /// It takes the *kind* of credential and never the material. §8.1 separates the two, and a
    /// session assembled this way is where the separation becomes structural: the credential is
    /// resolved from the operator's configuration on every invocation and never held here, so no
    /// invocation can be answered with a credential another one resolved.
    #[must_use]
    pub fn for_endpoint(
        instance: impl Into<String>,
        endpoint: impl Into<String>,
        namespace: Option<&str>,
        credential: Credential,
    ) -> Self {
        Self {
            connection: None,
            instance: instance.into(),
            endpoint: endpoint.into(),
            namespace: namespace.map(str::to_owned),
            credential,
            tls: None,
            identity: Identity::unknown(),
            fingerprint: Fingerprint::unknown(),
            discovery: None,
            documents: BTreeMap::new(),
            schemas: SchemaCache::new(""),
            watches: BTreeMap::new(),
            capabilities: BTreeSet::new(),
            clock: SystemClock,
        }
    }
}

impl<C: Clock> Session<C> {
    /// A session on a clock the caller chooses, which is what makes freshness assertable (§59.2).
    #[must_use]
    pub fn with_clock(connection: Connection, clock: C) -> Self {
        let instance = connection.instance_id();
        let endpoint = connection.server().to_owned();
        let namespace = connection.namespace().map(str::to_owned);
        let credential = connection.credential();
        Self {
            connection: Some(connection),
            instance,
            endpoint,
            namespace,
            credential,
            tls: None,
            identity: Identity::unknown(),
            fingerprint: Fingerprint::unknown(),
            discovery: None,
            documents: BTreeMap::new(),
            schemas: SchemaCache::new(""),
            watches: BTreeMap::new(),
            capabilities: BTreeSet::new(),
            clock,
        }
    }

    /// Records the TLS configuration the connection was established with (§6.3, §8.4).
    #[must_use]
    pub fn connected(mut self, tls: TlsSettings) -> Self {
        self.tls = Some(tls);
        self
    }

    // --- identity and configuration (§6.2, §6.3, §7.5, §10.1) ------------------------------------

    /// The provider instance this session speaks for (§6.2).
    ///
    /// Ono-local, derived from the configuration name and never from the cluster, so that it
    /// survives a reconnect and even a cluster replacement (§10.1).
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// The resolved API server endpoint (§6.3).
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The default namespace this instance starts navigation in, where its context names one.
    ///
    /// A starting point, never an authorization boundary (§7.5), and never inherited from another
    /// session (§6.5).
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// How this session proves who it is — the kind, never the material (§8.1).
    #[must_use]
    pub fn credential(&self) -> Credential {
        self.credential
    }

    /// The active credential material, where the connection carries it inline.
    ///
    /// Reaching it is a visible act: [`Secret::expose`] is what a request builder calls to put an
    /// `Authorization` header together, and nothing else here ever reads it. The session's own
    /// [`fmt::Debug`] and [`Self::diagnostic`] cannot reach it at all, which is §6.3's last line.
    #[must_use]
    pub fn credential_material(&self) -> Option<&Secret> {
        self.connection.as_ref().and_then(Connection::material)
    }

    /// The resolved kubeconfig context, for a caller that has to open the byte stream.
    ///
    /// Absent for a session built by [`Self::for_endpoint`], which has no context behind it
    /// (§7.3). `None` here is "this session was configured without a kubeconfig" and never "the
    /// context could not be resolved", which would have been a failure before a session existed.
    #[must_use]
    pub fn connection(&self) -> Option<&Connection> {
        self.connection.as_ref()
    }

    /// The TLS configuration, once a connection has been established (§6.3).
    #[must_use]
    pub fn tls(&self) -> Option<&TlsSettings> {
        self.tls.as_ref()
    }

    /// What protects this session, in the words §8.4 requires a diagnostic to use.
    #[must_use]
    pub fn tls_posture(&self) -> TlsPosture {
        match &self.tls {
            None => TlsPosture::None,
            Some(tls) if tls.verifies_certificates() => TlsPosture::Verified,
            Some(_) => TlsPosture::InsecureSkipVerify,
        }
    }

    /// Who the provider is to this cluster, as far as it has discovered (§8.6).
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Records the effective identity, so the next invocation does not ask again (§8.6).
    pub fn identified(&mut self, identity: Identity) {
        self.identity = identity;
    }

    /// What identifies the upstream cluster this session is connected to (§10.2).
    #[must_use]
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// The session's non-secret diagnostic (§6.3, §61.1).
    ///
    /// Built from the fields rather than accumulated beside them, so it cannot drift out of step
    /// with the session it describes — and so that there is exactly one thing to check against
    /// §6.3's last line: secret material stays outside serializable session diagnostics, and the
    /// only way in would be to add a field here.
    #[must_use]
    pub fn diagnostic(&self) -> ClusterDiagnostic {
        ClusterDiagnostic::for_instance(&self.instance, self.tls_posture())
            .with_fingerprint(self.fingerprint.clone())
            .with_identity(self.identity.clone())
    }

    // --- §10.4: the cluster behind the configuration name --------------------------------------

    /// Compares a freshly observed cluster fingerprint against this session's, and acts on it.
    ///
    /// §10.4's `MUST`, and the ordering in it is the requirement: when strong evidence changes,
    /// the cached object identities and watches of the previous cluster are invalidated *before*
    /// anything is presented as current. Doing it here — at the moment the evidence arrives,
    /// rather than at the moment somebody reads a cache — is what makes "before" mean something.
    ///
    /// What survives a replacement is the configuration: instance id, endpoint, default namespace
    /// and credential (§10.1). What does not survive is everything the *cluster* told the session
    /// — discovery, schemas, caches, watch checkpoints, effective identity and negotiated
    /// capabilities — because every one of them is a statement about a cluster that is no longer
    /// the one answering.
    pub fn observed_fingerprint(&mut self, fingerprint: Fingerprint) -> ClusterChange {
        let change = if self.fingerprint.is_empty() {
            ClusterChange::FirstObserved
        } else {
            match self.fingerprint.compare(&fingerprint).verdict() {
                Alias::Distinct => ClusterChange::Replaced,
                Alias::Possible => ClusterChange::Same,
                Alias::Undetermined => ClusterChange::Undetermined,
            }
        };
        self.fingerprint = fingerprint;

        if change.invalidated() {
            self.discovery = None;
            self.documents.clear();
            self.watches.clear();
            self.identity = Identity::unknown();
            self.capabilities.clear();
        }
        if matches!(
            change,
            ClusterChange::Replaced | ClusterChange::FirstObserved
        ) {
            // §12.4's third and fourth bullets. A GVK is unique within one cluster, so
            // `example.io/v1 Widget` elsewhere is another CRD wearing the same name.
            self.schemas
                .reconnected(&self.fingerprint.digest().unwrap_or_default());
        }
        change
    }

    // --- §11, §12: what the server serves and what it looks like -------------------------------

    /// The discovery snapshot, where one has been taken (§11.3).
    #[must_use]
    pub fn discovery(&self) -> Option<&Discovery> {
        self.discovery.as_ref()
    }

    /// Records a discovery snapshot, so the next invocation does not pay for it again (§50.2).
    pub fn discovered(&mut self, discovery: Discovery) {
        self.discovery = Some(discovery);
    }

    /// Whether discovery has to be run before this session can answer anything about types.
    ///
    /// Asked rather than inferred from a `None`, because the question a caller has is not "is
    /// there a snapshot" but "do I have to pay §50.2's cost now".
    #[must_use]
    pub fn needs_discovery(&self) -> bool {
        self.discovery.is_none()
    }

    /// One discovery document this session has already read, by the path it came from.
    ///
    /// §50.2's cost is three round trips before the first object — `/api`, `/apis` and a resource
    /// list — and they are the same three every invocation. Holding the *documents* rather than
    /// only the assembled [`Discovery`] is what lets a caller that assembles a different subset
    /// per question still pay for each document once: the snapshot a query resolves against must
    /// be built from exactly the group-versions that query searched, because §35.8's ambiguity is
    /// a property of the search space and an answer that depended on what an earlier query had
    /// fetched would not be the same answer twice.
    ///
    /// The path is the key because the path is what identifies the document to the server. A
    /// document cached under a group-version would need a second rule for `/api` and `/apis`,
    /// which name no group-version at all.
    ///
    /// It answers nothing once the document has passed [`DISCOVERY_VALIDITY`] or something this
    /// session did made it stale, which is how §11.4's refresh reaches every caller without any
    /// of them having to ask for one: a caller that needs discovery calls this, gets nothing,
    /// reads the document from the API server, and hands it back through
    /// [`Self::cache_discovery_document`] — where the comparison against what it replaced is what
    /// §33.2's detection is made of.
    #[must_use]
    pub fn discovery_document(&self, path: &str) -> Option<&str> {
        let held = self.documents.get(path)?;
        if held.stale || self.expired(held.observed_at) {
            return None;
        }
        Some(held.text.as_str())
    }

    /// Whether a document read at that instant has passed its validity window (§11.4, §16.2).
    fn expired(&self, observed_at: ObservedAt) -> bool {
        let age = self
            .clock
            .now()
            .unix_millis()
            .saturating_sub(observed_at.unix_millis());
        u128::from(age) >= DISCOVERY_VALIDITY.as_millis()
    }

    /// Remembers a discovery document, so the next invocation does not fetch it again (§50.2).
    ///
    /// **A document that replaces a different one is an observation, and this is where it is
    /// read.** §33.2 asks the provider to detect a CRD added, a served version added or removed,
    /// a storage version changed, a schema changed and a CRD deleted, "through discovery/schema
    /// invalidation and relevant watches where active". A refreshed discovery document is the
    /// discovery half of that sentence and the only half that needs nobody to be watching
    /// anything: the API server has just restated what it serves, and the difference from what it
    /// said last time is the event. §12.4's first two bullets — CRD updates, API group/version
    /// changes — are then applied at the narrowest grain the difference supports, because a
    /// refresh that emptied the schema cache would make every CRD anybody installs cost every
    /// session its schemas.
    ///
    /// Nothing here re-derives what a *query* would answer. The four outcomes of §11.5 — not
    /// served, not listable, ambiguous, empty — are resolved against whatever snapshot exists at
    /// the moment the question is asked, and a refresh only decides which snapshot that is.
    pub fn cache_discovery_document(
        &mut self,
        path: impl Into<String>,
        document: impl Into<String>,
    ) {
        let path = path.into();
        let document = document.into();
        if let Some(previous) = self
            .documents
            .get(&path)
            .filter(|held| held.text != document)
            .map(|held| held.text.clone())
        {
            self.refreshed(&path, &previous, &document);
        }
        let observed_at = self.clock.now();
        self.documents.insert(
            path,
            Document {
                text: document,
                observed_at,
                stale: false,
            },
        );
    }

    /// Applies what a document that replaced a different one says about this session's caches.
    fn refreshed(&mut self, path: &str, before: &str, after: &str) {
        // The assembled snapshot is a function of the documents, so it goes with the one that
        // moved. It is rebuilt from the documents the next question needs, which is the same
        // thing §11.3 means by a snapshot being one observation rather than an accumulation.
        self.discovery = None;
        match DocumentKind::of(path) {
            Some(DocumentKind::CoreVersions) => self.core_versions_refreshed(before, after),
            Some(DocumentKind::Groups) => self.groups_refreshed(before, after),
            Some(DocumentKind::ResourceList) => self.resource_list_refreshed(before, after),
            None => {}
        }
    }

    /// What a refreshed `/api` says: a core version this cluster no longer serves (§12.4).
    fn core_versions_refreshed(&mut self, before: &str, after: &str) {
        let (Some(before), Some(after)) = (core_versions(before), core_versions(after)) else {
            return;
        };
        let after = after.versions_of("");
        for version in before.versions_of("") {
            if !after.contains(&version) {
                self.group_version_changed("", &version);
            }
        }
    }

    /// What a refreshed `/apis` says: a group withdrawn, or a version it stopped serving (§33.2).
    fn groups_refreshed(&mut self, before: &str, after: &str) {
        let (Some(before), Some(after)) = (groups(before), groups(after)) else {
            return;
        };
        let served: BTreeSet<&str> = after.groups().collect();
        let withdrawn: Vec<String> = before
            .groups()
            .filter(|group| !served.contains(group))
            .map(str::to_owned)
            .collect();
        let dropped: Vec<(String, String)> = before
            .groups()
            .filter(|group| served.contains(group))
            .flat_map(|group| {
                let still = after.versions_of(group);
                before
                    .versions_of(group)
                    .into_iter()
                    .filter(move |version| !still.contains(version))
                    .map(move |version| (group.to_owned(), version))
            })
            .collect();
        for group in withdrawn {
            self.group_withdrawn(&group);
        }
        for (group, version) in dropped {
            self.group_version_changed(&group, &version);
        }
    }

    /// What a refreshed resource list says: which kinds the server now describes differently.
    ///
    /// Per kind, and never per group-version. A CRD installed beside two that were already there
    /// changes the document and invalidates nothing — every schema this session holds is still
    /// about a kind the server still serves exactly as it did — and §33.1's "a newly installed
    /// CRD MUST be discoverable without rebuilding Ono" is answered by the new document itself
    /// rather than by throwing away the old one's neighbours.
    fn resource_list_refreshed(&mut self, before: &str, after: &str) {
        let (Some(before), Some(after)) = (resources(before), resources(after)) else {
            return;
        };
        let restated: Vec<Gvk> = before
            .all()
            .filter(|resource| {
                after.all().find(|other| other.gvk() == resource.gvk()) != Some(*resource)
            })
            .map(|resource| resource.gvk().clone())
            .collect();
        for gvk in restated {
            self.crd_updated(&gvk);
        }
    }

    /// Stops every discovery document answering, and keeps every one of them as a baseline.
    fn mark_documents_stale(&mut self) {
        for document in self.documents.values_mut() {
            document.stale = true;
        }
    }

    /// How many discovery documents this session holds.
    ///
    /// A count rather than an iterator: the question a caller has is whether §50.2's cost has
    /// already been paid, and handing out the documents would invite a second assembler.
    #[must_use]
    pub fn discovery_documents(&self) -> usize {
        self.documents
            .values()
            .filter(|held| !held.stale && !self.expired(held.observed_at))
            .count()
    }

    /// The schemas held for this cluster (§12.4).
    #[must_use]
    pub fn schemas(&self) -> &SchemaCache {
        &self.schemas
    }

    /// One cached schema, where it is still valid.
    #[must_use]
    pub fn schema(&self, gvk: &Gvk) -> Option<&Schema> {
        self.schemas.get(gvk)
    }

    /// Remembers a schema for this cluster.
    pub fn cache_schema(&mut self, gvk: Gvk, schema: Schema) {
        self.schemas.insert(gvk, schema);
    }

    /// Forgets a kind's schema, for a CRD whose structural schema changed (§12.4, §33.2).
    pub fn crd_updated(&mut self, gvk: &Gvk) {
        self.schemas.invalidate(gvk);
    }

    /// Forgets one group/version, and the discovery snapshot that described it (§12.4, §11.4).
    ///
    /// Both, because they are one fact seen from two sides: a served version that appeared,
    /// vanished or changed makes the resource list that named it a claim about a cluster which
    /// has moved on. Keeping a resource list that no longer matches the schemas beside it is how
    /// a kind comes to be addressed at a version the server stopped serving.
    pub fn group_version_changed(&mut self, group: &str, version: &str) {
        self.schemas.invalidate_group_version(group, version);
        self.discovery = None;
        // Every document rather than that group-version's: `/apis` names which versions are
        // served and which one is preferred, so a change to one of them makes the group list a
        // claim about a cluster that has moved on. Keeping it and dropping only the resource list
        // is how a kind comes to be addressed at a version the server stopped serving.
        //
        // Marked rather than dropped: none of them may answer again, and each is still the
        // baseline the next read of its own path is compared against (§33.2).
        self.mark_documents_stale();
    }

    /// Forgets a whole group, for a CRD deleted or an API group withdrawn (§12.4, §11.5).
    pub fn group_withdrawn(&mut self, group: &str) {
        self.schemas.invalidate_group(group);
        self.discovery = None;
        self.mark_documents_stale();
    }

    // --- §20.5 and generic §16.5: what a successful write makes this session forget -------------

    /// Invalidates what a successful write to one object made this session's caches wrong about.
    ///
    /// §20.5 and §16.5 of the generic provider contract are one requirement seen twice: after a
    /// successful mutation the provider invalidates or marks stale the cached facts the change
    /// could have reached, and it never shows known-stale pre-change state as if it had just been
    /// confirmed. A session that has watched a collection holds exactly such a cache, and
    /// [`Self::lookup`] answers from it with `origin=cache` — a *confirmed observation* of a
    /// cluster this session itself knows it has changed.
    ///
    /// **The cache entry is dropped, and nothing is put in its place.** §20.5's `MUST NOT` is
    /// about the tempting alternative: writing the applied document into the cache, where it
    /// would be served as a server observation of an object no server ever returned. Removing
    /// only the object would be the same mistake wearing the other face, because a live cache
    /// that no longer holds a name answers [`Lookup::ConfirmedAbsent`] — a write reported as
    /// having deleted what it changed (§4 invariant 13). Dropping the collection entry answers
    /// [`Lookup::NotWatched`], which is true the moment it becomes true: this session knows
    /// nothing about that collection, and the next read goes to the API server.
    ///
    /// **"Potentially affected" is answered narrowly, and the limit is stated rather than hidden.**
    /// Every watched scope that could be holding this object is invalidated — the namespace it is
    /// in, and any cluster-wide or all-namespaces watch over the same collection — because each of
    /// those caches certainly held the pre-change object. Its *dependents* are not: a deletion
    /// with `Foreground` or `Background` propagation reaches objects this provider never learnt
    /// the identity of, because neither the delete response nor the `Status` that may replace it
    /// names one (§45.2, §45.5). Invalidating every cache in the session on the chance that one of
    /// them holds a dependent would spend §50.2's cost on collections the write demonstrably did
    /// not touch, in exchange for a guess. So the caches of dependents are left alone and stay
    /// what they were — observations of a moment before the deletion, carrying their own
    /// `observed_at` and their own `origin=cache` (§20.2) — and the record of the change says so.
    ///
    /// A write to `customresourcedefinitions` reaches one thing more: what the cluster serves.
    /// That is §33.2's "CRD added" and "CRD deleted" observed at the one place a provider can be
    /// certain of them, and it marks the discovery documents stale rather than dropping them, so
    /// that the refreshed ones can still be compared against what they replace.
    pub fn mutated(&mut self, gvr: &Gvr, namespace: Option<&str>) -> Invalidation {
        let collections: Vec<(Gvr, Scope)> = self
            .watches
            .keys()
            .filter(|(watched, scope)| watched == gvr && could_hold(scope, namespace))
            .cloned()
            .collect();
        for key in &collections {
            self.watches.remove(key);
        }
        let serves = defines_resources(gvr);
        if serves {
            self.discovery = None;
            self.mark_documents_stale();
        }
        Invalidation {
            collections,
            discovery: serves,
        }
    }

    // --- §6.3: negotiated capabilities ----------------------------------------------------------

    /// Records that the server offers a capability, and this session may use it (§19.2).
    pub fn negotiate(&mut self, capability: Capability) {
        self.capabilities.insert(capability);
    }

    /// Whether a capability was negotiated with the cluster currently connected.
    #[must_use]
    pub fn negotiated(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Every capability negotiated, in a fixed order.
    #[must_use]
    pub fn capabilities(&self) -> Vec<Capability> {
        self.capabilities.iter().copied().collect()
    }

    // --- §19, §20: watches and the caches they keep true -----------------------------------------

    /// The watch over one collection and scope, opened on demand (§19.6).
    ///
    /// Demand-driven rather than fanned out over everything discovered: §19.6 says watching every
    /// GVR in a large cluster is expensive and not required, and a session that opened one per
    /// discovered resource would be the most expensive thing this provider does.
    pub fn watch(&mut self, gvr: &Gvr, scope: &Scope) -> &mut WatchStream {
        let instance = self.instance.clone();
        let now = self.clock.now();
        &mut self
            .watches
            .entry((gvr.clone(), scope.clone()))
            .or_insert_with(|| Watched {
                stream: WatchStream::new(gvr.clone(), scope.clone()),
                decoder: WatchDecoder::new(instance),
                observed_at: now,
            })
            .stream
    }

    /// The watch over one collection and scope, where this session holds one.
    #[must_use]
    pub fn watch_stream(&self, gvr: &Gvr, scope: &Scope) -> Option<&WatchStream> {
        self.watches
            .get(&(gvr.clone(), scope.clone()))
            .map(|watched| &watched.stream)
    }

    /// When this session last observed the collection one watch covers, on its own clock.
    ///
    /// The only provider-clock fact a stream has. `watch.rs` records which change arrived and in
    /// what order and keeps no arrival instant, so this is the moment of the most recent
    /// observation of the collection — the listing that seeded the cache, or the last event
    /// applied to it (§20.2).
    ///
    /// It is what a temporal answer widens its window back to: a timeline assembled now, over a
    /// collection this session has been watching, covers a period that began before the read
    /// (§39.3). Never a substitute for a per-event time, which does not exist.
    #[must_use]
    pub fn watch_observed_at(&self, gvr: &Gvr, scope: &Scope) -> Option<ObservedAt> {
        self.watches
            .get(&(gvr.clone(), scope.clone()))
            .map(|watched| watched.observed_at)
    }

    /// Every collection this session is watching.
    #[must_use]
    pub fn watched(&self) -> Vec<(&Gvr, &Scope)> {
        self.watches
            .keys()
            .map(|(gvr, scope)| (gvr, scope))
            .collect()
    }

    /// Releases a watch that no longer serves a consumer (§19.7).
    ///
    /// Returns whether there was one. Releasing a watch nobody holds is neither an error nor an
    /// achievement, and a caller closing the last of several live views should not have to know
    /// which one it was.
    pub fn release_watch(&mut self, gvr: &Gvr, scope: &Scope) -> bool {
        self.watches.remove(&(gvr.clone(), scope.clone())).is_some()
    }

    /// Closes a live view, releasing its watch when nothing else is served by it (§19.7).
    ///
    /// The rule §19.7 states has a qualifier, and the qualifier is the whole of it: a closing view
    /// releases the watches that "no longer serve **another active consumer**". This session has
    /// exactly one other consumer of a watch, and it is not a second stream — it is [`Self::lookup`].
    /// §20.2 makes `origin=cache` a first-class answer a later read may be given, and §20.3 lets a
    /// synchronised stream report an absence *as* an absence. A stream that can still do either is
    /// serving a consumer; one that cannot is holding a checkpoint the API server has already
    /// discarded and a set of objects nothing is keeping true.
    ///
    /// So the question this asks is the same question [`Self::lookup`] asks, and asking it here
    /// rather than in the caller is what keeps the two from drifting: a view that released a cache
    /// still entitled to answer would make §20.2's cache origin unreachable in practice, and one
    /// that released nothing would be `release_watch` never being called at all.
    ///
    /// Returns whether the watch was released.
    pub fn close_view(&mut self, gvr: &Gvr, scope: &Scope) -> bool {
        let Some(watched) = self.watches.get(&(gvr.clone(), scope.clone())) else {
            return false;
        };
        if watched.stream.absence_is_conclusive() {
            return false;
        }
        self.release_watch(gvr, scope)
    }

    /// Seeds or re-acquires a watched cache from a completed listing (§19.1, §20.3).
    ///
    /// # Errors
    ///
    /// [`SyncRefused`] when the listing is not a snapshot a cache may stand on. A listing that
    /// lost a page is a perfectly legitimate answer to a query — §18.3 says so — and a perfectly
    /// illegitimate cache: every object it was refused would then be reported as absent by
    /// [`Self::lookup`], which is §4 invariant 13's collapse arrived at through the back door.
    pub fn synchronise(
        &mut self,
        gvr: &Gvr,
        scope: &Scope,
        listing: Listing,
    ) -> Result<(), SyncRefused> {
        let Some(version) = listing.resource_version().map(ResourceVersion::new) else {
            return Err(SyncRefused::NoCollectionVersion);
        };
        if !listing.coverage().is_complete() {
            return Err(SyncRefused::IncompleteCoverage);
        }
        if !listing.continuity().is_intact() {
            return Err(SyncRefused::BrokenContinuity);
        }
        let observed_at = listing.freshness().observed_at();
        let objects = listing.into_objects();

        let instance = self.instance.clone();
        let watched = self
            .watches
            .entry((gvr.clone(), scope.clone()))
            .or_insert_with(|| Watched {
                stream: WatchStream::new(gvr.clone(), scope.clone()),
                decoder: WatchDecoder::new(instance),
                observed_at,
            });
        watched.stream.listed(objects, version);
        watched.observed_at = observed_at;
        Ok(())
    }

    /// Applies the bytes of a watch response to the cache they belong to (§19.3).
    ///
    /// The chunk is whatever [`crate::transport::ResponseStream::next_chunk`] handed over. It is
    /// not a frame and it is not expected to be one: HTTP chunked framing and the newline framing
    /// of a watch body are unrelated, so a chunk boundary lands mid-object as a matter of course
    /// and the decoder holds the remainder until the rest arrives.
    ///
    /// # Errors
    ///
    /// [`FrameError`] when a whole frame could not be read. A caller should treat that as a break
    /// in continuity rather than resuming: the events after an unreadable one are a history with
    /// a hole in it.
    pub fn feed_watch(
        &mut self,
        gvr: &Gvr,
        scope: &Scope,
        chunk: &[u8],
    ) -> Result<Vec<Reception>, FrameError> {
        let now = self.clock.now();
        let instance = self.instance.clone();
        let watched = self
            .watches
            .entry((gvr.clone(), scope.clone()))
            .or_insert_with(|| Watched {
                stream: WatchStream::new(gvr.clone(), scope.clone()),
                decoder: WatchDecoder::new(instance),
                observed_at: now,
            });
        let events = watched.decoder.decode(chunk)?;
        let mut receptions = Vec::with_capacity(events.len());
        for event in events {
            let reception = watched.stream.observe(event);
            if reception != Reception::Discarded {
                // The cache is current as of the moment this provider read the event, never as of
                // any timestamp inside the object: §14.3 keeps `resourceVersion` from being a
                // clock, and `creationTimestamp` is about the object rather than the observation.
                watched.observed_at = now;
            }
            receptions.push(reception);
        }
        Ok(receptions)
    }

    /// What this session's caches can say about one namespace and name (§20.2, §20.3).
    ///
    /// The whole of §20.2's requirement in one call: a hit comes back as a [`Read`] whose
    /// freshness says [`crate::transport::Origin::Cache`], carries the observation time of the
    /// read that filled the cache rather than the moment of the hit, and states whether a watch
    /// was keeping it true. A miss is only [`Lookup::ConfirmedAbsent`] while the cache is live —
    /// before synchronisation, and after continuity broke, absence in the cache is absence of
    /// observation (§20.3).
    #[must_use]
    pub fn lookup(&self, gvr: &Gvr, scope: &Scope, namespace: Option<&str>, name: &str) -> Lookup {
        let Some(watched) = self.watches.get(&(gvr.clone(), scope.clone())) else {
            return Lookup::NotWatched;
        };
        if !watched.stream.absence_is_conclusive() {
            // The same gate for a hit as for a miss. A quarantined cache still holds objects and
            // they were true once, but a value served from it would claim to be a current
            // observation of a stream that has stopped (§19.4 step 2).
            return Lookup::NotSynced(watched.stream.state());
        }
        match watched.stream.find(namespace, name) {
            None => Lookup::ConfirmedAbsent,
            Some(object) => Lookup::Cached(Box::new(Read::new(
                object.clone(),
                Freshness::cached(
                    watched.observed_at,
                    object.resource_version().map(str::to_owned),
                    &self.instance,
                    scope.clone(),
                    EndpointCategory::of(gvr),
                    watched.stream.has_synced(),
                ),
            ))),
        }
    }
}

/// Which of the three discovery documents a path names.
///
/// From the path rather than from the document's own `kind`, because the path is what identifies
/// the document to the server and is the only thing available before it parses. Anything else —
/// an OpenAPI document, an aggregated discovery response — is `None`, and a change to it teaches
/// this session nothing it could act on narrowly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentKind {
    /// `/api`, the core group's version list.
    CoreVersions,
    /// `/apis`, the named group list.
    Groups,
    /// `/api/v1` or `/apis/<group>/<version>`, one group-version's resource list.
    ResourceList,
}

impl DocumentKind {
    fn of(path: &str) -> Option<Self> {
        match path {
            "/api" => Some(Self::CoreVersions),
            "/apis" => Some(Self::Groups),
            _ => {
                let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                match segments.as_slice() {
                    ["api", _] | ["apis", _, _] => Some(Self::ResourceList),
                    _ => None,
                }
            }
        }
    }
}

/// `/api`, read far enough to compare two of them. A document that does not read teaches nothing.
fn core_versions(document: &str) -> Option<Discovery> {
    Discovery::builder()
        .core_versions(document)
        .ok()
        .map(crate::discovery::Builder::build)
}

/// `/apis`, read far enough to compare two of them.
fn groups(document: &str) -> Option<Discovery> {
    Discovery::builder()
        .groups(document)
        .ok()
        .map(crate::discovery::Builder::build)
}

/// One resource list, read far enough to compare two of them.
fn resources(document: &str) -> Option<Discovery> {
    Discovery::builder()
        .resources(document)
        .ok()
        .map(crate::discovery::Builder::build)
}

/// Whether a watch over that scope could have been holding an object in that namespace.
///
/// A watch with no namespace is a cluster-scoped or all-namespaces one, and both of them hold
/// every object of their collection; a namespaced watch holds exactly its own. Erring towards
/// `true` is the safe direction here and nowhere else in this module: a cache invalidated for
/// nothing costs a round trip, and a cache left alone that should not have been costs the truth.
fn could_hold(scope: &Scope, namespace: Option<&str>) -> bool {
    match scope.namespace() {
        None => true,
        Some(watched) => Some(watched) == namespace,
    }
}

/// Whether writing to this collection changes what the cluster serves (§33.2).
///
/// Matched on group and resource and never on version: §5.3 forbids assuming which version of an
/// API a cluster serves, and `apiextensions.k8s.io/v1beta1` defines resources exactly as
/// `apiextensions.k8s.io/v1` does.
fn defines_resources(gvr: &Gvr) -> bool {
    gvr.group() == "apiextensions.k8s.io" && gvr.resource() == "customresourcedefinitions"
}

impl<C: Clock> fmt::Debug for Session<C> {
    /// Names what the session holds and never the material it holds it with (§6.3, §8.1).
    ///
    /// Written by hand rather than derived. A derived `Debug` is correct today only because every
    /// field below happens to redact itself, and the rule in §8.1 is exactly the kind a future
    /// field breaks silently — the leak appears in the first log line somebody writes and stays
    /// invisible until someone reads it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("instance", &self.instance)
            .field("endpoint", &self.endpoint)
            .field("namespace", &self.namespace)
            .field("credential", &self.credential)
            .field("tls", &self.tls_posture().as_str())
            .field("identity", &self.identity)
            .field("fingerprint", &self.fingerprint.obtained_signals())
            .field("discovery", &self.discovery.is_some())
            .field("discovery_documents", &self.discovery_documents())
            .field("schemas", &self.schemas.len())
            .field("watches", &self.watches.len())
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

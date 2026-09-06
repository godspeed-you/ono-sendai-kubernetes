//! What a provider instance holds between two invocations, and what it must forget.
//!
//! Specification §6.3 (what a session is), §6.4 (lazy connection), §6.5 (multiple clusters),
//! §10.4 (cluster replacement), §12.4 (schema cache invalidation), §19 (watch), §20.1–§20.3
//! (cache classes, freshness, informer sync) and §50.2 (discovery is not free).
//!
//! The absence these tests exist to close is a structural one rather than a bug: with no session,
//! every invocation re-resolved the endpoint, re-ran discovery and re-fetched the OpenAPI
//! document, `SchemaCache` was written and never used, §10.4 had no cache to invalidate, and
//! §20.2's "cached or direct?" could not be answered because nothing was ever cached. So most of
//! what is asserted here is that a fact *survives* a call — and, just as often, that it does not
//! survive the one event that makes it a lie.
//!
//! Nothing here opens a socket. A watch is driven by handing the session the bytes a recorded
//! response would have delivered (§59.1).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::time::Duration;

use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::diagnostics::{
    Fingerprint, Identity, Known, Subject, TlsPosture, normalised_origin,
};
use ono_provider_kubernetes::discovery::{Discovery, Gvk, Gvr};
use ono_provider_kubernetes::kubeconfig::{Connection, Credential, Kubeconfig};
use ono_provider_kubernetes::schema::Schema;
use ono_provider_kubernetes::session::{
    Capability, ClusterChange, DISCOVERY_VALIDITY, Lookup, Session, SyncRefused,
};
use ono_provider_kubernetes::tls::{Anchors, TlsSettings};
use ono_provider_kubernetes::transport::{
    Client, Clock, FixedClock, FixtureStream, ListOptions, Listing, ObservedAt, Origin,
};
use ono_provider_kubernetes::watch::SyncState;

const HOST: &str = "dev.example.test";
const OBSERVED: u64 = 1_700_000_000_000;
const TOKEN: &str = "dev-secret-token-9f2c";

/// Two contexts against two clusters — the shape §6.5's isolation rules are about.
const KUBECONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: dev
clusters:
  - name: dev-cluster
    cluster:
      server: https://dev.example.test:6443
  - name: prod-cluster
    cluster:
      server: https://prod.example.test:6443
users:
  - name: dev-user
    user:
      token: dev-secret-token-9f2c
  - name: prod-user
    user:
      token: prod-secret-token-4a71
contexts:
  - name: dev
    context:
      cluster: dev-cluster
      user: dev-user
      namespace: shop
  - name: prod
    context:
      cluster: prod-cluster
      user: prod-user
      namespace: billing
"#;

fn connection(context: &str) -> Connection {
    Kubeconfig::parse(KUBECONFIG)
        .expect("the kubeconfig parses")
        .connection(context)
        .expect("the context is in the file")
}

fn clock() -> FixedClock {
    FixedClock::at_unix_millis(OBSERVED)
}

fn session(context: &str) -> Session<FixedClock> {
    Session::with_clock(connection(context), clock())
}

fn pods() -> Gvr {
    Gvr::new("", "v1", "pods")
}

fn shop() -> Scope {
    Scope::in_namespace("shop")
}

/// `/api` and `/api/v1`, trimmed to what a session has to remember.
const CORE_VERSIONS: &str = r#"{"kind":"APIVersions","versions":["v1"]}"#;
const CORE_V1: &str = r#"{
  "kind": "APIResourceList",
  "groupVersion": "v1",
  "resources": [
    {"name":"pods","singularName":"pod","namespaced":true,"kind":"Pod",
     "verbs":["get","list","watch"],"shortNames":["po"]}
  ]
}"#;

fn discovered() -> Discovery {
    Discovery::builder()
        .core_versions(CORE_VERSIONS)
        .expect("the core version list reads")
        .resources(CORE_V1)
        .expect("the core resource list reads")
        .build()
}

fn pod_gvk() -> Gvk {
    Gvk::new("", "v1", "Pod")
}

fn fingerprint(origin: &str, kube_system_uid: Option<&str>) -> Fingerprint {
    let mut print = Fingerprint::unknown().with_origin(Known::Obtained(origin.to_owned()));
    if let Some(uid) = kube_system_uid {
        print = print.with_kube_system_uid(Known::Obtained(uid.to_owned()));
    }
    print
}

fn dev_origin() -> String {
    normalised_origin("https", "dev.example.test", 6443)
}

/// A `200 OK` response with the body a collection read returns.
fn ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn pod_item(name: &str, uid: &str, resource_version: &str) -> String {
    format!(
        r#"{{"metadata":{{"name":"{name}","namespace":"shop","uid":"{uid}","resourceVersion":"{resource_version}"}}}}"#
    )
}

/// A whole collection, read the way the provider reads one.
fn listing_of(responses: &[String]) -> Listing {
    let mut client = Client::with_clock(
        FixtureStream::replaying(responses),
        HOST,
        "kubernetes:dev",
        clock(),
    );
    client.list(&pods(), &shop(), &ListOptions::new())
}

/// One page holding one Pod, complete and continuous.
fn one_pod_listing() -> Listing {
    listing_of(&[ok(&format!(
        r#"{{"apiVersion":"v1","kind":"PodList","metadata":{{"resourceVersion":"18010"}},
            "items":[{}]}}"#,
        pod_item("checkout-1", "uid-1", "18005")
    ))])
}

/// One watch frame, as the API server writes it.
fn frame(class: &str, object: &str) -> String {
    format!(r#"{{"type":"{class}","object":{object}}}"#) + "\n"
}

fn pod_frame_object(name: &str, uid: &str, resource_version: &str) -> String {
    format!(
        r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"{name}","namespace":"shop","uid":"{uid}","resourceVersion":"{resource_version}"}}}}"#
    )
}

/// The collection identities and kinds the invalidation tests are written against.
fn configmaps() -> Gvr {
    Gvr::new("", "v1", "configmaps")
}

/// The collection a write to which changes what the whole cluster serves (§33.2).
fn crds() -> Gvr {
    Gvr::new("apiextensions.k8s.io", "v1", "customresourcedefinitions")
}

fn widget_gvk() -> Gvk {
    Gvk::new("example.io", "v1", "Widget")
}

fn gadget_gvk() -> Gvk {
    Gvk::new("example.io", "v1", "Gadget")
}

fn nebula_gvk() -> Gvk {
    Gvk::new("astro.example.dev", "v1", "Nebula")
}

/// One object, listed under the collection identity and scope a test names.
///
/// `one_pod_listing` fixes both, which is what the freshness assertions around it need; an
/// invalidation test needs several collections and several scopes in one session, because the
/// whole question is which of them a write reaches.
fn one_object_listing(gvr: &Gvr, scope: &Scope, namespace: &str) -> Listing {
    // `<Kind>List`, not the generic `List` this fixture used to send. A collection endpoint
    // names the kind its items are of, and since ADR-0046 this provider requires it to: the kind
    // is what §22's protection is keyed on, so an envelope that names none is one the items'
    // redaction cannot be decided from (`transport::identify`).
    let kind = match gvr.resource() {
        "pods" => "Pod",
        "configmaps" => "ConfigMap",
        other => panic!("this fixture does not know the kind of `{other}`"),
    };
    let body = format!(
        r#"{{"apiVersion":"v1","kind":"{kind}List","metadata":{{"resourceVersion":"18010"}},
            "items":[{{"metadata":{{"name":"one","namespace":"{namespace}","uid":"uid-one",
            "resourceVersion":"18005"}}}}]}}"#
    );
    let mut client = Client::with_clock(
        FixtureStream::replaying(&[ok(&body)]),
        HOST,
        "kubernetes:dev",
        clock(),
    );
    client.list(gvr, scope, &ListOptions::new())
}

/// A clock a test moves by hand, for the one behaviour that is about time passing.
///
/// [`FixedClock`] cannot express it: a validity window is the difference between two instants,
/// and a clock that answers one instant makes every document eternally fresh — which is the
/// behaviour these tests exist to disprove.
#[derive(Debug, Clone)]
struct SteppingClock {
    at: std::rc::Rc<std::cell::Cell<u64>>,
}

impl SteppingClock {
    fn at(unix_millis: u64) -> Self {
        Self {
            at: std::rc::Rc::new(std::cell::Cell::new(unix_millis)),
        }
    }

    fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.at.set(self.at.get().saturating_add(by));
    }
}

impl Clock for SteppingClock {
    fn now(&self) -> ObservedAt {
        ObservedAt::from_unix_millis(self.at.get())
    }
}

/// `/apis`, from a cluster serving a custom group at two versions beside an unrelated one.
const APIS_WITH_WIDGETS: &str = r#"{"kind":"APIGroupList","groups":[
  {"name":"example.io",
   "versions":[{"groupVersion":"example.io/v1","version":"v1"},
               {"groupVersion":"example.io/v2","version":"v2"}],
   "preferredVersion":{"groupVersion":"example.io/v2","version":"v2"}},
  {"name":"astro.example.dev",
   "versions":[{"groupVersion":"astro.example.dev/v1","version":"v1"}],
   "preferredVersion":{"groupVersion":"astro.example.dev/v1","version":"v1"}}]}"#;

/// The same `/apis`, after the CRD behind `example.io` was deleted.
const APIS_WITHOUT_WIDGETS: &str = r#"{"kind":"APIGroupList","groups":[
  {"name":"astro.example.dev",
   "versions":[{"groupVersion":"astro.example.dev/v1","version":"v1"}],
   "preferredVersion":{"groupVersion":"astro.example.dev/v1","version":"v1"}}]}"#;

/// The same `/apis`, after `example.io/v1` stopped being served.
const APIS_WIDGETS_V2_ONLY: &str = r#"{"kind":"APIGroupList","groups":[
  {"name":"example.io",
   "versions":[{"groupVersion":"example.io/v2","version":"v2"}],
   "preferredVersion":{"groupVersion":"example.io/v2","version":"v2"}},
  {"name":"astro.example.dev",
   "versions":[{"groupVersion":"astro.example.dev/v1","version":"v1"}],
   "preferredVersion":{"groupVersion":"astro.example.dev/v1","version":"v1"}}]}"#;

/// `/apis/example.io/v1`, as the CRD first published it.
const WIDGETS_V1: &str = r#"{"kind":"APIResourceList","groupVersion":"example.io/v1","resources":[
  {"name":"widgets","kind":"Widget","namespaced":true,"verbs":["get","list","watch"]},
  {"name":"gadgets","kind":"Gadget","namespaced":true,"verbs":["get","list","watch"]}]}"#;

/// The same list, after the CRD behind `Widget` was updated and the kind gained a verb.
const WIDGETS_V1_PATCHABLE: &str = r#"{"kind":"APIResourceList","groupVersion":"example.io/v1","resources":[
  {"name":"widgets","kind":"Widget","namespaced":true,"verbs":["get","list","watch","patch"]},
  {"name":"gadgets","kind":"Gadget","namespaced":true,"verbs":["get","list","watch"]}]}"#;

/// The same list, after a CRD was installed beside the two that were already there.
const WIDGETS_V1_WITH_SPROCKET: &str = r#"{"kind":"APIResourceList","groupVersion":"example.io/v1","resources":[
  {"name":"widgets","kind":"Widget","namespaced":true,"verbs":["get","list","watch"]},
  {"name":"gadgets","kind":"Gadget","namespaced":true,"verbs":["get","list","watch"]},
  {"name":"sprockets","kind":"Sprocket","namespaced":true,"verbs":["get","list","watch"]}]}"#;

// --- §6.3: what a session is ---------------------------------------------------------------------

#[test]
fn should_hold_the_connection_facts_section_6_3_names() {
    // §6.3 lists what a session is, and the list is the test: endpoint, TLS, credential source,
    // identity, discovery snapshot, schema snapshot, watch/cache state, default namespace and
    // negotiated capabilities. A "session" that held only a socket would satisfy the word and
    // none of the sentence, and every one of these is a fact the provider re-derived per call
    // before this type existed.
    let mut session = session("dev");

    assert_eq!(session.instance(), "kubernetes:dev");
    assert_eq!(session.endpoint(), "https://dev.example.test:6443");
    assert_eq!(session.credential(), Credential::BearerToken);
    assert_eq!(session.namespace(), Some("shop"));
    assert_eq!(session.tls_posture(), TlsPosture::None);
    assert!(!session.identity().credential().is_obtained());
    assert!(session.discovery().is_none());
    assert!(session.schemas().is_empty());
    assert!(session.watched().is_empty());
    assert!(session.capabilities().is_empty());

    session.identified(
        Identity::unknown().with_effective(Known::Obtained(Subject::new(
            "dev-user",
            None,
            Vec::new(),
        ))),
    );
    assert_eq!(
        session
            .identity()
            .effective()
            .obtained()
            .map(Subject::username),
        Some("dev-user"),
        "§8.6: the effective identity is discovered once and kept, not asked for per query"
    );
}

#[test]
fn should_start_a_session_without_contacting_the_cluster() {
    // §6.4: loading Ono or discovering the package MUST NOT contact every configured cluster.
    // The proof available to a test with no network is stronger than a mocked one: a new session
    // knows nothing the cluster could have told it, and says so as "not yet asked" rather than as
    // an empty answer.
    let session = session("prod");

    assert!(session.needs_discovery());
    assert!(session.discovery().is_none());
    assert!(session.fingerprint().is_empty());
    assert!(session.tls().is_none());
    assert_eq!(session.watched().len(), 0);
}

#[test]
fn should_answer_a_second_query_from_the_discovery_the_first_one_paid_for() {
    // §50.2: discovery is a real cost, and it was being paid on every invocation because nothing
    // outlived one. A session that holds the snapshot answers the second question for free — and
    // `needs_discovery` is what a caller asks instead of re-fetching to find out.
    let mut session = session("dev");
    assert!(session.needs_discovery());

    session.discovered(discovered());

    assert!(!session.needs_discovery());
    assert_eq!(
        session
            .discovery()
            .and_then(|discovery| discovery.resource("v1", "pods"))
            .map(|resource| resource.kind()),
        Some("Pod"),
        "the snapshot answers the second query without a second round trip"
    );
}

// --- §12.4: the schema cache is used, and invalidated -------------------------------------------

#[test]
fn should_keep_a_schema_between_invocations_and_forget_it_when_its_crd_changes() {
    // §12.4: schema documents may be cached, and invalidation MUST account for CRD updates.
    // `SchemaCache` was written and never used, which made both halves vacuous: a cache nobody
    // holds is never stale. The plausible mistake once it is held is to leave it alone — a CRD
    // whose schema changed keeps serving fields that no longer exist.
    let mut session = session("dev");
    let widget = Gvk::new("example.io", "v1", "Widget");
    session.cache_schema(widget.clone(), Schema::absent());

    assert!(session.schema(&widget).is_some());

    session.crd_updated(&widget);

    assert!(
        session.schema(&widget).is_none(),
        "an updated CRD invalidates the schema it described"
    );
}

#[test]
fn should_forget_a_group_version_whose_served_versions_changed() {
    // §12.4's second bullet. A group/version change also makes the discovery snapshot a claim
    // about a cluster that has moved on, so the session asks for discovery again — the mistake
    // being to invalidate the schema and keep serving from a resource list that no longer
    // matches it.
    let mut session = session("dev");
    session.discovered(discovered());
    session.cache_schema(Gvk::new("example.io", "v1", "Widget"), Schema::absent());
    session.cache_schema(Gvk::new("example.io", "v2", "Widget"), Schema::absent());

    session.group_version_changed("example.io", "v1");

    assert!(
        session
            .schema(&Gvk::new("example.io", "v1", "Widget"))
            .is_none()
    );
    assert!(
        session
            .schema(&Gvk::new("example.io", "v2", "Widget"))
            .is_some(),
        "only the version that changed is forgotten"
    );
    assert!(session.needs_discovery());
}

// --- §10.4: the cluster behind the name changed --------------------------------------------------

#[test]
fn should_invalidate_identities_schemas_and_watches_when_the_cluster_behind_the_name_changed() {
    // §10.4, the only MUST in §10: when the configuration name stays and strong fingerprint
    // evidence changes, cached object identities and watches from the previous cluster MUST be
    // invalidated *before* data is presented as current. The plausible mistake is the comfortable
    // one — reconnect, keep the caches, carry on — and it makes a Pod from one cluster answer a
    // question about another under the same instance name.
    let mut session = session("dev");
    assert_eq!(
        session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-a"))),
        ClusterChange::FirstObserved
    );
    session.discovered(discovered());
    session.cache_schema(pod_gvk(), Schema::absent());
    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");
    assert!(matches!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::Cached(_)
    ));

    let verdict = session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-b")));

    assert_eq!(verdict, ClusterChange::Replaced);
    assert!(
        session.schemas().is_empty(),
        "another cluster's Widget is another CRD"
    );
    assert!(
        session.discovery().is_none(),
        "another cluster serves what it serves"
    );
    assert!(session.needs_discovery());
    assert!(
        session.watched().is_empty(),
        "a watch checkpoint names a position in a history this cluster never had"
    );
    assert!(
        matches!(
            session.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
            Lookup::NotWatched
        ),
        "the cached object identity is gone before anything is presented as current"
    );
    assert!(!session.identity().effective().is_obtained());
}

#[test]
fn should_keep_the_provider_instance_id_stable_across_a_cluster_replacement() {
    // §10.1: the instance id is Ono-local configuration identity and MUST stay stable across
    // reconnects. Deriving it from the cluster instead — the obvious shortcut once a fingerprint
    // exists — would rename the instance underneath every place, bookmark and diagnostic that
    // refers to it, at the exact moment the user most needs the name to hold still.
    let mut session = session("dev");
    session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-a")));

    session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-b")));

    assert_eq!(session.instance(), "kubernetes:dev");
    assert_eq!(session.namespace(), Some("shop"));
    assert_eq!(session.endpoint(), "https://dev.example.test:6443");
}

#[test]
fn should_keep_the_caches_when_the_fingerprint_evidence_still_agrees() {
    // The other half of §10.4, and the one a cautious implementation gets wrong: invalidating on
    // every reconnect is safe and useless. It pays §50.2's discovery cost again on every
    // reconnect, which is precisely what having a session was for.
    let mut session = session("dev");
    session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-a")));
    session.discovered(discovered());
    session.cache_schema(pod_gvk(), Schema::absent());

    let verdict = session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-a")));

    assert_eq!(verdict, ClusterChange::Same);
    assert!(session.discovery().is_some());
    assert!(session.schema(&pod_gvk()).is_some());
    assert!(!session.needs_discovery());
}

#[test]
fn should_not_invalidate_on_evidence_that_decides_nothing() {
    // §10.2's closing sentence: no single optional signal is universally available. Two
    // fingerprints that share no signal say nothing about each other, and treating "I could not
    // compare" as "it changed" would empty the caches whenever a probe was denied — a
    // permission failure rendered as a cluster replacement.
    let mut session = session("dev");
    session.observed_fingerprint(
        Fingerprint::unknown().with_kube_system_uid(Known::Obtained("uid-cluster-a".to_owned())),
    );
    session.discovered(discovered());

    let verdict = session.observed_fingerprint(
        Fingerprint::unknown().with_server_public_key(Known::Obtained("sha256:abc".to_owned())),
    );

    assert_eq!(verdict, ClusterChange::Undetermined);
    assert!(session.discovery().is_some());
}

// --- §20.2 and §20.3: cached or direct, and what absence means ------------------------------------

#[test]
fn should_serve_a_watched_object_as_a_cached_observation_rather_than_a_direct_read() {
    // §20.2: the user MUST be able to distinguish a direct read from a cached observation, and
    // that requirement was unanswerable while nothing was cached at all. What makes it true
    // rather than merely representable is that the cache's answer carries `Origin::Cache` and the
    // observation time of the *read that filled it* — not the moment the hit was served.
    let mut session = session("dev");
    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");

    let Lookup::Cached(read) = session.lookup(&pods(), &shop(), Some("shop"), "checkout-1") else {
        panic!("a synchronised cache holds the Pod it listed");
    };

    assert_eq!(read.object().name(), "checkout-1");
    assert_eq!(read.object().uid(), Some("uid-1"));
    assert_eq!(read.freshness().origin(), Origin::Cache);
    assert!(!read.freshness().is_direct_read());
    assert_eq!(read.freshness().watch_synced(), Some(true));
    assert_eq!(read.freshness().observed_at().unix_millis(), OBSERVED);
    assert_eq!(
        read.freshness().resource_version(),
        Some("18005"),
        "the object's own version, not the collection's"
    );
    assert_eq!(read.freshness().provider_instance(), "kubernetes:dev");
}

#[test]
fn should_not_read_absence_from_a_cache_that_has_not_synchronised() {
    // §20.3: before sync completion, absence in the cache MUST NOT mean upstream absence, and
    // §4 invariant 13 keeps "not there" and "not looked" apart. The plausible mistake is a
    // `HashMap::get` returning `None` and a caller rendering "no such Pod" — a cache that was
    // never filled answers every question with an absence it did not observe.
    let mut session = session("dev");
    session.watch(&pods(), &shop());

    assert_eq!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::NotSynced(SyncState::Syncing)
    );
    assert!(
        !session
            .lookup(&pods(), &shop(), Some("shop"), "checkout-1")
            .is_answer(),
        "a lookup that cannot answer must not look like one that did"
    );
}

#[test]
fn should_report_absence_as_absence_once_the_cache_is_live() {
    // The other side of §20.3, which is why the state exists at all: a synchronised, live cache
    // is entitled to say a name is not in the cluster. Without that, a cache is only ever a
    // hint, and every lookup pays for a round trip anyway.
    let mut session = session("dev");
    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");

    assert_eq!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-999"),
        Lookup::ConfirmedAbsent
    );
}

#[test]
fn should_stop_answering_from_a_cache_whose_continuity_broke() {
    // §19.4 step 2: an expiry quarantines the assumptions that require gap-free observation. The
    // cache still holds objects, and they are still the last thing that was true — but the stream
    // that was keeping them true has stopped, so a miss is no longer evidence of absence and a
    // hit is no longer entitled to claim it is synchronised.
    let mut session = session("dev");
    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");

    let expiry = frame(
        "ERROR",
        r#"{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"too old resource version: 18010 (18700)","reason":"Expired","code":410}"#,
    );
    session
        .feed_watch(&pods(), &shop(), expiry.as_bytes())
        .expect("the ERROR frame decodes");

    assert_eq!(
        session
            .watch_stream(&pods(), &shop())
            .map(ono_provider_kubernetes::watch::WatchStream::state),
        Some(SyncState::GapDetected)
    );
    assert_eq!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-999"),
        Lookup::NotSynced(SyncState::GapDetected),
        "an absence after a gap is unobserved, not observed to be absent"
    );
    assert_eq!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::NotSynced(SyncState::GapDetected),
        "and a hit from a quarantined cache is not a current observation either"
    );
}

#[test]
fn should_not_seed_a_cache_from_a_listing_that_did_not_cover_the_collection() {
    // §18.3 meets §20.3. A listing whose second page was denied is a partial truth and a
    // perfectly legitimate answer to a query — but seeding an informer cache with it makes every
    // object it never read look absent, and the cache would then answer `ConfirmedAbsent` for
    // objects it was refused permission to see. Refusing to seed keeps the two honest separately.
    let mut session = session("dev");
    let denied = listing_of(&[
        ok(&format!(
            r#"{{"apiVersion":"v1","kind":"PodList","metadata":{{"resourceVersion":"18010","continue":"tok"}},
                "items":[{}]}}"#,
            pod_item("checkout-1", "uid-1", "18005")
        )),
        {
            let body = r#"{"kind":"Status","apiVersion":"v1","code":403,"reason":"Forbidden","message":"pods is forbidden"}"#;
            format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        },
    ]);
    assert!(
        !denied.coverage().is_complete(),
        "the fixture is a partial read"
    );

    let refusal = session
        .synchronise(&pods(), &shop(), denied)
        .expect_err("a partial listing may not become a synchronised cache");

    assert_eq!(refusal, SyncRefused::IncompleteCoverage);
    assert!(
        matches!(
            session.lookup(&pods(), &shop(), Some("shop"), "checkout-2"),
            Lookup::NotWatched | Lookup::NotSynced(_)
        ),
        "nothing was cached, so nothing may be reported absent"
    );
}

// --- §19: the watch reaches the session ----------------------------------------------------------

#[test]
fn should_apply_decoded_watch_frames_to_the_cache_it_synchronised() {
    // The two halves joined: `transport` hands over chunks, the decoder turns them into
    // `WatchEvent`s, and the session applies them to the cache a listing seeded. Before this the
    // watch state machine was only ever fed by hand, so the whole path — list, watch, cache,
    // freshness — had never once run end to end.
    let mut session = session("dev");
    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");

    let wire = format!(
        "{}{}{}",
        frame("ADDED", &pod_frame_object("checkout-2", "uid-2", "18011")),
        frame("DELETED", &pod_frame_object("checkout-1", "uid-1", "18012")),
        frame(
            "BOOKMARK",
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"resourceVersion":"18999"}}"#
        ),
    );
    // Split mid-frame, because a chunk boundary respects no JSON boundary.
    let (head, tail) = wire.split_at(wire.len() / 3);
    session
        .feed_watch(&pods(), &shop(), head.as_bytes())
        .expect("the first chunk decodes as far as it goes");
    session
        .feed_watch(&pods(), &shop(), tail.as_bytes())
        .expect("the rest completes the frames");

    assert!(matches!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-2"),
        Lookup::Cached(_)
    ));
    assert_eq!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::ConfirmedAbsent,
        "a DELETED that was observed is evidence of absence, unlike a cache that never read"
    );
    let stream = session
        .watch_stream(&pods(), &shop())
        .expect("the watch is open");
    assert_eq!(stream.state(), SyncState::Live);
    assert_eq!(
        stream
            .checkpoint()
            .map(|version| version.as_str().to_owned()),
        Some("18999".to_owned()),
        "the bookmark moved the checkpoint without pretending anything changed"
    );
    assert!(stream.is_gap_free());
}

#[test]
fn should_release_a_watch_that_no_longer_serves_a_consumer() {
    // §19.7: leaving a place or closing a live view SHOULD release watches nobody needs, and
    // §19.6 says watches are demand-driven rather than opened over everything discovered. A
    // session that only ever accumulates streams is a slow leak against the API server, and the
    // released stream's absence must read as "not watched" rather than as an empty cluster.
    let mut session = session("dev");
    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");
    assert_eq!(session.watched().len(), 1);

    assert!(session.release_watch(&pods(), &shop()));

    assert!(session.watched().is_empty());
    assert_eq!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::NotWatched
    );
    assert!(
        !session.release_watch(&pods(), &shop()),
        "releasing a watch nobody holds is not an error and not a success"
    );
}

#[test]
fn should_release_a_closed_view_s_watch_only_when_its_cache_can_no_longer_answer() {
    // §19.7's qualifier, which is the whole of the rule: a closing live view releases the watches
    // that "no longer serve another active consumer". In this provider the other consumer is the
    // session's own object cache — §20.2 makes `origin=cache` a first-class answer and §20.3 lets
    // a synchronised stream report an absence as an absence — so a stream a later read may still
    // be answered from is serving one, and a stream past a `410` is serving nobody while holding
    // a checkpoint the API server has already discarded.
    //
    // Releasing both, or neither, is what this prevents. Releasing both makes §20.2's cache
    // origin unreachable in practice; releasing neither is `release_watch` never being called,
    // which is a session that only ever grows.
    let mut live = session("dev");
    live.synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");

    assert!(
        !live.close_view(&pods(), &shop()),
        "a synchronised cache still answers reads, so the watch behind it still serves a consumer"
    );
    assert_eq!(live.watched().len(), 1);
    assert!(matches!(
        live.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::Cached(_)
    ));

    let mut broken = session("dev");
    broken
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");
    let expiry = frame(
        "ERROR",
        r#"{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"too old resource version: 18010 (18700)","reason":"Expired","code":410}"#,
    );
    broken
        .feed_watch(&pods(), &shop(), expiry.as_bytes())
        .expect("the ERROR frame decodes");

    assert!(
        broken.close_view(&pods(), &shop()),
        "a stream past a gap answers no read and holds a checkpoint the server has discarded"
    );
    assert!(broken.watched().is_empty());
    assert_eq!(
        broken.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::NotWatched,
        "and what it left behind reads as unwatched rather than as a cluster with nothing in it"
    );
    assert!(
        !broken.close_view(&pods(), &shop()),
        "closing a view over a watch nobody holds is neither an error nor an achievement"
    );
}

// --- §6.5 and §6.3's last line -------------------------------------------------------------------

#[test]
fn should_keep_two_sessions_from_sharing_caches_watches_credentials_or_namespaces() {
    // §6.5 lists five ways two provider instances must not collide, and every one of them is a
    // consequence of where state lives. State kept in a process-wide map keyed by GVR — the
    // obvious first implementation — collides on all five at once, and the failure is invisible
    // until two clusters happen to hold a Pod of the same name.
    let mut dev = session("dev");
    let prod = session("prod");
    dev.discovered(discovered());
    dev.cache_schema(pod_gvk(), Schema::absent());
    dev.synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");
    dev.negotiate(Capability::StreamingLists);

    assert_eq!(prod.instance(), "kubernetes:prod");
    assert_eq!(prod.namespace(), Some("billing"), "no namespace carry-over");
    assert!(prod.discovery().is_none(), "no discovery carry-over");
    assert!(prod.schemas().is_empty(), "no schema cache carry-over");
    assert!(prod.watched().is_empty(), "no watch checkpoint carry-over");
    assert!(!prod.negotiated(Capability::StreamingLists));
    assert_eq!(
        prod.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::NotWatched,
        "one cluster's cached object identity is not the other's"
    );
    assert_eq!(
        prod.credential_material()
            .map(ono_provider_kubernetes::kubeconfig::Secret::expose),
        Some("prod-secret-token-4a71"),
        "each session carries its own credential and no other"
    );
    assert_eq!(
        dev.credential_material()
            .map(ono_provider_kubernetes::kubeconfig::Secret::expose),
        Some(TOKEN)
    );
}

#[test]
fn should_keep_credential_material_out_of_the_session_and_its_diagnostic() {
    // §6.3's last line: "Secret material MUST remain outside serializable session diagnostics",
    // and §8.1 says the same for everything else. A derived `Debug` on a session satisfies the
    // compiler and prints the bearer token into the first log line anybody writes; the leak is
    // silent until someone reads the log. So the whole rendered session, and the diagnostic it
    // produces, are searched for the token itself.
    let mut session = session("dev");
    session.identified(
        Identity::unknown().with_credential(Known::Obtained(Subject::new(
            "dev-user",
            None,
            Vec::new(),
        ))),
    );
    session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-a")));

    let rendered = format!("{session:?}");
    let diagnostic = format!("{:?}", session.diagnostic());

    assert!(
        !rendered.contains(TOKEN),
        "the session rendered the token: {rendered}"
    );
    assert!(
        !diagnostic.contains(TOKEN),
        "the diagnostic rendered the token: {diagnostic}"
    );
    assert!(
        rendered.contains("BearerToken"),
        "the kind of credential is exactly what a diagnostic should say: {rendered}"
    );
    assert_eq!(session.diagnostic().instance(), "kubernetes:dev");
    assert_eq!(
        session.diagnostic().fingerprint().obtained_signals().len(),
        2,
        "the diagnostic carries the non-secret fingerprint §10.2 asks for"
    );
}

#[test]
fn should_not_use_a_capability_that_was_never_negotiated() {
    // §19.2: streaming lists MUST be capability-negotiated and MUST have a list/watch fallback.
    // Defaulting a capability to available is the mistake — a cluster one version older then
    // fails a request the provider had no reason to make, and the fallback path never runs.
    let mut session = session("dev");

    assert!(!session.negotiated(Capability::StreamingLists));
    assert!(!session.negotiated(Capability::AggregatedDiscovery));

    session.negotiate(Capability::AggregatedDiscovery);

    assert!(session.negotiated(Capability::AggregatedDiscovery));
    assert!(
        !session.negotiated(Capability::StreamingLists),
        "negotiating one capability says nothing about another"
    );
    assert_eq!(
        session.capabilities(),
        vec![Capability::AggregatedDiscovery]
    );
}

#[test]
fn should_forget_negotiated_capabilities_when_the_cluster_is_replaced() {
    // §10.4 again, applied to the part of §6.3 that is easiest to forget: a capability was
    // negotiated with the cluster that has just been replaced. Carrying it over would send a
    // streaming-list request to a server that never agreed to one.
    let mut session = session("dev");
    session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-a")));
    session.negotiate(Capability::StreamingLists);

    session.observed_fingerprint(fingerprint(&dev_origin(), Some("uid-cluster-b")));

    assert!(!session.negotiated(Capability::StreamingLists));
}

#[test]
fn should_hold_the_tls_configuration_the_connection_was_established_with() {
    // §6.3 names TLS configuration as part of a session, and §8.4 requires the posture to be
    // visible in diagnostics. Recomputing it per request is the alternative, and it is how one
    // request path comes to verify certificates while another, built a little later, does not.
    let verified = TlsSettings::verifying(&Anchors::system(), None).expect("a verifying config");
    let session = session("dev").connected(verified);

    assert!(session.tls().is_some());
    assert_eq!(session.tls_posture(), TlsPosture::Verified);
    assert_eq!(session.diagnostic().tls(), TlsPosture::Verified);
    assert!(
        format!("{session:?}").contains("verified"),
        "what protects the session is part of what the session says about itself"
    );
}

#[test]
fn should_say_when_it_last_observed_a_watched_collection() {
    // §20.2 and §39.3. A watch's segments say *which* changes were seen and in what order; they
    // carry no instant, because `watch.rs` records arrival order and never arrival time. The one
    // provider-clock fact about a stream lives here — the moment this session last observed the
    // collection — and it is what lets a timeline widen its window back to a period this provider
    // was demonstrably watching, instead of reporting a window one read wide beside changes that
    // happened earlier.
    let mut session = session("dev");
    assert_eq!(
        session.watch_observed_at(&pods(), &shop()),
        None,
        "a collection nobody watched has no moment of observation"
    );

    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");

    assert_eq!(
        session
            .watch_observed_at(&pods(), &shop())
            .map(ono_provider_kubernetes::transport::ObservedAt::unix_millis),
        Some(OBSERVED),
        "the moment the read that filled the cache was made, never the moment it is asked about"
    );
    assert_eq!(
        session.watch_observed_at(&pods(), &Scope::in_namespace("payments")),
        None,
        "another scope is another stream (§6.5)"
    );
}

// --- §20.5 and generic §16.5: a write invalidates what it changed --------------------------------

#[test]
fn should_stop_answering_from_a_cache_the_write_it_made_moved_past() {
    // §20.5, and §16.5 of the generic provider contract: after a successful mutation the provider
    // MUST invalidate or mark potentially affected cached facts as stale. Nothing did, and the
    // consequence was not subtle — a session that had watched a collection kept answering for the
    // object it had just written to, from a cache filled before the write, with `origin=cache` on
    // the record. That reads as a confirmed observation of a cluster this session itself knows it
    // has changed, which is exactly the sentence §16.5's second half forbids.
    let mut session = session("dev");
    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");
    assert!(matches!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::Cached(_)
    ));

    session.mutated(&pods(), Some("shop"));

    assert_eq!(
        session.lookup(&pods(), &shop(), Some("shop"), "checkout-1"),
        Lookup::NotWatched,
        "the next read observes rather than recalls"
    );
}

#[test]
fn should_not_read_an_invalidated_cache_as_an_absence_or_fill_it_with_what_the_write_asked_for() {
    // The two ways of getting §20.5 wrong in opposite directions, in one test.
    //
    // Dropping the *object* from the cache and keeping the cache live would answer
    // `ConfirmedAbsent` — a write reported as having deleted what it changed (§4 invariant 13).
    // Writing the applied document into the cache would answer `Cached` with an object no server
    // ever returned, which is §20.5's `MUST NOT` in as many words: a synthetic result labelled as
    // a server observation.
    let mut session = session("dev");
    session
        .synchronise(&pods(), &shop(), one_pod_listing())
        .expect("a complete listing seeds the cache");

    session.mutated(&pods(), Some("shop"));

    let after = session.lookup(&pods(), &shop(), Some("shop"), "checkout-1");
    assert!(
        !after.is_answer(),
        "an invalidated cache answers neither the object nor its absence: {after:?}"
    );
    assert!(
        after.read().is_none(),
        "nothing was put into the cache in place of what the write asked for"
    );
}

#[test]
fn should_leave_a_cache_the_write_could_not_have_reached_alone() {
    // "Potentially affected" is the object and the collection entry that holds it — not every
    // cache in the session. Emptying the lot would satisfy §16.5 and pay for it with §50.2's cost
    // on every other collection, and it would assert that writing to a Pod in `shop` told this
    // session something about ConfigMaps and about Pods in `payments`. It did not.
    let mut session = session("dev");
    for (gvr, scope, namespace) in [
        (pods(), shop(), "shop"),
        (pods(), Scope::all_namespaces(), "shop"),
        (pods(), Scope::in_namespace("payments"), "payments"),
        (configmaps(), shop(), "shop"),
    ] {
        session
            .synchronise(&gvr, &scope, one_object_listing(&gvr, &scope, namespace))
            .expect("a complete listing seeds the cache");
    }

    session.mutated(&pods(), Some("shop"));

    assert_eq!(
        session.lookup(&pods(), &shop(), Some("shop"), "one"),
        Lookup::NotWatched,
        "the collection the object lives in is invalidated"
    );
    assert_eq!(
        session.lookup(&pods(), &Scope::all_namespaces(), Some("shop"), "one"),
        Lookup::NotWatched,
        "and so is every other watched scope that could be holding the same object"
    );
    assert!(
        matches!(
            session.lookup(
                &pods(),
                &Scope::in_namespace("payments"),
                Some("payments"),
                "one"
            ),
            Lookup::Cached(_)
        ),
        "another namespace's cache was not made wrong by this write"
    );
    assert!(
        matches!(
            session.lookup(&configmaps(), &shop(), Some("shop"), "one"),
            Lookup::Cached(_)
        ),
        "and neither was another collection's"
    );
}

#[test]
fn should_re_read_what_the_cluster_serves_after_it_wrote_a_custom_resource_definition() {
    // §33.2's first and last facts — a CRD added, a CRD deleted — observed at the one place this
    // provider can be certain of them: it made the change itself. What the cluster serves is a
    // cached fact like any other (§20.1), and a write to `customresourcedefinitions` is the write
    // that makes it wrong.
    //
    // The pre-change copy is *kept* rather than dropped, and that is deliberate: it may never be
    // served again, and it is the only baseline against which the refreshed document can say
    // which group stopped being served (§33.2, §12.4).
    let mut session = session("dev");
    session.cache_discovery_document("/apis", APIS_WITH_WIDGETS);
    assert_eq!(session.discovery_document("/apis"), Some(APIS_WITH_WIDGETS));

    session.mutated(&crds(), None);

    assert_eq!(
        session.discovery_document("/apis"),
        None,
        "a snapshot of what the cluster served before this session changed it is not an answer"
    );
}

#[test]
fn should_not_invalidate_what_the_cluster_serves_for_an_ordinary_write() {
    // The narrow half of the rule above. A Pod is not a statement about what the API server
    // serves, and re-running discovery after every write would pay §50.2's three round trips for
    // a fact no write of that kind can change.
    let mut session = session("dev");
    session.cache_discovery_document("/apis", APIS_WITH_WIDGETS);

    session.mutated(&pods(), Some("shop"));

    assert_eq!(session.discovery_document("/apis"), Some(APIS_WITH_WIDGETS));
}

// --- §11.4 and §33.2: discovery is refreshed, and the refresh is what invalidates ---------------

#[test]
fn should_re_read_a_discovery_document_once_its_validity_window_has_passed() {
    // §11.4's `MUST`: the provider MUST support discovery invalidation and refresh *without
    // restarting Ono*. Until this window existed, the only thing that cleared a discovery
    // document was a cluster **replacement** — so a CRD installed while a shell session was live
    // stayed invisible for the life of the process, which is precisely the restart §11.4 forbids
    // as the remedy. §16.2 of the generic contract asks a cache for explicit invalidation *and
    // expiry* semantics, and §50.2 asks for discovery to be "cached and incrementally refreshed
    // rather than downloaded before every query" — both halves are this window.
    let clock = SteppingClock::at(OBSERVED);
    let mut session = Session::with_clock(connection("dev"), clock.clone());
    session.cache_discovery_document("/apis", APIS_WITH_WIDGETS);

    clock.advance(DISCOVERY_VALIDITY - Duration::from_millis(1));

    assert_eq!(
        session.discovery_document("/apis"),
        Some(APIS_WITH_WIDGETS),
        "inside the window the second question of a session is still free (§50.2)"
    );

    clock.advance(Duration::from_millis(1));

    assert_eq!(
        session.discovery_document("/apis"),
        None,
        "past it, the next question that needs discovery asks the API server again"
    );
}

#[test]
fn should_forget_the_schemas_of_a_group_a_refreshed_group_list_no_longer_serves() {
    // §33.2's "CRD deleted", detected the way §33.2 asks for it — "through discovery/schema
    // invalidation". The refreshed `/apis` *is* the observation: the group was served, and it is
    // not. §12.4's second bullet then says what follows, and it is not optional, because a schema
    // held for a kind nobody serves is a set of fields with nothing behind them.
    let mut session = session("dev");
    session.cache_discovery_document("/apis", APIS_WITH_WIDGETS);
    session.cache_discovery_document("/apis/example.io/v1", WIDGETS_V1);
    session.cache_schema(widget_gvk(), Schema::absent());
    session.cache_schema(nebula_gvk(), Schema::absent());

    session.cache_discovery_document("/apis", APIS_WITHOUT_WIDGETS);

    assert!(
        session.schema(&widget_gvk()).is_none(),
        "the withdrawn group's schemas go with it"
    );
    assert!(
        session.schema(&nebula_gvk()).is_some(),
        "a group that is still served keeps its schemas"
    );
    assert_eq!(
        session.discovery_document("/apis/example.io/v1"),
        None,
        "§11.5: the resource list of a group that is no longer served must not answer for it — \
         the next question goes to the API server and gets `not served` from the server"
    );
}

#[test]
fn should_forget_only_the_group_version_a_refreshed_group_list_stopped_serving() {
    // §33.2's "served version added/removed", and §12.4's second bullet at the grain the
    // specification writes it in: the group is still there, one of its versions is not.
    let mut session = session("dev");
    session.cache_discovery_document("/apis", APIS_WITH_WIDGETS);
    session.cache_schema(widget_gvk(), Schema::absent());
    session.cache_schema(Gvk::new("example.io", "v2", "Widget"), Schema::absent());

    session.cache_discovery_document("/apis", APIS_WIDGETS_V2_ONLY);

    assert!(session.schema(&widget_gvk()).is_none());
    assert!(
        session
            .schema(&Gvk::new("example.io", "v2", "Widget"))
            .is_some(),
        "only the version that stopped being served is forgotten"
    );
}

#[test]
fn should_forget_the_schema_of_a_kind_a_refreshed_resource_list_changed() {
    // §33.2's "schema changed" and "storage version changed" reach a resource list as a changed
    // entry — a verb gained, a subresource appearing, a scope corrected. The cached schema was
    // read for the kind as it was described then, so it is a description of something the server
    // has since restated. Only that kind's, though: a CRD updated in one group-version says
    // nothing about the kind next to it.
    let mut session = session("dev");
    session.cache_discovery_document("/apis/example.io/v1", WIDGETS_V1);
    session.cache_schema(widget_gvk(), Schema::absent());
    session.cache_schema(gadget_gvk(), Schema::absent());

    session.cache_discovery_document("/apis/example.io/v1", WIDGETS_V1_PATCHABLE);

    assert!(
        session.schema(&widget_gvk()).is_none(),
        "the kind the server described differently is re-read"
    );
    assert!(
        session.schema(&gadget_gvk()).is_some(),
        "the kind it described the same way is not"
    );
}

#[test]
fn should_keep_every_schema_a_refreshed_resource_list_did_not_change() {
    // The half a cautious implementation gets wrong: a CRD *installed* invalidates nothing at
    // all. Every schema this session holds is still about a kind the server still serves exactly
    // as it did, and emptying the cache because the document changed would pay §50.2's cost
    // again every time anybody in the cluster installs anything.
    let mut session = session("dev");
    session.cache_discovery_document("/apis/example.io/v1", WIDGETS_V1);
    session.cache_schema(widget_gvk(), Schema::absent());
    session.cache_schema(gadget_gvk(), Schema::absent());

    session.cache_discovery_document("/apis/example.io/v1", WIDGETS_V1_WITH_SPROCKET);

    assert!(session.schema(&widget_gvk()).is_some());
    assert!(session.schema(&gadget_gvk()).is_some());
    assert_eq!(
        session.discovery_document("/apis/example.io/v1"),
        Some(WIDGETS_V1_WITH_SPROCKET),
        "and the kind installed since the snapshot was taken is the one now on offer (§33.1)"
    );
}

#[test]
fn should_learn_nothing_from_a_document_that_is_the_first_of_its_path() {
    // A document with no predecessor is not a change. The mistake it guards against is treating
    // the first read of a path as "everything I hold about this group is stale", which would make
    // the first query of every session throw away the schemas the same query just cached.
    let mut session = session("dev");
    session.cache_schema(widget_gvk(), Schema::absent());

    session.cache_discovery_document("/apis/example.io/v1", WIDGETS_V1);

    assert!(session.schema(&widget_gvk()).is_some());
}

//! Where a provider instance's session lives, and why it lives there (§6.3, §6.4, §6.5, §50.2).
//!
//! `ono_provider_kubernetes::session::Session` holds everything §6.3 says survives a call: the
//! endpoint, the credential *kind*, the default namespace, discovery, the schema cache, the
//! negotiated capabilities, the cluster fingerprint, the watch registry and the object caches
//! those watches keep. It performs no I/O and it has no opinion about how long it lives. This
//! module is that opinion.
//!
//! **A session lives in the package process, for as long as the process does.** A KUANG/11
//! package is a process the host starts once and keeps: `Plugin::run_io` reads an envelope,
//! answers it, and reads the next, so the process outlives every invocation it serves while
//! `Ctx` — the invocation's arguments, its output stream, its capability broker — does not.
//! Anything held on a `Ctx` would be discarded between two queries, which is exactly the state
//! the specification calls out in §50.2. So the registry is built once, in
//! [`crate::plugin`], and every target handler is handed the same one.
//!
//! **It is not `state.persist`, and the manifest's grant stays unused by this route.** The
//! obvious alternative is to write the discovery snapshot to the host's key-value store and read
//! it back on the next process. It is refused on the specification's own terms: §10.4 requires a
//! cache to be invalidated when the cluster behind a configuration name changes, and the evidence
//! for that — the fingerprint — is gathered *live*. A snapshot restored from disk arrives with no
//! evidence at all, so either it is trusted (and a rebuilt cluster answers from the previous
//! one's cache) or it is re-verified (and the round trips it was meant to save are spent
//! verifying it). The same argument holds harder for a watch checkpoint, which names a
//! `resourceVersion` the server has almost certainly discarded by the time a new process starts.
//! A session is live state, and living exactly as long as the process that can keep it true is
//! the honest lifetime.
//!
//! **§6.5's isolation is a property of the key.** Two provider instances must not share an
//! identity, a cache, a watch checkpoint, a credential or a namespace. Three things make that
//! hold here:
//!
//! - the key is [`Key`], and it is *stricter* than §6.2's provider instance: two contexts of one
//!   name pointed at two servers, or at one server with and without certificate verification, are
//!   different keys and therefore different sessions. A key can only ever split sessions that
//!   §6.5 would have kept apart; it cannot merge two;
//! - **no credential is stored.** A session records the credential's *kind* (§8.1) and never its
//!   material. The bearer token, the client certificate and the certificate authority are
//!   resolved from the operator's configuration on every invocation, so no invocation can be
//!   answered with a credential another one resolved, and a rotated token takes effect at once;
//! - **no namespace is stored as an answer.** The scope a query reads is resolved per invocation
//!   from its own options and its own context (§7.5), and the session's default namespace is a
//!   fact about the configuration rather than a value any read takes.
//!
//! What a session does hold across a call is what the *cluster* said: which documents discovery
//! returned, what the OpenAPI document types, what the fingerprint is, and what the watches have
//! seen. Every one of those is a fact about one cluster reached one way, which is what the key
//! names.

use std::cell::RefCell;
use std::collections::BTreeMap;

use ono_provider_kubernetes::session::Session;

/// What makes two invocations the same session (§6.2, §6.5, §10.3).
///
/// The provider instance is §6.2's `kubernetes:<context>` and would be the whole key if a context
/// name were enough to identify a cluster reached a particular way. It is not: two kubeconfig
/// files may both define `prod`, and one file edited between two queries may point `prod`
/// somewhere else entirely. So the endpoint and the transport posture join it, and the rule for
/// adding a component is one-directional — a component may only ever *split* two invocations that
/// would otherwise have shared a session, never merge two that would not have.
///
/// §10.3's prohibition is the other side of it: two instances that happen to reach one cluster
/// share a fingerprint and are still two instances, so the fingerprint is deliberately *not* part
/// of this key. Keying on what the cluster says about itself is precisely how two instances come
/// to be merged into one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    /// §6.2's provider instance: `kubernetes:<context>`, or the endpoint where none was named.
    pub instance: String,
    /// The API server this instance resolved to, as `scheme://host:port`.
    pub endpoint: String,
    /// How the bytes are protected — verified TLS, unverified TLS, or none at all (§8.4).
    ///
    /// Part of the key because §8.4 makes an insecure session a different thing from a verified
    /// one rather than a slower one, and a discovery snapshot taken over a connection nobody
    /// verified must not become the snapshot a verified session answers from.
    pub transport: &'static str,
}

/// Every session this package process holds, one per [`Key`].
///
/// `RefCell` rather than a lock: the SDK serves one invocation at a time on one thread, so there
/// is no contention to arbitrate and a lock would suggest a concurrency this protocol does not
/// have. The borrow is taken for the length of one invocation and released with it.
#[derive(Debug, Default)]
pub struct Sessions {
    entries: RefCell<BTreeMap<Key, Session>>,
}

impl Sessions {
    /// A registry holding nothing, which is what a package that has spoken to no cluster holds.
    ///
    /// §6.4: constructing this contacts nothing, and neither does creating a session in it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `work` against the session for `key`, starting one with `seed` where there is none.
    ///
    /// The session is reached only through this call, so there is no way to take a reference to
    /// one and keep it past the invocation that asked for it — which is the same discipline
    /// `Guarded` enforces on a Secret's payload, applied to state rather than to secrets.
    ///
    /// `seed` is a closure rather than a value because the ordinary case is a session that
    /// already exists, and building one means copying the endpoint out of a resolved kubeconfig
    /// for nothing.
    pub fn with<T>(
        &self,
        key: &Key,
        seed: impl FnOnce() -> Session,
        work: impl FnOnce(&mut Session) -> T,
    ) -> T {
        let mut entries = self.entries.borrow_mut();
        let session = entries.entry(key.clone()).or_insert_with(seed);
        work(session)
    }

    /// How many provider instances this process is holding state for.
    ///
    /// A count rather than the sessions themselves: a caller that could reach into another
    /// instance's session is the crossover §6.5 forbids, and the only honest thing to publish is
    /// how many there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Whether this process holds no session at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.borrow().is_empty()
    }
}

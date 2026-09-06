//! Where a provider instance's session lives, and why it lives there (§6.3, §6.4, §6.5, §50.2).
//!
//! `ono_provider_kubernetes::session::Session` holds everything §6.3 says survives a call: the
//! endpoint, the credential *kind*, the default namespace, discovery, the schema cache, the
//! negotiated capabilities, the cluster fingerprint, the watch registry and the object caches
//! those watches keep. It performs no I/O and it has no opinion about how long it lives. This
//! module is that opinion.
//!
//! **A session lives in the package process, for as long as the process does.** A KUANG/11
//! package is a process the host starts once and keeps: `Plugin::run_io` reads frames and routes
//! them, so the process outlives every invocation it serves while `Ctx` — the invocation's
//! arguments, its output stream, its capability broker — does not. Anything held on a `Ctx` would
//! be discarded between two queries, which is exactly the state the specification calls out in
//! §50.2. So the registry is built once, in [`crate::plugin`], and every target handler is handed
//! the same one.
//!
//! **Several invocations reach it at once, and that is the point rather than a hazard.** Since
//! `ADR-0586 (core)` a package may have more than one invocation open at a time, each on a worker
//! of its own, and a handler is `Fn(&mut Ctx) -> Outcome + Send + Sync`. Two threads therefore
//! arrive at this registry, and what a shared store does about that decides whether §62.10's
//! "concurrently" is provable or merely survivable. Two rules, and the second is the load-bearing
//! one:
//!
//! - **the registry is locked only while a session is looked up**, never while one is used. A
//!   handler holds its session across every round trip it makes, and a registry lock held for
//!   that long would make two invocations of two different clusters take turns — the concurrency
//!   would compile, be declared, and not exist;
//! - **a session is locked for the length of the invocation that claimed it.** The only route to
//!   one is [`Sessions::with`], which takes a [`Key`], so a thread can reach exactly the session
//!   its own key names and no other. Two invocations of *different* instances hold two different
//!   locks and never meet; two invocations of the *same* instance take turns, because a session
//!   is one cluster's answer to §6.3 and interleaving two invocations inside it would produce a
//!   state neither of them asked for. Contention there is a queue of one instance's own work,
//!   which is not the crossover §6.5 forbids.
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
//!   §6.5 would have kept apart; it cannot merge two. Concurrency does not weaken that: a lock
//!   arbitrates who uses a session, and it is the key alone that decides *which* session that is,
//!   so two invocations running at the same time can no more see each other's cache than two
//!   invocations running one after the other;
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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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
/// Two locks rather than one, because they answer two different questions and holding one lock
/// for both answers is how declared concurrency turns into serialised work:
///
/// - the **registry** lock protects the map. It is held for a lookup and an insertion and for
///   nothing else — never for the length of an invocation, and never across a round trip;
/// - each **session** has a lock of its own, held for the length of the invocation that claimed
///   it. This is what makes a session a coherent thing to read and write: §6.3's discovery
///   documents, schema cache, fingerprint and watch registry are consistent with each other
///   because exactly one invocation is inside them at a time.
///
/// The session behind the lock is an `Option` so that a poisoned session can be *discarded*
/// rather than recovered. A handler that panicked was unwound by the SDK's `catch_unwind` and its
/// invocation failed (`ADR-0586 (core)` §6); whatever it had half-written into a session is state
/// with no evidence behind it, and §10.4's discipline — never present as current what cannot be
/// shown to still be true — says to drop it and pay for discovery again rather than to answer
/// from it. The instance keeps serving; the next invocation seeds a fresh session under the same
/// key.
#[derive(Debug, Default)]
pub struct Sessions {
    entries: Mutex<BTreeMap<Key, Arc<Mutex<Option<Session>>>>>,
}

/// Takes `lock`, recovering the map a panicking thread left behind.
///
/// A poisoned registry means some thread unwound while holding it, which this module's own code
/// cannot do — nothing between the two ends of the borrow can panic. Recovering rather than
/// propagating is still the right answer: the map is a `BTreeMap` of handles, it is structurally
/// intact whatever happened, and refusing every later invocation because of one dead thread is
/// the failure `ADR-0586 (core)` §6 exists to prevent.
fn registry<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
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
    /// `Guarded` enforces on a Secret's payload, applied to state rather than to secrets. With
    /// several invocations open at once it does one thing more: the borrow another thread cannot
    /// take is also the borrow it cannot take *for another key*, so a session is unreachable from
    /// every invocation but the ones whose own key names it (§6.5).
    ///
    /// `seed` is a closure rather than a value because the ordinary case is a session that
    /// already exists, and building one means copying the endpoint out of a resolved kubeconfig
    /// for nothing.
    ///
    /// This call **blocks** while another invocation of the same provider instance is inside its
    /// session, and returns as soon as that one is done. It cannot block on an invocation of a
    /// different instance: those hold a different lock, and the registry lock the two of them do
    /// share is released before either starts working.
    pub fn with<T>(
        &self,
        key: &Key,
        seed: impl FnOnce() -> Session,
        work: impl FnOnce(&mut Session) -> T,
    ) -> T {
        // The registry, for exactly as long as it takes to find out which session this is.
        let session = Arc::clone(
            registry(&self.entries)
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(None))),
        );
        let mut held = match session.lock() {
            Ok(held) => held,
            Err(poisoned) => {
                // A panicked invocation left this session half-written. Clearing the flag and
                // emptying the slot puts the *next* invocation back where it would have been if
                // this instance had never been asked, which is the only state that can be shown
                // to be true.
                session.clear_poison();
                let mut held = poisoned.into_inner();
                *held = None;
                held
            }
        };
        work(held.get_or_insert_with(seed))
    }

    /// How many provider instances this process is holding state for.
    ///
    /// A count rather than the sessions themselves: a caller that could reach into another
    /// instance's session is the crossover §6.5 forbids, and the only honest thing to publish is
    /// how many there are. A key counts from the moment an invocation claims it, whether or not
    /// that invocation has finished seeding its session.
    #[must_use]
    pub fn len(&self) -> usize {
        registry(&self.entries).len()
    }

    /// Whether this process holds no session at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        registry(&self.entries).is_empty()
    }
}

//! What a credential source resolved to, and when it expires — never the token bytes (§8.2, §8.3,
//! ADR-0055).
//!
//! §8.3 makes credential expiry a `MUST` and refresh a `SHOULD` "before a request when the
//! credential is expired". ADR-0054 fetched a credential once per endpoint resolution and let a
//! stale one produce the API server's `401`; this module is where a resolved credential *lives*
//! between resolutions, so the second query of a long session reuses one helper run and the query
//! after an expiry pays for a fresh one.
//!
//! **The key is a source, and a source is never a token.** An entry is keyed on the session
//! identity — provider instance, endpoint, transport posture — plus the *source identity*: the
//! kubeconfig path list, the context, and the helper's command, arguments and environment. Two
//! resolutions are the same credential exactly when both halves match. The material the helper
//! returned is the *value*, never part of the key: §8.1 forbids credential bytes reaching a log,
//! a diagnostic, history or serialized state, and a key is every one of those at once.
//!
//! **A per-entry lock is held across the helper run**, so several callers that meet one expiry at
//! once wait for a single run and reuse its result. A stampede — every concurrent query launching
//! its own helper the instant a token expires — is the failure a shared store exists to prevent.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use ono_kuang_sdk::protocol::WireError;
use ono_provider_kubernetes::kubeconfig::Secret;
use ono_provider_kubernetes::transport::ObservedAt;

/// How long before a credential's stated expiry it is refreshed rather than used (§8.3).
///
/// A small margin, because a credential that is valid *now* but expires while the request is in
/// flight produces exactly the `401` refresh exists to avoid. Thirty seconds is longer than any
/// single round trip this package makes and far shorter than a managed-cloud token's lifetime, so
/// it refuses a credential about to die without churning a healthy one.
const EARLY_REFRESH_MARGIN_MILLIS: u64 = 30_000;

/// The identity of a credential source (§8.1, ADR-0055). Never the material.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SourceKey {
    /// The provider instance, `kubernetes:<context>` (§6.2).
    pub instance: String,
    /// The API server this resolved to, as `scheme://host:port[/base-path]`.
    pub endpoint: String,
    /// The transport posture — `plaintext`, `tls-verified` or `tls-unverified` (§8.4).
    pub transport: &'static str,
    /// A fingerprint of the *source*: the kubeconfig path list, the context, and the helper's
    /// command, arguments and environment. What the helper *returned* is never in here.
    pub source: String,
}

/// What a credential source resolved to (§8.3). The material, and when it dies.
///
/// The material is [`Secret`], so it never renders under `Debug`, and it is cloned to a caller
/// rather than exposed: a caller already had to be trusted with a token to send one, and cloning
/// keeps the store's own copy for the next query (§8.1).
#[derive(Clone)]
pub(crate) struct Resolved {
    /// The bearer token, where the helper returned one.
    pub token: Option<Secret>,
    /// The client certificate and its key, where the helper returned that form instead.
    pub client_certificate: Option<(Secret, Secret)>,
    /// When this credential expires, in Unix milliseconds, where the helper stated a timestamp
    /// this provider could parse. `None` is "no expiry this provider can see" — not "never
    /// expires": the API server may still refuse it, and that refusal is a `401` reported rather
    /// than an expiry predicted (§4, ADR-0054).
    expires_at: Option<u64>,
}

impl Resolved {
    /// A resolved credential with the material and the expiry the helper stated.
    #[must_use]
    pub(crate) fn new(
        token: Option<Secret>,
        client_certificate: Option<(Secret, Secret)>,
        expires_at: Option<u64>,
    ) -> Self {
        Self {
            token,
            client_certificate,
            expires_at,
        }
    }

    /// Whether this credential is expired, or close enough to expiry to refresh now (§8.3).
    ///
    /// A credential with no parseable expiry is never "expiring" as far as this provider can tell,
    /// which is why a helper that states no timestamp is used until the API server refuses it.
    #[must_use]
    fn is_expiring(&self, now: ObservedAt) -> bool {
        self.expires_at.is_some_and(|expires| {
            expires
                <= now
                    .unix_millis()
                    .saturating_add(EARLY_REFRESH_MARGIN_MILLIS)
        })
    }
}

/// Every credential this package process has resolved, one entry per [`SourceKey`] (ADR-0055).
///
/// Two locks, for the same reason [`crate::sessions::Sessions`] has two: the registry lock is held
/// only to find the entry, and each entry has a lock of its own held across the helper run so that
/// concurrent callers meeting one expiry wait for a single run rather than each launching a helper.
#[derive(Default)]
pub(crate) struct CredentialStore {
    entries: Mutex<BTreeMap<SourceKey, Arc<Mutex<Option<Resolved>>>>>,
}

/// Takes `lock`, recovering the state a panicking thread left behind.
///
/// A poisoned lock here means a thread unwound while resolving a credential. Recovering is right:
/// the map is structurally intact, and the entry it half-wrote is discarded (an `Option` set back
/// to `None`) so the next caller resolves afresh rather than trusting a partial result.
fn recover<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

impl CredentialStore {
    /// A store holding nothing, which is what a package that has run no helper holds.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The credential for `key`, running `resolve` to acquire or refresh one when it must (§8.3).
    ///
    /// Returns a cached credential where one is present and not within the early-refresh margin of
    /// its expiry; otherwise runs `resolve` — once, under the entry's own lock, so that concurrent
    /// callers meeting one expiry share the single run. A run that fails leaves the entry as it
    /// was (or empty), so nothing stale is presented as fresh and the failure is the caller's to
    /// route (§8.3, §21.4).
    ///
    /// # Errors
    ///
    /// Whatever `resolve` returned, unchanged.
    pub(crate) fn resolve(
        &self,
        key: &SourceKey,
        now: ObservedAt,
        resolve: impl FnOnce() -> Result<Resolved, WireError>,
    ) -> Result<Resolved, WireError> {
        let entry = self.entry(key);
        let mut held = recover(&entry);
        if let Some(existing) = held.as_ref()
            && !existing.is_expiring(now)
        {
            return Ok(existing.clone());
        }
        let fresh = resolve()?;
        *held = Some(fresh.clone());
        Ok(fresh)
    }

    /// Forces a fresh acquisition for `key`, whatever the cache holds (§8.3, the 401 path).
    ///
    /// The one route that ignores an unexpired entry: a `401` means the API server refused the
    /// credential this provider believed was good, so the credential is re-run rather than reused.
    /// The result replaces the entry, so the retry and every request after it carry the new one.
    ///
    /// # Errors
    ///
    /// Whatever `resolve` returned, unchanged.
    pub(crate) fn refresh(
        &self,
        key: &SourceKey,
        resolve: impl FnOnce() -> Result<Resolved, WireError>,
    ) -> Result<Resolved, WireError> {
        let entry = self.entry(key);
        let mut held = recover(&entry);
        let fresh = resolve()?;
        *held = Some(fresh.clone());
        Ok(fresh)
    }

    /// The lock for `key`'s entry, created empty where there is none. Holds the registry lock only
    /// for the lookup, never across a run.
    fn entry(&self, key: &SourceKey) -> Arc<Mutex<Option<Resolved>>> {
        Arc::clone(
            recover(&self.entries)
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(None))),
        )
    }
}

/// The store for this package process, built once (§8.3, ADR-0055).
///
/// A process-global rather than a value threaded through the handlers: `Endpoint::resolve` reaches
/// it, and `Endpoint::resolve` is called from every target handler with nothing but a `Ctx`, so a
/// value handed to handlers would have to travel through a signature this package does not own.
/// `crate::plugin` installs it beside `Sessions` so the two registries are built in one place.
static STORE: OnceLock<CredentialStore> = OnceLock::new();

/// Builds the process credential store, beside `Sessions`, if it is not built yet (ADR-0055).
pub(crate) fn install() {
    let _ = STORE.get_or_init(CredentialStore::new);
}

/// The process credential store, building it on first use.
#[must_use]
pub(crate) fn global() -> &'static CredentialStore {
    STORE.get_or_init(CredentialStore::new)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn key(source: &str) -> SourceKey {
        SourceKey {
            instance: "kubernetes:prod".to_owned(),
            endpoint: "https://api.example:6443".to_owned(),
            transport: "tls-verified",
            source: source.to_owned(),
        }
    }

    fn credential(token: &str, expires_at: Option<u64>) -> Resolved {
        Resolved::new(Some(Secret::new(token.to_owned())), None, expires_at)
    }

    fn at(millis: u64) -> ObservedAt {
        ObservedAt::from_unix_millis(millis)
    }

    #[test]
    fn should_run_a_helper_once_for_a_credential_that_stays_valid() {
        let store = CredentialStore::new();
        let runs = AtomicUsize::new(0);
        let run = |token: &'static str| {
            let runs = &runs;
            move || {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok(credential(token, Some(1_000_000)))
            }
        };

        let first = store
            .resolve(&key("s"), at(0), run("t1"))
            .expect("resolves");
        let second = store
            .resolve(&key("s"), at(1), run("t2"))
            .expect("resolves");

        assert_eq!(runs.load(Ordering::SeqCst), 1, "the helper ran once");
        assert_eq!(first.token.as_ref().map(Secret::expose), Some("t1"));
        assert_eq!(
            second.token.as_ref().map(Secret::expose),
            Some("t1"),
            "the second resolution reused the first run's credential"
        );
    }

    #[test]
    fn should_run_a_helper_again_when_the_credential_has_expired() {
        let store = CredentialStore::new();
        let runs = AtomicUsize::new(0);
        // Expires at 100_000; the second resolution is well past it.
        let acquire = || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(credential("t1", Some(100_000)))
        };
        store.resolve(&key("s"), at(0), acquire).expect("resolves");
        let refresh = || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(credential("t2", Some(1_000_000)))
        };
        let second = store
            .resolve(&key("s"), at(200_000), refresh)
            .expect("resolves");

        assert_eq!(
            runs.load(Ordering::SeqCst),
            2,
            "the expired credential was refreshed"
        );
        assert_eq!(
            second.token.as_ref().map(Secret::expose),
            Some("t2"),
            "the replacement credential is the one returned"
        );
    }

    #[test]
    fn should_refresh_before_the_stated_expiry_by_the_early_margin() {
        let store = CredentialStore::new();
        let runs = AtomicUsize::new(0);
        let acquire = || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(credential("t1", Some(100_000)))
        };
        store.resolve(&key("s"), at(0), acquire).expect("resolves");
        // Still valid, but within the 30s early-refresh margin of expiry.
        let refresh = || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(credential("t2", Some(1_000_000)))
        };
        store
            .resolve(&key("s"), at(100_000 - 10_000), refresh)
            .expect("resolves");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            2,
            "a credential inside the early-refresh margin is refreshed before it is sent"
        );
    }

    #[test]
    fn should_keep_a_credential_with_no_stated_expiry() {
        let store = CredentialStore::new();
        let runs = AtomicUsize::new(0);
        let run = || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(credential("t1", None))
        };
        store.resolve(&key("s"), at(0), run).expect("resolves");
        store
            .resolve(&key("s"), at(u64::MAX / 2), run)
            .expect("resolves");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "a credential with no expiry this provider can see is not treated as expired"
        );
    }

    #[test]
    fn should_key_two_sources_apart() {
        let store = CredentialStore::new();
        let runs = AtomicUsize::new(0);
        let run = |token: &'static str| {
            let runs = &runs;
            move || {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok(credential(token, None))
            }
        };
        store
            .resolve(&key("a"), at(0), run("ta"))
            .expect("resolves");
        store
            .resolve(&key("b"), at(0), run("tb"))
            .expect("resolves");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            2,
            "two different sources are two different credentials"
        );
    }

    #[test]
    fn should_not_cache_a_failed_resolution() {
        let store = CredentialStore::new();
        let failing = || {
            Err(WireError {
                code: "x".to_owned(),
                name: "x".to_owned(),
                message: "no".to_owned(),
                help: None,
                metadata: Box::default(),
            })
        };
        assert!(store.resolve(&key("s"), at(0), failing).is_err());
        let runs = AtomicUsize::new(0);
        let run = || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(credential("t1", None))
        };
        store.resolve(&key("s"), at(0), run).expect("resolves");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "a failed resolution cached nothing, so the next one runs"
        );
    }

    #[test]
    fn should_run_one_helper_when_two_threads_meet_one_expiry() {
        // §8.3's no-stampede: two callers arriving at once with an empty (or expired) entry share
        // a single run rather than each launching a helper.
        let store = Arc::new(CredentialStore::new());
        let runs = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let runs = Arc::clone(&runs);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .resolve(&key("s"), at(0), || {
                        runs.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        Ok(credential("t1", None))
                    })
                    .expect("resolves");
            }));
        }
        for handle in handles {
            handle.join().expect("the thread finished");
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "two concurrent callers shared one helper run"
        );
    }

    #[test]
    fn should_run_on_a_forced_refresh_even_when_the_cache_is_valid() {
        // The 401 path: the API server refused a credential this provider believed was good, so it
        // is re-run rather than reused.
        let store = CredentialStore::new();
        store
            .resolve(&key("s"), at(0), || Ok(credential("t1", Some(1_000_000))))
            .expect("resolves");
        let refreshed = store
            .refresh(&key("s"), || Ok(credential("t2", Some(1_000_000))))
            .expect("refreshes");
        assert_eq!(refreshed.token.as_ref().map(Secret::expose), Some("t2"));
        // And the refreshed credential is what a later resolve now returns.
        let later = store
            .resolve(&key("s"), at(1), || Ok(credential("t3", None)))
            .expect("resolves");
        assert_eq!(
            later.token.as_ref().map(Secret::expose),
            Some("t2"),
            "the forced refresh replaced the cached credential"
        );
    }
}

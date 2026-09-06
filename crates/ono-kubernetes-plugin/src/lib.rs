//! The KUANG/11 package that answers Ono-Sendai's provider queries from a Kubernetes cluster.
//!
//! This crate is the *boundary*: it speaks the protocol of `docs/contracts/kuang/protocol.v1.yaml`
//! on one side and calls `ono_provider_kubernetes` on the other, and it holds no Kubernetes
//! knowledge that the domain layer does not already have. The split is what keeps the domain
//! testable without a host and this crate testable without a cluster.
//!
//! ```text
//! contributions   what the package declares: targets, schemas, what each one reads
//! broker          the host's brokered connection, seen as a byte stream, and the context lease
//!                 that lets a handler read and emit alternately over one open connection
//! changes         one live watch: acquire, observe until the operator stops it, and say which
//!                 periods were not observed
//! sessions        what a provider instance keeps between two invocations, and keyed on what
//! query           one `provider.query`: discovery, list, redact, emit
//! cluster         the diagnostic: which cluster, reachable, as whom, and what is unknown
//! dynamic         a resource nobody compiled in: resolving it, and typing it from the cluster
//! records         one Kubernetes object, as a record of the target's schema
//! relations       one object's relationships, as a record per edge with its evidence
//! ```
//!
//! **`main.rs` is four lines on purpose.** Everything above lives in the library so that the
//! conformance test can drive the real binary while the unit tests reach the same code directly.

pub mod broker;
pub mod changes;
pub mod cluster;
pub mod contributions;
pub mod dynamic;
pub mod query;
pub mod records;
pub mod relations;
pub mod sessions;

use std::rc::Rc;

use ono_kuang_sdk::Plugin;

use crate::sessions::Sessions;

/// The package id, exactly as `package/manifest.yaml` declares it (spec §31.5).
///
/// A package may not claim the `ono.*` namespace even when the Ono-Sendai project ships it, so
/// this one is published under the namespace that can actually be checked.
pub const PACKAGE: &str = "io.github.godspeed-you.kubernetes";

/// The package version, as `package/manifest.yaml` declares it.
///
/// The host refuses a hello that contradicts the manifest, so the two are the same string or the
/// package does not load.
pub const VERSION: &str = "0.1.0";

/// The plugin, with every contribution declared and every target wired to a handler.
///
/// The schemas go across the handshake beside the targets that name them: the host registers a
/// contributed schema before it will accept a record carrying one, and a target naming a schema
/// the package does not contribute is refused at load (spec §31.23).
#[must_use]
pub fn plugin() -> Plugin {
    // One registry for the whole process, shared by every handler. It is built here because this
    // is the only place that outlives an invocation: a `Ctx` is the invocation, and a session
    // held on one would be discarded between two queries — which is §50.2's cost written as a
    // lifetime. `Rc` rather than `Arc` because the SDK serves one request at a time on one
    // thread, and a handler is `Fn` rather than `FnMut`, so the interior mutability lives in
    // `Sessions` where §6.5's key can be checked beside it.
    let sessions = Rc::new(Sessions::new());
    let mut plugin = Plugin::new(PACKAGE, VERSION);
    for target in contributions::TARGETS {
        let sessions = Rc::clone(&sessions);
        plugin = plugin
            .contribute_schema(target.schema_contribution())
            .contribute_target(target.target_contribution())
            // Which handler answers is decided by what the target *reads*, so a table entry
            // cannot be wired to a handler that does not fit it. The diagnostic reads the session
            // rather than a collection, and there is no listing path it could take.
            .provider(target.name, move |ctx| match target.reads {
                contributions::Reads::Instance => cluster::answer(target, &sessions, ctx),
                contributions::Reads::Relations => relations::answer(target, &sessions, ctx),
                contributions::Reads::Changes => changes::answer(target, &sessions, ctx),
                contributions::Reads::Kind { .. } | contributions::Reads::Discovered => {
                    query::answer(target, &sessions, ctx)
                }
            });
    }
    plugin
}

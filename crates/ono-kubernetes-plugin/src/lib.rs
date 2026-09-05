//! The KUANG/11 package that answers Ono-Sendai's provider queries from a Kubernetes cluster.
//!
//! This crate is the *boundary*: it speaks the protocol of `docs/contracts/kuang/protocol.v1.yaml`
//! on one side and calls `ono_provider_kubernetes` on the other, and it holds no Kubernetes
//! knowledge that the domain layer does not already have. The split is what keeps the domain
//! testable without a host and this crate testable without a cluster.
//!
//! ```text
//! contributions   what the package declares: targets, schemas, the group and kind each reads
//! broker          the host's brokered connection, seen as a byte stream
//! query           one `provider.query`: discovery, list, redact, emit
//! records         one Kubernetes object, as a record of the target's schema
//! ```
//!
//! **`main.rs` is four lines on purpose.** Everything above lives in the library so that the
//! conformance test can drive the real binary while the unit tests reach the same code directly.

pub mod broker;
pub mod contributions;
pub mod query;
pub mod records;

use ono_kuang_sdk::Plugin;

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
    let mut plugin = Plugin::new(PACKAGE, VERSION);
    for target in contributions::TARGETS {
        plugin = plugin
            .contribute_schema(target.schema_contribution())
            .contribute_target(target.target_contribution())
            .provider(target.name, move |ctx| query::answer(target, ctx));
    }
    plugin
}

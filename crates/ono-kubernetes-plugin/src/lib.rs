//! The KUANG/11 package that answers Ono-Sendai's provider queries from a Kubernetes cluster.
//!
//! This crate is the *boundary*: it speaks the protocol of `docs/contracts/kuang/protocol.v1.yaml`
//! on one side and calls `ono_provider_kubernetes` on the other, and it holds no Kubernetes
//! knowledge that the domain layer does not already have. The split is what keeps the domain
//! testable without a host and this crate testable without a cluster.
//!
//! ```text
//! audit           what this provider records about itself, for what the broker cannot see
//! contributions   what the package declares: targets, schemas, what each one reads
//! broker          the host's brokered connection, seen as a byte stream, and the context lease
//!                 that lets a handler read and emit alternately over one open connection
//! changes         one live watch: acquire, observe until the operator stops it, and say which
//!                 periods were not observed
//! sessions        what a provider instance keeps between two invocations, and keyed on what
//! planning        one prospective change, built from the object it is aimed at and shown
//! mutations       one bounded write: the plan, the request, the answer, and what it is not
//! query           one `provider.query`: discovery, list, redact, emit
//! cluster         the diagnostic: which cluster, reachable, as whom, and what is unknown
//! dynamic         a resource nobody compiled in: resolving it, and typing it from the cluster
//! records         one Kubernetes object, as a record of the target's schema
//! relations       one object's relationships, as a record per edge with its evidence
//! spatial         the same objects as places in Ono's graph, and the edges between them
//! events          the Events regarding one object, and the refusal to read none as none
//! evidence        what a Node states about the machine under it, exported rather than resolved
//! logs            one container's log, as lines that carry the bounds of the read
//! timeline        what is known to have happened to one object, and by whose clock
//! why             what may be said about the state an object is in, and where that stops
//! conditions      the structured observations an object's controllers wrote about it
//! ```
//!
//! **`main.rs` is four lines on purpose.** Everything above lives in the library so that the
//! conformance test can drive the real binary while the unit tests reach the same code directly.

pub mod audit;
pub mod broker;
pub mod changes;
pub mod cluster;
pub mod conditions;
pub mod contributions;
pub mod credentials;
pub mod dynamic;
pub mod events;
pub mod evidence;
pub mod logs;
pub mod mutations;
pub mod planning;
pub mod query;
pub mod records;
pub mod relations;
pub mod sessions;
pub mod spatial;
pub mod timeline;
pub mod why;

use std::sync::Arc;

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

/// How many invocations this package's code is willing to answer at once (spec §49.1).
///
/// **Three, and the number is the work rather than a round figure.** `ADR-0586 (core)` splits the
/// declaration in two on purpose: this one is the *author's* — the handlers are safe to run beside
/// each other, and this is how many of them the package is prepared to spawn — while
/// `runtime.max_concurrent_invocations` in `package/manifest.yaml` is the *operator's* budget, and
/// the smaller of the two wins. A manifest cannot raise this number, which is the point: no
/// operator can assert thread-safety on somebody else's behalf.
///
/// Three is what this package's own shapes of work need at once. One slot is a live watch: §19's
/// `k8s-change` borrows its invocation for as long as the operator keeps watching (ADR-0023), so
/// it holds its slot for minutes rather than for a round trip. Two more are the two contexts of
/// §62.10, which is the case the specification asks to be possible while something else is going
/// on. A fourth slot would buy a second simultaneous watch and cost a fourth worker, a fourth
/// brokered connection and a fourth TLS session inside one instance's 256 MiB; §49.1 says this
/// provider MUST bound its concurrency because Ono is an interactive shell rather than a load
/// generator, and a bound that stops at the work it can name is a bound.
pub const CONCURRENT_INVOCATIONS: u32 = 3;

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
    // lifetime. `Arc` rather than `Rc` because a handler is
    // `Fn(&mut Ctx) -> Outcome + Send + Sync` since `ADR-0586 (core)` and runs on a worker of its
    // own; the interior mutability lives in `Sessions`, where §6.5's key is checked beside the
    // lock that arbitrates who may use the session that key names.
    let sessions = Arc::new(Sessions::new());
    let mut plugin = Plugin::new(PACKAGE, VERSION).concurrent_invocations(CONCURRENT_INVOCATIONS);
    for target in contributions::TARGETS {
        let sessions = Arc::clone(&sessions);
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
                contributions::Reads::Plan => planning::answer(target, &sessions, ctx),
                contributions::Reads::Events => events::answer(target, &sessions, ctx),
                contributions::Reads::Evidence => evidence::answer(target, &sessions, ctx),
                contributions::Reads::Logs => logs::answer(target, &sessions, ctx),
                contributions::Reads::Timeline => timeline::answer(target, &sessions, ctx),
                contributions::Reads::Why => why::answer(target, &sessions, ctx),
                contributions::Reads::Conditions => conditions::answer(target, &sessions, ctx),
                contributions::Reads::Kind { .. } | contributions::Reads::Discovered => {
                    query::answer(target, &sessions, ctx)
                }
            });
    }
    // The schemas a *command* answers with, which no target names. A mutation's answer is what
    // one attempt produced; there is no collection of attempts to enumerate, so there is no noun
    // to hang it on (§31.23).
    for schema in contributions::COMMAND_SCHEMAS {
        plugin = plugin.contribute_schema(schema.contribution());
    }
    // The two words that write. They are commands rather than targets because a contributed
    // command declares a `risk` and a set of capabilities and a contributed target declares
    // neither — and the host checks the capability at every invocation, before any of this
    // package's code runs (§31.22, §31.75). ADR-0024.
    for declared in contributions::COMMANDS {
        let sessions = Arc::clone(&sessions);
        plugin = plugin
            .contribute_command(declared.contribution())
            .command(&declared.id(), move |ctx| {
                mutations::answer(declared, &sessions, ctx)
            });
    }
    // The edges between the places the targets above became. A command answering for the shell's
    // own `spatial-relation` target, because §36.1 is how a package contributes a relationship
    // provider and §35.5 wants the capability checked before anything is merged — which a target
    // contribution has nowhere to declare and a command contribution does (`ADR-0585 (core)`,
    // ADR-0027).
    {
        let sessions = Arc::clone(&sessions);
        plugin = plugin
            .contribute_command(spatial::contribution())
            .command(spatial::COMMAND, move |ctx| spatial::answer(&sessions, ctx));
    }
    plugin
}

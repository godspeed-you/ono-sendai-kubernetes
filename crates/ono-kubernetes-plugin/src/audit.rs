//! What this provider records about itself, for the things the capability broker cannot see
//! (§51.6, §27.6 of the generic contract).
//!
//! The broker audits what it *checked*: a `network.connect` to a host and a port, a
//! `filesystem.read` of a path. It cannot see what the bytes on that connection were for, because
//! it is a byte broker and this package carries its own protocol over it (ADR-0002, `ADR-0573
//! (core)`). So the facts an operator most wants in a trail — which cluster was reached, which
//! read the API server refused, which object was changed — are exactly the ones only this package
//! knows.
//!
//! `audit.event` is how a package adds to the host's trail, and until `ADR-0589 (core)` the host
//! pushed those records onto a vector nothing read. It now carries them into the same trail the
//! broker's own decisions go into, attributed and timestamped by the host, marked advisory, and
//! reachable through `get audit --plugin io.github.godspeed-you.kubernetes`.
//!
//! **Nothing here may carry a secret.** §51.6 says non-secret metadata, and the trail is shown,
//! exported and kept — a payload put here is a payload published. So these records carry an
//! endpoint, a scope, a verb, a GVR and an outcome, and never an object, a credential, a header
//! or a field value. The Secret *name* is a name, and names are what a trail is made of; the
//! `data` map has no route into this module at all, because nothing here takes an [`Object`].
//!
//! [`Object`]: ono_provider_kubernetes::object::Object

use ono_kuang_sdk::Ctx;
use serde_json::json;

use crate::broker::Lease;

/// Records that this provider opened a connection to an API server (§51.6, §10.1).
///
/// The endpoint and the provider instance, which is what makes a later record in the trail
/// attributable to a cluster rather than to "Kubernetes". No credential and no TLS material: the
/// posture is a fact about the connection and reaches a user through `get k8s-cluster`, where it
/// belongs beside the rest of the diagnostic.
pub fn connected(ctx: &mut Ctx<'_>, instance: &str, host: &str, port: u16) {
    record(
        ctx,
        json!({
            "action": "connect",
            "provider_instance": instance,
            "endpoint": format!("{host}:{port}"),
        }),
    );
}

/// Records that the API server refused a read to the identity this provider is using (§21.4).
///
/// The one §51.6 names that is neither a connection nor a change, and the most useful of the
/// three: a trail of denials is how an operator finds out that a token lost a grant, and it is
/// the half of §21.4 that a query's own refusal reports to one person once.
pub fn refused(lease: &Lease<'_, '_>, instance: &str, what: &str, scope: &str, verb: &str) {
    let _ = lease.with(|ctx| {
        record(
            ctx,
            json!({
                "action": "denied",
                "provider_instance": instance,
                "resource": what,
                "scope": scope,
                "verb": verb,
            }),
        );
    });
}

/// Records that this provider changed something in a cluster (§43, §51.6).
///
/// `acceptance` is the API server's own word for what happened, and `dry_run` says whether
/// anything could have changed at all — a dry run is recorded because "somebody asked what this
/// would do" is a fact worth having, and left distinguishable because it is not a change.
///
/// The fields that were written are named and their values are not. What was set is the operator's
/// intent and lives on the mutation record; what is here is the shape of the act.
pub fn mutated(
    ctx: &mut Ctx<'_>,
    instance: &str,
    what: &str,
    scope: &str,
    name: &str,
    dry_run: bool,
    acceptance: &str,
    fields: &[String],
) {
    record(
        ctx,
        json!({
            "action": "mutate",
            "provider_instance": instance,
            "resource": what,
            "scope": scope,
            "name": name,
            "dry_run": dry_run,
            "acceptance": acceptance,
            "fields": fields,
        }),
    );
}

/// Hands one record to the host, and forgets a host that would not take it.
///
/// A trail this package could fail an invocation over would be a trail that decides whether a
/// query succeeds, which is the wrong way round: the record is *about* the work, and losing one
/// must not lose the work. The host's own audit of the call is the backstop — `audit.event` needs
/// no capability, so the only way it fails is a host that is already in trouble.
fn record(ctx: &mut Ctx<'_>, event: serde_json::Value) {
    let _ = ctx.audit_event(event);
}

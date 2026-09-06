//! What an object states about the systems around Kubernetes, routed so that somebody can read it.
//!
//! Specification §28.3 to §28.5, §47 and Appendix C.3. `evidence.rs` in the domain layer exports
//! cross-system identity evidence and refuses to resolve any of it; §47.7 then requires that
//! evidence to be **inspectable**, and until this module existed it was inspectable only by a
//! Rust test. An export nobody can read is not an export.
//!
//! **Which object is the query's answer, and only from a table.** Five kinds state such evidence
//! and each states a different one — §47.2's machine under a Node, §47.3's containers of a Pod,
//! §47.4's load-balancer addresses of a Service or an Ingress, §47.5's CSI handle and driver
//! under a PersistentVolume — so the `kind` option says which,
//! defaulting to `Node`. It is deliberately not the resolution `k8s-resource` does over every
//! group the cluster serves: there is no generic evidence rule, every rule is a set of pointers
//! into one kind's own fields, and a kind resolved through discovery would be fetched and then
//! refused. Refusing by name, before a cluster is reached, is the same answer without the read.
//!
//! Three things decide the shape of the answer, and all three are the domain module's rules
//! surviving into a record.
//!
//! **Nothing here presents a match.** There is no target field, no foreign identifier and no
//! resolution. This provider has read Kubernetes and nothing else, so the strongest honest thing
//! it can say about a machine in another system is "the API server stated this, at this pointer,
//! and this is how far it narrows anything down" (§47.1, ADR-0016). Which foreign resource a
//! value matches is a finding of a resolver that has read both sides, and this package is not
//! one.
//!
//! **Distinguishing evidence stays distinguishable from correlating evidence.** §47.2 ranks
//! `providerID` above IP or name matching, and the rank travels as a field rather than as
//! something a consumer rebuilds from key names — which would be the vendor knowledge §47.1 keeps
//! out of the domain module, re-entering through the boundary. Every address is `correlating` and
//! `lookup_key: false` however exact it looks: private ranges repeat between clusters, a public
//! address outlives the machine that held it, and an identifier baked into a disk image is shared
//! by every machine built from it (§28.5).
//!
//! **A key that could not be read is a record.** `observed: false`, a null value and an `outcome`
//! from §21.4's vocabulary — so a Node whose spec carries no provider identifier reads
//! differently from a Node whose spec nobody projected (§4 invariant 13).
//!
//! No cloud vendor is named anywhere in this file, and `tests/query.rs` reads this source to
//! check it. The moment one scheme gets a match arm here — "just to show the instance nicely" —
//! the policy §28.4 forbids has arrived at the boundary instead of in the library, which is the
//! same policy in a place nobody is looking.

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, Outcome};
use ono_provider_kubernetes::evidence::SubjectEvidence;
use ono_provider_kubernetes::place::Place;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{ByteStream, Client, Freshness};
use ono_value::Schema;

use crate::conditions::named;
use crate::contributions::{Reads, Target};
use crate::query::{
    self, Answer, Conversation, Endpoint, Subject, UNAVAILABLE, UNAVAILABLE_CODE, UNSUPPORTED,
    UNSUPPORTED_CODE, failure,
};
use crate::records::{Exported, evidence_record};
use crate::sessions::Sessions;

/// Answers a `k8s-evidence` query: one object in, what it states about a foreign system out.
#[must_use]
pub fn answer(target: &'static Target, sessions: &Sessions, ctx: &mut Ctx<'_>) -> Outcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return Outcome::Failed(error.into()),
    };
    let Some(name) = named(ctx) else {
        return Outcome::Failed(query::unnamed(
            "to export identity evidence for",
            "--name node-a",
        ));
    };
    let Reads::Evidence = target.reads else {
        return Outcome::Failed(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            "this target does not read identity evidence".to_owned(),
            "This is a defect in the Kubernetes provider's contribution table.",
        ));
    };
    // Which kind, from the query, against the table of kinds that have a rule. A kind with none
    // is refused here rather than fetched and then refused: the answer is the same and the
    // cluster is not asked a question this package cannot use (§47.1).
    let wanted = match subject_kind(ctx) {
        Ok(wanted) => wanted,
        Err(error) => return Outcome::Failed(error),
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return Outcome::Failed(error),
    };
    if ctx.cancelled() {
        return Outcome::Cancelled;
    }

    let read = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            query::converse(
                ctx,
                &endpoint,
                Machine {
                    endpoint: &endpoint,
                    wanted,
                    name: &name,
                    session,
                },
            )
        },
    );
    match read {
        Ok(read) => emit(ctx, target, &schema, read.as_ref()),
        Err(error) => Outcome::Failed(error),
    }
}

/// The kinds §47 gives an evidence rule, and the API group each is served in.
///
/// A table rather than discovery's whole surface, because a rule is pointers into one kind's own
/// fields and no rule generalises. GVK identity on both halves: a custom resource called `Pod` in
/// somebody else's group is not this Pod (§13.5).
const SUBJECTS: &[(&str, &str)] = &[
    ("", "Node"),
    ("", "Pod"),
    ("", "Service"),
    ("networking.k8s.io", "Ingress"),
    ("", "PersistentVolume"),
];

/// Which kind the query asked about, or a refusal naming the ones that have a rule.
fn subject_kind(ctx: &Ctx<'_>) -> Result<&'static (&'static str, &'static str), WireError> {
    let asked = ctx
        .arguments()
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .filter(|kind| !kind.is_empty())
        .unwrap_or("Node");
    SUBJECTS
        .iter()
        .find(|(_, kind)| kind.eq_ignore_ascii_case(asked))
        .ok_or_else(|| {
            let known: Vec<&str> = SUBJECTS.iter().map(|(_, kind)| *kind).collect();
            failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("`{asked}` states no cross-system identity evidence this provider exports"),
                &format!(
                    "Answering nothing would say the object has nothing to say about the systems \
                     around it, which is a different claim. The kinds are: {}. Section 47 gives \
                     each of them a rule of its own; there is no generic one.",
                    known.join(", ")
                ),
            )
        })
}

/// Resolve the subject's collection through discovery, and read one object by name.
struct Machine<'a> {
    endpoint: &'a Endpoint,
    wanted: &'static (&'static str, &'static str),
    name: &'a str,
    session: &'a mut Session,
}

impl Conversation for Machine<'_> {
    type Answer = Option<Subject>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        let served = query::served(session, client, self.endpoint)?;
        // Which collection serves the kind, and at which version, is discovery's answer even for
        // a kind this table names: §4 invariants 1–2 do not make an exception for a kind that has
        // been in the core group since v1.
        let (group, kind) = *self.wanted;
        let resource = query::curated(session, client, self.endpoint, &served, group, kind)?;
        // A Node is cluster-scoped and a Pod is not, and which one this is, is the resource's
        // answer rather than this table's (§9.2, §9.5).
        let scope = query::scope_for(self.endpoint, &resource);
        let (object, freshness) = match query::fetch(client, &resource, &scope, self.name)? {
            Answer::Absent => return Ok(None),
            Answer::Fetched(read) => *read,
            Answer::Listed(_) => {
                return Err(failure(
                    UNAVAILABLE_CODE,
                    UNAVAILABLE,
                    "a direct read answered with a collection".to_owned(),
                    "This is a defect in the Kubernetes provider, not in the cluster.",
                ));
            }
        };
        Ok(Some(Subject {
            resource,
            scope,
            guarded: query::hold(object)?,
            freshness,
        }))
    }
}

/// Streams one record per exported fact, then one per key that could not be read.
///
/// The gaps go last and they go out: a rendering that dropped them would read as "this object has
/// no cross-system identity" when it means "nobody asked" (§4 invariant 13, §47.7).
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    subject: Option<&Subject>,
) -> Outcome {
    // An object that is not there states nothing about a foreign system, and that is an answer
    // rather than a refusal (§21.4 `absent`).
    let Some(subject) = subject else {
        return Outcome::Completed;
    };
    let object = subject.guarded.object();
    let evidence = match SubjectEvidence::of(object) {
        Ok(evidence) => evidence,
        Err(error) => {
            return Outcome::Failed(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("{error}"),
                "This target reads what an object states about the systems around Kubernetes \
                 (specification section 47).",
            ));
        }
    };
    let here = match Place::of_object(object) {
        Ok(here) => here,
        Err(error) => {
            return Outcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the object this is evidence about has no address: {error}"),
                "A place needs a name, and §35.4 binds it to the object's lifetime identity.",
            ));
        }
    };
    let exported = evidence
        .items()
        .iter()
        .map(Exported::Observed)
        .chain(evidence.unobserved().iter().map(Exported::Unobserved));
    for item in exported {
        if ctx.cancelled() {
            return Outcome::Cancelled;
        }
        if let Err(outcome) = one(
            ctx,
            target,
            schema,
            &here,
            subject,
            &item,
            &subject.freshness,
        ) {
            return outcome;
        }
    }
    Outcome::Completed
}

/// One record, built and handed over.
#[allow(
    clippy::too_many_arguments,
    reason = "every argument is one fact the record carries"
)]
fn one(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    here: &Place,
    subject: &Subject,
    exported: &Exported<'_>,
    freshness: &Freshness,
) -> Result<(), Outcome> {
    let value = query::built(
        target,
        evidence_record(target, schema, here, &subject.guarded, exported, freshness),
    )?;
    query::deliver(ctx, &value)
}

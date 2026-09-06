//! What a Node states about the machine underneath it, routed so that somebody can read it.
//!
//! Specification §28.3 to §28.5, §47 and Appendix C.3. `evidence.rs` in the domain layer exports
//! a Node's cross-system identity evidence and refuses to resolve any of it; §47.7 then requires
//! that evidence to be **inspectable**, and until this module existed it was inspectable only by
//! a Rust test. An export nobody can read is not an export.
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
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::evidence::NodeEvidence;
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

/// Answers a `k8s-evidence` query: one Node in, what it states about its machine out.
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
    // The kind is this table's rather than the query's, and it is the one read below `Kind` that
    // still names one: the pointers and the published keys are a Node's, and reading a Pod
    // through them would answer an empty evidence set that renders as a machine with nothing to
    // say rather than as the wrong question (§47.1).
    let Reads::Evidence = target.reads else {
        return Outcome::Failed(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            "this target does not read Node evidence".to_owned(),
            "This is a defect in the Kubernetes provider's contribution table.",
        ));
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

/// Resolve the Node collection through discovery, and read one Node by name.
struct Machine<'a> {
    endpoint: &'a Endpoint,
    name: &'a str,
    session: &'a mut Session,
}

impl Conversation for Machine<'_> {
    type Answer = Option<Subject>;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        let session = self.session;
        let served = query::served(session, client, self.endpoint)?;
        // Which collection serves a Node, and at which version, is discovery's answer even for a
        // kind this table names: §4 invariants 1–2 do not make an exception for a kind that has
        // been in the core group since v1.
        let resource = query::curated(session, client, self.endpoint, &served, "", "Node")?;
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
            scope: Scope::cluster(),
            guarded: query::hold(object)?,
            freshness,
        }))
    }
}

/// Streams one record per exported fact, then one per key that could not be read.
///
/// The gaps go last and they go out: a rendering that dropped them would read as "this Node has
/// no cross-system identity" when it means "nobody asked" (§4 invariant 13, §47.7).
fn emit(
    ctx: &mut Ctx<'_>,
    target: &'static Target,
    schema: &Arc<Schema>,
    subject: Option<&Subject>,
) -> Outcome {
    // A Node that is not there states nothing about a machine, and that is an answer rather than
    // a refusal (§21.4 `absent`).
    let Some(subject) = subject else {
        return Outcome::Completed;
    };
    let node = subject.guarded.object();
    let evidence = match NodeEvidence::of(node) {
        Ok(evidence) => evidence,
        Err(error) => {
            return Outcome::Failed(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("{error}"),
                "This target reads the machine evidence of a Node (specification section 47).",
            ));
        }
    };
    let here = match Place::of_object(node) {
        Ok(here) => here,
        Err(error) => {
            return Outcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the Node this is evidence about has no address: {error}"),
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
            &evidence,
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
    evidence: &NodeEvidence,
    exported: &Exported<'_>,
    freshness: &Freshness,
) -> Result<(), Outcome> {
    let value = query::built(
        target,
        evidence_record(
            target,
            schema,
            here,
            &subject.guarded,
            evidence,
            exported,
            freshness,
        ),
    )?;
    query::deliver(ctx, &value)
}

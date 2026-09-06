//! §60.8 step 3: a synthetic cloud resolver maps this package's exported evidence, and neither
//! side learns anything about the other.
//!
//! Steps 1, 2 and 4 of §60.8 are proven elsewhere — a Node states a `providerID`, `get
//! k8s-evidence` exports it with its pointer, its class and its strength, and `tests/evidence.rs`
//! plus `tests/query.rs` check that no cloud vendor is named on the route and no cloud SDK is in
//! the dependency graph. Step 3 is the one this file is for, and the point of it is a negative:
//! **writing a resolver must require no change in this repository.**
//!
//! So the resolver below lives entirely in this file and is written against the *declared record
//! schema* of `k8s-evidence` and nothing else. Its whole input is `&[Arc<RecordValue>]` — the
//! records the target emits — and the only names it knows are the field names that schema
//! declares. It imports no Kubernetes type, holds no reference to `ono_provider_kubernetes`, and
//! could be compiled in another repository against the published document alone. That is what
//! [`should_read_every_input_field_from_the_declared_evidence_schema`] checks, and it is the
//! whole of §47.1's "a generic cross-system resolver can consume".
//!
//! The decoupling is checked in both directions:
//!
//! ```text
//! resolver -> kubernetes   its input is records; no Kubernetes type appears in its signature
//! kubernetes -> cloud      an invented scheme is exported exactly like a real one, because the
//!                          package has no arm for either
//! ```
//!
//! And the *link* is the resolver's claim, never this provider's (§47.1, ADR-0016). This package
//! emits no field for a match, a link or a foreign identifier; the resolver produces one, and the
//! finding it produces says whose it is and what it rests on. A `providerID` yields a link because
//! the scheme's issuer names one machine with it; an address yields a *candidate* and never a
//! link, because address equality is correlation and §28.5 refuses to let correlation stand as a
//! verified foreign relationship.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::sync::Arc;

use ono_kubernetes_plugin::contributions::{Target, target};
use ono_kubernetes_plugin::records::{Exported, evidence_record};
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::evidence::NodeEvidence;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::place::Place;
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::transport::{EndpointCategory, Freshness, ObservedAt};
use ono_value::{RecordValue, Value};

const INSTANCE: &str = "kubernetes:prod-eu";

/// A Node in a cluster whose cloud controller writes a `providerID` (§60.8 step 1).
const NODE: &str = r#"{
  "apiVersion":"v1","kind":"Node",
  "metadata":{
    "name":"worker-03","uid":"node-1","resourceVersion":"4100",
    "labels":{
      "topology.kubernetes.io/zone":"eu-central-1a",
      "topology.kubernetes.io/region":"eu-central-1",
      "kubernetes.io/hostname":"ip-10-42-0-17"
    }
  },
  "spec":{"providerID":"aws:///eu-central-1a/i-0123456789abcdef0"},
  "status":{
    "addresses":[
      {"type":"InternalIP","address":"10.42.0.17"},
      {"type":"Hostname","address":"ip-10-42-0-17"}
    ],
    "nodeInfo":{"systemUUID":"EC2E4F1A-0000-4000-8000-0123456789AB","machineID":"9f2c"}
  }
}"#;

/// The same Node, in a cluster whose provider identifier belongs to a system nobody has heard of.
///
/// The package must not be able to tell the difference. It is the same fixture with one string
/// changed, so any difference in what comes out is a difference this package invented.
const UNRECOGNISED: &str = r#"{
  "apiVersion":"v1","kind":"Node",
  "metadata":{"name":"worker-04","uid":"node-2","resourceVersion":"4101"},
  "spec":{"providerID":"quantum-fabric:///lattice-7/node-0123456789abcdef0"},
  "status":{"addresses":[{"type":"InternalIP","address":"10.42.0.18"}],"nodeInfo":{}}
}"#;

/// A Node in a cluster running no cloud controller at all (§4 invariant 13).
const BARE_METAL: &str = r#"{
  "apiVersion":"v1","kind":"Node",
  "metadata":{"name":"rack-07","uid":"node-3","resourceVersion":"4102"},
  "spec":{},
  "status":{"addresses":[{"type":"InternalIP","address":"10.42.0.19"}],"nodeInfo":{}}
}"#;

// --- what `get k8s-evidence` puts on the wire ---------------------------------------------------

/// The `k8s-evidence` records for one Node, exactly as the target's handler streams them.
///
/// This is the *producer* half, and it is the only half that may name a Kubernetes type. It runs
/// the same record builder the route runs, over the same contribution table, so what the resolver
/// below reads is what an operator's pipeline receives.
fn exported(document: &str) -> Vec<Arc<RecordValue>> {
    let target: &'static Target = target("k8s-evidence").expect("the package contributes it");
    let schema = Arc::new(
        target
            .schema_contribution()
            .to_schema()
            .expect("the contributed schema is well formed"),
    );
    let node = Object::parse(INSTANCE, document).expect("the fixture is a well-formed Node");
    let evidence = NodeEvidence::of(&node).expect("the fixture is a Node");
    let here = Place::of_object(&node).expect("a Node has an address");
    let freshness = Freshness::direct_read(
        ObservedAt::from_unix_millis(1_000),
        node.resource_version().map(str::to_owned),
        INSTANCE,
        Scope::cluster(),
        EndpointCategory::Core,
    );
    let guarded = Guarded::hold(node.clone()).expect("a Node is not a Secret");

    evidence
        .items()
        .iter()
        .map(Exported::Observed)
        .chain(evidence.unobserved().iter().map(Exported::Unobserved))
        .map(|item| {
            match evidence_record(
                target, &schema, &here, &guarded, &evidence, &item, &freshness,
            )
            .expect("every field the table names is one the schema declares")
            {
                Value::Record(record) => record,
                other => panic!("the record builder answered {other:?}"),
            }
        })
        .collect()
}

// --- the synthetic cloud resolver ----------------------------------------------------------------
//
// Everything below this line is written as if it lived in another repository. It sees records and
// field names; it has never seen a Node, an `Object`, a `Gvr` or this package's source.

/// A resolver for one synthetic foreign system, written against the `k8s-evidence` document.
mod synthetic_cloud {
    use std::sync::Arc;

    use ono_value::{RecordValue, Value};

    /// Every field this resolver reads, exactly as the evidence schema spells them.
    ///
    /// Named as data rather than scattered through the code so a test can check the list against
    /// the schema the package declares: a resolver that read a field the document does not
    /// promise would be coupled to an implementation detail rather than to a contract.
    pub const READS: &[&str] = &[
        "subject",
        "key",
        "qualifier",
        "value",
        "source",
        "strength",
        "evidence_class",
        "lookup_key",
        "uri_scheme",
        "uri_path",
        "observed",
        "outcome",
    ];

    /// The published key a provider identifier arrives under, from the schema's documentation.
    const PROVIDER_ID: &str = "kubernetes.node.provider-id";
    /// The published key an address arrives under.
    const ADDRESS: &str = "kubernetes.node.address";

    /// The one thing this resolver knows that the Kubernetes side does not: which scheme belongs
    /// to which foreign system, and how that system spells an instance.
    ///
    /// This table is the whole of the vendor knowledge in the scenario, and it lives here. A
    /// second system is a second row, in this file, in this repository — never a match arm in the
    /// package that exported the evidence (§47.1, §28.4).
    const SYSTEMS: &[(&str, &str)] = &[("aws", "synthetic-ec2")];

    /// A machine in the foreign system, as this resolver models one.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ForeignInstance {
        /// Which foreign system it belongs to.
        pub system: String,
        /// The identifier that system knows it by.
        pub id: String,
        /// The failure domain that system places it in, where the identifier carries one.
        pub zone: Option<String>,
    }

    /// How far this resolver got with one Kubernetes subject.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Finding {
        /// A distinguishing value resolved to one foreign machine.
        Linked(Link),
        /// A value that correlates and does not identify: worth looking up, never a link (§28.5).
        Candidate {
            /// The Kubernetes place the value belongs to.
            subject: String,
            /// The value itself.
            value: String,
            /// Why it is not a link.
            because: String,
        },
        /// The evidence names a scheme this resolver has never heard of.
        UnknownSystem {
            /// The Kubernetes place the identifier belongs to.
            subject: String,
            /// The scheme nobody here recognises.
            scheme: String,
        },
        /// The key was not read at all, which is not a machine with nothing to say.
        NotExported {
            /// The Kubernetes place the key belongs to.
            subject: String,
            /// Which key.
            key: String,
            /// The outcome the exporter stated.
            outcome: String,
        },
    }

    /// One resolved cross-system link, with whose claim it is.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Link {
        /// The Kubernetes place, as the exporter addressed it.
        pub subject: String,
        /// The foreign machine.
        pub instance: ForeignInstance,
        /// Who says the two are the same thing. Never the Kubernetes provider (§47.1).
        pub claimed_by: String,
        /// What the Kubernetes side stated, and where it stated it.
        pub rests_on: String,
        /// The evidence class of the *link*, in the exporter's own vocabulary.
        ///
        /// `inference` and not `native-field`: the field is native, the identification is not.
        pub evidence_class: String,
    }

    /// This resolver's name, carried on every link it draws.
    pub const NAME: &str = "synthetic-cloud-resolver";

    fn text(record: &RecordValue, field: &str) -> Option<String> {
        match record.get(field) {
            Some(Value::String(value)) => Some(value.to_string()),
            _ => None,
        }
    }

    fn flag(record: &RecordValue, field: &str) -> Option<bool> {
        match record.get(field) {
            Some(Value::Bool(value)) => Some(*value),
            _ => None,
        }
    }

    /// Resolves whatever the exported evidence supports, and refuses the rest.
    #[must_use]
    pub fn resolve(records: &[Arc<RecordValue>]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for record in records {
            let Some(subject) = text(record, "subject") else {
                continue;
            };
            let key = text(record, "key").unwrap_or_default();

            if flag(record, "observed") == Some(false) {
                if key == PROVIDER_ID {
                    findings.push(Finding::NotExported {
                        subject,
                        key,
                        outcome: text(record, "outcome").unwrap_or_default(),
                    });
                }
                continue;
            }

            // §47.2's ranking, read off the record rather than rebuilt from the key name. A value
            // this resolver may not key a lookup on is a candidate and stays one, however exact
            // it looks.
            if flag(record, "lookup_key") != Some(true) {
                if key == ADDRESS {
                    findings.push(Finding::Candidate {
                        subject,
                        value: text(record, "value").unwrap_or_default(),
                        because: format!(
                            "{} evidence: {}",
                            text(record, "strength").unwrap_or_default(),
                            text(record, "qualifier").unwrap_or_default(),
                        ),
                    });
                }
                continue;
            }
            if key != PROVIDER_ID {
                continue;
            }

            let Some(scheme) = text(record, "uri_scheme") else {
                continue;
            };
            let Some((_, system)) = SYSTEMS.iter().find(|(known, _)| *known == scheme) else {
                findings.push(Finding::UnknownSystem { subject, scheme });
                continue;
            };
            let path = text(record, "uri_path").unwrap_or_default();
            // The convention this resolver knows and the exporter does not: this scheme writes the
            // failure domain first and the instance identifier last (§28.4).
            let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
            let Some(id) = segments.last() else {
                continue;
            };
            findings.push(Finding::Linked(Link {
                subject,
                instance: ForeignInstance {
                    system: (*system).to_owned(),
                    id: (*id).to_owned(),
                    zone: segments
                        .first()
                        .filter(|_| segments.len() > 1)
                        .map(|zone| (*zone).to_owned()),
                },
                claimed_by: NAME.to_owned(),
                rests_on: format!(
                    "{} stated at {}",
                    text(record, "value").unwrap_or_default(),
                    text(record, "source").unwrap_or_default(),
                ),
                // The Kubernetes side's class for the *field* is on the record and is
                // `native-field`. The link is not a field anybody stated, so it takes the weakest
                // word the exporter's own vocabulary has.
                evidence_class: "inference".to_owned(),
            }));
        }
        findings
    }
}

use synthetic_cloud::{Finding, Link};

/// The one exported record that carries the provider identifier.
fn identifier_record(records: &[Arc<RecordValue>]) -> Arc<RecordValue> {
    records
        .iter()
        .find(|record| {
            matches!(record.get("key"), Some(Value::String(key)) if
                &**key == "kubernetes.node.provider-id")
        })
        .cloned()
        .expect("the Node states a provider identifier")
}

fn linked(findings: &[Finding]) -> Option<&Link> {
    findings.iter().find_map(|finding| match finding {
        Finding::Linked(link) => Some(link),
        _ => None,
    })
}

// --- §60.8 step 3 --------------------------------------------------------------------------------

#[test]
fn should_map_an_exported_provider_id_to_a_foreign_object() {
    // §60.8 step 3, and the K5 requirement §61.6 spells as "first verified external resolver path
    // without provider-core coupling". The resolver's entire input is the records `get
    // k8s-evidence` emits; it never sees the Node, the object model or this package's source, and
    // it reaches the right machine anyway.
    let findings = synthetic_cloud::resolve(&exported(NODE));
    let link = linked(&findings).expect("a distinguishing identifier resolves to one machine");

    assert_eq!(link.instance.system, "synthetic-ec2");
    assert_eq!(link.instance.id, "i-0123456789abcdef0");
    assert_eq!(link.instance.zone.as_deref(), Some("eu-central-1a"));
    assert_eq!(
        link.subject, "k8s://prod-eu/cluster/node/worker-03",
        "the link attaches to the place the exporter addressed, not to a bare name"
    );
}

#[test]
fn should_leave_the_link_as_the_resolvers_claim_rather_than_this_providers() {
    // §47.1 and ADR-0016. This provider exports evidence and resolves no foreign domain, so the
    // identification is the resolver's finding and has to say so. A link that carried the
    // Kubernetes provider's authority would be a guessed relationship rendered as a proven one
    // (§4 invariant 20).
    let records = exported(NODE);
    let findings = synthetic_cloud::resolve(&records);
    let link = linked(&findings).expect("the identifier resolves");

    assert_eq!(link.claimed_by, synthetic_cloud::NAME);
    assert_eq!(
        link.evidence_class, "inference",
        "the field is native; the identification of a machine in another system is not"
    );
    assert!(
        link.rests_on.contains("/spec/providerID"),
        "the claim cites the pointer it was read from, so a reader can check it: {}",
        link.rests_on
    );

    // And the record it rests on presents no match of its own. The strongest thing this package
    // says is what the API server stated and how far it goes.
    let identifier = records
        .iter()
        .find(|record| {
            matches!(record.get("key"), Some(Value::String(key)) if
                &**key == "kubernetes.node.provider-id")
        })
        .expect("the Node states a provider identifier");
    assert_eq!(
        identifier.get("evidence_class"),
        Some(&Value::String("native-field".into())),
        "the exporter's class is about the field, and the field is native"
    );
    for forbidden in [
        "link",
        "match",
        "matched",
        "resolved",
        "foreign_id",
        "instance",
    ] {
        assert!(
            identifier.get(forbidden).is_none(),
            "`{forbidden}` on an exported record would be a claim about a system this provider \
             has not read (§47.1)"
        );
    }
}

#[test]
fn should_refuse_to_key_a_link_on_correlating_evidence_alone() {
    // §28.5 and §47.4. An address is exact and is the wrong thing to resolve on: private ranges
    // repeat between clusters and a public address outlives the machine that held it. The record
    // carries `lookup_key: false`, the resolver reads it rather than judging the value itself,
    // and the result is a candidate that a human may follow up — never a link.
    let findings = synthetic_cloud::resolve(&exported(NODE));

    let candidates: Vec<&Finding> = findings
        .iter()
        .filter(|finding| matches!(finding, Finding::Candidate { .. }))
        .collect();
    assert!(
        !candidates.is_empty(),
        "the Node reports addresses, and they are worth looking up"
    );
    for candidate in candidates {
        let Finding::Candidate { value, because, .. } = candidate else {
            unreachable!()
        };
        assert!(
            because.contains("correlating"),
            "{value} was offered without the reason it is not a link: {because}"
        );
    }
    assert_eq!(
        findings
            .iter()
            .filter(|finding| matches!(finding, Finding::Linked(_)))
            .count(),
        1,
        "one distinguishing identifier, one link — the addresses added none"
    );
}

#[test]
fn should_answer_a_node_that_states_no_provider_identifier_as_a_gap() {
    // §4 invariant 13 across the boundary. A bare-metal Node has no provider identifier, and the
    // export says so with an outcome rather than by omitting the row. A resolver that saw nothing
    // could not tell "this machine is not in a cloud" from "nobody read the spec".
    let findings = synthetic_cloud::resolve(&exported(BARE_METAL));

    let gap = findings
        .iter()
        .find_map(|finding| match finding {
            Finding::NotExported { key, outcome, .. } => Some((key, outcome)),
            _ => None,
        })
        .expect("a key that was not read is still a record");
    assert_eq!(gap.0, "kubernetes.node.provider-id");
    assert_eq!(
        gap.1, "absent",
        "the spec was read and carries none, which is a fact about the cluster"
    );
    assert!(
        linked(&findings).is_none(),
        "nothing was identified, and nothing may be presented as identified"
    );
}

// --- decoupling, in both directions ---------------------------------------------------------------

#[test]
fn should_export_an_unrecognised_scheme_exactly_as_it_exports_a_recognised_one() {
    // Gate K (§62.11) as a claim about behaviour rather than about a grep. If this package knew
    // anything about a cloud, an invented scheme would come out differently from a real one —
    // decomposed less, ranked lower, or dropped. It comes out identically, because there is no arm
    // for either: §28.4's whole permitted decomposition is a scheme and a path, and no segment is
    // labelled.
    let known = identifier_record(&exported(NODE));
    let invented = identifier_record(&exported(UNRECOGNISED));

    for field in [
        "strength",
        "evidence_class",
        "asserted",
        "lookup_key",
        "observed",
    ] {
        assert_eq!(
            known.get(field),
            invented.get(field),
            "`{field}` differs between a scheme this package could recognise and one it could \
             not, so something in the package recognises one"
        );
    }
    assert_eq!(
        invented.get("uri_scheme"),
        Some(&Value::String("quantum-fabric".into()))
    );
    assert_eq!(
        invented.get("uri_path"),
        Some(&Value::String("/lattice-7/node-0123456789abcdef0".into())),
        "undivided, because knowing that a scheme puts a failure domain first is knowledge of a \
         system this package has not read"
    );

    // And the resolver is where the knowledge is: it recognises one of the two and says so about
    // the other rather than guessing.
    let findings = synthetic_cloud::resolve(&exported(UNRECOGNISED));
    assert!(
        findings.iter().any(
            |finding| matches!(finding, Finding::UnknownSystem { scheme, .. } if
                scheme == "quantum-fabric")
        ),
        "the vendor table is the resolver's, so an unknown scheme is the resolver's refusal"
    );
    assert!(linked(&findings).is_none());
}

#[test]
fn should_read_every_input_field_from_the_declared_evidence_schema() {
    // The decoupling in the other direction, and the reason step 3 is worth a test at all: writing
    // a resolver must require no change in this repository. This one is written against the
    // `k8s-evidence` contribution and nothing else — every name it reads is a field that schema
    // declares, so it could have been written from the published document by somebody who has
    // never seen this source tree.
    let target = target("k8s-evidence").expect("the package contributes it");
    let declared: Vec<&str> = target.fields.iter().map(|field| field.name).collect();

    for field in synthetic_cloud::READS {
        assert!(
            declared.contains(field),
            "the resolver reads `{field}`, which the `k8s-evidence` schema does not declare — \
             a resolver coupled to an implementation detail rather than to a contract"
        );
    }
}

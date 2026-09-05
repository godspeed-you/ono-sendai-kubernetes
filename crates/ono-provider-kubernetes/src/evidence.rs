//! What a Node says about the machine underneath it, exported for someone else to resolve.
//!
//! Specification §28.3 to §28.5, §47 and Appendix C.3. One rule shapes the whole module, and it
//! is §47.1: **this provider exports identity evidence and never resolves a foreign domain.** It
//! has read Kubernetes and nothing else, so the honest strongest claim it can make about a
//! machine in another system is "here is what the API server stated, and here is how strongly
//! that field identifies anything". Which foreign resource the value matches is a finding of the
//! resolver that has read both sides.
//!
//! That is also Gate K (§62.11), and Gate K is a claim about this file: `spec.providerID` is
//! exported *without* the package learning what any particular scheme means. The identifier is
//! decomposed as far as `<scheme>://<path>` goes and no further, because the moment one scheme
//! gets a match arm — "just to show the instance nicely" — the vendor policy §28.4 forbids has
//! arrived, and the second arm follows within a week. `tests/evidence.rs` reads this source and
//! fails if a vendor is named in it, including in an example.
//!
//! Three strengths, because §47.2 ranks them and a flat list would throw the ranking away:
//!
//! ```text
//! distinguishing   a field that exists to name one thing: spec.providerID, status.nodeInfo.systemUUID
//! correlating      equal across unrelated things, or reassigned: an address, a copied host id
//! placement        where the subject sits rather than which thing it is: zone, region, arch
//! ```
//!
//! What is deliberately absent: any way to turn evidence into a relationship. There is no
//! constructor here that produces one, because §28.5 forbids address equality from establishing a
//! verified foreign link and a type that could express the link would eventually be asked to.

use crate::coverage::Outcome;
use crate::object::{Identity, Object};
use crate::relationship::Evidence;

/// The keys evidence is published under.
///
/// Constants rather than literals at each call site, because Appendix C.3 fixes the spelling a
/// resolver written against the document will look for, and a key nobody can typo is one fewer
/// way for exported evidence to become unreachable.
pub mod key {
    /// `spec.providerID` (§28.4, Appendix C.3).
    pub const PROVIDER_ID: &str = "kubernetes.node.provider-id";
    /// One entry of `status.addresses`, qualified by the type the API gave it (§28.5).
    pub const ADDRESS: &str = "kubernetes.node.address";
    /// `status.nodeInfo.systemUUID` (§47.2).
    pub const SYSTEM_UUID: &str = "kubernetes.node.system-uuid";
    /// `status.nodeInfo.machineID` (§47.2).
    pub const MACHINE_ID: &str = "kubernetes.node.machine-id";
    /// The failure domain the Node is in (§28.3).
    pub const ZONE: &str = "kubernetes.node.zone";
    /// The wider region the failure domain belongs to (§28.3).
    pub const REGION: &str = "kubernetes.node.region";
    /// The machine class the Node runs on (§28.3).
    pub const INSTANCE_TYPE: &str = "kubernetes.node.instance-type";
    /// The CPU architecture (§28.3).
    pub const ARCHITECTURE: &str = "kubernetes.node.architecture";
    /// The operating system (§28.3).
    pub const OPERATING_SYSTEM: &str = "kubernetes.node.operating-system";
    /// The hostname the cluster labelled the Node with (§28.3).
    ///
    /// Distinct from an address of type `Hostname`: one is a label a controller wrote and the
    /// other is what the kubelet reported into status. They usually agree, and when they disagree
    /// that is worth seeing rather than resolving.
    pub const HOSTNAME: &str = "kubernetes.node.hostname";
}

/// Why no evidence could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// The object is not a Node, so the Node pointers below would read nothing from it.
    NotANode {
        /// What the object turned out to be.
        gvk: String,
    },
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotANode { gvk } => write!(
                f,
                "`{gvk}` is not a Node, and Node evidence read from it would be empty rather \
                 than absent"
            ),
        }
    }
}

impl std::error::Error for EvidenceError {}

/// How much one value narrows down which foreign thing the subject is.
///
/// §47.2 states the ranking — `providerID` is stronger evidence than IP or name matching — and a
/// consumer that could not see the ranking would have to rebuild it from field names, which is
/// the vendor knowledge §47.1 keeps out of here in a different disguise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Strength {
    /// A field whose purpose is to name one thing, uniquely, in the system that assigned it.
    Distinguishing,
    /// A value that correlates and does not identify: equal across unrelated things, reassigned
    /// while the thing lives, or copied when a machine is cloned (§28.5).
    Correlating,
    /// A property of where the subject sits rather than of which thing it is. A thousand machines
    /// share a zone (§28.3).
    Placement,
}

impl Strength {
    /// The word this strength is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Distinguishing => "distinguishing",
            Self::Correlating => "correlating",
            Self::Placement => "placement",
        }
    }

    /// Whether one value of this strength is, on its own, a candidate key for a foreign lookup.
    #[must_use]
    pub fn is_distinguishing(self) -> bool {
        matches!(self, Self::Distinguishing)
    }
}

/// The generic shape of an identifier that came as a URI: a scheme, and the path under it.
///
/// The whole decomposition §28.4 permits. It knows that `://` separates a scheme from a path and
/// that `/` separates path segments; it does not know that some schemes put a failure domain
/// first, and it labels no segment. A resolver that has read the other system knows both, and
/// that is where the knowledge belongs (§47.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriShape {
    scheme: String,
    path: String,
}

impl UriShape {
    /// The scheme, without the separator.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Everything after the separator, unchanged — leading slashes and all.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The path's non-empty segments, in the order they were written.
    ///
    /// Empty segments are dropped because `scheme:///a/b` and `scheme://a/b` differ only in a
    /// convention about authority, and a consumer counting segments would otherwise have to know
    /// which schemes use which. The raw string keeps the difference for anyone who needs it.
    #[must_use]
    pub fn segments(&self) -> Vec<&str> {
        self.path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect()
    }
}

/// `spec.providerID`, kept whole and read only as far as its shape allows (§28.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderId {
    raw: String,
    shape: Option<UriShape>,
}

impl ProviderId {
    /// Reads an identifier without interpreting it.
    ///
    /// A value with no `://` is not malformed and is not rejected: the field is documented as
    /// opaque to Kubernetes, so an installation may write anything into it, and a parser that
    /// insisted on a URI would drop the strongest evidence a Node carries because it did not like
    /// the spelling.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        Self {
            raw: raw.to_owned(),
            shape: raw.split_once("://").map(|(scheme, path)| UriShape {
                scheme: scheme.to_owned(),
                path: path.to_owned(),
            }),
        }
    }

    /// The identifier exactly as the API server stated it.
    ///
    /// What a resolver matches on. The shape below is for reading; this is the value.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The scheme and path, where the value came as a URI.
    #[must_use]
    pub fn shape(&self) -> Option<&UriShape> {
        self.shape.as_ref()
    }

    /// Whether the identifier carried a recognisable URI structure.
    #[must_use]
    pub fn is_uri_shaped(&self) -> bool {
        self.shape.is_some()
    }
}

/// One exported fact about the subject, with where it came from and how far it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityEvidence {
    subject: Identity,
    key: String,
    qualifier: Option<String>,
    value: String,
    source: String,
    strength: Strength,
    evidence: Evidence,
}

impl IdentityEvidence {
    /// The object this is evidence about (Appendix C.3's `subject`).
    ///
    /// The identity rather than the name, so a resolver's finding attaches to a lifetime: a Node
    /// rebuilt under the same name is a different machine, and evidence that outlived the rebuild
    /// would point the resolver at hardware that is gone (§4 invariants 4 and 5).
    #[must_use]
    pub fn subject(&self) -> &Identity {
        &self.subject
    }

    /// What kind of fact this is, from [`key`].
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// What narrows the key: the address type for an address (§28.5).
    ///
    /// Absent where the key already says everything. It is carried beside the value rather than
    /// folded into it, because a resolver matching an internal address against a public inventory
    /// is precisely the mistake §28.5's "with type information" prevents.
    #[must_use]
    pub fn qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }

    /// The value, as the field held it.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The JSON pointer this was read from, resolvable against the object it came from.
    ///
    /// A citation a reader can check rather than a field name they have to trust (§47.7).
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// How far this value narrows the subject down.
    #[must_use]
    pub fn strength(&self) -> Strength {
        self.strength
    }

    /// What class of thing this rests on: a field the server stated, or a naming convention.
    ///
    /// The provider's existing vocabulary (§23), deliberately not a second one. It carries the
    /// distinction that matters most here — what the API server *states* against what someone
    /// *derived* — and [`Evidence::Inferred`] is the resolver's to produce. Nothing in this
    /// module produces it: an inference wearing this provider's authority is exactly what §4
    /// invariant 20 forbids.
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Whether a resolver may key a foreign lookup on this value alone (§47.2).
    ///
    /// False for every address and every copied host identifier (§28.5): private ranges repeat
    /// between clusters, a public address outlives the machine that held it, a hostname is
    /// assigned rather than owned, and an identifier baked into a disk image is shared by every
    /// machine built from it.
    ///
    /// Note what neither answer says: that a match *is* a verified link. Matching happens against
    /// a system this provider has not read, so the strongest thing exported here is a key worth
    /// looking up (§47.1, §28.5).
    #[must_use]
    pub fn is_lookup_key(&self) -> bool {
        self.strength.is_distinguishing()
    }

    /// One line, in the field's own spelling (§47.7).
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}: {}", self.label(), self.value)
    }

    fn label(&self) -> &str {
        self.qualifier
            .as_deref()
            .unwrap_or_else(|| label_of(&self.key))
    }
}

/// A key that could not be read, and whether that is a fact about the cluster or about the read.
///
/// [`Outcome`] rather than a bool, for §4 invariant 13's reason one field down: a Node whose spec
/// came back without a provider identifier has none, and a metadata-only projection says nothing
/// about whether it has one. Both render as "no identifier" unless the difference is carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unobserved {
    key: String,
    outcome: Outcome,
}

impl Unobserved {
    /// Which key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Why it is not here.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// One line naming the key and what happened.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}: {}", label_of(&self.key), self.outcome.as_str())
    }
}

/// Everything one Node exports for a cross-system resolver, and everything it could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEvidence {
    subject: Identity,
    provider_id: Option<ProviderId>,
    items: Vec<IdentityEvidence>,
    unobserved: Vec<Unobserved>,
}

impl NodeEvidence {
    /// Reads a Node's cross-system evidence.
    ///
    /// # Errors
    ///
    /// [`EvidenceError::NotANode`] for any other object. The keys and pointers below are a Node's,
    /// and reading a Pod through them would produce an empty evidence set that renders as a Node
    /// with nothing to say rather than as the wrong question.
    pub fn of(node: &Object) -> Result<Self, EvidenceError> {
        if !(node.gvk().group().is_empty() && node.gvk().kind() == "Node") {
            return Err(EvidenceError::NotANode {
                gvk: node.gvk().to_string(),
            });
        }

        let subject = node.identity();
        let mut items = Vec::new();
        let mut unobserved = Vec::new();

        let provider_id = node
            .field("/spec/providerID")
            .and_then(serde_json::Value::as_str)
            .map(ProviderId::parse);
        match &provider_id {
            Some(identifier) => items.push(IdentityEvidence {
                subject: subject.clone(),
                key: key::PROVIDER_ID.to_owned(),
                qualifier: None,
                value: identifier.raw().to_owned(),
                source: "/spec/providerID".to_owned(),
                strength: Strength::Distinguishing,
                evidence: Evidence::NativeField {
                    path: "/spec/providerID".to_owned(),
                    value: identifier.raw().to_owned(),
                },
            }),
            None => unobserved.push(Unobserved {
                key: key::PROVIDER_ID.to_owned(),
                // The spec stanza came back and did not carry the field, so the Node has no
                // provider identifier — a cluster running no cloud controller. With no spec at
                // all, nobody asked, and saying "absent" would make a projection choice look like
                // a fact about the machine.
                outcome: read_outcome(node, "/spec"),
            }),
        }

        let addresses = node
            .field("/status/addresses")
            .and_then(serde_json::Value::as_array);
        let mut address_count = 0;
        for (at, entry) in addresses.into_iter().flatten().enumerate() {
            let (Some(address_type), Some(address)) = (
                entry.get("type").and_then(serde_json::Value::as_str),
                entry.get("address").and_then(serde_json::Value::as_str),
            ) else {
                continue;
            };
            let source = format!("/status/addresses/{at}/address");
            items.push(IdentityEvidence {
                subject: subject.clone(),
                key: key::ADDRESS.to_owned(),
                qualifier: Some(address_type.to_owned()),
                value: address.to_owned(),
                source: source.clone(),
                strength: Strength::Correlating,
                evidence: Evidence::NativeField {
                    path: source,
                    value: address.to_owned(),
                },
            });
            address_count += 1;
        }
        if address_count == 0 {
            unobserved.push(Unobserved {
                key: key::ADDRESS.to_owned(),
                outcome: read_outcome(node, "/status"),
            });
        }

        // What the machine reports about itself through the kubelet (§47.2). The two are not
        // equally strong: a system UUID is issued per machine, and a machine id is written into
        // the filesystem, so every host built from one disk image carries the same one.
        push_node_info(
            &mut items,
            &mut unobserved,
            node,
            &subject,
            key::SYSTEM_UUID,
            "systemUUID",
            Strength::Distinguishing,
        );
        push_node_info(
            &mut items,
            &mut unobserved,
            node,
            &subject,
            key::MACHINE_ID,
            "machineID",
            Strength::Correlating,
        );

        for (published, labels, strength) in PLACEMENT {
            let Some((label, value)) = labels
                .iter()
                .find_map(|label| node.label(label).map(|value| (*label, value)))
            else {
                // A missing placement label is a missing label. It is not recorded as a gap: the
                // gaps above are about identity, and a list where every optional convention leaves
                // a row is one an operator stops reading.
                continue;
            };
            items.push(IdentityEvidence {
                subject: subject.clone(),
                key: (*published).to_owned(),
                qualifier: None,
                value: value.to_owned(),
                source: label_pointer(label),
                strength: *strength,
                // A well-known label is a convention rather than API structure (§23.4): a
                // controller writes it and anyone with write access can change it, which is
                // weaker than a field the server owns and must render as weaker.
                evidence: Evidence::Convention {
                    key: label.to_owned(),
                    value: value.to_owned(),
                },
            });
        }

        Ok(Self {
            subject,
            provider_id,
            items,
            unobserved,
        })
    }

    /// The Node this is evidence about.
    #[must_use]
    pub fn subject(&self) -> &Identity {
        &self.subject
    }

    /// Everything exported, in the order it was read.
    #[must_use]
    pub fn items(&self) -> &[IdentityEvidence] {
        &self.items
    }

    /// The provider identifier, decomposed (§28.4).
    #[must_use]
    pub fn provider_id(&self) -> Option<&ProviderId> {
        self.provider_id.as_ref()
    }

    /// Every item published under one key.
    ///
    /// A list because [`key::ADDRESS`] repeats: a Node commonly reports an internal address, a
    /// public one and a hostname, and each is separate evidence.
    #[must_use]
    pub fn by_key(&self, wanted: &str) -> Vec<&IdentityEvidence> {
        self.items
            .iter()
            .filter(|item| item.key == wanted)
            .collect()
    }

    /// The keys that could not be read, and why.
    #[must_use]
    pub fn unobserved(&self) -> &[Unobserved] {
        &self.unobserved
    }

    /// Why one key is missing, or [`None`] where it is not missing.
    #[must_use]
    pub fn outcome_for(&self, wanted: &str) -> Option<Outcome> {
        self.unobserved
            .iter()
            .find(|gap| gap.key == wanted)
            .map(Unobserved::outcome)
    }

    /// The evidence as §47.7 renders it, with no foreign provider attached.
    ///
    /// The point of exporting rather than resolving: an operator reads the identifier and goes to
    /// look it up themselves, today, against a system this provider will never speak to. The gaps
    /// are printed with it, because a rendering that dropped them would read as "this Node has no
    /// cross-system identity" when it means "nobody asked".
    #[must_use]
    pub fn describe(&self) -> String {
        self.items
            .iter()
            .map(IdentityEvidence::describe)
            .chain(self.unobserved.iter().map(Unobserved::describe))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The well-known labels §28.3 names, current spelling first.
///
/// The deprecated spellings are read too, and are not a courtesy: clusters inside the support
/// window of §5.1 still carry them, and a provider that read only the current key would report no
/// failure domain for a running cluster — an absence about this code rather than about the
/// cluster.
const PLACEMENT: &[(&str, &[&str], Strength)] = &[
    (
        key::ZONE,
        &[
            "topology.kubernetes.io/zone",
            "failure-domain.beta.kubernetes.io/zone",
        ],
        Strength::Placement,
    ),
    (
        key::REGION,
        &[
            "topology.kubernetes.io/region",
            "failure-domain.beta.kubernetes.io/region",
        ],
        Strength::Placement,
    ),
    (
        key::INSTANCE_TYPE,
        &[
            "node.kubernetes.io/instance-type",
            "beta.kubernetes.io/instance-type",
        ],
        Strength::Placement,
    ),
    (
        key::ARCHITECTURE,
        &["kubernetes.io/arch", "beta.kubernetes.io/arch"],
        Strength::Placement,
    ),
    (
        key::OPERATING_SYSTEM,
        &["kubernetes.io/os", "beta.kubernetes.io/os"],
        Strength::Placement,
    ),
    (
        // A hostname names one machine rather than a class of them, so it correlates where the
        // rest merely place. It is still not a key: hostnames are assigned, reused and duplicated
        // between networks.
        key::HOSTNAME,
        &["kubernetes.io/hostname"],
        Strength::Correlating,
    ),
];

fn push_node_info(
    items: &mut Vec<IdentityEvidence>,
    unobserved: &mut Vec<Unobserved>,
    node: &Object,
    subject: &Identity,
    published: &str,
    field: &str,
    strength: Strength,
) {
    let pointer = format!("/status/nodeInfo/{field}");
    match node.field(&pointer).and_then(serde_json::Value::as_str) {
        Some(value) => items.push(IdentityEvidence {
            subject: subject.clone(),
            key: published.to_owned(),
            qualifier: None,
            value: value.to_owned(),
            source: pointer.clone(),
            strength,
            evidence: Evidence::NativeField {
                path: pointer,
                value: value.to_owned(),
            },
        }),
        None => unobserved.push(Unobserved {
            key: published.to_owned(),
            outcome: read_outcome(node, "/status"),
        }),
    }
}

/// Whether a missing field means the object does not carry it, or that the stanza holding it was
/// never read.
fn read_outcome(node: &Object, stanza: &str) -> Outcome {
    if node.field(stanza).is_some() {
        Outcome::Absent
    } else {
        Outcome::NotQueried
    }
}

/// A label key as a JSON pointer, with RFC 6901's escapes applied.
///
/// Label keys contain `/`, which is the pointer's own separator. Writing the key in unescaped
/// would produce a citation that silently resolves to nothing — a source line that looks checkable
/// and is not, which is worse than no citation.
fn label_pointer(label: &str) -> String {
    format!(
        "/metadata/labels/{}",
        label.replace('~', "~0").replace('/', "~1")
    )
}

/// The field's own spelling, for a rendering that matches the object it came from (§47.7).
fn label_of(published: &str) -> &str {
    match published {
        key::PROVIDER_ID => "providerID",
        key::ADDRESS => "address",
        key::SYSTEM_UUID => "systemUUID",
        key::MACHINE_ID => "machineID",
        key::ZONE => "zone",
        key::REGION => "region",
        key::INSTANCE_TYPE => "instanceType",
        key::ARCHITECTURE => "architecture",
        key::OPERATING_SYSTEM => "operatingSystem",
        key::HOSTNAME => "hostname",
        other => other,
    }
}

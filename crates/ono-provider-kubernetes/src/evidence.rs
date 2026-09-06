//! What an object says about the systems around Kubernetes, exported for someone else to resolve.
//!
//! Specification §28.3 to §28.5, §47 and Appendix C.3. Three subjects state such a thing, and
//! each states a different one: a **Node** names the machine underneath it (§47.2), a **Pod**
//! names the containers and images a runtime holds for it (§47.3, §47.6), and a **Service** or an
//! **Ingress** names the load-balancer addresses something outside the cluster answers on
//! (§47.4). One rule shapes the whole module, and it
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
//! fails if a vendor is named in it, including in an example. §47.3 asks for exactly the same
//! restraint one level down: a container identifier keeps the scheme the kubelet wrote, and no
//! rule here knows what any particular runtime's scheme means.
//!
//! Three strengths, because §47.2 ranks them and a flat list would throw the ranking away:
//!
//! ```text
//! distinguishing   a field that exists to name one thing: spec.providerID, status.nodeInfo.systemUUID
//! correlating      equal across unrelated things, or reassigned: an address, a copied host id
//! placement        where the subject sits rather than which thing it is: zone, region, arch
//! ```
//!
//! §47.6 is where that ranking earns its keep: an image *tag* and an image *digest* are two
//! different claims about one container, the tag names something a person may move tonight, and
//! the section says in as many words that tag equality MUST NOT be confused with digest identity.
//! So they are exported as separate keys at separate strengths rather than as one "image".
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

    /// One container's `containerID`, with the runtime scheme the kubelet wrote (§47.3).
    ///
    /// Qualified by the container's name, because a Pod holds several and an identifier with no
    /// container against it is a fact about a Pod rather than about a container.
    pub const CONTAINER_ID: &str = "kubernetes.pod.container-id";
    /// One container's `imageID`: the image the runtime actually resolved and pulled (§47.6).
    pub const IMAGE_ID: &str = "kubernetes.pod.image-id";
    /// One container's `image`: the reference the object *asked* for (§47.6).
    ///
    /// A different claim from [`IMAGE_ID`] and deliberately a separate key. A tag is a name
    /// somebody may point at different content tonight; a digest names the content.
    pub const IMAGE: &str = "kubernetes.pod.image";
    /// One entry of `status.loadBalancer.ingress`, qualified by what kind of address it is
    /// (§47.4).
    ///
    /// One key for a Service and for an Ingress: the field is the same field, and a resolver
    /// matching an address against an inventory does not care which kind published it.
    pub const LOAD_BALANCER_ADDRESS: &str = "kubernetes.load-balancer.address";
}

/// Why no evidence could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// The object is not a Node, so the Node pointers below would read nothing from it.
    NotANode {
        /// What the object turned out to be.
        gvk: String,
    },
    /// The object is not of the kind the requested rule reads.
    WrongKind {
        /// What the rule reads.
        expected: &'static str,
        /// What the object turned out to be.
        gvk: String,
    },
    /// No rule here reads this kind, so there is no evidence to export rather than none present.
    ///
    /// Every rule in this module is a set of pointers into one kind's own fields. A kind without
    /// one would answer an empty evidence set, which renders as an object with nothing to say
    /// about the systems around it — and that is the wrong question answered confidently.
    NoRule {
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
            Self::WrongKind { expected, gvk } => write!(
                f,
                "`{gvk}` is not {expected}, and evidence read from it through {expected}'s \
                 pointers would be empty rather than absent"
            ),
            Self::NoRule { gvk } => write!(
                f,
                "`{gvk}` states no cross-system identity evidence this provider exports; the \
                 kinds that do are Node, Pod, Service and Ingress (specification section 47)"
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

/// An identifier written by another system, kept whole and read only as far as its shape allows.
///
/// One parser for §28.4's `spec.providerID` and §47.3's container and image identifiers, because
/// they are the same problem: a value some other system minted, conventionally written as
/// `<scheme>://<path>`, whose scheme this provider MUST preserve and MUST NOT interpret. A second
/// parser would be a second place for one of them to acquire a match arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemedId {
    raw: String,
    shape: Option<UriShape>,
}

/// What §28.4 and Appendix C.3 call this when the subject is a Node.
pub type ProviderId = SchemedId;

impl SchemedId {
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
    shape: Option<UriShape>,
}

impl IdentityEvidence {
    /// One value a field of the subject stated, at the pointer it was read from.
    ///
    /// The decomposition is attached here rather than recomputed by a consumer, and only for the
    /// keys that carry an identifier some other system minted: an address is not a URI, and a
    /// scheme parsed out of one would be a shape nobody stated.
    fn stated(
        subject: &Identity,
        key: &str,
        qualifier: Option<&str>,
        value: &str,
        source: String,
        strength: Strength,
    ) -> Self {
        Self {
            subject: subject.clone(),
            key: key.to_owned(),
            qualifier: qualifier.map(str::to_owned),
            value: value.to_owned(),
            source: source.clone(),
            strength,
            evidence: Evidence::NativeField {
                path: source,
                value: value.to_owned(),
            },
            shape: SCHEMED
                .contains(&key)
                .then(|| SchemedId::parse(value).shape)
                .flatten(),
        }
    }
}

/// The keys whose value is an identifier another system minted, written `<scheme>://<path>`.
///
/// A list rather than a guess at the value's shape: `10.42.0.17` will never contain `://`, and a
/// rule that decomposed whatever happened to look like a URI would eventually decompose something
/// that only looked like one.
const SCHEMED: &[&str] = &[key::PROVIDER_ID, key::CONTAINER_ID, key::IMAGE_ID];

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

    /// The scheme and path, where this key's value came as a URI (§28.4, §47.3).
    #[must_use]
    pub fn shape(&self) -> Option<&UriShape> {
        self.shape.as_ref()
    }

    /// One line, in the field's own spelling (§47.7).
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{}: {}",
            labelled(&self.key, self.qualifier.as_deref()),
            self.value
        )
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

/// Everything one object exports for a cross-system resolver, and everything it could not.
///
/// One type for three subjects, because a resolver consumes items rather than kinds: what differs
/// between a Node, a Pod and a load-balanced Service is which pointers were read, and that
/// travels on each item as its `source`. What must not differ is the shape of the answer, or a
/// consumer would need a rule per kind — and rules per kind are how foreign-domain knowledge
/// arrives (§47.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectEvidence {
    subject: Identity,
    provider_id: Option<ProviderId>,
    items: Vec<IdentityEvidence>,
    unobserved: Vec<Unobserved>,
}

impl SubjectEvidence {
    /// Reads whatever cross-system evidence the object's own kind states (§47.2 to §47.4).
    ///
    /// The dispatch is on GVK, so a custom resource that happens to be called `Pod` is not read
    /// through a Pod's pointers (§13.5).
    ///
    /// # Errors
    ///
    /// [`EvidenceError::NoRule`] for a kind no rule here reads. Answering an empty evidence set
    /// would render as an object that states nothing about the systems around it, which is a
    /// confident answer to a question nobody can ask of a ConfigMap.
    pub fn of(object: &Object) -> Result<Self, EvidenceError> {
        match (object.gvk().group(), object.gvk().kind()) {
            ("", "Node") => Self::of_node(object),
            ("", "Pod") => Self::of_pod(object),
            ("", "Service") | ("networking.k8s.io", "Ingress") => Self::of_load_balancer(object),
            _ => Err(EvidenceError::NoRule {
                gvk: object.gvk().to_string(),
            }),
        }
    }

    /// Reads a Node's cross-system evidence.
    ///
    /// # Errors
    ///
    /// [`EvidenceError::NotANode`] for any other object. The keys and pointers below are a Node's,
    /// and reading a Pod through them would produce an empty evidence set that renders as a Node
    /// with nothing to say rather than as the wrong question.
    pub fn of_node(node: &Object) -> Result<Self, EvidenceError> {
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
            Some(identifier) => items.push(IdentityEvidence::stated(
                &subject,
                key::PROVIDER_ID,
                None,
                identifier.raw(),
                "/spec/providerID".to_owned(),
                Strength::Distinguishing,
            )),
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
            items.push(IdentityEvidence::stated(
                &subject,
                key::ADDRESS,
                Some(address_type),
                address,
                format!("/status/addresses/{at}/address"),
                Strength::Correlating,
            ));
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
                shape: None,
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

    /// Reads a Pod's container and image evidence (§47.3, §47.6).
    ///
    /// Every container list the status carries, in the order `containerStatuses`,
    /// `initContainerStatuses`, `ephemeralContainerStatuses`: an init container that failed and a
    /// debug container somebody attached are exactly the ones an operator is chasing across a
    /// runtime boundary, and reading the first list alone would report them as absent.
    ///
    /// Three keys per container, and they are three claims rather than one. The `containerID` and
    /// the `imageID` name one thing each — a container the runtime holds, content a registry
    /// stores — while the `image` is the reference the object *asked* for, which somebody may
    /// point at different content tonight. §47.6 forbids confusing the last with the first two,
    /// and the strengths here are that sentence.
    ///
    /// The scheme in front of an identifier is kept exactly as the kubelet wrote it, including
    /// one no rule here has ever seen (§47.3, §47.1).
    ///
    /// # Errors
    ///
    /// [`EvidenceError::WrongKind`] for anything that is not a core-group Pod.
    pub fn of_pod(pod: &Object) -> Result<Self, EvidenceError> {
        if !(pod.gvk().group().is_empty() && pod.gvk().kind() == "Pod") {
            return Err(EvidenceError::WrongKind {
                expected: "a Pod",
                gvk: pod.gvk().to_string(),
            });
        }
        let subject = pod.identity();
        let mut items = Vec::new();

        for list in CONTAINER_LISTS {
            let pointer = format!("/status/{list}");
            let Some(statuses) = pod.field(&pointer).and_then(serde_json::Value::as_array) else {
                continue;
            };
            for (at, status) in statuses.iter().enumerate() {
                let Some(container) = status.get("name").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                for (field, published, strength) in CONTAINER_FIELDS {
                    // An empty string is a field the kubelet has not filled in yet — a container
                    // whose image the runtime has not resolved — and exporting it would hand a
                    // resolver a key that matches everything unresolved everywhere.
                    let Some(value) = status
                        .get(field)
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.is_empty())
                    else {
                        continue;
                    };
                    items.push(IdentityEvidence::stated(
                        &subject,
                        published,
                        Some(container),
                        value,
                        format!("{pointer}/{at}/{field}"),
                        *strength,
                    ));
                }
            }
        }

        // §4 invariant 13 at the Pod: a status that came back and lists no container is a Pod
        // running nothing, and a metadata-only projection says nothing about what it runs.
        let unobserved = CONTAINER_FIELDS
            .iter()
            .filter(|(_, published, _)| !items.iter().any(|item| item.key == *published))
            .map(|(_, published, _)| Unobserved {
                key: (*published).to_owned(),
                outcome: read_outcome(pod, "/status"),
            })
            .collect();

        Ok(Self {
            subject,
            provider_id: None,
            items,
            unobserved,
        })
    }

    /// Reads the load-balancer addresses a Service or an Ingress reports (§47.4).
    ///
    /// `status.loadBalancer.ingress[]` on both kinds, because it is the same field stating the
    /// same thing: an address something outside this cluster answers on. Each entry may carry an
    /// address, a hostname or both, and each is exported separately with the kind of address it
    /// is — §28.5's reason at another object, because an address and a hostname resolve against
    /// different foreign systems.
    ///
    /// Every one of them is `correlating` and no lookup key however exact it looks. §47.4 says
    /// why: an IP or hostname match alone remains a resolver's evidence, never a
    /// Kubernetes-verified foreign relationship — the address of a load balancer that was deleted
    /// this morning is answered by whatever took it over this afternoon.
    ///
    /// # Errors
    ///
    /// [`EvidenceError::WrongKind`] for a kind that has no such status stanza.
    pub fn of_load_balancer(object: &Object) -> Result<Self, EvidenceError> {
        let gvk = object.gvk();
        if !matches!(
            (gvk.group(), gvk.kind()),
            ("", "Service") | ("networking.k8s.io", "Ingress")
        ) {
            return Err(EvidenceError::WrongKind {
                expected: "a Service or an Ingress",
                gvk: gvk.to_string(),
            });
        }
        let subject = object.identity();
        let mut items = Vec::new();
        let entries = object
            .field("/status/loadBalancer/ingress")
            .and_then(serde_json::Value::as_array);
        for (at, entry) in entries.into_iter().flatten().enumerate() {
            for (field, address_type) in LOAD_BALANCER_FIELDS {
                let Some(value) = entry
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                items.push(IdentityEvidence::stated(
                    &subject,
                    key::LOAD_BALANCER_ADDRESS,
                    Some(address_type),
                    value,
                    format!("/status/loadBalancer/ingress/{at}/{field}"),
                    Strength::Correlating,
                ));
            }
        }
        let unobserved = if items.is_empty() {
            vec![Unobserved {
                key: key::LOAD_BALANCER_ADDRESS.to_owned(),
                outcome: read_outcome(object, "/status"),
            }]
        } else {
            Vec::new()
        };

        Ok(Self {
            subject,
            provider_id: None,
            items,
            unobserved,
        })
    }

    /// The object this is evidence about.
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

/// Every list a Pod's status reports containers in (§47.3).
const CONTAINER_LISTS: &[&str] = &[
    "containerStatuses",
    "initContainerStatuses",
    "ephemeralContainerStatuses",
];

/// What one container status states, under which key, and how far each value goes (§47.3, §47.6).
const CONTAINER_FIELDS: &[(&str, &str, Strength)] = &[
    // A runtime container identifier names one container in the runtime that minted it.
    ("containerID", key::CONTAINER_ID, Strength::Distinguishing),
    // A resolved image identifier names content: what was actually pulled.
    ("imageID", key::IMAGE_ID, Strength::Distinguishing),
    // The reference the object asked for. A tag is a name, and a name moves — §47.6 forbids
    // treating equality here as identity there.
    ("image", key::IMAGE, Strength::Correlating),
];

/// The two forms one load-balancer status entry may take, and the type each is published under.
const LOAD_BALANCER_FIELDS: &[(&str, &str)] = &[("ip", "IP"), ("hostname", "Hostname")];

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
        Some(value) => items.push(IdentityEvidence::stated(
            subject, published, None, value, pointer, strength,
        )),
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

/// One item's label: the field it came from, and what narrows it (§47.7).
///
/// Two kinds of qualifier, and they read differently on purpose. A qualifier that says *what kind
/// of value this is* — an address type — replaces the field name, because `InternalIP` says more
/// than `address` does. A qualifier that says *which part of the subject this is about* — a
/// container — qualifies the field name instead, because `app: containerd://ab12` would leave a
/// reader guessing whether they are looking at a container id, an image or an image id.
fn labelled(published: &str, qualifier: Option<&str>) -> String {
    match qualifier {
        None => label_of(published).to_owned(),
        Some(qualifier) if TYPED_BY_QUALIFIER.contains(&published) => qualifier.to_owned(),
        Some(qualifier) => format!("{} ({qualifier})", label_of(published)),
    }
}

/// The keys whose qualifier names the kind of the value rather than a part of the subject.
const TYPED_BY_QUALIFIER: &[&str] = &[key::ADDRESS, key::LOAD_BALANCER_ADDRESS];

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
        key::CONTAINER_ID => "containerID",
        key::IMAGE_ID => "imageID",
        key::IMAGE => "image",
        key::LOAD_BALANCER_ADDRESS => "address",
        other => other,
    }
}

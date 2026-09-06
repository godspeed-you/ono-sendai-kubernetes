//! Cross-system identity evidence, exported rather than resolved.
//!
//! Specification §28.3 to §28.5, §47 and Appendix C.3. Gate K: a Node's `providerID` leaves this
//! provider as evidence a later resolver can consume, and the package that exports it stays
//! unlinked from any cloud SDK.
//!
//! The line these tests hold is §47.1. This provider reads Kubernetes and nothing else, so it can
//! say what a field held and how strongly that field identifies something — and it can never say
//! which foreign resource the value matches, because it has not read the foreign system. An
//! address that happens to be equal on both sides is the clearest case: §28.5 forbids it as proof,
//! and it is exactly the match a helpful implementation would draw.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::coverage::Outcome;
use ono_provider_kubernetes::evidence::{ProviderId, Strength, SubjectEvidence, key};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::relationship::Evidence;

const NODE: &str = r#"{
  "apiVersion":"v1","kind":"Node",
  "metadata":{
    "name":"worker-03","uid":"node-1","resourceVersion":"884",
    "labels":{
      "kubernetes.io/hostname":"ip-10-42-0-17",
      "kubernetes.io/arch":"arm64",
      "kubernetes.io/os":"linux",
      "topology.kubernetes.io/zone":"eu-central-1a",
      "topology.kubernetes.io/region":"eu-central-1",
      "node.kubernetes.io/instance-type":"m6g.large"
    }
  },
  "spec":{"providerID":"aws:///eu-central-1a/i-0123456789"},
  "status":{
    "addresses":[
      {"type":"InternalIP","address":"10.42.0.17"},
      {"type":"ExternalIP","address":"52.58.1.9"},
      {"type":"Hostname","address":"ip-10-42-0-17"}
    ],
    "nodeInfo":{
      "machineID":"ec2b4f1c9a7d4e0f8b3c",
      "systemUUID":"ec2b4f1c-9a7d-4e0f-8b3c-1d2e3f405162",
      "bootID":"6f1c9a7d-4e0f",
      "kubeletVersion":"v1.31.2",
      "containerRuntimeVersion":"containerd://1.7.20"
    }
  }
}"#;

/// A Node the API server answered for in full, with neither a provider identifier nor a single
/// address: a bare-metal cluster running no cloud controller.
const NODE_WITHOUT_CLOUD_IDENTITY: &str = r#"{
  "apiVersion":"v1","kind":"Node",
  "metadata":{"name":"bench-1","uid":"node-2"},
  "spec":{"podCIDR":"10.244.3.0/24"},
  "status":{"addresses":[]}
}"#;

/// The same Node as a metadata-only projection: nobody asked for `spec` or `status`.
const NODE_METADATA_ONLY: &str = r#"{
  "apiVersion":"v1","kind":"Node",
  "metadata":{"name":"bench-1","uid":"node-2"}
}"#;

const POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"checkout-7f9d","namespace":"shop","uid":"pod-1"},
  "spec":{"nodeName":"worker-03"}
}"#;

fn node() -> Object {
    Object::parse("kubernetes:prod-eu", NODE).expect("the fixture is a Node")
}

fn evidence_of(json: &str) -> SubjectEvidence {
    let object = Object::parse("kubernetes:prod-eu", json).expect("the fixture is a Node");
    SubjectEvidence::of_node(&object).expect("a Node exports evidence")
}

fn one(evidence: &SubjectEvidence, wanted: &str) -> String {
    let found = evidence.by_key(wanted);
    assert_eq!(found.len(), 1, "expected exactly one `{wanted}`: {found:?}");
    found[0].value().to_owned()
}

#[test]
fn should_export_the_provider_identifier_as_the_strongest_node_evidence() {
    // §28.4 and §47.2: `spec.providerID` is the one Node field whose purpose is to name the
    // machine in the system that created it, and §47.2 says so in as many words — stronger than
    // IP or name matching. Exporting it at the same strength as an address would throw away the
    // only ranking the specification hands out.
    let evidence = evidence_of(NODE);
    let item = evidence
        .by_key(key::PROVIDER_ID)
        .first()
        .copied()
        .expect("the Node states a providerID");

    assert_eq!(item.value(), "aws:///eu-central-1a/i-0123456789");
    assert_eq!(item.source(), "/spec/providerID");
    assert_eq!(item.strength(), Strength::Distinguishing);
    assert!(item.is_lookup_key());
    // Appendix C.3 keys it exactly this way, so a resolver written against the document finds it.
    assert_eq!(item.key(), "kubernetes.node.provider-id");
}

#[test]
fn should_keep_the_raw_provider_identifier_beside_any_decomposition() {
    // §28.4: the decomposition exists to make the identifier readable, and the raw string is what
    // a resolver matches on. A parser that returned only its parts would force every consumer to
    // reassemble a value the API server already stated, and would lose whatever the reassembly
    // spells differently.
    let evidence = evidence_of(NODE);
    let identifier = evidence
        .provider_id()
        .expect("the Node states a providerID");

    assert_eq!(identifier.raw(), "aws:///eu-central-1a/i-0123456789");
    let shape = identifier.shape().expect("the value is URI shaped");
    assert_eq!(shape.scheme(), "aws");
    assert_eq!(shape.path(), "/eu-central-1a/i-0123456789");
    assert_eq!(shape.segments(), vec!["eu-central-1a", "i-0123456789"]);
}

#[test]
fn should_decompose_no_further_than_a_generic_uri_shape() {
    // §28.4 forbids vendor parsing policy here. The decomposition therefore knows `<scheme>://
    // <path>` and path separators and nothing else: it does not know that some schemes put a zone
    // first, and it does not label a segment. A value with no `://` keeps its raw form and reports
    // no shape rather than being forced into one.
    let opaque = ProviderId::parse("opaque-node-identifier-7");
    assert_eq!(opaque.raw(), "opaque-node-identifier-7");
    assert!(opaque.shape().is_none());
    assert!(!opaque.is_uri_shaped());

    // Three schemes with three different path shapes, read by one rule that names none of them.
    let flat = ProviderId::parse("scheme://instance-7");
    assert_eq!(
        flat.shape().map(|shape| shape.segments()),
        Some(vec!["instance-7"])
    );
    let nested = ProviderId::parse("other:///region-a/zone-b/instance-7");
    assert_eq!(
        nested.shape().map(|shape| shape.segments()),
        Some(vec!["region-a", "zone-b", "instance-7"])
    );
    // An empty path is a shape, not an absence: the scheme was still stated.
    let bare = ProviderId::parse("third://");
    assert_eq!(
        bare.shape().map(|shape| shape.scheme().to_owned()),
        Some("third".to_owned())
    );
    assert_eq!(bare.shape().map(|shape| shape.segments()), Some(Vec::new()));
}

#[test]
fn should_name_no_cloud_vendor_anywhere_in_the_module() {
    // Gate K, checked rather than trusted. §47.1 forbids AWS, Azure, GCP or host-inventory logic
    // in Kubernetes relationship code, and the way that rule dies is by degrees: a match arm for
    // one scheme "just to show the instance id nicely", then a second. A vendor name in the source
    // — even in a doc comment's example — is the first symptom, so the source is the assertion.
    let source = include_str!("../src/evidence.rs").to_lowercase();
    for vendor in VENDORS {
        assert!(
            !mentions(&source, vendor),
            "src/evidence.rs names `{vendor}`; §47.1 keeps foreign-domain knowledge out of it"
        );
    }
}

#[test]
fn should_link_the_package_to_no_cloud_sdk() {
    // Gate K's other half (§60.8 step 4, §59.5). The module can stay clean while a dependency
    // quietly makes the package a cloud client; the manifest is where that would show first.
    let manifest = include_str!("../Cargo.toml").to_lowercase();
    for vendor in VENDORS {
        assert!(
            !mentions(&manifest, vendor),
            "the package manifest names `{vendor}`; Gate K keeps this package free of cloud SDKs"
        );
    }
}

#[test]
fn should_export_node_addresses_with_their_type_as_weaker_evidence() {
    // §28.5 and §47.2: addresses are exportable evidence *with type information*, because an
    // internal address, a public one and a hostname resolve against different foreign systems.
    // Flattening them into a list of strings would leave a resolver matching a private address
    // against a public inventory.
    let evidence = evidence_of(NODE);
    let addresses: Vec<(String, String)> = evidence
        .by_key(key::ADDRESS)
        .iter()
        .map(|item| {
            (
                item.qualifier().unwrap_or_default().to_owned(),
                item.value().to_owned(),
            )
        })
        .collect();

    assert_eq!(
        addresses,
        vec![
            ("InternalIP".to_owned(), "10.42.0.17".to_owned()),
            ("ExternalIP".to_owned(), "52.58.1.9".to_owned()),
            ("Hostname".to_owned(), "ip-10-42-0-17".to_owned()),
        ]
    );
    // The type is spelled as the API spells it. Lower-casing it would make an exported record
    // disagree with the object it came from for no gain.
    let internal = evidence.by_key(key::ADDRESS)[0];
    assert_eq!(internal.source(), "/status/addresses/0/address");
    assert_eq!(internal.strength(), Strength::Correlating);
}

#[test]
fn should_refuse_an_address_as_a_key_a_resolver_may_match_on_alone() {
    // §28.5: IP equality alone MUST NOT establish a verified edge. Two clusters on the same
    // private range hand out the same addresses, a public address outlives the machine that held
    // it, and a hostname is assigned rather than owned. This is the refusal a helpful
    // implementation breaks first, because the match usually looks right.
    let evidence = evidence_of(NODE);
    for item in evidence.by_key(key::ADDRESS) {
        assert!(
            !item.is_lookup_key(),
            "{} was offered as a key a resolver may match on alone",
            item.describe()
        );
        assert_ne!(item.strength(), Strength::Distinguishing);
    }

    // And the module offers no edge at all: §47.1 leaves matching to the resolver, so there is
    // nothing here that could render as a Kubernetes-verified foreign relationship.
    let source = include_str!("../src/evidence.rs");
    assert!(
        !source.contains("Edge"),
        "evidence must not build relationships"
    );
    assert!(
        !source.contains("Relation"),
        "evidence must not name a relation"
    );
}

#[test]
fn should_export_placement_metadata_from_the_well_known_labels() {
    // §28.3: zone, region, instance type, hostname and architecture stay available as typed
    // properties. They are placement rather than identity — a thousand machines share a zone —
    // and the strength says so, so a resolver cannot key a lookup on "in eu-central-1a".
    let evidence = evidence_of(NODE);

    assert_eq!(one(&evidence, key::ZONE), "eu-central-1a");
    assert_eq!(one(&evidence, key::REGION), "eu-central-1");
    assert_eq!(one(&evidence, key::INSTANCE_TYPE), "m6g.large");
    assert_eq!(one(&evidence, key::ARCHITECTURE), "arm64");

    let zone = evidence.by_key(key::ZONE)[0];
    assert_eq!(zone.strength(), Strength::Placement);
    assert!(!zone.is_lookup_key());
    // The label key that carried it stays visible: a value read from the deprecated key and one
    // read from the current key are not equally trustworthy, and §23 wants the source readable.
    assert_eq!(
        zone.evidence(),
        &Evidence::Convention {
            key: "topology.kubernetes.io/zone".to_owned(),
            value: "eu-central-1a".to_owned(),
        }
    );
}

#[test]
fn should_read_a_deprecated_topology_label_when_it_is_the_only_one_present() {
    // §5.4 and §28.3: clusters within the support window still carry the beta labels, and a
    // provider that read only the current spelling would report no zone for a running cluster —
    // an absence that is about this code rather than about the cluster.
    let legacy = r#"{
      "apiVersion":"v1","kind":"Node",
      "metadata":{"name":"old-1","uid":"node-3","labels":{
        "failure-domain.beta.kubernetes.io/zone":"eu-central-1b",
        "beta.kubernetes.io/instance-type":"m5.large"
      }},
      "spec":{},"status":{"addresses":[]}
    }"#;
    let evidence = evidence_of(legacy);

    assert_eq!(one(&evidence, key::ZONE), "eu-central-1b");
    assert_eq!(one(&evidence, key::INSTANCE_TYPE), "m5.large");
    assert_eq!(
        evidence.by_key(key::ZONE)[0].evidence(),
        &Evidence::Convention {
            key: "failure-domain.beta.kubernetes.io/zone".to_owned(),
            value: "eu-central-1b".to_owned(),
        }
    );
}

#[test]
fn should_export_the_host_identifiers_the_node_reports_about_itself() {
    // §47.2 asks for kubelet/runtime identifiers where available. `systemUUID` is what a machine
    // reports about itself and is a candidate key; `machineID` is copied with a disk image, so
    // whole fleets built from one template share it. Ranking them alike would make a golden-image
    // fleet resolve to a single machine.
    let evidence = evidence_of(NODE);

    let system = evidence.by_key(key::SYSTEM_UUID)[0];
    assert_eq!(system.value(), "ec2b4f1c-9a7d-4e0f-8b3c-1d2e3f405162");
    assert_eq!(system.strength(), Strength::Distinguishing);

    let machine = evidence.by_key(key::MACHINE_ID)[0];
    assert_eq!(machine.value(), "ec2b4f1c9a7d4e0f8b3c");
    assert_eq!(machine.strength(), Strength::Correlating);
    assert!(!machine.is_lookup_key());
}

#[test]
fn should_state_what_the_api_server_stated_and_infer_nothing() {
    // §23 and §4 invariant 20. Every item here is a field the server sent or a label convention it
    // carries. `Evidence::Inferred` belongs to the resolver that draws a correlation across two
    // systems; produced here it would let a guess arrive wearing this provider's authority.
    let evidence = evidence_of(NODE);
    assert!(!evidence.items().is_empty());

    for item in evidence.items() {
        assert!(
            !matches!(item.evidence(), Evidence::Inferred { .. }),
            "{} arrived as an inference",
            item.describe()
        );
    }

    // A field the server sent is an assertion; a well-known label is a convention, which is
    // weaker and says so (§23.4).
    assert!(
        evidence.by_key(key::PROVIDER_ID)[0]
            .evidence()
            .is_asserted_by_provider()
    );
    assert!(
        evidence.by_key(key::ADDRESS)[0]
            .evidence()
            .is_asserted_by_provider()
    );
    assert!(
        !evidence.by_key(key::ZONE)[0]
            .evidence()
            .is_asserted_by_provider()
    );
}

#[test]
fn should_carry_the_node_identity_as_the_subject_of_every_item() {
    // Appendix C.3 keys evidence on `subject: Node uid=...`, and §47.2 lists uid and name among
    // the evidence. They are the subject rather than two more items: a resolver's finding has to
    // attach to a lifetime, and the provider instance is part of that (Gate J) so two clusters
    // whose Nodes share a name cannot collect into one subject.
    let evidence = evidence_of(NODE);

    assert_eq!(evidence.subject().name(), "worker-03");
    assert_eq!(evidence.subject().uid(), Some("node-1"));
    assert_eq!(evidence.subject().provider_instance(), "kubernetes:prod-eu");
    for item in evidence.items() {
        assert_eq!(item.subject(), evidence.subject());
    }

    let elsewhere = Object::parse("kubernetes:dev", NODE).expect("the fixture is a Node");
    let elsewhere = SubjectEvidence::of_node(&elsewhere).expect("a Node exports evidence");
    assert_ne!(elsewhere.subject(), evidence.subject());
}

#[test]
fn should_tell_a_node_with_no_provider_identifier_from_one_nobody_asked_about() {
    // §4 invariant 13, applied to a field instead of a collection. A Node whose spec came back
    // without a providerID has none; a metadata-only projection says nothing about whether it has
    // one. Reporting both as "no providerID" is how a projection choice becomes a fact about the
    // cluster, and `Outcome` already draws exactly this line.
    let stated = evidence_of(NODE_WITHOUT_CLOUD_IDENTITY);
    assert!(stated.provider_id().is_none());
    assert_eq!(stated.outcome_for(key::PROVIDER_ID), Some(Outcome::Absent));
    assert_eq!(stated.outcome_for(key::ADDRESS), Some(Outcome::Absent));
    assert!(
        stated
            .outcome_for(key::PROVIDER_ID)
            .is_some_and(Outcome::is_evidence_of_absence)
    );

    let unread = evidence_of(NODE_METADATA_ONLY);
    assert_eq!(
        unread.outcome_for(key::PROVIDER_ID),
        Some(Outcome::NotQueried)
    );
    assert_eq!(unread.outcome_for(key::ADDRESS), Some(Outcome::NotQueried));
    assert!(
        !unread
            .outcome_for(key::ADDRESS)
            .is_some_and(Outcome::is_evidence_of_absence)
    );

    // What was observed is not reported as a gap.
    let full = evidence_of(NODE);
    assert_eq!(full.outcome_for(key::PROVIDER_ID), None);
    assert!(full.unobserved().is_empty());
}

#[test]
fn should_cite_a_pointer_that_resolves_in_the_object_it_came_from() {
    // §47.7 and Gate D's habit applied to evidence: a source line a reader cannot follow is a
    // field name they have to trust. The label pointers are where this breaks quietly — a label
    // key contains `/`, which is the pointer's own separator, so an unescaped citation resolves
    // to nothing while still looking checkable.
    let node = node();
    let evidence = SubjectEvidence::of_node(&node).expect("a Node exports evidence");

    for item in evidence.items() {
        let at = node
            .field(item.source())
            .unwrap_or_else(|| panic!("`{}` resolves nothing", item.source()));
        assert_eq!(at.as_str(), Some(item.value()), "at {}", item.source());
    }
}

#[test]
fn should_refuse_an_object_that_is_not_a_node() {
    // The keys are `kubernetes.node.*` and the pointers are Node pointers. Reading a Pod through
    // them would export an empty evidence set that looks like a Node with nothing to say.
    let pod = Object::parse("kubernetes:prod-eu", POD).expect("the fixture is a Pod");
    let refused = SubjectEvidence::of_node(&pod).expect_err("a Pod is not a Node");
    assert!(refused.to_string().contains("Pod"));
}

#[test]
fn should_render_the_evidence_before_any_foreign_provider_is_connected() {
    // §47.7: cross-system evidence MUST be inspectable with no foreign provider attached, which
    // is the whole point of exporting rather than resolving — the operator reads the identifier
    // and goes to look it up themselves.
    let rendered = evidence_of(NODE).describe();

    assert!(
        rendered.contains("providerID: aws:///eu-central-1a/i-0123456789"),
        "{rendered}"
    );
    assert!(rendered.contains("InternalIP: 10.42.0.17"), "{rendered}");
    assert!(rendered.contains("Hostname: ip-10-42-0-17"), "{rendered}");
}

#[test]
fn should_render_what_it_could_not_observe_beside_what_it_did() {
    // A rendering that silently drops the gap reads as "this Node has no cloud identity", which
    // is the §4 invariant 13 failure in presentation rather than in data.
    let rendered = evidence_of(NODE_METADATA_ONLY).describe();
    assert!(rendered.contains("not queried"), "{rendered}");
}

/// Names that would mean this package had learned a foreign domain (§47.1, Gate K).
///
/// Word-bounded on purpose: `oci` inside `associated` is not a vendor, and a list that flagged it
/// would be turned off within a week.
const VENDORS: &[&str] = &[
    "aws",
    "amazon",
    "ec2",
    "azure",
    "gcp",
    "gce",
    "google",
    "alibaba",
    "alicloud",
    "openstack",
    "oracle",
    "oci",
    "ibm",
    "digitalocean",
    "hetzner",
    "hcloud",
    "linode",
    "vsphere",
    "vmware",
    "equinix",
    "scaleway",
    "cloudstack",
    "nutanix",
    "outscale",
    "brightbox",
];

fn mentions(haystack: &str, word: &str) -> bool {
    haystack.match_indices(word).any(|(at, _)| {
        let before = haystack[..at].chars().next_back();
        let after = haystack[at + word.len()..].chars().next();
        let boundary = |char: Option<char>| char.is_none_or(|char| !char.is_ascii_alphanumeric());
        boundary(before) && boundary(after)
    })
}

/// A running Pod as the kubelet reports it: three container lists, two runtimes, one image
/// resolved to a digest and one that never was.
const RUNNING_POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"checkout-7f9d","namespace":"shop","uid":"pod-9","resourceVersion":"77"},
  "spec":{"nodeName":"worker-03"},
  "status":{
    "phase":"Running",
    "initContainerStatuses":[
      {"name":"migrate","image":"registry.example/migrate:3",
       "imageID":"registry.example/migrate@sha256:9f2c",
       "containerID":"cri-o://7b1e0d"}
    ],
    "containerStatuses":[
      {"name":"app","image":"registry.example/checkout:1.25",
       "imageID":"pullable://registry.example/checkout@sha256:0a1b",
       "containerID":"containerd://ab12cd34"},
      {"name":"sidecar","image":"registry.example/proxy:latest",
       "imageID":"",
       "containerID":"futurert://f00d"}
    ],
    "ephemeralContainerStatuses":[
      {"name":"debug","image":"registry.example/tools:1",
       "imageID":"registry.example/tools@sha256:5e5e",
       "containerID":"containerd://beef01"}
    ]
  }
}"#;

/// A Pod the scheduler has not placed: `status` came back and carries no container at all.
const UNSTARTED_POD: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"pending-1","namespace":"shop","uid":"pod-10"},
  "spec":{},
  "status":{"phase":"Pending"}
}"#;

/// The same Pod as a metadata-only projection: nobody asked for `status`.
const POD_METADATA_ONLY: &str = r#"{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"pending-1","namespace":"shop","uid":"pod-10"}
}"#;

const LOAD_BALANCED_SERVICE: &str = r#"{
  "apiVersion":"v1","kind":"Service",
  "metadata":{"name":"checkout","namespace":"shop","uid":"svc-9"},
  "spec":{"type":"LoadBalancer","selector":{"app":"checkout"}},
  "status":{"loadBalancer":{"ingress":[
    {"ip":"198.51.100.7"},
    {"hostname":"a1b2c3.lb.example"}
  ]}}
}"#;

const ROUTED_INGRESS: &str = r#"{
  "apiVersion":"networking.k8s.io/v1","kind":"Ingress",
  "metadata":{"name":"shop","namespace":"shop","uid":"ing-9"},
  "spec":{},
  "status":{"loadBalancer":{"ingress":[{"hostname":"edge.example"}]}}
}"#;

/// A Service that is not load-balanced: `status` answered, and there is no address.
const CLUSTER_IP_SERVICE: &str = r#"{
  "apiVersion":"v1","kind":"Service",
  "metadata":{"name":"internal","namespace":"shop","uid":"svc-10"},
  "spec":{"type":"ClusterIP"},
  "status":{"loadBalancer":{}}
}"#;

const CONFIG_MAP: &str = r#"{
  "apiVersion":"v1","kind":"ConfigMap",
  "metadata":{"name":"settings","namespace":"shop","uid":"cm-1"}
}"#;

fn evidence_for(json: &str) -> SubjectEvidence {
    let object = Object::parse("kubernetes:prod-eu", json).expect("the fixture reads");
    SubjectEvidence::of(&object).expect("the object has an evidence rule")
}

fn qualified(evidence: &SubjectEvidence, wanted: &str) -> Vec<(String, String)> {
    evidence
        .by_key(wanted)
        .iter()
        .map(|item| {
            (
                item.qualifier().unwrap_or_default().to_owned(),
                item.value().to_owned(),
            )
        })
        .collect()
}

#[test]
fn should_export_a_container_runtime_id_with_the_scheme_the_kubelet_wrote() {
    // §47.3's `MUST`: the runtime scheme is preserved rather than stripped into an ambiguous
    // opaque string. `ab12cd34` alone is a hexadecimal string that means nothing to anybody; the
    // scheme is what tells a future container-runtime provider which runtime to ask.
    let evidence = evidence_for(RUNNING_POD);
    let app = evidence
        .by_key(key::CONTAINER_ID)
        .into_iter()
        .find(|item| item.qualifier() == Some("app"))
        .expect("the Pod reports a running container");

    assert_eq!(app.value(), "containerd://ab12cd34");
    assert_eq!(
        app.shape().map(|shape| shape.scheme().to_owned()),
        Some("containerd".to_owned())
    );
    assert_eq!(
        app.shape().map(|shape| shape.path().to_owned()),
        Some("ab12cd34".to_owned()),
        "decomposed exactly as far as `<scheme>://<path>` goes, and no further (§28.4)"
    );
    assert_eq!(app.strength(), Strength::Distinguishing);
    assert_eq!(app.source(), "/status/containerStatuses/0/containerID");
}

#[test]
fn should_export_an_unrecognised_runtime_scheme_exactly_as_it_exports_a_recognised_one() {
    // §47.1 and Gate K, one level below the Node: the decomposition knows that `://` separates a
    // scheme from a path and nothing else. A match arm per runtime — "just to show the container
    // id nicely" — is the foreign-domain knowledge §47.1 keeps out, arriving through a runtime
    // instead of through a cloud.
    let evidence = evidence_for(RUNNING_POD);
    let schemes: Vec<String> = evidence
        .by_key(key::CONTAINER_ID)
        .iter()
        .filter_map(|item| item.shape().map(|shape| shape.scheme().to_owned()))
        .collect();

    assert_eq!(
        schemes,
        vec![
            "containerd".to_owned(),
            "futurert".to_owned(),
            "cri-o".to_owned(),
            "containerd".to_owned(),
        ],
        "a runtime nobody has heard of is exported exactly as a familiar one is"
    );
}

#[test]
fn should_rank_an_image_tag_below_the_digest_the_runtime_resolved() {
    // §47.6's `MUST`: tag equality is not digest identity. `checkout:1.25` is a name somebody may
    // move to different content tonight, and the digest names the content itself. Exporting the
    // two at one strength would let a resolver key an image lookup on a tag and match a machine
    // running something else entirely.
    let evidence = evidence_for(RUNNING_POD);
    let tag = evidence
        .by_key(key::IMAGE)
        .into_iter()
        .find(|item| item.qualifier() == Some("app"))
        .expect("the container states the image it was asked for");
    let digest = evidence
        .by_key(key::IMAGE_ID)
        .into_iter()
        .find(|item| item.qualifier() == Some("app"))
        .expect("the runtime resolved it");

    assert_eq!(tag.value(), "registry.example/checkout:1.25");
    assert_eq!(tag.strength(), Strength::Correlating);
    assert!(
        !tag.is_lookup_key(),
        "a tag is a mutable name, and a resolver keying on it would match the wrong content"
    );
    assert_eq!(
        digest.value(),
        "pullable://registry.example/checkout@sha256:0a1b"
    );
    assert_eq!(digest.strength(), Strength::Distinguishing);
    assert!(digest.is_lookup_key());
}

#[test]
fn should_export_the_containers_of_every_list_a_pod_reports() {
    // §47.3 reads `status`, and a Pod's containers are in three lists. An init container that
    // failed and an ephemeral debug container are exactly the ones an operator is chasing across
    // a runtime boundary, and reading only `containerStatuses` would report them as absent.
    let evidence = evidence_for(RUNNING_POD);

    assert_eq!(
        qualified(&evidence, key::CONTAINER_ID),
        vec![
            ("app".to_owned(), "containerd://ab12cd34".to_owned()),
            ("sidecar".to_owned(), "futurert://f00d".to_owned()),
            ("migrate".to_owned(), "cri-o://7b1e0d".to_owned()),
            ("debug".to_owned(), "containerd://beef01".to_owned()),
        ],
        "every container the Pod reports, named by the container it belongs to"
    );
    assert!(
        evidence
            .by_key(key::IMAGE_ID)
            .iter()
            .all(|item| item.qualifier() != Some("sidecar")),
        "an empty `imageID` is a container whose image the runtime has not resolved, and an \
         empty string is not evidence"
    );
}

#[test]
fn should_tell_a_pod_that_runs_nothing_from_one_whose_status_nobody_projected() {
    // §4 invariant 13 again, at the Pod: a Pod whose status came back and lists no container is
    // running nothing, and a metadata-only projection says nothing at all about what it runs.
    assert_eq!(
        evidence_for(UNSTARTED_POD).outcome_for(key::CONTAINER_ID),
        Some(Outcome::Absent)
    );
    assert_eq!(
        evidence_for(POD_METADATA_ONLY).outcome_for(key::CONTAINER_ID),
        Some(Outcome::NotQueried)
    );
}

#[test]
fn should_export_the_load_balancer_addresses_a_service_reports() {
    // §47.4: `status.loadBalancer.ingress[]` is exportable for later resolution to a cloud
    // load-balancer resource. With type information, for §28.5's reason at another object: an
    // address and a hostname resolve against different foreign systems.
    let evidence = evidence_for(LOAD_BALANCED_SERVICE);

    assert_eq!(
        qualified(&evidence, key::LOAD_BALANCER_ADDRESS),
        vec![
            ("IP".to_owned(), "198.51.100.7".to_owned()),
            ("Hostname".to_owned(), "a1b2c3.lb.example".to_owned()),
        ]
    );
    assert!(
        evidence
            .by_key(key::LOAD_BALANCER_ADDRESS)
            .iter()
            .all(|item| item.strength() == Strength::Correlating && !item.is_lookup_key()),
        "§47.4: an IP or hostname match alone remains resolver evidence, never a \
         Kubernetes-verified foreign relationship"
    );
    assert_eq!(
        evidence.by_key(key::LOAD_BALANCER_ADDRESS)[0].source(),
        "/status/loadBalancer/ingress/0/ip"
    );
}

#[test]
fn should_export_the_load_balancer_address_an_ingress_reports() {
    // §47.4 names Service *and* Ingress, and an Ingress is where an operator starts from a URL.
    let evidence = evidence_for(ROUTED_INGRESS);

    assert_eq!(
        qualified(&evidence, key::LOAD_BALANCER_ADDRESS),
        vec![("Hostname".to_owned(), "edge.example".to_owned())]
    );
}

#[test]
fn should_tell_a_service_with_no_load_balancer_from_one_nobody_asked_about() {
    // A ClusterIP Service has no load-balancer address, and that is a fact about the Service.
    assert_eq!(
        evidence_for(CLUSTER_IP_SERVICE).outcome_for(key::LOAD_BALANCER_ADDRESS),
        Some(Outcome::Absent)
    );
}

#[test]
fn should_refuse_an_object_no_evidence_rule_covers() {
    // The pointers and the published keys belong to the kinds that have them. A ConfigMap read
    // through a Pod's pointers would export an empty evidence set, which renders as an object
    // with nothing to say rather than as the wrong question.
    let object = Object::parse("kubernetes:prod-eu", CONFIG_MAP).expect("the fixture reads");
    let refused =
        SubjectEvidence::of(&object).expect_err("a ConfigMap states no cross-system fact");
    assert!(refused.to_string().contains("ConfigMap"), "{refused}");
}

#[test]
fn should_render_a_container_fact_under_the_field_and_the_container_it_came_from() {
    // §47.7: the evidence is inspectable before any foreign provider is connected, and a line
    // that said only `app: containerd://ab12cd34` would leave a reader guessing whether they are
    // looking at a container id, an image or an image id.
    let rendered = evidence_for(RUNNING_POD).describe();

    assert!(
        rendered.contains("containerID (app): containerd://ab12cd34"),
        "{rendered}"
    );
    assert!(
        rendered.contains("image (app): registry.example/checkout:1.25"),
        "{rendered}"
    );
}

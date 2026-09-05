//! Typing a resource nobody compiled in.
//!
//! Specification §12 (OpenAPI and schema discovery) and §33 (CRDs and arbitrary custom
//! resources). Two acceptance gates meet here. **Gate A**: a CRD invented after this provider was
//! built is usable without a rebuild, so nothing in the implementation may name a kind. **Gate
//! B**: where a structural schema exists the resource gets typed field descriptions, and where it
//! is incomplete or missing the fields survive anyway with their precision degraded and marked
//! (§12.3, §12.5, §4 invariant 17).
//!
//! The failure these tests exist to make impossible is the one §33.1 calls non-conformant: built-in
//! kinds getting typed behaviour while a custom resource is handed over as a JSON blob.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::discovery::{Gvk, Scope};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::schema::{
    CustomResourceDefinition, FieldType, Intent, Precision, Projection, Schema, SchemaCache,
    SchemaSource,
};

/// A CRD for a kind that exists nowhere upstream and nowhere in this provider's source.
///
/// It carries everything §33 asks a CRD to be read for: two served versions, a structural schema,
/// a status subresource, a scale subresource whose replica paths are *not* the conventional ones,
/// and printer columns — one of which points at a field the schema never declares.
const SPROCKET_CRD: &str = r#"{
  "apiVersion": "apiextensions.k8s.io/v1",
  "kind": "CustomResourceDefinition",
  "metadata": {"name": "sprockets.machines.example.io"},
  "spec": {
    "group": "machines.example.io",
    "scope": "Namespaced",
    "names": {
      "kind": "Sprocket",
      "plural": "sprockets",
      "singular": "sprocket",
      "shortNames": ["spk"]
    },
    "versions": [
      {
        "name": "v1alpha1",
        "served": true,
        "storage": false,
        "schema": {"openAPIV3Schema": {"type": "object"}}
      },
      {
        "name": "v1",
        "served": true,
        "storage": true,
        "subresources": {
          "status": {},
          "scale": {
            "specReplicasPath": ".spec.size",
            "statusReplicasPath": ".status.spun",
            "labelSelectorPath": ".status.selector"
          }
        },
        "additionalPrinterColumns": [
          {"name": "Teeth", "type": "integer", "jsonPath": ".spec.teeth"},
          {"name": "Age", "type": "date", "jsonPath": ".metadata.creationTimestamp"},
          {"name": "Spin", "type": "string", "jsonPath": ".status.spin",
           "description": "How the operator words it today.", "priority": 1}
        ],
        "schema": {
          "openAPIV3Schema": {
            "type": "object",
            "properties": {
              "spec": {
                "type": "object",
                "required": ["teeth"],
                "properties": {
                  "teeth": {"type": "integer", "format": "int32",
                            "description": "How many teeth the sprocket is cut with."},
                  "material": {"type": "string"},
                  "size": {"type": "integer"},
                  "tolerances": {"type": "object", "x-kubernetes-preserve-unknown-fields": true},
                  "ports": {
                    "type": "array",
                    "items": {
                      "type": "object",
                      "properties": {
                        "name": {"type": "string"},
                        "number": {"type": "integer"}
                      }
                    }
                  },
                  "labelsByZone": {"type": "object", "additionalProperties": {"type": "string"}},
                  "nodeName": {"type": "string"},
                  "secretRef": {"type": "string", "description": "The token this sprocket reads."},
                  "targetPodName": {"type": "string"}
                }
              },
              "status": {
                "type": "object",
                "properties": {
                  "observedTeeth": {"type": "integer"},
                  "spun": {"type": "integer"},
                  "phase": {"type": "string"}
                }
              }
            }
          }
        }
      }
    ]
  }
}"#;

/// One object of that invented kind, carrying fields the schema declares and fields it does not.
const SPROCKET: &str = r#"{
  "apiVersion": "machines.example.io/v1",
  "kind": "Sprocket",
  "metadata": {"name": "mill-a", "namespace": "works", "uid": "11111111-2222-3333-4444-555555555555"},
  "spec": {
    "teeth": 11,
    "material": "brass",
    "size": 3,
    "tolerances": {"radial": "0.01mm", "axial": {"micrometres": 4}},
    "ports": [{"name": "drive", "number": 7}],
    "labelsByZone": {"eu-west": "primary"},
    "nodeName": "worker-1",
    "secretRef": "vault-token",
    "targetPodName": "grinder-0",
    "undeclared": "still here"
  },
  "status": {"observedTeeth": 11, "spun": 3, "phase": "Spinning", "spin": "clockwise"}
}"#;

/// A second invented kind, sharing nothing with the first: different group, different scope.
const NEBULA_CRD: &str = r#"{
  "apiVersion": "apiextensions.k8s.io/v1",
  "kind": "CustomResourceDefinition",
  "metadata": {"name": "nebulae.astro.example.dev"},
  "spec": {
    "group": "astro.example.dev",
    "scope": "Cluster",
    "names": {"kind": "Nebula", "plural": "nebulae", "singular": "nebula"},
    "versions": [
      {
        "name": "v1",
        "served": true,
        "storage": true,
        "schema": {
          "openAPIV3Schema": {
            "type": "object",
            "properties": {
              "spec": {
                "type": "object",
                "required": ["brightness"],
                "properties": {"brightness": {"type": "integer", "format": "int64"}}
              }
            }
          }
        }
      }
    ]
  }
}"#;

/// One object of the second invented kind.
const NEBULA: &str = r#"{
  "apiVersion": "astro.example.dev/v1",
  "kind": "Nebula",
  "metadata": {"name": "orion", "uid": "99999999-8888-7777-6666-555555555555"},
  "spec": {"brightness": 4}
}"#;

/// The CRD's storage version, which is the one the tests reason about.
fn sprocket_schema() -> Schema {
    let crd = CustomResourceDefinition::parse(SPROCKET_CRD).expect("the CRD reads");
    crd.version("v1").expect("v1 is served").schema().clone()
}

fn sprocket_object() -> Object {
    Object::parse("kubernetes:test", SPROCKET).expect("the object reads")
}

// --- Gate A: a kind nobody compiled in ---------------------------------------------------------

#[test]
fn should_type_a_custom_resource_nobody_compiled_in() {
    // Gate A and §12.2. The schema arrives with the cluster, so a kind invented after this build
    // is describable. The mistake this rules out is a compile-time table of kinds, which would
    // answer `None` here and leave every CRD untyped.
    let schema = sprocket_schema();

    let teeth = schema.field("/spec/teeth").expect("the schema declares it");
    assert_eq!(teeth.field_type(), FieldType::Integer);
    assert_eq!(teeth.format(), Some("int32"));
    assert!(teeth.is_required(), "the schema lists `teeth` as required");
    assert_eq!(
        teeth.description(),
        Some("How many teeth the sprocket is cut with.")
    );
    assert_eq!(teeth.precision(), Precision::Structural);
    assert_eq!(teeth.source(), SchemaSource::CrdStructural);
}

#[test]
fn should_treat_two_unrelated_invented_kinds_the_same_way() {
    // Gate A. Two CRDs that share no group, scope or field go through one path and both come back
    // typed. A provider carrying per-kind knowledge would type whichever one it had been taught.
    let sprocket = sprocket_schema();
    let nebula_crd = CustomResourceDefinition::parse(NEBULA_CRD).expect("the CRD reads");
    let nebula = nebula_crd.version("v1").expect("v1 is served").schema();

    assert_eq!(
        sprocket.field("/spec/material").map(|f| f.field_type()),
        Some(FieldType::String)
    );
    assert_eq!(
        nebula.field("/spec/brightness").map(|f| f.field_type()),
        Some(FieldType::Integer)
    );

    let projected = Projection::of(nebula, &Object::parse("kubernetes:test", NEBULA).unwrap());
    let brightness = projected
        .field("/spec/brightness")
        .expect("it is projected");
    assert_eq!(brightness.precision(), Precision::Structural);
    assert_eq!(brightness.value().as_i64(), Some(4));
}

#[test]
fn should_read_the_scope_and_identity_a_crd_declares() {
    // §13.1 and §9.2. A CRD states both identities and its scope; inventing a namespace for a
    // cluster-scoped custom resource is the error, and so is deriving the plural from the kind.
    let sprocket = CustomResourceDefinition::parse(SPROCKET_CRD).expect("the CRD reads");
    let nebula = CustomResourceDefinition::parse(NEBULA_CRD).expect("the CRD reads");

    assert_eq!(
        sprocket.gvk("v1"),
        Gvk::new("machines.example.io", "v1", "Sprocket")
    );
    assert_eq!(sprocket.gvr("v1").resource(), "sprockets");
    assert_eq!(sprocket.scope(), Scope::Namespaced);
    assert_eq!(sprocket.short_names(), ["spk"]);

    assert_eq!(nebula.scope(), Scope::Cluster);
    assert_eq!(
        nebula.gvr("v1").resource(),
        "nebulae",
        "the plural is declared, never guessed from the kind"
    );
}

#[test]
fn should_keep_every_served_version_and_name_the_storage_one() {
    // §33.2 and §13.4. Served versions and the storage version are different facts; collapsing
    // them loses the ability to notice a storage-version change, which invalidates schemas.
    let crd = CustomResourceDefinition::parse(SPROCKET_CRD).expect("the CRD reads");

    let served: Vec<&str> = crd.served_versions().map(|v| v.name()).collect();
    assert_eq!(served, ["v1alpha1", "v1"]);
    assert_eq!(crd.storage_version().map(|v| v.name()), Some("v1"));
}

// --- Gate B: typed where the schema reaches, preserved where it does not -----------------------

#[test]
fn should_project_a_custom_resource_as_typed_fields_rather_than_a_blob() {
    // Gate B and §33.1. The custom resource gets the same treatment a built-in would: named
    // fields with declared types. A provider that hands back the raw document is non-conformant.
    let projected = Projection::of(&sprocket_schema(), &sprocket_object());

    let material = projected.field("/spec/material").expect("it is projected");
    assert_eq!(material.field_type(), FieldType::String);
    assert_eq!(material.value().as_str(), Some("brass"));
    assert_eq!(material.precision(), Precision::Structural);

    let port_name = projected
        .field("/spec/ports/0/name")
        .expect("a list element is typed by the item schema");
    assert_eq!(port_name.field_type(), FieldType::String);
    assert_eq!(port_name.value().as_str(), Some("drive"));

    let zone = projected
        .field("/spec/labelsByZone/eu-west")
        .expect("a map value is typed by additionalProperties");
    assert_eq!(zone.field_type(), FieldType::String);
    assert_eq!(zone.precision(), Precision::Structural);
}

#[test]
fn should_keep_a_field_the_schema_never_declared() {
    // §12.5 and §4 invariant 17. `spec.undeclared` is in the object and in no schema. It stays
    // reachable and stays honest about where its type came from; discarding it would be the SDK
    // deciding what the cluster is allowed to contain.
    let object = sprocket_object();
    let projected = Projection::of(&sprocket_schema(), &object);

    let unknown = projected
        .field("/spec/undeclared")
        .expect("an undeclared field is still a field");
    assert_eq!(unknown.value().as_str(), Some("still here"));
    assert_eq!(unknown.precision(), Precision::Unknown);
    assert_eq!(
        unknown.source(),
        SchemaSource::Absent,
        "no schema described it, and the projection must say so rather than imply one did"
    );
    assert_eq!(
        object.field("/spec/undeclared").and_then(|v| v.as_str()),
        Some("still here"),
        "the native object reaches it too"
    );
    assert!(
        projected
            .unknown_fields()
            .any(|field| field.pointer() == "/spec/undeclared")
    );
}

#[test]
fn should_degrade_precision_where_the_schema_declines_to_describe_a_subtree() {
    // §12.3. `x-kubernetes-preserve-unknown-fields` is the schema saying "anything may be here".
    // The subtree is Loose rather than Structural, and its contents survive as Unknown. Marking
    // it Structural because `type: object` was stated would claim knowledge the schema withheld.
    let projected = Projection::of(&sprocket_schema(), &sprocket_object());

    let tolerances = projected
        .field("/spec/tolerances")
        .expect("it is projected");
    assert_eq!(tolerances.precision(), Precision::Loose);
    assert_eq!(tolerances.field_type(), FieldType::Object);

    let radial = projected
        .field("/spec/tolerances/radial")
        .expect("what a preserved subtree holds is still held");
    assert_eq!(radial.value().as_str(), Some("0.01mm"));
    assert_eq!(radial.precision(), Precision::Unknown);

    assert!(
        projected
            .field("/spec/tolerances/axial/micrometres")
            .is_some(),
        "depth inside a preserved subtree is preserved too"
    );
}

#[test]
fn should_preserve_every_field_when_there_is_no_schema_at_all() {
    // Gate B, second half, and §12.3. A resource whose schema the server does not publish is not
    // a blob: the fields are all there with the shape their values have, marked as coming from
    // the object rather than from a schema. Refusing to project at all would be the failure.
    let object = sprocket_object();
    let projected = Projection::of(&Schema::absent(), &object);

    let teeth = projected.field("/spec/teeth").expect("it is still a field");
    assert_eq!(teeth.value().as_i64(), Some(11));
    assert_eq!(
        teeth.field_type(),
        FieldType::Integer,
        "the value's own shape is observable; what is missing is a schema's claim about it"
    );
    assert_eq!(teeth.precision(), Precision::Unknown);
    assert_eq!(teeth.source(), SchemaSource::Absent);
    assert!(!teeth.is_required(), "nothing declared it required");

    assert_eq!(projected.source(), SchemaSource::Absent);
    assert_eq!(projected.precision(), Precision::Unknown);
    assert!(
        projected.fields().len() > 10,
        "the whole object is reachable, not a summary of it"
    );
}

#[test]
fn should_mark_a_projection_with_the_weakest_precision_it_contains() {
    // §12.3 asks for the precision to be *marked*. A projection holding one undescribed field is
    // not a fully typed projection, and reporting the best case would be the comfortable lie.
    let projected = Projection::of(&sprocket_schema(), &sprocket_object());

    assert_eq!(projected.source(), SchemaSource::CrdStructural);
    assert_eq!(projected.precision(), Precision::Unknown);
    assert!(
        projected
            .field("/spec/teeth")
            .is_some_and(|f| f.precision() == Precision::Structural),
        "the aggregate degrading does not degrade the fields that are typed"
    );
}

#[test]
fn should_read_a_plain_openapi_v3_schema_and_say_where_it_came_from() {
    // §12.1 and §12.3: the API server's OpenAPI document and a CRD's `openAPIV3Schema` are the
    // same shape from different sources, and the source is part of the answer.
    let schema = Schema::from_openapi_v3(
        r#"{"type":"object","properties":{"spec":{"type":"object",
            "properties":{"replicas":{"type":"integer","format":"int32"}}}}}"#,
    )
    .expect("the schema reads");

    assert_eq!(schema.source(), SchemaSource::OpenApiV3);
    let replicas = schema.field("/spec/replicas").expect("it is declared");
    assert_eq!(replicas.field_type(), FieldType::Integer);
    assert_eq!(replicas.source(), SchemaSource::OpenApiV3);
}

#[test]
fn should_refuse_a_schema_document_it_cannot_read() {
    // A document that does not parse is an error, never an empty schema: silently typing every
    // field as unknown would look exactly like a resource whose schema is legitimately absent.
    assert!(Schema::from_openapi_v3("{not json").is_err());
    assert!(Schema::from_openapi_v3("[]").is_err());
    assert!(CustomResourceDefinition::parse(r#"{"kind":"ConfigMap"}"#).is_err());
}

// --- §33.4, §33.5, §33.6: hints, discovery and boundaries --------------------------------------

#[test]
fn should_keep_printer_columns_a_presentation_hint_rather_than_the_schema() {
    // §33.4. `.status.spin` is a printer column and is nowhere in the schema. It may inform a
    // default view; it must not become a field description, because a column is what an operator
    // wants shown, not what the resource is.
    let crd = CustomResourceDefinition::parse(SPROCKET_CRD).expect("the CRD reads");
    let version = crd.version("v1").expect("v1 is served");

    let columns = version.printer_columns();
    assert_eq!(columns.len(), 3);
    assert_eq!(columns[0].name(), "Teeth");
    assert_eq!(columns[0].pointer().as_deref(), Some("/spec/teeth"));
    assert_eq!(columns[2].pointer().as_deref(), Some("/status/spin"));

    assert!(
        version.schema().field("/status/spin").is_none(),
        "a printer column must not add a field to the canonical schema"
    );
}

#[test]
fn should_discover_a_scale_subresource_rather_than_assume_one() {
    // §33.5. Scalability is a discovered capability. The paths are the CRD's own — `.spec.size`,
    // not `.spec.replicas` — so a provider that assumed the conventional field would read the
    // wrong number, and one that assumed the capability would offer scaling on a kind without it.
    let crd = CustomResourceDefinition::parse(SPROCKET_CRD).expect("the CRD reads");
    let v1 = crd.version("v1").expect("v1 is served");
    let alpha = crd.version("v1alpha1").expect("v1alpha1 is served");

    assert!(!alpha.subresources().has_scale());
    assert!(alpha.subresources().scale().is_none());

    let scale = v1.subresources().scale().expect("v1 declares scale");
    assert_eq!(scale.spec_replicas_path(), ".spec.size");
    assert_eq!(scale.spec_replicas_pointer().as_deref(), Some("/spec/size"));
    assert_eq!(
        scale.status_replicas_pointer().as_deref(),
        Some("/status/spun")
    );
    assert_eq!(
        scale.label_selector_pointer().as_deref(),
        Some("/status/selector")
    );

    let object = sprocket_object();
    let pointer = scale.spec_replicas_pointer().expect("a usable pointer");
    assert_eq!(
        object.field(&pointer).and_then(|v| v.as_i64()),
        Some(3),
        "the discovered path reads the object it was discovered for"
    );
}

#[test]
fn should_keep_desired_and_observed_apart_for_a_custom_resource() {
    // §33.6 and §4 invariant 8. `spec` is what someone asked for and `status` is what a controller
    // reported. Flattening them into one bag of fields is how a provider ends up presenting an
    // observation as an intent.
    let crd = CustomResourceDefinition::parse(SPROCKET_CRD).expect("the CRD reads");
    let v1 = crd.version("v1").expect("v1 is served");
    let projected = Projection::of(v1.schema(), &sprocket_object());

    assert_eq!(
        projected.field("/spec/teeth").map(|f| f.intent()),
        Some(Intent::Desired)
    );
    assert_eq!(
        projected.field("/status/observedTeeth").map(|f| f.intent()),
        Some(Intent::Observed)
    );
    assert_eq!(
        projected.field("/metadata/name").map(|f| f.intent()),
        Some(Intent::Metadata)
    );

    assert!(
        projected
            .desired_fields()
            .all(|f| f.intent() == Intent::Desired),
        "the desired half contains nothing observed"
    );
    assert!(
        projected.observed_fields().count() > 0,
        "and the observed half is not empty here"
    );
    assert!(
        v1.subresources().has_status(),
        "the mutation boundary is declared, and it is what makes status separately writable"
    );
    assert!(
        !crd.version("v1alpha1")
            .expect("v1alpha1 is served")
            .subresources()
            .has_status(),
        "a version without the subresource has no separate boundary, whatever its fields mean"
    );
}

#[test]
fn should_not_guess_a_relationship_from_a_field_name() {
    // §33.7, the explicit refusal: the provider MUST NOT scan arbitrary string fields and guess
    // relationships by matching names. `spec.nodeName`, `spec.secretRef` and `spec.targetPodName`
    // read exactly like the built-in fields that do carry edges, and a name-matching heuristic
    // would emit three relationships this CRD never declared. §68.7 says Kubernetes has no
    // annotation for this yet, so the honest answer is none — while the fields stay fully typed.
    let schema = sprocket_schema();

    for pointer in ["/spec/nodeName", "/spec/secretRef", "/spec/targetPodName"] {
        let field = schema.field(pointer).expect("the field is typed");
        assert_eq!(field.field_type(), FieldType::String);
    }

    assert!(
        schema.declared_references().is_empty(),
        "nothing in this schema declares a reference, so nothing may be reported as one"
    );
}

// --- §12.4: cache invalidation ------------------------------------------------------------------

#[test]
fn should_answer_from_the_cache_until_the_crd_changes() {
    // §12.4: schemas are cached independently of values, and a CRD update must replace the cached
    // schema. Caching by GVK and never invalidating is how a changed CRD keeps its old fields.
    let gvk = Gvk::new("machines.example.io", "v1", "Sprocket");
    let mut cache = SchemaCache::new("cluster-a-uid");
    cache.insert(gvk.clone(), sprocket_schema());

    assert!(
        cache
            .get(&gvk)
            .is_some_and(|s| s.field("/spec/teeth").is_some())
    );

    cache.invalidate(&gvk);
    assert!(
        cache.get(&gvk).is_none(),
        "an invalidated schema is refetched, not reused"
    );
}

#[test]
fn should_invalidate_only_the_group_version_that_changed() {
    // §12.4: a group/version change invalidates that group/version. Dropping the whole cache
    // would be safe but wasteful; dropping nothing would serve v1 fields for a changed v1.
    let v1 = Gvk::new("machines.example.io", "v1", "Sprocket");
    let alpha = Gvk::new("machines.example.io", "v1alpha1", "Sprocket");
    let other = Gvk::new("astro.example.dev", "v1", "Nebula");
    let mut cache = SchemaCache::new("cluster-a-uid");
    cache.insert(v1.clone(), sprocket_schema());
    cache.insert(alpha.clone(), Schema::absent());
    cache.insert(other.clone(), Schema::absent());

    cache.invalidate_group_version("machines.example.io", "v1");

    assert!(cache.get(&v1).is_none());
    assert!(
        cache.get(&alpha).is_some(),
        "another version of the same group is untouched"
    );
    assert!(cache.get(&other).is_some(), "another group is untouched");
}

#[test]
fn should_forget_a_whole_group_when_its_crd_is_deleted() {
    // §12.4 and §33.2: a deleted CRD takes every version of its kind with it.
    let v1 = Gvk::new("machines.example.io", "v1", "Sprocket");
    let alpha = Gvk::new("machines.example.io", "v1alpha1", "Sprocket");
    let other = Gvk::new("astro.example.dev", "v1", "Nebula");
    let mut cache = SchemaCache::new("cluster-a-uid");
    cache.insert(v1.clone(), sprocket_schema());
    cache.insert(alpha.clone(), Schema::absent());
    cache.insert(other.clone(), Schema::absent());

    cache.invalidate_group("machines.example.io");

    assert!(cache.get(&v1).is_none());
    assert!(cache.get(&alpha).is_none());
    assert!(cache.get(&other).is_some());
}

#[test]
fn should_forget_every_schema_when_it_reconnects_to_a_different_cluster() {
    // §12.4 and Gate J. A GVK is not globally unique: `machines.example.io/v1 Sprocket` may be a
    // different CRD in another cluster. Keying the cache by GVK alone lets cluster B inherit
    // cluster A's fields, which is a fabricated answer with no request behind it.
    let gvk = Gvk::new("machines.example.io", "v1", "Sprocket");
    let mut cache = SchemaCache::new("cluster-a-uid");
    cache.insert(gvk.clone(), sprocket_schema());

    cache.reconnected("cluster-a-uid");
    assert!(
        cache.get(&gvk).is_some(),
        "the same cluster keeps its schemas"
    );

    cache.reconnected("cluster-b-uid");
    assert!(
        cache.get(&gvk).is_none(),
        "a different cluster starts empty"
    );
    assert_eq!(cache.fingerprint(), "cluster-b-uid");
    assert!(cache.is_empty());
}

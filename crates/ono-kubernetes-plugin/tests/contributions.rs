//! What the package declares, checked against what a host would refuse.
//!
//! A package states its contributions twice — in `package/contributions/*.yaml`, which the host
//! reads without starting anything, and across the handshake, when the instance loads. These
//! tests hold the two to each other, because a declaration that only one of them carries is a
//! promise the other cannot keep.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use ono_kubernetes_plugin::contributions::{IDENTITY, TARGETS, target};
use ono_value::{Value, builtin_schemas, from_yaml};

const SCHEMAS: &str = include_str!("../../../package/contributions/schemas.yaml");
const TARGETS_DOCUMENT: &str = include_str!("../../../package/contributions/targets.yaml");

fn document(text: &str, key: &str) -> Vec<Value> {
    let Ok(Value::Map(map)) = from_yaml(text, builtin_schemas()) else {
        panic!("the document is a mapping");
    };
    let Some(Value::List(entries)) = map.get(key) else {
        panic!("the document has a `{key}` list");
    };
    entries.to_vec()
}

fn field(value: &Value, key: &str) -> Option<Value> {
    match value {
        Value::Map(map) => map.get(key).cloned(),
        _ => None,
    }
}

fn text(value: &Value, key: &str) -> String {
    match field(value, key) {
        Some(Value::String(text)) => text.to_string(),
        other => panic!("`{key}` is text, and it is {other:?}"),
    }
}

#[test]
fn should_declare_the_same_schemas_in_the_document_and_across_the_handshake() {
    let declared = document(SCHEMAS, "schemas");
    let contributed: Vec<_> = TARGETS
        .iter()
        .map(|target| target.schema_contribution())
        .collect();
    assert_eq!(
        declared.len(),
        contributed.len(),
        "every schema the document declares is contributed, and no more"
    );
    for (document, contribution) in declared.iter().zip(&contributed) {
        assert_eq!(text(document, "id"), contribution.id);
        assert_eq!(text(document, "name"), contribution.name);
        assert_eq!(text(document, "summary"), contribution.summary);

        let Some(Value::List(identity)) = field(document, "identity") else {
            panic!("`identity` is a list");
        };
        let identity: Vec<String> = identity
            .iter()
            .map(|entry| match entry {
                Value::String(name) => name.to_string(),
                other => panic!("an identity field is a name, and it is {other:?}"),
            })
            .collect();
        assert_eq!(identity, contribution.identity);

        let Some(Value::Map(fields)) = field(document, "fields") else {
            panic!("`fields` is a mapping");
        };
        assert_eq!(
            fields.len(),
            contribution.fields.len(),
            "schema `{}` declares the same fields in both places",
            contribution.id
        );
        for (declared, wire) in fields.iter().zip(&contribution.fields) {
            assert_eq!(
                declared.0, wire.name,
                "schema `{}` declares its fields in the same order in both places",
                contribution.id
            );
            assert_eq!(text(declared.1, "type"), wire.field_type);
            let required = matches!(field(declared.1, "required"), Some(Value::Bool(true)));
            let nullable = matches!(field(declared.1, "nullable"), Some(Value::Bool(true)));
            assert_eq!(required, wire.required, "field `{}`", wire.name);
            assert_eq!(nullable, wire.nullable, "field `{}`", wire.name);
        }
    }
}

#[test]
fn should_declare_every_field_as_exactly_one_of_required_and_nullable() {
    // `to_schema` is the host's own check (ADR-0012 §8): a field that is both, or neither, is a
    // package the supervisor refuses to load rather than a schema with a quirk.
    for target in TARGETS {
        target
            .schema_contribution()
            .to_schema()
            .unwrap_or_else(|error| panic!("schema `{}` is invalid: {error}", target.schema));
    }
}

#[test]
fn should_identify_every_kubernetes_object_by_uid_rather_than_by_name() {
    for target in TARGETS {
        let schema = target.schema_contribution().to_schema().unwrap();
        let identity: Vec<&str> = schema.identity().iter().map(|field| &**field).collect();
        assert_eq!(
            identity,
            vec![IDENTITY],
            "a name is a label a human reuses; `{}` must key on `metadata.uid` so that a \
             recreated object is a different object (§16.1)",
            target.schema
        );
        assert!(
            target.fields.iter().any(|field| field.name == "name"),
            "`{}` still carries the name as a locator (§16.2)",
            target.schema
        );
    }
}

#[test]
fn should_answer_only_for_targets_the_package_declares_statically() {
    let declared: Vec<String> = document(TARGETS_DOCUMENT, "targets")
        .iter()
        .map(|entry| text(entry, "name"))
        .collect();
    for wired in TARGETS {
        assert!(
            declared.contains(&wired.name.to_owned()),
            "`{}` is wired but `contributions/targets.yaml` never declares it, so the shell \
             would have no help, no completion and no reason to load the package",
            wired.name
        );
        let entry = document(TARGETS_DOCUMENT, "targets")
            .into_iter()
            .find(|entry| text(entry, "name") == wired.name)
            .expect("declared above");
        assert_eq!(
            text(&entry, "schema"),
            wired.schema,
            "`{}` names the same schema in both places",
            wired.name
        );
    }
}

#[test]
fn should_answer_for_the_pod_target_the_milestone_names() {
    let pod = target("k8s-pod").expect("the package answers for `k8s-pod`");
    assert_eq!(pod.schema, "io.github.godspeed-you.kubernetes.pod/1");
    assert_eq!(pod.group, "", "a Pod lives in the core API group");
    assert_eq!(
        pod.kind, "Pod",
        "the table names a kind, never a resource: which collection serves a Pod is discovery's \
         answer, not a compile-time one (§13.1)"
    );
    assert!(
        target("k8s-endpointslice").is_none(),
        "a target with no handler is a placeholder, and the package does not claim to answer it"
    );
}

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

use ono_kubernetes_plugin::contributions::{IDENTITY, Reads, TARGETS, target};
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

/// The field's type, as the wire spells it.
///
/// The one place the two vocabularies differ. A schema document is written in the language of
/// core's `docs/contracts/schemas/*.v1.yaml`, where a closed set is `type: enum` with its
/// members beside it; the wire has one string per type, so the same set is `enum<a|b>`. Core
/// parses both — `ono_value`'s document reader and `parse_type_name` on the wire — into the same
/// `FieldType`, so this is a spelling difference and not a second declaration.
fn declared_type(value: &Value) -> String {
    let declared = text(value, "type");
    if declared != "enum" {
        return declared;
    }
    let Some(Value::List(values)) = field(value, "values") else {
        panic!("an `enum` field declares its `values`");
    };
    let members: Vec<String> = values
        .iter()
        .map(|member| match member {
            Value::String(name) => name.to_string(),
            other => panic!("an enum member is a name, and it is {other:?}"),
        })
        .collect();
    format!("enum<{}>", members.join("|"))
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
            assert_eq!(declared_type(declared.1), wire.field_type);
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
    assert_eq!(
        pod.reads,
        Reads::Kind {
            group: "",
            kind: "Pod"
        },
        "a Pod lives in the core API group, and the table names a kind rather than a resource: \
         which collection serves a Pod is discovery's answer, not a compile-time one (§13.1)"
    );
}

#[test]
fn should_answer_for_every_target_the_static_document_declares() {
    // ADR-0005's rule, now that the deferral it recorded is over: a declared schema is a promise,
    // so every word the shell offers help and completion for has a handler and a schema behind
    // it. A placeholder naming a schema no document declares loads happily and fails at its
    // first emit, which is the failure mode furthest from where it was caused.
    for entry in document(TARGETS_DOCUMENT, "targets") {
        let name = text(&entry, "name");
        let wired = target(&name).unwrap_or_else(|| {
            panic!(
                "`{name}` is declared in `contributions/targets.yaml`, so `get {name}` resolves \
                 in a shell that has never loaded this package — and nothing answers it"
            )
        });
        assert_eq!(wired.schema, text(&entry, "schema"));
    }
}

#[test]
fn should_cover_the_tier_one_operational_set_of_section_15_2() {
    // §15.2 names nineteen resources as "the first complete operational target". The list is
    // written out here rather than counted, so that dropping one is a test failure that names it.
    for kind in [
        "namespace",
        "node",
        "pod",
        "deployment",
        "replicaset",
        "statefulset",
        "daemonset",
        "service",
        "endpointslice",
        "ingress",
        "job",
        "cronjob",
        "configmap",
        "secret",
        "serviceaccount",
        "persistentvolumeclaim",
        "persistentvolume",
        "storageclass",
        "networkpolicy",
    ] {
        let wired = target(&format!("k8s-{kind}"))
            .unwrap_or_else(|| panic!("§15.2's Tier 1 set includes {kind}, and nothing answers"));
        assert!(
            matches!(wired.reads, Reads::Kind { .. }),
            "a curated noun reads one kind the table names; which collection serves it is still \
             discovery's answer (§13.1)"
        );
    }
}

#[test]
fn should_derive_a_reconciliation_state_only_where_desired_and_observed_differ_meaningfully() {
    // §37.2: a reconciliation rule is kind-specific, and a kind with no meaningful
    // desired-versus-observed distinction gets none rather than a rule invented for symmetry. A
    // ConfigMap has no controller reconciling it towards anything; a Deployment does.
    for name in [
        "k8s-deployment",
        "k8s-statefulset",
        "k8s-daemonset",
        "k8s-job",
    ] {
        let wired = target(name).unwrap_or_else(|| panic!("`{name}` is wired"));
        assert!(
            wired
                .fields
                .iter()
                .any(|field| field.name == "reconciliation"),
            "`{name}` reconciles a desired state towards an observed one, and §37.5 requires the \
             derived state to arrive with the fields it rests on"
        );
    }
    for name in [
        "k8s-configmap",
        "k8s-service",
        "k8s-namespace",
        "k8s-secret",
    ] {
        let wired = target(name).unwrap_or_else(|| panic!("`{name}` is wired"));
        assert!(
            !wired
                .fields
                .iter()
                .any(|field| field.name == "reconciliation"),
            "`{name}` has no controller reconciling it, and a state derived for symmetry would be \
             a claim with no rule behind it (§37.2)"
        );
    }
}

#[test]
fn should_answer_for_a_resource_whose_kind_only_the_query_knows() {
    // §15.1 and §33.1: a CRD invented after this table was written cannot be named in it, so the
    // package declares one noun that takes the kind as a question instead (ADR-0010).
    let dynamic = target("k8s-resource").expect("the package answers for `k8s-resource`");
    assert_eq!(dynamic.reads, Reads::Discovered);
    assert_eq!(
        dynamic.reads.kind(),
        None,
        "a dynamic target names no kind, because it has none until a query supplies one"
    );
    assert_eq!(
        dynamic.schema, "io.github.godspeed-you.kubernetes.resource/1",
        "one declared schema for every kind there will ever be: a record may only claim a schema \
         the package contributed, and the contributions are fixed before any cluster is reached"
    );
    for field in ["api_group", "kind", "resource_name", "scope"] {
        assert!(
            dynamic.fields.iter().any(|declared| declared.name == field),
            "§13.2's canonical host type survives every kind sharing one schema: `{field}` is \
             missing"
        );
    }
    for field in ["schema_source", "precision", "untyped"] {
        assert!(
            dynamic.fields.iter().any(|declared| declared.name == field),
            "a projection that does not say how well it is known invites equal trust in all of \
             it (§12.3): `{field}` is missing"
        );
    }
}

#[test]
fn should_name_no_kubernetes_kind_on_the_route_that_reads_an_unknown_one() {
    // Gate A's real content: the dynamic route is code with no table of kinds in it. The five
    // curated targets name theirs in `contributions.rs`, which is the one file allowed to.
    const DYNAMIC: &str = include_str!("../src/dynamic.rs");
    let code: String = DYNAMIC
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let code = code.split("#[cfg(test)]").next().unwrap_or_default();
    for kind in [
        "\"Pod\"",
        "\"Deployment\"",
        "\"Secret\"",
        "\"Namespace\"",
        "\"Node\"",
    ] {
        assert!(
            !code.contains(kind),
            "the dynamic route must resolve kinds from discovery rather than recognise them: \
             it names {kind}"
        );
    }
}

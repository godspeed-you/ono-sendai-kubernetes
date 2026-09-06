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

use ono_kuang_sdk::protocol::{Capability, CommandDocument, ParameterContribution, TargetDocument};
use ono_kubernetes_plugin::contributions::{
    COMMAND_SCHEMAS, COMMANDS, IDENTITY, Reads, TARGETS, target,
};
use ono_kubernetes_plugin::spatial::{SHAPES, Shape};
use ono_value::{Value, builtin_schemas, from_yaml};

const SCHEMAS: &str = include_str!("../../../package/contributions/schemas.yaml");
const TARGETS_DOCUMENT: &str = include_str!("../../../package/contributions/targets.yaml");
const COMMANDS_DOCUMENT: &str = include_str!("../../../package/contributions/commands.yaml");

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
    // Every schema a target names, and then the ones that belong to a *command*: a mutation's
    // answer is what one attempt produced, and there is no collection of attempts to enumerate,
    // so it has no noun to hang it on (§31.23, ADR-0024). Matched by id rather than by position,
    // because the two documents are grown at their ends by different hands and an order the
    // handshake happens to build in is not a promise either of them makes.
    let contributed: Vec<_> = TARGETS
        .iter()
        .map(|target| target.schema_contribution())
        .chain(COMMAND_SCHEMAS.iter().map(|schema| schema.contribution()))
        .collect();
    assert_eq!(
        declared.len(),
        contributed.len(),
        "every schema the document declares is contributed, and no more"
    );
    for contribution in &contributed {
        let document = declared
            .iter()
            .find(|entry| text(entry, "id") == contribution.id)
            .unwrap_or_else(|| {
                panic!(
                    "`{}` crosses the handshake and `contributions/schemas.yaml` never declares \
                     it, so a host would register a record shape nothing documents",
                    contribution.id
                )
            });
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
        // Two of the things this package answers for are not objects, and both are named here
        // rather than written as `!= relation`, so that a *third* schema drifting off `uid`
        // fails this test instead of joining a category.
        //
        // A relationship has no `metadata.uid`, so it is keyed on the four things that make two
        // edges the same edge. An observed change has none either — the UID on a change record is
        // the *object's*, and one object changing three times is three observations — so it is
        // keyed on the collection, the observation period, the word, that UID and the version.
        //
        // Five more things this package answers for are facts *about* an object rather than
        // objects: a value a Node states about its machine, a log line, a temporal observation, a
        // causal finding and a condition. Each is keyed on the subject's `uid` plus whatever makes
        // two of them different, and each is named here rather than folded into a category, so
        // that a schema drifting off `uid` fails this test instead of joining one.
        if matches!(
            target.reads,
            Reads::Relations
                | Reads::Changes
                | Reads::Evidence
                | Reads::Logs
                | Reads::Timeline
                | Reads::Why
                | Reads::Conditions
                // A plan is not an object at all: it is a change that has not happened, and one
                // object may have several aimed at it. Keying it on `uid` alone would collapse a
                // scale-down and an image change into one record (ADR-0024).
                | Reads::Plan
        ) {
            continue;
        }
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
fn should_key_an_observed_change_on_the_period_it_belongs_to() {
    // §19.4 and §39.3. The segment is in the key because pre-gap and post-gap observation are two
    // histories: a key without it would let an object re-listed after a `410` collapse onto the
    // observation of it made before the break, which is the stitching §4 invariant 14 forbids,
    // arrived at through the identity model rather than through the record stream.
    let changes = target("k8s-change").expect("the package answers for `k8s-change`");
    let schema = changes.schema_contribution().to_schema().unwrap();
    let identity: Vec<&str> = schema.identity().iter().map(|field| &**field).collect();
    assert_eq!(
        identity,
        vec!["resource", "segment", "change", "uid", "resource_version"]
    );
    for component in &identity {
        assert!(
            changes.fields.iter().any(|field| field.name == *component),
            "`{component}` is part of the identity and must be a field of the schema"
        );
    }
    // A gap is about a period rather than about an object, so every object field it would fill
    // has to be able to be null — including `terminating`, which every object schema declares
    // required.
    for name in ["uid", "name", "kind", "terminating", "resource_version"] {
        let field = changes
            .fields
            .iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("`k8s-change` carries `{name}`"));
        assert!(
            !field.required,
            "`{name}` must be nullable on a change record: a gap is an observation of a period              with no object in it"
        );
    }
}

#[test]
fn should_key_an_edge_on_what_makes_two_edges_the_same_edge() {
    // ADR-0014. An edge has no `metadata.uid`, and every component below is there because
    // dropping it merges edges that are not the same relationship: `owned-by` and `controlled-by`
    // are one fact at two strengths (§24.3), one Pod's two owner references differ only in the
    // far end, and a Pod naming one ConfigMap from two containers differs only in the pointer.
    let relation = target("k8s-relation").expect("the package answers for `k8s-relation`");
    let schema = relation.schema_contribution().to_schema().unwrap();
    let identity: Vec<&str> = schema.identity().iter().map(|field| &**field).collect();
    assert_eq!(identity, vec!["uid", "relation", "target", "evidence_path"]);
    for component in &identity {
        assert!(
            relation.fields.iter().any(|field| field.name == *component),
            "`{component}` is part of the identity and must be a field of the schema"
        );
    }
    // Gate D (§62.4) as a schema obligation: an edge that could not name its class, what was
    // read, or whether the API server stated it would not be checkable.
    for required in ["evidence_class", "evidence", "asserted", "supporting"] {
        let field = relation
            .fields
            .iter()
            .find(|field| field.name == required)
            .unwrap_or_else(|| panic!("Gate D needs `{required}` on every edge"));
        assert!(
            field.required,
            "`{required}` is what makes an edge checkable rather than trusted, so it is never \
             absent"
        );
    }
}

/// The words a reader would take for a cause, in any spelling this package might reach for.
///
/// Written out rather than matched by a stem, because the point is to name them: a schema that
/// wants one of these is a schema whose author has decided the provider may say something §40
/// says it may not, and the failure should quote the word back.
const CAUSAL_WORDS: &[&str] = &[
    "cause",
    "caused",
    "caused_by",
    "causes",
    "causality",
    "because",
    "reason_for",
    "root_cause",
    "explanation",
    "explains",
    "effect",
    "effects",
    "impact",
    "blame",
    "culprit",
    "trigger",
    "triggered_by",
    "responsible",
];

#[test]
fn should_offer_no_field_a_reader_could_mistake_for_a_cause() {
    // §40 and ADR-0020. `causal.rs` has a test that fails if a word for causation appears in its
    // own source; this is the same rule at the boundary, where it is easier to breach by accident.
    // A `why` answer carries five claims and none of them says that one thing brought about
    // another — and a *field name* that implied one would be a regression even with the right
    // value in it, because a reader reads the column heading first.
    let why = target("k8s-why").expect("the package answers for `k8s-why`");
    for field in why.fields {
        assert!(
            !CAUSAL_WORDS.contains(&field.name),
            "`{}` names a cause, and §40's ladder has no rung for one",
            field.name
        );
    }
    // The words that *are* there, verbatim, because §11.3 of the Cloud-Native Vision fixes them
    // and a renderer keyed on a paraphrase would be keyed on nothing.
    let claim = why
        .fields
        .iter()
        .find(|field| field.name == "claim")
        .expect("a finding states its claim");
    for word in [
        "CAUSALITY_NOT_PROVEN",
        "CORRELATED_WITH",
        "PRECEDED_BY",
        "DEPENDENCY_PATH_EXISTS",
        "ASSERTED_BY_KUBERNETES",
    ] {
        assert!(
            claim.field_type.contains(word),
            "`{word}` is one of §40's five rungs, and a renderer keyed on a paraphrase of it \
             would be keyed on nothing"
        );
    }
    assert!(
        claim.field_type.starts_with("enum<"),
        "the ladder is closed: a sixth claim is not something a record may carry"
    );
    assert!(
        why.fields.iter().any(|field| field.name == "claim_means"),
        "a token on its own is read as strongly as its reader needs it to be, so the limit \
         travels with it"
    );
}

#[test]
fn should_present_no_match_on_any_piece_of_exported_identity_evidence() {
    // §47.1 and ADR-0016: this provider exports identity evidence and never resolves a foreign
    // domain. A field named for a match is where that stops being true — the value would be
    // honest and the column heading would not, and a reader trusts the heading.
    let evidence = target("k8s-evidence").expect("the package answers for `k8s-evidence`");
    for forbidden in [
        "match",
        "matched",
        "matches",
        "link",
        "linked",
        "links",
        "resolves_to",
        "resolved",
        "foreign_id",
        "foreign_resource",
        "external_id",
        "instance_id",
    ] {
        assert!(
            !evidence.fields.iter().any(|field| field.name == forbidden),
            "`{forbidden}` would present a match, and this provider has read Kubernetes and \
             nothing else (§47.1)"
        );
    }
    // What must be there instead: §47.2's ranking, the pointer §47.7 makes checkable, and the
    // class §23 already defines — so that distinguishing evidence stays distinguishable from
    // correlating evidence rather than being rebuilt from key names by whoever reads it.
    for required in [
        "key",
        "value",
        "source",
        "strength",
        "evidence_class",
        "lookup_key",
    ] {
        assert!(
            evidence.fields.iter().any(|field| field.name == required),
            "`{required}` is what makes exported evidence inspectable (§47.7)"
        );
    }
}

#[test]
fn should_state_the_bounds_of_a_log_on_every_line_it_answers_with() {
    // §42.1. A log is not the container's output, and the record has to say so rather than imply
    // completeness by omission — so `bounds` is required rather than nullable, and an empty list
    // is impossible because the runtime's own rotation is always in it.
    let log = target("k8s-log").expect("the package answers for `k8s-log`");
    let bounds = log
        .fields
        .iter()
        .find(|field| field.name == "bounds")
        .expect("a log line states its bounds");
    assert!(
        bounds.required,
        "a line whose bounds could be absent would read as the container's complete output"
    );
    assert_eq!(bounds.field_type, "list<string>");
    let secrets = log
        .fields
        .iter()
        .find(|field| field.name == "may_contain_secrets")
        .expect("§42.2 travels with the bytes");
    assert!(secrets.required);
}

#[test]
fn should_keep_a_time_written_by_another_clock_out_of_a_sortable_column() {
    // §39.2. A `timestamp` field is one a shell sorts, and Kubernetes' timestamps are written by
    // five machines. Every time this package answers with that came off another clock is a
    // `string` beside a `clock` field, and the pairing is what makes the cross-clock timeline
    // impossible to assemble by accident rather than merely discouraged.
    for (name, stamp, clock) in [
        ("k8s-timeline", "stamp", "clock"),
        ("k8s-event", "event_time", "clock"),
        ("k8s-log", "stamp", "clock"),
        ("k8s-condition", "last_transition_time", "clock"),
    ] {
        let wired = target(name).unwrap_or_else(|| panic!("`{name}` is wired"));
        let time = wired
            .fields
            .iter()
            .find(|field| field.name == stamp)
            .unwrap_or_else(|| panic!("`{name}` carries `{stamp}`"));
        assert_eq!(
            time.field_type, "string",
            "`{name}.{stamp}` was written by a clock this machine does not read, and a timestamp \
             field would be sorted against ones that are not comparable with it (§39.2)"
        );
        assert!(
            wired.fields.iter().any(|field| field.name == clock),
            "`{name}` states which machine's clock wrote `{stamp}`"
        );
    }
    // The one window that *is* this provider's own clock, and therefore is a timestamp: it is the
    // only clock this machine owns, and both ends of it come from that clock (§39.3).
    let timeline = target("k8s-timeline").expect("the package answers for `k8s-timeline`");
    for own in ["window_opened", "window_latest"] {
        let field = timeline
            .fields
            .iter()
            .find(|field| field.name == own)
            .unwrap_or_else(|| panic!("a timeline record carries `{own}`"));
        assert_eq!(field.field_type, "timestamp");
        assert!(
            field.required,
            "a record without its window reads as a whole history"
        );
    }
    for hole in ["gaps", "not_observed"] {
        let field = timeline
            .fields
            .iter()
            .find(|field| field.name == hole)
            .unwrap_or_else(|| panic!("a timeline record carries `{hole}`"));
        assert!(
            field.required,
            "both kinds of hole travel with every observation, because a reader who has to look \
             for a marker is a reader who will miss it (§19.4, §21.4)"
        );
    }
}

#[test]
fn should_state_a_condition_without_offering_a_word_for_healthy() {
    // §37.1 and §37.3. A condition is a structured observation, and `observedGeneration` matching
    // is evidence that a controller saw a desired state — never, on its own, a claim of health.
    // A boolean called `healthy` or `ready` on this record would be exactly that claim, derived
    // from a rule nobody named.
    let condition = target("k8s-condition").expect("the package answers for `k8s-condition`");
    for forbidden in [
        "healthy",
        "ready",
        "ok",
        "up",
        "green",
        "converged",
        "success",
    ] {
        assert!(
            !condition.fields.iter().any(|field| field.name == forbidden),
            "`{forbidden}` would be a verdict with no rule behind it (§37.3, §4 invariant 9)"
        );
    }
    let status = condition
        .fields
        .iter()
        .find(|field| field.name == "status")
        .expect("a condition states its status");
    assert_eq!(
        status.field_type, "string",
        "`True`, `False` and `Unknown` are three states, a controller may write a fourth, and a \
         boolean has two (§37.2)"
    );
    assert!(
        condition
            .fields
            .iter()
            .any(|field| field.name == "reconciliation"),
        "the only derived state on the record arrives with the rule that derived it (§37.5)"
    );
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

/// The arguments a document declares, read exactly as the host reads them.
///
/// Through the real `TargetDocument`, not through a second YAML reader written here: the point of
/// the test below is that what the *host* would register before this package runs is what the
/// package answers with, and a bespoke parser could agree with the table while the host disagreed
/// with both.
fn declared_target_options(name: &str) -> Vec<ParameterContribution> {
    TargetDocument::parse(TARGETS_DOCUMENT)
        .expect("the targets document reads as the host reads it")
        .targets
        .into_iter()
        .find(|target| target.name == name)
        .unwrap_or_else(|| panic!("`{name}` is declared"))
        .options
}

#[test]
fn should_declare_the_same_arguments_in_the_document_and_across_the_handshake() {
    // `ADR-0587 (core)` gave a contribution somewhere to declare its arguments, and the value of
    // the declaration is spent before this package is ever started: `help get k8s-pod` shows the
    // `--context` line, and completion offers it, from the document on disk (§31.68). A document
    // that declared a different argument set from the handshake would offer help for a word the
    // running package ignores — worse than no help, because it reads as a promise.
    for target in TARGETS {
        let contributed = target.target_contribution().options;
        assert_eq!(
            declared_target_options(target.name),
            contributed,
            "`{}` declares different arguments on disk and across the handshake",
            target.name
        );
        assert!(
            !contributed.is_empty(),
            "`{}` reaches an API server, so it takes at least a `--context`",
            target.name
        );
    }
}

/// The workflow that builds the shell the live suite drives.
const CI: &str = include_str!("../../../.github/workflows/ci.yml");
/// The workspace manifest, which pins the revision this package is built against.
const WORKSPACE: &str = include_str!("../../../Cargo.toml");

#[test]
fn should_build_the_shell_from_the_revision_this_package_is_built_against() {
    // Gate N's whole evidence rests on the live legs having run, and they run the package against
    // an `ono` built from `ONO_CORE_REV`. When that drifts from the revision `Cargo.toml` pins,
    // the legs test the package against a shell it was not built for — and the one that matters
    // is `ADR-0588 (core)`, without which `get k8s-change` and `get k8s-log --follow` are
    // collected rather than streamed and never return to a prompt.
    //
    // It had drifted: the workflow still named the revision that was current when the harness
    // landed. Nothing said so, because a green leg against the wrong shell looks exactly like a
    // green leg.
    let pinned = WORKSPACE
        .lines()
        .find_map(|line| {
            line.split_once("rev = \"")?
                .1
                .split_once('"')
                .map(|(rev, _)| rev)
        })
        .expect("the workspace pins a revision of core");
    let built = CI
        .lines()
        .find_map(|line| line.trim().strip_prefix("ONO_CORE_REV:"))
        .map(str::trim)
        .expect("the workflow names the revision it builds the shell from");

    assert_eq!(
        built, pinned,
        "`.github/workflows/ci.yml` builds `ono` from a different revision of core than \
         `Cargo.toml` builds this package against, so the live legs prove nothing about the pair \
         that ships"
    );
}

#[test]
fn should_declare_the_same_boundedness_in_the_document_and_across_the_handshake() {
    // `ADR-0588 (core)`. The host decides whether to collect a contributed answer *before* it
    // reads the first record, from this declaration — so a document that disagreed with the
    // handshake would have the shell collecting a watch, which never returns to the prompt.
    //
    // Exactly two words do not end: the watch, and the log, which is bounded until `follow` is
    // written and declares the worst case because boundedness belongs to the target rather than
    // to the invocation (ADR-0035). Naming them here rather than counting them means adding a
    // third is a decision somebody takes on purpose.
    let parsed = TargetDocument::parse(TARGETS_DOCUMENT).expect("the targets document reads");
    for target in TARGETS {
        let declared = parsed
            .targets
            .iter()
            .find(|entry| entry.name == target.name)
            .expect("the document declares it");
        assert_eq!(
            declared.answer,
            target.target_contribution().answer,
            "`{}` declares a different boundedness on disk and across the handshake",
            target.name
        );
        let unbounded = matches!(target.name, "k8s-change" | "k8s-log");
        assert_eq!(
            !declared.answer.is_bounded(),
            unbounded,
            "`{}` is {} the pair of words whose answer does not end",
            target.name,
            if unbounded { "one of" } else { "not one of" }
        );
    }
}

#[test]
fn should_declare_only_arguments_a_handler_actually_reads() {
    // A declared argument that nothing consumes is the same failure as an undeclared one that
    // something does: the shell offers a word, the user writes it, and it changes nothing. The
    // source of the package is the second reader — every name below is read out of an argument
    // map somewhere in `src/`, and this test fails when a declaration outlives its handler.
    let sources = source_text();
    for target in TARGETS {
        for option in target.options() {
            assert!(
                sources.contains(&format!("\"{}\"", option.name)),
                "`{}` declares `--{}` and no handler names it",
                target.name,
                option.name
            );
        }
    }
    for command in COMMANDS {
        for option in command.options() {
            assert!(
                sources.contains(&format!("\"{}\"", option.name)),
                "`{}` declares `--{}` and no handler names it",
                command.name,
                option.name
            );
        }
    }
}

/// Every source file of the package crate, concatenated.
fn source_text() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut text = String::new();
    for entry in std::fs::read_dir(root).expect("the package has sources") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            text.push_str(&std::fs::read_to_string(&path).expect("a source file reads"));
        }
    }
    text
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

#[test]
fn should_declare_the_same_commands_in_the_document_and_across_the_handshake() {
    // The same rule the targets are held to, on the half of the contribution surface that can
    // write. A command the handshake carries and the document does not is a word with no help
    // page and no risk level until the package is already loaded — which is exactly the moment
    // the operator's decision about it should have been made (§31.68).
    let declared = document(COMMANDS_DOCUMENT, "commands");
    assert_eq!(
        declared.len(),
        COMMANDS.len(),
        "every command the document declares is contributed, and no more"
    );
    for command in COMMANDS {
        let contribution = command.contribution();
        let entry = declared
            .iter()
            .find(|entry| text(entry, "id") == contribution.id)
            .unwrap_or_else(|| {
                panic!(
                    "`{}` crosses the handshake and `contributions/commands.yaml` never declares \
                     it",
                    contribution.id
                )
            });
        assert_eq!(text(entry, "verb"), contribution.verb);
        assert_eq!(text(entry, "target"), contribution.target);
        assert_eq!(text(entry, "summary"), contribution.summary);
        assert_eq!(text(entry, "output"), contribution.output);
        assert_eq!(text(entry, "argument_mode"), contribution.argument_mode);
        assert_eq!(Some(text(entry, "risk")), contribution.risk);
        let Some(Value::List(capabilities)) = field(entry, "capabilities") else {
            panic!("`capabilities` is a list");
        };
        let capabilities: Vec<String> = capabilities
            .iter()
            .map(|entry| match entry {
                Value::String(name) => name.to_string(),
                other => panic!("a capability is an id, and it is {other:?}"),
            })
            .collect();
        assert_eq!(capabilities, contribution.capabilities);
    }
    // And the arguments, through the host's own reader (`ADR-0587 (core)`). `dry_run` is the one
    // that matters: a document that failed to declare its default would leave the safe value to
    // the handler's memory on every route, including the ones written next year.
    let parsed = CommandDocument::parse(COMMANDS_DOCUMENT).expect("the commands document reads");
    for command in COMMANDS {
        let contribution = command.contribution();
        let entry = parsed
            .commands
            .iter()
            .find(|entry| entry.id == contribution.id)
            .expect("the document declares it");
        assert_eq!(
            entry.options, contribution.options,
            "`{}` declares different arguments on disk and across the handshake",
            command.name
        );
        assert!(entry.selectors.is_empty(), "every argument here is named");
        let dry_run = entry
            .options
            .iter()
            .find(|option| option.name == "dry_run")
            .expect("a command that writes declares whether it is writing");
        assert_eq!(
            dry_run.default_text().as_deref(),
            Some("true"),
            "§44.5: the shortest sentence a user can write predicts rather than writes"
        );
    }
}

#[test]
fn should_declare_a_risk_and_a_granted_capability_for_every_command_that_writes() {
    // §31.75 and the `risk-metadata` rule of core's `contributions.v1.yaml`: every mutating
    // command declares its risk, because the host applies confirmation policy to that descriptor
    // and a provider that prompted for itself would be the ad-hoc prompt §21.5 of the generic
    // contract forbids.
    for command in COMMANDS {
        let contribution = command.contribution();
        assert!(
            matches!(command.risk, "mutate" | "destructive"),
            "`{}` writes, so its risk is one of `risk_levels` in core's capabilities.yaml, and \
             one of the two that mean it changes something",
            contribution.id
        );
        assert!(
            !contribution.capabilities.is_empty(),
            "`{}` reaches a cluster and must say under which grant",
            contribution.id
        );
        for capability in &contribution.capabilities {
            // An id outside the registry makes the whole package `package.invalid` at load, so
            // this is the same check the host makes — held here, where the failure names the
            // command rather than the manifest.
            assert!(
                Capability::from_id(capability).is_some(),
                "`{capability}` is not a KUANG/11 capability of core's capabilities.yaml; a \
                 package may not invent one, and this package does not"
            );
        }
    }
}

#[test]
fn should_write_only_through_a_verb_that_says_so() {
    // §31.22's vocabulary rule, and §4 invariant 22. Both verbs are core's own — `set` is
    // "modify properties or configuration" and `remove` is "delete a resource or a membership"
    // in `docs/contracts/verbs.yaml` — and neither is a word this package invented. A
    // `k8s-apply` would have been the first entry of the Kubernetes mini-shell §35.1 forbids.
    //
    // The other half is the one that matters more: no *target* is a mutation. A contributed
    // target has nowhere to declare a risk or a capability, so a write reachable through `get`
    // would be a write with neither.
    let verbs: Vec<&str> = COMMANDS.iter().map(|command| command.verb).collect();
    assert_eq!(verbs, vec!["set", "remove"]);
    for command in COMMANDS {
        assert!(
            target(command.target).is_some(),
            "`{} {}` acts on a noun this package also answers for, so the same word reads and \
             writes",
            command.verb,
            command.target
        );
    }
    for wired in TARGETS {
        assert!(
            !matches!(wired.reads, Reads::Plan) || wired.name == "k8s-plan",
            "the plan target is the only read-only word about a prospective change"
        );
    }
}

#[test]
fn should_declare_every_command_schema_field_as_exactly_one_of_required_and_nullable() {
    for schema in COMMAND_SCHEMAS {
        schema
            .contribution()
            .to_schema()
            .unwrap_or_else(|error| panic!("schema `{}` is invalid: {error}", schema.id));
    }
}

#[test]
fn should_key_a_prospective_change_on_more_than_the_object_it_is_aimed_at() {
    // ADR-0024. A plan is not an object: one object may have several prospective changes aimed
    // at it, and a key of `uid` alone would collapse a scale-down and an image change into one
    // record. The `resource_version` component is the *precondition* — the point in the object's
    // continuity the change is aimed at — which is also why a mutation record shares the key: a
    // write consumes its precondition, so a second attempt asserting the same token is refused
    // rather than being a second record of the same key (§56.1).
    let plan = target("k8s-plan").expect("the package answers for `k8s-plan`");
    let identity: Vec<&str> = plan.identity_fields().to_vec();
    assert_eq!(
        identity,
        vec!["uid", "resource_version", "action", "changes"]
    );
    for schema in COMMAND_SCHEMAS {
        assert_eq!(
            schema.identity.to_vec(),
            identity,
            "a plan and an attempt at it are keyed the same way, because they are the same change"
        );
    }
    for component in &identity {
        assert!(
            plan.fields.iter().any(|field| field.name == *component),
            "`{component}` is part of the identity and must be a field of the schema"
        );
        for schema in COMMAND_SCHEMAS {
            assert!(
                schema.fields.iter().any(|field| field.name == *component),
                "`{component}` is part of the identity of `{}`",
                schema.id
            );
        }
    }
}

#[test]
fn should_carry_no_field_by_which_an_acceptance_could_read_as_an_outcome() {
    // Gate G (§62.7) as a schema obligation rather than a rendering habit. The record has
    // `stage`, which is the one rung an acceptance reaches, and `verdict`, which a later
    // observation fills. There is deliberately no field a renderer could read as "it worked".
    for schema in COMMAND_SCHEMAS {
        for forbidden in [
            "succeeded",
            "success",
            "rolled_out",
            "rollout",
            "healthy",
            "ok",
        ] {
            assert!(
                !schema.fields.iter().any(|field| field.name == forbidden),
                "`{}` must not carry `{forbidden}`: a mutation response is acceptance, and \
                 acceptance is not evidence that the intended outcome occurred (§4 invariant 18)",
                schema.id
            );
        }
        for required in ["acceptance", "stage", "verdict", "deletion_state"] {
            assert!(
                schema.fields.iter().any(|field| field.name == required),
                "`{required}` is what keeps the distinction visible, and `{}` is missing it",
                schema.id
            );
        }
    }
}

// --- the spatial contribution (§35.5, §35.6, §36.1; `ADR-0584 (core)`, `ADR-0585 (core)`) ------

/// The manifest, which is where a relation shape is declared and where the capability that gates
/// it is requested. Not a `contributions/*.yaml`: `ADR-0585 (core)` reads the shapes from the
/// manifest and the schema ids from the target document, and settles one against the other
/// **before the runtime is spawned**. These tests ask the same question of the same two files.
const MANIFEST: &str = include_str!("../../../package/manifest.yaml");

/// The `contributions.relations` the manifest declares, in order.
fn declared_shapes() -> Vec<String> {
    let Ok(Value::Map(map)) = from_yaml(MANIFEST, builtin_schemas()) else {
        panic!("the manifest is a mapping");
    };
    let Some(Value::Map(contributions)) = map.get("contributions") else {
        panic!("the manifest declares `contributions`");
    };
    let Some(Value::List(shapes)) = contributions.get("relations") else {
        panic!(
            "the manifest declares `contributions.relations`: without it no Kubernetes object is \
             related to any other in Ono's graph, so `near` finds nothing and `follow` has \
             nothing to follow (`ADR-0585 (core)`)"
        );
    };
    shapes
        .iter()
        .map(|shape| match shape {
            Value::String(text) => text.to_string(),
            other => panic!("a shape is text, and it is {other:?}"),
        })
        .collect()
}

/// The capability ids the manifest asks for, required and optional together.
fn requested_capabilities() -> Vec<String> {
    let Ok(Value::Map(map)) = from_yaml(MANIFEST, builtin_schemas()) else {
        panic!("the manifest is a mapping");
    };
    let Some(Value::Map(capabilities)) = map.get("capabilities") else {
        panic!("the manifest declares `capabilities`");
    };
    ["required", "optional"]
        .iter()
        .filter_map(|key| capabilities.get(key))
        .filter_map(|value| match value {
            Value::List(entries) => Some(entries.to_vec()),
            _ => None,
        })
        .flatten()
        .map(|entry| match entry {
            // `network.connect` is a bare word; `filesystem.read: {paths: [...]}` is a mapping of
            // one key, which is the capability id with its scope beside it.
            Value::String(id) => id.to_string(),
            Value::Map(scoped) => scoped
                .iter()
                .next()
                .map(|(id, _)| id.to_string())
                .unwrap_or_default(),
            other => {
                panic!("a capability request is a word or a scoped mapping, and it is {other:?}")
            }
        })
        .collect()
}

#[test]
fn should_declare_the_same_relation_shapes_in_the_manifest_and_in_the_table() {
    // The manifest is what the host reads before this package runs and `spatial::SHAPES` is what
    // the package answers edges for. A shape in only one of them is either a relation a user can
    // `follow` into silence or an edge the host drops on arrival, and both read as "there is
    // nothing there" (`ADR-0585 (core)`).
    let declared = declared_shapes();
    let table: Vec<String> = SHAPES.iter().map(Shape::declaration).collect();
    assert_eq!(
        declared, table,
        "`package/manifest.yaml`'s `contributions.relations` and `spatial::SHAPES` are one \
         declaration written twice, in the same order"
    );
}

#[test]
fn should_name_only_schemas_this_package_declares_a_target_for_at_both_ends_of_every_shape() {
    // The check the host makes at load, made here against the same two documents. `ADR-0585
    // (core)`: an endpoint is a declared §3.3 type or "the id of a schema one of this package's
    // `contributions.targets` declares", and anything else is `package.invalid` before the
    // runtime is spawned. Every endpoint of every shape below is of the second kind, so this is
    // the whole of what a host would check.
    let on_disk: Vec<String> = document(TARGETS_DOCUMENT, "targets")
        .iter()
        .map(|target| text(target, "schema"))
        .collect();
    for shape in declared_shapes() {
        let (from, to) = shape
            .split_once("->")
            .unwrap_or_else(|| panic!("`{shape}` is a `<from>-><to>` pair"));
        for endpoint in [from, to] {
            assert!(
                on_disk.iter().any(|schema| schema == endpoint),
                "`{endpoint}` of `{shape}` names no schema `package/contributions/targets.yaml` \
                 declares a target for, so the host would refuse this package at load"
            );
        }
    }
}

#[test]
fn should_relate_only_kinds_the_contribution_actually_reads() {
    // A declared shape whose ends are not kinds this package lists is a relation that can never
    // carry an edge — the far end would have no `uid` to bind a place to, so the host would
    // resolve nothing and `follow` would arrive nowhere. Every schema a shape names is therefore
    // a target that reads a Kubernetes kind, rather than one of the eleven targets that answer a
    // *question about* an object (`k8s-relation`, `k8s-why`, `k8s-plan`, and the rest).
    for shape in SHAPES {
        for endpoint in [shape.from, shape.to] {
            let target = TARGETS
                .iter()
                .find(|target| target.schema == endpoint)
                .unwrap_or_else(|| panic!("`{endpoint}` is a schema this package contributes"));
            assert!(
                matches!(target.reads, Reads::Kind { .. }),
                "`{endpoint}` is answered by `{}`, which reads no Kubernetes kind, so no object \
                 of it could ever be an end of an edge",
                target.name
            );
        }
    }
}

#[test]
fn should_request_the_capability_that_gates_every_contributed_relation() {
    // §35.5 puts the filter before the merge and `ADR-0585 (core)` implements it by dropping the
    // shapes of a package that holds no `relation.write`. A manifest that declared shapes and
    // never asked for the capability would contribute nothing, silently, on every machine.
    assert!(
        requested_capabilities()
            .iter()
            .any(|capability| capability == "relation.write"),
        "the manifest declares relation shapes, so it must request `relation.write`; it is never \
         granted by default"
    );
}

#[test]
fn should_name_the_relations_a_host_would_register_for_these_shapes() {
    // The id is derived from the shape's *text* — the local name of each schema id, lower-cased,
    // inside the package's own namespace (`ADR-0585 (core)`). It is the word a user types after
    // `follow`, so it is asserted rather than described.
    let ids: Vec<String> = SHAPES.iter().map(Shape::relation_id).collect();
    assert!(
        ids.contains(&"io.github.godspeed-you.kubernetes.pod_to_node".to_owned()),
        "a Pod is related to the Node it runs on, got {ids:?}"
    );
    assert!(
        ids.contains(&"io.github.godspeed-you.kubernetes.pod_to_namespace".to_owned()),
        "§35.6's spatial parent has a relation of its own, got {ids:?}"
    );
    assert!(
        ids.contains(&"io.github.godspeed-you.kubernetes.pod_to_replicaset".to_owned()),
        "and it is not the same relation as the one that owns the Pod, got {ids:?}"
    );
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        ids.len(),
        "two shapes registering one id would be two relations under one word, got {ids:?}"
    );
}

#[test]
fn should_answer_for_the_core_spatial_relation_target_and_declare_its_capability() {
    // §36.1: a package contributes a relationship provider by answering for the shell's own
    // `spatial-relation` target. A command rather than a target, because a contributed target
    // declares no capability and this contribution is gated on one at every invocation.
    let contribution = ono_kubernetes_plugin::spatial::contribution();
    assert_eq!(contribution.target, "spatial-relation");
    assert_eq!(contribution.verb, "get");
    assert_eq!(contribution.output, "stream<ono.spatial-relation/1>");
    assert!(
        contribution
            .capabilities
            .contains(&"relation.write".to_owned()),
        "the host checks the capability before this package's code runs, got {:?}",
        contribution.capabilities
    );
    assert!(
        contribution.risk.is_none(),
        "reading what is related to what changes nothing"
    );
    assert!(
        requested_capabilities().contains(&"network.connect".to_owned()),
        "the edges are read from a cluster, so the command needs the connection too"
    );
}

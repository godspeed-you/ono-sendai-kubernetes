//! Reading a resource this package has never heard of (§15.1, §33.1, Gates A and B).
//!
//! The curated targets of [`crate::contributions`] name a group and a kind at build time. This
//! module is the other route: the query names the kind, the *cluster* says which collection
//! serves it, and the cluster's own OpenAPI document says what its fields are. Nothing here
//! names a Kubernetes kind, and a test asserts that nothing in this crate does — a table of
//! known kinds is exactly what §33.1 calls non-conformant.
//!
//! Three problems, and how each is settled.
//!
//! **Which resource did the query mean?** [`Selector`] carries what the query said: a `kind`, or
//! a `resource` which may be a plural or a short name, optionally narrowed by `group` and
//! `version`. [`resolve`] matches it against a discovery snapshot. A kind that matches in two
//! API groups is *not* resolved by preferring one of them: §35.8 forbids choosing by an
//! arbitrary type priority, so the answer is a refusal that lists the candidates and how to
//! spell each one. Kinds are not globally unique (§13.5) and this is where that stops being a
//! footnote.
//!
//! **What are its fields?** [`Typing::of`] reads the API server's OpenAPI v3 document for the
//! resolved group-version and finds the component that declares this GVK. That path types a
//! built-in and a custom resource identically — which is the point, because the alternative
//! §33.1 names as non-conformant is typed behaviour for built-ins and raw JSON for the rest.
//! Where the server publishes no such document, the typing is [`Schema::absent`] and every field
//! still projects, with its precision saying so (§12.3, §12.5, Gate B).
//!
//! **What does the record carry?** [`content`] turns the projection into Ono values. The schema
//! is what decides that `2026-01-01T00:00:00Z` under a `date-time` format is an instant rather
//! than a string, and its silence is what leaves the same field as text. That is the visible
//! difference between a described resource and an undescribed one, and it is a degradation of
//! precision rather than a loss of the field.

use std::collections::BTreeMap;
use std::sync::Arc;

use ono_provider_kubernetes::discovery::{Discovery, Resource, Scope, Verb};
use ono_provider_kubernetes::schema::{Intent, Precision, Projection, Schema, SchemaSource};
use ono_value::{MapValue, Value};
use serde_json::{Map as JsonMap, Value as Json};

/// What a query said about the resource it wants, before any cluster has seen it.
///
/// Every part is optional because every part may be the thing the operator does not know. What
/// is *not* optional is that at least one of `kind` and `resource` is present: a query naming
/// neither has not asked about anything, and defaulting to some kind would be this package
/// choosing on the operator's behalf.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selector {
    kind: Option<String>,
    resource: Option<String>,
    group: Option<String>,
    version: Option<String>,
}

impl Selector {
    /// Reads a selector out of a query's options.
    ///
    /// `group` is deliberately *not* filtered for emptiness the way the other options are:
    /// `--group ''` names the core API group, which is a group with an empty name rather than
    /// an absent one (§13.3). Writing it and omitting it are different questions, and the
    /// difference decides whether a kind is searched for in one group or in all of them.
    #[must_use]
    pub fn from_options(options: &JsonMap<String, Json>) -> Self {
        let text = |key: &str| {
            options
                .get(key)
                .and_then(Json::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        Self {
            kind: text("kind"),
            resource: text("resource"),
            group: options
                .get("group")
                .and_then(Json::as_str)
                .map(str::to_owned),
            version: text("version"),
        }
    }

    /// Whether the query named anything at all to look for.
    #[must_use]
    pub fn names_something(&self) -> bool {
        self.kind.is_some() || self.resource.is_some()
    }

    /// The group the query narrowed to, where it named one.
    #[must_use]
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// The version the query named, which §13.4 keeps reachable beside the preferred one.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// How the query spelled what it wants, for an error message that quotes it back.
    #[must_use]
    pub fn spelling(&self) -> String {
        match (&self.kind, &self.resource) {
            (Some(kind), Some(resource)) => format!("kind `{kind}` and resource `{resource}`"),
            (Some(kind), None) => format!("kind `{kind}`"),
            (None, Some(resource)) => format!("resource `{resource}`"),
            (None, None) => "nothing".to_owned(),
        }
    }

    /// Whether this resource is one the query asked for.
    ///
    /// A kind is matched exactly, because a kind is a Kubernetes identifier with a spelling the
    /// server chose (§13.1) and a case-insensitive match would let `pods` find the kind `Pod`
    /// and blur the one distinction §13.1 exists to keep. A plural or short name is matched
    /// case-insensitively, because those *are* the typing convenience §13.5 describes.
    fn matches(&self, resource: &Resource) -> bool {
        // The group and the version narrow here as well as deciding which documents get
        // fetched. Resolution that depended on the caller having fetched exactly the right
        // documents would be correct only by arrangement, and §35.8 is too easy to breach by
        // accident for that.
        if let Some(group) = &self.group
            && resource.group() != group
        {
            return false;
        }
        if let Some(version) = &self.version
            && resource.version() != version
        {
            return false;
        }
        if let Some(kind) = &self.kind
            && resource.kind() != kind
        {
            return false;
        }
        if let Some(name) = &self.resource {
            let matched = resource.plural().eq_ignore_ascii_case(name)
                || resource
                    .short_names()
                    .iter()
                    .any(|short| short.eq_ignore_ascii_case(name));
            if !matched {
                return false;
            }
        }
        true
    }
}

/// Why a selector did not resolve to exactly one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unresolved {
    /// The query named no kind and no resource.
    Unasked,
    /// The cluster serves nothing that matches.
    NotServed,
    /// More than one served resource matches, and none of them is the obvious one (§35.8).
    Ambiguous {
        /// Every candidate, spelled the way a query would have to spell it to pick one.
        candidates: Vec<String>,
    },
    /// Exactly one resource matches and the server does not offer `list` on it.
    NotListable {
        /// The collection, for an error that says which one.
        gvr: String,
    },
}

/// The resources a selector matches, in the snapshot it was matched against.
///
/// # Errors
///
/// [`Unresolved`] — see its variants. Each is a different state and none of them is "empty":
/// §11.5 and §21.4 keep an unserved API apart from a collection with nothing in it, and §35.8
/// keeps an ambiguous name apart from both.
pub fn resolve<'snapshot>(
    selector: &Selector,
    discovery: &'snapshot Discovery,
) -> Result<&'snapshot Resource, Unresolved> {
    if !selector.names_something() {
        return Err(Unresolved::Unasked);
    }
    let mut matched: Vec<&Resource> = discovery
        .all()
        .filter(|resource| selector.matches(resource))
        .collect();
    matched.sort_by_key(|resource| (resource.group().to_owned(), resource.kind().to_owned()));
    match matched.as_slice() {
        [] => Err(Unresolved::NotServed),
        [only] => {
            if only.supports(Verb::List) {
                Ok(only)
            } else {
                Err(Unresolved::NotListable {
                    gvr: only.gvr().to_string(),
                })
            }
        }
        // §35.8 in one place: more than one type shares the name, so the answer is the list of
        // candidates rather than the first of them. A provider that picked here would be
        // inventing a type priority, and the operator would not find out until the records were
        // already wrong.
        several => Err(Unresolved::Ambiguous {
            candidates: several.iter().map(|resource| candidate(resource)).collect(),
        }),
    }
}

/// One candidate, spelled as the options that would select it alone.
fn candidate(resource: &Resource) -> String {
    format!(
        "--kind {} --group '{}' (version {}, resource {})",
        resource.kind(),
        resource.group(),
        resource.version(),
        resource.plural()
    )
}

/// A resolved resource's schema, and one object seen through it.
///
/// Holds the schema rather than only the projection so that the same typing serves every object
/// of a page: the document is fetched once per query, and §50.3's lazy schema loading is what
/// makes that affordable.
#[derive(Debug, Clone)]
pub struct Typing {
    schema: Schema,
}

impl Typing {
    /// The typing an OpenAPI v3 document gives for one GVK.
    ///
    /// `document` is the whole `/openapi/v3/...` response for the group-version. The component
    /// that describes this kind is the one whose `x-kubernetes-group-version-kind` says so —
    /// asked of the document rather than derived from a naming convention, because the component
    /// key is a Java-style package name that no rule this package could write reconstructs
    /// reliably for an arbitrary CRD.
    ///
    /// Anything that does not read gives [`Schema::absent`] rather than an error. A schema is
    /// an *aid* to projection (§12.1): a resource whose schema cannot be found is still a
    /// resource, and refusing to show it because its description is missing is precisely the
    /// all-or-nothing behaviour §15.5 rules out.
    #[must_use]
    pub fn of(document: Option<&str>, group: &str, version: &str, kind: &str) -> Self {
        let schema = document
            .and_then(|text| serde_json::from_str::<Json>(text).ok())
            .as_ref()
            .and_then(|value| component_for(value, group, version, kind))
            .and_then(|component| Schema::from_openapi_v3(&component.to_string()).ok())
            .unwrap_or_else(Schema::absent);
        Self { schema }
    }

    /// A typing that describes nothing, for a server that publishes no schema document (§12.3).
    #[must_use]
    pub fn absent() -> Self {
        Self {
            schema: Schema::absent(),
        }
    }

    /// Where the typing came from, as the record reports it.
    #[must_use]
    pub fn source(&self) -> SchemaSource {
        self.schema.source()
    }

    /// One object seen through this schema.
    #[must_use]
    pub fn project(&self, object: &ono_provider_kubernetes::object::Object) -> Projection {
        Projection::of(&self.schema, object)
    }
}

/// The component of an OpenAPI v3 document that declares this GVK.
fn component_for<'doc>(
    document: &'doc Json,
    group: &str,
    version: &str,
    kind: &str,
) -> Option<&'doc Json> {
    document
        .get("components")?
        .get("schemas")?
        .as_object()?
        .values()
        .find(|component| declares(component, group, version, kind))
}

/// Whether a component's `x-kubernetes-group-version-kind` names this GVK.
fn declares(component: &Json, group: &str, version: &str, kind: &str) -> bool {
    let Some(declared) = component.get("x-kubernetes-group-version-kind") else {
        return false;
    };
    // The extension is a list on the API server's own document and a single object on some
    // generators' output, so both shapes are read rather than one being called malformed.
    let entries: Vec<&Json> = match declared {
        Json::Array(entries) => entries.iter().collect(),
        object @ Json::Object(_) => vec![object],
        _ => return false,
    };
    entries.into_iter().any(|entry| {
        entry
            .get("group")
            .and_then(Json::as_str)
            .unwrap_or_default()
            == group
            && entry
                .get("version")
                .and_then(Json::as_str)
                .unwrap_or_default()
                == version
            && entry.get("kind").and_then(Json::as_str).unwrap_or_default() == kind
    })
}

/// What a dynamic record says about the object's own content, beyond the shared metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct Content {
    /// `spec`, as a map of typed values, or null where the object carries none.
    pub desired: Value,
    /// `status`, likewise (§4 invariant 8: the two are never merged).
    pub observed: Value,
    /// Every other top-level field — a ConfigMap's `data`, a Role's `rules` — so that §12.5's
    /// "no field is removed" holds for kinds that keep their payload nowhere near `spec`.
    pub other: Value,
    /// How well the content as a whole is known (§12.3).
    pub precision: Precision,
    /// The JSON pointers of the fields no schema described (§12.5).
    pub untyped: Vec<String>,
}

/// The object's content, typed as far as the projection types it.
///
/// **Metadata is excluded from `precision` and `untyped` deliberately.** This package projects
/// `metadata` itself, from §14's common projection, into the record's own named fields — so a
/// schema that says nothing about `metadata` has left no gap in what is reported, and counting
/// it as one would make every resource on every server read as undescribed. What the aggregate
/// measures is what the aggregate is about: the fields whose meaning only the resource's own
/// schema could supply.
#[must_use]
pub fn content(projection: &Projection, native: &Json) -> Content {
    let is_content = |intent: Intent| {
        matches!(
            intent,
            Intent::Desired | Intent::Observed | Intent::Unclassified
        )
    };
    let precision = projection
        .fields()
        .iter()
        .filter(|field| is_content(field.intent()))
        .map(|field| field.precision())
        .min()
        .unwrap_or(Precision::Unknown);
    let untyped: Vec<String> = projection
        .fields()
        .iter()
        .filter(|field| is_content(field.intent()) && field.precision() == Precision::Unknown)
        .map(|field| field.pointer().to_owned())
        .collect();

    let subtree = |name: &str| match native.get(name) {
        None | Some(Json::Null) => Value::Null,
        Some(value) => typed(projection, &format!("/{name}"), value),
    };
    let other: MapValue = native
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "apiVersion" | "kind" | "metadata" | "spec" | "status"
            )
        })
        .map(|(name, value)| {
            (
                Arc::from(name.as_str()),
                typed(projection, &format!("/{name}"), value),
            )
        })
        .collect();

    Content {
        desired: subtree("spec"),
        observed: subtree("status"),
        other: if other.is_empty() {
            Value::Null
        } else {
            Value::Map(Arc::new(other))
        },
        precision,
        untyped,
    }
}

/// One JSON value at a pointer, as the value model carries it.
///
/// The schema decides exactly one thing here: whether a string that a `date-time` format
/// describes becomes an instant. Everything else follows the value's own shape, because JSON
/// already distinguishes a number from a string and repeating the schema's word for it would
/// let a wrong schema contradict the data the server actually sent. Where the schema is silent
/// the string stays a string — the field is preserved and its precision is what degraded
/// (§12.3, §12.5, Gate B).
fn typed(projection: &Projection, pointer: &str, value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Number(number) => number
            .as_i64()
            .map(|whole| Value::Int(i128::from(whole)))
            .or_else(|| number.as_f64().map(Value::Float))
            .unwrap_or(Value::Null),
        Json::String(text) => match instant_format(projection, pointer) {
            true => timestamp(text),
            false => Value::String(text.as_str().into()),
        },
        Json::Array(items) => Value::List(
            items
                .iter()
                .enumerate()
                .map(|(index, item)| typed(projection, &format!("{pointer}/{index}"), item))
                .collect(),
        ),
        Json::Object(entries) => {
            let map: MapValue = entries
                .iter()
                .map(|(name, item)| {
                    (
                        Arc::from(name.as_str()),
                        typed(projection, &format!("{pointer}/{}", escape(name)), item),
                    )
                })
                .collect();
            Value::Map(Arc::new(map))
        }
    }
}

/// Whether the schema describes the field at this pointer as an instant.
fn instant_format(projection: &Projection, pointer: &str) -> bool {
    projection
        .field(pointer)
        .and_then(|field| field.format())
        .is_some_and(|format| format == "date-time")
}

/// An RFC 3339 instant, or the text itself where it does not parse.
///
/// A schema saying `date-time` over a value that is not one is the schema being wrong about the
/// data, and the data is what the server sent. Keeping the string is the honest half of that
/// disagreement; discarding it would lose a field to a description of it (§12.5).
fn timestamp(text: &str) -> Value {
    ono_value::from_json(
        &serde_json::json!({"$timestamp": text}),
        ono_value::builtin_schemas(),
    )
    .unwrap_or_else(|_| Value::String(text.into()))
}

/// A JSON pointer token, with `~` and `/` escaped as RFC 6901 requires.
fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// The scope word a record reports, which is the server's answer and never a guess (§13.2).
#[must_use]
pub fn scope_word(scope: Scope) -> &'static str {
    match scope {
        Scope::Namespaced => "namespaced",
        Scope::Cluster => "cluster",
    }
}

/// Every listable resource a snapshot holds, spelled as the query that would select it.
///
/// What a refusal offers when the query named nothing: the cluster's own catalogue, which is
/// the only honest answer to "which resource?" from a provider that compiles in no list of them.
#[must_use]
pub fn catalogue(discovery: &Discovery) -> Vec<String> {
    let mut by_group: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for resource in discovery.listable() {
        by_group
            .entry(resource.group())
            .or_default()
            .push(resource.kind());
    }
    by_group
        .into_iter()
        .map(|(group, mut kinds)| {
            kinds.sort_unstable();
            kinds.dedup();
            format!(
                "{}: {}",
                if group.is_empty() { "core" } else { group },
                kinds.join(", ")
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A cluster serving two groups that both offer a kind called `Widget`, plus one that only
    /// one of them offers. The names are invented here and appear nowhere in the crate.
    fn ambiguous_cluster() -> Discovery {
        Discovery::builder()
            .resources(
                &json!({
                    "kind": "APIResourceList",
                    "groupVersion": "left.example/v1",
                    "resources": [
                        {"name": "widgets", "kind": "Widget", "namespaced": true,
                         "verbs": ["get", "list"], "shortNames": ["wd"]},
                    ],
                })
                .to_string(),
            )
            .expect("a resource list")
            .resources(
                &json!({
                    "kind": "APIResourceList",
                    "groupVersion": "right.example/v1",
                    "resources": [
                        {"name": "widgets", "kind": "Widget", "namespaced": false,
                         "verbs": ["get", "list"], "shortNames": ["wd"]},
                        {"name": "gadgets", "kind": "Gadget", "namespaced": true,
                         "verbs": ["get", "list"]},
                        {"name": "sealed", "kind": "Sealed", "namespaced": true,
                         "verbs": ["get"]},
                    ],
                })
                .to_string(),
            )
            .expect("a resource list")
            .build()
    }

    fn selector(pairs: &[(&str, Json)]) -> Selector {
        Selector::from_options(
            &pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    #[test]
    fn should_resolve_a_kind_only_one_group_offers() {
        let cluster = ambiguous_cluster();
        let resolved = resolve(&selector(&[("kind", json!("Gadget"))]), &cluster)
            .expect("one group offers it");
        assert_eq!(resolved.plural(), "gadgets");
        assert_eq!(resolved.group(), "right.example");
    }

    #[test]
    fn should_refuse_an_ambiguous_kind_rather_than_prefer_a_group() {
        // §35.8: a name that two types share must not resolve by an arbitrary type priority.
        // The refusal carries the candidates, because "be more specific" without saying what
        // the choices are is a dead end.
        let cluster = ambiguous_cluster();
        let Err(Unresolved::Ambiguous { candidates }) =
            resolve(&selector(&[("kind", json!("Widget"))]), &cluster)
        else {
            panic!("two groups offer `Widget`, and neither of them wins");
        };
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|entry| entry.contains("left.example"))
        );
        assert!(
            candidates
                .iter()
                .any(|entry| entry.contains("right.example"))
        );
    }

    #[test]
    fn should_resolve_an_ambiguous_kind_once_the_query_names_the_group() {
        let cluster = ambiguous_cluster();
        let resolved = resolve(
            &selector(&[("kind", json!("Widget")), ("group", json!("left.example"))]),
            &cluster,
        )
        .expect("the group settles it");
        assert_eq!(resolved.group(), "left.example");
        assert_eq!(resolved.scope(), Scope::Namespaced);
    }

    #[test]
    fn should_refuse_an_ambiguous_short_name_the_same_way() {
        // A short name is a typing convenience and never identity (§13.5), so it gets no more
        // authority to break a tie than a kind does.
        let cluster = ambiguous_cluster();
        assert!(matches!(
            resolve(&selector(&[("resource", json!("wd"))]), &cluster),
            Err(Unresolved::Ambiguous { .. })
        ));
    }

    #[test]
    fn should_report_a_kind_the_cluster_does_not_serve_as_not_served() {
        // §11.5, §21.4: not served is its own answer. An empty stream would say the cluster has
        // none of them, which is a claim nobody made.
        let cluster = ambiguous_cluster();
        assert_eq!(
            resolve(&selector(&[("kind", json!("Absent"))]), &cluster),
            Err(Unresolved::NotServed)
        );
    }

    #[test]
    fn should_report_a_resource_that_cannot_be_listed_as_such() {
        let cluster = ambiguous_cluster();
        assert!(matches!(
            resolve(&selector(&[("kind", json!("Sealed"))]), &cluster),
            Err(Unresolved::NotListable { .. })
        ));
    }

    #[test]
    fn should_refuse_a_query_that_names_no_resource_at_all() {
        let cluster = ambiguous_cluster();
        assert_eq!(resolve(&selector(&[]), &cluster), Err(Unresolved::Unasked));
    }

    #[test]
    fn should_read_an_explicitly_empty_group_as_the_core_group() {
        // §13.3: the core group has an empty name rather than no name, so `--group ''` is a
        // narrowing and omitting `group` is not.
        assert_eq!(selector(&[("group", json!(""))]).group(), Some(""));
        assert_eq!(selector(&[("kind", json!("X"))]).group(), None);
    }

    #[test]
    fn should_not_match_a_kind_case_insensitively() {
        // A kind is an identifier the server chose. Matching `widget` to `Widget` would put a
        // plural and a kind one keystroke apart, which is the confusion §13.1 exists to stop.
        let cluster = ambiguous_cluster();
        assert_eq!(
            resolve(&selector(&[("kind", json!("gadget"))]), &cluster),
            Err(Unresolved::NotServed)
        );
    }

    #[test]
    fn should_type_a_described_instant_and_leave_an_undescribed_one_as_text() {
        // Gate B in miniature: the schema is what turns text into an instant, and its silence
        // leaves the field present and typed by its own shape.
        let object = ono_provider_kubernetes::object::Object::from_json(
            "kubernetes:test",
            json!({
                "apiVersion": "left.example/v1",
                "kind": "Widget",
                "metadata": {"name": "one", "uid": "u"},
                "spec": {"renewAt": "2026-01-01T00:00:00Z", "count": 3},
            }),
        )
        .expect("an object");

        let described = Typing::of(
            Some(
                &json!({
                    "components": {"schemas": {"any.name": {
                        "type": "object",
                        "x-kubernetes-group-version-kind": [
                            {"group": "left.example", "version": "v1", "kind": "Widget"},
                        ],
                        "properties": {"spec": {"type": "object", "properties": {
                            "renewAt": {"type": "string", "format": "date-time"},
                            "count": {"type": "integer"},
                        }}},
                    }}},
                })
                .to_string(),
            ),
            "left.example",
            "v1",
            "Widget",
        );
        let typed = content(&described.project(&object), object.native());
        let Value::Map(spec) = &typed.desired else {
            panic!("spec is a map, and it is {:?}", typed.desired);
        };
        assert!(
            matches!(spec.get("renewAt"), Some(Value::Timestamp(_))),
            "a `date-time` format makes it an instant, got {:?}",
            spec.get("renewAt")
        );
        assert_eq!(spec.get("count"), Some(&Value::Int(3)));
        assert_eq!(typed.precision, Precision::Structural);
        assert!(typed.untyped.is_empty());

        let undescribed = Typing::absent();
        let raw = content(&undescribed.project(&object), object.native());
        let Value::Map(spec) = &raw.desired else {
            panic!("the field survives the missing schema");
        };
        assert_eq!(
            spec.get("renewAt"),
            Some(&Value::String("2026-01-01T00:00:00Z".into())),
            "no schema means no claim that it is an instant — and the field is still here"
        );
        assert_eq!(spec.get("count"), Some(&Value::Int(3)));
        assert_eq!(raw.precision, Precision::Unknown);
        assert!(
            raw.untyped.contains(&"/spec/renewAt".to_owned()),
            "an undescribed field is named as undescribed, got {:?}",
            raw.untyped
        );
    }

    #[test]
    fn should_ignore_a_schema_component_that_declares_another_kind() {
        // The component is found by what it declares (§13.2), not by the shape of its key.
        let typing = Typing::of(
            Some(
                &json!({"components": {"schemas": {"other": {
                    "type": "object",
                    "x-kubernetes-group-version-kind": [
                        {"group": "left.example", "version": "v1", "kind": "Elsewhere"},
                    ],
                }}}})
                .to_string(),
            ),
            "left.example",
            "v1",
            "Widget",
        );
        assert_eq!(
            typing.source(),
            SchemaSource::Absent,
            "a document that describes another kind describes this one not at all"
        );
    }

    #[test]
    fn should_keep_a_payload_field_that_lives_outside_spec_and_status() {
        // §12.5: a kind whose content is neither desired nor observed state still has content,
        // and a projection that only knew about `spec` would drop it.
        let object = ono_provider_kubernetes::object::Object::from_json(
            "kubernetes:test",
            json!({
                "apiVersion": "left.example/v1",
                "kind": "Widget",
                "metadata": {"name": "one"},
                "payload": {"key": "value"},
            }),
        )
        .expect("an object");
        let held = content(&Typing::absent().project(&object), object.native());
        let Value::Map(other) = &held.other else {
            panic!("the payload survives, and it is {:?}", held.other);
        };
        assert!(other.get("payload").is_some());
        assert_eq!(
            held.desired,
            Value::Null,
            "there is no spec, and null says so"
        );
    }
}

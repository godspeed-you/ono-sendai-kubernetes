//! What a resource's fields *are*, learned from the cluster rather than from this crate.
//!
//! Specification §12 and §33. Discovery says which resources the server serves (§11); it does not
//! say what their fields hold. That is what this module reads, from the OpenAPI v3 shapes the API
//! server and every CRD publish — `type`, `properties`, `items`, `required`, `format` and the
//! `x-kubernetes-*` extensions.
//!
//! Nothing here names a Kubernetes kind, and nothing here is a table of known types. A CRD
//! installed an hour ago is typed by the same code that types anything else, which is the whole of
//! Gate A: the kind is data, not code.
//!
//! Two rules shape the design.
//!
//! **A schema gap degrades precision; it never removes a field** (§12.3, §12.5, §4 invariant 17,
//! Gate B). Every projected field says how well it is known — [`Precision`] — and where that
//! knowledge came from — [`SchemaSource`]. A resource whose schema the server never published is
//! still a resource with fields; what it lacks is anyone's claim about their types. The
//! non-conformant alternative §33.1 names is a custom resource handed over as raw JSON while
//! built-in kinds get typed behaviour.
//!
//! **A schema describes fields, not relationships** (§33.7). `spec.nodeName` on a custom resource
//! reads exactly like the built-in field that does carry an edge, and it means nothing of the
//! sort until something declares that it does. Kubernetes has no annotation that says "this field
//! references that GVK" (§68.7), so [`Schema::declared_references`] is empty for every schema
//! today and the alternative — matching field names against kind names — is not implemented here
//! and must not be.
//!
//! This module is pure parsing and projection. It performs no I/O and holds no connection.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value as Json;

use crate::discovery::{Gvk, Gvr, Scope};
use crate::object::Object;

/// What went wrong reading a schema document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// The bytes are not JSON.
    Malformed(String),
    /// The JSON is not an OpenAPI schema object.
    NotASchema(String),
    /// The JSON is not a `CustomResourceDefinition`.
    NotACrd(String),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "the schema does not read as JSON: {detail}"),
            Self::NotASchema(detail) => {
                write!(f, "the document is not an OpenAPI schema: {detail}")
            }
            Self::NotACrd(detail) => write!(
                f,
                "the document is not a CustomResourceDefinition: {detail}"
            ),
        }
    }
}

impl std::error::Error for SchemaError {}

/// The kind of value a field holds.
///
/// The OpenAPI type words, plus [`FieldType::Unknown`] for a schema that declines to say. An
/// unrecognised type word becomes `Unknown` rather than an error: an extension this provider has
/// not seen is a gap in precision, never a reason to reject the resource (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// A nested structure.
    Object,
    /// A list.
    Array,
    /// Text.
    String,
    /// A whole number.
    Integer,
    /// A number that may have a fraction.
    Number,
    /// True or false.
    Boolean,
    /// An explicit JSON `null`, which is absence stated rather than a value (§4: unknown is null).
    Null,
    /// Nothing said what this holds.
    Unknown,
}

impl FieldType {
    /// The type this OpenAPI type word names, where it is one this provider models.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "object" => Self::Object,
            "array" => Self::Array,
            "string" => Self::String,
            "integer" => Self::Integer,
            "number" => Self::Number,
            "boolean" => Self::Boolean,
            "null" => Self::Null,
            _ => return None,
        })
    }

    /// The shape a value actually has.
    ///
    /// This observes the data; it does not claim a schema said so. Callers pair it with
    /// [`Precision::Unknown`] so that "the value is a number" is never read as "the resource
    /// declares this field a number".
    #[must_use]
    pub fn of_value(value: &Json) -> Self {
        match value {
            Json::Null => Self::Null,
            Json::Bool(_) => Self::Boolean,
            Json::Number(number) => {
                if number.is_f64() {
                    Self::Number
                } else {
                    Self::Integer
                }
            }
            Json::String(_) => Self::String,
            Json::Array(_) => Self::Array,
            Json::Object(_) => Self::Object,
        }
    }

    /// The word this type is written as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Array => "array",
            Self::String => "string",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Null => "null",
            Self::Unknown => "unknown",
        }
    }
}

/// How well a field is known (§12.3).
///
/// Ordered weakest first, so the precision of a whole projection is the minimum of its parts: one
/// undescribed field makes a projection partly undescribed, and reporting the best case would be
/// the comfortable lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Precision {
    /// No schema described this field. It exists because the object carries it.
    Unknown,
    /// A schema reaches this field but declines to describe what it holds —
    /// `x-kubernetes-preserve-unknown-fields`, `x-kubernetes-int-or-string`, or no stated type.
    Loose,
    /// A structural schema states this field's type.
    Structural,
}

impl Precision {
    /// The word this precision is reported as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Loose => "loose",
            Self::Structural => "structural",
        }
    }
}

/// Where a field description came from (§12.1, §12.3).
///
/// Carried alongside [`Precision`] because "the schema says nothing" and "there is no schema" are
/// different situations for a user deciding how much to trust a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaSource {
    /// The API server's OpenAPI v3 document.
    OpenApiV3,
    /// The `openAPIV3Schema` a CRD publishes for one of its versions (§33.3).
    CrdStructural,
    /// Nothing described it: the field is here because the object carries it.
    Absent,
}

impl SchemaSource {
    /// The word this source is reported as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenApiV3 => "openapi-v3",
            Self::CrdStructural => "crd-structural",
            Self::Absent => "absent",
        }
    }
}

/// Whether a field is something asked for or something reported (§4 invariant 8, §33.6).
///
/// Derived from the position every Kubernetes object shares — `spec`, `status`, `metadata` — and
/// not from any kind's vocabulary, so it holds for a CRD as it does for a built-in. It is a
/// reading of meaning, separate from the *mutation boundary*, which only a declared `status`
/// subresource establishes ([`Subresources::has_status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// `apiVersion` and `kind`: what the object is.
    Identity,
    /// `metadata`: identity, lifetime and labelling.
    Metadata,
    /// `spec`: what someone asked for.
    Desired,
    /// `status`: what a controller reported observing.
    Observed,
    /// Anything else a resource carries at its top level, such as a ConfigMap-style payload.
    Unclassified,
}

impl Intent {
    /// The intent of the field at this JSON pointer.
    #[must_use]
    pub fn of_pointer(pointer: &str) -> Self {
        match first_token(pointer).as_deref() {
            Some("apiVersion" | "kind") => Self::Identity,
            Some("metadata") => Self::Metadata,
            Some("spec") => Self::Desired,
            Some("status") => Self::Observed,
            _ => Self::Unclassified,
        }
    }
}

/// A reference from a field of one resource to another object, where a schema *declares* one.
///
/// The type exists so that §33.7's permitted source — "explicit object references discoverable
/// through future schema annotations" — has a shape, and so that the refusal has something to be
/// empty. Kubernetes has no such annotation yet and §68.7 forbids inventing one, so nothing
/// constructs this today. What must never construct it is a scan of string fields whose names
/// resemble kind names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredReference {
    pointer: String,
    target: Gvk,
}

impl DeclaredReference {
    /// The JSON pointer of the field holding the reference.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// What the field refers to.
    #[must_use]
    pub fn target(&self) -> &Gvk {
        &self.target
    }
}

/// One field a schema describes.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    name: String,
    pointer: String,
    field_type: FieldType,
    format: Option<String>,
    description: Option<String>,
    required: bool,
    precision: Precision,
    source: SchemaSource,
    children: BTreeMap<String, Field>,
    element: Option<Box<Field>>,
}

impl Field {
    /// The field's own name, empty for the root of a schema.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where the field sits, as a JSON pointer.
    ///
    /// For the description of a list element or a map value this is a template containing `*`,
    /// because one description covers every entry. Concrete pointers come from a
    /// [`Projection`], which walks an actual object.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// What the field holds.
    #[must_use]
    pub fn field_type(&self) -> FieldType {
        self.field_type
    }

    /// The OpenAPI `format`, such as `int32` or `date-time`.
    #[must_use]
    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    /// What the schema says the field is for.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Whether the enclosing schema lists this field as required.
    #[must_use]
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// How well this field is known (§12.3).
    #[must_use]
    pub fn precision(&self) -> Precision {
        self.precision
    }

    /// Where the description came from.
    #[must_use]
    pub fn source(&self) -> SchemaSource {
        self.source
    }

    /// Whether this field is desired state, observed state or neither.
    #[must_use]
    pub fn intent(&self) -> Intent {
        Intent::of_pointer(&self.pointer)
    }

    /// The named fields directly beneath this one.
    pub fn children(&self) -> impl Iterator<Item = &Self> {
        self.children.values()
    }

    /// One named field directly beneath this one.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Self> {
        self.children.get(name)
    }

    /// What one entry holds, for a list or for a map declared with `additionalProperties`.
    #[must_use]
    pub fn element(&self) -> Option<&Self> {
        self.element.as_deref()
    }
}

/// One resource's fields, as some schema document describes them.
#[derive(Debug, Clone, PartialEq)]
pub struct Schema {
    source: SchemaSource,
    declared_gvk: Option<Gvk>,
    declared_references: Vec<DeclaredReference>,
    root: Field,
}

impl Schema {
    /// Reads an OpenAPI v3 schema object, as the API server publishes it.
    ///
    /// # Errors
    ///
    /// [`SchemaError::Malformed`] when the bytes are not JSON, and [`SchemaError::NotASchema`]
    /// when they are JSON but not a schema object. A document that does not read is an error and
    /// never an empty schema: an unreadable schema and an absent one call for different
    /// behaviour, and collapsing them would hide a broken API server behind a shrug.
    pub fn from_openapi_v3(json: &str) -> Result<Self, SchemaError> {
        let value: Json = serde_json::from_str(json)
            .map_err(|error| SchemaError::Malformed(error.to_string()))?;
        Self::from_value(&value, SchemaSource::OpenApiV3)
    }

    /// The schema of a resource nothing describes (§12.3).
    ///
    /// Every field of such a resource still projects, marked [`Precision::Unknown`] and
    /// [`SchemaSource::Absent`]. This is the degradation Gate B requires, and it is emphatically
    /// not a refusal to project.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            source: SchemaSource::Absent,
            declared_gvk: None,
            declared_references: Vec::new(),
            root: Field {
                name: String::new(),
                pointer: String::new(),
                field_type: FieldType::Object,
                format: None,
                description: None,
                required: false,
                precision: Precision::Unknown,
                source: SchemaSource::Absent,
                children: BTreeMap::new(),
                element: None,
            },
        }
    }

    fn from_value(value: &Json, source: SchemaSource) -> Result<Self, SchemaError> {
        if !value.is_object() {
            return Err(SchemaError::NotASchema(
                "an OpenAPI schema is a JSON object".to_owned(),
            ));
        }
        Ok(Self {
            source,
            declared_gvk: declared_gvk(value),
            declared_references: Vec::new(),
            root: build_field(String::new(), String::new(), value, false, source),
        })
    }

    /// Where this schema came from.
    #[must_use]
    pub fn source(&self) -> SchemaSource {
        self.source
    }

    /// Whether nothing describes this resource.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        self.source == SchemaSource::Absent
    }

    /// The whole resource as one field.
    #[must_use]
    pub fn root(&self) -> &Field {
        &self.root
    }

    /// The top-level fields the schema declares.
    pub fn fields(&self) -> impl Iterator<Item = &Field> {
        self.root.children()
    }

    /// The description of the field at a JSON pointer, where the schema reaches it.
    ///
    /// The same pointer vocabulary [`Object::field`] uses, so a caller asks one question of the
    /// schema and of the object. A numeric or unnamed token descends into a list's item schema or
    /// a map's value schema, because one description covers every entry.
    #[must_use]
    pub fn field(&self, pointer: &str) -> Option<&Field> {
        let mut current = &self.root;
        for token in pointer_tokens(pointer) {
            current = match current.children.get(&token) {
                Some(child) => child,
                None => current.element.as_deref()?,
            };
        }
        Some(current)
    }

    /// The GVK a schema states it describes, from `x-kubernetes-group-version-kind` (§13.2).
    #[must_use]
    pub fn declared_gvk(&self) -> Option<&Gvk> {
        self.declared_gvk.as_ref()
    }

    /// The object references this schema **declares** (§33.7).
    ///
    /// Empty for every schema today, and deliberately so. Kubernetes has no annotation meaning
    /// "this field references that GVK" (§68.7), and the tempting substitute — reading
    /// `spec.nodeName` or `spec.secretRef` as an edge because the name resembles a kind — is the
    /// name-matching guess §33.7 forbids and §63.4 names as an anti-pattern. A relationship the
    /// cluster never stated must not arrive wearing the provider's authority.
    #[must_use]
    pub fn declared_references(&self) -> &[DeclaredReference] {
        &self.declared_references
    }
}

/// One field of an object, with what the schema knows about it and what the object holds.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectedField {
    pointer: String,
    name: String,
    field_type: FieldType,
    format: Option<String>,
    description: Option<String>,
    required: bool,
    precision: Precision,
    source: SchemaSource,
    value: Json,
}

impl ProjectedField {
    /// Where the field sits, as a JSON pointer into the native object.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// The field's own name — a key, or a list index written as a number.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What the field holds: the schema's statement where there is one, otherwise the shape the
    /// value itself has.
    #[must_use]
    pub fn field_type(&self) -> FieldType {
        self.field_type
    }

    /// The OpenAPI `format`, where a schema stated one.
    #[must_use]
    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    /// What the schema says the field is for.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Whether a schema lists this field as required.
    #[must_use]
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// How well this field is known (§12.3).
    #[must_use]
    pub fn precision(&self) -> Precision {
        self.precision
    }

    /// Where the field's description came from, [`SchemaSource::Absent`] when from nowhere.
    #[must_use]
    pub fn source(&self) -> SchemaSource {
        self.source
    }

    /// Whether this field is desired state, observed state or neither (§33.6).
    #[must_use]
    pub fn intent(&self) -> Intent {
        Intent::of_pointer(&self.pointer)
    }

    /// The value the object carries here.
    #[must_use]
    pub fn value(&self) -> &Json {
        &self.value
    }
}

/// One object seen through one schema (§12.2).
///
/// Every field of the object appears, whether or not the schema describes it: a projection is a
/// typed *view* of the native object, never a filter that decides what the cluster is allowed to
/// contain (§12.5, §4 invariant 17).
#[derive(Debug, Clone, PartialEq)]
pub struct Projection {
    source: SchemaSource,
    precision: Precision,
    fields: Vec<ProjectedField>,
    index: BTreeMap<String, usize>,
}

impl Projection {
    /// Projects an object through a schema.
    ///
    /// Works for any kind, including one invented after this provider was built, because the
    /// schema is data the cluster supplied (Gate A).
    #[must_use]
    pub fn of(schema: &Schema, object: &Object) -> Self {
        let mut fields = Vec::new();
        collect(schema, "", object.native(), &mut fields);

        let precision = fields
            .iter()
            .map(ProjectedField::precision)
            .min()
            .unwrap_or(if schema.is_absent() {
                Precision::Unknown
            } else {
                Precision::Structural
            });
        let index = fields
            .iter()
            .enumerate()
            .map(|(position, field)| (field.pointer.clone(), position))
            .collect();

        Self {
            source: schema.source(),
            precision,
            fields,
            index,
        }
    }

    /// Where the typing came from.
    #[must_use]
    pub fn source(&self) -> SchemaSource {
        self.source
    }

    /// The weakest precision any projected field has (§12.3).
    ///
    /// The aggregate, so that a caller can say how well the resource as a whole is known without
    /// implying that its typed fields are untyped.
    #[must_use]
    pub fn precision(&self) -> Precision {
        self.precision
    }

    /// Every field of the object, in pointer order.
    #[must_use]
    pub fn fields(&self) -> &[ProjectedField] {
        &self.fields
    }

    /// One field by JSON pointer.
    #[must_use]
    pub fn field(&self, pointer: &str) -> Option<&ProjectedField> {
        self.fields.get(*self.index.get(pointer)?)
    }

    /// The fields no schema described (§12.5).
    ///
    /// Present, valued and addressable — the point being that "not promoted to a named schema
    /// field" is a statement about the schema and not about the data.
    pub fn unknown_fields(&self) -> impl Iterator<Item = &ProjectedField> {
        self.fields
            .iter()
            .filter(|field| field.precision() == Precision::Unknown)
    }

    /// The fields under `spec`: what someone asked for (§4 invariant 8).
    pub fn desired_fields(&self) -> impl Iterator<Item = &ProjectedField> {
        self.fields
            .iter()
            .filter(|field| field.intent() == Intent::Desired)
    }

    /// The fields under `status`: what a controller reported (§4 invariant 8).
    pub fn observed_fields(&self) -> impl Iterator<Item = &ProjectedField> {
        self.fields
            .iter()
            .filter(|field| field.intent() == Intent::Observed)
    }
}

/// The `scale` subresource a resource declares (§33.5).
///
/// The paths are the resource's own. A CRD may keep its replica count in `spec.size`, and a
/// provider that assumed `spec.replicas` would read the wrong field or none at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleSubresource {
    spec_replicas_path: String,
    status_replicas_path: String,
    label_selector_path: Option<String>,
}

impl ScaleSubresource {
    /// The declared path to the desired replica count, as the CRD writes it.
    #[must_use]
    pub fn spec_replicas_path(&self) -> &str {
        &self.spec_replicas_path
    }

    /// The declared path to the observed replica count, as the CRD writes it.
    #[must_use]
    pub fn status_replicas_path(&self) -> &str {
        &self.status_replicas_path
    }

    /// The declared path to the selector, where the CRD offers one.
    #[must_use]
    pub fn label_selector_path(&self) -> Option<&str> {
        self.label_selector_path.as_deref()
    }

    /// The desired replica count as a JSON pointer usable with [`Object::field`].
    #[must_use]
    pub fn spec_replicas_pointer(&self) -> Option<String> {
        pointer_from_json_path(&self.spec_replicas_path)
    }

    /// The observed replica count as a JSON pointer.
    #[must_use]
    pub fn status_replicas_pointer(&self) -> Option<String> {
        pointer_from_json_path(&self.status_replicas_path)
    }

    /// The selector as a JSON pointer, where the CRD declares one.
    #[must_use]
    pub fn label_selector_pointer(&self) -> Option<String> {
        pointer_from_json_path(self.label_selector_path.as_deref()?)
    }
}

/// The subresources one CRD version declares (§33.5, §33.6).
///
/// Absence is meaningful: a version without `status` has no separate mutation boundary, and a
/// version without `scale` is not scalable however conventional its fields look. Both are
/// discovered, never assumed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subresources {
    status: bool,
    scale: Option<ScaleSubresource>,
}

impl Subresources {
    /// Whether `status` is a separate subresource, and therefore separately writable (§33.6).
    #[must_use]
    pub fn has_status(&self) -> bool {
        self.status
    }

    /// Whether the resource exposes the standard `scale` subresource (§33.5).
    #[must_use]
    pub fn has_scale(&self) -> bool {
        self.scale.is_some()
    }

    /// The declared scale subresource.
    #[must_use]
    pub fn scale(&self) -> Option<&ScaleSubresource> {
        self.scale.as_ref()
    }
}

/// One `additionalPrinterColumns` entry (§33.4).
///
/// A presentation hint and never the canonical schema. A column may point at a field the schema
/// does not declare, and that must not make the field part of the schema — a column says what an
/// operator wants shown, which is a different claim from what the resource is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrinterColumn {
    name: String,
    column_type: String,
    json_path: String,
    description: Option<String>,
    priority: i64,
}

impl PrinterColumn {
    /// The column heading the CRD suggests.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The OpenAPI type word the column declares.
    #[must_use]
    pub fn column_type(&self) -> &str {
        &self.column_type
    }

    /// The JSONPath the CRD writes.
    #[must_use]
    pub fn json_path(&self) -> &str {
        &self.json_path
    }

    /// What the column is for, where the CRD says.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The column's priority; `0` is shown by default and higher values are extra detail.
    #[must_use]
    pub fn priority(&self) -> i64 {
        self.priority
    }

    /// The column's path as a JSON pointer, where it is simple enough to be one.
    ///
    /// `None` for a JSONPath using filters or wildcards. Returning a wrong pointer would be worse
    /// than returning none: a default view missing a column is visibly incomplete, while a column
    /// reading the wrong field is invisibly false.
    #[must_use]
    pub fn pointer(&self) -> Option<String> {
        pointer_from_json_path(&self.json_path)
    }
}

/// One version of a CRD.
#[derive(Debug, Clone, PartialEq)]
pub struct CrdVersion {
    name: String,
    served: bool,
    storage: bool,
    schema: Schema,
    subresources: Subresources,
    printer_columns: Vec<PrinterColumn>,
}

impl CrdVersion {
    /// The version name, such as `v1alpha1`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the API server serves this version.
    #[must_use]
    pub fn is_served(&self) -> bool {
        self.served
    }

    /// Whether objects are persisted at this version (§33.2: a storage-version change matters).
    #[must_use]
    pub fn is_storage(&self) -> bool {
        self.storage
    }

    /// The structural schema this version publishes, [`Schema::absent`] where it publishes none.
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// The subresources this version declares.
    #[must_use]
    pub fn subresources(&self) -> &Subresources {
        &self.subresources
    }

    /// The presentation hints this version offers (§33.4).
    #[must_use]
    pub fn printer_columns(&self) -> &[PrinterColumn] {
        &self.printer_columns
    }
}

/// A `CustomResourceDefinition`, read as the description of a resource this provider never knew.
///
/// Nothing about reading one is special-cased per kind, which is what Gate A asks: install a CRD
/// invented after this build and it is describable, queryable and enterable without a recompile.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomResourceDefinition {
    group: String,
    kind: String,
    plural: String,
    singular: String,
    short_names: Vec<String>,
    scope: Scope,
    versions: Vec<CrdVersion>,
}

impl CustomResourceDefinition {
    /// Reads a CRD as the API server stores it.
    ///
    /// # Errors
    ///
    /// [`SchemaError::Malformed`] when the bytes are not JSON, and [`SchemaError::NotACrd`] when
    /// they are JSON without the `kind`, group, names or versions a CRD carries.
    pub fn parse(json: &str) -> Result<Self, SchemaError> {
        let value: Json = serde_json::from_str(json)
            .map_err(|error| SchemaError::Malformed(error.to_string()))?;
        Self::from_json(&value)
    }

    /// Reads a CRD already decoded.
    ///
    /// # Errors
    ///
    /// [`SchemaError::NotACrd`] when the document is not a `CustomResourceDefinition`.
    pub fn from_json(value: &Json) -> Result<Self, SchemaError> {
        let kind_word = value.get("kind").and_then(Json::as_str);
        if kind_word != Some("CustomResourceDefinition") {
            return Err(SchemaError::NotACrd(format!(
                "its kind is {}",
                kind_word.unwrap_or("absent")
            )));
        }
        let spec = value
            .get("spec")
            .ok_or_else(|| SchemaError::NotACrd("no `spec`".to_owned()))?;
        let names = spec
            .get("names")
            .ok_or_else(|| SchemaError::NotACrd("no `spec.names`".to_owned()))?;
        let group = text(spec, "group")
            .ok_or_else(|| SchemaError::NotACrd("no `spec.group`".to_owned()))?;
        let kind = text(names, "kind")
            .ok_or_else(|| SchemaError::NotACrd("no `spec.names.kind`".to_owned()))?;
        let plural = text(names, "plural")
            .ok_or_else(|| SchemaError::NotACrd("no `spec.names.plural`".to_owned()))?;

        let versions = spec
            .get("versions")
            .and_then(Json::as_array)
            .map(|entries| entries.iter().filter_map(crd_version).collect())
            .unwrap_or_default();

        Ok(Self {
            group,
            singular: text(names, "singular").unwrap_or_else(|| kind.to_lowercase()),
            kind,
            plural,
            short_names: names
                .get("shortNames")
                .and_then(Json::as_array)
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| entry.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            // The CRD states its scope, and a cluster-scoped custom resource must never be given
            // an invented namespace (§9.2). An unrecognised word is treated as cluster scope
            // rather than as a namespace nobody named.
            scope: if text(spec, "scope").as_deref() == Some("Namespaced") {
                Scope::Namespaced
            } else {
                Scope::Cluster
            },
            versions,
        })
    }

    /// The API group the CRD adds.
    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }

    /// The kind objects of this CRD carry.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The plural REST resource name, which the CRD declares and nothing derives (§13.1).
    #[must_use]
    pub fn plural(&self) -> &str {
        &self.plural
    }

    /// The singular name.
    #[must_use]
    pub fn singular(&self) -> &str {
        &self.singular
    }

    /// The short names the CRD offers, which are typing convenience and never identity (§13.5).
    #[must_use]
    pub fn short_names(&self) -> &[String] {
        &self.short_names
    }

    /// Whether objects of this kind live in a namespace.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Every version the CRD declares, served or not.
    #[must_use]
    pub fn versions(&self) -> &[CrdVersion] {
        &self.versions
    }

    /// One version by name.
    #[must_use]
    pub fn version(&self, name: &str) -> Option<&CrdVersion> {
        self.versions.iter().find(|version| version.name() == name)
    }

    /// The versions the API server serves (§13.4: several may be, at once).
    pub fn served_versions(&self) -> impl Iterator<Item = &CrdVersion> {
        self.versions.iter().filter(|version| version.is_served())
    }

    /// The version objects are persisted at, which is one version and not the served set.
    #[must_use]
    pub fn storage_version(&self) -> Option<&CrdVersion> {
        self.versions.iter().find(|version| version.is_storage())
    }

    /// What an object of this CRD at a given version *is* (§13.1).
    #[must_use]
    pub fn gvk(&self, version: &str) -> Gvk {
        Gvk::new(&self.group, version, &self.kind)
    }

    /// Where the collection lives (§13.1). A different question from [`Self::gvk`].
    #[must_use]
    pub fn gvr(&self, version: &str) -> Gvr {
        Gvr::new(&self.group, version, &self.plural)
    }
}

/// Schemas held between requests, and the reasons they stop being true (§12.4).
///
/// Schemas are cached apart from values because they change on a different clock: an object
/// changes constantly, its schema when someone applies a CRD. The interesting part is not the
/// storage but the invalidation, and the fingerprint is part of it — a GVK is unique within one
/// cluster, so a cache keyed by GVK alone lets a second cluster inherit the first one's fields.
#[derive(Debug, Clone, Default)]
pub struct SchemaCache {
    fingerprint: String,
    entries: BTreeMap<Gvk, Schema>,
}

impl SchemaCache {
    /// A cache for one connected cluster, identified by its fingerprint (§10.2).
    #[must_use]
    pub fn new(fingerprint: &str) -> Self {
        Self {
            fingerprint: fingerprint.to_owned(),
            entries: BTreeMap::new(),
        }
    }

    /// The fingerprint of the cluster whose schemas these are.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Remembers a schema, replacing any earlier one for that GVK.
    pub fn insert(&mut self, gvk: Gvk, schema: Schema) {
        self.entries.insert(gvk, schema);
    }

    /// The cached schema, where one is still valid.
    #[must_use]
    pub fn get(&self, gvk: &Gvk) -> Option<&Schema> {
        self.entries.get(gvk)
    }

    /// How many schemas are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forgets one kind's schema, for a CRD whose schema changed (§33.2).
    pub fn invalidate(&mut self, gvk: &Gvk) {
        self.entries.remove(gvk);
    }

    /// Forgets one group/version, for a served version added, removed or changed (§12.4).
    pub fn invalidate_group_version(&mut self, group: &str, version: &str) {
        self.entries
            .retain(|gvk, _| !(gvk.group() == group && gvk.version() == version));
    }

    /// Forgets a whole group, for a CRD deleted or an API group withdrawn (§12.4, §33.2).
    pub fn invalidate_group(&mut self, group: &str) {
        self.entries.retain(|gvk, _| gvk.group() != group);
    }

    /// Records a connection to a cluster, and forgets everything when it is a different one.
    ///
    /// Reconnecting to the same cluster keeps the cache, which is the point of having one.
    /// Reconnecting elsewhere empties it, because `example.io/v1 Widget` in another cluster is
    /// another CRD wearing the same name (§12.4, Gate J).
    pub fn reconnected(&mut self, fingerprint: &str) {
        if self.fingerprint != fingerprint {
            self.entries.clear();
            self.fingerprint = fingerprint.to_owned();
        }
    }

    /// Forgets everything, for a caller that knows the cache is stale for a reason of its own.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// --- reading one schema node -------------------------------------------------------------------

fn build_field(
    name: String,
    pointer: String,
    node: &Json,
    required: bool,
    source: SchemaSource,
) -> Field {
    let Some(map) = node.as_object() else {
        // `items: true` and friends: a schema position that permits anything.
        return Field {
            name,
            pointer,
            field_type: FieldType::Unknown,
            format: None,
            description: None,
            required,
            precision: Precision::Loose,
            source,
            children: BTreeMap::new(),
            element: None,
        };
    };

    let preserves_unknown = map
        .get("x-kubernetes-preserve-unknown-fields")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    let int_or_string = map
        .get("x-kubernetes-int-or-string")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    let field_type = if int_or_string {
        FieldType::Unknown
    } else {
        map.get("type")
            .and_then(Json::as_str)
            .and_then(FieldType::from_word)
            .unwrap_or(FieldType::Unknown)
    };

    // A stated type is a structural description. `x-kubernetes-preserve-unknown-fields` withdraws
    // it for everything below: the schema is saying "anything may be here", and reporting that as
    // structural would claim knowledge the schema explicitly declined to give (§12.3).
    let precision = if preserves_unknown || int_or_string || field_type == FieldType::Unknown {
        Precision::Loose
    } else {
        Precision::Structural
    };

    let required_names: Vec<&str> = map
        .get("required")
        .and_then(Json::as_array)
        .map(|entries| entries.iter().filter_map(Json::as_str).collect())
        .unwrap_or_default();

    let mut children = BTreeMap::new();
    if let Some(properties) = map.get("properties").and_then(Json::as_object) {
        for (child_name, child) in properties {
            let child_pointer = format!("{pointer}/{}", escape_token(child_name));
            children.insert(
                child_name.clone(),
                build_field(
                    child_name.clone(),
                    child_pointer,
                    child,
                    required_names.contains(&child_name.as_str()),
                    source,
                ),
            );
        }
    }

    // A list's `items` and a map's `additionalProperties` are the same idea: one description that
    // covers every entry, reached by an index or a key nobody can enumerate in advance.
    let element = map
        .get("items")
        .or_else(|| map.get("additionalProperties"))
        .filter(|value| !matches!(value, Json::Bool(false)))
        .map(|value| {
            Box::new(build_field(
                String::new(),
                format!("{pointer}/*"),
                value,
                false,
                source,
            ))
        });

    Field {
        name,
        pointer,
        field_type,
        format: map.get("format").and_then(Json::as_str).map(str::to_owned),
        description: map
            .get("description")
            .and_then(Json::as_str)
            .map(str::to_owned),
        required,
        precision,
        source,
        children,
        element,
    }
}

fn declared_gvk(node: &Json) -> Option<Gvk> {
    let entry = node
        .get("x-kubernetes-group-version-kind")
        .and_then(|value| match value {
            Json::Array(entries) => entries.first(),
            other => Some(other),
        })?;
    Some(Gvk::new(
        entry.get("group").and_then(Json::as_str).unwrap_or(""),
        entry.get("version").and_then(Json::as_str)?,
        entry.get("kind").and_then(Json::as_str)?,
    ))
}

fn crd_version(entry: &Json) -> Option<CrdVersion> {
    let name = text(entry, "name")?;
    let schema = entry
        .get("schema")
        .and_then(|schema| schema.get("openAPIV3Schema"))
        .and_then(|node| Schema::from_value(node, SchemaSource::CrdStructural).ok())
        .unwrap_or_else(Schema::absent);

    let subresources = entry.get("subresources");
    let scale = subresources
        .and_then(|node| node.get("scale"))
        .and_then(|scale| {
            Some(ScaleSubresource {
                spec_replicas_path: text(scale, "specReplicasPath")?,
                status_replicas_path: text(scale, "statusReplicasPath")?,
                label_selector_path: text(scale, "labelSelectorPath"),
            })
        });

    Some(CrdVersion {
        name,
        served: entry.get("served").and_then(Json::as_bool).unwrap_or(false),
        storage: entry
            .get("storage")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        schema,
        subresources: Subresources {
            status: subresources.is_some_and(|node| node.get("status").is_some()),
            scale,
        },
        printer_columns: entry
            .get("additionalPrinterColumns")
            .and_then(Json::as_array)
            .map(|columns| columns.iter().filter_map(printer_column).collect())
            .unwrap_or_default(),
    })
}

fn printer_column(entry: &Json) -> Option<PrinterColumn> {
    Some(PrinterColumn {
        name: text(entry, "name")?,
        column_type: text(entry, "type").unwrap_or_default(),
        json_path: text(entry, "jsonPath")?,
        description: text(entry, "description"),
        priority: entry.get("priority").and_then(Json::as_i64).unwrap_or(0),
    })
}

fn text(node: &Json, key: &str) -> Option<String> {
    node.get(key)?.as_str().map(str::to_owned)
}

// --- projecting one object ---------------------------------------------------------------------

fn collect(schema: &Schema, pointer: &str, value: &Json, out: &mut Vec<ProjectedField>) {
    match value {
        Json::Object(map) => {
            for (key, child) in map {
                let child_pointer = format!("{pointer}/{}", escape_token(key));
                push(schema, &child_pointer, key.clone(), child, out);
                collect(schema, &child_pointer, child, out);
            }
        }
        Json::Array(entries) => {
            for (index, child) in entries.iter().enumerate() {
                let child_pointer = format!("{pointer}/{index}");
                push(schema, &child_pointer, index.to_string(), child, out);
                collect(schema, &child_pointer, child, out);
            }
        }
        _ => {}
    }
}

fn push(schema: &Schema, pointer: &str, name: String, value: &Json, out: &mut Vec<ProjectedField>) {
    let described = schema.field(pointer);
    // Where the schema states a type, that statement is the answer. Where it does not, the value's
    // own shape is still observable and still useful — marked `Unknown`, so that "this is a
    // number" is never mistaken for "the resource declares this a number" (§12.3).
    let field_type = match described {
        Some(field) if field.field_type() != FieldType::Unknown => field.field_type(),
        _ => FieldType::of_value(value),
    };
    out.push(ProjectedField {
        pointer: pointer.to_owned(),
        name,
        field_type,
        format: described.and_then(Field::format).map(str::to_owned),
        description: described.and_then(Field::description).map(str::to_owned),
        required: described.is_some_and(Field::is_required),
        precision: described.map_or(Precision::Unknown, Field::precision),
        source: described.map_or(SchemaSource::Absent, Field::source),
        value: value.clone(),
    });
}

// --- pointers ----------------------------------------------------------------------------------

/// The tokens of a JSON pointer, with RFC 6901's escapes undone.
fn pointer_tokens(pointer: &str) -> Vec<String> {
    pointer
        .split('/')
        .skip(1)
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect()
}

fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn first_token(pointer: &str) -> Option<String> {
    pointer_tokens(pointer).into_iter().next()
}

/// A CRD's JSONPath as a JSON pointer, where the expression is simple enough to be one.
///
/// CRDs write `.spec.size` and `.status.conditions[0].type`; that subset maps onto a pointer
/// exactly. Filters, wildcards and recursive descent do not, and this answers `None` for them
/// rather than producing a pointer that reads a different field.
fn pointer_from_json_path(path: &str) -> Option<String> {
    let trimmed = path.strip_prefix('$').unwrap_or(path);
    if trimmed.is_empty()
        || trimmed.contains(['*', '?', '@', '\'', '"', ':'])
        || trimmed.contains("..")
    {
        return None;
    }
    let body = trimmed.strip_prefix('.').unwrap_or(trimmed);
    let mut pointer = String::new();
    for segment in body.split('.') {
        let (name, indices) = match segment.split_once('[') {
            Some((name, rest)) => (name, Some(rest)),
            None => (segment, None),
        };
        if name.is_empty() {
            return None;
        }
        pointer.push('/');
        pointer.push_str(&escape_token(name));
        if let Some(indices) = indices {
            for index in indices.trim_end_matches(']').split("][") {
                if index.is_empty() || !index.chars().all(|character| character.is_ascii_digit()) {
                    return None;
                }
                pointer.push('/');
                pointer.push_str(index);
            }
        }
    }
    Some(pointer)
}

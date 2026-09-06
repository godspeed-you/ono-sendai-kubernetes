//! Secret payload, removed at the boundary rather than filtered at the edge.
//!
//! Specification §22, §29.2, §3.7 and §4 invariant 21. Gate I: the default list, detail and
//! navigation paths cannot reveal Secret payload values.
//!
//! # Why a wrapper and not a `redact()` call
//!
//! [`crate::object::Object`] is deliberately total: `field()` reaches any JSON pointer and
//! `native()` returns the whole document the server sent (§12.5, §4 invariant 17). That is right
//! for every kind except the one whose bytes are the thing being protected. A Secret held as an
//! ordinary object is one `/data/password` away from disclosure, and no amount of care in the
//! rendering layer removes that — redaction that has to be *remembered* fails on the first path
//! nobody reviewed, silently, with no error to notice.
//!
//! So redaction here is structural. [`Guarded::hold`] is the boundary every read path takes its
//! objects from, and it does not filter the payload on the way out: it **destroys** it on the way
//! in. What a [`Secret`] holds is an `Object` whose `data` and `stringData` values were replaced
//! with [`REDACTED`] before the value existed. `native()`, `field()`, `Debug`, serialisation and
//! any future accessor nobody has written yet are all safe for the same reason — there is nothing
//! left to find.
//!
//! # Where the boundary lies
//!
//! It lies at [`Guarded::hold`], and saying so is worth more than pretending it lies nowhere.
//! `Object::parse` is the wire decoder; it is *inside* the boundary and does hold what the API
//! server sent, because something has to. Everything a user, a renderer, a history entry or a
//! relationship walk sees comes from a `Guarded`. `tests/redaction.rs` pins that line so it fails
//! the day someone moves it.
//!
//! # What stays visible
//!
//! Everything §22.2 calls safe: name, namespace, type, **which keys are present**, creation time,
//! owner references. Knowing that a Secret has a `password` key is what tells an operator whether
//! the Pod that mounts it will start, and it is not knowing the password. The relationships of
//! §22.4 stay too ([`secret_references`], as ordinary edges) — a Secret's name is not its
//! contents, and the workload that consumes it is usually the reason anyone looked.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::Value as Json;

use crate::discovery::Gvk;
use crate::object::{Object, ObjectError};
use crate::relationship::{Edge, Evidence, Graph, Relation, Target};

/// What stands where a secret value stood.
///
/// A marker rather than a removed key: §22.2 asks for the keys present, so the pointer
/// `/data/password` must still resolve. It resolves to this.
pub const REDACTED: &str = "<redacted>";

/// The annotation `kubectl apply` writes, which embeds the whole submitted object.
///
/// Redacting `data` and printing this verbatim leaks the same bytes one field to the left, which
/// is why §22.2's "or equivalent secret payload" is not only about the obvious two fields.
const LAST_APPLIED: &str = "kubectl.kubernetes.io/last-applied-configuration";

/// Why an object could not be held as a Secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionError {
    /// The object is not a payload-bearing kind.
    NotASecret {
        /// What it is instead.
        gvk: Gvk,
    },
    /// The redacted document did not read back as an object.
    Unreadable(ObjectError),
}

impl fmt::Display for RedactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotASecret { gvk } => {
                write!(f, "{gvk} is not a Secret, so there is no payload to redact")
            }
            Self::Unreadable(error) => write!(f, "the redacted object did not read back: {error}"),
        }
    }
}

impl std::error::Error for RedactionError {}

/// Whether objects of this kind carry a payload that §22 protects.
///
/// Matched on the kind alone, across every API group. A CRD called `Secret` in some operator's
/// group is very likely holding what its name says, and §33.1 makes CRDs normal resources rather
/// than second-class ones. Over-redaction costs a reader some detail; under-redaction cannot be
/// taken back, and §3.7 forbids making secret data easier to expose merely because Secrets are
/// ordinary API resources.
#[must_use]
pub fn is_payload_protected(gvk: &Gvk) -> bool {
    gvk.kind() == "Secret"
}

/// A Secret, held in the only form this provider has for one: without its payload.
///
/// The value is constructed by removing the payload, so nothing on it — including the accessors
/// inherited from the object it wraps — can return one. See the module documentation for why that
/// is a wrapper rather than a rendering rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Secret {
    object: Object,
    keys: Vec<String>,
}

impl Secret {
    /// Holds a Secret by destroying its payload.
    ///
    /// # Errors
    ///
    /// [`RedactionError::NotASecret`] when the object is some other kind — the wrapper makes a
    /// claim about what it holds, and letting a Pod in would make [`Self::keys`] mean nothing.
    /// [`RedactionError::Unreadable`] when the redacted document does not read back as an object,
    /// which would mean redaction damaged more than the values it replaced.
    pub fn redact(object: &Object) -> Result<Self, RedactionError> {
        if !is_payload_protected(object.gvk()) {
            return Err(RedactionError::NotASecret {
                gvk: object.gvk().clone(),
            });
        }
        let keys = payload_keys(object.native());
        let provider_instance = object.identity().provider_instance().to_owned();
        let redacted = redacted_document(object.native());
        let object =
            Object::from_json(&provider_instance, redacted).map_err(RedactionError::Unreadable)?;
        Ok(Self { object, keys })
    }

    /// The redacted object, safe to hand to any renderer, log line or navigation path.
    #[must_use]
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// `metadata.name` (§22.2).
    #[must_use]
    pub fn name(&self) -> &str {
        self.object.name()
    }

    /// `metadata.namespace` (§22.2).
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.object.namespace()
    }

    /// `metadata.creationTimestamp` (§22.2).
    #[must_use]
    pub fn creation_timestamp(&self) -> Option<&str> {
        self.object.creation_timestamp()
    }

    /// The Secret's `type`, such as `Opaque` or `kubernetes.io/tls` (§22.2).
    ///
    /// Absent where the object carries none, rather than defaulted to `Opaque`: the API server's
    /// defaulting is the API server's business, and inventing it here would report a fact the
    /// object did not state.
    #[must_use]
    pub fn secret_type(&self) -> Option<&str> {
        self.object.field("/type").and_then(Json::as_str)
    }

    /// Which keys the Secret carries, sorted, from `data` and `stringData` together (§22.2).
    ///
    /// The names only. A length or a hash would be a small, steady leak of the payload for a
    /// small, occasional gain in diagnosis, and §22.2 asks for keys.
    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// Whether one key is present.
    #[must_use]
    pub fn has_key(&self, key: &str) -> bool {
        self.keys.iter().any(|held| held == key)
    }

    /// Asks to reveal one key's value, and is refused (§22.3, §3.7).
    ///
    /// There is no success case, by construction: this value holds no payload, so no policy
    /// decision could produce one. A reveal, if the project ever supports it, has to be a fresh
    /// read against the API server under an explicit high-friction operation with audit
    /// semantics — never a getter on a value that a log line might already have seen.
    ///
    /// The capability is modelled as present and off rather than left out, so that the refusal is
    /// inspectable and so that the friction §22.3 requires has somewhere to live.
    #[must_use]
    pub fn request_reveal(&self, key: &str, policy: &RevealPolicy) -> RevealRefusal {
        let _ = key;
        if policy.permits_reveal() {
            RevealRefusal::NoPayloadHeld
        } else {
            RevealRefusal::PolicyForbids
        }
    }
}

impl fmt::Display for Secret {
    /// The safe default view of §22.2, as one line fit for history and scrollback.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let place = match self.namespace() {
            Some(namespace) => format!("{namespace}/{}", self.name()),
            None => self.name().to_owned(),
        };
        write!(f, "Secret {place}")?;
        if let Some(kind) = self.secret_type() {
            write!(f, " type={kind}")?;
        }
        write!(f, " keys=[{}]", self.keys.join(", "))
    }
}

/// Whether the host permits revealing secret payload (§22.3).
///
/// Owned by the host, not by this provider: §8.1 puts the credential and secret boundary on the
/// host side, and a provider that could grant itself a reveal would not be governed by anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealPolicy {
    permitted: bool,
    audit_reason: Option<String>,
}

impl RevealPolicy {
    /// The default: no reveal (§22.3, §3.7).
    #[must_use]
    pub fn host_default() -> Self {
        Self {
            permitted: false,
            audit_reason: None,
        }
    }

    /// A reveal the host granted, against a reason the host will have recorded.
    ///
    /// Constructible so that the refusal can be tested under a permissive policy — a value that
    /// holds no payload refuses either way, which is the property that makes redaction survive a
    /// future policy change.
    #[must_use]
    pub fn host_granted(audit_reason: &str) -> Self {
        Self {
            permitted: true,
            audit_reason: Some(audit_reason.to_owned()),
        }
    }

    /// Whether the host permits a reveal at all.
    #[must_use]
    pub fn permits_reveal(&self) -> bool {
        self.permitted
    }

    /// The reason the host recorded for granting one.
    #[must_use]
    pub fn audit_reason(&self) -> Option<&str> {
        self.audit_reason.as_deref()
    }
}

/// Why a reveal did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealRefusal {
    /// Host policy does not permit revealing secret payload (§22.3).
    PolicyForbids,
    /// The value holds no payload to reveal, whatever the policy says.
    NoPayloadHeld,
}

impl RevealRefusal {
    /// The word this refusal is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyForbids => "host policy forbids revealing secret payload",
            Self::NoPayloadHeld => "no payload is held; a reveal would need an audited API read",
        }
    }
}

impl fmt::Display for RevealRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An object as the provider hands it out: redacted where it needs to be, whole where it does not.
///
/// Every list, detail and navigation path takes its objects from here (Gate I). The uniform
/// accessor [`Self::object`] is safe for both variants, so a caller that does not care which kind
/// it is holding cannot get the unsafe answer by not asking.
#[derive(Debug, Clone, PartialEq)]
pub enum Guarded {
    /// A payload-bearing kind, with the payload gone.
    Secret(Secret),
    /// Everything else, whole (§12.5, §4 invariant 17).
    Plain(Object),
}

impl Guarded {
    /// Takes an object across the boundary.
    ///
    /// # Errors
    ///
    /// [`RedactionError::Unreadable`] when a Secret's redacted document does not read back.
    pub fn hold(object: Object) -> Result<Self, RedactionError> {
        if is_payload_protected(object.gvk()) {
            Ok(Self::Secret(Secret::redact(&object)?))
        } else {
            Ok(Self::Plain(object))
        }
    }

    /// Takes a whole page across the boundary.
    ///
    /// A list path that loops over raw objects while the detail path is careful is the classic
    /// split, so the list gets the same one call rather than its own reasoning.
    ///
    /// # Errors
    ///
    /// The first [`RedactionError`] any object produces.
    pub fn hold_all(objects: Vec<Object>) -> Result<Vec<Self>, RedactionError> {
        objects.into_iter().map(Self::hold).collect()
    }

    /// The object, in the form this provider is willing to show.
    #[must_use]
    pub fn object(&self) -> &Object {
        match self {
            Self::Secret(secret) => secret.object(),
            Self::Plain(object) => object,
        }
    }

    /// The Secret, where this is one.
    #[must_use]
    pub fn secret(&self) -> Option<&Secret> {
        match self {
            Self::Secret(secret) => Some(secret),
            Self::Plain(_) => None,
        }
    }

    /// Whether §22 applies to this object.
    #[must_use]
    pub fn is_payload_protected(&self) -> bool {
        matches!(self, Self::Secret(_))
    }
}

/// Takes a *document* across the same boundary [`Guarded`] takes an object across (§22.3).
///
/// The half of an admission comparison that was submitted is a request body rather than something
/// the cluster sent back, and §22.3 does not care which direction the bytes were travelling in:
/// "Secret bytes MUST NOT flow into ordinary command history, terminal scrollback capture or
/// provider logs by default" has no exception for a payload the operator typed. A mutation record
/// that reported the returned value as `<redacted>` beside the submitted value verbatim would
/// leak it under the sibling rule §42.2 states for logs.
///
/// The door is the same one, which is the point: a document that reads as an object is held by
/// [`Guarded::hold`], so the rule for which kinds are payload-bearing is not written twice. A
/// document that does not read as one — a fragment, a body with no `kind` — is redacted anyway,
/// because over-redaction costs a reader some detail and under-redaction cannot be taken back
/// (§3.7).
#[must_use]
pub fn guarded_document(provider_instance: &str, document: &Json) -> Json {
    match Object::from_json(provider_instance, document.clone()).map(Guarded::hold) {
        Ok(Ok(guarded)) => guarded.object().native().clone(),
        _ => redacted_document(document),
    }
}

/// Every Secret one object refers to, derived without reading any payload (§22.4).
///
/// Ordinary [`Edge`]s in the ordinary vocabulary. A reference to a Secret is a relationship like
/// any other — it is the *payload* that is protected, not the fact that a workload consumes one —
/// and giving these their own shape would leave the edges §22.4 asks for unfollowable.
///
/// The Pod cases come from [`Graph::edges_of`] rather than being restated here, so there is one
/// set of reference rules. Only references a field states: a convention or an inference is not
/// produced here, because §23 keeps those evidence classes apart and a guessed edge to a Secret
/// is a worse guess than most.
#[must_use]
pub fn secret_references(object: &Object) -> Vec<Edge> {
    let mut references: Vec<Edge> = Graph::edges_of(object)
        .into_iter()
        .filter(|edge| edge.relation() == Relation::ReferencesSecret)
        .filter(|edge| edge.evidence().path().is_some())
        .collect();

    if object.gvk().kind() == "ServiceAccount" {
        references.extend(named_entries(object, "/secrets", Relation::UsesSecret));
        references.extend(named_entries(
            object,
            "/imagePullSecrets",
            Relation::UsesImagePullSecret,
        ));
    }

    references
}

/// The `{ name: ... }` entries of one array, as edges to Secrets.
///
/// The namespace is the referring object's, because none of §22.4's references crosses one: a
/// ServiceAccount's Secrets and pull Secrets are namespace-local, and looking one up elsewhere
/// would find a namesake rather than the Secret in question (§24.2, §32.1).
fn named_entries(object: &Object, pointer: &str, relation: Relation) -> Vec<Edge> {
    let Some(entries) = object.field(pointer).and_then(Json::as_array) else {
        return Vec::new();
    };
    let source = object.identity();
    entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let name = entry.get("name")?.as_str()?;
            Some(Edge::new(
                source.clone(),
                relation,
                Target::new("Secret", name)
                    .with_api_version(Some("v1"))
                    .in_namespace(object.namespace()),
                Evidence::NativeField {
                    path: format!("{pointer}/{index}/name"),
                    value: name.to_owned(),
                },
            ))
        })
        .collect()
}

/// The union of the `data` and `stringData` key names, sorted.
fn payload_keys(native: &Json) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for field in ["data", "stringData"] {
        if let Some(map) = native.get(field).and_then(Json::as_object) {
            keys.extend(map.keys().cloned());
        }
    }
    keys.into_iter().collect()
}

/// The document with every payload value replaced, before anything can read the original.
fn redacted_document(native: &Json) -> Json {
    let mut document = native.clone();
    for field in ["data", "stringData"] {
        if let Some(Json::Object(map)) = document.get_mut(field) {
            for value in map.values_mut() {
                *value = Json::String(REDACTED.to_owned());
            }
        }
    }
    if let Some(Json::Object(annotations)) = document.pointer_mut("/metadata/annotations")
        && let Some(applied) = annotations.get_mut(LAST_APPLIED)
    {
        *applied = Json::String(REDACTED.to_owned());
    }
    document
}

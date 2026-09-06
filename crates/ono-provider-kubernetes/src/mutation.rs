//! The request a change becomes, what the server's answer means, and what it still does not prove.
//!
//! Specification §43 (mutation principles), §44 (server-side apply and field ownership), §45
//! (delete, finalizers and garbage collection), §46.3 and §46.4 (verification and its timeouts),
//! §56 (preconditions), Gate G (§62.7) and Gate H (§62.8). [`crate::plan`] holds the prospective
//! half; this module holds the wire half and the evidence that comes back.
//!
//! Nothing here does I/O. A [`Request`] is built and handed to whoever owns the connection, and a
//! [`Response`] that somebody else read is turned into what it actually says. That is what lets
//! the awkward answers — an apply conflict naming another manager, a UID precondition catching a
//! recreated object, a deletion that never finishes — be ordinary tests rather than a cluster
//! somebody has to break on purpose (§59.1).
//!
//! Four rules run through the module.
//!
//! **Observed state is not writable** (§33.6, Gate G). A field change under `/status` is refused
//! here as well as at the boundary, with [`MutationError::ObservedStateNotWritable`]. `status` is
//! a controller's report of what it saw: sent to the object endpoint the API server drops it and
//! still answers `200`, and sent to the subresource it succeeds and a value that means "what a
//! controller observed" comes to say what somebody typed. ADR-0042.
//!
//! **An acceptance is not an outcome** (§4 invariant 18, Gate G). [`MutationOutcome`] can reach
//! [`Stage::ApiAccepted`] and no rung higher, whatever the server returned. Everything above that
//! rung is [`Verification`]'s to establish from a later observation, and it may fail to.
//!
//! **Force is never automatic** (§44.3). A [`Conflict`] carries the manager that owns the field,
//! and its resolution is [`Resolution::ExplicitChoiceRequired`]. The only way to force is
//! [`ApplyOptions::force_conflicts_because`], which takes a reason, because the edit that makes a
//! failing apply succeed is the one that gets made at the end of a long incident.
//!
//! **An inconclusive verification is its own answer** (§46.4). [`Verdict`] has four members, and
//! neither [`Verdict::is_success`] nor [`Verdict::is_failure`] is true of
//! [`Verdict::Inconclusive`]. A timeout means verification is incomplete; it does not mean the
//! change failed, and it does not mean it worked.

use std::fmt;
use std::time::Duration;

use serde_json::{Map as JsonMap, Value as Json};

use crate::condition::{Reconciliation, ReconciliationState, Stage, reconciliation};
use crate::coverage::Outcome;
use crate::discovery::Gvr;
use crate::object::Object;
use crate::plan::{FieldChange, Plan, Propagation, VerificationRule};
use crate::redaction::guarded_document;
use crate::transport::{
    ApiError, ErrorKind, Method, ObservedAt, Operation, Request, Response, Status, object_path,
};

/// Metadata fields the API server rewrites on every write, whatever admission did.
///
/// Excluded from the admission diff of §44.6 because they are the server's bookkeeping rather than
/// an effect of the change: a `resourceVersion` that differs after a write is the write, and
/// reporting it beside a mutating webhook's rewritten image buries the signal in the noise.
const SERVER_OWNED_METADATA: [&str; 5] = [
    "/metadata/resourceVersion",
    "/metadata/uid",
    "/metadata/generation",
    "/metadata/creationTimestamp",
    "/metadata/managedFields",
];

// --- refusals ---------------------------------------------------------------------------------

/// Why a mutation request was not built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationError {
    /// The plan's action is not the one this request shape carries out.
    ActionMismatch {
        /// The action the request builder is for.
        expected: &'static str,
        /// The action the plan holds.
        found: &'static str,
    },
    /// A field manager that identifies nobody (§44.2).
    UnusableFieldManager(String),
    /// A field path this module cannot turn into a document.
    UnusablePath(String),
    /// A change reaches into a list entry without naming the key that entry is merged on (§44.1).
    UnkeyedListEntry(String),
    /// A change writes into `status`, which is a controller's report and not desired state
    /// (§33.6, Gate G).
    ObservedStateNotWritable(String),
}

impl fmt::Display for MutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActionMismatch { expected, found } => write!(
                f,
                "this request carries out a {expected}, and the plan describes a {found}"
            ),
            Self::UnusableFieldManager(given) => write!(
                f,
                "`{given}` does not identify a field manager: server-side apply tracks ownership \
                 by this name, and an empty one makes every apply anonymous (§44.2)"
            ),
            Self::UnusablePath(path) => {
                write!(
                    f,
                    "`{path}` is not a field path this change can be built from"
                )
            }
            Self::ObservedStateNotWritable(path) => write!(
                f,
                "`{path}` writes into `status`, and this provider does not write observed state. \
                 §33.6 asks a provider to preserve desired/observed semantics *and* mutation \
                 boundaries, and `status` is on the far side of that boundary: it is a \
                 controller's report of what it saw, reached through its own subresource where \
                 one is served. Sent to the object endpoint the field is dropped by the API \
                 server and the request still answers 200, which is a change that reports success \
                 for having done nothing; sent to the subresource it succeeds, and a value that \
                 is supposed to say what a controller observed now says what somebody typed \
                 (Gate G, §62.7). Change the desired state instead and let the controller write \
                 what it observes"
            ),
            Self::UnkeyedListEntry(path) => write!(
                f,
                "`{path}` reaches into a list by index without setting that entry's `name`. \
                 Server-side apply merges list entries by key, not by position, so an index \
                 without its key would be merged against whichever entry the server chose (§44.1)"
            ),
        }
    }
}

impl std::error::Error for MutationError {}

// --- what an apply is sent as (§44.1, §44.2, §44.4, §44.5) --------------------------------------

/// The name server-side apply records field ownership under (§44.2).
///
/// A newtype rather than a `&str` parameter, because §44.2 requires the name to be stable and
/// identifiable and a string parameter is where "" ends up on the day somebody is in a hurry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldManager(String);

impl FieldManager {
    /// This provider's manager name.
    ///
    /// One name for all of Ono's applies, so that a cluster administrator reading `managedFields`
    /// can tell Ono's changes from a controller's without knowing which session made them (§44.2).
    #[must_use]
    pub fn ono() -> Self {
        Self("ono-sendai".to_owned())
    }

    /// A manager name a caller chose, for the case where a narrower identity is wanted.
    ///
    /// # Errors
    ///
    /// [`MutationError::UnusableFieldManager`] when the name is empty or only whitespace.
    pub fn named(name: &str) -> Result<Self, MutationError> {
        if name.trim().is_empty() {
            return Err(MutationError::UnusableFieldManager(name.to_owned()));
        }
        Ok(Self(name.trim().to_owned()))
    }

    /// The name as it goes on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FieldManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether the server should run the request without persisting it (§44.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DryRun {
    /// The request is carried out.
    Off,
    /// The server runs admission and defaulting and writes nothing (§44.5).
    Server,
}

impl DryRun {
    /// Whether this is a dry run.
    #[must_use]
    pub fn is_dry_run(self) -> bool {
        matches!(self, Self::Server)
    }
}

/// How an apply is sent (§44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOptions {
    manager: FieldManager,
    dry_run: DryRun,
    force_because: Option<String>,
}

impl ApplyOptions {
    /// An apply under this field manager: not a dry run, and not forcing.
    #[must_use]
    pub fn new(manager: FieldManager) -> Self {
        Self {
            manager,
            dry_run: DryRun::Off,
            force_because: None,
        }
    }

    /// The same apply as a server dry run (§44.5).
    #[must_use]
    pub fn as_dry_run(mut self) -> Self {
        self.dry_run = DryRun::Server;
        self
    }

    /// Takes ownership of conflicting fields, for this stated reason (§44.4).
    ///
    /// The only way to force, and it is deliberately a sentence rather than a flag. §44.3 forbids
    /// forcing merely to make an action succeed, and §44.4 requires forcing to be a separate
    /// explicit high-risk choice — which a `force: bool` parameter is not, because the shortest
    /// path to a green apply becomes flipping it.
    #[must_use]
    pub fn force_conflicts_because(mut self, reason: impl Into<String>) -> Self {
        self.force_because = Some(reason.into());
        self
    }

    /// The field manager (§44.2).
    #[must_use]
    pub fn manager(&self) -> &FieldManager {
        &self.manager
    }

    /// Whether the server is asked to write (§44.5).
    #[must_use]
    pub fn dry_run(&self) -> DryRun {
        self.dry_run
    }

    /// Whether ownership will be taken from a conflicting manager (§44.4).
    #[must_use]
    pub fn forces(&self) -> bool {
        self.force_because.is_some()
    }

    /// Why forcing was chosen, where it was.
    #[must_use]
    pub fn forced_because(&self) -> Option<&str> {
        self.force_because.as_deref()
    }
}

/// How a delete is sent (§45).
///
/// The propagation policy is not here: it is part of the plan, because §45.2 requires prospective
/// output to state it, and a policy that could be changed between the plan and the request would
/// make that statement worthless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeleteOptions {
    dry_run: bool,
}

impl DeleteOptions {
    /// A delete that is carried out.
    #[must_use]
    pub fn new() -> Self {
        Self { dry_run: false }
    }

    /// A delete the server evaluates and does not perform (§44.5).
    #[must_use]
    pub fn as_dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Whether the server is asked to actually delete.
    #[must_use]
    pub fn dry_run(&self) -> DryRun {
        if self.dry_run {
            DryRun::Server
        } else {
            DryRun::Off
        }
    }
}

/// The document an apply sends: identity, preconditions, and the fields the plan changes (§44.1).
///
/// Only the changed fields travel. That is what makes this an apply rather than a replacement: the
/// server merges the document into the object and leaves every field this manager does not claim
/// to whoever owns it. A field the plan *removes* is expressed by its absence here, which is what
/// server-side apply means by removal.
///
/// # Errors
///
/// [`MutationError::ActionMismatch`] for a deletion plan, and
/// [`MutationError::UnkeyedListEntry`] for a change that indexes into a list without naming the
/// entry's merge key.
pub fn apply_document(plan: &Plan) -> Result<Json, MutationError> {
    let changes = expect_apply(plan)?;
    let target = plan.target();
    let mut metadata = JsonMap::new();
    metadata.insert("name".to_owned(), Json::String(target.name().to_owned()));
    if let Some(namespace) = target.namespace() {
        metadata.insert("namespace".to_owned(), Json::String(namespace.to_owned()));
    }
    // §56.1 and §56.3 on the apply path: server-side apply reads its optimistic-concurrency
    // precondition from `metadata.resourceVersion` in the applied document, and refuses a `uid`
    // that does not match the object it would merge into. A plan that holds preconditions and
    // sends none guards nothing.
    if let Some(version) = plan.preconditions().resource_version() {
        metadata.insert(
            "resourceVersion".to_owned(),
            Json::String(version.to_owned()),
        );
    }
    if let Some(uid) = plan.preconditions().uid() {
        metadata.insert("uid".to_owned(), Json::String(uid.to_owned()));
    }

    let mut document = JsonMap::new();
    document.insert("apiVersion".to_owned(), Json::String(api_version(plan)));
    document.insert(
        "kind".to_owned(),
        Json::String(target.gvk().kind().to_owned()),
    );
    document.insert("metadata".to_owned(), Json::Object(metadata));
    let mut document = Json::Object(document);

    for change in changes {
        check_observed_state(change)?;
        check_list_keys(change, changes)?;
        if let Some(value) = change.to() {
            set_at(&mut document, change.path(), value.clone())?;
        }
    }
    Ok(document)
}

/// The request that applies a plan's field changes (§43.2, §44.1).
///
/// `PATCH` with the apply content type rather than `PUT`: a replacement takes ownership of every
/// field it happens to include, which is how an unrelated controller's setting disappears from an
/// object nobody meant to touch (§44.1).
///
/// # Errors
///
/// As [`apply_document`].
pub fn apply_request(
    plan: &Plan,
    gvr: &Gvr,
    options: &ApplyOptions,
) -> Result<Request, MutationError> {
    let document = apply_document(plan)?;
    let target = plan.target();
    let mut request = Request::new(
        Method::Patch,
        object_path(gvr, &target.scope(), target.name()),
    )
    // JSON is a subset of YAML, and this is the media type the API server recognises as
    // server-side apply. Sending `application/merge-patch+json` here would be a different
    // operation with no field ownership at all.
    .header("Content-Type", "application/apply-patch+yaml")
    .query("fieldManager", options.manager().as_str())
    .body(document.to_string().into_bytes());
    if options.dry_run().is_dry_run() {
        request = request.query("dryRun", "All");
    }
    if options.forces() {
        request = request.query("force", "true");
    }
    Ok(request)
}

/// The request that deletes a plan's target, with its policy and preconditions (§45.2, §56.3).
///
/// # Errors
///
/// [`MutationError::ActionMismatch`] for an apply plan.
pub fn delete_request(
    plan: &Plan,
    gvr: &Gvr,
    options: &DeleteOptions,
) -> Result<Request, MutationError> {
    let Some(propagation) = plan.propagation() else {
        return Err(MutationError::ActionMismatch {
            expected: "delete",
            found: plan.action().verb(),
        });
    };
    let target = plan.target();
    let mut body = JsonMap::new();
    body.insert("apiVersion".to_owned(), Json::String("v1".to_owned()));
    body.insert("kind".to_owned(), Json::String("DeleteOptions".to_owned()));
    body.insert(
        "propagationPolicy".to_owned(),
        Json::String(propagation.as_str().to_owned()),
    );
    let mut preconditions = JsonMap::new();
    if let Some(uid) = plan.preconditions().uid() {
        preconditions.insert("uid".to_owned(), Json::String(uid.to_owned()));
    }
    if let Some(version) = plan.preconditions().resource_version() {
        preconditions.insert(
            "resourceVersion".to_owned(),
            Json::String(version.to_owned()),
        );
    }
    if !preconditions.is_empty() {
        body.insert("preconditions".to_owned(), Json::Object(preconditions));
    }
    if options.dry_run().is_dry_run() {
        body.insert(
            "dryRun".to_owned(),
            Json::Array(vec![Json::String("All".to_owned())]),
        );
    }
    Ok(Request::new(
        Method::Delete,
        object_path(gvr, &target.scope(), target.name()),
    )
    .header("Content-Type", "application/json")
    .body(Json::Object(body).to_string().into_bytes()))
}

fn expect_apply(plan: &Plan) -> Result<&[FieldChange], MutationError> {
    if plan.action().is_destructive() {
        return Err(MutationError::ActionMismatch {
            expected: "apply",
            found: plan.action().verb(),
        });
    }
    Ok(plan.field_changes())
}

fn api_version(plan: &Plan) -> String {
    let gvk = plan.target().gvk();
    if gvk.group().is_empty() {
        gvk.version().to_owned()
    } else {
        format!("{}/{}", gvk.group(), gvk.version())
    }
}

/// Refuses a change that writes into `status` (§33.6, Gate G).
///
/// The `status` *tree* and nothing wider: `/spec/statusPage` and a CRD field called `statusCheck`
/// are ordinary desired state, and refusing them would be this provider inventing a restriction
/// the API server does not have. The boundary is `/status` itself and anything under it.
fn check_observed_state(change: &FieldChange) -> Result<(), MutationError> {
    if change.path() == "/status" || change.path().starts_with("/status/") {
        return Err(MutationError::ObservedStateNotWritable(
            change.path().to_owned(),
        ));
    }
    Ok(())
}

/// Refuses a list index whose entry does not also carry the key it is merged on (§44.1).
///
/// Server-side apply merges list entries by key rather than by position. `containers/0/image`
/// alone describes "the first container" to this provider and "some container" to the server, and
/// the two need not be the same one. Rather than guess a key, this refuses and says which change
/// is missing it — `name` being the key of every list Ono's bounded actions touch.
fn check_list_keys(change: &FieldChange, all: &[FieldChange]) -> Result<(), MutationError> {
    let segments: Vec<&str> = change.path().split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        if !segment.chars().all(|character| character.is_ascii_digit()) || segment.is_empty() {
            continue;
        }
        let prefix = segments[..=index].join("/");
        let key = format!("{prefix}/name");
        if !all.iter().any(|other| other.path() == key) {
            return Err(MutationError::UnkeyedListEntry(change.path().to_owned()));
        }
    }
    Ok(())
}

/// Writes a value at a JSON pointer, creating the objects and arrays on the way.
fn set_at(document: &mut Json, path: &str, value: Json) -> Result<(), MutationError> {
    let segments: Vec<String> = path.split('/').skip(1).map(unescape).collect();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(MutationError::UnusablePath(path.to_owned()));
    }
    let mut current = document;
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        let next_is_index = !last
            && segments[index + 1]
                .chars()
                .all(|character| character.is_ascii_digit());
        current = match segment.parse::<usize>() {
            Ok(position) => {
                let array = as_array(current, path)?;
                while array.len() <= position {
                    array.push(Json::Null);
                }
                let slot = array
                    .get_mut(position)
                    .ok_or_else(|| MutationError::UnusablePath(path.to_owned()))?;
                if last {
                    *slot = value;
                    return Ok(());
                }
                fill(slot, next_is_index);
                slot
            }
            Err(_) => {
                let object = as_object(current, path)?;
                if last {
                    object.insert(segment.clone(), value);
                    return Ok(());
                }
                let slot = object.entry(segment.clone()).or_insert(Json::Null);
                fill(slot, next_is_index);
                slot
            }
        };
    }
    Ok(())
}

/// One JSON pointer segment as the key it spells (RFC 6901).
///
/// `~1` is a `/` and `~0` is a `~`, and the order matters: unescaping `~0` first would turn `~01`
/// into `~1` and then into `/`. A label key is the reason this is not academic — the convention
/// §23.4 names is `app.kubernetes.io/name`, and a segment left escaped would create a field beside
/// the labels rather than setting one.
fn unescape(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn fill(slot: &mut Json, wants_array: bool) {
    let suits = if wants_array {
        slot.is_array()
    } else {
        slot.is_object()
    };
    if !suits {
        *slot = if wants_array {
            Json::Array(Vec::new())
        } else {
            Json::Object(JsonMap::new())
        };
    }
}

fn as_array<'a>(value: &'a mut Json, path: &str) -> Result<&'a mut Vec<Json>, MutationError> {
    value
        .as_array_mut()
        .ok_or_else(|| MutationError::UnusablePath(path.to_owned()))
}

fn as_object<'a>(
    value: &'a mut Json,
    path: &str,
) -> Result<&'a mut JsonMap<String, Json>, MutationError> {
    value
        .as_object_mut()
        .ok_or_else(|| MutationError::UnusablePath(path.to_owned()))
}

// --- conflicts (§44.3) ---------------------------------------------------------------------------

/// One field an apply could not take, and who holds it (§44.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldConflict {
    field: String,
    manager: Option<String>,
    message: Option<String>,
}

impl FieldConflict {
    /// The field path the server named, in its own notation.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The manager that owns it, where the server named one.
    ///
    /// `Option` because the ownership evidence is carried in a prose message the API server is not
    /// obliged to phrase any particular way. A conflict whose owner could not be read is still a
    /// conflict, and inventing a manager name would be worse than saying so.
    #[must_use]
    pub fn manager(&self) -> Option<&str> {
        self.manager.as_deref()
    }

    /// What the server said about this one field.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for FieldConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.manager {
            Some(manager) => write!(f, "{} is owned by {manager}", self.field),
            None => write!(f, "{} is owned by another manager", self.field),
        }
    }
}

/// What a conflict may be resolved by.
///
/// There is no `Force` member and no `Retry` member. §44.3 forbids forcing to make an action
/// succeed, and a resolution enum that offered it would put the forbidden answer in the same list
/// as the permitted ones, one match arm away from being taken automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// A person decides between yielding the field and taking ownership of it (§44.4).
    ExplicitChoiceRequired,
}

impl fmt::Display for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "an explicit choice is required: leave the field to its owner, or take ownership with \
             a stated reason (§44.4)",
        )
    }
}

/// An apply that another manager's ownership refused (§44.3, §60.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    fields: Vec<FieldConflict>,
    status: Status,
}

impl Conflict {
    /// The fields that could not be taken, with their owners.
    #[must_use]
    pub fn fields(&self) -> &[FieldConflict] {
        &self.fields
    }

    /// The distinct managers the server named, in the order they appear.
    #[must_use]
    pub fn managers(&self) -> Vec<&str> {
        let mut managers: Vec<&str> = Vec::new();
        for conflict in &self.fields {
            if let Some(manager) = conflict.manager()
                && !managers.contains(&manager)
            {
                managers.push(manager);
            }
        }
        managers
    }

    /// What the server said, kept whole (§48.1).
    #[must_use]
    pub fn status(&self) -> &Status {
        &self.status
    }

    /// Whether this provider may resolve the conflict on its own.
    ///
    /// Always false, and it is a method rather than a doc sentence so that a caller asking the
    /// question gets the answer in code (§44.3).
    #[must_use]
    pub fn is_automatically_resolvable(&self) -> bool {
        false
    }

    /// What resolving it requires (§44.4).
    #[must_use]
    pub fn resolution(&self) -> Resolution {
        Resolution::ExplicitChoiceRequired
    }

    /// The conflict with its ownership evidence, in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        let owned: Vec<String> = self.fields.iter().map(ToString::to_string).collect();
        format!(
            "apply conflict: {}. {}",
            owned.join("; "),
            self.resolution()
        )
    }

    /// Reads the field-ownership causes out of a `Status`, or `None` when there are none.
    fn parse(status: &Status) -> Option<Self> {
        let fields: Vec<FieldConflict> = status
            .causes()
            .iter()
            .filter(|cause| cause.reason() == Some("FieldManagerConflict"))
            .map(|cause| FieldConflict {
                field: cause.field().unwrap_or_default().to_owned(),
                manager: cause.message().and_then(quoted),
                message: cause.message().map(str::to_owned),
            })
            .collect();
        (!fields.is_empty()).then_some(Self {
            fields,
            status: status.clone(),
        })
    }
}

/// The first double-quoted word of a message, which is where the API server puts the manager name.
fn quoted(message: &str) -> Option<String> {
    let (_, rest) = message.split_once('"')?;
    let (name, _) = rest.split_once('"')?;
    (!name.is_empty()).then(|| name.to_owned())
}

// --- preconditions that did not hold (§56) --------------------------------------------------------

/// Which precondition the server refused on (§56.1, §56.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionKind {
    /// The object moved on since the plan was built: a lost update prevented (§56.1).
    ResourceVersion,
    /// The name holds a different object lifetime than the plan targeted (§56.3, §16.3).
    Uid,
}

/// A refusal that a precondition caused, rather than a conflict over field ownership (§56).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreconditionFailure {
    kind: PreconditionKind,
    status: Status,
}

impl PreconditionFailure {
    /// Which precondition held the mutation back.
    #[must_use]
    pub fn kind(&self) -> PreconditionKind {
        self.kind
    }

    /// What the server said, kept whole.
    #[must_use]
    pub fn status(&self) -> &Status {
        &self.status
    }

    /// The refusal, and what it means for what happens next.
    #[must_use]
    pub fn describe(&self) -> String {
        let told = self
            .status
            .message()
            .unwrap_or("the server gave no message");
        match self.kind {
            PreconditionKind::ResourceVersion => format!(
                "the target changed since the plan was built, so the change was not applied: \
                 {told}. Re-plan against the current object rather than repeating this request \
                 (§56.2)"
            ),
            PreconditionKind::Uid => format!(
                "the name now holds a different object lifetime, so the mutation was refused: \
                 {told}. Without this precondition the change would have been made to an object \
                 the plan never targeted (§56.3, §16.3)"
            ),
        }
    }

    /// Classifies a `409` that carries no field-ownership causes.
    ///
    /// The API server offers no structured discriminator between "somebody wrote first" and "your
    /// UID precondition failed": both are `reason: Conflict`, and the difference is in the prose.
    /// So the structured causes are read first, the message second, and a `409` that matches
    /// neither phrase is *not* called a precondition failure — an unrecognised refusal reported as
    /// a recognised one is worse than one reported as unknown.
    fn parse(status: &Status) -> Option<Self> {
        let message = status.message()?;
        let kind = if message.contains("UID in precondition") {
            PreconditionKind::Uid
        } else if message.contains("the object has been modified") {
            PreconditionKind::ResourceVersion
        } else {
            return None;
        };
        Some(Self {
            kind,
            status: status.clone(),
        })
    }
}

// --- what the answer amounts to (§43, Gate G) -----------------------------------------------------

/// What the server's answer to a mutation says (§43.2, §44.3, §56).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acceptance {
    /// The server accepted the change and wrote it. Nothing more (§4 invariant 18).
    Persisted,
    /// A dry run passed: admission and defaulting ran, nothing was written (§44.5).
    DryRun,
    /// Another field manager owns a field this apply set (§44.3).
    Conflict(Conflict),
    /// A precondition did not hold (§56).
    PreconditionFailed(PreconditionFailure),
    /// The server refused for another reason, classified in §48.2's vocabulary.
    Refused(ErrorKind),
}

/// A mutation's answer, and the one rung of §20.4's ladder it establishes.
#[derive(Debug, Clone, PartialEq)]
pub struct MutationOutcome {
    acceptance: Acceptance,
    code: u16,
    returned: Option<Object>,
    status: Option<Status>,
}

impl MutationOutcome {
    /// Reads what the response says about the mutation.
    ///
    /// `dry_run` is what was *asked for*, not something read back: a `200` on a dry run and a `200`
    /// on a write are the same bytes, and the difference — whether anything was persisted — is
    /// known only to the caller that built the request.
    #[must_use]
    pub fn read(plan: &Plan, dry_run: DryRun, response: &Response) -> Self {
        let code = response.status();
        let status = Status::parse(response.body());
        let returned = returned_object(plan, response.body());
        let acceptance = if (200..300).contains(&code) {
            if dry_run.is_dry_run() {
                Acceptance::DryRun
            } else {
                Acceptance::Persisted
            }
        } else {
            refusal(code, response.reason(), status.as_ref())
        };
        Self {
            acceptance,
            code,
            returned,
            status,
        }
    }

    /// What the answer amounts to.
    #[must_use]
    pub fn acceptance(&self) -> &Acceptance {
        &self.acceptance
    }

    /// The HTTP status code behind it.
    #[must_use]
    pub fn code(&self) -> u16 {
        self.code
    }

    /// The object the server returned, where it returned one rather than a `Status`.
    #[must_use]
    pub fn returned(&self) -> Option<&Object> {
        self.returned.as_ref()
    }

    /// What the server said about a refusal (§48.1).
    #[must_use]
    pub fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    /// Whether the change was written.
    #[must_use]
    pub fn is_persisted(&self) -> bool {
        matches!(self.acceptance, Acceptance::Persisted)
    }

    /// The conflict, where field ownership refused the apply (§44.3).
    #[must_use]
    pub fn conflict(&self) -> Option<&Conflict> {
        match &self.acceptance {
            Acceptance::Conflict(conflict) => Some(conflict),
            _ => None,
        }
    }

    /// The precondition failure, where one held the mutation back (§56).
    #[must_use]
    pub fn precondition_failure(&self) -> Option<&PreconditionFailure> {
        match &self.acceptance {
            Acceptance::PreconditionFailed(failure) => Some(failure),
            _ => None,
        }
    }

    /// The furthest rung of §20.4's ladder this answer establishes (Gate G).
    ///
    /// [`Stage::ApiAccepted`] at most, and only for a write. A dry run establishes no rung at all:
    /// nothing was persisted, so not even the first claim holds. Everything above that rung is
    /// [`Verification`]'s to establish from a later observation.
    #[must_use]
    pub fn established_stage(&self) -> Option<Stage> {
        self.is_persisted().then_some(Stage::ApiAccepted)
    }

    /// Whether an outcome exists that verification could still establish (§46.3).
    #[must_use]
    pub fn requires_verification(&self) -> bool {
        self.is_persisted()
    }

    /// What admission and defaulting did to the document on the way in (§44.6).
    ///
    /// Compares the fields the request set against what came back. The server's own bookkeeping is
    /// excluded, so what remains is what admission changed: a mutating webhook rewriting an image
    /// registry, a default injected into a field the caller left alone.
    #[must_use]
    pub fn admission_differences(&self, requested: &Json) -> Vec<FieldChange> {
        self.returned
            .as_ref()
            .map(|returned| admission_differences_of(requested, returned))
            .unwrap_or_default()
    }

    /// The answer, and the sentence that stops it being read as an outcome.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.acceptance {
            Acceptance::Persisted => {
                "the API server accepted and wrote the change. That is what a \
                 mutation response is: acceptance is not evidence that the intended outcome \
                 occurred (§4 invariant 18, Gate G)"
                    .to_owned()
            }
            Acceptance::DryRun => "the server accepted the change as a dry run: admission and \
                 defaulting ran and nothing was written. A successful dry run is not a proof of \
                 post-apply convergence (§44.5)"
                .to_owned(),
            Acceptance::Conflict(conflict) => conflict.describe(),
            Acceptance::PreconditionFailed(failure) => failure.describe(),
            Acceptance::Refused(kind) => {
                let told = self
                    .status
                    .as_ref()
                    .and_then(Status::message)
                    .unwrap_or("the server gave no message");
                format!("the change was refused ({}): {told}", kind.as_str())
            }
        }
    }
}

/// The same comparison as [`MutationOutcome::admission_differences`], against an object the
/// caller supplies (§44.6).
///
/// It exists for one caller: a boundary that may not hold a Secret's payload. §22 requires the
/// payload to be destroyed on the way in rather than filtered on the way out, so a caller that
/// has taken the returned object through `redaction::Guarded` passes the guarded object here and
/// gets the same answer for every field that is not one. Comparing against
/// [`MutationOutcome::returned`] instead would report an admission-rewritten payload value
/// verbatim, which is the one way a mutation could disclose what a read may not (Gate I).
#[must_use]
pub fn admission_differences_of(requested: &Json, returned: &Object) -> Vec<FieldChange> {
    // Both halves go through the same door. The returned half is guarded by the caller — that is
    // what this function exists for — and the submitted half is guarded here, because §22.3's
    // rule is about the bytes rather than about which way they were travelling: an applied
    // Secret's payload in a mutation record is that payload in command history (§42.2).
    let requested = guarded_document(returned.identity().provider_instance(), requested);
    let mut differences = Vec::new();
    let mut paths = Vec::new();
    leaves(&requested, String::new(), &mut paths);
    for (path, sent) in paths {
        if SERVER_OWNED_METADATA.contains(&path.as_str()) {
            continue;
        }
        match returned.field(&path) {
            Some(got) if got == &sent => {}
            Some(got) => differences.push(FieldChange::change(path, sent, got.clone())),
            None => differences.push(FieldChange::remove(path, sent)),
        }
    }
    differences
}

/// The object a response body carries, where it carries one.
///
/// A `Status` document parses as a Kubernetes object — it has an `apiVersion` and a `kind` — and
/// treating one as the mutated object would report `kind: Status` as the thing that was changed.
fn returned_object(plan: &Plan, body: &[u8]) -> Option<Object> {
    let text = std::str::from_utf8(body).ok()?;
    let object = Object::parse(plan.target().provider_instance(), text).ok()?;
    (object.gvk().kind() != "Status").then_some(object)
}

/// Classifies a refusal: ownership first, preconditions second, the taxonomy last.
fn refusal(code: u16, reason: &str, status: Option<&Status>) -> Acceptance {
    let status = status
        .cloned()
        .unwrap_or_else(|| Status::from_http(code, reason));
    if code == 409 {
        if let Some(conflict) = Conflict::parse(&status) {
            return Acceptance::Conflict(conflict);
        }
        if let Some(failure) = PreconditionFailure::parse(&status) {
            return Acceptance::PreconditionFailed(failure);
        }
    }
    // The taxonomy is `transport`'s, reached through the error type it classifies, so that a
    // refused mutation and a refused read are described in the same seventeen words (§48.2).
    // `Operation::Get` is the right reading of a `404` here: a mutation addresses one object by
    // name, so "it is not there" is about the object rather than about the API being served.
    let boxed = Box::new(status);
    let error = match code {
        403 => ApiError::Denied(boxed),
        404 => ApiError::NotFound(boxed),
        410 => ApiError::ContinuityExpired(boxed),
        429 => ApiError::RateLimited {
            status: boxed,
            retry_after: None,
        },
        other => ApiError::Failed {
            code: other,
            status: boxed,
        },
    };
    Acceptance::Refused(error.kind(Operation::Get))
}

/// Every scalar in a document, by JSON pointer.
fn leaves(value: &Json, prefix: String, into: &mut Vec<(String, Json)>) {
    match value {
        Json::Object(fields) => {
            for (key, child) in fields {
                leaves(child, format!("{prefix}/{key}"), into);
            }
        }
        Json::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                leaves(child, format!("{prefix}/{index}"), into);
            }
        }
        scalar => into.push((prefix, scalar.clone())),
    }
}

// --- deletion (§45, Gate H) -----------------------------------------------------------------------

/// Where a deletion stands, in the words §45.1 requires to stay apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionState {
    /// The server accepted the request and said nothing about the object's state.
    Accepted,
    /// A `deletionTimestamp` is set. The object is still there (Gate H).
    Terminating {
        /// The finalizers that must be removed before the object can go (§45.3).
        finalizers: Vec<String>,
        /// When deletion was requested, as the object records it.
        since: Option<String>,
    },
    /// A later read found the object gone.
    Absent,
}

impl DeletionState {
    /// The state in the words it is reported under.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "deletion accepted; the object's state is not known",
            Self::Terminating { .. } => "terminating; deletion is pending",
            Self::Absent => "the object is absent from the API",
        }
    }
}

/// A deletion in progress: what was accepted, what is still there, and what nobody can see.
///
/// The type exists because §45.1 lists six distinctions that a boolean collapses, and Gate H turns
/// on the one in the middle: an accepted delete with a finalizer on the object is *terminating*.
/// There is deliberately no method called `is_deleted` — [`Self::is_object_absent`] answers what
/// this provider can actually observe, which is the object being gone from the API, and says
/// nothing about the volume, the load balancer or the cloud resource behind it (§45.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deletion {
    propagation: Propagation,
    dry_run: bool,
    state: DeletionState,
    notes: Vec<String>,
}

impl Deletion {
    /// Reads what an accepted delete response says about the object (§45.1).
    ///
    /// # Errors
    ///
    /// The [`MutationOutcome`] of a refusal, which is the interesting case for §56.3: a UID
    /// precondition that caught a recreated object is a delete that correctly did not happen. It
    /// is boxed because a refusal carrying the object the server returned is larger than the
    /// deletion state, and the successful path should not pay for it.
    pub fn read(
        plan: &Plan,
        options: &DeleteOptions,
        response: &Response,
    ) -> Result<Self, Box<MutationOutcome>> {
        let outcome = MutationOutcome::read(plan, options.dry_run(), response);
        let dry_run = matches!(outcome.acceptance(), Acceptance::DryRun);
        if !outcome.is_persisted() && !dry_run {
            return Err(Box::new(outcome));
        }
        let state = match outcome.returned() {
            Some(object) if object.is_terminating() => DeletionState::Terminating {
                finalizers: object.finalizers().to_vec(),
                since: object.deletion_timestamp().map(str::to_owned),
            },
            // The server returned the object without a `deletionTimestamp`, or returned a
            // `Status: Success` instead. Either way the request was accepted and what became of
            // the object has not been observed.
            _ => DeletionState::Accepted,
        };
        Ok(Self {
            propagation: plan.propagation().unwrap_or(Propagation::Background),
            dry_run,
            state,
            notes: Vec::new(),
        })
    }

    /// Where the deletion stands.
    #[must_use]
    pub fn state(&self) -> &DeletionState {
        &self.state
    }

    /// The propagation policy the delete was sent with (§45.2).
    #[must_use]
    pub fn propagation(&self) -> Propagation {
        self.propagation
    }

    /// The finalizers still holding the object, where it is terminating (§45.3).
    #[must_use]
    pub fn pending_finalizers(&self) -> Vec<String> {
        match &self.state {
            DeletionState::Terminating { finalizers, .. } => finalizers.clone(),
            _ => Vec::new(),
        }
    }

    /// Whether the object is gone from the API server.
    ///
    /// True only after a read proved it. It is not a claim about anything outside the API: storage
    /// reclaim, cloud resources and external side effects are unobserved either way (§45.5).
    #[must_use]
    pub fn is_object_absent(&self) -> bool {
        matches!(self.state, DeletionState::Absent)
    }

    /// Folds in a later read that returned the object.
    pub fn observe(&mut self, object: &Object) {
        if object.is_terminating() {
            self.state = DeletionState::Terminating {
                finalizers: object.finalizers().to_vec(),
                since: object.deletion_timestamp().map(str::to_owned),
            };
        }
    }

    /// Folds in a later read that returned no object, for the reason the coverage names.
    ///
    /// Only [`Outcome::Absent`] advances the state. §4 invariant 13 in the place it costs the most:
    /// a `403` on the follow-up read is a permission boundary, and reading it as "the object is
    /// gone" turns a deletion nobody can see into a deletion that finished.
    pub fn observe_absence(&mut self, outcome: Outcome) {
        if outcome.is_evidence_of_absence() {
            self.state = DeletionState::Absent;
        } else {
            self.notes.push(format!(
                "a later read did not establish absence: {}",
                outcome.as_str()
            ));
        }
    }

    /// Where the deletion stands, with everything §45.1 keeps apart.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut line = if self.dry_run {
            format!(
                "a dry-run delete was accepted and nothing was removed (propagation {})",
                self.propagation
            )
        } else {
            format!("{} (propagation {})", self.state.as_str(), self.propagation)
        };
        if let DeletionState::Terminating { finalizers, since } = &self.state
            && !finalizers.is_empty()
        {
            line.push_str(&format!(
                "; completion depends on these finalizers being removed: {}",
                finalizers.join(", ")
            ));
            if let Some(since) = since {
                line.push_str(&format!(" (requested at {since})"));
            }
        }
        for note in &self.notes {
            line.push_str(&format!("; {note}"));
        }
        line.push_str("; external effects outside the API server are unknown either way (§45.5)");
        line
    }
}

// --- verification (§46.3, §46.4) ---------------------------------------------------------------

/// How long verification may wait before it reports that it did not finish (§46.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    started: ObservedAt,
    timeout: Duration,
}

impl Deadline {
    /// A deadline of `timeout` from this instant.
    ///
    /// The start is passed in rather than read from a clock, because a verification that cannot be
    /// given a fixed time cannot be tested at its own boundary — and the boundary is the whole
    /// point of §46.4.
    #[must_use]
    pub fn starting_at(started: ObservedAt, timeout: Duration) -> Self {
        Self { started, timeout }
    }

    /// When waiting began.
    #[must_use]
    pub fn started(&self) -> ObservedAt {
        self.started
    }

    /// How long verification may wait.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Whether the deadline has passed at this instant.
    #[must_use]
    pub fn has_expired(&self, now: ObservedAt) -> bool {
        let elapsed = now.unix_millis().saturating_sub(self.started.unix_millis());
        u128::from(elapsed) >= self.timeout.as_millis()
    }
}

/// What a later look at the target found (§46.3).
///
/// Three members, because "no object" is two different facts: the object is not there, or nobody
/// could look. §21.4 keeps those apart everywhere else in this provider, and verification is the
/// place where merging them would turn a `403` into a completed change.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Observation<'a> {
    /// The object as a later read returned it.
    Object(&'a Object),
    /// A read established that the object is gone.
    Absent,
    /// Nobody could look, for this reason (§21.4).
    Unobservable(Outcome),
}

/// What verification concluded (§46.3, §46.4).
///
/// Four members. The fourth is the one the specification insists on: §46.4 says a timeout means
/// verification is incomplete and does *not* mean the change failed. So an inconclusive
/// verification answers no to both questions a renderer can ask of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Evidence establishes the intended outcome, by the rule the verification names.
    Confirmed,
    /// Evidence establishes that it did not happen, by the rule the verification names.
    Refuted,
    /// The deadline has not passed and the evidence is not decisive yet.
    Pending,
    /// The evidence never became decisive, or could not be gathered at all (§46.4).
    Inconclusive,
}

impl Verdict {
    /// The verdict in the words it is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Refuted => "refuted",
            Self::Pending => "pending",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Whether the intended outcome was established. True for [`Self::Confirmed`] alone.
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::Confirmed)
    }

    /// Whether failure was established. True for [`Self::Refuted`] alone.
    ///
    /// Deliberately false for [`Self::Inconclusive`]: §46.4 says a timeout is not a failure unless
    /// provider-specific evidence proves one, and this is where that sentence is enforced.
    #[must_use]
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Refuted)
    }

    /// Whether the question has been answered either way.
    #[must_use]
    pub fn is_decided(self) -> bool {
        matches!(self, Self::Confirmed | Self::Refuted)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a later observation establishes about a change that was accepted (§46.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    verdict: Verdict,
    rule: VerificationRule,
    reached: Option<Stage>,
    detail: String,
    reconciliation: Option<Reconciliation>,
}

impl Verification {
    /// What this observation establishes about the plan's outcome.
    ///
    /// The rule comes from the plan, because §46.3 requires verification to match the action's
    /// semantics and because choosing the rule afterwards is choosing the rule that passes. The
    /// clock is a parameter for the same reason [`Deadline`] takes one.
    #[must_use]
    pub fn of(
        plan: &Plan,
        observation: Observation<'_>,
        deadline: &Deadline,
        now: ObservedAt,
    ) -> Self {
        let rule = plan.verification_rule();
        if rule == VerificationRule::NoneKnown {
            return Self::inconclusive(rule, VerificationRule::NoneKnown.as_str().to_owned());
        }
        match observation {
            Observation::Unobservable(outcome) => Self::inconclusive(
                rule,
                format!(
                    "the target could not be read, so no evidence was gathered: {}",
                    outcome.as_str()
                ),
            ),
            Observation::Absent => {
                if rule == VerificationRule::Absence {
                    Self {
                        verdict: Verdict::Confirmed,
                        rule,
                        reached: None,
                        detail: "a read established that the object is gone from the API; effects \
                                 outside it are unobserved (§45.5)"
                            .to_owned(),
                        reconciliation: None,
                    }
                } else {
                    Self::inconclusive(
                        rule,
                        "the target is gone, so the change cannot be observed on it".to_owned(),
                    )
                }
            }
            Observation::Object(object) => Self::of_object(plan, rule, object, deadline, now),
        }
    }

    fn of_object(
        plan: &Plan,
        rule: VerificationRule,
        object: &Object,
        deadline: &Deadline,
        now: ObservedAt,
    ) -> Self {
        let planned_uid = plan.preconditions().uid();
        if let (Some(planned), Some(seen)) = (planned_uid, object.uid())
            && planned != seen
        {
            // §16.3: the name is the same and the object is not. For a deletion that is the
            // strongest possible confirmation; for everything else it means the question was
            // asked of an object nobody planned to change.
            return if rule == VerificationRule::Absence {
                Self {
                    verdict: Verdict::Confirmed,
                    rule,
                    reached: None,
                    detail: format!(
                        "the name now holds a different object lifetime (uid {planned} -> \
                         {seen}), so the planned object's lifetime has ended"
                    ),
                    reconciliation: None,
                }
            } else {
                Self::inconclusive(
                    rule,
                    format!(
                        "the name now holds a different object lifetime (uid {planned} -> \
                         {seen}); this observation is not about the planned target"
                    ),
                )
            };
        }

        if rule == VerificationRule::Absence {
            let detail = if object.is_terminating() {
                format!(
                    "the object is still present and terminating; {} finalizer(s) remain",
                    object.finalizers().len()
                )
            } else {
                "the object is still present and carries no deletion timestamp".to_owned()
            };
            return Self::waiting(rule, None, detail, None, deadline, now);
        }

        let unmet: Vec<&FieldChange> = plan
            .field_changes()
            .iter()
            .filter(|change| match change.to() {
                Some(wanted) => object.field(change.path()) != Some(wanted),
                None => object.field(change.path()).is_some(),
            })
            .collect();
        if !unmet.is_empty() {
            let paths: Vec<&str> = unmet.iter().map(|change| change.path()).collect();
            return Self::waiting(
                rule,
                None,
                format!(
                    "the requested fields are not on the object: {}",
                    paths.join(", ")
                ),
                None,
                deadline,
                now,
            );
        }

        if rule == VerificationRule::FieldObserved {
            return Self {
                verdict: Verdict::Confirmed,
                rule,
                reached: Some(Stage::SpecObserved),
                detail: "the requested fields are on the object; no controller behaviour is \
                         claimed by this rule"
                    .to_owned(),
                reconciliation: None,
            };
        }

        let state = reconciliation(object);
        match state.state() {
            ReconciliationState::Converged => Self {
                verdict: Verdict::Confirmed,
                rule,
                reached: Some(Stage::StatusConverged),
                detail: "the controller observed the generation and status converged".to_owned(),
                reconciliation: Some(state),
            },
            ReconciliationState::Failed => Self {
                verdict: Verdict::Refuted,
                rule,
                reached: state.state().established_stage(),
                detail: "the controller reported failure".to_owned(),
                reconciliation: Some(state),
            },
            other => {
                let reached = other.established_stage();
                Self::waiting(
                    rule,
                    reached,
                    other.as_str().to_owned(),
                    Some(state),
                    deadline,
                    now,
                )
            }
        }
    }

    /// Pending before the deadline, inconclusive after it (§46.4).
    fn waiting(
        rule: VerificationRule,
        reached: Option<Stage>,
        detail: String,
        reconciliation: Option<Reconciliation>,
        deadline: &Deadline,
        now: ObservedAt,
    ) -> Self {
        Self {
            verdict: if deadline.has_expired(now) {
                Verdict::Inconclusive
            } else {
                Verdict::Pending
            },
            rule,
            reached,
            detail,
            reconciliation,
        }
    }

    fn inconclusive(rule: VerificationRule, detail: String) -> Self {
        Self {
            verdict: Verdict::Inconclusive,
            rule,
            reached: None,
            detail,
            reconciliation: None,
        }
    }

    /// What was established.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// The rule the verdict was reached under (§46.3).
    #[must_use]
    pub fn rule(&self) -> VerificationRule {
        self.rule
    }

    /// The furthest rung of §20.4's ladder the evidence reaches.
    ///
    /// Never [`Stage::ExternallyHealthy`]: no API read establishes that a workload is serving
    /// anybody, and a verification that claimed it would be a promise about traffic nobody
    /// measured (§37.5, Gate G).
    #[must_use]
    pub fn reached(&self) -> Option<Stage> {
        self.reached
    }

    /// The reconciliation state the verdict rests on, with its citations (§37.5).
    #[must_use]
    pub fn reconciliation(&self) -> Option<&Reconciliation> {
        self.reconciliation.as_ref()
    }

    /// The verdict, the rule, the evidence, and what an inconclusive answer is not.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut line = match self.verdict {
            Verdict::Inconclusive => format!(
                "verification incomplete: {}. This is not evidence that the change failed, and \
                 not evidence that it succeeded (§46.4)",
                self.detail
            ),
            Verdict::Pending => format!("verification pending: {}", self.detail),
            Verdict::Confirmed => format!("confirmed [{}]: {}", self.rule, self.detail),
            Verdict::Refuted => format!("refuted [{}]: {}", self.rule, self.detail),
        };
        if let Some(stage) = self.reached {
            line.push_str(&format!("; evidence reaches: {}", stage.as_str()));
        }
        if let Some(state) = &self.reconciliation {
            line.push_str(&format!("; {}", state.describe()));
        }
        line
    }
}

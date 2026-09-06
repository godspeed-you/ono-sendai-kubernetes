//! What a change would do, answered before anything is changed.
//!
//! Specification §46 (prospective change), §56 (preconditions) and §43.3 (a bounded action
//! surface). `ono_provider_kubernetes::plan` holds the reasoning; this module is the boundary
//! that reaches it — it reads the object the change is aimed at, turns the invocation's arguments
//! into field changes against what that object actually holds, and answers a record.
//!
//! Five properties decide the shape of everything below.
//!
//! **§43.3's actions are arguments, not words.** `--replicas`, `--image`, `--restart_rollout`,
//! `--schedulable`, `--label` and `--annotation` are the seven candidate transitions of §43.3,
//! reached through the verb the shell already has; the package still contributes zero verbs (§4
//! invariant 22, §35.1). Exactly one per invocation, because §46.3 gives one verification rule per
//! action. `--set` and `--unset` are §43.4's low-level escape hatch and are labelled as one
//! everywhere a user meets them. ADR-0042.
//!
//! **Asking is a read.** `k8s-plan` is a *target*, so `get k8s-plan` answers it and it changes
//! nothing: discovery, the `GET` of the object, and §21.2's `SelfSubjectAccessReview` — which is
//! a `POST` by the REST verb and a question by its semantics, because the API server computes the
//! answer and stores no object. There is no server dry run on this path: a dry-run `PATCH` is a
//! write-shaped request that runs admission webhooks, and a target a user may point at anything
//! must not do that. The plan says so — `Caveat::AdmissionEffectsNotPreviewed` — rather than
//! leaving the omission to be inferred, and the dry run lives on `set k8s-resource`, where the
//! risk is declared (§44.5, ADR-0024).
//!
//! **The permission check is advisory and never an authorizer.** §21.1 leaves the API server the
//! only authority, so the review's answer is a plan field (§46.2, Appendix E's `AUTHORIZATION`
//! line) and every plan carries a caveat about it: a grant can lapse before the request, and
//! everything that is not an explicit denial — an unserved review API, an authorizer with no
//! opinion, a review the server would not answer — is §21.4's `not queried` rather than a
//! refusal this package invented.
//!
//! **Preconditions come from the object or the plan is refused.** Nothing an invocation can say
//! supplies a `resourceVersion` or a UID: the only source is the object that
//! was read, which is what makes §56 travel rather than be described. `Plan::of` refuses a target
//! that cannot supply one, and the refusal is passed through with the sentence that names what
//! the missing precondition would have prevented.
//!
//! **The change is expressed against what the object holds.** `--set '{"/spec/replicas": 1}'`
//! becomes `FieldChange::change("/spec/replicas", 3, 1)` when the field is there and
//! `FieldChange::set` when it is not, so a plan states the before as well as the after (§46.2). A
//! `--unset` of a field the object does not carry is dropped rather than sent, because removing
//! an absent field changes nothing and taking field ownership of it is not what was asked.
//!
//! **The object crosses the redaction boundary first.** Everything here works from a
//! [`Guarded`], so a plan that touches a Secret states which keys change without ever holding a
//! payload to state (§22, Gate I).

use std::sync::Arc;

use ono_kuang_sdk::protocol::WireError;
use ono_kuang_sdk::{Ctx, EmitError, Outcome as InvocationOutcome};
use ono_provider_kubernetes::coverage::{Coverage, Gap, Outcome, Scope};
use ono_provider_kubernetes::discovery::{self, Discovery, Gvr, Resource, Verb};
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::plan::{
    Action, CompetingWriter, Contained, Curated, Dependent, Effect, FieldChange, Plan, PlanRefusal,
    Preconditions, Preflight, Propagation, access_review,
};
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{
    ByteStream, Client, ListOptions, Operation, create_request,
};
use ono_value::{ErrorValue, MapValue, Provenance, RecordValue, Schema, Value};
use serde_json::{Map as JsonMap, Value as Json};

use crate::contributions::{Field, Target, Writes};
use crate::dynamic::Selector;
use crate::query::{
    Answer, Conversation, Endpoint, GroupRead, UNAVAILABLE, UNAVAILABLE_CODE, UNSUPPORTED,
    UNSUPPORTED_CODE, converse, document, failure, fetch, group_document, group_version_of,
    resolve_in, resource_list,
};
use crate::sessions::Sessions;

pub(crate) use crate::query::{REFUSED, REFUSED_CODE};

/// What a plan or a mutation was asked to do, read from one invocation's arguments.
///
/// Deliberately small, and deliberately missing two things. There is no `resource_version` and no
/// `uid` argument, because §56's preconditions come from the object that was read and a caller
/// who could type one could aim a change at an object nobody looked at. And there is no `force`
/// flag: forcing is a *reason*, and it lives on the apply options rather than here (§44.4).
#[derive(Debug, Clone)]
pub(crate) struct Intent {
    selector: Selector,
    name: String,
    wanted: Wanted,
}

/// What the arguments asked for, before an object has been read to express it against.
///
/// §43.3's seven candidate actions all reduce to a bounded field change, and reducing them is not
/// the same as offering them: a user who has to know that scaling is `/spec/replicas` and that a
/// JSON pointer is how it is spelled has an action surface they cannot find (§52). So each curated
/// transition is its own member here, and the *pointers* are derived once the object is in hand —
/// which is also the only moment a container name can be turned into a list index (§44.1).
#[derive(Debug, Clone)]
enum Wanted {
    /// §43.4's raw escape hatch: field changes named by JSON pointer.
    Apply {
        set: Vec<(String, Json)>,
        unset: Vec<String>,
    },
    /// §43.3's "scale workload".
    Scale { replicas: i64 },
    /// §43.3's "set image", by container name rather than by list position.
    SetImage { images: Vec<(String, String)> },
    /// §43.3's "restart rollout through an explicit supported mechanism".
    RestartRollout,
    /// §43.3's "cordon / uncordon node".
    Schedulable { allowed: bool },
    /// §43.3's "annotate / label", on the metadata of any object.
    Metadata {
        curation: Curated,
        field: &'static str,
        pairs: Vec<(String, Option<String>)>,
    },
    /// The object, with the propagation policy the invocation chose (§45.2).
    Delete { propagation: Propagation },
}

impl Intent {
    /// What the arguments ask for, where the caller may ask for either (the `k8s-plan` target).
    ///
    /// # Errors
    ///
    /// A refusal naming what the arguments did not say.
    pub(crate) fn read(options: &JsonMap<String, Json>) -> Result<Self, WireError> {
        let action = options
            .get("action")
            .and_then(Json::as_str)
            .unwrap_or("apply");
        match action {
            "apply" => Self::of(options, Writes::Fields),
            "delete" => Self::of(options, Writes::Object),
            other => Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("`action {other}` is not a change this provider plans"),
                "§43.3 keeps the action surface bounded: `apply` states a set of field changes, \
                 `delete` removes the object. Every candidate action of that section reduces to \
                 one of the two.",
            )),
        }
    }

    /// What the arguments ask for, where the *command* already decided which kind of write it is.
    ///
    /// # Errors
    ///
    /// A refusal naming what the arguments did not say.
    pub(crate) fn of(options: &JsonMap<String, Json>, writes: Writes) -> Result<Self, WireError> {
        let name = options
            .get("name")
            .and_then(Json::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                failure(
                    UNSUPPORTED_CODE,
                    UNSUPPORTED,
                    "the invocation named no object to change".to_owned(),
                    "§21.3 of the generic provider contract: a change is resolved to one object \
                     before it is made, so `name` is required. A change aimed at a collection is \
                     not something this provider does.",
                )
            })?
            .to_owned();
        let wanted = match writes {
            Writes::Fields => fields_wanted(options)?,
            Writes::Object => Wanted::Delete {
                propagation: propagation(options)?,
            },
        };
        Ok(Self {
            selector: Selector::from_options(options),
            name,
            wanted,
        })
    }

    /// Which resource the change is aimed at, as the invocation named it.
    pub(crate) fn selector(&self) -> &Selector {
        &self.selector
    }

    /// The object's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The verb the API server has to offer for this change to be possible at all (§11.5).
    ///
    /// Asked of discovery before anything is sent, so that a resource nobody may patch is a
    /// refusal naming the verb rather than a `405` somebody has to interpret.
    pub(crate) fn verb(&self) -> Verb {
        match self.wanted {
            Wanted::Delete { .. } => Verb::Delete,
            _ => Verb::Patch,
        }
    }

    /// The action, expressed against what the object actually holds (§46.2).
    ///
    /// # Errors
    ///
    /// A refusal where the curated transition names something the object does not have — a
    /// container that is not in the pod template, most of all. §44.1 merges list entries by key
    /// rather than by position, so an image change has to find the container before it can name
    /// an index, and a name that matches nothing is a refusal rather than a container this
    /// provider would add.
    fn action(&self, object: &Object) -> Result<Action, WireError> {
        Ok(match &self.wanted {
            Wanted::Delete { propagation } => Action::delete(*propagation),
            Wanted::Apply { set, unset } => {
                let mut changes: Vec<FieldChange> = Vec::new();
                for (path, wanted) in set {
                    changes.push(against(object, path, wanted.clone()));
                }
                for path in unset {
                    // A field that is not there cannot be removed, and taking ownership of it in
                    // order to say so is not what was asked.
                    if let Some(held) = object.field(path) {
                        changes.push(FieldChange::remove(path, held.clone()));
                    }
                }
                Action::apply(changes)
            }
            Wanted::Scale { replicas } => Action::curated(
                Curated::Scale,
                vec![against(object, "/spec/replicas", Json::from(*replicas))],
            ),
            Wanted::SetImage { images } => {
                let base = container_base(object)?;
                let mut changes: Vec<FieldChange> = Vec::new();
                for (container, image) in images {
                    let at = container_index(object, base, container)?;
                    // The merge key travels with the value: §44.1 merges list entries by `name`,
                    // and an index without its key is merged against whichever entry the server
                    // chose. `mutation.rs` refuses the document that lacks it, and this is the
                    // one place that knows the name to put there.
                    changes.push(against(
                        object,
                        &format!("{base}/{at}/name"),
                        Json::String(container.clone()),
                    ));
                    changes.push(against(
                        object,
                        &format!("{base}/{at}/image"),
                        Json::String(image.clone()),
                    ));
                }
                Action::curated(Curated::SetImage, changes)
            }
            Wanted::RestartRollout => {
                if object.field("/spec/template").is_none() {
                    return Err(failure(
                        UNSUPPORTED_CODE,
                        UNSUPPORTED,
                        format!(
                            "`{}` carries no pod template, so there is no rollout to restart",
                            object.gvk()
                        ),
                        "§43.3 asks for a restart through an explicit supported mechanism, and \
                         the mechanism is the pod template: changing it is what makes a \
                         controller replace its pods. An object without one has no rollout, and \
                         deleting its pods would be a second mechanism this provider invented.",
                    ));
                }
                // The marker is the `resourceVersion` this restart was planned against. It is an
                // opaque continuity token used as an opaque token — never as a time and never
                // sorted (§14.3) — which is what lets it say *which observation* the restart was
                // made from without this provider needing a clock.
                let token = object.resource_version().unwrap_or("unknown").to_owned();
                Action::curated(
                    Curated::RestartRollout,
                    vec![against(object, RESTART_MARKER, Json::String(token))],
                )
            }
            Wanted::Schedulable { allowed } => Action::curated(
                if *allowed {
                    Curated::Uncordon
                } else {
                    Curated::Cordon
                },
                vec![against(
                    object,
                    "/spec/unschedulable",
                    Json::Bool(!*allowed),
                )],
            ),
            Wanted::Metadata {
                curation,
                field,
                pairs,
            } => {
                let mut changes: Vec<FieldChange> = Vec::new();
                for (key, value) in pairs {
                    let path = format!("{field}/{}", escape(key));
                    match value {
                        Some(value) => {
                            changes.push(against(object, &path, Json::String(value.clone())));
                        }
                        None => {
                            if let Some(held) = object.field(&path) {
                                changes.push(FieldChange::remove(&path, held.clone()));
                            }
                        }
                    }
                }
                Action::curated(*curation, changes)
            }
        })
    }
}

/// The annotation a restarted rollout carries, as a JSON pointer (§43.3).
const RESTART_MARKER: &str =
    "/spec/template/metadata/annotations/ono-sendai.io~1restarted-from-resource-version";

/// One field change, stated against what the object holds now (§46.2).
fn against(object: &Object, path: &str, wanted: Json) -> FieldChange {
    match object.field(path) {
        Some(held) => FieldChange::change(path, held.clone(), wanted),
        None => FieldChange::set(path, wanted),
    }
}

/// One key as a JSON pointer segment spells it (RFC 6901).
///
/// `app.kubernetes.io/name` is the label convention §23.4 names, and a pointer spells the slash
/// inside a key as `~1`. Escaping `~` first is not optional: the other order turns `~1` into `/`
/// after having produced it.
fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Where an object's containers live: a pod template for a controller, the spec itself for a Pod.
fn container_base(object: &Object) -> Result<&'static str, WireError> {
    if object.field("/spec/template/spec/containers").is_some() {
        return Ok("/spec/template/spec/containers");
    }
    if object.field("/spec/containers").is_some() {
        return Ok("/spec/containers");
    }
    Err(failure(
        UNSUPPORTED_CODE,
        UNSUPPORTED,
        format!(
            "`{}` carries no container list, so there is no image to set on it",
            object.gvk()
        ),
        "§43.3's `set image` is a change to a container, and this provider finds containers at \
         `/spec/template/spec/containers` for a workload and `/spec/containers` for a Pod. A \
         custom resource that keeps its containers elsewhere is reachable through the low-level \
         `--set` path, which names the pointer explicitly (§43.4).",
    ))
}

/// Which entry of the container list carries this name (§44.1).
fn container_index(object: &Object, base: &str, container: &str) -> Result<usize, WireError> {
    let entries = object.field(base).and_then(Json::as_array);
    let named: Vec<String> = entries
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("name")?.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    named
        .iter()
        .position(|name| name == container)
        .ok_or_else(|| {
            failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!(
                    "`{}` has no container named `{container}`; it has {}",
                    object.name(),
                    if named.is_empty() {
                        "none this provider could read".to_owned()
                    } else {
                        named.join(", ")
                    }
                ),
                "A container is named rather than numbered because server-side apply merges list \
                 entries by key rather than by position (§44.1). A name that matches nothing \
                 would otherwise become a container this change adds.",
            )
        })
}

/// Which curated transition, or which raw apply, the arguments of a field-writing command ask for.
///
/// Exactly one of them. §46.3 gives one verification rule per action and §46.2 one set of effects,
/// so two curated arguments in one invocation would produce a plan whose rule belongs to one of
/// them and whose effects belong to both. The refusal names what was written rather than telling
/// the caller to read the documentation.
fn fields_wanted(options: &JsonMap<String, Json>) -> Result<Wanted, WireError> {
    let mut chosen: Vec<(&str, Wanted)> = Vec::new();
    if let Some(replicas) = options.get("replicas") {
        let replicas = replicas
            .as_i64()
            .or_else(|| replicas.as_str()?.parse().ok());
        let replicas = replicas.ok_or_else(|| {
            failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                "`replicas` is a whole number of replicas".to_owned(),
                "For example `--replicas 3`. §43.3's `scale workload`, which is a change to \
                 `/spec/replicas`.",
            )
        })?;
        if replicas < 0 {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!("`{replicas}` is not a number of replicas"),
                "A replica count is zero or more. Zero is a scale to nothing, which the plan \
                 reports as stopping the pods that are running (§46.2).",
            ));
        }
        chosen.push(("replicas", Wanted::Scale { replicas }));
    }
    let images = pairs(options, "image")?;
    if !images.is_empty() {
        let mut named = Vec::with_capacity(images.len());
        for (container, image) in images {
            let Some(image) = image else {
                return Err(failure(
                    UNSUPPORTED_CODE,
                    UNSUPPORTED,
                    format!("`{container}` names a container and no image"),
                    "`--image <container>=<image>`, as in `--image web=registry.example/web:2`. \
                     The container is named rather than numbered because server-side apply \
                     merges list entries by key (§44.1).",
                ));
            };
            named.push((container, image));
        }
        chosen.push(("image", Wanted::SetImage { images: named }));
    }
    if flag(options, "restart_rollout") {
        chosen.push(("restart_rollout", Wanted::RestartRollout));
    }
    if let Some(schedulable) = options.get("schedulable") {
        let allowed = schedulable
            .as_bool()
            .or_else(|| schedulable.as_str()?.parse().ok())
            .ok_or_else(|| {
                failure(
                    UNSUPPORTED_CODE,
                    UNSUPPORTED,
                    "`schedulable` is true or false".to_owned(),
                    "`--schedulable false` cordons the node and `--schedulable true` uncordons \
                     it (§43.3). Neither moves a pod that is already running on it.",
                )
            })?;
        chosen.push(("schedulable", Wanted::Schedulable { allowed }));
    }
    let labels = pairs(options, "label")?;
    if !labels.is_empty() {
        chosen.push((
            "label",
            Wanted::Metadata {
                curation: Curated::Label,
                field: "/metadata/labels",
                pairs: labels,
            },
        ));
    }
    let annotations = pairs(options, "annotation")?;
    if !annotations.is_empty() {
        chosen.push((
            "annotation",
            Wanted::Metadata {
                curation: Curated::Annotate,
                field: "/metadata/annotations",
                pairs: annotations,
            },
        ));
    }
    let set = pointers(options)?;
    let unset = unset(options)?;
    if !set.is_empty() || !unset.is_empty() {
        chosen.push(("set", Wanted::Apply { set, unset }));
    }
    if chosen.len() > 1 {
        let written: Vec<&str> = chosen.iter().map(|(name, _)| *name).collect();
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!(
                "one change describes one action, and this one names {}",
                written
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<String>>()
                    .join(" and ")
            ),
            "§46.3 gives one verification rule per action and §46.2 one set of effects, so a plan \
             that carried two transitions would have a rule belonging to one of them and effects \
             belonging to both. Make them one at a time.",
        ));
    }
    chosen.pop().map(|(_, wanted)| wanted).ok_or_else(|| {
        failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            "the invocation named no change to make".to_owned(),
            "§43.3's curated actions are `--replicas`, `--image`, `--restart_rollout`, \
             `--schedulable`, `--label` and `--annotation`. `--set` and `--unset` are §43.4's \
             low-level path, which names raw JSON pointers.",
        )
    })
}

/// Whether a boolean argument was written and is true.
fn flag(options: &JsonMap<String, Json>, name: &str) -> bool {
    options.get(name).is_some_and(|value| {
        value
            .as_bool()
            .or_else(|| value.as_str()?.parse().ok())
            .unwrap_or(false)
    })
}

/// A repeatable `<key>=<value>` argument, where an empty value means removal.
fn pairs(
    options: &JsonMap<String, Json>,
    name: &str,
) -> Result<Vec<(String, Option<String>)>, WireError> {
    let Some(written) = options.get(name) else {
        return Ok(Vec::new());
    };
    let words: Vec<String> = match written {
        Json::String(one) => vec![one.clone()],
        Json::Array(many) => many
            .iter()
            .filter_map(|entry| entry.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    if words.is_empty() {
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("`{name}` is written as `<key>=<value>`"),
            "Write it more than once for more than one. A trailing `=` with nothing after it \
             removes the entry rather than setting it to the empty string.",
        ));
    }
    words
        .iter()
        .map(|word| {
            let (key, value) = word.split_once('=').ok_or_else(|| {
                failure(
                    UNSUPPORTED_CODE,
                    UNSUPPORTED,
                    format!("`{word}` is not a `<key>=<value>` pair"),
                    "For example `--label tier=edge`. A trailing `=` with nothing after it \
                     removes the entry.",
                )
            })?;
            if key.is_empty() {
                return Err(failure(
                    UNSUPPORTED_CODE,
                    UNSUPPORTED,
                    format!("`{word}` names no key"),
                    "A key is what the value is stored under, and an empty one is not a key.",
                ));
            }
            Ok((
                key.to_owned(),
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                },
            ))
        })
        .collect()
}

/// The JSON pointers and values an `apply` sets.
fn pointers(options: &JsonMap<String, Json>) -> Result<Vec<(String, Json)>, WireError> {
    let Some(set) = options.get("set") else {
        return Ok(Vec::new());
    };
    // Two spellings, because a shell has two ways to hand over a mapping and the documented one
    // is the quoted document. An Ono record literal arrives as a record because `set` is declared
    // `record`; a quoted JSON document arrives as text, because a written word is only coerced to
    // a type it parses as and `'{"/spec/replicas": 2}'` is a string until somebody reads it. The
    // example in `package/contributions/commands.yaml` is the second, so the second has to work.
    let parsed;
    let fields = match set {
        Json::Object(fields) => Some(fields),
        Json::String(document) => {
            parsed = serde_json::from_str::<Json>(document).ok();
            parsed.as_ref().and_then(Json::as_object)
        }
        _ => None,
    };
    let Some(fields) = fields else {
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            "`set` is a mapping from a field path to the value it should hold".to_owned(),
            "For example `--set '{\"/spec/replicas\": 2}'`. A path is a JSON pointer into the \
             object, which is the same notation every other part of this provider reads a field \
             by.",
        ));
    };
    fields
        .iter()
        .map(|(path, value)| {
            check_pointer(path)?;
            Ok((path.clone(), value.clone()))
        })
        .collect()
}

/// The JSON pointers an `apply` removes.
fn unset(options: &JsonMap<String, Json>) -> Result<Vec<String>, WireError> {
    let Some(unset) = options.get("unset") else {
        return Ok(Vec::new());
    };
    let paths: Vec<String> = match unset {
        Json::String(one) => vec![one.clone()],
        Json::Array(many) => many
            .iter()
            .filter_map(|path| path.as_str().map(str::to_owned))
            .collect(),
        _ => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                "`unset` is a field path, or a list of them".to_owned(),
                "For example `--unset /spec/replicas`. Server-side apply expresses a removal by \
                 the field's absence from the applied document (§44.1).",
            ));
        }
    };
    for path in &paths {
        check_pointer(path)?;
    }
    Ok(paths)
}

fn check_pointer(path: &str) -> Result<(), WireError> {
    // §33.6: preserve desired/observed semantics *and* mutation boundaries. `status` is on the far
    // side of that boundary, and this provider refuses rather than routing the write to the
    // subresource — see ADR-0042. The refusal is here, before discovery and before any request,
    // because a change that cannot be made should cost a cluster nothing to find out.
    if path == "/status" || path.starts_with("/status/") {
        return Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("`{path}` writes observed state, which this provider does not write"),
            "§33.6 asks a provider to preserve desired/observed semantics and mutation \
             boundaries. `status` is a controller's report of what it observed, reached through \
             its own subresource wherever one is served: sent to the object endpoint the field is \
             dropped and the request still answers 200, and sent to the subresource it succeeds \
             and a value meant to say what a controller saw now says what somebody typed (Gate G, \
             §62.7). Change the desired state and let the controller write what it observes; read \
             the observed side with `get k8s-resource`, which keeps the two apart already.",
        ));
    }
    if path.starts_with('/') && path.len() > 1 {
        return Ok(());
    }
    Err(failure(
        UNSUPPORTED_CODE,
        UNSUPPORTED,
        format!("`{path}` is not a field path"),
        "A field path is a JSON pointer: it starts with `/` and names the fields down to the one \
         being changed, as in `/spec/template/spec/containers/0/image`.",
    ))
}

/// The propagation policy a deletion was asked for, defaulting to the API server's own (§45.2).
fn propagation(options: &JsonMap<String, Json>) -> Result<Propagation, WireError> {
    let Some(chosen) = options.get("propagation").and_then(Json::as_str) else {
        return Ok(Propagation::Background);
    };
    match chosen.to_ascii_lowercase().as_str() {
        "foreground" => Ok(Propagation::Foreground),
        "background" => Ok(Propagation::Background),
        "orphan" => Ok(Propagation::Orphan),
        other => Err(failure(
            UNSUPPORTED_CODE,
            UNSUPPORTED,
            format!("`{other}` is not a propagation policy"),
            "§45.2's three: `Foreground` keeps the object until its dependents are gone, \
             `Background` removes it now and collects them afterwards, `Orphan` leaves them \
             behind owned by nothing.",
        )),
    }
}

/// A plan, and what was learnt on the way to it.
pub(crate) struct Planned {
    /// The change, described before it is made.
    pub(crate) plan: Plan,
    /// Which REST collection serves the object, as discovery answered (§13.1).
    pub(crate) resource: Resource,
    /// The scope the object was read in.
    pub(crate) scope: Scope,
}

/// Reads the object a change is aimed at and builds the plan for it.
///
/// Shared by the `k8s-plan` target and by both mutating commands, because §46.1 makes them the
/// same first step: a mutation *is* a plan that was then carried out, and a second path from
/// arguments to a request would be a second place for a precondition to go missing.
///
/// # Errors
///
/// A refusal naming what could not be resolved, read or planned. Every one of them happens
/// before anything is sent that could change a cluster.
pub(crate) fn plan_on<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    intent: &Intent,
) -> Result<Planned, WireError> {
    let core = document(session, client, endpoint, "/api")?;
    let groups = document(session, client, endpoint, "/apis")?;
    let served = Discovery::builder()
        .core_versions(&core)
        .and_then(|builder| builder.groups(&groups))
        .map_err(|error| {
            failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!("the API server's discovery documents did not read: {error}"),
                "The endpoint answered, but not as a Kubernetes API server.",
            )
        })?
        .build();

    // Resolved for `get` first, because the object has to be read before it can be changed: §56's
    // preconditions come from the reading, and §21.3 of the generic contract requires the target
    // to be resolved to a stable identity before a mutation rather than after it.
    let resource = resolve_in(
        session,
        client,
        endpoint,
        &served,
        intent.selector(),
        Verb::Get,
    )?;
    let wanted = intent.verb();
    if !resource.supports(wanted) {
        return Err(unsupported_verb(&resource, wanted));
    }
    let scope = match resource.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => endpoint.scope.clone(),
    };

    let object = match fetch(client, &resource, &scope, intent.name())? {
        Answer::Fetched(read) => read.0,
        Answer::Absent => {
            return Err(failure(
                UNSUPPORTED_CODE,
                UNSUPPORTED,
                format!(
                    "`{}` in {scope} holds no object named `{}`, so there is nothing to change",
                    resource.gvr(),
                    intent.name()
                ),
                "A change is aimed at an object that exists, and this provider creates nothing \
                 it was not asked to change. A `404` on an object's own endpoint is the one \
                 outcome that is evidence of absence rather than a statement about what could \
                 not be seen (§21.4).",
            ));
        }
        // `fetch` answers a listing only when it was asked for one, and it never is here.
        Answer::Listed(_) => {
            return Err(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                "a direct read answered with a collection".to_owned(),
                "This is a defect in the Kubernetes provider, not in the cluster.",
            ));
        }
    };
    // §22 and Gate I before anything else touches the object: a plan that changes a Secret says
    // which keys it changes, and there is no payload left in the value for it to say more.
    let guarded = Guarded::hold(object).map_err(|error| {
        failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("an object could not be taken across the redaction boundary: {error}"),
            "This is a defect in the Kubernetes provider, not in the cluster.",
        )
    })?;
    let action = intent.action(guarded.object())?;
    let plan = Plan::of(guarded.object(), action).map_err(|refusal| refused(&refusal))?;
    // §54.1 and §54.2. Only for a change that writes the replica count: §54.2 is about a *direct
    // replica change*, and listing every namespace's autoscalers on every plan would pay §50.2
    // for a warning that could not apply.
    let plan = if plan
        .field_changes()
        .iter()
        .any(|change| change.path() == "/spec/replicas")
    {
        let (autoscalers, coverage) =
            autoscalers_targeting(session, client, endpoint, &served, &scope);
        plan.with_competing_writers(autoscalers, coverage)
    } else {
        plan
    };
    // §55.2: a Namespace deletion "MUST receive enhanced prospective analysis".
    let plan = if plan.action().is_destructive() && resource.kind() == "Namespace" {
        let (counted, coverage) =
            namespace_contents(session, client, endpoint, &served, plan.target().name());
        plan.with_contents(counted, coverage)
    } else {
        plan
    };
    // §46.2's `permission preflight result`, and Appendix E's `AUTHORIZATION` line. Last, because
    // the review asks about the action the plan turned out to describe, and because a plan that
    // could not be built is a plan whose authorization nobody needs to have asked about.
    let preflight = preflight_for(session, client, endpoint, &served, &plan, &resource);
    let plan = plan.with_preflight(preflight);
    Ok(Planned {
        plan,
        resource,
        scope,
    })
}

/// The group whose objects write a workload's replica count on their own (§54.2).
const AUTOSCALING_GROUP: &str = "autoscaling";

/// The kind that names the workload it scales in `spec.scaleTargetRef` (§54.2).
const AUTOSCALER_KIND: &str = "HorizontalPodAutoscaler";

/// How many objects one page of a namespace inventory asks for (§18.1, §50.2).
///
/// One page and no more. §55.2 wants counts, and a namespace-deletion plan that walked every
/// collection to its end would cost an unbounded number of requests at the moment somebody is
/// waiting to decide. A page that did not end is reported as a floor rather than a total, which
/// is the honest shape of a bounded count (§18.4).
const INVENTORY_PAGE: u32 = 500;

/// The autoscalers that may write this namespace's replica counts, and what the search covered.
///
/// Every way this can come up empty is a coverage gap rather than an answer: §54.1 asks for
/// *known* competing writers, and a cluster that serves no `autoscaling` group, a resource list
/// that would not read and a listing the authorizer refused are three different reasons to have
/// found none — and none of them is evidence that there is no autoscaler (§21.4, §4 invariant 13).
///
/// The matching is `plan.rs`'s: a candidate that does not name this object in `scaleTargetRef` is
/// dropped by [`CompetingWriter::autoscaler`] rather than filtered here, so the rule that decides
/// what counts as evidence lives beside the rest of the plan's reasoning.
fn autoscalers_targeting<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    scope: &Scope,
) -> (Vec<Object>, Coverage) {
    let mut coverage = Coverage::complete(scope.clone());
    let gap = |coverage: &mut Coverage, outcome: Outcome| {
        coverage.record(Gap::new(
            Scope::in_group_version(AUTOSCALING_GROUP),
            outcome,
        ));
    };
    // §5.3 and §11.1: which version of the autoscaling API this cluster serves is learnt.
    let Some(version) = served.preferred_version(AUTOSCALING_GROUP) else {
        gap(&mut coverage, Outcome::TypeNotServed);
        return (Vec::new(), coverage);
    };
    let group_version = group_version_of(AUTOSCALING_GROUP, version);
    let Ok(catalogue) = resource_list(session, client, endpoint, &group_version) else {
        gap(&mut coverage, Outcome::RequestFailed);
        return (Vec::new(), coverage);
    };
    let Some(resource) = catalogue.by_kind(&group_version, AUTOSCALER_KIND) else {
        gap(&mut coverage, Outcome::TypeNotServed);
        return (Vec::new(), coverage);
    };
    if !resource.supports(Verb::List) {
        gap(&mut coverage, Outcome::TypeNotServed);
        return (Vec::new(), coverage);
    }
    match client.list_page(
        resource.gvr(),
        scope,
        &ListOptions::new().limit(INVENTORY_PAGE),
    ) {
        Ok(page) => {
            if page.continue_token().is_some() {
                coverage.more_available();
            }
            coverage.observed(scope.clone());
            (page.into_objects(), coverage)
        }
        Err(error) => {
            coverage.record(Gap::new(
                Scope::in_group_version(&group_version),
                error.outcome(Operation::List),
            ));
            (Vec::new(), coverage)
        }
    }
}

/// What a namespace holds, counted by GVR, with what the counting could not reach (§55.2).
///
/// The enumeration is over the *preferred* version of every group the cluster serves, because
/// §55.2 asks for counts by GVR and the same objects served at two versions would be counted
/// twice (§13.4). Every group-version whose resource list did not read, and every collection that
/// would not list, becomes a gap: §55.4 and §45.4 both say the same thing in different words, and
/// a count of zero for a collection nobody was allowed to read is the one number this must not
/// print.
fn namespace_contents<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    namespace: &str,
) -> (Vec<Contained>, Coverage) {
    let scope = Scope::in_namespace(namespace);
    let mut coverage = Coverage::complete(scope.clone());
    let mut counted: Vec<Contained> = Vec::new();
    let group_versions: Vec<String> = served
        .groups()
        .filter_map(|group| {
            served
                .preferred_version(group)
                .map(|version| group_version_of(group, version))
        })
        .collect();
    for group_version in group_versions {
        let mut builder = Discovery::builder();
        let read = match group_document(session, client, endpoint, &group_version) {
            Ok(GroupRead::Document(list)) => builder.add_resources(&list).is_ok(),
            Ok(GroupRead::Unread(outcome)) => {
                coverage.record(Gap::new(Scope::in_group_version(&group_version), outcome));
                continue;
            }
            Err(_) => {
                coverage.record(Gap::new(
                    Scope::in_group_version(&group_version),
                    Outcome::RequestFailed,
                ));
                continue;
            }
        };
        if !read {
            coverage.record(Gap::new(
                Scope::in_group_version(&group_version),
                Outcome::RequestFailed,
            ));
            continue;
        }
        let discovered = builder.build();
        let namespaced: Vec<Gvr> = discovered
            .listable()
            .filter(|resource| resource.scope() == discovery::Scope::Namespaced)
            .map(|resource| resource.gvr().clone())
            .collect();
        for gvr in namespaced {
            match client.list_page(&gvr, &scope, &ListOptions::new().limit(INVENTORY_PAGE)) {
                Ok(page) => {
                    let more = page.continue_token().is_some();
                    let seen = page.into_objects().len();
                    let name = format!(
                        "{}/{}",
                        group_version_of(gvr.group(), gvr.version()),
                        gvr.resource()
                    );
                    counted.push(if more {
                        coverage.more_available();
                        Contained::at_least(name, seen)
                    } else {
                        Contained::counted(name, seen)
                    });
                }
                Err(error) => {
                    // §21.4 one outcome at a time, and §55.2's second bullet in one line: this
                    // type is a type that *could not be listed*, which is neither a count nor a
                    // zero. It gets no entry at all, and the gap says why.
                    coverage.record(Gap::new(
                        Scope::in_group_version(gvr.to_string()),
                        error.outcome(Operation::List),
                    ));
                }
            }
        }
        coverage.observed(scope.clone());
    }
    (counted, coverage)
}

/// The API group that answers "may this identity do that" (§21.2).
const REVIEW_GROUP: &str = "authorization.k8s.io";

/// The kind that asks about one action for the caller's own identity.
///
/// `SelfSubjectAccessReview` and not `SubjectAccessReview`: the second asks about *another*
/// identity and needs a privilege this provider has no business holding (§8.1).
const REVIEW_KIND: &str = "SelfSubjectAccessReview";

/// Asks the API server whether this identity may make this change (§21.2, §46.2, Appendix E).
///
/// **This is the one write a read-only path makes, and it changes nothing.** A
/// `SelfSubjectAccessReview` is a create by the REST verb — a `POST` to a collection — and a
/// question by its semantics: the API server computes the answer, returns it in `status`, and
/// stores no object. So `get k8s-plan` stays a read of the cluster while gaining the line
/// Appendix E puts on a plan.
///
/// **It never fails a plan, and it never denies one on this provider's behalf.** Every way this
/// can go wrong — an unserved `authorization.k8s.io`, a resource list that did not read, a review
/// the server refused, an authorizer with no opinion — is §21.4's `not queried`, which reaches a
/// user as §21.6's `unknown / unchecked` with the reason attached. A provider that turned "I
/// could not ask" into "you may not" would be answering an authorization question the API server
/// never answered (§21.1).
fn preflight_for<S: ByteStream>(
    session: &mut Session,
    client: &mut Client<S>,
    endpoint: &Endpoint,
    served: &Discovery,
    plan: &Plan,
    target: &Resource,
) -> Preflight {
    // §5.3 and §11.1: which version of the review API this cluster serves is learnt, not assumed.
    let Some(version) = served.preferred_version(REVIEW_GROUP) else {
        return Preflight::not_answered(format!(
            "this cluster serves no `{REVIEW_GROUP}` API group, so no permission check \
             could be asked"
        ));
    };
    let group_version = group_version_of(REVIEW_GROUP, version);
    let Ok(catalogue) = resource_list(session, client, endpoint, &group_version) else {
        return Preflight::not_answered(format!(
            "the resource list of `{group_version}` could not be read, so no permission \
             check could be asked"
        ));
    };
    let Some(review) = catalogue.by_kind(&group_version, REVIEW_KIND) else {
        return Preflight::not_answered(format!(
            "this cluster's `{group_version}` serves no `{REVIEW_KIND}`, so no permission \
             check could be asked"
        ));
    };
    // §11.5: a verb the server does not offer is not a permission the caller is missing.
    if !review.supports(Verb::Create) {
        return Preflight::not_answered(format!(
            "this cluster serves `{}` and does not offer `create` on it, so no permission \
             check could be asked",
            review.gvr()
        ));
    }
    let scope = match review.scope() {
        discovery::Scope::Cluster => Scope::cluster(),
        discovery::Scope::Namespaced => endpoint.scope.clone(),
    };
    let request = endpoint.authorise(create_request(
        review.gvr(),
        &scope,
        &access_review(plan, target.gvr(), review.gvk()),
    ));
    let response = match client.connection().send(&request) {
        Ok(response) => response,
        Err(error) => {
            return Preflight::not_answered(format!(
                "the permission check could not be sent: {error}"
            ));
        }
    };
    if !(200..300).contains(&response.status()) {
        return Preflight::not_answered(format!(
            "the API server answered the permission check with {} {}",
            response.status(),
            response.reason()
        ));
    }
    match serde_json::from_slice::<Json>(response.body()) {
        Ok(review) => Preflight::from_review(&review),
        Err(error) => Preflight::not_answered(format!(
            "the API server's answer to the permission check did not read: {error}"
        )),
    }
}

/// A change the cluster does not offer on this resource (§11.5).
fn unsupported_verb(resource: &Resource, verb: Verb) -> WireError {
    let word = match verb {
        Verb::Patch => "patch",
        Verb::Delete => "delete",
        Verb::Get => "get",
        Verb::List => "list",
        Verb::Watch => "watch",
        Verb::Create => "create",
        Verb::Update => "update",
    };
    failure(
        UNSUPPORTED_CODE,
        UNSUPPORTED,
        format!(
            "the cluster serves `{}` and does not offer `{word}` on it",
            resource.gvr()
        ),
        "A verb the API server does not serve is not a permission the caller is missing and not \
         an object that is not there: discovery says which verbs a resource offers, and this one \
         does not offer that (§11.5).",
    )
}

/// A plan `plan.rs` would not build.
fn refused(refusal: &PlanRefusal) -> WireError {
    failure(
        REFUSED_CODE,
        REFUSED,
        format!("this change was refused before anything was sent: {refusal}"),
        "§56 asks a mutation to carry preconditions, and this provider reads that as a refusal \
         rather than a warning: a change with nothing guarding its target can land on an object \
         recreated under the same name since it was planned, and the response would look \
         exactly like success (ADR-0019). Read the object again and plan against what came back.",
    )
}

// --- the target -----------------------------------------------------------------------------------

/// Answers `get k8s-plan`: one prospective change, and nothing sent that could make it.
#[must_use]
pub fn answer(
    target: &'static Target,
    sessions: &Sessions,
    ctx: &mut Ctx<'_>,
) -> InvocationOutcome {
    let schema = match target.schema_contribution().to_schema() {
        Ok(schema) => Arc::new(schema),
        Err(error) => return InvocationOutcome::Failed(error.into()),
    };
    let intent = match Intent::read(ctx.arguments()) {
        Ok(intent) => intent,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    let endpoint = match Endpoint::resolve(ctx) {
        Ok(endpoint) => endpoint,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    if ctx.cancelled() {
        return InvocationOutcome::Cancelled;
    }
    let planned = sessions.with(
        &endpoint.session_key(),
        || endpoint.start_session(),
        |session| {
            converse(
                ctx,
                &endpoint,
                Planning {
                    intent: &intent,
                    endpoint: &endpoint,
                    session,
                },
            )
        },
    );
    let planned = match planned {
        Ok(planned) => planned,
        Err(error) => return InvocationOutcome::Failed(error),
    };
    let value = match record(target.fields, &schema, &planned.plan) {
        Ok(value) => value,
        Err(error) => {
            return InvocationOutcome::Failed(failure(
                UNAVAILABLE_CODE,
                UNAVAILABLE,
                format!(
                    "a record of `{}` could not be built: {error}",
                    target.schema
                ),
                "This is a defect in the Kubernetes provider's schema table.",
            ));
        }
    };
    match ctx.emit(&value) {
        Ok(()) => InvocationOutcome::Completed,
        Err(EmitError::Cancelled) => InvocationOutcome::Cancelled,
        Err(error) => InvocationOutcome::Failed(failure(
            UNAVAILABLE_CODE,
            UNAVAILABLE,
            format!("the host refused the plan: {error}"),
            "The stream ended before the query did.",
        )),
    }
}

/// The exchange a plan needs: discovery, one read, and no write.
struct Planning<'a> {
    intent: &'a Intent,
    endpoint: &'a Endpoint,
    session: &'a mut Session,
}

impl Conversation for Planning<'_> {
    type Answer = Planned;

    fn run<S: ByteStream>(self, client: &mut Client<S>) -> Result<Self::Answer, WireError> {
        plan_on(self.session, client, self.endpoint, self.intent)
    }
}

// --- the record -------------------------------------------------------------------------------------

/// One plan, as a record of the `k8s-plan` schema.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares, which means this crate's
/// table and the schema built from it have drifted apart.
pub(crate) fn record(
    fields: &[Field],
    schema: &Arc<Schema>,
    plan: &Plan,
) -> Result<Value, ErrorValue> {
    let provenance = Provenance::local(crate::PACKAGE, schema.id().clone());
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance);
    for field in fields {
        builder = builder.set(field.name, plan_field(field.name, plan))?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// One field of a plan record, by the name the schema declares it under.
fn plan_field(name: &str, plan: &Plan) -> Value {
    match name {
        // --- what it is aimed at (§16.1, §56) ---
        "prediction" => Value::String(
            "static provider metadata: derived from the object as it was read and from this \
             provider's own rules. No server dry run was made, so admission and defaulting are \
             unpreviewed (§21.4 of the generic provider contract, §44.5)"
                .into(),
        ),
        "precondition_guarded" => Value::Bool(plan.is_precondition_guarded()),
        "effects" => Value::List(plan.effects().iter().map(effect).collect()),
        "reversibility" => Value::String(plan.reversibility().as_str().into()),
        "recovery" => recovery(plan),
        "dependents" => Value::List(plan.dependents().iter().map(dependent).collect()),
        "dependent_coverage" => Value::String(plan.dependent_coverage().describe().into()),
        "preflight" => Value::String(plan.preflight().to_string().into()),
        "verification" => Value::String(plan.verification_rule().as_str().into()),
        "verification_stage" => plan
            .verification_rule()
            .established_stage()
            .map_or(Value::Null, |stage| Value::String(stage.as_str().into())),
        "statement" => Value::String(plan.describe().into()),
        other => analysis_field(other, plan),
    }
}

/// The fields a plan record and a mutation record share about what *else* is true of the change.
///
/// On both schemas because both paths compute them: §46.1 makes a mutation a plan that was then
/// carried out, and a §54.2 warning or a §55.2 inventory that only reached `get k8s-plan` would be
/// invisible to the shortest sentence a user writes.
pub(crate) fn analysis_field(name: &str, plan: &Plan) -> Value {
    match name {
        "caveats" => Value::List(
            plan.caveats()
                .iter()
                .map(|caveat| Value::String(caveat.to_string().into()))
                .collect(),
        ),
        // §54.1: the five sources in one list, each entry saying which of them named it. A list
        // with no coverage beside it reads as complete, so the coverage is a field of its own.
        "competing_writers" => Value::List(
            plan.competing_writers()
                .iter()
                .map(competing_writer)
                .collect(),
        ),
        "competing_writer_coverage" => {
            Value::String(plan.competing_writer_coverage().describe().into())
        }
        // §55.2, and null rather than empty for every change that is not a Namespace deletion:
        // a count of zero for a question nobody asked is the one number this must not print.
        "contained" => plan.contents().map_or(Value::Null, |contents| {
            Value::List(contents.counted().iter().map(contained).collect())
        }),
        "contained_coverage" => plan.contents().map_or(Value::Null, |contents| {
            Value::String(contents.coverage().describe().into())
        }),
        other => target_field(other, plan),
    }
}

/// One competing desired-state writer, with the source that named it (§54.1).
fn competing_writer(writer: &CompetingWriter) -> Value {
    let mut map = MapValue::new();
    map.insert(Arc::from("name"), Value::String(writer.name().into()));
    map.insert(
        Arc::from("evidence"),
        Value::String(writer.evidence().as_str().into()),
    );
    map.insert(Arc::from("writes"), Value::String(writer.writes().into()));
    map.insert(
        Arc::from("detail"),
        writer
            .detail()
            .map_or(Value::Null, |detail| Value::String(detail.into())),
    );
    Value::Map(Arc::new(map))
}

/// One resource type a namespace holds, and whether the number is a total or a floor (§55.2).
fn contained(entry: &Contained) -> Value {
    let mut map = MapValue::new();
    map.insert(Arc::from("gvr"), Value::String(entry.gvr().into()));
    map.insert(
        Arc::from("count"),
        Value::Int(i128::try_from(entry.count()).unwrap_or(i128::MAX)),
    );
    map.insert(Arc::from("at_least"), Value::Bool(entry.is_lower_bound()));
    Value::Map(Arc::new(map))
}

/// The fields a plan record and a mutation record share: what the change is aimed at (§46.2).
pub(crate) fn target_field(name: &str, plan: &Plan) -> Value {
    let target = plan.target();
    match name {
        "uid" => optional(target.uid()),
        "name" => Value::String(target.name().into()),
        "namespace" => optional(target.namespace()),
        "api_version" => Value::String(
            if target.gvk().group().is_empty() {
                target.gvk().version().to_owned()
            } else {
                format!("{}/{}", target.gvk().group(), target.gvk().version())
            }
            .into(),
        ),
        "kind" => Value::String(target.gvk().kind().into()),
        "resource_version" => optional(target.resource_version()),
        "action" => Value::String(plan.action().verb().into()),
        "changes" => Value::List(
            plan.field_changes()
                .iter()
                .map(|change| Value::String(change.describe().into()))
                .collect(),
        ),
        "preconditions" => preconditions(plan.preconditions()),
        "propagation" => plan
            .propagation()
            .map_or(Value::Null, |policy| Value::String(policy.as_str().into())),
        // Every field of both schemas is answered above; a name that reaches here is a table this
        // crate wrote disagreeing with a schema this crate built, and null is what a record may
        // honestly carry for a fact nobody produced (§4).
        _ => Value::Null,
    }
}

/// One field change in one line, in the words `plan.rs` writes it (§46.2).
///
/// A free function rather than a closure at each call site, so that a plan's `changes` and a
/// mutation's `admission_differences` are spelled the same way: both are "this field held that
/// and would hold this", and a reader comparing the two should not have to translate.
pub(crate) fn describe_change(change: &FieldChange) -> String {
    change.describe()
}

fn optional(text: Option<&str>) -> Value {
    text.map_or(Value::Null, |text| Value::String(text.into()))
}

/// What the mutation will assert about its target, structured rather than in prose (§56).
fn preconditions(preconditions: &Preconditions) -> Value {
    let mut map = MapValue::new();
    map.insert(
        Arc::from("resource_version"),
        optional(preconditions.resource_version()),
    );
    map.insert(Arc::from("uid"), optional(preconditions.uid()));
    map.insert(
        Arc::from("guards_lost_update"),
        Value::Bool(preconditions.guards_lost_update()),
    );
    map.insert(
        Arc::from("guards_recreation"),
        Value::Bool(preconditions.guards_recreation()),
    );
    Value::Map(Arc::new(map))
}

/// One expected effect, with the reversibility that belongs to it rather than to the plan (§46.5).
fn effect(effect: &Effect) -> Value {
    let mut map = MapValue::new();
    map.insert(
        Arc::from("effect"),
        Value::String(effect.kind().as_str().into()),
    );
    map.insert(
        Arc::from("reversibility"),
        Value::String(effect.reversibility().as_str().into()),
    );
    Value::Map(Arc::new(map))
}

/// What reapplying the previous values would and would not restore (§46.5).
///
/// Two lists and a sentence, never a verdict: "recoverable" as one word is the claim §46.5
/// forbids, and the second list is the one an operator needs.
fn recovery(plan: &Plan) -> Value {
    let recovery = plan.recovery();
    let mut map = MapValue::new();
    map.insert(
        Arc::from("restores"),
        Value::List(
            recovery
                .restores()
                .iter()
                .map(|kind| Value::String(kind.as_str().into()))
                .collect(),
        ),
    );
    map.insert(
        Arc::from("does_not_restore"),
        Value::List(
            recovery
                .does_not_restore()
                .iter()
                .map(|kind| Value::String(kind.as_str().into()))
                .collect(),
        ),
    );
    map.insert(
        Arc::from("statement"),
        Value::String(recovery.describe().into()),
    );
    Value::Map(Arc::new(map))
}

/// One object that names the target as an owner, on owner-reference evidence alone (§24.1, §45.4).
fn dependent(dependent: &Dependent) -> Value {
    let identity = dependent.identity();
    let mut map = MapValue::new();
    map.insert(
        Arc::from("uid"),
        identity
            .uid()
            .map_or(Value::Null, |uid| Value::String(uid.into())),
    );
    map.insert(Arc::from("name"), Value::String(identity.name().into()));
    map.insert(
        Arc::from("kind"),
        Value::String(identity.gvk().kind().into()),
    );
    map.insert(
        Arc::from("controller"),
        Value::Bool(dependent.is_controller()),
    );
    map.insert(
        Arc::from("blocks_owner_deletion"),
        Value::Bool(dependent.blocks_owner_deletion()),
    );
    Value::Map(Arc::new(map))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "a test states its preconditions directly (AGENTS.md section 16)"
    )]

    use super::*;
    use serde_json::json;

    fn options(set: Json) -> JsonMap<String, Json> {
        let mut options = JsonMap::new();
        options.insert("set".to_owned(), set);
        options
    }

    #[test]
    fn should_read_a_quoted_json_document_as_the_mapping_it_spells() {
        // §43.3 and the example `package/contributions/commands.yaml` documents:
        // `--set '{"/spec/replicas": 2}'`. A shell hands that over as *text*, because a written
        // word is coerced only to a type it parses as, and a quoted document parses as a string.
        // The example was refused for exactly that reason until a demonstration ran it.
        let read = pointers(&options(json!(r#"{"/spec/replicas": 2}"#)))
            .expect("the documented spelling is the one that has to work");

        assert_eq!(read, vec![("/spec/replicas".to_owned(), json!(2))]);
    }

    #[test]
    fn should_read_a_record_the_shell_evaluated_as_the_same_mapping() {
        // The other spelling, which is what an Ono record literal becomes once the host coerces
        // it against the declared `record` type. Both reach the same plan, so which one a user
        // writes is a matter of taste rather than of capability.
        let read = pointers(&options(json!({"/spec/replicas": 2})))
            .expect("a record arrives as a mapping");

        assert_eq!(read, vec![("/spec/replicas".to_owned(), json!(2))]);
    }

    #[test]
    fn should_refuse_text_that_is_not_a_mapping_rather_than_guessing_at_it() {
        // A string that is not a document, and a document that is not a mapping, are both
        // refusals rather than an empty change: `set k8s-resource` with nothing to set would be
        // a write that reports success for having done nothing.
        for wrong in [json!("/spec/replicas"), json!("[1, 2]"), json!(3)] {
            assert!(
                pointers(&options(wrong.clone())).is_err(),
                "`{wrong}` is not a mapping from a pointer to a value"
            );
        }
    }
}

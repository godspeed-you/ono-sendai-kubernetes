//! A Kubernetes object, as the record a pipeline can work with.
//!
//! The input is always a [`Guarded`], never an [`Object`]: §22 and Gate I ask that a Secret's
//! payload be destroyed at the boundary rather than filtered on the way out, and the only way to
//! be sure of that at every call site is for there to be no other call site. A function taking an
//! `Object` here would be a second door into the emission path, and the whole point of the guard
//! is that there is one door.
//!
//! Two rules decide every field below.
//!
//! **Unknown is null.** An absent `spec.unschedulable` is null, not `false`; a `status` with no
//! `containerStatuses` is null restarts, not `0`. The API server's defaulting is the API server's
//! business, and repeating it here would report a fact the object never stated (§4, §10.5).
//!
//! **Nothing is derived that the object did not say.** `restarts` is the only sum, and it is a
//! sum of numbers the object carries; `ready` is a condition's `status` verbatim, never
//! translated into a boolean, because `True`, `False` and `Unknown` are three states and a
//! boolean has two.

use std::sync::Arc;

use ono_provider_kubernetes::discovery::Resource;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::redaction::Guarded;
use ono_value::{ErrorValue, MapValue, Provenance, RecordValue, Schema, Value, builtin_schemas};
use serde_json::Value as Json;

use crate::contributions::Target;
use crate::dynamic::{self, Typing};

/// Builds one record of `target`'s schema from a guarded object.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares. Both come from
/// [`crate::contributions::TARGETS`], so a failure means this crate's table and the schema built
/// from it have drifted apart — a bug here, never something a cluster can cause, and it is
/// returned rather than ignored so that a test sees it.
pub fn record(
    target: &Target,
    schema: &Arc<Schema>,
    guarded: &Guarded,
) -> Result<Value, ErrorValue> {
    let provenance = Provenance::local(crate::PACKAGE, schema.id().clone());
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance);
    for field in target.fields {
        builder = builder.set(field.name, field_value(field.name, guarded))?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// Builds one record of a resource this package has never heard of (§15.1, §33.1, Gate A).
///
/// The shared metadata is filled by exactly the same code the curated targets use, because §14's
/// projection is common to every Kubernetes object and a second copy of it would be a second
/// chance to disagree about what `terminating` means. What the discovered resource adds is what
/// only discovery and the cluster's schema can say: §13.2's type identity, how well the fields
/// are known, and the fields themselves.
///
/// **The record claims `io.github.godspeed-you.kubernetes.resource/1` whatever kind it holds.**
/// A record may only claim a schema its package contributed at load, and the contributions are
/// fixed before the package has spoken to a cluster — so a schema id naming the kind is not a
/// choice this package gets to make. The cost is that the Ono schema no longer distinguishes one
/// custom kind from another; the record carries `api_group`, `kind`, `resource_name` and `scope`
/// so that the *Kubernetes* type identity §13.2 requires survives that flattening. ADR-0010.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn dynamic_record(
    target: &Target,
    schema: &Arc<Schema>,
    resource: &Resource,
    typing: &Typing,
    guarded: &Guarded,
) -> Result<Value, ErrorValue> {
    let object = guarded.object();
    let projection = typing.project(object);
    let content = dynamic::content(&projection, object.native());
    let provenance = Provenance::local(crate::PACKAGE, schema.id().clone());
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance);
    for field in target.fields {
        let value = match field.name {
            // --- what this is: §13.2's canonical host type, which one shared schema would
            // otherwise lose ---
            "api_group" => Value::String(resource.group().into()),
            "resource_name" => Value::String(resource.plural().into()),
            "scope" => Value::String(dynamic::scope_word(resource.scope()).into()),

            // --- how well it is known (§12.3) ---
            "schema_source" => Value::String(typing.source().as_str().into()),
            "precision" => Value::String(content.precision.as_str().into()),

            // --- what it holds, with desired and observed kept apart (§4 invariant 8, §33.6) ---
            "spec" => content.desired.clone(),
            "status" => content.observed.clone(),
            "other" => content.other.clone(),
            "untyped" => Value::List(
                content
                    .untyped
                    .iter()
                    .map(|pointer| Value::String(pointer.as_str().into()))
                    .collect(),
            ),

            name => field_value(name, guarded),
        };
        builder = builder.set(field.name, value)?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// One field's value, by the name the schema declares it under.
///
/// A match on the name rather than a table of closures: the field list, the schema and this match
/// are read together, and a name in one that is missing here answers `Value::Null` — unknown,
/// which is exactly what a field nothing fills is.
fn field_value(name: &str, guarded: &Guarded) -> Value {
    let object = guarded.object();
    match name {
        // --- the metadata every object carries (§14) ---
        "uid" => text(object.uid()),
        "name" => Value::String(object.name().into()),
        "namespace" => text(object.namespace()),
        "api_version" => Value::String(api_version(object).into()),
        "kind" => Value::String(object.gvk().kind().into()),
        "resource_version" => text(object.resource_version()),
        "created" => timestamp(object.creation_timestamp()),
        "labels" => labels(object),
        "terminating" => Value::Bool(object.is_terminating()),

        // --- Namespace, and Pod ---
        "phase" => text(field_str(object, "/status/phase")),

        // --- Node ---
        "ready" => text(condition_status(object, "Ready")),
        "unschedulable" => field_bool(object, "/spec/unschedulable"),
        "kubelet_version" => text(field_str(object, "/status/nodeInfo/kubeletVersion")),
        "internal_ip" => text(node_address(object, "InternalIP")),

        // --- Pod ---
        "node" => text(field_str(object, "/spec/nodeName")),
        "pod_ip" => text(field_str(object, "/status/podIP")),
        "containers" => container_names(object),
        "restarts" => restarts(object),

        // --- Deployment ---
        "desired_replicas" => field_int(object, "/spec/replicas"),
        "ready_replicas" => field_int(object, "/status/readyReplicas"),
        "updated_replicas" => field_int(object, "/status/updatedReplicas"),
        "available_replicas" => field_int(object, "/status/availableReplicas"),
        "generation" => object.generation().map_or(Value::Null, integer),
        "observed_generation" => field_int(object, "/status/observedGeneration"),

        // --- Secret: metadata only, and by construction there is no payload to reach ---
        "secret_type" => text(guarded.secret().and_then(|secret| secret.secret_type())),
        "keys" => guarded.secret().map_or(Value::Null, |secret| {
            Value::List(
                secret
                    .keys()
                    .iter()
                    .map(|key| Value::String(key.as_str().into()))
                    .collect(),
            )
        }),

        _ => Value::Null,
    }
}

/// `apiVersion` as the object carries it: `v1` for the core group, `group/version` otherwise.
///
/// Reassembled from the GVK rather than read back out of the document, so that a list item the
/// transport typed from its envelope reports the same thing as one read on its own (§13.3).
fn api_version(object: &Object) -> String {
    let gvk = object.gvk();
    if gvk.group().is_empty() {
        gvk.version().to_owned()
    } else {
        format!("{}/{}", gvk.group(), gvk.version())
    }
}

/// Text, or null where there was none.
fn text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |text| Value::String(text.into()))
}

/// An integer, widened to the value model's width.
fn integer(value: i64) -> Value {
    Value::Int(i128::from(value))
}

/// An RFC 3339 instant, or null where there was none or it did not parse.
///
/// A timestamp this shell cannot read is unknown rather than an error: the object is still worth
/// showing, and inventing an instant for it would be worse than saying nothing.
fn timestamp(value: Option<&str>) -> Value {
    let Some(text) = value else {
        return Value::Null;
    };
    ono_value::from_json(&serde_json::json!({"$timestamp": text}), builtin_schemas())
        .unwrap_or(Value::Null)
}

/// `metadata.labels`, or null where the object carries none.
///
/// Empty and absent are folded together here, and only here: the API server omits `labels`
/// entirely for an object with none, so there is no observation that distinguishes them.
fn labels(object: &Object) -> Value {
    if object.labels().is_empty() {
        return Value::Null;
    }
    let map: MapValue = object
        .labels()
        .iter()
        .map(|(key, value)| {
            (
                Arc::from(key.as_str()),
                Value::String(value.as_str().into()),
            )
        })
        .collect();
    Value::Map(Arc::new(map))
}

/// A string field by JSON pointer.
fn field_str<'object>(object: &'object Object, pointer: &str) -> Option<&'object str> {
    object.field(pointer).and_then(Json::as_str)
}

/// An integer field by JSON pointer, null where absent or not a number.
fn field_int(object: &Object, pointer: &str) -> Value {
    object
        .field(pointer)
        .and_then(Json::as_i64)
        .map_or(Value::Null, integer)
}

/// A boolean field by JSON pointer, null where absent — never defaulted to `false`.
fn field_bool(object: &Object, pointer: &str) -> Value {
    object
        .field(pointer)
        .and_then(Json::as_bool)
        .map_or(Value::Null, Value::Bool)
}

/// The `status` of the named condition, verbatim.
///
/// `True`, `False` and `Unknown` are three states the API deliberately distinguishes; mapping
/// them onto a boolean would turn "the kubelet stopped reporting" into "not ready", which is a
/// different claim and a worse one (§21.4).
fn condition_status<'object>(object: &'object Object, condition: &str) -> Option<&'object str> {
    object
        .field("/status/conditions")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("type").and_then(Json::as_str) == Some(condition))?
        .get("status")?
        .as_str()
}

/// The first `status.addresses` entry of the given type.
fn node_address<'object>(object: &'object Object, kind: &str) -> Option<&'object str> {
    object
        .field("/status/addresses")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("type").and_then(Json::as_str) == Some(kind))?
        .get("address")?
        .as_str()
}

/// The names in `spec.containers`, in order.
///
/// Init and ephemeral containers are deliberately left out: they are different lifecycles, and a
/// single merged list would make a crash-looping init container look like an ordinary one.
fn container_names(object: &Object) -> Value {
    let Some(containers) = object.field("/spec/containers").and_then(Json::as_array) else {
        return Value::Null;
    };
    Value::List(
        containers
            .iter()
            .filter_map(|container| container.get("name")?.as_str())
            .map(|name| Value::String(name.into()))
            .collect(),
    )
}

/// The sum of every container's restart count, or null where the server sent no statuses.
///
/// Null rather than zero, because a pod whose status has not been written yet has not restarted
/// zero times — nobody has looked. Reporting `0` would turn missing evidence into a measurement,
/// which §4 forbids in one line.
fn restarts(object: &Object) -> Value {
    let Some(statuses) = object
        .field("/status/containerStatuses")
        .and_then(Json::as_array)
    else {
        return Value::Null;
    };
    let total: i64 = statuses
        .iter()
        .filter_map(|status| status.get("restartCount")?.as_i64())
        .sum();
    integer(total)
}

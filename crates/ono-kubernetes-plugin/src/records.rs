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

use std::collections::BTreeMap;
use std::sync::Arc;

use ono_provider_kubernetes::causal::{Finding, Support, Why};
use ono_provider_kubernetes::condition::{self, Condition};
use ono_provider_kubernetes::discovery::Resource;
use ono_provider_kubernetes::events::Event;
use ono_provider_kubernetes::evidence::{IdentityEvidence, NodeEvidence, Unobserved, key};
use ono_provider_kubernetes::logs::{LineText, LogLine, Retrieved};
use ono_provider_kubernetes::object::{Object, OwnerReference};
use ono_provider_kubernetes::place::Place;
use ono_provider_kubernetes::redaction::Guarded;
use ono_provider_kubernetes::relationship::{Edge, Relation};
use ono_provider_kubernetes::temporal::{ClockSource, Observation, Timeline};
use ono_provider_kubernetes::transport::{EndpointCategory, Freshness, Origin};
use ono_provider_kubernetes::workload::{Endpoint as WorkloadEndpoint, Workload};
use ono_value::{ErrorValue, MapValue, Provenance, RecordValue, Schema, Value, builtin_schemas};
use serde_json::Value as Json;

use crate::contributions::Target;
use crate::dynamic::{self, Typing};

/// The label by which an EndpointSlice says which Service it represents (§26.2).
///
/// Spelled here because the domain layer keeps it private: `workload.rs` uses it to build an edge
/// from a Service to its slices, which needs both objects, and a record built from one slice has
/// only the slice. The evidence class is the same one the edge carries — a *convention* rather
/// than API structure (§23.4), and the schema documentation says so.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

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
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        builder = builder.set(field.name, field_value(field.name, guarded))?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// Builds one record of one relationship, with the evidence it rests on (§23 to §32, Gate D).
///
/// The source's metadata comes from the same projection every other schema uses, so `uid`,
/// `name`, `namespace`, `api_version` and `kind` mean here exactly what they mean there: this
/// record is a fact *about* that object (ADR-0013). What the edge adds is the word, the far end
/// and the evidence, and the evidence is not optional in any of its three parts — the class, what
/// was read, and whether the API server states it or this provider derived it.
///
/// Both places are built by `place.rs` and handed in rather than formatted here (§35.4,
/// ADR-0008). That is what keeps a cluster-scoped target from acquiring the source's namespace,
/// and it is why the far end of an edge nobody has read is still an address (§24.1). They are
/// arguments because an address that cannot be built is a refusal the caller expresses in the
/// error vocabulary of the wire, which this function has no way to reach.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn edge_record(
    target: &Target,
    schema: &Arc<Schema>,
    here: &Place,
    there: &Place,
    source: &Guarded,
    edge: &Edge,
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let evidence = edge.evidence();
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        let value = match field.name {
            // --- what it is, in the vocabulary `follow` takes (§35.7) ---
            "relation" => Value::String(edge.relation().as_str().into()),

            // --- where it starts and where it points, as places (§35.4) ---
            "source" => Value::String(here.uri().to_string().into()),
            "target" => Value::String(there.uri().to_string().into()),
            "target_kind" => Value::String(edge.target().kind().into()),
            "target_name" => Value::String(edge.target().name().into()),
            // Null is cluster scope and never "wherever the source lives": a namespace copied
            // onto a cluster-scoped target would name an address nobody can look up (§9.2, §24.2).
            "target_namespace" => text(edge.target().namespace()),
            "target_uid" => text(edge.target().uid()),
            // §24.1: an edge whose far end nobody read is a relationship rather than a broken
            // edge, and the record says which of the two this is instead of hiding it.
            "target_resolved" => Value::Bool(edge.target().is_resolved()),
            // §36.1 and §36.2: the role overlay travels beside the native kind, never instead of
            // it. An empty list is a kind with no role, which is a statement rather than a gap.
            "target_roles" => Value::List(
                there
                    .roles()
                    .iter()
                    .map(|role| Value::String(role.as_str().into()))
                    .collect(),
            ),

            // --- why it exists: Gate D, in three fields that cannot be dropped ---
            "evidence_class" => Value::String(evidence.class().into()),
            "evidence" => Value::String(evidence.describe().into()),
            // Only the classes that rest on one field cite a pointer. Reporting one for a
            // selector evaluation would name a field as the proof when the proof is two objects.
            "evidence_path" => text(evidence.path()),
            // §23.3: the server states a selector and it states some labels, and it is *this*
            // provider that evaluated one against the other. §4 invariant 20 is the reason the
            // difference is a field rather than a footnote.
            "asserted" => Value::Bool(evidence.is_asserted_by_provider()),
            // What qualifies the edge without deciding it: the host, path and port §27.1
            // requires to stay attached, the adapter that read a custom resource (§33.8). Each
            // entry keeps its own class, because a supporting fact is checkable on the same terms
            // as a deciding one.
            "supporting" => Value::List(
                edge.supporting()
                    .iter()
                    .map(|support| {
                        Value::String(format!("{}: {}", support.class(), support.describe()).into())
                    })
                    .collect(),
            ),

            name => field_value(name, source),
        };
        builder = builder.set(field.name, value)?;
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
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let object = guarded.object();
    let projection = typing.project(object);
    let content = dynamic::content(&projection, object.native());
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
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

/// One observed change, as everything the record says about it (§19, §39.3, §41.4).
///
/// A struct rather than eight arguments because the fields are read together and their meanings
/// only make sense together: the word without the segment is a change nobody can place in time,
/// and the segment without `continuous` is a number nobody can act on.
pub struct Change<'a> {
    /// `listed`, `added`, `modified`, `deleted` or `gap`.
    pub class: &'a str,
    /// The REST collection being observed (§13.1), which is a GVR and never a GVK.
    pub resource: &'a str,
    /// What was asked about: one namespace, every namespace, or cluster scope (§9.4).
    pub scope: &'a str,
    /// Which unbroken period of observation this record belongs to, counting from one.
    pub segment: usize,
    /// Whether observation has been unbroken from the acquisition to this record (§19.4).
    pub continuous: bool,
    /// What a live view may honestly show right now (§41.4).
    pub sync_state: &'a str,
    /// Why continuity broke, for the record that reports a break.
    pub gap_reason: Option<&'a str>,
    /// The break with both of its edges, in the shape Appendix D.4 sketches.
    pub gap_detail: Option<String>,
    /// The object it happened to, absent for a gap — which is about a period, not an object.
    pub object: Option<&'a Guarded>,
}

/// Builds one record of one observed change, or of one period that was not observed (Gate F).
///
/// The object half goes through the same projection every other schema's does, so `uid`,
/// `name` and `resource_version` mean here what they mean everywhere (ADR-0013). What this adds
/// is the continuity, and it is required on every record rather than attached to the ones that
/// broke: a reader who has to look for a marker is a reader who will miss it, and §4 invariant 14
/// is precisely about the history that reads as continuous while a piece of it was never seen.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn change_record(
    target: &Target,
    schema: &Arc<Schema>,
    change: &Change<'_>,
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        let value = match field.name {
            // --- what happened, and where ---
            "change" => Value::String(change.class.into()),
            "resource" => Value::String(change.resource.into()),
            "scope" => Value::String(change.scope.into()),

            // --- which observation period, and what reaching it cost ---
            "segment" => integer(i64::try_from(change.segment).unwrap_or(i64::MAX)),
            "continuous" => Value::Bool(change.continuous),
            "sync_state" => Value::String(change.sync_state.into()),

            // --- what was not observed ---
            "gap_reason" => text(change.gap_reason),
            "gap_detail" => text(change.gap_detail.as_deref()),

            // --- the object, where the observation was about one. Null everywhere for a gap,
            // because a period nobody observed is exactly what is unknown about it. ---
            name => match change.object {
                Some(guarded) => field_value(name, guarded),
                None => Value::Null,
            },
        };
        builder = builder.set(field.name, value)?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// Builds one record of one Kubernetes Event (§38).
///
/// The Event's own metadata goes through the projection every other schema uses, because an Event
/// *is* an object (ADR-0013). What this adds is what §38 asks to survive: which representation it
/// was read from, who reported it, what it regards, and the *count* — as a count, on one record,
/// with `aggregate` saying that one record stands for more than one occurrence. There is no route
/// from here that turns 47 into 47 records.
///
/// Every time on the record is a string beside a `clock`. A timestamp field would be sortable,
/// and a set of Events sorted by time reads as a history it is not (§38.1, §39.2).
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn event_record(
    target: &Target,
    schema: &Arc<Schema>,
    guarded: &Guarded,
    event: &Event,
    regarding: Option<&Place>,
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let occurrences = event.occurrences();
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        let value = match field.name {
            "representation" => Value::String(event.representation().as_str().into()),

            // --- what the reporter said, as evidence and never as machine semantics (§38.5) ---
            "level" => Value::String(event.level().as_str().into()),
            "reason" => text(event.reason()),
            "note" => text(event.note()),
            "action" => text(event.action()),

            // --- what it is about (§38.3) ---
            "regarding" => regarding.map_or(Value::Null, |place| {
                Value::String(place.uri().to_string().into())
            }),
            "regarding_kind" => text(
                event
                    .regarding()
                    .map(ono_provider_kubernetes::relationship::Target::kind),
            ),
            "regarding_name" => text(
                event
                    .regarding()
                    .map(ono_provider_kubernetes::relationship::Target::name),
            ),
            "regarding_namespace" => text(
                event
                    .regarding()
                    .and_then(ono_provider_kubernetes::relationship::Target::namespace),
            ),
            "regarding_uid" => text(
                event
                    .regarding()
                    .and_then(ono_provider_kubernetes::relationship::Target::uid),
            ),
            "related" => text(
                event
                    .related()
                    .map(|target| format!("{}/{}", target.kind(), target.name()))
                    .as_deref(),
            ),

            // --- who said it, and from where (§38.3) ---
            "reporting_controller" => text(event.reporter().controller()),
            "reporting_instance" => text(event.reporter().instance()),

            // --- when, on whose clock (§39.1) ---
            "event_time" => text(event.event_time()),
            "clock" => Value::String(event_clock(event).to_string().into()),

            // --- how often, as a count (§38.4) ---
            "aggregate" => Value::Bool(occurrences.is_aggregate()),
            "recorded_count" => count(occurrences.recorded_count()),
            "series_count" => count(occurrences.series_count()),
            "series_last_observed" => text(occurrences.series_last_observed()),
            "first_seen" => text(occurrences.first_seen()),
            "last_seen" => text(occurrences.last_seen()),

            name => field_value(name, guarded),
        };
        builder = builder.set(field.name, value)?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// Which machine's clock wrote an Event's `eventTime` (§38.3, §39.1).
///
/// The reporting controller where the Event names one, and [`ClockSource::Unattributed`] where it
/// does not — never this provider's clock, which never saw the occurrence.
fn event_clock(event: &Event) -> ClockSource {
    event
        .reporter()
        .controller()
        .map_or(ClockSource::Unattributed, |controller| {
            ClockSource::Reporter(controller.to_owned())
        })
}

/// One row of a Node's exported evidence: a value that was read, or a key that was not (§47).
pub enum Exported<'a> {
    /// A value the Node states, with where it was read and how far it goes.
    Observed(&'a IdentityEvidence),
    /// A key that could not be read, and whether that is about the cluster or about the read.
    Unobserved(&'a Unobserved),
}

/// Builds one record of one exported identity fact (§28.3–§28.5, §47, ADR-0016).
///
/// **Nothing built here presents a match.** The record carries what the API server stated, the
/// pointer it stated it at, the evidence class and the strength — and there is no field for a
/// foreign resource, because this provider has read Kubernetes and nothing else (§47.1). §28.4's
/// whole permitted decomposition is `uri_scheme` and `uri_path`; no segment is labelled, because
/// labelling one is the vendor policy §28.4 forbids arriving one match arm at a time.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn evidence_record(
    target: &Target,
    schema: &Arc<Schema>,
    here: &Place,
    node: &Guarded,
    evidence: &NodeEvidence,
    exported: &Exported<'_>,
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let item = match exported {
        Exported::Observed(item) => Some(*item),
        Exported::Unobserved(_) => None,
    };
    // §28.4's decomposition belongs to the one key that is a URI-shaped identifier, and to no
    // other. An address decomposed as a URI would be a shape nobody stated.
    let shape = item
        .filter(|item| item.key() == key::PROVIDER_ID)
        .and_then(|_| evidence.provider_id())
        .and_then(ono_provider_kubernetes::evidence::ProviderId::shape);
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        let value = match field.name {
            "subject" => Value::String(here.uri().to_string().into()),

            // --- what kind of fact, and what it held ---
            "key" => Value::String(
                match exported {
                    Exported::Observed(item) => item.key(),
                    Exported::Unobserved(gap) => gap.key(),
                }
                .into(),
            ),
            "qualifier" => text(item.and_then(IdentityEvidence::qualifier)),
            "value" => text(item.map(IdentityEvidence::value)),
            "source" => text(item.map(IdentityEvidence::source)),

            // --- how far it goes (§47.2) ---
            "strength" => item.map_or(Value::Null, |item| {
                Value::String(item.strength().as_str().into())
            }),
            "evidence_class" => item.map_or(Value::Null, |item| {
                Value::String(item.evidence().class().into())
            }),
            "evidence" => item.map_or(Value::Null, |item| {
                Value::String(item.evidence().describe().into())
            }),
            "asserted" => item.map_or(Value::Null, |item| {
                Value::Bool(item.evidence().is_asserted_by_provider())
            }),
            "lookup_key" => item.map_or(Value::Null, |item| Value::Bool(item.is_lookup_key())),

            // --- §28.4, as far as it goes and no further ---
            "uri_scheme" => text(shape.map(ono_provider_kubernetes::evidence::UriShape::scheme)),
            "uri_path" => text(shape.map(ono_provider_kubernetes::evidence::UriShape::path)),

            // --- or a key nobody read, which is not a machine with nothing to say (§4 inv. 13) ---
            "observed" => Value::Bool(item.is_some()),
            "outcome" => match exported {
                Exported::Observed(_) => Value::Null,
                Exported::Unobserved(gap) => Value::String(gap.outcome().as_str().into()),
            },

            name => field_value(name, node),
        };
        builder = builder.set(field.name, value)?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// One line of a retrieved log, with what the retrieval as a whole was (§42.1).
pub struct Line<'a> {
    /// The Pod the log was read from, for the metadata every record here shares.
    pub pod: &'a Guarded,
    /// What was read, what from, and everything that was cut off first.
    pub retrieved: &'a Retrieved,
    /// This line.
    pub line: &'a LogLine,
    /// Which line of this retrieval it is, counting from one.
    pub ordinal: usize,
    /// The clock that wrote the line's timestamp prefix, where the server wrote one.
    pub clock: &'a ClockSource,
}

/// Builds one record of one log line (§42.1, §42.2).
///
/// **`bounds` is on every record and is never empty.** The container runtime rotated and
/// truncated this log before anybody asked, so the answer is short of the container's output
/// whatever the request said — and a record that omitted the bounds would imply completeness by
/// saying nothing, which is the reading §42.1 exists to prevent.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn log_record(
    target: &Target,
    schema: &Arc<Schema>,
    line: &Line<'_>,
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let retrieved = line.retrieved;
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        let value = match field.name {
            "container" => text(retrieved.target().container()),
            "instance" => Value::String(retrieved.instance().as_str().into()),

            // --- the line, as bytes first and as text only where it is text ---
            "line" => integer(i64::try_from(line.ordinal).unwrap_or(i64::MAX)),
            "text" => match line.line.text() {
                LineText::Utf8(text) => Value::String(text.into()),
                LineText::NotUtf8 { .. } => Value::Null,
            },
            "bytes" => integer(i64::try_from(line.line.bytes().len()).unwrap_or(i64::MAX)),
            "not_utf8_after" => match line.line.text() {
                LineText::Utf8(_) => Value::Null,
                LineText::NotUtf8 { valid_up_to } => {
                    integer(i64::try_from(valid_up_to).unwrap_or(i64::MAX))
                }
            },
            // A string beside its clock, never an instant: the prefix is the container runtime's
            // time on the node, and parsing it would make it sortable against this provider's own
            // observations (§39.2).
            "stamp" => text(line.line.stamp()),
            "clock" => Value::String(line.clock.to_string().into()),
            "terminated" => Value::Bool(line.line.is_terminated()),

            // --- and what this is not (§42.1) ---
            "bounds" => Value::List(
                retrieved
                    .bounds()
                    .iter()
                    .map(|bound| Value::String(bound.describe().into()))
                    .collect(),
            ),
            "ending" => Value::String(retrieved.ending().describe().into()),
            "may_contain_secrets" => Value::Bool(retrieved.may_contain_secrets()),

            name => field_value(name, line.pod),
        };
        builder = builder.set(field.name, value)?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// Builds one record of one temporal observation, with the window it was made in (§39).
///
/// **The window and the gaps are on every record.** A stream of observations with the window on a
/// summary somebody may not read is a stream a reader takes for a complete history, and §39.3 is
/// precisely about the periods that are missing from one.
///
/// **`stamp` is a string and `clock` is beside it.** The two together are §39.2 as a record shape:
/// there is no field a shell can sort into a cross-clock timeline, because the raw string of one
/// clock and the raw string of another are not comparable and nothing here pretends they are.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn observation_record(
    target: &Target,
    schema: &Arc<Schema>,
    subject: &Guarded,
    observation: &Observation,
    timeline: &Timeline,
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let window = timeline.window();
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        let value = match field.name {
            // --- what kind of observation, and whose clock (§39.1, §39.2) ---
            "basis" => Value::String(observation.basis().as_str().into()),
            "source" => Value::String(observation.source().as_str().into()),
            "clock" => Value::String(observation.stamp().source().to_string().into()),
            "stamp" => Value::String(observation.stamp().raw().into()),
            "placeable" => Value::Bool(observation.stamp().is_placeable()),
            "detail" => Value::String(observation.detail().into()),

            // --- the period it belongs to, and both kinds of hole in it (§19.4, §39.3, §21.4) ---
            "window_opened" => instant(window.opened_at().unix_millis()),
            "window_latest" => instant(window.latest_at().unix_millis()),
            "continuous" => Value::Bool(timeline.is_continuous()),
            "gaps" => Value::List(
                timeline
                    .gaps()
                    .iter()
                    .map(|gap| Value::String(gap.describe().into()))
                    .collect(),
            ),
            "not_observed" => Value::List(
                timeline
                    .coverage()
                    .gaps()
                    .iter()
                    .map(|gap| Value::String(gap.describe().into()))
                    .collect(),
            ),

            name => field_value(name, subject),
        };
        builder = builder.set(field.name, value)?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// Builds one record of one causal finding, and of the rung it stops at (§40).
///
/// **There is no field for a cause.** `claim` is one of five words, none of which says that one
/// thing brought about another, and `claim_means` carries where the word stops — because a token
/// on its own is read as strongly as its reader needs it to be. `strongest_claim` is the ceiling
/// of the whole answer on every record, so a reader who sees one finding still sees the limit.
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn finding_record(
    target: &Target,
    schema: &Arc<Schema>,
    subject: &Guarded,
    finding: &Finding,
    why: &Why,
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let support = finding.support();
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        let value = match field.name {
            "claim" => Value::String(finding.claim().as_str().into()),
            "claim_means" => Value::String(finding.claim().means().into()),

            "support_class" => Value::String(support_class(support).into()),
            "support" => Value::String(support.describe().into()),
            "not_proven" => match support {
                Support::Nothing(unproven) => Value::String(unproven.as_str().into()),
                Support::Sequence { .. } | Support::Path(_) | Support::Assertion { .. } => {
                    Value::Null
                }
            },
            // A distance exists only where one clock wrote both, which is why the two travel
            // together and why both are null for everything else (§39.2).
            "clock" => match support {
                Support::Sequence { clock, .. } => Value::String(clock.to_string().into()),
                _ => Value::Null,
            },
            "apart_ms" => match support {
                Support::Sequence { apart_millis, .. } => {
                    integer(i64::try_from(*apart_millis).unwrap_or(i64::MAX))
                }
                _ => Value::Null,
            },
            "evidence_class" => match support {
                Support::Assertion { evidence, .. } => Value::String(evidence.class().into()),
                _ => Value::Null,
            },
            "evidence_path" => match support {
                Support::Assertion { evidence, .. } => text(evidence.path()),
                _ => Value::Null,
            },

            // --- the ceiling, and what the search could not reach (§40.5, §21.4) ---
            "strongest_claim" => Value::String(why.strongest_claim().as_str().into()),
            "insufficient_evidence" => Value::Bool(why.is_insufficient()),
            "not_observed" => Value::List(
                why.coverage()
                    .gaps()
                    .iter()
                    .map(|gap| Value::String(gap.describe().into()))
                    .collect(),
            ),

            name => field_value(name, subject),
        };
        builder = builder.set(field.name, value)?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// Which of the four shapes of support a finding rests on.
///
/// A word of its own rather than something a reader infers from which fields are null, because
/// "no support" and "support this build did not render" would otherwise look the same.
fn support_class(support: &Support) -> &'static str {
    match support {
        Support::Sequence { .. } => "sequence",
        Support::Path(_) => "path",
        Support::Assertion { .. } => "assertion",
        Support::Nothing(_) => "nothing",
    }
}

/// Builds one record of one condition (§37.1).
///
/// **`observedGeneration` arrives as a number and never as a verdict.** The only derived state on
/// the record is the `reconciliation` map, which carries the rule that produced it and the fields
/// that rule read, and whose `verified_convergence` key is true for exactly one of five states —
/// never for `generation-observed-only`, which is what a matching `observedGeneration` on its own
/// establishes (§37.3, §37.5).
///
/// # Errors
///
/// [`ErrorValue`] when a field name is not one the schema declares — a drift between this crate's
/// table and the schema built from it, never something a cluster can cause.
pub fn condition_record(
    target: &Target,
    schema: &Arc<Schema>,
    subject: &Guarded,
    condition: &Condition,
    freshness: &Freshness,
) -> Result<Value, ErrorValue> {
    let object = subject.object();
    let mut builder = RecordValue::builder(Arc::clone(schema), provenance(schema, freshness));
    for field in target.fields {
        let value = match field.name {
            "condition_type" => Value::String(condition.type_name().into()),
            // The string the API carries. `True`, `False` and `Unknown` are three states, a
            // controller may write a fourth, and a boolean has two (§37.2).
            "status" => Value::String(condition.status().as_str().into()),
            "reason" => text(condition.reason()),
            "message" => text(condition.message()),
            "observed_generation" => count_i64(condition.observed_generation()),
            "generation" => count_i64(object.generation()),
            "last_transition_time" => text(condition.last_transition_time()),
            // `status.conditions` does not say which controller wrote the entry, so the clock is
            // nobody's in particular and two conditions must not be ordered against each other.
            "clock" => Value::String(ClockSource::Unattributed.to_string().into()),
            "reconciliation" => reconciliation(object),

            name => field_value(name, subject),
        };
        builder = builder.set(field.name, value)?;
    }
    Ok(Value::Record(Arc::new(builder.build())))
}

/// An unsigned count the object stated, or null where it stated none.
fn count(value: Option<u64>) -> Value {
    value.map_or(Value::Null, |count| {
        integer(i64::try_from(count).unwrap_or(i64::MAX))
    })
}

/// A signed count the object stated, or null where it stated none.
fn count_i64(value: Option<i64>) -> Value {
    value.map_or(Value::Null, integer)
}

/// The record's provenance, carrying what §17.1 requires a read to state about itself.
///
/// §17.1 asks a read to carry six things. `resourceVersion` is a field of the record, because it
/// is a fact about the object. The other five — when it was observed, which provider instance
/// asked, which scope was asked about, which REST surface answered, and whether this was a
/// direct read or something a cache remembered — are facts about the *observation*, and the
/// value model already has a place for those. Putting them in provenance rather than in five
/// more schema fields means `inspect` shows them for every kind without each schema repeating
/// them, and it keeps the record's fields about the Kubernetes object.
///
/// The host overwrites `provider` on the way through, because a package may not forge where a
/// record came from (§31.80 of core's specification). It leaves `observed` and `source` alone,
/// which is why they are the two this function fills.
fn provenance(schema: &Arc<Schema>, freshness: &Freshness) -> Provenance {
    let stated = Provenance::local(crate::PACKAGE, schema.id().clone()).from_source(&format!(
        "provider_instance={} origin={} scope={} endpoint={} resource_version={}",
        freshness.provider_instance(),
        origin_word(freshness.origin()),
        freshness.scope(),
        endpoint_word(freshness.endpoint()),
        freshness.resource_version().unwrap_or("unknown"),
    ));
    match instant(freshness.observed_at().unix_millis()) {
        Value::Timestamp(observed) => stated.observed_at(observed),
        // An instant this shell cannot build is unknown rather than fabricated: a wrong
        // observation time is worse than none, because the freshness of a read is what a reader
        // decides how much to trust it by (§20.2).
        _ => stated,
    }
}

/// How this provider came by the object (§20.2), in the word a reader sees.
fn origin_word(origin: Origin) -> &'static str {
    match origin {
        Origin::DirectRead => "direct-read",
        Origin::Cache => "cache",
        Origin::WatchEvent => "watch-event",
    }
}

/// Which REST surface answered — §17.1's source endpoint category.
fn endpoint_word(endpoint: EndpointCategory) -> &'static str {
    match endpoint {
        EndpointCategory::Core => "core",
        EndpointCategory::Group => "group",
    }
}

/// A Unix millisecond instant, as the value model's timestamp.
///
/// Rendered as RFC 3339 and parsed back, because the value model builds a timestamp from text
/// and this package has no date library of its own. The rendering is proleptic-Gregorian UTC,
/// which is the calendar RFC 3339 defines and the one the API server's own timestamps are in.
fn instant(unix_millis: u64) -> Value {
    ono_value::from_json(
        &serde_json::json!({"$timestamp": rfc3339(unix_millis)}),
        builtin_schemas(),
    )
    .unwrap_or(Value::Null)
}

/// A Unix millisecond instant as RFC 3339 text in UTC.
fn rfc3339(unix_millis: u64) -> String {
    let seconds = i64::try_from(unix_millis / 1000).unwrap_or(i64::MAX);
    let millis = unix_millis % 1000;
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let time = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60,
    )
}

/// The civil date a count of days since 1970-01-01 names, in the proleptic Gregorian calendar.
///
/// Howard Hinnant's `civil_from_days`, which is exact for every day a 64-bit count can hold and
/// needs no table. It is here rather than in a dependency because the only thing this package
/// needs a calendar for is rendering one instant it already holds as a number.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Shift the epoch to 0000-03-01, so that the leap day is the last day of the year and the
    // month arithmetic below has no special case in it.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
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
        "labels" => string_map(object.labels()),
        // §14.5: a structured map beside `labels`, never one flattened string. The two carry
        // different intents — a label selects, an annotation records — and both are read one key
        // at a time, which text does not allow.
        "annotations" => string_map(object.annotations()),
        "terminating" => Value::Bool(object.is_terminating()),
        // §14.6, the other half of `terminating`. A deletion that was accepted completes when the
        // last finalizer clears, so an object that is terminating and holds finalizers is being
        // held by something namable rather than being slow (Gate H).
        "finalizers" => string_list(object.finalizers()),
        // §14.6's references, whole. The `controller` and `blockOwnerDeletion` flags are what
        // make an owner reference more than a name, and a list of names would drop both.
        "owner_references" => owner_references(object),
        // §14.7's summary rather than `managedFields` itself: the distinct managers, sorted. The
        // structure stays reachable through `k8s-resource`, which projects the whole object.
        "field_managers" => string_list(object.field_managers()),

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

        // --- the workload controllers, and Job: where an object stands between what was asked
        // of it and what has been observed (§37.5, Gate G) ---
        "reconciliation" => reconciliation(object),

        // --- ReplicaSet, StatefulSet ---
        "current_replicas" => field_int(object, "/status/replicas"),

        // --- ReplicaSet, Job: the controller above this object (§24.3, §25.2, §25.5) ---
        "controller" => text(controller(object).map(OwnerReference::name)),
        "controller_kind" => text(controller(object).map(OwnerReference::kind)),

        // --- StatefulSet (§25.3) ---
        "service_name" => service_name(object),
        "current_revision" => text(field_str(object, "/status/currentRevision")),
        "update_revision" => text(field_str(object, "/status/updateRevision")),
        "claim_templates" => claim_templates(object),

        // --- DaemonSet: counted per node, which is why none of these is a replica (§25.4) ---
        "desired_scheduled" => field_int(object, "/status/desiredNumberScheduled"),
        "current_scheduled" => field_int(object, "/status/currentNumberScheduled"),
        "ready_scheduled" => field_int(object, "/status/numberReady"),
        "updated_scheduled" => field_int(object, "/status/updatedNumberScheduled"),
        "available_scheduled" => field_int(object, "/status/numberAvailable"),
        "misscheduled" => field_int(object, "/status/numberMisscheduled"),

        // --- Service (§26.1, §26.5, §31.4) ---
        "service_type" => text(field_str(object, "/spec/type")),
        "cluster_ip" => text(field_str(object, "/spec/clusterIP")),
        "external_ips" => strings(object, "/spec/externalIPs"),
        "external_name" => text(field_str(object, "/spec/externalName")),
        "selector" => map_field(object, "/spec/selector"),

        // --- Service and Ingress: the addresses the outside world reaches them at ---
        "load_balancer" => load_balancer(object),

        // --- Service and EndpointSlice (§26.5, §31.4) ---
        "ports" => ports(object),

        // --- EndpointSlice (§26.2, §26.4) ---
        "address_type" => text(field_str(object, "/addressType")),
        "endpoint_count" => endpoint_count(object, |_| true),
        "ready_endpoints" => endpoint_count(object, |endpoint| endpoint.is_ready() == Some(true)),
        "addresses" => endpoint_addresses(object),
        "targets" => endpoint_targets(object),

        // --- Ingress (§27.1, §27.2) ---
        "ingress_class" => text(
            routed(object, Relation::UsesIngressClass)
                .first()
                .map(String::as_str),
        ),
        "hosts" => ingress_hosts(object),
        "services" => list(routed(object, Relation::RoutesTo)),
        "tls_secrets" => list(routed(object, Relation::UsesTlsSecret)),

        // --- Job (§25.5) ---
        "completions" => field_int(object, "/spec/completions"),
        "parallelism" => field_int(object, "/spec/parallelism"),
        "active" => field_int(object, "/status/active"),
        "succeeded" => field_int(object, "/status/succeeded"),
        "failed" => field_int(object, "/status/failed"),
        "start_time" => timestamp(field_str(object, "/status/startTime")),
        "completion_time" => timestamp(field_str(object, "/status/completionTime")),
        "complete" => text(condition_status(object, "Complete")),
        "failure_reason" => text(condition_reason(object, "Failed")),

        // --- CronJob (§25.5) ---
        "schedule" => text(field_str(object, "/spec/schedule")),
        "suspend" => field_bool(object, "/spec/suspend"),
        "concurrency_policy" => text(field_str(object, "/spec/concurrencyPolicy")),
        "last_schedule_time" => timestamp(field_str(object, "/status/lastScheduleTime")),
        "last_successful_time" => timestamp(field_str(object, "/status/lastSuccessfulTime")),
        "active_jobs" => names_at(object, "/status/active"),

        // --- ConfigMap (§29.4) ---
        "binary_keys" => data_keys(object, "/binaryData"),
        "immutable" => field_bool(object, "/immutable"),

        // --- ServiceAccount (§32.1) ---
        "secrets" => names_at(object, "/secrets"),
        "image_pull_secrets" => names_at(object, "/imagePullSecrets"),
        "automount_token" => field_bool(object, "/automountServiceAccountToken"),

        // --- storage (§30) ---
        "volume_name" => text(field_str(object, "/spec/volumeName")),
        "storage_class" => text(field_str(object, "/spec/storageClassName")),
        "volume_mode" => text(field_str(object, "/spec/volumeMode")),
        "access_modes" => strings(object, "/spec/accessModes"),
        "requested_storage" => text(field_str(object, "/spec/resources/requests/storage")),
        "bound_capacity" => text(field_str(object, "/status/capacity/storage")),
        "capacity" => text(field_str(object, "/spec/capacity/storage")),
        // A PersistentVolume states it under `spec`, a StorageClass at the top level. One field
        // because it is one question — what happens to the storage when the object is released
        // (§30.5) — and no object carries both pointers.
        "reclaim_policy" => text(
            field_str(object, "/spec/persistentVolumeReclaimPolicy")
                .or_else(|| field_str(object, "/reclaimPolicy")),
        ),
        "claim" => claim(object),
        "csi_driver" => text(field_str(object, "/spec/csi/driver")),
        "provisioner" => text(field_str(object, "/provisioner")),
        "volume_binding_mode" => text(field_str(object, "/volumeBindingMode")),
        "allow_volume_expansion" => field_bool(object, "/allowVolumeExpansion"),
        "is_default" => is_default_storage_class(object),
        "parameters" => map_field(object, "/parameters"),

        // --- NetworkPolicy (§31.1, §31.2) ---
        "pod_selector" => map_field(object, "/spec/podSelector"),
        "policy_types" => strings(object, "/spec/policyTypes"),
        "rules" => policy_rules(object),

        // --- Secret and ConfigMap: key names only, and for a Secret there is by construction
        // no payload left to reach ---
        "secret_type" => text(guarded.secret().and_then(|secret| secret.secret_type())),
        "keys" => match guarded.secret() {
            Some(secret) => Value::List(
                secret
                    .keys()
                    .iter()
                    .map(|key| Value::String(key.as_str().into()))
                    .collect(),
            ),
            None => data_keys(object, "/data"),
        },

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

/// A `metadata` string map — `labels` or `annotations` — or null where the object carries none.
///
/// Empty and absent are folded together here, and only here: the API server omits the key
/// entirely for an object with none, so there is no observation that distinguishes them.
fn string_map(entries: &BTreeMap<String, String>) -> Value {
    if entries.is_empty() {
        return Value::Null;
    }
    let map: MapValue = entries
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

/// A list of strings the projection already holds, or null where it holds none.
///
/// Null for the same reason [`string_map`] is: the API server omits `finalizers` and
/// `managedFields` entirely rather than sending them empty, so "none" and "not stated" are one
/// observation and inventing an empty list would be the more precise of two readings.
fn string_list(entries: &[String]) -> Value {
    if entries.is_empty() {
        return Value::Null;
    }
    Value::List(
        entries
            .iter()
            .map(|entry| Value::String(entry.as_str().into()))
            .collect(),
    )
}

/// `metadata.ownerReferences`, each whole, or null where the object states none (§14.6).
///
/// A map per reference rather than a name per reference. `controller` is what §24.3 turns into
/// the difference between `owned-by` and `controlled-by`, and `blockOwnerDeletion` is what
/// decides whether the owner's deletion waits — neither survives a list of names. The keys are
/// spelled as this package spells every other field, so `api_version` here means what
/// `api_version` means on the record itself (ADR-0013).
fn owner_references(object: &Object) -> Value {
    let references = object.owner_references();
    if references.is_empty() {
        return Value::Null;
    }
    Value::List(
        references
            .iter()
            .map(|owner| {
                let mut map = MapValue::new();
                map.insert(
                    Arc::from("api_version"),
                    Value::String(owner.api_version().into()),
                );
                map.insert(Arc::from("kind"), Value::String(owner.kind().into()));
                map.insert(Arc::from("name"), Value::String(owner.name().into()));
                map.insert(Arc::from("uid"), Value::String(owner.uid().into()));
                map.insert(Arc::from("controller"), Value::Bool(owner.is_controller()));
                map.insert(
                    Arc::from("block_owner_deletion"),
                    Value::Bool(owner.blocks_owner_deletion()),
                );
                Value::Map(Arc::new(map))
            })
            .collect(),
    )
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

// --- the fields the domain layer answers, rather than this module reading them again -----------

/// Where the object stands between desired and observed state, with its rule and its evidence.
///
/// `condition::reconciliation` is the whole of the derivation; this function only turns its
/// answer into a value. §37.5 requires the state to arrive with the fields it rests on, so the
/// citations travel with it, and §37.3's rule — that a matching `observedGeneration` is not a
/// claim of health — survives as `verified_convergence`, which is true for exactly one of the
/// five states and never for `generation-observed-only`.
///
/// `stage` is §20.4's ladder: how far the evidence reaches. It is null where the evidence
/// establishes nothing, and it is never `workload externally healthy`, which no API read can
/// establish.
fn reconciliation(object: &Object) -> Value {
    let derived = condition::reconciliation(object);
    let mut map = MapValue::new();
    map.insert(
        Arc::from("state"),
        Value::String(derived.state().as_str().into()),
    );
    map.insert(Arc::from("rule"), Value::String(derived.rule().into()));
    map.insert(
        Arc::from("verified_convergence"),
        Value::Bool(derived.state().is_verified_convergence()),
    );
    map.insert(
        Arc::from("stage"),
        derived
            .state()
            .established_stage()
            .map_or(Value::Null, |stage| Value::String(stage.as_str().into())),
    );
    map.insert(
        Arc::from("evidence"),
        Value::List(
            derived
                .citations()
                .iter()
                .map(|citation| Value::String(citation.to_string().into()))
                .collect(),
        ),
    );
    Value::Map(Arc::new(map))
}

/// The owner reference that names this object's controller, where one does (§24.3).
fn controller(object: &Object) -> Option<&OwnerReference> {
    object
        .owner_references()
        .iter()
        .find(|owner| owner.is_controller())
}

/// The Service this object belongs to, by whichever evidence its kind offers.
///
/// A StatefulSet states it as a field — `spec.serviceName`, §25.3's governing Service, which the
/// domain layer turns into an edge with that field as its evidence. An EndpointSlice states it as
/// the standard label instead (§26.2), which is *convention* evidence: an operator can relabel a
/// slice, and this field is therefore weaker than the StatefulSet's. Both are recorded, and the
/// schema documentation says which is which rather than the record pretending they are one class
/// of evidence (§23, Gate D).
fn service_name(object: &Object) -> Value {
    if let Some(edge) = Workload::governing_service(object) {
        return Value::String(edge.target().name().into());
    }
    text(object.label(SERVICE_NAME_LABEL))
}

/// The names of the claim templates a StatefulSet declares (§25.3).
///
/// Template intent, and never a list of PersistentVolumeClaims that exist: the specification
/// requires the two to stay distinguishable, and the domain layer keeps them apart by giving the
/// templates a type of their own rather than an edge.
fn claim_templates(object: &Object) -> Value {
    let templates = Workload::volume_claim_templates(object);
    if templates.is_empty() {
        return Value::Null;
    }
    Value::List(
        templates
            .iter()
            .map(|template| Value::String(template.name().into()))
            .collect(),
    )
}

/// The names an Ingress's routing edges point at, for one relation (§27.1, §27.2).
fn routed(object: &Object, relation: Relation) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for edge in Workload::ingress_edges(object) {
        if edge.relation() == relation && !names.iter().any(|seen| seen == edge.target().name()) {
            names.push(edge.target().name().to_owned());
        }
    }
    names
}

/// The hosts an Ingress answers for, in the order it lists its rules (§27.1).
fn ingress_hosts(object: &Object) -> Value {
    let Some(rules) = object.field("/spec/rules").and_then(Json::as_array) else {
        return Value::Null;
    };
    let mut hosts: Vec<String> = Vec::new();
    for rule in rules {
        if let Some(host) = rule.get("host").and_then(Json::as_str)
            && !hosts.iter().any(|seen| seen == host)
        {
            hosts.push(host.to_owned());
        }
    }
    list(hosts)
}

/// How many of a slice's endpoints satisfy `wanted` (§26.2).
fn endpoint_count(object: &Object, wanted: impl Fn(&WorkloadEndpoint) -> bool) -> Value {
    let endpoints = Workload::endpoints(object);
    if endpoints.is_empty() && object.field("/endpoints").is_none() {
        // No `endpoints` array at all is a kind that has none, not a slice with zero of them.
        return Value::Null;
    }
    integer(i64::try_from(endpoints.iter().filter(|e| wanted(e)).count()).unwrap_or(i64::MAX))
}

/// Every address a slice's endpoints serve, in the slice's own order (§26.2).
fn endpoint_addresses(object: &Object) -> Value {
    let endpoints = Workload::endpoints(object);
    if endpoints.is_empty() {
        return Value::Null;
    }
    Value::List(
        endpoints
            .iter()
            .flat_map(|endpoint| endpoint.addresses())
            .map(|address| Value::String(address.as_str().into()))
            .collect(),
    )
}

/// The objects behind a slice's endpoints, where `targetRef` names one (§26.2, §26.4).
///
/// An endpoint with no target reference contributes nothing rather than a placeholder: §26.4
/// keeps an external address an endpoint fact instead of forcing it into a Pod relationship, and
/// a blank entry in this list would be exactly that forcing.
fn endpoint_targets(object: &Object) -> Value {
    let endpoints = Workload::endpoints(object);
    if endpoints.is_empty() {
        return Value::Null;
    }
    Value::List(
        endpoints
            .iter()
            .filter_map(|endpoint| endpoint.pod_edge())
            .map(|edge| Value::String(edge.target().name().into()))
            .collect(),
    )
}

// --- plain field projections -------------------------------------------------------------------

/// The ports an object declares, keyed by name where it names them (§26.5, §31.4).
///
/// A Service states them under `spec`, an EndpointSlice at the top level. Structured rather than
/// flattened into text, because §31.4 asks for fields a later layer can relate to a local socket
/// or a cloud load balancer, and `"http 80/TCP"` is not one.
fn ports(object: &Object) -> Value {
    let entries = object
        .field("/spec/ports")
        .or_else(|| object.field("/ports"))
        .and_then(Json::as_array);
    let Some(entries) = entries else {
        return Value::Null;
    };
    let mut map = MapValue::new();
    for (index, entry) in entries.iter().enumerate() {
        let key = entry
            .get("name")
            .and_then(Json::as_str)
            .map(str::to_owned)
            .or_else(|| entry.get("port").map(std::string::ToString::to_string))
            .unwrap_or_else(|| index.to_string());
        map.insert(Arc::from(key.as_str()), json_value(entry));
    }
    Value::Map(Arc::new(map))
}

/// The addresses a load balancer answers on, from `status.loadBalancer.ingress` (§26.5, §27.1).
///
/// An entry states an `ip` or a `hostname` and occasionally both; whichever it states is what is
/// recorded, and an entry that states neither contributes nothing rather than an empty string.
fn load_balancer(object: &Object) -> Value {
    let Some(entries) = object
        .field("/status/loadBalancer/ingress")
        .and_then(Json::as_array)
    else {
        return Value::Null;
    };
    Value::List(
        entries
            .iter()
            .filter_map(|entry| {
                entry
                    .get("ip")
                    .or_else(|| entry.get("hostname"))
                    .and_then(Json::as_str)
            })
            .map(|address| Value::String(address.into()))
            .collect(),
    )
}

/// The claim holding a volume, as `namespace/name` (§30.2).
fn claim(object: &Object) -> Value {
    let Some(reference) = object.field("/spec/claimRef") else {
        return Value::Null;
    };
    let Some(name) = reference.get("name").and_then(Json::as_str) else {
        return Value::Null;
    };
    match reference.get("namespace").and_then(Json::as_str) {
        Some(namespace) => Value::String(format!("{namespace}/{name}").into()),
        None => Value::String(name.into()),
    }
}

/// Whether the cluster treats this StorageClass as its default (§30.3).
///
/// The annotation is the only place Kubernetes states it, and its absence is *not* `false`: a
/// class that has never carried the annotation and one that carries `"false"` are the same state
/// as far as provisioning goes, and both are stated rather than one being inferred.
fn is_default_storage_class(object: &Object) -> Value {
    object
        .annotation("storageclass.kubernetes.io/is-default-class")
        .map_or(Value::Null, |value| Value::Bool(value == "true"))
}

/// A NetworkPolicy's rules, in the structure the API states them (§31.2).
///
/// Verbatim and never reduced. §31.2 forbids collapsing ingress and egress peers into a boolean
/// such as `internet_access = false`, because the peers combine namespace selectors, pod
/// selectors and IP blocks and no summary of them is true without complete coverage. And §31.3:
/// the presence of a policy object is intent, not proof that the installed network plugin
/// enforces it — which is why nothing here is named `enforced`.
fn policy_rules(object: &Object) -> Value {
    let mut map = MapValue::new();
    for (key, pointer) in [("ingress", "/spec/ingress"), ("egress", "/spec/egress")] {
        if let Some(rules) = object.field(pointer) {
            map.insert(Arc::from(key), json_value(rules));
        }
    }
    if map.is_empty() {
        return Value::Null;
    }
    Value::Map(Arc::new(map))
}

/// The `name` of each entry of an array of object references, in order.
fn names_at(object: &Object, pointer: &str) -> Value {
    let Some(entries) = object.field(pointer).and_then(Json::as_array) else {
        return Value::Null;
    };
    Value::List(
        entries
            .iter()
            .filter_map(|entry| entry.get("name")?.as_str())
            .map(|name| Value::String(name.into()))
            .collect(),
    )
}

/// The key names of a data map, sorted, and never their values.
///
/// Sorted because a JSON object states no order and the API server's is an implementation
/// detail; two reads of one ConfigMap should not differ in the order of this list.
fn data_keys(object: &Object, pointer: &str) -> Value {
    let Some(entries) = object.field(pointer).and_then(Json::as_object) else {
        return Value::Null;
    };
    let mut keys: Vec<&str> = entries.keys().map(String::as_str).collect();
    keys.sort_unstable();
    Value::List(
        keys.into_iter()
            .map(|key| Value::String(key.into()))
            .collect(),
    )
}

/// A list of strings at a pointer, or null where the object has none.
fn strings(object: &Object, pointer: &str) -> Value {
    let Some(entries) = object.field(pointer).and_then(Json::as_array) else {
        return Value::Null;
    };
    Value::List(
        entries
            .iter()
            .filter_map(Json::as_str)
            .map(|entry| Value::String(entry.into()))
            .collect(),
    )
}

/// A JSON object at a pointer, as a map, or null where the object has none.
fn map_field(object: &Object, pointer: &str) -> Value {
    match object.field(pointer) {
        Some(value) if value.is_object() => json_value(value),
        _ => Value::Null,
    }
}

/// A list of owned strings, or null where there are none.
///
/// Null rather than an empty list, because an Ingress with no TLS block and one whose TLS block
/// names no secret are the same observation, and neither is "this ingress has zero secrets" in
/// any sense a reader would act on.
fn list(entries: Vec<String>) -> Value {
    if entries.is_empty() {
        return Value::Null;
    }
    Value::List(
        entries
            .into_iter()
            .map(|entry| Value::String(entry.as_str().into()))
            .collect(),
    )
}

/// Any JSON value, as the value model carries it, with nothing typed beyond its own shape.
///
/// Used for the fields a specification requires to keep their native structure — a Service's
/// ports, a NetworkPolicy's peers — where flattening would lose exactly what makes them useful
/// later (§31.2, §31.4). Nothing is interpreted here: a string stays a string, because no schema
/// on this path claims otherwise.
fn json_value(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Number(number) => number
            .as_i64()
            .map(integer)
            .or_else(|| number.as_f64().map(Value::Float))
            .unwrap_or(Value::Null),
        Json::String(text) => Value::String(text.as_str().into()),
        Json::Array(items) => Value::List(items.iter().map(json_value).collect()),
        Json::Object(entries) => {
            let map: MapValue = entries
                .iter()
                .map(|(name, item)| (Arc::from(name.as_str()), json_value(item)))
                .collect();
            Value::Map(Arc::new(map))
        }
    }
}

/// The `reason` of the named condition, where the object states one.
fn condition_reason<'object>(object: &'object Object, condition: &str) -> Option<&'object str> {
    object
        .field("/status/conditions")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("type").and_then(Json::as_str) == Some(condition))?
        .get("reason")?
        .as_str()
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

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn should_render_an_instant_the_value_model_can_read_back() {
        // The calendar is written out here rather than taken from a dependency, so it is checked
        // rather than assumed. A wrong observation time is worse than none: freshness is what a
        // reader decides how much to trust a read by (§20.2).
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1), "1970-01-01T00:00:00.001Z");
        assert_eq!(rfc3339(86_399_999), "1970-01-01T23:59:59.999Z");
        assert_eq!(rfc3339(86_400_000), "1970-01-02T00:00:00.000Z");
        // A leap day, and a century year that *is* a leap year — the case a naive rule gets
        // wrong, and the one this calendar is written out rather than assumed for.
        assert_eq!(rfc3339(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(951_868_800_000), "2000-03-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_757_073_845_678), "2025-09-05T12:04:05.678Z");
    }

    #[test]
    fn should_parse_back_into_the_value_model_s_own_timestamp() {
        assert!(
            matches!(
                super::instant(1_757_073_845_678),
                ono_value::Value::Timestamp(_)
            ),
            "an instant this package renders must be one the value model reads"
        );
    }
}

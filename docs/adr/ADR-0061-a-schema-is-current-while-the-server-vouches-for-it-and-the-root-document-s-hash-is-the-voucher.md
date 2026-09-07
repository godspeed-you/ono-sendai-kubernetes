# ADR-0061: A schema is current while the server vouches for it, and the root document's hash is the voucher

- Status: accepted
- Date: 2026-09-07
- Spec refs: §11.4, §12.1, §12.3, §12.4, §33.2, §50.2, §50.3; §16.2 of the generic provider
  contract in core; ADR-0015, ADR-0037, ADR-0048
- Decided by: agent (autonomous)

## Context

§12.4 lists four things a schema cache's invalidation MUST account for — CRD updates, API
group/version changes, reconnecting to a different cluster, fingerprint changes — and the cache
answered three of them by the discovery refresh's diff and the fingerprint. What it could not
answer was a structural schema change whose discovery footprint is byte-identical: a CRD whose
`openAPIV3Schema` is edited serves the same resource list, and `SchemaCache` had no window of its
own, so the old fields stayed for the life of the process. `Session::crd_updated` and
`group_version_changed` existed and, outside the discovery diff, had no runtime caller.

The API server publishes exactly the token this needs. `/openapi/v3` is a small document naming
every group-version's schema document by a URL carrying `hash=<sha512>`, and the hash changes
when the schema does; the hashed URL is served immutable. Reading the root is one request;
reading every schema document again is one per group-version.

## Decision

### 1. A schema entry is current while something has vouched for it inside a window

`SCHEMA_VALIDITY` is `DISCOVERY_VALIDITY` (thirty seconds): the two answer the same question —
has the cluster changed what it serves — on the same clock. Every entry records when it was
loaded and, where known, the root document's hash for its group-version.
`Session::schema` answers only while the entry's instant is inside the window. Past it, the next
dynamic projection loads that one document again and the entry is vouched for anew. Nothing
downloads every document on any request, and nothing downloads any document on an ordinary read
inside the window (§50.2, §50.3).

### 2. The root document's hash revalidates without downloading, and invalidates without waiting

`Session::cache_schema_root` takes a freshly read `/openapi/v3` and does two things at once.
Every entry loaded under a hash the root still publishes is vouched for again from that instant
— the server has just said the document is unchanged, and no document was downloaded. Every
entry whose group-version's hash changed, vanished, or was never recorded is forgotten, so the
next projection loads the document the root now names. `Session::schema_document_path` gives the
hashed URL, which the server marks immutable. `Session::schema_root_is_current` says whether the
root has been read within the window.

### 3. A CRD change seen on a watch is a schema change observed the moment it happened

`Session::observe_event` reads a `CustomResourceDefinition` event on a watch over that collection
and calls `crd_updated` for every version the definition names, and marks discovery for refresh —
§33.2's "relevant watches where active". A write to the CRD collection through this provider
invalidates the written group's schemas the same way (`Session::mutated`). The served-version
change the discovery refresh detects already called `group_version_changed`; that is unchanged.

### 4. Provenance is inspectable on the session

`Session::schema_provenance` answers which hash a schema was loaded under and when it was last
vouched for, beside `schema_source` and `precision` on the projection. The dynamic record does
not yet carry it: the record's fields are declared in `contributions.rs` and built in
`records.rs`, which belong to another owner, and the addition is recorded here as theirs.

## Consequences

`should_project_through_the_new_schema_once_a_watched_crd_changed` proves the sequence through
the provider boundary: schema A types `renewAt` as an instant, a watch on the CRD collection
observes the definition change, the next `k8s-resource` projection types it as text, and the
schema document was read once per definition. `tests/session.rs` proves the window and the hash
route on a stepping clock; `tests/schema.rs` proves the root document's parsing and the cache's
refresh rule.

**What is not wired, and by whom it would be.** `query.rs::typing_of` — the one loader of schema
documents, owned elsewhere — still asks for the bare document path and never reads the root. So
in the running package the window is what expires an entry today, and the hash route is
exercised by tests rather than by a caller. Wiring it is three lines in `typing_of`: read
`/openapi/v3` through `cache_schema_root` when `schema_root_is_current` is false, and ask for
`schema_document_path(gvk)`. Recorded here rather than done, because the file is not this
increment's to edit.

The window costs one schema document per group-version per thirty seconds of *active* use of a
dynamic kind — the same order as discovery's own refresh — and nothing for a session nobody is
using, because an entry expires when it is asked for rather than on a timer.

## Alternatives considered

**No window; hash only.** Would be right once the root is read by the running package, and
until then would leave the process-lifetime staleness this decision exists to end.

**Empty the whole schema cache on every discovery refresh.** Every CRD anybody installs would
cost every session all of its schemas (ADR-0037's argument against the same move for discovery).

**Compare schema documents by content instead of by hash.** Costs the download the hash exists to
avoid, and the server's hash *is* the content comparison, done once server-side.

**Carry the hash and instant onto the dynamic record now.** Right, and another owner's files;
the session exposes them so the change is a field addition rather than a mechanism.

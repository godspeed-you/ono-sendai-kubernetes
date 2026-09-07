# ADR-0059: A watch capability is earned from what the server did, and a refusal is remembered for the session

- Status: accepted
- Date: 2026-09-07
- Spec refs: §5.2, §5.3, §19.1, §19.2, §19.3, §19.4, §19.5, §19.6, §20.3, §21.4, §62.6 (Gate F);
  §29.4 of the generic provider contract in core; ADR-0022, ADR-0023, ADR-0044, ADR-0058
- Decided by: agent (autonomous)

## Context

`Session` declared two optional watch behaviours and negotiated neither. `Capability::WatchBookmarks`
was requested on every watch (`allowWatchBookmarks=true`) and never recorded as answered;
`Capability::StreamingLists` was a slot nothing asked for. §19.2 is precise about the second:

> Where the server supports streaming lists / initial events, the provider MAY use them to
> reduce control-plane and client memory pressure. Use of such a feature MUST be
> capability-negotiated and MUST have a list/watch fallback for supported clusters where it is
> unavailable.

Two things make the negotiation harder than a version check. §5.3 forbids assuming what a
cluster serves from its `gitVersion`, and upstream's `WatchList` feature gate has moved between
alpha, beta, default-on and back within the support window — the same minor version answers
differently depending on how the API server was started. And a streaming list is not a separate
endpoint that can be probed: it is the ordinary watch request with three parameters on it, and
the only way to learn whether a server honours them is to send them.

The live probe against `kind` at v1.37.0 answered a streaming request with the initial `ADDED`
events, a `BOOKMARK` annotated `k8s.io/initial-events-end: "true"` at the collection's version,
and an open body carrying the changes after it. What the two older declared versions answer is
recorded under Consequences.

## Decision

### 1. A capability is negotiated from the server's answer, never from the request

`Session::observe_event` records `WatchBookmarks` on the first `Reception::Checkpointed` — the
server sent a bookmark, so it sends bookmarks — and `StreamingLists` on
`Reception::Synchronised`, which only a streaming list that reached its terminating bookmark
produces. Asking for a behaviour proves nothing about the server; a recorded answer does.

### 2. A streaming list is asked for once per session, and a refusal is remembered

The first watch a session opens asks for the initial state on the watch itself:
`watch=true&sendInitialEvents=true&resourceVersionMatch=NotOlderThan&allowWatchBookmarks=true`,
with no `resourceVersion` — upstream's own spelling. Three answers are possible and each has one
reading:

| Answer | Meaning | What the package does |
|---|---|---|
| `200`, `ADDED` events, then the annotated `BOOKMARK` | the server streams lists | the events are *staged* on the stream and the cache is seeded from all of them at the bookmark's version; `listed` records are emitted; the same body goes on delivering changes |
| `400` or `403` to the request | the feature is off or forbidden | `Session::refuse(StreamingLists)`; the attempt is abandoned; the collection is listed and watched exactly as §19.1 spells out |
| the body ends before the annotated bookmark | the server does not serve them as asked | likewise |

The refusal lives on the session beside the negotiated set, and `Session::refused` reports it.
It is cleared with everything else the session knew when the cluster behind the name is
replaced (§10.4). So the question costs one round trip per cluster per session — a `400` on the
first watch — and never one per watch.

A `403` to the streaming request is read as a refused *feature*, not a denied *collection*: the
ordinary watch is opened next, and if the identity may not watch the collection at all, that
watch is denied in the ordinary way and reported as §21.4 requires. The alternative — reading the
`403` as a denial of the watch — would report a collection as unwatchable because a feature gate
is off, which is the confusion §21.4 exists to prevent.

### 3. Staging keeps §20.3 true, and a `410` while staging is a gap

The initial events of a streaming list are held on the stream and not in the cache until the
terminating bookmark arrives: before it the set is incomplete, and a cache seeded from an
incomplete set answers absence for everything it has not yet received. `WatchStream::observe`
answers `Reception::Staged` for each, and `Reception::Synchronised` for the bookmark, at which
point `listed` seeds the cache the way a listing does and ADR-0058's index is rebuilt from it.

An expiry during staging is Gate F like any other: the staged objects are void with the stream
that was delivering them, the gap is recorded with no `after` (nothing was ever acquired), and the
listing that follows closes it. Every record after it says `continuous = false`. A streaming
list begun after a gap is a fresh acquisition in §19.4's sense and closes the gap at the
bookmark's version.

### 4. A reconnect resumes from the last bookmark

Nothing new was needed for §19.5 beyond the negotiation: the stream's checkpoint already moves on
every bookmark, and a watch reopened after a clean close asks for `resourceVersion=<checkpoint>`.
`tests/watch_scenarios.rs` now proves the round trip — a bookmark, a close, and the next request
carrying the bookmark's version rather than the listing's.

## Consequences

The first watch of a session against a cluster that streams lists costs **one** request where it
cost two; against a cluster that does not, it costs **three** where it cost two, once, and two
thereafter. The recorded fixtures that predate the feature — `tests/query.rs`, the
`performance.rs` server — answer the streaming request with `400`, and the request-count contracts
ADR-0044 recorded for them carry the extra round trip with this ADR named beside the number.
Those are the only existing assertions this change touched.

`get k8s-cluster` **does not print the negotiated set**, and the instruction that led to this
work believed it did. The diagnostic's `capabilities` map is §57.1's provider/session report
(ADR-0039), which is a different vocabulary on purpose (its Alternatives explain why
`port forward` does not belong beside `allowWatchBookmarks`). `Session::capabilities`,
`Session::refused` and the session's `Debug` are where the protocol negotiation is inspectable;
carrying it onto `k8s-cluster` means adding a field to `ClusterDiagnostic` and `cluster.rs`,
which belong to another owner, and is recorded as the next step rather than done here.

Live results per declared version are recorded here as they were observed:

| Version | Streaming list request | Negotiated |
|---|---|---|
| v1.37.0 | initial events, annotated bookmark, open body | `streaming-lists`, `watch-bookmarks` |
| v1.36.4 | initial events, annotated bookmark, open body | `streaming-lists`, `watch-bookmarks` |
| v1.35.8 | initial events, annotated bookmark, open body | `streaming-lists`, `watch-bookmarks` |

Every version of the declared window streams its lists as `kind` starts it, so the fallback is
proven against recorded servers rather than live ones; the negotiation is kept because §5.3
forbids concluding from three answers that a fourth cluster will give the same one, and because
an API server started with the gate off is one `--feature-gates` flag away.

## Alternatives considered

**Decide from `gitVersion`.** §5.3 forbids it, and the feature gate's history makes it wrong even
where it were allowed: the same minor answers both ways depending on the gate.

**Probe with a separate request before every watch.** There is no separate request; the probe
*is* the watch. Asking twice per watch would double the cost of the case the feature exists to
make cheaper.

**Never remember a refusal.** Simpler, and a `400` on every watch of a session against every
cluster started with the gate off.

**Seed the cache from each initial event as it arrives.** The obvious implementation, and the one
§20.3 forbids: between the first `ADDED` and the terminating bookmark the cache would report every
object it had not yet received as absent.

**Carry the annotation on `WatchEvent::Bookmark`.** It would change a public variant's shape and
every test that constructs one; a second variant with the same upstream class is the smaller
change, and `class()` still answers `BOOKMARK` for both.

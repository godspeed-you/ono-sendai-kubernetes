# ADR-0015: A session owns what outlives one call, and decisive fingerprint evidence empties it before anything is read

- Status: accepted
- Date: 2026-09-06
- Spec refs: §6.3, §6.4, §6.5, §10.1, §10.2, §10.4, §11.4, §12.4, §18.3, §19.1, §19.3, §19.4, §19.6, §19.7, §20.1, §20.2, §20.3, §50.2; ADR-0006, ADR-0011 here
- Decided by: agent (autonomous)

## Context

The provider had no session. Every invocation re-resolved the endpoint, re-ran discovery and
re-fetched the OpenAPI document, and five separate requirements failed for that one reason:
`schema::SchemaCache` was written and never used, §50.2's discovery cost was paid per query,
§10.4's only `MUST` had no cache to invalidate, §20.2's "cached or direct?" could not be answered
because nothing was ever cached, and §19's watch state machine — the most complete module in the
repository — was only ever fed by hand, because **nothing anywhere decoded a watch frame**.

Five things had to be decided together, because each constrains the others.

**Where the state lives.** §6.5 forbids identity, cache, watch-checkpoint, credential and
namespace crossover between provider instances. Those are five separate rules with one cause: a
process-wide cache keyed by GVR — the obvious first implementation, and the one every Kubernetes
client library encourages — violates all five at once, and the violation is invisible until two
clusters happen to hold a Pod of the same name.

**What "invalidate before presenting data as current" means in code.** §10.4 requires that a
changed cluster behind an unchanged configuration name invalidates cached object identities and
watches *before* data is presented as current. "Before" is a temporal claim, and it needs a moment
to attach to. There are two candidates: the moment a cache is read, and the moment the evidence
arrives.

**What counts as evidence that the cluster changed.** §10.2 says no single optional signal is
universally available, and `diagnostics::Fingerprint` already models signals as `Known<String>`
with a decisiveness rule (ADR-0011 here). That leaves a third state besides "same" and "different":
two fingerprints that share no obtained signal, which is the *ordinary* case for an identity that
may not read `kube-system`.

**Whether a cache may be seeded from any listing.** §18.3 makes a listing that lost a page a
legitimate answer — coverage says which scope failed and why. §20.3 makes a synchronised cache
entitled to say a name is absent upstream. Composing the two without thought produces a cache
that reports every object it was refused as absent.

**How a watch frame becomes an event.** A watch body is newline-delimited JSON objects, each
`{"type":…,"object":…}`. Three things about it are not obvious: HTTP chunked framing and JSON
framing are unrelated, so a chunk boundary lands mid-object routinely; a `BOOKMARK`'s object holds
nothing but `metadata.resourceVersion`; and a `410 Gone` **never arrives as an HTTP status** — the
response was `200 OK`, possibly hours earlier — it arrives as an `ERROR` frame whose object is a
`Status`. An implementation that classifies only HTTP codes will never see one.

## Decision

**1. `session::Session` is the owner of everything §6.3 lists**, and it is a value rather than a
registry: resolved endpoint, TLS configuration, credential source, effective identity, discovery
snapshot, schema cache, watch/cache state, default namespace and negotiated capabilities. Two
sessions cannot collide without somebody deliberately handing one's contents to the other, which
makes §6.5's five rules a consequence of the type rather than five things to remember. It performs
no I/O: a caller reads with `transport` and hands the results in. §6.4's "MUST NOT contact every
configured cluster" is then guaranteed by a constructor that has no way to.

**2. Invalidation is triggered by the arrival of evidence, not by a read.**
`Session::observed_fingerprint` compares the newly observed `Fingerprint` against the session's
and acts in the same call. What survives a replacement is the *configuration* — instance id,
endpoint, default namespace, credential (§10.1) — and what does not survive is everything the
cluster said: discovery, schemas, caches, watch checkpoints, effective identity and negotiated
capabilities. Attaching invalidation to the read instead would make every cache reader responsible
for a rule stated once in §10.4, and the reader that forgot it would be the one presenting a
previous cluster's object as current.

**3. "I could not compare" is its own answer and does not invalidate.** `ClusterChange` has four
variants: `FirstObserved`, `Same`, `Replaced`, `Undetermined`. Only `Replaced` — a *decisive*
signal disagreeing — empties the caches. Treating `Undetermined` as a replacement would be the
cautious-looking choice and would empty the caches whenever a fingerprint probe was denied,
rendering a permission failure as a cluster replacement and paying §50.2's discovery cost again on
every reconnect. §12.4's four bullets are then reachable individually — `crd_updated`,
`group_version_changed`, `group_withdrawn` — and a group/version change also drops the discovery
snapshot, because a served version that moved makes the resource list that named it a claim about
a cluster that has moved on (§11.4).

**4. A cache may only be seeded from a listing that covered its scope.**
`Session::synchronise` refuses with `SyncRefused` when the listing carries no collection
`resourceVersion` (§19.1), when its coverage is incomplete (§18.3) or when its pages are not one
snapshot (§18.2). `Session::lookup` returns four answers rather than an `Option` —
`Cached(Read)`, `ConfirmedAbsent`, `NotWatched`, `NotSynced(SyncState)` — and only a *live*
stream may produce the second. A cached hit comes back as the same `transport::Read` a direct read
produces, distinguished by `Freshness::origin() == Origin::Cache`, carrying the observation time of
the read that filled the cache and the watch's sync state. The distinction §20.2 requires lives in
the value, not in the type: a cache hit with a type of its own would need every consumer to grow a
second code path, and the consumer that grew only the first would render a cached object as a
fresh one without anybody deciding to.

**5. `watch::WatchDecoder` turns bytes into `WatchEvent`s, buffers across chunk boundaries, and
refuses rather than skips.** It holds a partial frame until the rest arrives. An `ERROR` frame is
classified by the `Status` *inside* it: code `410` or reason `Expired` becomes
`WatchFailure::Expired`, `401`/`403` becomes `Denied`, anything else becomes `Interrupted` and
keeps the checkpoint usable (§19.5). A `BOOKMARK` becomes `WatchEvent::Bookmark` and never touches
the object path. A class the provider does not model, a bookmark with no position and a truncated
final frame are each an error rather than a silent skip — a decoder that drops what it cannot read
leaves the stream looking continuous over bytes nobody accounted for, which is §19.4's forbidden
claim arrived at by a quieter route. Decoding stays out of `WatchStream`: decoding answers "what
did the server say", the stream answers "what may this provider now claim", and a decoder that
also updated a cache would make the second question untestable without the first.

## Consequences

- §12.4's schema cache has an owner, and its invalidation is exercised rather than merely written:
  a CRD update, a group/version change, a group withdrawal and a cluster replacement each have a
  test that names the rule they hold.
- §50.2's discovery cost is paid once per session, and again only when the cluster behind the name
  changed. `Session::needs_discovery` is what a caller asks instead of re-fetching to find out.
- §20.2 becomes true rather than representable. `Origin` and `Freshness` existed before this and
  nothing ever produced an `Origin::Cache`; `Session::lookup` now does, and
  `Freshness::cached` gives it a constructor of its own so that a cache hit is never a direct read
  with a field corrected afterwards.
- §20.3 is enforced at the only place it can be: a miss in a cache that is syncing, reconnecting,
  past a gap or denied comes back as `NotSynced(state)` and not as an absence. So does a *hit*
  from a quarantined cache — it was true once, and a stream that has stopped cannot say it still
  is.
- The watch is now openable end to end over recorded bytes: `watch_request` → `ResponseStream`
  chunks → `WatchDecoder` → `WatchStream` → `Session` cache, with a `410` arriving as the expiry
  that breaks continuity. Gate F's end-to-end claim, §39's temporal history and §41's live views
  no longer lack a wire driver. They still lack a route to a user — that is a separate increment
  in `ono-kubernetes-plugin`, deliberately not taken here.
- `Session<C: Clock>` is generic over a clock, mirroring `transport::Client`. The cost is a type
  parameter on a widely-held type; the gain is that freshness is assertable in a fixture test
  rather than measured against the machine's wall clock.
- One observation time is kept per watch stream rather than per object. That is the informer
  reading and it is deliberate: a synchronised cache is current as of its last observation for
  every object in it, because the watch would have said otherwise. Per-object stamps would make an
  unchanged object look stale beside a changed one when both are known to the same instant.
- Nothing in `ono-kubernetes-plugin` uses a session yet, so the discovery cost is still paid per
  invocation *in practice*. The provider now has the place for a connection to live; putting one
  there is routing work and is left to the increment that does routing.

## Alternatives considered

**A process-wide cache keyed by GVR, as most Kubernetes clients do.** Rejected: it violates all
five of §6.5's non-collision rules simultaneously, and does so invisibly — two clusters with a Pod
of the same name is not an exotic scenario, it is the normal shape of a dev and a prod context.

**Invalidating at the point of read, by comparing a fingerprint stamped on each entry.** Rejected:
it satisfies §10.4's letter and spreads the rule over every reader. The rule is stated once in the
specification and should be enforced once in the code, at the moment the evidence arrives.

**Treating any fingerprint difference as a replacement.** Rejected under §10.2's closing sentence.
The signals are optional by design, so a difference in the *set* of obtained signals is routine
and says nothing about the cluster. Only a decisive signal that disagrees decides.

**Deriving the instance id from the cluster fingerprint now that one is held.** Rejected under
§10.1 and ADR-0011 here: the instance id must be stable across reconnects, and renaming the
instance at the moment a cluster is replaced would rename it underneath every place, bookmark and
diagnostic that refers to it — at exactly the moment the user most needs the name to hold still.

**Decoding watch frames inside `transport::ResponseStream`.** Rejected: it would put the watch
state machine inside the transport, which the transport's own documentation refuses for the same
reason. A chunk is a transfer-framing fact; a frame is a §19 fact; keeping them apart is what lets
the split-across-chunks case be a test rather than a coincidence.

**Skipping a watch frame whose class is unknown, so that a future Kubernetes release does not
break the provider.** Rejected: §19.3 says "including", so a new class is expected — and a class
nobody accounted for is a hole in a history the stream would go on presenting as continuous. The
decoder says so and lets the caller break continuity deliberately, which is the same trade
ADR-0006 here made for `resourceVersion` ordering: refuse to compile the comfortable mistake.

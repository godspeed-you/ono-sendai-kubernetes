# ADR-0037: A write makes this session forget what it can no longer confirm, and what the cluster serves expires instead of waiting for a restart

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariant 13, §5.3, §10.4, §11.3, §11.4, §11.5, §12.4, §19.6, §20.1, §20.2, §20.3, §20.5, §33.1, §33.2, §45.2, §45.5, §46.3, §50.2; generic contract §16.2, §16.3, §16.5, §21.4
- Decided by: agent (autonomous)

## Context

Two `MUST`s were unmet for the same reason: the machinery existed, was tested, and had no
production caller.

**§20.5, and §16.5 of the generic provider contract.** §16.5 says:

> After a successful mutation, the provider MUST invalidate or mark potentially affected cached
> facts as stale according to declared impact.
>
> It MUST NOT show known-stale pre-change state as if freshly confirmed.

This repository's §20.5 says the same thing in this provider's own words:

> After a successful mutation request, the provider SHOULD invalidate or refresh affected cached
> objects and relationships.
>
> It MUST NOT simply patch its local cache and label the synthetic result as a server observation.

`mutations.rs` touched the session for two things — discovery, and the endpoint — and invalidated
nothing. `session.rs` holds an object cache per watched `(GVR, scope)`, seeded by `synchronise`
from a `k8s-change` acquisition and read by `Session::lookup`, whose hits carry
`Origin::Cache` (§20.2). So in one process: watch a collection, write to an object in it, read
that object by name — and the answer was the pre-change object, with a cache origin and the
observation time of the read that filled the cache. That is a *confirmed observation* of a cluster
this session itself knows it has changed, which is §16.5's second sentence exactly.

The second half of §20.5 already held and had to keep holding: nothing anywhere patches the cache
with what a write hoped it did.

**§11.4, and §33.2.** §11.4:

> Discovery results MAY change while a cluster is running because CRDs or aggregated APIs can
> appear or disappear.
>
> The provider MUST support discovery invalidation and refresh without restarting Ono.

`session.rs` had `crd_updated`, `group_version_changed` and `group_withdrawn` — written, tested,
and called by nothing but tests. The only production path that dropped a discovery document was
`observed_fingerprint`, and only on a cluster **replacement** (§10.4). A CRD installed while a
shell session is live was therefore invisible until the package process was replaced, which is the
restart §11.4 names as the thing that must not be necessary. `docs/STATE.md` recorded it under
*Deferred / blocked*: "A stale snapshot is possible within one process, and nothing detects it."

## Decision

### 1. A persisted write drops the collection caches that certainly held the object

`Session::mutated(gvr, namespace)` removes every watched `(GVR, scope)` entry whose GVR is the
written collection and whose scope could hold an object in that namespace — the namespace itself,
and any cluster-scoped or all-namespaces watch over the same collection. `mutations.rs` calls it
once, from `Conversation::run`, after the answer and only when `MutationOutcome::is_persisted()`.

**Dropped rather than edited, and the two obvious alternatives are both §20.5's `MUST NOT`.**
Writing the applied document into the cache produces a value no server returned, served under
`origin=cache` as a server observation. Removing only the object from a live cache is the same
mistake wearing the other face: `Lookup` then answers `ConfirmedAbsent`, and a write is reported as
having deleted what it changed (§4 invariant 13, §20.3). Dropping the collection entry answers
`Lookup::NotWatched`, which is true the moment it becomes true — this session holds nothing about
that collection — and the caller falls through to the API server, which is what "a later read
observes rather than recalls" means.

The invalidation happens **after** the API server's answer and **before** the record is built, so
there is no ordering in which a consumer reads a stale cache in between. The one read that does
happen in between is §46.3's verification, which goes to the object's own endpoint by name and
through no cache at all.

**Only after a *successful* mutation.** A dry run persisted nothing, a conflict changed nothing, a
refusal never happened, and only the API server knows which of those it was. Invalidating on the
way in — on the intent, before the request — would cost every preview this session's caches and
would still be invalidating for a write that may not have occurred.

### 2. "Potentially affected" is answered narrowly, and the limit is declared

Certainly affected: the object, and the cache entry of the collection it lives in. Those are the
same thing here, because the cache is per collection and the object is in it; there is no
per-object entry to invalidate on its own without reaching into `watch.rs`'s stream, and there
should not be, because a live cache minus one name is a cache that lies about that name.

Certainly *not* answerable: the dependents of a deletion with `Foreground` or `Background`
propagation. The API server names none of them — neither the `DeleteOptions` sent nor the object
or `Status` returned carries a dependent's kind, namespace, name or UID — so this provider does not
know which collections, if any, of this session hold one. Two ways to pretend otherwise were
rejected:

- **invalidate every cache in the session on a cascading delete.** It costs §50.2's three
  discovery round trips plus a re-acquisition for every collection this session was watching, in
  exchange for a guess, and it is wrong in both directions at once: it drops caches the write
  demonstrably did not touch, and it still does not cover a dependent in a collection this session
  is not watching;
- **derive dependents from owner references already cached.** Ownership edges are impact evidence
  and not a promise about what the garbage collector does or in which order (§24.4, §45.5), and a
  set derived from a cache is exactly as stale as the cache it came from.

So the dependents' caches are left as they are, and what they are is honest: observations of a
moment before the deletion, each carrying its own `observed_at` and each saying it came from a
cache (§20.2, §16.3). §16.5 invalidates "according to **declared impact**", and this is the
declaration — the mutation record's `statement` says what was invalidated, and for a cascading
deletion it says in the same breath that the objects the collector removes along with the target
are not named in the answer and so nothing held about them was invalidated.

There are no cached relationship indexes to invalidate: `relations.rs` computes edges per
invocation from objects read in that invocation, so §20.5's "and relationships" has nothing in
this session to reach.

### 3. A write to `customresourcedefinitions` also makes what the cluster serves a question again

What the API server serves is a cached fact like any other (§20.1), and a persisted write to
`apiextensions.k8s.io/…/customresourcedefinitions` is part of the answer to it. `Session::mutated`
therefore also marks this session's discovery documents stale. Matched on group and resource and
never on version, because §5.3 forbids assuming which version of an API a cluster serves.

The group the CRD serves is readable from an apply's returned object and *not* from a deletion's
`Status`, so a rule using it would differ at the case that matters most. Marking the documents
stale composes with §4 below instead: the next invocation re-reads them, and the comparison against
what they replace says precisely which group went away.

### 4. The refresh trigger: a discovery document has a validity window, and a refreshed one is an observation

Three triggers were available and none was obviously right.

**An explicit user-facing refresh command.** Core's `refresh` verb exists — "bring a local copy of
remote metadata up to date" — and this package already contributes two commands, so the pattern is
established. It was rejected as the *primary* trigger because it makes correctness depend on the
user knowing to type it: a user who has not heard of it is told a kind is not served by a cluster
that serves it, and the answer looks exactly like the truthful one. §11.4 is satisfied by a
provider that *can* be refreshed; §33.1's "a newly installed CRD MUST be discoverable without
rebuilding Ono" is about the kind being discoverable, not about a ritual that makes it so. A
command may still be added later — it composes with this decision rather than competing with it —
but it cannot be the only thing standing between a live session and a stale answer.

**A watch over `customresourcedefinitions`.** It is §33.2's own mechanism and it is precise. It is
rejected as a trigger this package opens for itself: §19.6 makes watches demand-driven — active
live views, explicit temporal observation, relationship maintenance, host-approved background
capability — and a watch nobody asked for is none of those. §33.2 says "and relevant watches
**where active**", and a CRD watch is active here only when an operator asked for one.

**Re-reading discovery when a resolution fails.** The cheapest and the one that catches the
commonest case, and it carries a trap the specification is unusually exposed to: a retry on every
miss turns a genuine "not served" into two round trips and a slower refusal, and a retry that
answers from the second attempt makes `provider.unsupported` harder to reach. It also cannot be
narrowed to the resolution that failed without teaching the resolver about the document cache
below it.

**What was chosen: the discovery-document cache has an explicit validity window, and the refresh is
what invalidates.** `DISCOVERY_VALIDITY` is 30 seconds. `Session::discovery_document` answers
nothing for a document older than that or for one marked stale, so the caller reads it from the API
server and hands it back — and `Session::cache_discovery_document`, comparing the new document
against the one it replaces, is where §33.2's detection happens:

- a refreshed `/apis` that no longer names a group → `group_withdrawn` (§33.2's "CRD deleted");
- a refreshed `/apis` where a surviving group serves fewer versions → `group_version_changed` per
  version (§33.2's "served version added/removed");
- a refreshed `/api` that drops a core version → `group_version_changed` for the core group;
- a refreshed resource list where a kind is gone or is described differently — a verb, a scope, a
  subresource, a short name → `crd_updated` for that kind alone (§33.2's "schema changed" and
  "storage version changed" as they reach discovery).

Three properties make this the right shape rather than merely a working one.

*It needs no new caller.* Every handler in this package already reads discovery through
`query::document`, which already asks the session first. The refresh reaches queries, plans,
mutations, relationships, spatial navigation and the diagnostic without any of them being changed,
and without any of them having to know that a refresh exists.

*The stale copy is kept.* §16.5 offers "invalidate **or** mark stale", and here marking is strictly
better than dropping: a stale document may never be served again, and it is the only baseline
against which the refreshed one can say what changed. `group_version_changed` and `group_withdrawn`
therefore mark this session's documents stale rather than clearing them, and so does a CRD write.
Only §10.4's cluster replacement still *clears* them, because another cluster's documents are a
baseline for nothing.

*A CRD installed is not a reason to forget anything.* A refreshed resource list that gained a kind
invalidates no schema at all: every schema held is still about a kind the server still serves
exactly as it did. An implementation that dropped the group-version because the document changed
would make every CRD anybody installs cost every session its schemas.

**Thirty seconds** is an argument rather than a round figure. §50.2 asks for discovery to be
"cached and incrementally refreshed rather than downloaded before every query", so the window has
to be long enough that a burst — a pipeline, a completion, a place being drawn — pays the three
round trips once. It also bounds how long a session may be wrong about what the cluster serves, and
being wrong about that is not a slow answer but a false one. Half a minute is under the time it
takes an operator to install a CRD and ask about it, and it costs at most three small `GET`s per
half-minute of *active* use — nothing for a session nobody is using, because the refresh happens
when a question needs discovery rather than on a timer, which keeps §19.6's rule about work nobody
asked for true of discovery as well as of watches.

### 5. §11.5's four answers are untouched

Not served, not listable, ambiguous and empty stay four different answers, and a refresh converts
none of them into another. The refresh happens strictly *before* resolution, in the layer that
hands a document to the resolver; nothing here re-runs, retries or reinterprets a resolution, and
`dynamic::resolve_for` is not called differently or twice. A kind that is not served is still
`provider.unsupported` after a refresh, reached in the same number of round trips as before and
from a fresher observation. §11.5's other half — "a resource type disappearing from discovery MUST
NOT immediately erase previously observed objects from history" — is unaffected: what a withdrawal
invalidates is this session's *schema* cache and its discovery documents, and records already
emitted belong to the host and keep the type identity they were emitted with.

## Consequences

- A `k8s-change` cache in one process can no longer answer for an object the same process has
  written to. The next read of it is a direct read, and says so.
- A dry run costs nothing: no cache is invalidated, and the second preview in a session still
  answers from what the first one learnt.
- A session that is actively used pays `/api` and `/apis` again at most twice a minute, plus the
  resource lists a question actually needs. A session nobody is using pays nothing.
- A CRD installed anywhere in the cluster — by this session, by `kubectl`, by an operator's
  controller — becomes addressable within the validity window, in a process that never restarted.
  A CRD installed by *this* session is visible on the next invocation.
- `crd_updated`, `group_version_changed` and `group_withdrawn` now have production callers, and
  the paths through them are exercised by the tests that were already written for them.
- A CRD whose structural schema changes while its discovery footprint stays byte-identical is not
  detected: the schema cache is keyed by GVK and has no window of its own, so that schema lives
  until a group-version change, a CRD write, or a cluster replacement invalidates it. §33.2 is a
  `SHOULD` and this is the part of it not yet met; a validity window on `SchemaCache` is the
  obvious next increment and is deliberately not part of this one.
- The mutation record's `statement` grew two clauses on a persisted write. Existing assertions
  match on substrings, and Gate H's "this must not say `deleted`" still holds — the new sentences
  say "deletion", never "deleted".
- `Session::discovery_documents()` now counts documents that may still answer rather than entries
  held, which is what its one question — "has §50.2's cost already been paid" — actually asks.

## Alternatives considered

**Invalidate on a mutation by clearing every cache in the session.** Simple, safe, and it turns
every write into a session-wide re-acquisition. Rejected in §2 above: it pays §50.2 for
collections the write did not touch, and buys a guess about dependents rather than knowledge of
them.

**Patch the cache with the object the API server returned from the apply.** It is right there in
the response and it is the object as the server has it. Rejected because §20.5's second sentence is
about exactly this: what would be served afterwards is a value this provider decided to remember,
and the record would call it a server observation from a moment that is not the moment it will be
read. The verification read of §46.3 makes the same information available honestly, once, labelled
as what it is.

**Give `Lookup` a fifth variant meaning "invalidated by a write this session made".** Cleaner to
read at the call site than `NotWatched`. Rejected because it is not a fifth state: after the
collection entry is dropped, this session genuinely knows nothing about that collection, which is
what `NotWatched` says. A variant that means the same thing as another one is a distinction
consumers have to learn without a difference to learn it from — and §4 invariant 13's four states
are worth keeping at four.

**Time-bound the object caches too, rather than the discovery documents.** An object cache is
already bounded by something better than a clock: a watch that is delivering, and a `SyncState`
that says whether absence in it is conclusive (§20.3). A window there would drop caches a live
watch is keeping true, which is the one kind of cache that does not need one.

**A `refresh k8s-cluster` command as the only trigger.** Discussed in §4. It is compatible with
this decision and may still arrive; it is not sufficient on its own, because the failure it would
have to prevent looks identical to a correct answer.

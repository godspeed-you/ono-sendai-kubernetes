# ADR-0021: A session lives in the process and is keyed on what the operator configured, never on what the cluster said

- Status: accepted
- Date: 2026-09-06
- Spec refs: §6.2, §6.3, §6.4, §6.5, §7.3, §7.5, §8.1, §10.1, §10.3, §10.4, §11.4, §12.3, §12.4, §14.1, §14.5, §14.6, §14.7, §20.2, §20.3, §35.8, §50.2, §50.3, §61.2, §62.10
- Decided by: agent (autonomous)

## Context

`session.rs` was written, tested and unreachable. It holds all nine components §6.3 names across a
call — endpoint, credential, namespace, discovery, schema cache, negotiated capabilities, cluster
fingerprint, watch registry and object cache — and nothing in `ono-kubernetes-plugin` imported it.
The consequences were counted in `docs/coverage.md` as four separate rows and they were one
absence: every invocation re-resolved the endpoint, re-ran discovery over `/api` and `/apis`, and
re-fetched the OpenAPI document, so §50.2 was unmet; §12.4's invalidation rules had no cache to
invalidate; §10.4's `MUST` had nothing to empty; and §20.2's "cached or direct?" had one origin to
report because nothing was ever cached.

Wiring it raises exactly one hard question and it is not a Kubernetes question. **Where does a
session live, when `Ctx` is per-invocation?** A KUANG/11 package handles one invocation at a time:
`Plugin::run_io` reads an envelope, answers it, reads the next. `Ctx` is the invocation — its
arguments, its output stream, its capability broker — and anything held on one is gone by the next
query. The process, meanwhile, is started once and kept.

Three candidate homes, and the second question that decides between them: **§6.5 forbids two
provider instances from sharing an identity, a cache, a watch checkpoint, a credential or a
namespace.** Gate J (§62.10) is that requirement made checkable, and `tests/isolation.rs` proves it
today against a decrypted wire transcript of two clusters with two authorities, two tokens, two
namespaces and two `kube-system` UIDs. Until now nothing was shared between two queries, so nothing
*could* cross over — a good state and a weak proof, and the file says so in its own header. The
moment a session exists, the proof has to start doing work.

A third question arrives with the metadata projection that shares this record. §14.1 names twelve
fields and says a provider MUST NOT pretend the data is absent; `object.rs` projected all twelve
and the boundary carried nine. `annotations`, `finalizers`, `ownerReferences` and `managedFields`
were declared by no contributed schema, and `dynamic::content` excludes `metadata` from
`k8s-resource`'s payload by design, so no route reached them. §14.5's and §14.6's `MUST`s were
unmet at the boundary rather than in the library, and metadata projection was the one K1
requirement (§61.2) still open.

## Decision

### 1. A session lives in the package process, for as long as the process does

`crate::sessions::Sessions` is built once in `crate::plugin()` and handed to every target handler
by `Rc`. It holds one `Session` per key in a `RefCell<BTreeMap<Key, Session>>`, reached only
through `Sessions::with`, which takes the borrow for the length of one invocation and releases it
with the invocation. `Rc` and `RefCell` rather than `Arc` and a lock: the SDK serves one request at
a time on one thread, and a lock would suggest a concurrency this protocol does not have.

### 2. It is not `state.persist`, and the manifest's grant stays unused by this route

The obvious alternative is the host's key-value store, which the manifest already asks for. It is
refused on the specification's own terms. §10.4 requires a cache to be invalidated when the cluster
behind a configuration name changes, and the evidence for that — the fingerprint of §10.2 — is
gathered live. A snapshot restored from disk arrives with no evidence at all, so it is either
trusted (and a rebuilt cluster answers from the previous one's cache, which is precisely §10.4's
failure) or re-verified (and the round trips it was meant to save are spent verifying it). The
argument holds harder for a watch checkpoint, which names a `resourceVersion` the server has almost
certainly discarded by the time a new process starts. A session is live state; living exactly as
long as the process that can keep it true is the honest lifetime.

### 3. The key is stricter than the provider instance, and holds nothing the cluster said

`sessions::Key` is the provider instance of §6.2 (`kubernetes:<context>`), the resolved API server
as `scheme://host:port`, and the transport posture — `plaintext`, `tls-verified` or
`tls-unverified`. The rule for adding a component is one-directional: **a component may only ever
split two invocations that would otherwise have shared a session, never merge two that would not
have.** Two kubeconfig files may both define `prod`; one file edited between two queries may point
`prod` somewhere else; §8.4 makes an insecure session a different thing from a verified one rather
than a slower one. Each of those is a split.

The cluster fingerprint is deliberately **not** in the key. §10.3 says two instances that reach one
cluster are never merged, and keying on what the cluster says about itself is exactly how they
would be.

### 4. No credential and no answered namespace live in a session

`Session::for_endpoint` takes the credential's *kind* and never its material (§8.1). The bearer
token, the client certificate and the certificate authority are resolved from the operator's
configuration on every invocation, so no invocation can be answered with a credential another one
resolved and a rotated token takes effect on the next call. The namespace a session records is the
context's default (§7.5) — a fact about configuration; the scope a query reads is resolved per
invocation from its own options.

To make that possible, `Session`'s kubeconfig `Connection` became optional and `Session::connection`
now answers `Option<&Connection>`. §7.3 admits an endpoint named directly, and such a session has no
context to hand back. This is the one behavioural change in the domain layer this work required;
everything else added to `session.rs` is additive.

### 5. What a session caches is the discovery *documents*, not the assembled snapshot

`Session::discovery_document` / `cache_discovery_document` hold each discovery response by the path
it came from. The assembled `Discovery` cannot be extended after it is built, and — more
importantly — the snapshot a query resolves against must cover exactly the group-versions *that
query* searched: §35.8's ambiguity is a property of the search space, and an answer that depended
on what an earlier query happened to fetch would not be the same answer twice. So each invocation
assembles its own snapshot, from documents it pays for once.

The OpenAPI document is cached differently, through the `SchemaCache` §12.4 already describes, keyed
by GVK. An absent schema is cached too: "this server publishes none" is an answer about this
cluster (§12.3), and re-asking is §50.2's cost paid for a document that will not be there next time
either.

### 6. §10.4 fires where the evidence arrives, which is the cluster diagnostic

`cluster::answer` hands the fingerprint it just observed to `Session::observed_fingerprint`, which
empties discovery, documents, watches, identity and capabilities on a decisive disagreement. A
fingerprint costs a read of `kube-system` and is not something §50.2 will pay for on every list, so
this is the one moment the package has the evidence — and doing it as the evidence arrives rather
than as a cache is read is what makes §10.4's "before anything is presented as current" mean
something.

### 7. §14.1's last four fields become schema fields, and `managedFields` is summarised

`annotations` is a map beside `labels` (§14.5). `finalizers` is a list beside `terminating`, which
is §14.6 asked twice — a deletion was accepted, and something is holding it (Gate H). Owner
references are a `list<map>` carrying `controller` and `blockOwnerDeletion`, because a list of names
drops the two flags that make a reference more than a name. `field_managers` is §14.7's summary —
the distinct managers, sorted — rather than `managedFields` itself, whose structure stays reachable
through `k8s-resource`'s projection of the whole object. All four join the shared metadata block, so
a discovered CRD reaches them by exactly the route a Pod does; `dynamic::content` keeps excluding
`metadata` from the payload, because reporting one fact twice under two names at two precisions is
worse than reporting it once.

## Consequences

- **§50.2 is met for the second query onwards, and measured.**
  `should_not_run_discovery_again_for_a_second_query_in_one_session` counts the request heads the
  recorded server saw: `/api`, `/apis` and `/api/v1` once across two queries, and the Pod collection
  read twice. A session caches what a cluster *is* and never what is in it.
- **§12.4 has a reader.** `should_read_the_published_schema_once_for_two_queries_of_one_kind`
  proves the OpenAPI document is fetched once and that the second answer is not a degraded one.
- **§20.2 has two origins.** With a watch open (ADR-0022), a `get` by name is answered from the
  session's cache and the record's provenance says `origin=cache`; the object endpoint is never
  asked. Before this, `direct-read` was the only word any record could carry.
- **Gate J's proof does more work than it did.**
  `should_hold_one_session_per_context_and_nothing_between_two` asserts that alpha discovers once
  across two queries, that beta discovers its own cluster rather than inheriting alpha's snapshot,
  and that *every* request each server saw carries its own context's credential — which is how the
  transcript proves the credential is resolved again rather than taken from state.
- **K1's last requirement is met.** §14.5 and §14.6 reach a user, for a curated kind and for a kind
  whose group, name and fields exist only in a test file.
- **A stale snapshot is possible within one process.** A CRD installed while a session is live is
  not discovered until something invalidates the documents — a fingerprint disagreement, a group
  version change, or a new process. §11.4 and §33.2 ask for more than that; what exists is the
  place to put it, which is what did not exist before.
- **A long-lived process holds discovery documents per instance.** Bounded by the number of
  instances an operator queries and by the API surface of each, and released only when the process
  ends. There is no eviction policy; §50.2 asks for the cost to be paid once, not for a cache
  manager.

## Alternatives considered

**A session on `Ctx`, rebuilt per invocation.** What exists today, spelled out. It cannot meet
§50.2 by construction, and it makes §12.4, §10.4 and §20.2 unimplementable rather than unimplemented.

**A session in `state.persist`, surviving the process.** Rejected in §2 above: the evidence that a
cached snapshot is still about the same cluster is live evidence, and a restored snapshot has none.

**Keying the session on the provider instance alone**, as §6.2 spells it. Correct in the case the
specification describes and wrong in two the specification does not forbid: two kubeconfigs with one
context name, and one context edited between two queries. Adding the endpoint and the posture can
only split, never merge, so it is strictly safer than the specified key without contradicting it.

**Keying it on the cluster fingerprint**, which is what actually identifies a cluster. Refused by
§10.3: two instances that reach one cluster share a fingerprint and are not one instance.

**Holding the resolved `Connection`, with its credential, in the session.** It would have made
`Session::credential_material` answer for the live session and saved re-reading the kubeconfig. It
also means a session outliving the credential it was resolved with, and a rotated token taking
effect only when the process restarts. §8.1's separation of kind from material is the cheaper
discipline and the one that cannot go quietly wrong.

**Caching the assembled `Discovery` rather than the documents.** Would have used
`Session::discovered` as written. Rejected because the snapshot a query resolves against decides
§35.8's ambiguity, and a snapshot accumulated across queries makes that answer depend on history.
`Session::discovery` therefore stays unset by this route and remains for a caller that takes a whole
inventory in one request — §11.2's aggregated discovery, which nothing negotiates yet.

**Flattening annotations into text.** §14.5 requires labels and annotations to stay structured, and
the reason is what an operator does with them: reads one key. A rendered blob is a different thing
from a map with a key in it.

**Emitting `managedFields` whole.** §14.7 asks for a summary by default, and the full record is
large, rarely wanted, and already reachable through `k8s-resource`.

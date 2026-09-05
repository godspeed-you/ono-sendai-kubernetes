# ADR-0012: A direct lookup by name is its own request, and its absence is an answer

- Status: accepted
- Date: 2026-09-05
- Spec refs: §11.5, §15.1, §17.1, §17.2, §20.2, §21.4, §60.5, §61.2 (K1); §4 invariant 13
- Decided by: agent (autonomous)

## Context

K1 (§61.2) asks for `get`, `list` and pagination. `list` was wired; §17.1's direct lookup by name
had no route, and it was the last unmet requirement of the level.

Wiring it raises two questions that a straightforward implementation answers wrongly.

**Is `get` a different request, or a listing with a filter over it?** A provider could answer
`--name api-7d9f` by listing the namespace and keeping the object whose name matches. The result
would be right on a cluster where the caller may enumerate the namespace, and wrong everywhere
else: §60.5's canonical scenario is exactly "allow `get` Pod A, deny `list` Pods", and a provider
that listed would report the readable Pod as a denial. §11.5 makes the same point from the other
side — a resource may offer `get` and not `list` at all.

**What is a `404`?** On the collection endpoint it is an API this cluster does not serve, which is
a fact about what the cluster can answer at all (§11.5). On the object endpoint it is the object
not being there. The transport layer already keeps these apart — `ApiError::outcome` takes the
operation as an argument for this reason — and the question is what the *query* does with the
second one, because §21.4's vocabulary has eight ways to come back with nothing and only one of
them is evidence of absence.

The tempting answer is to fail both, on the grounds that ADR-0004 already decided an incomplete
read fails the invocation. That reads the rule backwards. ADR-0004 fails an invocation because
the read was *incomplete* and a value stream cannot carry a coverage report. A get of an object
that is not there is not incomplete: everything that was asked for was answered.

## Decision

**`name` is an option on every target that reads objects, and it takes §17.1's canonical object
endpoint.** Discovery resolves the GVR exactly as it does for a listing, the scope rules of §9.2
are unchanged, and the redaction boundary is the same one — a Secret read by name goes through
`Guarded` like a Secret read from a collection. What differs is the request: `GET
{collection}/{name}`, and a check that discovery says the resource offers `get` rather than
`list`.

**An absent object is a completed answer of no records. Every other outcome is a failure.**

```text
404 on the object            absent            → Completed, zero records
403 on the object            read denied       → Failed, naming `read denied`
404 whose details name a namespace  namespace absent → Failed, naming it
connection, protocol, 429, 5xx      disconnected / request failed → Failed, naming it
kind not served by the cluster      (caught at discovery) → provider.unsupported
```

The rule behind the table is §21.4's own: `absent` is the only outcome that
`Outcome::is_evidence_of_absence`, so it is the only one this provider is entitled to render as
"there is nothing". A refusal rendered as an empty answer tells an operator the object was
deleted, which is the most expensive mistake in the whole §21.4 list.

**A read states its own freshness in the record's provenance.** §17.1 requires a get result to
carry `observed_at`, `resourceVersion`, `provider_instance`, `scope`, the source endpoint
category and its freshness. `resourceVersion` is a fact about the object and stays a schema
field. The other five are facts about the *observation*, and `ono_value::Provenance` already has
`observed` and `source` for exactly that — so they go there, for the listing as well as for the
get, and `inspect` shows them without every schema growing five more columns.

## Consequences

Easy: §60.5 is now an end-to-end test rather than a domain-level one — the same loaded package,
against a recorded cluster that refuses `list` on Pods and allows `get` on one, answers the
listing with a refusal naming `list denied` and the direct read with a record. A resource that
offers `get` and not `list` is reachable for the first time. Every record, from either route,
now says when it was observed and by which provider instance, at which scope, over which REST
surface.

Hard: an absent object is silent. `get k8s-pod --name typo` completes with an empty stream, and
the shell prints an empty table where `kubectl` would print `NotFound`. The value stream of a
contributed target has nowhere to carry "and the reason there are none is that this one is
absent", which is the same protocol constraint ADR-0004 records for coverage. The cost is
accepted because the alternative — failing — would report a fact about the cluster as an error
about the query, and would make `get --name` unusable in a pipeline that asks whether something
exists.

Watch: the freshness in provenance is `direct-read` for everything today, because nothing caches
between invocations. The day a cache exists, `origin=cache` appears in the same field with no
schema change — which is the reason the word is written out rather than implied by the field's
presence (§20.2).

## Alternatives considered

**Answer `--name` by listing and filtering.** Rejected: §60.5 is precisely the case it gets
wrong, and it silently needs a permission the operator never had to grant for the question they
asked.

**Fail on an absent object, so that every empty answer has a reason attached.** Rejected: it
contradicts §21.4's own distinction between the one outcome that is evidence of absence and the
seven that are not, and it would make `get --name` unusable as a test for existence. It would
also invert ADR-0004, which fails an invocation for incompleteness rather than for emptiness.

**Give `get` its own target word, `k8s-pod-get` or similar.** Rejected: §35.1 and §4 invariant 22
forbid a hidden Kubernetes mini-shell, and "the same noun, a narrower question" is what an option
is for. It would also double the vocabulary of §31.68's static document for no new capability.

**Put the freshness in five new schema fields on every schema.** Rejected: it is metadata about
the observation rather than about the object, every schema would repeat it, and the value model
already has the place for it — one that `inspect` renders without any schema saying so.

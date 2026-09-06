# ADR-0048: A served surface that cannot say when it was observed is a lookup table

- Status: accepted
- Date: 2026-09-06
- Spec refs: §11.1, §11.2, §11.3, §11.4, §11.5, §21.4, §34.2, §57.1, §62.1; ADR-0027, ADR-0036
- Decided by: agent (autonomous)

## Context

§11.3 is four lines long and was the sharpest unmet `MUST` left in the specification:

> A discovery snapshot MUST carry: `provider_instance`, `observed_at`, `api_server`, `coverage`,
> source endpoint / mechanism.

`Discovery` carried none of them. It knew what a cluster serves — groups, versions, resources,
scope, verbs, kinds, subresources, which is all of §11.1 — and nothing whatever about the act of
observing it. Two facts were being discarded at the moment they were known: `query::assemble`
matched on `RootDocument::Aggregated` versus `Legacy` to pick a reader and then dropped which one
it had used, and `served` had the endpoint, the client and the clock in scope and used none of
them.

The consequence is not abstract. Every one of the five fields is a question a stale snapshot
answers wrongly *in silence*:

- with no instance, one cluster's surface cannot be told from another's — and §10.3 forbids
  merging two instances of the same upstream cluster, which a shared snapshot would do invisibly;
- with no `observed_at`, a surface read an hour ago cannot be told from one read now. For a
  cluster that has since installed a CRD this is the whole of §11.4, and it turns Gate A's
  premise — a kind invented after the build is discoverable — into a claim that quietly decays;
- with no `api_server`, a snapshot cannot be checked against the server it is being used to talk
  to;
- with no `coverage`, a pass that was refused one group's resource list is indistinguishable from
  a complete one, so §34.2's carefully preserved hole is lost the moment the surface is stored
  rather than streamed;
- with no mechanism, an aggregated inventory cannot be told from a legacy pass that stopped at the
  group list — two surfaces with different completeness properties and the same shape.

Each is the same failure: a snapshot that cannot describe its own provenance invites a reader to
treat *not looked at* as *not served*, which is §21.4's central prohibition applied to discovery.

## Decision

**`discovery::Provenance` carries §11.3's five fields, `Discovery` holds one optionally, and the
diagnostic surfaces it.**

Three parts, and the third is what makes the first two a kept promise rather than a private field:

1. **`Provenance` in the domain crate**, with `Source { mechanism, endpoints }` for §11.3's
   "source endpoint / mechanism". `Mechanism` has three members — `Aggregated`, `Legacy` and
   `Mixed` — because §11.2's fallback is *per document*: a cluster can answer `/apis` aggregated
   and `/api` legacy, and a snapshot reporting either word alone would describe a pass that never
   happened. `Mechanism::combined` is the only way to get `Mixed`, so the case cannot be forgotten.

2. **`Discovery::provenance()` returns `Option`.** A builder fed a fixture document has a served
   surface and no pass behind it. Giving it a provenance would mean inventing an instance and a
   time, which is precisely the substitution the rest of this provider is arranged against; `None`
   is §21.4's *not queried* and nothing else. The two production paths — `query::served` and
   `cluster::discover` — fill it; the ten builders in tests and fixtures do not, and are honest
   for not doing so.

3. **`k8s-cluster` carries a `discovery` map.** §11.3 calls a snapshot a *provider fact*, and a
   fact nothing can read is not one. The five fields land on the diagnostic that already answers
   "what is this cluster and what can I do here" (§57.1), which is where an operator asking "is
   that CRD really not served, or did you last look before it was installed?" would go.

`observed_at` is emitted as a `Timestamp` rather than as milliseconds, so the shell can compare
and sort on it — a number that has to be parsed to be compared is not an instant a pipeline can
use. It comes from the client's clock rather than the wall clock, for the reason `Clock` exists at
all: a fixture that cannot fix the time cannot assert freshness (§59.2), and `Client::now` is
public now for exactly that.

`coverage` reads `complete` on both production paths today, and this is a fact rather than a
placeholder: §11.1 makes a cluster that will not answer `/api` or `/apis` unreadable, so
`root_document` fails the whole read and there is no state in which an assembled snapshot has a
hole in its root documents. The per-group holes §34.2 is about belong to the group document that
has one — they are reported by the query that hit them, not retroactively attributed to the
snapshot. The field is a `Coverage` rather than a bool so that the day a partial pass becomes
possible, the type does not have to change and the reader does not have to be rewritten.

## Consequences

An operator can now ask when the served surface was last observed, of which server, by which
route, and how completely — and `k8s-cluster` answers in one record beside the capabilities that
were derived from that same snapshot, which is where the two belong.

The provenance is deliberately *not* threaded through the session cache invalidation of ADR-0036.
A refreshed snapshot gets a new provenance because it is a new pass; a cached one keeps the old
`observed_at`, which is the truthful answer and the entire point.

Two `Provenance` types now exist — `records::Provenance` for what a record carries and
`discovery::Provenance` for what a snapshot carries. They are different facts about different
things, and `cluster.rs` imports the second under an alias rather than letting one word mean both.

# ADR-0049: The way to keep a selector translation from changing meaning is to have no translation

- Status: accepted
- Date: 2026-09-06
- Spec refs: §17.1, §17.3, §17.4, §17.5, §17.6, §18.4, §21.4, §50.2; ADR-0010, ADR-0012
- Decided by: agent (autonomous)

## Context

§17.3 to §17.5 govern server-side filtering, and nothing in this provider filtered server-side.
`ListOptions` had `label_selector` and `field_selector` and no caller ever set either, so every
question narrower than "the whole collection" was answered by listing the whole collection and
letting the pipeline discard the rest. On a cluster with a hundred thousand Pods that is not a
missing convenience; it is the difference between an interactive answer and a query that spends
its whole budget (§50.2) fetching objects the caller already said they did not want.

The section is unusually careful about *how*, and the care is the interesting part:

> The provider SHOULD push supported label selectors and field selectors … when Ono query
> semantics map exactly. It MUST NOT push a filter when the translation changes semantics.
> — §17.3
>
> Kubernetes label selector semantics MUST remain Kubernetes semantics. The provider MUST NOT
> invent logical OR support and silently translate it into several requests without preserving
> fan-out and completeness metadata. — §17.4
>
> Unsupported field selection MUST not become an empty result. — §17.5

Three prohibitions, and all three are about the same hazard from different angles: a filter is a
claim about what was *excluded*, and a filter that does not mean what the caller thought produces
an answer that is wrong while looking complete. The `MUST NOT` on fan-out is the sharpest — a
provider that decomposed `env in (staging, prod)` into two listings and concatenated them would
produce a plausible table that has silently lost the completeness metadata of both halves.

## Decision

**The selector is passed to the API server exactly as the operator wrote it.**

`get k8s-pod --selector 'env in (staging, prod),tier!=cache'` sends that string as
`labelSelector`, percent-encoded and otherwise untouched. There is no expression type, no parser,
no Ono-side predicate language mapped onto Kubernetes' — and therefore no translation for §17.3's
`MUST NOT` to bite on, no invented OR for §17.4's, and no fan-out. `in` is the API server's `in`.

This is a smaller decision than it looks, and it is the reason the three prohibitions are kept
rather than merely respected. Every alternative — a structured selector argument, a mapping from
Ono's own filter syntax, a convenience that accepts several `--selector` flags — reintroduces
exactly the translation the specification is warning about, and each would need its own proof that
the semantics survived. Passing the string through needs no such proof because nothing happens to
it.

Two consequences follow directly:

- **No client-side residual filtering.** §17.3 permits it "after a correct server-side subset",
  and there is no subset here: the pushed selector *is* the caller's question, so filtering again
  locally would either be a no-op or a second, different filter. Nothing is filtered twice.
- **Empty text is no selector at all.** An API server reads an absent `labelSelector` and an empty
  one identically, but a package that sent `labelSelector=` for a caller who typed nothing would
  make an empty argument look like a deliberate filter in every request log an operator later
  reads.

**A field selector the server will not index is refused by name.** §17.5's `MUST` — "unsupported
field selection MUST not become an empty result" — names the cheapest possible mistake: catch the
`400`, call it "no matching objects", and complete with an empty table. An operator reads that and
concludes nothing on the cluster matches, when in truth nothing was ever selected. It is §21.4's
central prohibition wearing a query-string costume.

So the `400` is detected where it happens and turned into a refusal that quotes the field the
operator wrote and what the server said about it. There is deliberately **no fallback that lists
the collection unfiltered**: §17.5 permits falling back "only when safe and affordable", and
widening a caller's question without being asked is neither. Re-implementing field-selector
semantics locally would be worse still — that is the translation §17.3 forbids, for a feature
whose availability "varies by resource type and server implementation", which is to say for a
feature whose semantics this package cannot know.

Both parameters are declared on the twenty targets that reach `query::answer`'s listing route and
on no others. `k8s-event` was sharing `k8s-resource`'s argument list on disk and had to stop:
`events.rs` reads its collection by its own route and does not push them, and a declared argument
no handler reads is a promise the package would break on first use.

## Consequences

`get k8s-pod --selector app=api` is now one request that returns the matching Pods instead of one
per page of the whole collection, and the saving grows with the cluster.

`k8s-event` now carries its own copy of an argument list it used to share. That is fifteen lines of
duplication in `targets.yaml`, and it is the honest shape: the two targets diverged, and an alias
that hid the divergence would have declared arguments that silently did nothing.

A field selector remains the sharp edge. It is offered because §17.5 expects it and because
`involvedObject.name` and `spec.nodeName` are how real questions get asked — but it is the one
argument in this package that can be refused by a healthy cluster for a well-formed value, and the
refusal says so in those words.

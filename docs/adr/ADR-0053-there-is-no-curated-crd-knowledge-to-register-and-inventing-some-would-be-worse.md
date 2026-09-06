# ADR-0053: There is no curated CRD knowledge to register, and inventing some would be worse

- Status: accepted
- Date: 2026-09-06
- Spec refs: §13.5, §15.1, §15.4, §33.1, §33.5, §33.8, §55.2, §58.4, §66.2, §68; ADR-0010, ADR-0052
- Decided by: agent (autonomous)

## Context

Three sections ask for an adapter registry, and they ask for slightly different things:

- **§33.8** — "curated **CRD** knowledge SHOULD be implemented through provider-side adapters keyed
  by group/kind/version compatibility", contributing semantic roles, relationship extractors,
  default views, prospective effects, verification rules and cross-system identity evidence. "An
  adapter MUST NOT replace the underlying dynamically discovered object representation."
- **§58.4** — "curated semantics SHOULD be registered by type capability rather than scattered
  `if kind == ...` branches across query code", with a conceptual interface.
- **§66.2** — "a contributor adding support for one CRD ecosystem SHOULD not need commit access to
  Ono parser/core internals."

No registry exists. The coverage map listed this as an open gap, and it is worth being exact about
what is actually missing, because the three sections are in different states.

## Decision

**Nothing is built, the property §58.4 asks for is asserted by a test, and this records why.**

Taking them in turn:

**§66.2 is already true, structurally.** This provider is a separate repository from Ono core with
its own ADR series. A contributor adding a CRD ecosystem needs commit access to *this* repository
and to nothing in core's parser or internals. The section asks for a property of the topology, and
the topology has it.

**§58.4's prohibition holds, and now has a guard.** The phrase is "scattered `if kind == ...`
branches across query code", and the query code has none. Curated semantics live in the domain
crate, one table per concern: `relationship.rs` matches `(group, kind)` once,
`evidence.rs` once, `condition.rs` once, `contributions.rs` holds the target table. A handler is
handed a `Resource` and applies whatever the table gave it.

That was true by convention and is now true by test.
`should_key_curated_semantics_rather_than_branch_on_a_kind_in_query_code` counts kind comparisons
across all fourteen handler modules and allows exactly one, named: §55.2's enhanced prospective
analysis for a Namespace deletion, which the specification itself singles out by kind. Writing the
test found that branch reading `resource.kind() == "Namespace"` with no group beside it — so a
custom resource called `Namespace` in somebody else's group would have had a cluster's namespaced
inventory counted as its contents and attached to its deletion plan. §13.5 is the rule it broke,
and it is fixed in the same change. That is what the guard is for: the drift §58.4 warns about
does not arrive as a bad design, it arrives as one convenience that was right at the time.

**§33.8 has no subject.** It governs *curated CRD knowledge*, and this provider curates none. Every
custom resource is read through the discovered floor of §15.1 and §33.1 — its schema from the
cluster's own OpenAPI document, its fields typed by `dynamic.rs`, its relationships from the ones
it states about itself. That is deliberate and it is what Gate A tests: a kind invented after the
build is installed, discovered, queried, entered and watched with no recompilation.

Building the registry now would mean either an empty one — a mechanism with no members, which is
the stub §26 forbids dressed as architecture — or inventing an ecosystem's semantics. The second
is worse. Curated knowledge about a CRD ecosystem is a claim about what somebody else's controller
means by its fields, and a wrong claim there is exactly the fabrication §4's invariants exist
against: a `relationships()` extractor asserting an edge that ecosystem does not have would render
identically to an owner reference. §15.4 puts Tier 3 ecosystems behind explicit recognition, and
§68 reserves the topic; ADR-0010 already declined to guess at custom-resource semantics for the
same reason.

**What would make this decision expire.** A curated ecosystem arriving — because a maintainer with
that expertise contributes one, which is the path §66.4 asks the review policy to value. At that
point the registry is written *with* its first member, keyed by group/kind/version as §33.8 says,
and the `MUST NOT` becomes the load-bearing part: the adapter contributes semantics beside the
dynamically discovered representation and never in place of it, so `get k8s-resource` on an
adapted kind still returns what the cluster served.

## Consequences

The gap is closed as a decision rather than as code, and the decision is testable in the one
direction that matters: the drift §58.4 describes cannot happen quietly, because a fifteenth
handler that branches on a kind fails the gate.

One real defect was found and fixed by writing the guard rather than by reasoning about it, which
is the argument for guards that read the tree over prose that describes it.

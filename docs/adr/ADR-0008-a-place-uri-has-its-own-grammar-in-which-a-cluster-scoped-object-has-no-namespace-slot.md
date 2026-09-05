# ADR-0008: A place URI has its own grammar, in which a cluster-scoped object has no namespace slot

- Status: accepted
- Date: 2026-09-05
- Spec refs: §9.2, §13.2, §13.5, §16.1, §16.2, §35.1, §35.2, §35.3, §35.4, §35.8, §36.1, §68.1
- Decided by: agent (autonomous)

## Context

§35 asks for Kubernetes to appear as *places* in Ono's existing world — a cluster root, enterable
namespaces, enterable resources — and gives examples rather than a grammar:

```text
k8s://prod/
k8s://prod/ns/production/
k8s://prod/ns/production/pod/checkout-7c9...
k8s://prod/cluster/node/worker-03
```

It attaches one requirement to them: "Exact URI grammar may be consolidated later, but URI
identity MUST remain stable and machine-parseable." §68.1 is explicit that the global
external-provider URI grammar is deliberately not frozen before Kubernetes and AWS have both
validated it.

A candidate already existed. `object::Locator` renders
`provider_instance/group/version/Kind/namespace/name` and is §16.2's locator: the right shape for
human lookup of one object by its type. Reusing it would have avoided a second way to write down
one object.

It is the wrong shape for a place, for three reasons that would each have to be worked around
rather than lived with. Its type component expands into three slash-separated fields, so a reader
— and a parser — cannot tell where the type ends and the namespace begins. Its namespace is
positional and optional, which makes `.../Node/worker-03` and `.../shop/checkout` the same
grammar, so a cluster-scoped resource sits in a slot a namespace could occupy; that is precisely
the confusion §9.2 forbids. And it renders only: there is no parser, while §35.3 requires an
address that survives a round trip.

## Decision

**A `PlaceUri` is built with its own grammar, and the locator stays what it is.**

The scheme is `k8s` and the authority is the context alone — `k8s://prod/` — because the scheme
has already said which provider this is; the `kubernetes:` prefix of §6.2's instance identifier is
stripped on render and put back on parse. Below the authority there are exactly three shapes, and
**cluster scope and namespace scope are two of them rather than one shape with an optional slot**:

```text
k8s://prod/                                     the cluster root
k8s://prod/ns/shop/                             a namespace
k8s://prod/ns/shop/pod/checkout-7c9             a namespaced resource
k8s://prod/cluster/node/worker-03               a cluster-scoped resource
```

There is no way to write a namespace for a Node, so §9.2's fake namespace is not something the
code must remember to avoid — it is unrepresentable. Where discovery's scope for a kind and an
object's own metadata disagree, the constructor fails with `ScopeConflict` naming both, because
that disagreement is a fact worth reporting rather than a case to smooth over.

**The type segment is always group-qualified.** `pod`, `node`, `deployment.apps`,
`widget.acme.example.com` — `kubectl`'s own disambiguation form, applied unconditionally rather
than only when two kinds collide. §13.5 makes kind uniqueness a property of *this cluster's*
discovery, so an address that dropped the group while no collision existed would change shape the
day an operator installed an unrelated CRD. An address that installing a CRD can rewrite is not
the stable identity §35.3 requires.

**The version is deliberately absent.** It is observed representation rather than lifetime
identity (§16.1), and a place whose address changed when a group's preferred version rolled over
would not be stable either.

**The kind is lower-cased and the canonical spelling is not recovered from the address.** Case is
not recoverable from a URI, and recovering the canonical `Kind` is discovery's job (§13.2); a
place built from an object keeps the full `Gvk` alongside for exactly that reason.

**A place binds a lifetime, not only a name** (§35.4). Where the object behind a place has been
read, the place carries its `Identity`, so two Pods that occupied one address in sequence are two
places and §16.3's recreate discontinuity is visible spatially as well as temporally.

This is a provider-local grammar offered as input to §68.1, not a claim on the global one. It is
recorded as revisitable with a concrete condition: when core consolidates the external-provider
URI grammar, this grammar conforms to it, and the two-shape distinction is the property this
provider would argue to keep.

## Consequences

Easy: addresses round-trip, which §35.3 requires and the locator could not do. A cluster-scoped
object cannot acquire a namespace by any code path, including the ones not written yet. Addresses
survive a CRD installation and a preferred-version rollover unchanged. Parse failures name the
component that was empty or malformed rather than rejecting the whole string.

Hard: there are now two ways to write down one object — a locator for human lookup by type, a
place for navigation — and a reader will meet both. The split is §16.2's own ("a locator is not
the same as lifetime identity") and it is still one more thing to explain.

Hard, too: constructing a place needs the kind's *scope*, which is discovery's answer and not the
object's. An absent `metadata.namespace` is not proof of cluster scope, so a caller holding only
an object cannot always build a place; it has to have asked the server what it serves. That is the
right dependency — discovery is authoritative (§4 invariant 1) — and it does mean the place layer
cannot be used offline against a document nobody has discovered.

Hard, too: `k8s://prod/ns/shop/deployment.apps/checkout` is more to type and read than
`.../deployment/checkout`. The cost is per address and the benefit is that the address means the
same thing next month.

Watch: §68.1 may consolidate a global grammar that differs from this one, at which point these
addresses change. Nothing may treat a place URI as durable storage in the meantime — which is
consistent with §3.5's refusal of a persistent cluster inventory, but is a real constraint on any
future history or bookmark feature. Watch also that this package has claimed the `k8s` scheme
without core having allocated scheme names to providers; if core grows a registry, this is the
first entry rather than a squatter.

## Alternatives considered

**Reuse `Locator` and write a parser for it.** Rejected: the three-field type component makes the
grammar ambiguous to parse without knowing the type in advance, and the optional positional
namespace gives a cluster-scoped resource the same shape as a namespaced one — §9.2's exact
failure.

**One grammar with an optional namespace segment.** Rejected for the same reason in a smaller
form: an optional slot is a slot, and every code path that builds an address has to decide what to
put in it. Two shapes move that decision to the type, where it is made once.

**Qualify the type with its group only when kinds collide.** Rejected: uniqueness is a property of
one cluster at one moment (§13.5), so the address shape would depend on which CRDs happen to be
installed, and installing an unrelated operator would silently rewrite addresses that already
existed.

**Include the API version in the address.** Rejected: §16.1 makes version representation rather
than identity, and every address would change when a group's preferred version rolled over.

**Address places by UID.** Rejected: a UID is not enterable by a human and §35.4 asks for a place
that *binds* lifetime identity, not one that is replaced by it. The place carries the `Identity`
alongside the name, which gives the recreate discontinuity without making the address unreadable.

**Wait for core to freeze the grammar (§68.1) and address places some other way meanwhile.**
Rejected: §68.1 says the grammar will not be frozen until Kubernetes and AWS have validated one,
so a Kubernetes provider producing a real grammar is the input that decision is waiting for.

# Adapters: adding a curated CRD ecosystem

This is the contributor guide for §33.8's semantic adapter registry — the surface §66.1 calls
**CRD adapters** and §66.2 promises can be extended without reading the parser, the shell or the
generic query handlers. [ADR-0062](adr/ADR-0062-curated-ecosystem-knowledge-is-an-adapter-keyed-by-group-kind-and-version-that-adds-beside-the-record-and-never-replaces-it.md)
records the design; this page is how to use it.

## What an adapter is, and what it is not

Every custom resource already works without one. Discovery finds it, its schema comes from the
cluster's own OpenAPI document, its fields are typed dynamically, it is addressable as a place,
watchable, and it states whatever relationships its own fields state (§15.1, §33.1). That is the
floor, and Gate A (§62.1) proves it for a kind invented after the build.

An adapter adds what a reader *of that ecosystem* knows and the floor cannot: that an HTTPRoute's
`spec.parentRefs` names a Gateway, that a Gateway answers to the `network-endpoint` role, which
fields a default view should show, what a change to it is expected to do. It is layered over
the dynamic representation and is optional in the strict sense — a cluster that does not serve
the group never presents an object the adapter recognises, and a cluster that serves a version
the adapter has not seen gets the floor.

**An adapter cannot replace the record.** This is §33.8's `MUST NOT`, and the types enforce it:
an adapter is handed `&Object` and returns roles, edges, a view, effects, a verification rule and
evidence. There is no method that takes `&mut Object`, returns an `Object`, or removes a field.
`get k8s-resource` on an adapted kind returns what the cluster served.

**An adapter cannot present an inference as a relationship.** `Registry::relationships` drops
any edge whose deciding or supporting evidence is `Evidence::Inferred` (§23.5). If your
ecosystem's knowledge is a correlation — a name that matches, an address that fits — it belongs
under `cross_system_evidence`, where it is labelled as what it is.

## The interface

```text
crates/ono-provider-kubernetes/src/adapter/mod.rs
```

```rust
pub trait Adapter: Send + Sync {
    fn name(&self) -> &'static str;                       // "gateway-api"
    fn coverage(&self) -> Coverage;                       // group, kinds, served versions

    fn semantic_roles(&self, gvk: &Gvk) -> Vec<SemanticRole>                       { Vec::new() }
    fn relationships(&self, object: &Object, context: &Context<'_>) -> Vec<Edge>   { Vec::new() }
    fn default_view(&self, object: &Object) -> Option<View>                        { None }
    fn prospective_effects(&self, object: &Object, action: &Action) -> Vec<Prospect> { Vec::new() }
    fn verification(&self, object: &Object, action: &Action) -> Option<VerificationRule> { None }
    fn cross_system_evidence(&self, object: &Object) -> Vec<IdentityEvidence>      { Vec::new() }
}
```

Every method after the first two has a no-op default. Implement the ones your ecosystem can
defend and leave the rest.

**`Coverage`** is one API group, the kinds within it you have written rules for, and the served
versions whose field layout you have actually seen. There is no wildcard: a version you did not
list is `Compatibility::UnknownVersion`, and the object is dynamic (§5.3, §27.3). When a new
version ships, read its schema, add it to the list, and add a fixture at that version.

**`Context`** is what the caller has already read — other objects, in hand, no I/O. An adapter
that needs a second object to derive an edge reads it from `context.candidates()` and derives
nothing when it is not there. Nothing in the domain crate performs I/O (§58.1, §59.1).

**`relationships`** returns `Edge`s. `Edge::new` takes `Evidence` as an argument, so an edge
without evidence cannot be built (Gate D, §62.4). Cite the JSON pointer you read as
`Evidence::NativeField { path, value }`, and name yourself and the version you assumed as
supporting evidence: `Evidence::Derived { rule: "curated Gateway API adapter for
gateway.networking.k8s.io/v1" }`. Use the vocabulary in `relationship::Relation`; a relation the
vocabulary lacks is a change to `relationship.rs` and `place::Waypoint`, made in its own commit
with its own ADR, because every relation is a word a user can `follow`.

**`semantic_roles`** takes a `Gvk`, because a role is a judgement about a kind (§36.2, generic
contract §25.1). Return one of the nine `SemanticRole`s or nothing; a wrong overlay is worse than
none (§36.3).

## Fixture first

§66.3: a relationship or API behaviour change arrives with its deterministic fixture, not after
it. For an adapter that means, before any rule:

1. **An object at each version you list**, as JSON, inside the test. The Gateway adapter's
   fixtures are `HTTPROUTE`, `GATEWAY` and `FUTURE_HTTPROUTE` in
   `crates/ono-provider-kubernetes/tests/workload.rs`; the registry's own are in
   `tests/adapter.rs`.
2. **The object at a version you did not list**, proving the fallback: no roles, no curated
   edges, the object still whole.
3. **One test per edge**, asserting the relation, the target's kind, name and namespace, and the
   evidence path. A cross-namespace reference and a defaulted one are two tests.
4. **The record test**: the object's fields after the registry has run are the object's fields
   before. `tests/adapter.rs` has one; copy its shape.

Fixtures are generated in the test rather than checked in, so the fixture and the behaviour it
pins cannot drift apart (AGENTS.md §2).

## Adding one

1. Create `crates/ono-provider-kubernetes/src/adapter/<ecosystem>.rs` from the template below.
2. Add `pub mod <ecosystem>;` and one entry to `BUILTIN` in `src/adapter/mod.rs`. That line is
   the registration; nothing else in the crate or the plugin changes.
3. Write the fixtures and tests in `crates/ono-provider-kubernetes/tests/`.
4. Run `scripts/gate.sh`. It needs no cluster.
5. Write the ADR that says what the ecosystem's fields mean and which upstream document says so.
   Curated knowledge is a claim about somebody else's controller, and the review will ask for
   the source (§66.4).

Do not add an ecosystem you cannot defend from its upstream documentation. ADR-0053's reason for
declining to invent cert-manager, Argo, Flux and Crossplane adapters still stands: a wrong claim
about what a controller means by a field renders identically to an owner reference.

## Template

```rust
//! <Ecosystem>: what its objects state about each other, read at the versions listed below.
//!
//! Upstream reference: <URL of the API reference for the versions covered>.

use crate::adapter::{Adapter, Context, Coverage};
use crate::discovery::Gvk;
use crate::object::Object;
use crate::place::SemanticRole;
use crate::relationship::{Edge, Evidence, Relation, Target};

/// The group the ecosystem is served under.
const GROUP: &str = "example.io";

/// The versions whose field layout this adapter has seen. Add one only with its fixture.
const VERSIONS: &[&str] = &["v1beta1", "v1"];

/// The kinds this adapter has rules for.
const KINDS: &[&str] = &["Widget"];

/// The adapter. A unit struct: it holds no state, because it performs no I/O.
pub struct ExampleAdapter;

impl Adapter for ExampleAdapter {
    fn name(&self) -> &'static str {
        "example"
    }

    fn coverage(&self) -> Coverage {
        Coverage::new(GROUP, KINDS, VERSIONS)
    }

    fn semantic_roles(&self, gvk: &Gvk) -> Vec<SemanticRole> {
        match gvk.kind() {
            "Widget" => vec![SemanticRole::Workload],
            _ => Vec::new(),
        }
    }

    fn relationships(&self, object: &Object, _context: &Context<'_>) -> Vec<Edge> {
        let Some(name) = object.field("/spec/serviceName").and_then(|v| v.as_str()) else {
            return Vec::new();
        };
        vec![
            Edge::new(
                object.identity(),
                Relation::UsesService,
                Target::new("Service", name)
                    .with_api_version(Some("v1"))
                    .in_namespace(object.namespace()),
                Evidence::NativeField {
                    path: "/spec/serviceName".to_owned(),
                    value: name.to_owned(),
                },
            )
            .with_supporting(vec![Evidence::Derived {
                rule: format!("curated {} adapter for {}", self.name(), object.gvk()),
            }]),
        ]
    }
}
```

Registration, in `src/adapter/mod.rs`:

```rust
pub const BUILTIN: &[&dyn Adapter] = &[&gateway::GatewayApi, &example::ExampleAdapter];
```

## What the registry does with your answers today

- **Roles** reach `Place::roles()` and every edge record's `target_roles`.
- **Relationships** reach `get k8s-relation`, `near`, `follow` and the routing reversal
  (`routed-from`), through the same rule as every built-in edge.
- **Default views, prospective effects, verification rules and cross-system evidence** are
  collected by the registry and consumed by nothing yet. They are part of the contract so that
  an ecosystem can state them the day it arrives and the consumer can be written against a
  member that exists; the Gateway adapter implements none of them, which is what the defaults
  are for.

## Where the built-in kinds live, and why they are not adapters

`relationship.rs`, `workload.rs`, `condition.rs` and `place::ROLE_OVERLAY` are keyed by group
and kind too, and they stay tables. §33.8 governs curated *CRD* knowledge; a Pod's `spec.nodeName`
does not change meaning between one `v1` and the next, and gating it on a version list would
serve no reader. The line is the group: a kind under a group this package did not compile
against is adapter territory. See ADR-0062.

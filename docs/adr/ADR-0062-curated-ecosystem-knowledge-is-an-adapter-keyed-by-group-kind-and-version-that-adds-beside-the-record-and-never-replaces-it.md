# ADR-0062: Curated ecosystem knowledge is an adapter keyed by group, kind and version, that adds beside the record and never replaces it

- Status: accepted
- Date: 2026-09-07
- Spec refs: §2.9, §5.3, §13.5, §15.1, §15.4, §23.5, §27.3, §33.8, §36.1, §36.2, §58.4, §62.4,
  §64 Phase 9, §66.2, §66.3; §25.1 of the generic provider contract; ADR-0010, ADR-0052,
  ADR-0053
- Decided by: agent (autonomous)

## Context

`ADR-0053` declined to build §33.8's semantic adapter registry, and named what would make the
decision expire: "a curated ecosystem arriving … at that point the registry is written *with*
its first member, keyed by group/kind/version as §33.8 says, and the `MUST NOT` becomes the
load-bearing part".

The ecosystem was already here. `workload.rs` carried `GATEWAY_GROUP`, `KNOWN_GATEWAY_VERSIONS`
and `gateway_edges`; `place.rs` carried the Gateway and HTTPRoute rows of `ROLE_OVERLAY`;
`relationship.rs` carried `Relation::UsesGatewayClass` and `AttachesTo`. §27.3 calls this "a
curated Gateway API adapter" in so many words, and it was version-aware, keyed on a foreign
group, and optional in exactly the sense §15.4 asks for. What it was not was *an adapter*: it
lived inside the module that owns the built-in routing path, a second ecosystem would have gone
into the same file, and §66.2's contributor would have needed to read `workload.rs`,
`place.rs` and the relations handler to add one. That is the gap the coverage map recorded
against §2.9, §33.8, §58.4 and §66.2 in four separate rows, and it is one gap.

Five questions had to be answered together.

**What an adapter receives and what it may return.** §33.8's `MUST NOT` — an adapter must not
replace the dynamically discovered representation — is the sentence that decides the types.

**What the registry is keyed on.** §33.8 says group/kind/version compatibility; §5.3 forbids
assuming the newest version; §27.3 requires version awareness; §13.5 makes the group part of
the identity.

**Whether the built-in tables become adapters too.** `ROLE_OVERLAY`, `POD_TEMPLATES`, the
`(group, kind)` matches in `relationship.rs` and `condition.rs` are curated semantics keyed by
type, which is what §58.4 asks for. They are also *built-in* kinds whose schemas are stable
across the whole support window.

**Where roles come from.** §58.4's conceptual interface says `semantic_roles(resource)`;
`Place` is built from an `Identity` that carries a GVK and no object.

**What a plan needs from an adapter.** §58.4 names `prospective_effects(action)` and
`verification(action)`; `plan::Effect` has no public constructor and `plan.rs` is not part of
this change.

## Decision

**The registry is an extension architecture in the domain crate — `adapter::Adapter`,
`adapter::Registry` — and the Gateway API is its first member, moved there whole.**

**An adapter is handed `&Object` and returns semantics; it cannot produce, replace or narrow an
object.** No method of `Adapter` or `Registry` takes `&mut Object`, returns an `Object`, or
returns anything an `Object` is built from. What comes back is a `Vec<SemanticRole>`, a
`Vec<Edge>` — each carrying `Evidence`, because `Edge::new` takes it as an argument — an
optional `View` naming pointers into the object it was given, `Prospect`s, a
`VerificationRule`, and `IdentityEvidence`. §33.8's `MUST NOT` is therefore a property of the
signatures rather than of review: `get k8s-resource` on an adapted kind returns what the cluster
served because there is no path by which it could return anything else.

**Coverage is a group, a list of kinds and an explicit list of served versions, and a version the
adapter did not name is dynamic.** `Registry` indexes members by `(group, kind)` and answers
`Compatibility::Adapted` only when the object's version is one the adapter listed;
`UnknownVersion` and `NotCovered` both mean "no adapter", and the object is what §15.1's floor
makes it. This is `KNOWN_GATEWAY_VERSIONS` promoted from a private constant to the contract:
`gateway.networking.k8s.io/v99` still yields no curated edge and no role, and the test that
pinned that (`should_not_read_an_unrecognised_gateway_api_version_as_if_the_schema_were_known`)
still passes unchanged. There is no wildcard version, because a wildcard is §5.3's assumption
written down.

**The registry never presents an inference as a relationship.** `Registry::relationships` drops
any edge whose deciding or supporting evidence is `Evidence::Inferred`. An adapter that has a
correlation to offer has §23.5's cross-system confidence model to offer it under, and
`cross_system_evidence` is the method for that; `relationships` is for edges a reader can check.
This makes `should_never_present_an_inference_as_a_relationship` a property of the registry
rather than of every contributor, and `tests/adapter.rs` proves it with an adapter that tries.

**The built-in tables stay tables.** §33.8 governs curated *CRD* knowledge; the registry is for
ecosystem knowledge keyed by a foreign group and gated by served version. A Pod's `spec.nodeName`
does not change meaning between `v1` and `v1`, and moving `relationship.rs`'s matches into
adapters would add a version list to every built-in kind for nothing. The line is the group: a
kind the cluster serves under a group this package did not compile against is adapter territory.
The one consequence for the tables is that `ROLE_OVERLAY` loses its two Gateway rows and
`place::roles_of` consults the table and then the built-in registry.

**Roles are a judgement about a kind, so `semantic_roles` takes a `Gvk`.** The generic
contract's §25.1 registers native resource *types* under roles, `Place` is built from an
identity, and an adapter that needed the object to decide a role would be deciding it from a
field, which is a different fact with a different evidence class. The rest of the interface takes
the object.

**`prospective_effects` and `verification` take the object and the action, and answer in the
adapter's own words.** An action carries no kind, so the registry dispatches on the object.
`adapter::Prospect` is the adapter's statement of an expected effect — `EffectKind` and
`Reversibility`, which are public — and the plan is what turns it into an `Effect` when a member
contributes one. Nothing consumes either method yet; the Gateway adapter implements neither,
which is what the defaults are for.

**Registration is one line in one list.** `adapter::BUILTIN` names the members;
`Registry::builtin()` assembles them once. A contributor's change is `src/adapter/<name>.rs`,
its fixtures, and that line — no parser, no shell, no handler, no unrelated relationship code.
`docs/adapters.md` is the guide and carries the template.

**`Workload::gateway_edges` and `Workload::routed_from` answer through the registry.** The
first stays as the entry the workload tests and the routing reversal use, and it now delegates;
the relations handler calls the registry directly. No test changed, which is what a move is.

## Consequences

- §33.8, §58.4's conceptual interface, §66.2 and §2.9 are structural rather than topological.
  The `should_key_curated_semantics_rather_than_branch_on_a_kind_in_query_code` guard is
  unchanged and still allows exactly one branch.
- `Place` holds its roles by value rather than as a `&'static` slice, because an adapter's roles
  are computed. `Place::roles()` is unchanged.
- The registry's members are the ones this project can defend, which is one. cert-manager, Argo,
  Flux and Crossplane are not written, for ADR-0053's unchanged reason: a wrong claim about what
  somebody else's controller means by its fields renders identically to an owner reference.
- Two adapters may cover one GVK; each contributes and the registry concatenates. There is no
  precedence and no de-duplication, and a member that emits an edge another member also emits
  is a defect its own tests should catch.
- Proven by `tests/adapter.rs` (an unknown CRD works without an adapter; an adapted CRD gains
  roles and an evidenced edge; a listed version is adapted; an unlisted one falls back; the
  object is field-for-field what dynamic projection gave; an inference does not pass), by the
  Gateway tests in `tests/workload.rs` unchanged, and by the relations handler's Gateway path in
  the plugin's `tests/query.rs` unchanged.

## Alternatives considered

**A `match kind` in the handler with a comment saying it is a registry.** Rejected: it is the
thing §58.4 names.

**Adapters that return a replacement `Object`.** Rejected: §33.8's `MUST NOT`, and it would make
Gate A's kind-invented-after-the-build depend on which adapters were compiled in.

**A version matcher (`v1*`, `>= v1beta1`) beside the list.** Rejected: an adapter has seen the
field layout of the versions it lists, and a matcher says it has seen versions it has not.

**Moving every built-in table into the registry.** Rejected: it would gate a Pod's own fields on
a version list for no reader's benefit, and it would make the Tier 1 graph look optional.

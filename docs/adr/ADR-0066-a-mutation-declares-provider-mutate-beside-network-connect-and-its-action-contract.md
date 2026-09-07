# ADR-0066: A mutation declares `provider.mutate` beside `network.connect`, and its action contract

- Status: accepted
- Date: 2026-09-07
- Spec refs: §21.1, §21.5, §43.3, §44, §45, §46.3, §51.2, §56.1, §56.3; `ADR-0594 (core)`,
  `ADR-0595 (core)`; ADR-0024
- Decided by: agent (autonomous)

## Context

ADR-0024 recorded a finding this package could not fix from its own side: `network.connect` was
the only capability the two mutating commands could honestly declare, because everything they do
to a cluster travels as bytes through the network broker and KUANG/11 had no capability family for
"change state in the external system a provider fronts". The consequence, stated there: an
operator who granted the connectivity to read a cluster granted, in the same act, the connectivity
to write to one. `risk: mutate`, `risk: destructive` and the dry-run default were real safety
mechanisms and not a security boundary.

Core closed the generic half. `ADR-0594 (core)` added the `provider.mutate` family — the authority
to change the system a provider fronts, checked by the host at every invocation of a contribution
that declares it, before any package code runs. `ADR-0595 (core)` gave a command an `action`
block: the §21.1 contract a host reads to understand an action's safety and type before executing
it.

## Decision

**`set k8s-resource` and `remove k8s-resource` declare `[network.connect, provider.mutate]` and an
`action` block.** Reaching a cluster and changing one are now two grants, and a mutation needs
both. The manifest declares `provider.mutate` as an optional capability, never granted by default.

The action each declares:

- `targets: ["*"]` — the command acts on whatever kind the invocation names, resolved against
  discovery (§15.1, ADR-0010), not a fixed list;
- `mutates: true`, which is why the load-time check of `ADR-0595 (core)` requires the risk and the
  mutating capability that are present;
- `idempotency: conditionally-idempotent` — every write carries a UID precondition (§56.1, §56.3),
  so repeating one is safe under that precondition and no further; it is never replayed on the
  package's behalf;
- `verification` in prose the package stands behind: the field/generation/condition comparison
  against a watch for `set` (§46.3, and the convergence of ADR-0060), the absence-or-different-
  lifetime read for `remove` (§45.1, §16.3);
- `effects`: `changes-desired-state` for `set`, `deletes-object` for `remove`.

## Consequences

The security boundary ADR-0024 said was missing is enforced by the host. A read-only grant of
`network.connect` cannot invoke either write, and `provider.mutate` without `network.connect`
authorises the change and can send nothing. Both are proven, and both prove the cluster saw no
request:

- `crates/ono-kubernetes-plugin/tests/mutation.rs::should_refuse_a_mutation_to_a_read_only_grant_that_can_reach_the_cluster`;
- `…::should_reach_no_cluster_with_a_mutation_grant_and_no_transport`;
- `…::should_refuse_a_mutation_the_operator_granted_no_capability_for` (deny by default, unchanged);

and `tests/contributions.rs::should_declare_a_risk_and_a_granted_capability_for_every_command_that_writes`
now reads both capabilities. The host audits the allowed mutating invocation as well as the denial
(`ADR-0594 (core)`), so both a denied and an allowed write are in the trail.

ADR-0024 stands as the record of the finding; this ADR is where it is closed. The dry-run default
and the risk descriptor keep their jobs — the confirmation the operator sees — and are no longer
asked to be the boundary.

## Alternatives considered

**Declare only `provider.mutate` and drop `network.connect`.** Rejected: the write still travels
as bytes through the network broker, whose scope is which cluster this package may reach at all
(§51.2). Both authorities are real and neither implies the other, which is the whole point.

**Scope `provider.mutate` in the manifest to particular kinds or actions.** Rejected here: the
scope keys are advisory (the broker cannot read the protocol on the connection), and pinning them
in the package would be this package deciding an operator's grant. The operator narrows them on
the grant; the manifest declares the family.

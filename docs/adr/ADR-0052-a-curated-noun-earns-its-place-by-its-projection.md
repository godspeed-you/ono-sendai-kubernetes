# ADR-0052: A curated noun earns its place by its projection

- Status: accepted
- Date: 2026-09-06
- Spec refs: §9.5, §12.3, §12.4, §15.1, §15.2, §15.3, §15.5, §21.3, §44.6, §47.5, §48.1;
  ADR-0010, ADR-0051
- Decided by: agent (autonomous)

## Context

§15.3 lists seventeen kinds a second tier SHOULD include — the platform-operation set: RBAC,
quotas, admission, scheduling, storage plumbing. Every one of them was already readable, through
`k8s-resource` and the discovered floor of §15.1. Nothing was broken, and the SHOULD was unmet.

The question worth answering first was what curation actually buys, because if the answer is "a
shorter command" then seventeen new targets is a poor trade. §15.1 gives it:

> `k8s-resource` … reads whatever the cluster serves and this package never heard of, so a curated
> noun is a *better* answer for a kind rather than the only answer for it.

What makes it better is §15.5's projection. `get k8s-resource --kind ResourceQuota` returns the
whole object with `spec.hard` and `status.used` in their native places; `get k8s-resourcequota`
puts what is allowed beside what has been consumed as two named fields a pipeline can compare. The
same for an autoscaler's decision beside its observation, a VolumeAttachment's error beside its
`attached` flag, a RoleBinding's `roleRef` where §9.5's namespace rule is decided.

## Decision

**All seventeen, in §15.3's order, curated for what an operator troubleshoots with.**

Three things shaped the field sets:

1. **Most of these kinds are rules, not state, and a rule is kept whole.** An RBAC rule, an
   admission webhook, a limit range entry, a CSI node's driver registration — in each, *which keys
   are present* is the intent. §15.5 asks for the fields an operator troubleshoots with, and for a
   rule that is the rule. Flattening one into a sentence is §12.3's prohibition with extra steps,
   and summarising an RBAC rule into a verdict would additionally make this provider the
   authorization oracle §21.3 forbids. So `rules`, `webhooks`, `subjects`, `limits`, `drivers` and
   `validations` are `list<map>`, each entry as the API stated it.

2. **Quantities stay text.** A quota's `hard`, a PDB's `minAvailable`, a RuntimeClass's overhead:
   `1Gi` and `1073741824` are different claims, and "60 percent" is not a count. §12.4 keeps a
   quantity a quantity, and parsing one into a number here would invent precision the object never
   had.

3. **Nothing is evaluated.** A ValidatingAdmissionPolicy's expression is reported and never run; a
   ClusterRole's aggregated rules are labelled as what the controller last filled in rather than
   as the author's intent. What a policy would decide about a particular object is the API
   server's answer, and §21.3 is explicit that even the review that *is* an authorization answer
   does not make this provider one.

**Three field names now collide with Tier 1 and are resolved by pointer rather than by kind.**
`records.rs` projects with one flat `match field.name`, so a name means one projection everywhere:

- `desired_replicas` and `current_replicas` — a controller writes `spec.replicas` and
  `status.replicas`; an autoscaler writes `status.desiredReplicas` and `status.currentReplicas`.
  One question, two spellings, and no object carries both, so a fallback disambiguates.
- `rules` — an RBAC rule lives at the object's top level and a NetworkPolicy's under `spec`, in
  different shapes. Neither pointer reads anything on the other's object.

A `match object.gvk().kind()` would have worked and is what §58.4 warns against. Choosing by what
is *there* is both shorter and safer: a custom resource in someone else's group that happens to be
called `Role` gets whichever field it actually states, and asserts nothing about a kind it is not.

## Consequences

Thirty targets became forty-seven, and `k8s-resource` remains the floor beneath all of them. A
Tier 2 noun deleted from the table costs its user a more verbose spelling and nothing else, which
is the property §15.1 asks curation to preserve.

`ValidatingAdmissionPolicy` is listed by §15.3 as "where served", and needs no special handling:
discovery resolves it or refuses it by name, which is the same answer every kind gets on a cluster
that does not serve it (§11.5).

The seventeen are proven against a recorded server serving one object of each kind, every object
stating a value no other object states — so a projection reading the wrong pointer produces a
visibly wrong record rather than a plausible one. They are not yet proven against a live cluster;
a `kind` cluster serves eight of the seventeen out of the box, and the fixtures for the rest would
be a second pass over `scripts/cluster.sh`.

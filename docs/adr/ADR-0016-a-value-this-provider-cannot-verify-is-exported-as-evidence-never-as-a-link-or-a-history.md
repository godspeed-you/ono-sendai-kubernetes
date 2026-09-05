# ADR-0016: A value this provider cannot verify is exported as evidence, never as a link or a history

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariant 20, §23, §28.3, §28.4, §28.5, §38, §39.2, §47, §60.8, §62.11, §63.6, Appendix C.3
- Decided by: agent (autonomous)

## Context

Two untouched sections of the specification ask the provider to publish data it has no way to
check, and they ask it in the same shape.

**§28.4 and §47** want a Node's `spec.providerID` exported as cross-system identity evidence. The
value names a machine in a system this provider has never spoken to. It is the strongest identity
signal a Node carries, §47.2 says so explicitly, and §47.1 forbids the code that exports it from
knowing what any particular scheme means. `docs/coverage.md` recorded the consequence of leaving
it unread: invariant 20 was the single one of §4's twenty-two that did not hold, because "resolved
outside Kubernetes logic" held vacuously while "evidence-driven" had no code at all.

**§38** wants Kubernetes Events read. They are best-effort, their retention is whatever the cluster
was configured for, their `reason` strings are documented upstream as liable to change, and the
server aggregates repetitions into a count instead of storing what happened. Five of §38's six
subsections are refusals, and §63.6 names "Events as complete historical truth" an anti-pattern.

Both are cases where the useful reading and the wrong reading are one keystroke apart. A providerID
beside an address invites `if node_ip == instance_ip { same machine }`. A list of Events sorted by
timestamp invites reading it as what happened. Neither mistake looks like a mistake in review: the
match is usually right and the ordering is usually plausible.

The question this record answers is where the refusal lives. A comment saying "do not sort these"
is not a mechanism.

## Decision

**One rule, applied twice: a value this provider cannot verify leaves as evidence, carrying what it
rests on and how far it goes, and no type here can turn it into a link or into a history.**

`src/evidence.rs` exports Node identity evidence (§28.3 to §28.5, §47.2, Appendix C.3):

- `spec.providerID` at strength **distinguishing**, keyed `kubernetes.node.provider-id` exactly as
  Appendix C.3 spells it. The raw string is always kept; the decomposition knows `<scheme>://<path>`
  and path separators and nothing else. No scheme is named, no segment is labelled, and a value that
  is not URI shaped is exported whole rather than rejected.
- `status.addresses` at strength **correlating**, each with the address type the API gave it, and
  `status.nodeInfo.systemUUID`/`machineID` — the first distinguishing, the second correlating,
  because a machine id is baked into a disk image and every host cloned from that image shares it.
- The well-known topology, instance-type, architecture, OS and hostname labels at strength
  **placement**, read through their current and deprecated spellings, as `Evidence::Convention` so
  that a label a human can edit does not render like a field the server owns.
- What could not be read is recorded as an `Outcome` from `coverage.rs`: a spec that came back
  without a providerID is `absent`, and a metadata-only projection is `not queried`.

`src/events.rs` reads both Event representations (§38.2) into a type whose refusals are structural:
`Observations` keeps arrival order and offers no sort, no earliest, no latest and no time range;
`Occurrences` carries the recorded count and its endpoints and has no way to expand into occurrences;
`Found` makes an empty search an `Outcome` that is never `Absent`; `Level::Other` and
`Level::Unstated` keep an unrecognised `type` instead of folding it into `Normal`.

**Three things follow from the rule and are worth stating separately.**

*Strength is a second axis, not a second evidence vocabulary.* Every item carries a
`relationship::Evidence` — the existing one — so the distinction between what the API server states
and what someone derived is spelled the same way here as on every edge (§23). `Strength` sits beside
it because §47.2 ranks providerID above IP and name matching, and a consumer that could not see the
ranking would have to rebuild it from field names, which is the foreign-domain knowledge §47.1 keeps
out of this package in a different disguise. `Evidence::Inferred` is produced nowhere in either
module; it belongs to the resolver that has read both systems.

*Neither module can express a relationship.* `evidence.rs` constructs no edge and names no relation,
so §28.5's "IP equality alone MUST NOT establish a verified cloud-resource edge" is not a rule that
could be broken here. `events.rs` relates an Event to what it regards through a `Target` and a
`regards()` predicate that matches on UID first and falls back to the locator only where a UID is
missing — a recreated Pod does not inherit its predecessor's Events (§4 invariants 4 and 5), and an
Event read through one provider instance never attaches to another's objects (Gate J).

*Gate K is asserted by reading the source.* `tests/evidence.rs` fails if a vendor name appears
anywhere in `src/evidence.rs`, including inside a doc comment's example, and if one appears in the
package manifest. `tests/events.rs` fails if a known Event reason literal appears in `src/events.rs`.
Both are checks on text rather than on behaviour, which is unusual and deliberate: these rules die
by degrees — one match arm "just to render the instance id nicely", one branch on one reason string —
and each degree is individually defensible and collectively fatal. A test that reads the source is
the only kind that fails on the first degree.

## Consequences

Easy: §4 invariant 20 now holds in the domain library. A Node exports its provider identifier, its
typed addresses, its self-reported host identifiers and its placement labels, each with a strength, a
resolvable JSON-pointer citation and an evidence class, inspectable with no foreign provider attached
(§47.7). §60.8's steps 1, 2 and 4 are met; step 3 is a resolver in another package. Gate K holds and
is checked. §38 has an implementation whose refusals a later author cannot forget, because reaching
for them does not compile into anything.

Hard: neither module reaches a user. They join `relationship`, `workload`, `place`, `watch` and
`condition` as domain code the plugin does not import — gap 4 of `docs/coverage.md`, unchanged by
this work and not made worse by it. Invariant 20 holds *in the library*; the row for §47 stays
"domain only" until something routes it.

Watch: the source-reading tests are as strong as their word lists. A vendor the list does not name,
or a reason literal it does not know, passes. The lists are visible at the bottom of each test file
so that extending them is obvious, and the doc comment of each module states the rule the list is
only a sampler of.

Watch also: `evidence.rs` carries no observation timestamp, where Appendix C.3's sketch shows an
`observed_at`. Nothing in this provider reads a clock — the whole domain layer is a function of bytes
already received (§59.1) — so the observation time belongs to the read that produced the object, and
inventing one here would be the smallest possible version of the fabrication both modules exist to
prevent.

## Alternatives considered

**Parse the providerID by scheme, so a user sees a labelled instance identifier.** Rejected: §28.4
forbids it in as many words, and it is the exact mechanism by which a provider acquires a cloud
dependency. The decomposition stops at the generic URI shape, and the resolver that knows the scheme
does the rest — which is also the only place that knowledge can be kept current.

**Let evidence produce an inferred edge to a foreign resource when an address matches.** Rejected:
§28.5 forbids it, and it would be useless as well as wrong — this package has read only Kubernetes,
so it has nothing to match the address against. The correlation is the resolver's finding, and
`Evidence::Inferred` is where the resolver puts it.

**Model Events as a `Timeline` with `earliest`, `latest` and a time range.** Rejected as the direct
route to §63.6. Event timestamps come from the clocks of the components that reported them, delivery
is unordered, and retention has already discarded some — so an ordering assembled from them looks
like a causal history and is an artefact of three unrelated accidents (§39.2).

**Expand an aggregated count into that many occurrences, so a caller can iterate them.** Rejected as
the failure §38.4 names: 46 of 47 aggregated failures were never observed individually, and the
records produced would be indistinguishable from ones that had been.

**Return `Vec<Event>` from a search and let the caller check `is_empty`.** Rejected: it makes
`if events.is_empty() { nothing went wrong }` the natural spelling, which is §38.6 broken in one
line. `Found::NotObserved` carries an `Outcome` for which `is_evidence_of_absence()` is false.

**A second evidence enum for cross-system facts.** Rejected: §23's classes already draw the line that
matters — stated by the server against derived by someone — and a second vocabulary would let the two
disagree about what a convention is. Strength was added as an orthogonal axis instead, because §47.2
ranks evidence and §23 does not.

# ADR-0069: `trace` and `diff` are the shell's, and reach no contributed target by design today

- Status: accepted
- Date: 2026-09-07
- Spec refs: §0.4, §4 invariant 13, §35.5, §35.7, §40.3, §53.8, §69; core's v0.2 §22, v0.4 §31,
  v0.5; `ADR-0584 (core)`, `ADR-0585 (core)`; ADR-0027, ADR-0068
- Decided by: agent (autonomous)

## Context

§69's list of the eleven verbs a user should be able to think in names `trace` and `diff`. Neither
reaches Kubernetes, and until now the coverage map said so without saying whether that was a gap
in this provider, a gap in core, or a boundary. A statement that can be read three ways is the
ambiguity this repository's stopping rule forbids.

What the code says:

- **`trace`** is bound per target by core's command contracts (`ono.<target>.trace`), and its
  implementation walks the kernel relationship providers of `ono-graph` — procfs, systemd, the
  container engine. `ADR-0585 (core)` opened `look`, `near`, `follow` and `map` to a package's
  contributed relations and lists what it did not open; `trace` is not among the four. So
  `trace k8s-pod` is refused by the shell with `resolve.target_not_found` — "`trace` has no target
  `k8s-pod`", pointing at `help trace` — before this package is consulted, exactly as it would be
  for any package. It is not this provider's to change: a `trace` over contributed relations is a
  generic increment in core, and §0.4 forbids a Kubernetes special case there.
- **`diff`** (§53.8, `diff now -10m`) is core's v0.5 Temporal & Causal Systems Interface, which is
  specified and not implemented in core. A snapshot comparison this package built for itself would
  be the second grammar §35.1 forbids.

What the same graph *is* reachable through: `near` and `follow` at any Kubernetes place
(`ADR-0585 (core)`, ADR-0027), `get k8s-relation` for every edge with its evidence (ADR-0014), and
`get k8s-why --depth N` for the paths between objects (ADR-0068).

## Decision

**`trace` and `diff` are outside this provider's scope by design, not by omission: both wait on a
generic increment in core, and this repository records the boundary and pins its shape.**

The shape is pinned by
`tests/spatial_shell.rs::should_refuse_trace_on_a_kubernetes_noun_by_name_rather_than_answer_an_empty_graph`:
with the package loaded and every grant given, `trace k8s-pod` refuses by name and answers no
graph value, and `near` at the same object answers the neighbours. The test exists so that the
boundary cannot drift into the worse state — an empty graph that reads as "this Pod is related to
nothing" (§4 invariant 13).

Nothing in this package declares, documents or hints at a `trace` or `diff` route. `coverage.md`'s
§53 and §69 rows classify both as *outside scope, generic core increment*, distinct from "not yet
implemented here".

## Consequences

- A reader of `coverage.md`, the README or the board finds one classification for the two verbs,
  and it names what would change it: in core, a relationship provider over contributed relations
  bound to `trace` for contributed targets; and the v0.5 tranche for `diff`. When either lands,
  this package needs no change to be reached by it — its relations are declared in the manifest
  and answered through `spatial-relations` — and the test above is the one that turns red.
- The two are listed in `coverage.md`'s "What is left" beside the remote sessions and the Tier 3
  ecosystems, as the third reservation with a reason.

## Alternatives considered

**Build `trace` in core now, as a generic relationship provider over contributed relations.**
Declined for this pass. It is a real increment and a provider-neutral one, but it is a core
feature — a new command binding for every contributed target, a bridge from the spatial
contribution registry to `ono-graph`'s provider trait, and contracts for both — and this pass is
a completion of what exists rather than a widening of it. It is recorded on core's board as the
finding it is.

**Contribute a `k8s-trace` noun that answers a graph value.** Rejected: the first word of the
mini-shell §35.1 forbids, and a second `trace` beside the shell's own.

**Say nothing and leave the §69 row as it was.** Rejected: "does not reach Kubernetes" without a
reason is the ambiguity this record exists to remove.

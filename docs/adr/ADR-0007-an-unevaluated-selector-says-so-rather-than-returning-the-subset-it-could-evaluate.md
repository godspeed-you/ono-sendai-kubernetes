# ADR-0007: An unevaluated selector says so rather than returning the subset it could evaluate

- Status: accepted
- Date: 2026-09-05
- Spec refs: §4 invariant 13, §21.4, §23.3, §23.5, §25.1, §26.1, §62.4 (Gate D), §62.5 (Gate E)
- Decided by: agent (autonomous)

## Context

Kubernetes label selectors have two halves. `matchLabels` is a map that must all match.
`matchExpressions` is a list of operators — `In`, `NotIn`, `Exists`, `DoesNotExist` — that must
*also* all match. The two are combined with AND, which has an uncomfortable consequence for a
partial implementation: evaluating `matchLabels` alone produces a set that is **wider** than the
selector, never narrower. An object that an expression excludes arrives looking selected.

This provider evaluates `matchLabels` today and not `matchExpressions`. The question is what a
selector carrying expressions should return.

The signature that suggests itself is `Vec<Edge>`, and both of its plausible answers are false.
Returning the `matchLabels` matches presents objects as selected that the selector excludes, which
is a guessed relationship rendered as a provider-derived one — the thing §23.3 and Gate D exist to
stop, and worse than a guess elsewhere because a selector *looks* authoritative. Returning an
empty vector says "nothing matched", which is a statement about the cluster, while what is true is
"this was not evaluated", which is a statement about the provider. That is exactly §21.4's
distinction between a denied read and an empty result, transposed from RBAC onto selectors:
absence of results is not a result.

## Decision

`Workload::selector_matches` returns a `SelectorMatch`, not a `Vec<Edge>`:

- `Evaluated(Vec<Edge>)` — the selector was applied in full to every candidate offered, and the
  edges are the answer. An empty vector here genuinely means nothing matched.
- `NotEvaluated { reason }` — the selector was not applied, no candidate may be presumed excluded,
  and the reason is stated in the words of the field that stopped it.

Three cases produce `NotEvaluated`: a `matchExpressions` list that is present and non-empty; an
object stating no `spec.selector` at all; and an empty `matchLabels`, because an empty selector is
not a match on everything (§26.1's "an empty selector or selector-less Service MUST not create
guessed Pod edges").

The caller has to look at which variant it holds, so the difference cannot be lost by accident.

## Consequences

Easy: the wrong answer is unrepresentable. There is no value of this type that means "here are
some of the matches"; either the evaluation happened or it is named as not having happened. When
`matchExpressions` is implemented, the enum does not change — the case that returns
`NotEvaluated` for expressions simply stops being reached — so this is a decision about honesty,
not a shape that has to be undone later.

Easy, too: the reason travels. An operator following `selector-matches` from a Deployment that
uses expressions is told which field stopped the evaluation rather than shown a plausible-looking
list, and the same phrasing works for the selector-less and empty-selector cases.

Hard: every caller matches on two variants for what looks like a list, including the callers that
would be happy with a best effort. That cost is paid at every call site and is the point — a
call site that wants to ignore the distinction has to write the code that ignores it.

Hard, too: real clusters use `matchExpressions`, particularly for canary and migration workflows,
and those are exactly the situations in which an operator most wants the graph. Until the
operators are implemented, this provider is less useful there and says so instead of being
confidently wrong there.

Watch: the four operators are not difficult, and the reason they are not implemented is sequencing
rather than depth — `selector_matches` is a §25.1 curated relation and the K2 operational graph is
a later phase. The risk is that `NotEvaluated` becomes comfortable and stays. It is on the board
as work, not as a design.

Watch also: ownership is unaffected and must stay so. `Workload::owns` reads owner references and
is proof (§23.2); `selector_matches` is weaker evidence with a separate label (§23.3). A future
convenience that merged the two — "give me the Pods of this Deployment" — would have to decide
what to do when the selector is unevaluated and the owner references are complete, and the answer
is that it reports both, because they are different claims.

## Alternatives considered

**Return the `matchLabels` subset with a warning attached to each edge.** Rejected: it renders
excluded objects as selected, and a warning on an edge is read after the edge is believed. §23.5
forbids promoting a guess to a verified relationship, and a superset of the true answer is a guess
with a good disguise.

**Return an empty `Vec` and log.** Rejected: an empty result is a claim about the cluster. This is
the §21.4 error in miniature, and a log line is not visible to the pipeline that consumed the
empty list.

**Implement `matchExpressions` now.** Not rejected on merit — it is the right end state, and it is
sequenced after the K2 graph rather than argued against. What this ADR decides is what the type
says in the meantime, which is a question that survives the implementation: `NotEvaluated` will
still be needed for the selector-less and empty-selector cases.

**Return `Result<Vec<Edge>, SelectorError>`.** Rejected as the wrong meaning: an unevaluated
selector is not an error. Nothing went wrong, nothing failed, and a caller that treats it as a
failure would abandon a traversal that is otherwise fine. It is a coverage statement, and it reads
as one.

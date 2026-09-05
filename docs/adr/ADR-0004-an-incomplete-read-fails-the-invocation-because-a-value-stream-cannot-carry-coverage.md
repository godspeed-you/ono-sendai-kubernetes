# ADR-0004: An incomplete read fails the invocation, because a value stream cannot carry coverage

- Status: accepted
- Date: 2026-09-05
- Spec refs: §4 invariant 13, §18.1, §18.2, §18.3, §18.4, §21.4, §21.5, §62.5 (Gate E); core spec §31.23, §31.68
- Decided by: agent (autonomous)

## Context

The domain layer models incompleteness properly. A `Listing` carries the objects that arrived
*and* a `Coverage` — which scopes were observed, which were denied, which were never queried —
*and* a `Continuity`, because "did every scope answer" and "do the answers belong together" are
two different questions (§18.2). §21.4 requires at least eight distinguishable outcomes, of which
"there is nothing there" is one and the other seven are not.

The host protocol has nowhere to put that. A contributed target declares exactly one schema
(core §31.23), and every value the handler emits is checked against it; a value of another shape
closes the stream. A handler ends with `Completed`, `Failed(WireError)` or `Cancelled`, and there
is no third channel — no per-stream metadata, no trailer, no collection object that the records
hang off. So a `Coverage` record cannot ride along beside the Pod records, and there is no
"collection result" to attach an error to in the sense §18.3 means it.

That leaves two candidate shapes for a query whose read was denied a namespace, or whose page N+1
failed. Emit what was read and report `Completed` — which presents a `403` as a complete answer
and is the exact failure §21.4 and Gate E exist to prevent. Or emit nothing and fail — which
throws away values that are true, and §18.3 explicitly permits returning them.

## Decision

**The handler emits what it read, and then fails the invocation with the gap described.**

`query::emit` streams every object it has, each through the redaction boundary and into a record
of the target's schema, and then asks the listing two questions: is the coverage complete, and is
the continuity intact. If both, the outcome is `Completed`. Otherwise the outcome is `Failed`,
carrying `provider.unavailable`, the coverage description in the message, and help text that
spells out the distinction the user needs:

> The records that did arrive are true. What is missing is named above — a denial, an unserved API
> and an exhausted page budget are different things, and none of them means the cluster is empty.

A broken continuity gets its own message, because a listing stitched from two snapshots is
coverage-*complete* and still not one observation.

This is §18.3's "partial page with the error attached" carried as closely as the protocol allows:
the values cross first, the error follows, and the two arrive on the same invocation.

## Spec deviation

**§18.3 Partial-page failure.** The specification says:

> If pages 1..N succeed and page N+1 fails, the provider MAY return the already received values,
> but coverage MUST be `partial` and the error MUST be attached to the collection result.

At this boundary there is no collection result. The provider's answer to a contributed target is a
stream of records of one declared schema, and a coverage state is not a record of that schema.

**The rule that replaces it:** the error is attached to the *invocation* that produced the stream,
and the invocation fails. Coverage is reported in the failure's message rather than as a field of
a collection. The clause that matters most is kept literally and strengthened rather than weakened
— §18.3's "a default table MUST NOT look identical to a complete result" holds, because a partial
read does not produce a completed invocation at all.

This deviation is local to the shape of the report. It does not weaken §21.4: the eight outcomes
are still distinguished inside `Coverage`, and the text that reaches the user names which one
occurred. When core grows a way for a value stream to carry a coverage annotation, this decision
should be revisited, and the domain layer already holds everything such an annotation would need.

## Consequences

Easy: a denial cannot render as an empty table by any route through this package, and neither can
an exhausted continue token. The user still receives every object that was genuinely read, so the
answer is useful as far as it goes and says where it stops going.

Hard: at the level of the outcome *code*, a partial read is indistinguishable from a transport
failure — both are `Failed` with `provider.unavailable`. Only the message and the coverage
description separate them, and a machine reading the code alone cannot. The alternative would be
inventing an error code the KUANG taxonomy does not define, which would put a code on the wire
that no registry explains; the package refuses to do that for the same reason it refuses to invent
an endpoint.

Hard, too: a pipeline that wanted only the first rows still receives a failed invocation if the
read was denied somewhere. That is the intended trade — a `first 20` over a listing that could not
see three namespaces is twenty true rows out of an unknown population, and saying so is the point.

Watch: §18.4's other half is not carried yet. A deliberately limited listing — a page budget the
caller set — is coverage-*complete* by design, so it completes, and the `may_have_more` flag the
domain layer sets is dropped on the way out. §18.4 says the value stream SHOULD still know that
more upstream results may exist, and this stream does not. The same protocol constraint causes it
and the same future mechanism would fix it; it is recorded on the board rather than left as a
silent difference between what the domain layer knows and what the user is told.

Watch also: the partial path is proven at the domain level (`tests/transport.rs` returns the pages
that arrived with partial coverage when a later one fails) and is not yet driven end to end
through the test host. Until it is, the mapping from "coverage is partial" to "the invocation
fails" is tested by reading rather than by running.

## Alternatives considered

**Complete the invocation and emit a final record describing the coverage.** Rejected: it would be
a record of a different schema on a stream that declares one, which the host refuses — and if it
were made to fit by adding coverage fields to every Kubernetes schema, every Pod row would carry a
cluster-wide observation state that is not a property of that Pod.

**Complete the invocation and report the gap as a warning through a side channel.** Rejected:
there is no such channel for a provider target, and a warning that the pipeline can drop is
exactly the "default table that looks identical to a complete result" §18.3 forbids.

**Fail without emitting anything.** Rejected: §18.3 permits returning the values already received,
and discarding true observations because part of the read failed is a second, avoidable loss —
particularly for §21.5's partial namespace visibility, where the readable namespaces are usually
the ones the operator is standing in.

**Ask core for a coverage annotation on the value stream now.** Rejected as premature rather than
wrong: it is a change to the generic provider contract, so it belongs in an ADR in core, and it
should be proposed with evidence from a working provider rather than from a design sketch. This
package will have that evidence once K1 is real.

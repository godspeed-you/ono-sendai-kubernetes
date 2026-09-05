# ADR-0006: `ResourceVersion` carries no ordering, so the forbidden comparison does not compile

- Status: accepted
- Date: 2026-09-05
- Spec refs: §4 invariant 6, §14.3, §19.1, §19.4, §20.4, §62.6 (Gate F), §63.11
- Decided by: agent (autonomous)

## Context

§14.3 is unusually specific about what `resourceVersion` must not become:

> It MUST NOT be:
> - sorted numerically across unrelated resources as a timeline;
> - converted into a timestamp;
> - used as a cross-resource causal clock.

Kubernetes documents the field as an opaque string. That it *usually* looks like an increasing
integer is an etcd implementation detail the API contract does not promise, and it is the reason
this rule needs writing down at all: every one of the forbidden operations works on a development
cluster. Sorting a change list by `resourceVersion`, taking `max()` over a page to find "the
latest", comparing one resource's token against another's to decide which observation came first —
all three pass their tests, ship, and are wrong in a way that only appears against a server that
hands out something else, or across two resources whose counters were never related.

A doc comment saying "do not order this" is a rule enforced by attention. Deriving `Ord` alongside
`PartialEq` is one word in a derive list, and once it is there, `versions.iter().max()` reads like
ordinary good code in review.

## Decision

`ResourceVersion` is a newtype over `String` that derives `Debug`, `Clone`, `PartialEq`, `Eq` and
`Hash`, and **deliberately does not derive `Ord` or `PartialOrd`**. It also offers no
`is_newer_than`, no `succeeds`, and no numeric accessor. It has `new`, `as_str` and `Display`.

Equality is kept because it is meaningful: two identical tokens name the same continuity point,
which is what a checkpoint comparison actually needs. Ordering is dropped because the API contract
does not define it, and a type that carries an operation its domain does not define is an
invitation with a comment next to it.

The questions that look like they need ordering are answered elsewhere and better. "Have we missed
anything since the checkpoint?" is answered by the server, with `410 Gone`, and by the watch state
machine that turns a `410` into a segment boundary (§19.4, Gate F). "Which observation came first?"
is answered by the order of the observations, which the segments record. Neither needs the token
compared to anything except itself.

The rule lives in the type rather than in a comment because a comment cannot fail a build, and
this is precisely the mistake that otherwise fails no test.

## Consequences

Easy: the three operations §14.3 forbids do not compile. `max()`, `sort_by_key`, `>` and
`BTreeSet<ResourceVersion>` are all unavailable, so the reviewer's attention is spent on things
attention is needed for. A future author who genuinely needs an ordering has to write the `impl`,
which is a visible act with this record to argue against, rather than a derive nobody notices.

Hard: some legitimate-looking conveniences go with it. A cache cannot deduplicate events by
"keep the highest version seen" and instead keys by `Identity`, which is what §16.1 says identity
is anyway. A change list cannot be sorted for display by version and is instead shown in the order
it was observed. Ordered map keys need the string, taken deliberately.

Watch: `as_str` exists, so `a.as_str() < b.as_str()` is one call away, and `String`'s ordering is
lexicographic — which is wrong even on the clusters where numeric ordering would have been right
(`"10" < "9"`). The type makes the mistake harder to reach and not impossible to reach, and that
is the honest limit of what a newtype achieves.

Watch also: the token leaves this package as a nullable string field on every record
(`resource_version`, §14.1). A pipeline can sort a string column, and nothing here can stop it.
§14.3 binds the provider rather than the user; what the provider owes is not doing it itself and
not presenting the field as something ordered — which is why it is projected as a string and never
as a number.

## Alternatives considered

**Derive `Ord` and rely on the doc comment.** Rejected: the comment is on the type and the mistake
happens at the call site, three files away, in code that looks correct and passes every test
written against a cluster that hands out integers.

**Offer `is_newer_than` as a checked comparison.** Rejected: it would have to lie. There is no
definition of "newer" the API contract supports, so the method could only implement a heuristic —
parse as a number, fall back to string order — and a heuristic behind an honest-sounding name is
worse than no method, because the call site stops looking like a decision.

**Parse to `u64` where it parses and treat the rest as unordered.** Rejected: it works on almost
every cluster, which is exactly what makes it dangerous, and it is the "numeric timeline" §14.3
names first. It would also silently change behaviour when a server changes format, with no failure
to notice.

**Keep the field as a plain `String` and rely on review.** Rejected for the opposite reason: a
plain `String` has ordering, so this would be the derive alternative with less type safety and no
place to put the explanation.

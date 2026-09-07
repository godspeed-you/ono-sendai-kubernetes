# ADR-0067: An empty answer that proves nothing is inconclusive, and a refused credential is an authentication failure

- Status: accepted
- Date: 2026-09-07
- Spec refs: §8.3, §8.4, §21.4, §38.6, §42.1, §46.4, §48.2, §63.6; `ADR-0592 (core)`;
  ADR-0025, ADR-0028, ADR-0055
- Decided by: agent (autonomous)

## Context

Two refusals this package makes had no exact code and borrowed a near one, which the coverage map
recorded as a standing deviation:

- **an empty answer that proves nothing** — a `k8s-event` search that matched no Event, a `k8s-log`
  read or follow that produced no line. `contribution.refused` (ADR-0028) carried it, which says
  *the package declined under a precondition of its own*; the truer statement is that the cluster
  answered and its emptiness establishes neither presence nor absence, because Event retention is
  minutes and a log may have been rotated away (§38.6, §63.6, §21.4);
- **a credential the external system would not accept** — a helper that failed at refresh, a
  malformed or already-expired `ExecCredential`, an API server that answered `401`. ADR-0055
  borrowed `provider.unavailable`, which says the cluster did not answer when it did (§8.3, §8.4).

`ADR-0592 (core)` added the four codes that make these exact: `provider.inconclusive` (E0404) and
`provider.authentication_failed` (E0405), beside `provider.authorization_denied` and
`provider.rate_limited`.

## Decision

**`k8s-event`'s unobserved-search refusal and `k8s-log`'s empty-read and empty-follow refusals are
`provider.inconclusive`; the credential class is `provider.authentication_failed`.**

`events::not_observed`, `logs::empty` and `logs::unfollowed` move from `contribution.refused` to
`provider.inconclusive`. `query::AUTHENTICATION_CODE`/`AUTHENTICATION`, which every credential
failure routes through (ADR-0055), move from `provider.unavailable` to
`provider.authentication_failed`. The messages are unchanged, so the assertions that read them
still hold; the code a script matches on is now the one that is true.

What stays `contribution.refused`: a plan refused for a missing precondition, and any place this
package declines under a rule of *its own* rather than reporting an inconclusive observation
(ADR-0028 keeps that distinction — the two are now told apart by the two codes rather than sharing
one). What stays `provider.unavailable`: a partial read that did not see everything it asked about
(a coverage gap is not an inconclusive emptiness), and a cluster that genuinely did not answer.

## Consequences

The error registry now keeps apart, on this provider's own refusals, the truths §48.2 and the
generic contract's §19.1 ask a provider to distinguish: unsupported, unavailable, denied,
safety-refused, authentication-failed, and inconclusive-not-absence. A pipeline that treated an
empty `k8s-event` as "nothing happened" was matching a lie under the old code and matches
`provider.inconclusive` — the `provider` kind, which a script reads as "unknown, not absent" —
under the new one; a `401` after a stale credential is `provider.authentication_failed`, the
`permission` kind, whose fix is a credential rather than a retry.

Encoded by the tests that already assert these refusals by message, now over the exact codes:
`tests/query.rs::should_refuse_an_unobserved_event_search_rather_than_answer_empty` and
`should_refuse_to_answer_an_empty_log_with_an_empty_stream`, and the credential-failure tests of
`tests/isolation.rs` (ADR-0055).

## Alternatives considered

**Leave `contribution.refused` on the empty-event and empty-log cases.** Rejected: `ADR-0592 (core)`
names these as the call sites for `provider.inconclusive`, and the distinction between "the package
declined" and "the answer is inconclusive" is exactly what the two codes exist to keep. A reader of
`contribution.refused` looks for a precondition to satisfy; there is none — the read succeeded.

**Add a Kubernetes-specific code.** Rejected: emptiness-is-not-absence and credential-refusal are
generic provider truths, which is why they are core codes (§0.4).

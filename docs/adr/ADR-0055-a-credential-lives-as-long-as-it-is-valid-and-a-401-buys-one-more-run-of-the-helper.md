# ADR-0055: A credential lives as long as it is valid, and a 401 buys one more run of the helper

- Status: accepted
- Date: 2026-09-07
- Spec refs: §6.3, §6.5, §8.1, §8.2, §8.3, §21.4, §51.6; §8.3 and §8.4 of the generic provider
  contract; ADR-0021, ADR-0054
- Decided by: agent (autonomous)

## Context

ADR-0054 made a kubeconfig's credential plugin run, and left §8.3's second sentence open:

> Credential expiry MUST be honored. Refresh SHOULD occur before a request when the credential is
> expired or according to standard client behavior.

A credential was fetched once per endpoint resolution and stored on the `Endpoint` for that
invocation. Every invocation of a managed-cloud context ran the helper again — a network round
trip to an identity provider per query — and a credential that expired mid-session produced the
API server's `401`, which an operator reads as *their* RBAC being wrong. The generic contract's
§8.4 asks that `authentication expired` be distinguishable from `authorization denied`, and a bare
`401` surfaced as a denied read is not that.

ADR-0021 fixed the shape of a session: keyed on what the operator configured, never on what the
cluster said, and holding no credential material. A credential that outlives one invocation
therefore needs a home that is not the session.

## Decision

**A credential store, keyed on the source and never on the token; refresh before a request when
the credential is expiring; and after a `401`, one more run of the helper and one more request.**

1. **`credential_store::CredentialStore`** holds one entry per `SourceKey`: the session identity
   (provider instance, endpoint URL, transport posture — ADR-0021's key) plus the *source
   identity*: the kubeconfig path list, the context, and the helper's command, arguments and
   environment. Two resolutions are the same credential exactly when both halves match. What the
   helper *returned* is the entry's value and never part of its key — a key is a thing that ends up
   in maps, in comparisons and in debugging, and §8.1 keeps credential bytes out of all of those.
   The material is held as `Secret`, renders as `<redacted>`, and no record, `Debug`, log, audit
   record or error text carries it.

2. **Each entry has a lock held across the helper run.** Concurrent invocations that meet one
   expiry wait for a single run and reuse its result. The stampede — every open query launching a
   helper the instant a token dies — is what a shared store exists to prevent.

3. **Expiry is tracked from the `ExecCredential`'s own `expirationTimestamp`**, parsed to an
   instant. A credential is refreshed *before* a request when it is expired or within thirty
   seconds of expiring — the early-refresh margin. Thirty seconds is longer than any single round
   trip this package makes and far shorter than a managed-cloud token's lifetime, so a credential
   about to die is refused without churning a healthy one. A credential stating no expiry, or one
   this provider cannot parse, has no instant to refresh before and is used until the API server
   refuses it (ADR-0054's rule, unchanged).

4. **Refresh is the same run as first acquisition.** `credentials::run` checks the `process.exec`
   grant again, honours `interactiveMode` again, parses an `ExecCredential` or nothing, and refuses
   an already-expired replacement. Every run is a credential-plugin execution in the audit trail
   (§51.6). Nothing about a refresh is less policed than the first run.

5. **One `401` buys one refresh and one retry.** When the API server answers `401` to a request on
   a refreshable credential, the helper is run once more, the replacement goes on the *same*
   connection (`Client::replace_default_header`), and the same request is sent once more. A second
   `401` ends it with an explicit authentication failure; nothing is sent a third time and the
   helper is not run a third time. Replaying is safe for reads and writes alike: authentication
   precedes admission, validation and persistence in the API server, so a request refused as
   unauthenticated ran nothing — there is no side effect to duplicate. On a listing the replay
   happens only before any page has crossed, because a second first page would be a second
   snapshot (§18.2).

6. **Every failure of this class goes through one function.** `query::authentication_failure`
   carries `AUTHENTICATION_CODE` and `AUTHENTICATION`, which today borrow `provider.unavailable`
   — a cluster this provider cannot reach *as anyone* is unreachable to it — with a message in
   §8.4's own word. A helper that fails at refresh, a malformed replacement, a replacement already
   expired, a grant gone at refresh time and an API server that refuses the replacement too are
   all reported there, and a dedicated core code is adopted in one edit. The policy refusals of
   ADR-0054 at first acquisition — no grant, `interactiveMode: Always` — keep `provider.unsupported`,
   because they are this package's rule and not a credential's failure.

7. **The store is a process-global, installed beside `Sessions` in `crate::plugin`.** It is
   reached from `Endpoint::resolve`, which every target handler calls with nothing but a `Ctx`;
   handing it to each handler would mean changing signatures in modules this work does not own.
   The session key itself is unchanged and still holds no credential (ADR-0021).

## Consequences

- The second query of a managed-cloud context costs no helper run
  (`should_run_the_credential_plugin_once_while_its_credential_stays_valid`); one that has expired
  runs the helper again before its first request
  (`should_run_the_credential_plugin_again_once_its_credential_has_expired`); two invocations
  meeting one expiry share one run
  (`should_run_one_credential_plugin_when_two_invocations_meet_one_expiry`). The store's own
  rules — margin, no expiry, two sources, no caching of a failure, forced refresh, one run under
  contention — are unit-tested with a fixed clock.
- A token revoked between two invocations is replaced on the wire once
  (`should_send_the_replacement_credential_the_plugin_returns_after_a_401`,
  `should_retry_a_direct_read_once_with_the_replacement_credential`: exactly two requests, two
  distinct `Authorization` headers) and the refusal of the replacement stops the invocation
  (`should_stop_after_one_refresh_when_the_api_server_refuses_the_replacement_too`).
- A refresh that yields no usable credential — an expired replacement, a malformed one, a helper
  that fails — ends with `authentication_failure` and nothing sent with the stale credential.
- The credential appears in no record, error, audit record or log line of either a successful or
  a failed invocation (`should_keep_the_credential_out_of_every_record_error_audit_and_log`).
- The one sleep in the suite is the three and a half seconds two tests wait for a credential to
  cross the early-refresh margin; it is the only way a wall clock moves a credential from valid to
  expiring, and the assertions are shaped so that a slower machine cannot fail them.
- A grant revoked *between* two invocations of one process cannot be exercised through the test
  host, whose grants are fixed at load; the store's refusal to cache a failed run and the
  first-acquisition refusal of ADR-0054 are the proof that path has.
- The `401` retry covers the two read paths the query module sends itself — the listing and the
  direct read. Handlers that build their own requests get the pre-request refresh through
  `Endpoint::resolve` and read the current credential through `Endpoint::authorise`; a `401`
  inside them is still the API server's answer, distinguished by `ErrorKind::Unauthenticated`.

## Alternatives considered

**Keep fetching per resolution (ADR-0054).** A helper run per query is a round trip to an identity
provider per query, and a credential that expires mid-session is a `401` reported as a denial.

**Hold the credential on the session.** Forbidden by ADR-0021 and §8.1: a session is serialised
into diagnostics, and a credential must not be.

**Key the entry on the token bytes.** The obvious way to tell two credentials apart, and the one
§8.1 rules out: the key is what ends up in maps, comparisons and debugging output.

**Refresh without a margin, on expiry alone.** A credential valid at the moment of the check and
dead by the time the request arrives produces exactly the `401` the refresh exists to avoid.

**Retry a `401` more than once, or refresh on every `401` without a bound.** An identity provider
that has revoked a principal answers every refresh with a token the API server refuses; an
unbounded loop is a hang, and a bounded one is an answer.

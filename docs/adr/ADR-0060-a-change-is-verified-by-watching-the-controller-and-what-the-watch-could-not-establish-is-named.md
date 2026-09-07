# ADR-0060: A change is verified by watching the controller, and what the watch could not establish is named

- Status: accepted
- Date: 2026-09-07
- Spec refs: §19.1, §19.4, §20.3, §20.4, §20.5, §21.4, §37.3, §37.5, §45.1, §46.3, §46.4,
  §62.7 (Gate G), §62.12 (Gate L); §16.4 and §21.6 of the generic provider contract in core;
  ADR-0019, ADR-0037, ADR-0046, ADR-0058, ADR-0059
- Decided by: agent (autonomous)

## Context

`set k8s-resource` verified a persisted change with one `GET` made immediately after the write,
under a window of zero: anything not decisive at that instant was `Inconclusive`. That was honest
— §46.4 says a verification that did not finish is neither success nor failure — and it was
coarse: a scale that converges in four seconds was reported as incomplete every time, and the
machinery §46.3 describes (accepted, generation advanced, controller observed, replicas
satisfied) had nowhere to run. §46.4's own words are "explicit timeouts/cancellation", which
presupposes something to time out.

§16.4 of the generic contract says why the immediate read is not enough: "GET may lag mutation
result … relationship indexes may lag resource creation. Ono SHOULD use these semantics in
verification windows rather than declaring failure too early." And §20.4's ladder — accepted,
spec observed, generation observed, status converged — is a sequence a controller climbs over
time, which only an observation *over time* can report.

## Decision

### 1. One read, then a watch, under an explicit window

`verify` still makes the immediate read: it is a direct observation (§20.2), it decides the cases
that need no waiting — a field that is already on the object, a node already cordoned — and its
`resourceVersion` is where the watch opens from, so nothing between that observation and the
watch is missed (§19.1). Where the read leaves the rule `Pending`, `converge` watches the target
until the rule is proven, refuted, or `VERIFICATION_WINDOW` (sixty seconds) ends.

The window applies to the rules a watch can prove. An absence is established by a read (§45.1),
and a rule this provider does not have is proven by nothing, so those two keep a window of zero
and answer at once.

### 2. The session's own watch first, then a bounded watch of the invocation's own

Where the session holds a live watch over the target's collection and scope — fed by another
invocation, which borrows the session per event (ADR-0058) — the cache is polled through
`Session::lookup` and the verdict is drawn from the objects that watch delivers. Otherwise the
invocation opens its own watch, narrowed to the target by `fieldSelector=metadata.name=<name>`
and opened at the read's version, reads it under `ReadPolicy::watch`, and releases it with the
conversation. A body that ends cleanly is reopened from its last checkpoint while the window
allows (§19.5).

### 3. Nothing is fabricated, and every way of not finishing is named

`Verification::unfinished` carries an `Unfinished` reason beside the last observation's stage and
reconciliation state, so the record still says how far the evidence reached:

| Reason | When |
|---|---|
| `generation_not_observed` | the window ended and no controller had recorded the generation (§37.3) |
| `conditions_inconclusive` | the window ended with the generation observed and the status not decisive |
| `window_expired` | the window ended before any observation of the target arrived |
| `watch_gap` | `410 Gone`, as a status or as a frame: what followed the break is unobserved (§19.4, Gate F) |
| `partial_coverage` | the observation had a hole in it — a frame that could not be read |
| `watch_unavailable` | the watch could not be opened: denied, not served, failed (§21.4) |
| `target_gone` | the target left the collection while the change was being verified (§16.3) |

Each is `Inconclusive` — "not evidence that the change failed, and not evidence that it
succeeded" — and the verdict's sentence carries the token in brackets so a pipeline can filter on
it. A `403` on the follow-up read stays what §21.4 makes it: not absence, and now also not a
denied *change*.

### 4. A write to a collection a live watch covers quarantines the object, not the stream

ADR-0037 had `Session::mutated` drop every watched cache that could hold the written object. That
was right while no other invocation could be feeding one — a watch held its session for its whole
life until ADR-0058 — and wrong the moment one can: dropping a live stream discards every other
object it was keeping true, restarts the view reading it in `syncing`, and makes the session's
own watch useless for exactly the verification that wants it.

The event the API server sends for the write *is* §20.5's refresh, and a live stream receives
it. So a live stream keeps its cache and quarantines the one object: `WatchStream::written`
records the key, `find` answers nothing for it, `Session::lookup` answers `NotWatched` — the
same word ADR-0037 chose for the dropped collection, now said about one object — and the index
over the collection reports `PendingWrite` and declines to answer, because a selector evaluated
over a cache with a hole in it would answer a subset that looks whole (§50.4). The next event
naming the object lifts the quarantine with what the server sent, never with what the write
asked for. A stream that is not live is dropped exactly as before. `Session::mutated` therefore
takes the object's name, and the domain tests that called it without one were updated in this
increment.

### 5. Cancellation stays inside Gate L's bound

The watch reads under `ReadPolicy::watch`, whose quiet window is a quarter of a second
(ADR-0046), and `converge` checks the invocation's cancellation between rounds and between polls.
The existing measurement — cancellation while the immediate read is outstanding — holds
unchanged; a second measurement covers cancellation while the verification *watch* is open. On
either path exactly one write was made and nothing is rolled back (§46.4, §26 core).

### 6. The window is a process-wide constant with one environment override

`ONO_K8S_VERIFICATION_WINDOW_MS` shortens or lengthens the window for a process (§7.4 of the
generic contract's environment-derived configuration). It exists so a deterministic test can make
the window end, and so an operator running against a slow control plane can lengthen it without
a rebuild. It is not a per-invocation argument: a window is a property of how patient this
provider is, not of one change.

## Consequences

A scale or an image change on a healthy cluster now answers `confirmed` with
`verified_convergence = true` a few seconds after the write, and the live suite proves both
against `kind` (`should_verify_a_scale_by_watching_the_real_controller_converge`,
`should_verify_an_image_change_by_watching_the_real_rollout_converge`).

`set k8s-resource` on a change that does not converge takes up to sixty seconds to answer, and
answers `inconclusive [generation_not_observed]` or `[conditions_inconclusive]` with the state
it last saw. The operator can stop it earlier and the change stands as the API server took it.

The recorded mutation server answers the verification watch with `404` for every test that
predates this decision, so their verdicts read `inconclusive [watch_unavailable]` where they
read `inconclusive` before; `should_not_report_an_accepted_deployment_update_as_a_completed_rollout`
holds without change, because an unopened watch is still no evidence of a rollout.

`Made` carries the target's collection, scope and the read's `resourceVersion`, which it did not
need before.

## Alternatives considered

**Poll with repeated `GET`s.** Simpler, and a request every few hundred milliseconds against an
API server §49.1 asks to be respected; a watch is one request and the server's own push.

**Watch the whole collection.** What `k8s-change` does, and a verification is about one object;
`metadata.name` is a field selector every API server indexes.

**Treat the window ending as failure.** §46.4 forbids it in as many words, and the controller
that has not converged in a minute may converge in the next.

**Skip the immediate read and watch from the write's `resourceVersion`.** It would save one
request and lose the cases the read decides at once, and the read is the observation Gate L's
existing measurement cancels inside.

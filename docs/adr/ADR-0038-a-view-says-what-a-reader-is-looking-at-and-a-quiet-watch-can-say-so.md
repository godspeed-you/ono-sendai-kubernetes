# ADR-0038: A view says what a reader is looking at, and a quiet watch can say so

- Status: accepted
- Date: 2026-09-06
- Spec refs: §18.5, §19.3, §19.5, §20.3, §41.1, §41.2, §41.3, §41.4, §50.4, §61.4 (K3), §62.12;
  §16.1–§16.4 and §30.4 of `docs/architecture/external-system-provider.md`;
  `docs/specs/ono_sendai_shell_spec_v0.9_live_view_integration.md` §14.2, §14.4, §14.5 in core;
  ADR-0022, ADR-0023, ADR-0035
- Decided by: agent (autonomous)

## Context

ADR-0035 routed a watch to the shell's live view, which is §41.1. What it left open is §41.4:

> Live views MUST expose meaningful states such as: `syncing`, `live`, `reconnecting`,
> `gap detected`, `stale`, `denied`. **A disconnected watch MUST not leave a frozen table that
> visually appears live.**

Five of the six reached a user already, as `sync_state` on every change record. The sixth did not,
and `live.rs` — the module written for §41, 603 lines and 20 tests — had no importer at all. The
reason is real rather than an oversight: `watch.rs` deliberately holds no clock, and `stale` is the
one state that cannot be decided without one.

The second sentence was the harder half. A reader of a stream learns only from records that
arrive. A watch that stops being live *stops producing records* — that is what being disconnected
means — so the last thing the reader was told is `live`, and nothing is coming to correct it.
That is the frozen table, described exactly.

## Decision

### `view_state` and `sync_state` are two fields because they answer two questions

`sync_state` is what the **connection** is doing, which `watch.rs` knows without a clock.
`view_state` is what a **reader is looking at**, which is `LiveView`'s and needs one. They can
honestly disagree — a connection that is `live` while the screen shows something older than the
declared cadence is precisely the case worth reporting — and collapsing them would lose whichever
question the surviving field did not answer.

`withheld` rides beside them (§18.5, §50.4). The view holds a bounded number of the collection's
objects; a bound that is not reported is a truncation presented as a whole picture.

### `stale` is measured against observations received, not against wall-clock silence

`LiveView`'s live-observation mark advances on every **reception** — an event, and also a bookmark,
which is a checkpoint rather than a change and emits nothing. So:

- a healthy watch of a collection where nothing is happening stays `live`, because
  `allowWatchBookmarks` means the server keeps saying so. Core's v0.9 §14.5 is explicit that a live
  event stream with no recent events is not automatically stale, and this is how that holds here;
- a connected watch whose server has gone silent — no events, no bookmarks — goes `stale`, because
  nothing is saying otherwise.

The window is a **source-declared threshold**, which is the only kind that may exist: core's v0.9
§14.2 forbids a universal "stale after N seconds" rule and its §14.4 permits a source that knows
its own cadence to declare one. Thirty seconds by default, `stale_after_ms` to move it.

### A `notice` is a record about the view, and it is what unfreezes the table

`change: notice` carries no object, exactly as a `gap` carries none: both are facts about a period
rather than about anything in the cluster. It is emitted when the view's state changes and no
observation is going to say so — between watch rounds, and, crucially, **while the read is
blocked**, which is where a watch spends its life.

### A watch read may report that a window passed quietly

That last point needed the transport to give control back. `BrokeredStream::read` looped inside
its 250 ms poll window until bytes arrived, so a caller could not act during silence — and silence
is the whole subject. `ReadPolicy::watch()` now yields `QUIET` after one quiet window: a sentinel
on the one failure channel a byte stream has, beside `CANCELLED`, and it is a **yield rather than
an end** — the connection is open, the buffer is untouched, and the next read continues mid-frame.

This is deliberately not a live-view concept pushed into the transport, which is what ADR-0023
refused for `Ctx`. What the transport learns is "tell me when a window passes quietly", which is a
statement about a byte stream. What is done with that is `changes.rs`'s.

### A notice reads the view; it does not refresh it

`LiveView::refresh` advances the live-observation mark. A notice that refreshed first would report
the state it had just erased — every notice would say `live`, which is the bug this decision
exists to avoid and the one the first implementation had. So `deliver` takes the view state as an
argument: an arrival refreshes and passes the result, a notice reads and passes that.

## Consequences

- All six of §41.4's words reach a user, on every record, and `stale` is reachable — proven by
  `should_tell_a_reader_the_view_went_stale_rather_than_leaving_it_looking_live`, which drives a
  server that opens the watch, sends one frame and then holds the body open forever. Nothing more
  arrives from the cluster; what arrives is the view correcting itself.
- K3's live-view requirement is met, and `live.rs` has an importer.
- A watch now wakes four times a second while idle to ask its view a question that is a few
  comparisons. That is the cost of being able to say anything about silence, and it is paid in the
  package rather than in requests to the API server: no round trip, no reopen, nothing the cluster
  can see (§49.1).
- `change` gained a sixth word. A consumer matching exhaustively on the five sees a new one; a
  consumer filtering for object changes filters it out with `gap`, which it already had to do.

## Alternatives considered

**Emit nothing and let the shell's renderer decide.** Rejected: the shell has no view-state model
to decide with, and core's v0.9 §4.10 forbids introducing a universal semantic `stale` field. The
threshold is this source's fact, so this source has to state it.

**Treat any quiet watch as stale after the window.** Rejected under v0.9 §14.5 and §4 invariant 13
applied to time: a collection where nothing is happening is the ordinary case, and calling it
stale would make the state mean "nothing changed" rather than "you may be looking at something
old".

**Refresh the view inside the read loop.** Rejected, and it is the subtlest wrong answer here: it
would advance the live-observation mark on evidence that no observation happened, so `stale` would
become unreachable and the field would be a word nothing produces.

**Reopen the watch periodically so the outer loop regains control.** Rejected under §49.1: it
turns the provider into a poller against the API server to obtain a fact it already has locally.

**Leave `stale` undeclared and say so.** Considered seriously, and it is the honest fallback if the
transport yield had not been available — an enum value nothing can produce is the defect this
repository refuses to ship, as `Relation::BoundTo` was. The yield made it reachable instead.

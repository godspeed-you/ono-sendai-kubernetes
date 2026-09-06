# ADR-0018: A remote session that cannot be opened is a refusal that names what is missing, never a handle that appears to work

- Status: accepted
- Date: 2026-09-06
- Spec refs: §42.1–§42.6, §51.1, §51.4, §57, §57.1, §61.5 (Gate L), §62.13 (Gate M); §4 invariant 22
- Decided by: agent (autonomous)

## Context

§42 covers four operations that share a Pod and share nothing else. Logs are a read over an
ordinary HTTP response body. Exec, attach and port forward are bidirectional sessions that begin
with `101 Switching Protocols` and then speak a multiplexed channel protocol — SPDY/3.1, or
WebSocket with the `v4.channel.k8s.io` subprotocol — over the upgraded connection.

Logs land cleanly on what this package already has. `transport::HttpConnection::open` returns a
`ResponseStream` that hands over chunked frames as they arrive, which is exactly what a followed
log is, so `logs.rs` is a decoder and a state machine over recorded bytes and nothing else.

The other three do not land at all, and it is worth being precise about why rather than writing
"unsupported":

1. **There is no upgrade path.** `HttpConnection` classifies a response body as `Content-Length`,
   chunked or read-to-end, and has no route that returns the raw byte stream to a caller after a
   `101`. Adding one is not just a new arm: the connection holds a read buffer, and whatever it
   has already pulled past the head has to travel with the stream or be lost mid-frame.
2. **There is no channel codec.** Above the upgraded connection the API server multiplexes stdin,
   stdout, stderr, a terminal-resize channel and an error channel. Neither SPDY/3.1 nor a
   WebSocket implementation exists in this tree, and the WebSocket route additionally needs
   per-frame masking keys from a random source — §51.1's capability list grants this provider
   network, brokered files, credentials, conditional process execution for credential plugins and
   host time, and no entropy.
3. **There is no terminal or job control here to integrate with.** §42.3 requires an exec to run
   inside Ono's terminal and job-control integration, and §42.5 requires a forward's lifecycle to
   be a job/session. Both live in core, and §0.4 forbids inventing a Kubernetes-shaped exception
   there from this side.
4. **A forward has no local end.** KUANG/11 brokers outbound connections (`ADR-0573` in core). It
   does not broker a listening socket, so the local endpoint §42.5 requires to be "clear" has
   nowhere to exist.
5. **The capability is not granted.** §57 declares `remote_exec` and `port_forward` as
   *conditional*, and §57.1 separates a declared capability from a session-effective one. This
   build's manifest grants neither, so the effective answer is no whatever the code could do.

§42 permits all of this: exec, attach and port forward are each introduced with "if supported".
What §42 does not settle is the *shape* of not supporting them, and that shape is the decision,
because it is what a later implementation and every caller in between are built against.

Three shapes were available. Omit the operations entirely, so that asking is a compile error in
the caller's own code. Provide them as stubs that return a session object which does nothing.
Or model the request fully and refuse to open it.

## Decision

**`logs.rs` models all four operations of §42. Logs are retrievable. Exec, attach and port
forward are requestable, classified, and refused — and the refusal names every missing piece.**

Concretely:

```rust
pub fn open(&self) -> Result<Infallible, Unavailable>
```

**The success type is uninhabited.** There is no input under which this returns a session, so no
caller can be written that holds one, no code can grow around a handle that silently does
nothing, and the day the upgrade path exists this signature changes and every call site has to be
revisited. That last part is the point: acquiring the ability to execute code inside a container
is not something that should arrive as a silent upgrade to an existing call.

**`Unavailable` carries a list of `Missing`, one variant per absence above.** `ProtocolUpgrade`,
`StreamMultiplexing`, `TerminalJobControl`, `LocalListener`, `HostCapability` — plus
`ExplicitContainer` when the caller did not name one, which is §42.3's requirement that the
target be explicit before anything runs, reported as a fixable input rather than as a platform
limit.

**The HTTP request is still built.** `SessionRequest::http_request` produces the exact request the
API server would be sent, subresource and parameters included. A named gap with the request
written down is a starting point; "unsupported" is a dead end.

**Risk is on the type rather than in a policy table elsewhere.** `SessionKind::risk` answers
`CodeExecution` for exec, `ProcessInput` for attach, `NetworkPath` for port forward and
`Observation` for a log, and `Risk::is_read_only` is true for exactly one of them. Attach is the
one this exists for: it streams a container's output exactly as `logs` does, and it also writes to
the standard input of a process the operator did not start. A capability whose risk is implicit is
one a host grants by accident.

## Consequences

Easy: §42 has an implementation and a test suite rather than a hole. The gap is discoverable from
inside the code — `Missing::describe` says what is absent in a sentence somebody could act on —
instead of from a runtime failure against a real cluster. §42.6 and Gate M hold by construction
and are checked: `tests/logs.rs` reads `src/logs.rs` and fails if it names the upstream
command-line client, `std::process` or `Command::new`, so the shortcut that makes exec work this
afternoon cannot be taken quietly.

Hard: a caller who wants exec today gets a structured refusal and not a session, and no amount of
configuration changes that. That is the intended cost. The alternative shapes both hide the same
fact — one behind a missing symbol, the other behind a handle that does nothing — and only this
one puts the reason where the person who has to fix it will read it.

Also hard: `Retrieved` is deliberately not `Clone`, and no other module in this crate may
reference it. §42.2 forbids a log becoming provider cache or temporal history, and the cheapest
route to both is a type that copies into a map without anybody deciding to keep it. A test reads
`session.rs`, `watch.rs` and `coverage.rs` and fails if any of them mentions this module.

Watch: when the upgrade path is built, the first thing it needs is a decision about which channel
protocol to speak. Upstream is migrating from SPDY to WebSocket, and the WebSocket route drags in
an entropy capability that §51.1 does not currently list — so that is an ADR of its own, and it is
a security-capability decision before it is a protocol one.

## Alternatives considered

**Omit exec, attach and port forward entirely.** Rejected. The absence is then undocumented in the
one place people look, the operations reappear as a request nobody wrote down, and there is no
place to put the risk classification — which is the part of §42 that matters most, because §51's
capability gating depends on somebody having said out loud that exec is arbitrary code execution.

**Stub them: return a session object whose methods do nothing.** Rejected, and it is the dangerous
option rather than merely the useless one. Code grows around a handle that compiles, tests are
written against a session that "succeeds", and the discovery that nothing ever ran happens in
front of a cluster. §42.3 calls exec "not an ordinary resource mutation"; a stub makes it look
like the most ordinary thing in the module.

**Return `Result<RemoteSession, Unavailable>` with an inhabited success type, so the signature
does not change later.** Rejected. A signature that can succeed invites callers that assume it
will, and the stability it buys is stability of the wrong thing: the day this can execute code in
a container, every call site should be re-read rather than silently upgraded.

**Shell out to the upstream command-line client as a temporary bridge.** Rejected. §42.6 names it
as an anti-pattern, Gate M requires core conformance on a machine where that client is absent, and
§51.4 allows a subprocess for exec credential plugins and for nothing else — a general
command-execution path opened for convenience is exactly the escalation §51.4 exists to close.

**Put logs in one module and the sessions in another.** Rejected as a smaller call, but recorded:
they are one specification section, they share a target type, and separating them would put the
risk classification of `exec` somewhere a reader of the log path never passes. §42's whole point is
that these four operations sit next to each other and are not the same kind of thing.

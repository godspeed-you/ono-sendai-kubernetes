# ADR-0047: What the broker cannot see is what is worth recording

- Status: accepted
- Date: 2026-09-06
- Spec refs: §8.1, §21.4, §22.1, §42.2, §43, §51.2, §51.4, §51.6, §62.9;
  §27.6 of `docs/architecture/external-system-provider.md`; §31.37 in core's specification;
  `ADR-0589 (core)`; ADR-0002, ADR-0003, ADR-0024, ADR-0043
- Decided by: agent (autonomous)

## Context

§51.6 asks for non-secret audit metadata covering connection, permission failures, mutations and
credential-plugin invocations. Nothing recorded any of it, and the board recorded why: *"the host
call exists and needs no capability, and `Shared::plugin_events` in the supervisor has no public
accessor — so a test cannot assert that a record was emitted or what it contained, and under 'no
test, no code' the emission was not written."*

That reading was right, and it was fixed in core rather than here: `ADR-0589 (core)` found that
`audit.event` pushed a package's records onto a vector nothing read — not `LoadedPlugin::audit()`,
not `get audit`, not the persisted trail. A call nothing can observe is a call a package cannot be
held to.

The gap it leaves is specific to a package like this one. The capability broker audits what it
*checked*: a `network.connect` to a host and a port. It cannot see what the bytes on that
connection were for, because it is a byte broker and this package carries HTTPS over it
(ADR-0002, `ADR-0573 (core)`). So the three facts an operator most wants — which cluster was
reached, which read the API server refused, which object was changed — are exactly the three only
this package knows.

## Decision

**Three records, at the three moments §51.6 names, and nothing else.**

- **`connect`**, in `BrokeredStream::connect`, emitted *before* the handshake rather than after
  it: what a reader of a trail wants is which cluster this package reached *for*, and a connection
  that failed is the more interesting of the two.
- **`denied`**, once per denied coverage gap when a listing finishes. This is the one worth having
  most: a refusal reaches one person once, and a trail of refusals is how somebody finds out days
  later that a token lost a grant.
- **`mutate`**, when a change has been attempted, whatever became of it. A dry run is recorded and
  left distinguishable, because "somebody asked what this would do" is a fact worth having and is
  not a change.

**The fourth thing §51.6 names is not recorded, because it does not happen.** Exec credential
plugins are refused rather than approximated (§8.2, ADR-0018), so there is no invocation to make
auditable. §51.4's requirement is satisfied by there being nothing to satisfy it about, and that
is worth stating rather than leaving as an absence somebody has to notice.

**Nothing here may carry a secret**, and the module is shaped so that it cannot. No function takes
an `Object`, so a payload has no route in at all; a mutation record names the *fields* a change
touched and never their values; a refusal carries the classified error kind rather than the API
server's `Status` message, because prose about somebody's object is where a payload hides. The
test asserts this over the whole trail rather than field by field: a trail is shown, exported and
kept, so a payload put there is a payload published.

**A record that cannot be delivered is dropped, not raised.** A trail this package could fail an
invocation over would be a trail that decides whether a query succeeds, which is backwards — the
record is *about* the work, and losing one must not lose the work.

## Consequences

- `get audit --plugin io.github.godspeed-you.kubernetes` shows what this provider did beside what
  the broker checked, with `enforcement` saying which is which — the broker's records are
  `broker`, these are `advisory`, because no capability was checked to produce them.
- §51.6 and generic §27.6 are met, and the board entry that recorded them as blocked is
  discharged: the block was in core and core removed it.
- Three records per invocation is the cost, on a host call that needs no capability and does no
  I/O of its own. A busy watch does not multiply them: the connection is recorded once per
  connection, not once per frame.
- An operator who wants none of this cannot turn it off. That is the inherited contract's shape
  rather than this package's: a package cannot suppress an entry, which is the sentence
  `protocol.v1.yaml` uses.

## Alternatives considered

**Record every request.** Rejected. A listing is hundreds of requests and none of them is a
security event; a trail that grows with traffic is one nobody reads, and §51.6 names four kinds of
thing rather than "what happened".

**Record the `Status` message on a refusal.** Rejected: it is the API server's prose about
somebody's object, and this ADR's own rule is that prose is where a payload hides. The classified
kind is what a reader filters on anyway.

**Emit from one place, at the end of the invocation.** Rejected. A connection that failed and a
denial that a later error masked would both be lost, and those are the two an operator is looking
for.

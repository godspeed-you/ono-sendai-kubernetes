# ADR-0046: A name from a cluster is text, a collection decides what its items are, and a poll window is not a deadline

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariants 13, 20, 21, §5.4, §9.2, §13.5, §16.1, §16.2, §21.1, §22.1, §22.2,
  §34.2, §48.1, §51.2, §62.9 (Gate I), §62.12 (Gate L); §27.2 of
  `docs/architecture/external-system-provider.md`; ADR-0003, ADR-0023, ADR-0038, ADR-0043, ADR-0044
- Decided by: agent (autonomous)

## Context

The adversarial suite (ADR-0043) and the performance suite (ADR-0044) each found defects their
authors were not scoped to repair. Three of them are these, and two are the reason this ADR is
written rather than folded into a commit message: one is a payload disclosure and one is request
smuggling.

### 1. Gate I was defeated by a field the payload's author writes

`transport::identify` gave a list item the envelope's `apiVersion` and `kind` only where the item
did not state its own, with the comment *"an aggregated or mixed list is entitled to disagree with
its envelope"*. That is true about the wire and wrong about the consequence, because
`redaction::is_payload_protected` is keyed on the kind:

```
GET /api/v1/namespaces/shop/secrets
  → { kind: SecretList, items: [ { kind: ConfigMap, data: { password: … } } ] }
```

produced an object that never reached the redaction rule, and **`get k8s-secret` completed with
the plaintext payload in the record** — confirmed end to end through the real binary. §34.2
requires surviving a hostile aggregated API server, and this is what one would send.

A second route reached the same place: the item kind was the envelope's with `List` stripped, so a
generic `v1 List` envelope left every item with the kind `""`, which is not `Secret` either.

### 2. A name could write a header

`collection_path` and `object_path` interpolated the namespace and the object name into the
request path unencoded, although `Request::target` had percent-encoded every *query* value all
along for the same class of reason. Both components are attacker-chosen: anyone who can create an
object names it.

- a namespace of `../../../api/v1/secrets` walked the URL out of its collection — Go's mux
  normalises `..` before the authorizer sees the path, so a Pod-shaped RBAC decision carried a
  read of Secrets;
- a namespace containing CRLF ended the request line and started a header. Against the recorded
  server this put **`X-Remote-User: cluster-admin`** on the wire, and on the keep-alive connection
  this package holds for a session, a second request the operator never asked for.

### 3. Gate L's first named operation was the one that failed it

§62.12 names "large list, watch, log-follow and verification". The watch and the followed log
stopped in under half a second; a cancelled listing blocked on a silent server took **59.99
seconds**. `ReadPolicy::request` used one constant as both the liveness deadline and the
cancellation window, so an invocation parked in `streams.next` could not be told the operator had
stopped it until a full thirty-second window returned — and the cancellation was not observed in
the window it arrived in, so it cost two.

## Decision

### The collection decides what its items are, and a disagreement is refused

The kind comes from the collection's envelope, and an item that states a different one makes the
**page** malformed. A collection this provider cannot name the kind of — a generic `List`, an
empty kind, a missing one — is refused for the same reason.

**Refused rather than overridden**, and the choice is deliberate. Overriding would silently
rewrite what the server said, and §5.4 asks this provider to preserve an object's actual
`apiVersion` when it reads one. A collection endpoint answering with an item of another kind is a
server contradicting itself about that page, and nothing on the page is then trustworthy about its
own identity — including the parts redaction does not cover.

### A path component is text

`path_segment` percent-encodes every byte outside RFC 3986's unreserved set, using the same
conservative encoder the query string uses. `/`, `%`, `\r` and `\n` become `%XX`; what a cluster
called something is one segment's worth of text and never a place to put something.

**Encoded rather than validated.** Refusing a namespace that is not a DNS label was the
alternative, and it asserts something this provider is not entitled to assert: §21.1 makes the API
server the authority on its own names, and a client that refuses a name the server accepts has
made itself a second authorizer. Encoding is the narrower answer and closes the same door.

### A poll window and a deadline are two numbers

`POLL_SECONDS` is a quarter of a second on every path — it is how often this package looks up, and
therefore how quickly a cancellation is observed. `REQUEST_PATIENCE_SECONDS` is ninety seconds —
how long an API server may say nothing after accepting a request before it is broken rather than
slow, which is exactly what three thirty-second windows used to mean.

The tolerance was never the defect. The defect was that noticing a cancellation cost the same wait.

## Consequences

- **Gate I holds on the route that defeated it.** A `secrets` collection whose items claim another
  kind cannot complete, and the refusal carries no payload — asserted at the domain layer and
  again end to end through the binary.
- **A hostile name cannot become protocol.** Three tests now assert what the recorded server
  *saw*, which is the only honest place to check it: an encoder test proves the encoder, and what
  matters is that nothing between the argument and the socket puts the bytes back.
- **A cancelled listing terminates in 492 ms** where it took 59.99 s, and the performance suite
  runs in 0.69 s where it took 64 s — almost all of which was that one test waiting.
- A request that is waiting now makes four cheap host calls a second instead of one every thirty.
  That is the price of the window, it is the price the watch has always paid, and it buys §62.12
  on every path rather than on two of three.
- A cluster whose API server genuinely returns mixed-kind collections on a typed collection
  endpoint is now refused. No conforming Kubernetes API server does this; an aggregated one that
  did would be misreporting its own resource.

## Alternatives considered

**Key redaction on the requested GVR rather than on the kind.** The stronger fix, and the one the
finding suggested: an item of the `secrets` collection is payload-bearing whatever it calls
itself. Rejected for now because it threads the requested resource through `Object`, `Guarded` and
`is_payload_protected`, and the refusal closes the disclosure completely without it. Worth
revisiting if a legitimate mixed collection ever appears — it is the shape that survives one.

**Override the item's kind with the collection's.** Rejected: it makes the record say something
the server did not, and §48.1 asks for what the server said. A reader who sees the refusal can ask
the server what it meant; a reader who sees a rewritten record cannot.

**Refuse a namespace that is not a DNS label.** Rejected above — it makes this provider a second
authorizer.

**Leave the request window at thirty seconds and check cancellation elsewhere.** There is nowhere
else: the invocation is inside the host call for the whole window, which is precisely the problem
ADR-0023 solved for the watch by making the window short. Doing it once, for both, removes the
class rather than the instance.

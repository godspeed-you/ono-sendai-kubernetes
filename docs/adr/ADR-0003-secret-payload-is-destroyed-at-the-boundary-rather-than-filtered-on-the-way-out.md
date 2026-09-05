# ADR-0003: Secret payload is destroyed at the boundary rather than filtered on the way out

- Status: accepted
- Date: 2026-09-05
- Spec refs: §3.7, §4 invariant 21, §12.5, §22.1, §22.2, §22.3, §22.4, §29.2, §33.1, §62.9 (Gate I)
- Decided by: agent (autonomous)

## Context

`Object` is deliberately total. `field()` reaches any JSON pointer and `native()` returns the
whole document the API server sent, because §12.5 and §4 invariant 17 require unknown fields to
survive rather than be dropped by a projection nobody updated. That is the right shape for every
kind except the one whose bytes are the thing being protected: a Secret held as an ordinary
object is one `/data/password` away from disclosure.

Gate I (§62.9) asks that the default list, detail and navigation paths cannot reveal Secret
payload values. The obvious way to satisfy it is a rule at the rendering edge — redact on the way
out, in the formatter, in the table builder, in the detail view. That rule has to be *remembered*
on every path, including the paths that do not exist yet: a history entry, a diagnostic dump, a
diff, a `Debug` line in a panic message, a cache serialised to disk, an accessor a future author
adds for a reason unrelated to Secrets. It fails silently and with no error to notice, and by the
time anyone notices, the bytes are in a scrollback buffer (§22.3).

Two further questions came with it, and neither is answered by §22.2's list of field names.

`kubectl apply` writes the whole submitted object into the
`kubectl.kubernetes.io/last-applied-configuration` annotation. On a Secret that annotation
contains the `data` map verbatim. Redacting `data` and printing metadata faithfully leaks the same
bytes one field to the left. The specification does not name this path; §22.2's "or equivalent
secret payload" covers it in spirit, and nothing in the document points at the annotation.

And §33.1 makes CRDs normal resources. An operator that defines its own `Secret` kind in its own
API group is very likely holding what the name says, and matching on `v1 Secret` alone would leave
it unprotected while the built-in kind next to it is guarded.

## Decision

**Redaction is structural.** `Guarded::hold` is the single boundary every read path takes its
objects from, and it does not filter the payload on the way out: it destroys it on the way in. For
a payload-bearing kind it rebuilds the document with every `data` and `stringData` value replaced
by `<redacted>`, and the `Secret` value is constructed *from the rebuilt document*. There is no
moment at which a `Secret` exists holding a payload. `native()`, `field()`, `Debug`,
serialisation and any accessor nobody has written yet are all safe for the same reason: there is
nothing left to find.

The values are replaced rather than removed. §22.2 asks for the keys present, so `/data/password`
must still resolve — it resolves to the marker.

**The boundary has a stated location, and saying where it is beats pretending it is nowhere.**
`Object::parse` is the wire decoder; it is *inside* the boundary and does hold what the server
sent, because something has to. Everything a user, a renderer, a history entry or a relationship
walk sees comes from a `Guarded`, and `tests/redaction.rs` pins that line so it fails the day
someone moves it. In the plugin, `records::record` takes a `Guarded` and never an `Object`, so
there is one door into the emission path rather than a rule about which door to use.

**`last-applied-configuration` is redacted too.** The annotation is replaced with the same marker
whenever it is present on a payload-bearing object. It is a second leak path for the same bytes,
and the fact that the specification does not name it is a reason to write this down, not a reason
to leave it open.

**Any kind named `Secret`, in any API group, is protected.** The match is on the kind alone.
Over-redaction costs a reader some detail; under-redaction cannot be taken back, and §3.7 forbids
making secret data easier to expose merely because Secrets are ordinary API resources. There is
deliberately no allowlist for custom kinds that are *not* really secrets, because an allowlist is
precisely the mechanism through which the mistake would eventually be made.

What stays visible is everything §22.2 calls safe: name, namespace, type, which keys are present,
creation time, owner references — and the relationships of §22.4 as ordinary edges, because a
Secret's name is not its contents and the workload that consumes it is usually the reason anyone
looked.

## Consequences

Easy: Gate I holds by construction rather than by review. New accessors on `Object` are safe
without anyone thinking about Secrets, and a new read path is safe as soon as it takes its objects
from `Guarded::hold` — which is the only way it can get them. The list path gets the same single
call as the detail path through `hold_all`, so the classic split, where the detail view is careful
and the table loops over raw objects, is not available.

Hard: a held Secret cannot answer §22.3's explicit reveal. The payload is not behind a flag or a
policy check; it is gone, so a future reveal must be a second, audited API read rather than a
lookup on a value already in memory. `RevealRefusal::NoPayloadHeld` says exactly that rather than
returning an empty answer. That is more work later, and it is the correct amount of work: a
reveal that can be served from a value lying around in the pipeline is a reveal that can happen by
accident.

Watch: the guarantee is per value, and the *routing* is still a discipline. Any future path that
obtains `Object`s from the transport and skips `Guarded` — a watch cache, a diff, a tombstone
store — loses it, and nothing in the type system stops that today. The mitigation is that the
emission path takes a `Guarded` in its signature, so a bypass has to be written on purpose, plus
the test that pins where the boundary lies. A stronger version, in which the transport itself can
only hand out guarded values, is available if a second consumer ever appears.

Also watch: matching on the kind name means a CRD called `Secret` that holds nothing sensitive is
reported with less detail than it could be, and its `data` map will read as markers. That is the
intended direction of the error.

## Alternatives considered

**Redact at the rendering layer.** Rejected: it has to be remembered on every path, it fails
silently on the first path nobody reviewed, and the paths that will exist in a year cannot be
reviewed now.

**A view type that exposes only the safe fields, over an object that still holds the payload.**
Rejected: the payload still exists behind an accessor, and the next author who needs one field
adds one. It moves the problem from "remember to redact" to "remember not to expose", which is the
same problem.

**Delete the payload keys instead of replacing their values.** Rejected: §22.2 asks which keys are
present, and a deleted key cannot answer that. Deletion would also make `/data/password` resolve
to nothing, which reads as "no such key" rather than "not shown".

**Redact `data` and leave `stringData`.** Rejected: `stringData` is write-only by convention, not
by guarantee, and a convention is not a reason to print bytes an object carries.

**Protect only `v1 Secret`.** Rejected: §33.1 makes CRDs normal resources, so an operator's own
Secret kind would be unprotected purely because of its group.

**Make the boundary configurable, so a host policy can turn it off.** Rejected as the wrong
default and the wrong location: §22.3 puts an explicit reveal behind a high-friction, audited
operation, which is a different mechanism from a switch on the ingest path — a switch on ingest is
one someone eventually leaves flipped.

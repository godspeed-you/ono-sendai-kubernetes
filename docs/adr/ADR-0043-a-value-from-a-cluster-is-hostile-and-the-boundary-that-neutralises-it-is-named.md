# ADR-0043: A value from a cluster is hostile, and the boundary that neutralises it is named

- Status: accepted
- Date: 2026-09-06
- Spec refs: §9.2, §12.5, §13.5, §14.2, §14.5, §14.6, §14.7, §16.1, §16.2, §16.3, §16.5, §17.1, §17.2, §18.1, §18.3, §18.4, §18.5, §19.3, §19.6, §21.4, §22, §33.1, §34.2, §35.3, §35.4, §42.1, §48.1, §48.2, §49.5, §50.1, §50.5, §51, §62.9, §62.10, §63.5; core `external-system-provider.md` §8.3, §10.5, §12.3, §19.1, §19.2, §27, §30.4
- Decided by: agent (autonomous)

## Context

This provider's inputs are chosen by an adversary. Not hypothetically: **every name, label key,
label value, annotation, Event message, condition message, finalizer, container image and log line
in a cluster is written by whoever can create an object in it**, which in a shared cluster is
everyone with a namespace. §34 adds a second author — an aggregated API server serves whatever
bytes it likes over the same connection as the core API — and §51's isolation model exists because
the provider is assumed to be handling material it does not control.

The suite before this change tested the *cooperative* cluster thoroughly and the hostile one
hardly at all. Every fixture held DNS-label names, UUID UIDs, well-formed lists and servers that
framed their own responses correctly. Nothing asked what happens when a name is 253 bytes of
escape sequences, when a `SecretList`'s items claim to be ConfigMaps, when a `continue` token never
advances, or when a watch body contains no newline at all.

Three questions had to be settled before any of that could be tested rather than merely worried
about.

**Where does sanitising happen?** Ono core sanitises. `ono_render::sanitise` replaces every control
character with an inert printable form; `Theme::paint` and `Theme::colour` run their text through
it, so every table cell, tree node, error message, error detail, error help line and view string
is neutralised by the host. `ono-cli`'s `Reporter::error` says so explicitly and names the reason:
"an error message is where attacker-controlled text most reliably reaches a terminal". So the
provider's obligation is the *opposite* of sanitising — it must carry a value through unchanged,
because a package that strips bytes corrupts legitimate names and breaks the round trip §35.3
requires, and because a value the provider reformatted is one the renderer can no longer neutralise
correctly. This package writes nothing to a terminal: there is no `println!`, `eprintln!` or direct
`stdout`/`stderr` use anywhere in either crate, and the protocol is the only thing on the wire.

**What is the provider's own obligation, then?** Two things the host cannot do for it. Sanitising
does not redact, so **payload** is the provider's problem (§22, Gate I). And sanitising does not
bound, so **size and termination** are the provider's problem (§18.5, §50.5, core §30.4): a
sanitiser applied to a gigabyte returns a gigabyte, and applied to a request that never returns it
is never called at all.

**Is a fuzzing dependency worth its place?** Core has a `fuzz/` directory and it earns it, because
core's parser has an input space nobody can enumerate. The candidates here are different in kind.
`WatchDecoder` and `LogDecoder` have exactly one interesting property — that chunk boundaries do
not change the answer — over an input space that is *a body and a set of split points*. The JSON
pointer escaper has a two-character alphabet. `PlaceUri`'s round trip turns on five characters:
`/`, `%`, `.`, `:` and the scheme prefix. Underneath all of them, `serde_json` is the actual
decoder and it is already fuzzed upstream and already bounded at 128 levels of nesting.

## Decision

### 1. Two adversarial suites, and the render boundary is written down in them

`crates/ono-provider-kubernetes/tests/adversarial.rs` (45 tests) attacks the domain layer;
`crates/ono-kubernetes-plugin/tests/adversarial.rs` (8 tests) attacks the whole package through the
real binary against a recorded server that writes down every request head it receives.

The first section of the domain file states the boundary as executable text rather than as a
comment: a control sequence in a name **survives a place URI round trip byte for byte**, and that
is the assertion. It fails if the package starts stripping bytes and it fails if the package starts
reformatting the address around them. The plugin file makes the same claim end to end and adds the
half the domain file cannot see: the record's *shape* — one record, the package's schema id, the
grammar's address — is never chosen by the data.

Disclosure is asserted against the **whole event stream** (`{:?}` over every emitted value plus the
invocation's error), not against the fields a schema names. A leak that arrives through a field
nobody thought to check is the leak worth looking for, and §22.2's "or equivalent secret payload"
is exactly that class — the `last-applied-configuration` annotation embeds the whole submitted
object one field to the left of `data`.

### 2. Four defects in this worker's files are repaired

**An empty string is not a value** (`object.rs`). `metadata.uid: ""` was read as a UID, so
`Identity::is_lifetime_stable()` answered `true` and §16.3's recreate detection compared every such
object equal to every other — two lifetimes merging instead of producing the discontinuity Gate C
requires. §16.5 requires the degradation to be *explicit*. The same rule now applies to
`namespace` (the API server writes `""` for cluster scope, and §9.2 turns on "no namespace" versus
"empty namespace slot"), to `resourceVersion` (§14.3's token; an empty one is no position) and to
`deletionTimestamp` (Gate H reads its presence as terminating). An empty `metadata.name` is now
`ObjectError::NotAnObject`, because §16.2's locator is built from it and `.../pods/` addresses a
collection.

**A place URI round-tripped into a different provider instance** (`place.rs`). `Display` wrote
`context()`, which strips the `kubernetes:` prefix; `parse` then stripped a *second* one. A
kubeconfig context called `kubernetes:prod` therefore parsed back as the instance of the context
`prod` — Gate J's merge, reached by navigation. `parse` now qualifies the authority as a context
without stripping (`qualify_context`), which makes the map from contexts to instances injective.
`normalise_instance` is unchanged for callers, who legitimately hold both spellings.

**Two decoders held an unbounded buffer** (`watch.rs`, `logs.rs`). Both frame on newlines and both
waited indefinitely for one. A watch body with no newline in it — a hostile server, a broken
proxy, an aggregated API server having a bad day — grew `WatchDecoder`'s buffer without limit; a
container running `yes | tr -d '\n'` did the same to `LogDecoder`, and anyone who can run a Pod can
do that. Neither is a slow server; both are a peer turning the client's heap into its own, and a
killed process reports nothing at all, which is the one outcome §48.2's taxonomy has no word for.

The two bounds are deliberately different, because the two situations are:

- `watch::FRAME_LIMIT` = 16 MiB, and past it the frame is **refused**
  (`FrameError::Oversized { held, limit }`). etcd caps an object near 1.5 MiB, so a legitimate
  frame is an order of magnitude below this; the headroom is for §34's aggregated servers, which
  serve what they like. Above it no legitimate framing explains the absence of a newline, and a
  break in continuity is the honest answer.
- `logs::LINE_LIMIT` = 1 MiB, and past it the line is **cut and handed over**
  (`LogLine::was_cut()`). A container's output has no maximum line length and nothing upstream
  imposes one, so refusing would discard a legitimate log. Nothing is lost: the pieces are
  delivered in order, and each says it was cut by this provider rather than ended by the server —
  §12.5's rule applied to a stream, and distinct from `is_terminated()`, which is a fact about what
  the server sent.

Both limits are constants with a `holding_back(limit)` builder beside them, so a caller that knows
it is reading something else states its own bound rather than editing a constant everyone shares.
A limit nobody can see is a limit nobody can raise, so both appear in the refusal.

### 3. Findings in other workers' files are pinned, never ignored

Four defects were found in modules this worker may not repair. Each has a test that **asserts what
happens today** under a `// FINDING:` comment naming what should change, and none is `#[ignore]`d:
an ignored test tells the next reader nothing, and a red suite tells them the same. Where a fix
would invert an assertion, the comment says so.

They are listed in the Consequences below rather than decided here, because they are somebody
else's decision to make.

### 4. No fuzzing dependency, and the reason is the input spaces rather than the cost

`proptest`, `arbitrary` and a `fuzz/` directory are all declined. What replaces them:

- **Deterministic split-point properties** over the two decoders. One body, two hundred random
  splits from a seeded LCG written into the test file, and the answer must equal the whole-body
  answer every time. That is the property, and a generator that produced arbitrary *bodies* would
  spend its budget rediscovering `serde_json`'s error paths.
- **Exhaustive tables** where the alphabet is small enough to enumerate, which is every remaining
  candidate: the place URI round trip over pairs from an eleven-member hostile alphabet (400+
  addresses, all four shapes), and the JSON pointer escaper over pairs from a nine-member one.
  Exhaustive beats sampled here, and it beats shrinking too — there is nothing to shrink when every
  case ran.

A generator earns its place when the input space cannot be enumerated *and* the oracle is cheap.
`serde_json` is where that is true on this path, and it is fuzzed upstream. This decision is worth
revisiting if this package ever writes a decoder of its own — a YAML reader for kubeconfig beyond
what `serde_yaml_ng` does, or a hand-rolled protobuf path for `application/vnd.kubernetes.protobuf`
— because both would be genuine parsers of adversary-chosen bytes with no upstream fuzzing behind
them.

## Consequences

**The render boundary is now load-bearing and stated.** Anyone reading `tests/adversarial.rs` learns
that core sanitises and that this package's job is to carry values whole. A future change that adds
a terminal write, or that "helpfully" strips escapes from a name, fails.

**Four defects are fixed and one behaviour change is visible outside this file.** `Object::parse`
now rejects an object whose `metadata.name` is the empty string, and reads `""` as absent for four
metadata fields. The whole workspace suite is green with the change, which is the evidence that
nothing depended on the old reading.

**`FrameError` and `LogLine` grew.** `FrameError::Oversized` is a new variant, so an exhaustive
match on it elsewhere would need an arm; `LogLine::was_cut()` is new and additive. Both are within
the modules this ADR repairs.

**Four findings are open and routed to their owners.** In descending order of severity:

1. **A hostile item's `kind` decides whether §22 applies** — `transport::identify`, disclosed end
   to end. `identify` lets an item's own `apiVersion`/`kind` win over the list envelope's, on the
   reasoning that "an aggregated or mixed list is entitled to disagree with its envelope". The
   consequence is that a `GET /api/v1/namespaces/shop/secrets` whose items each carry
   `"kind":"ConfigMap"` produces objects that never reach `redaction::is_payload_protected`, and
   `get k8s-secret` completes with the payload in the record. **Gate I (§62.9) is defeated by an
   adversary who controls a served API**, which §34.2 requires this provider to survive. The
   requested GVR is known at that point and is the honest authority; `redaction.rs`'s own principle
   settles the trade-off — over-redaction costs a reader some detail, under-redaction cannot be
   taken back. Tests: `should_type_a_secret_by_the_collection_it_came_from_rather_than_by_what_the_item_claims`
   (domain) and `should_disclose_a_secret_payload_when_the_item_claims_another_kind` (plugin).
   The same rule has a second route: `identify` strips `List` off the envelope's kind, so a
   generic `v1 List` leaves every item with the kind `""`, which is not `Secret` either. Test:
   `should_not_leave_an_item_kindless_when_the_envelope_is_a_generic_list`.
2. **Request path components are neither validated nor encoded** — `transport::collection_path`,
   `transport::object_path`, `Request::serialise`. `Request::target` percent-encodes every query
   value and the path is pasted in raw beside it. A namespace or name of `../../secrets/admin` is
   normalised by Go's HTTP mux before the API server's authorizer sees it, so a Pod-shaped RBAC
   decision carries a Secret-shaped read; a component containing CRLF writes a header or a second
   request on the keep-alive connection this package uses for a whole session. Both were confirmed
   against the recorded server, which saw `GET /api/v1/namespaces/../../../api/v1/secrets/pods` and
   an injected `X-Remote-User: cluster-admin`. Tests:
   `should_not_let_a_path_shaped_namespace_or_name_climb_the_rest_path`,
   `should_not_let_a_name_carrying_crlf_forge_a_header_or_a_second_request` (domain),
   `should_not_let_a_namespace_argument_climb_the_rest_path`,
   `should_send_a_hostile_namespace_as_one_request_rather_than_as_two` (plugin).
3. **A `continue` token that never advances is followed rather than recognised** —
   `transport::walk`. The live path *is* bounded: `query::budget_of` installs
   `Budget::interactive()`, so an invocation stops after sixteen pages and ends as a failure rather
   than as a short list. What is missing is the recognition — core §12.3 asks a provider to
   "prevent duplicate emission where provider pagination semantics permit stable deduplication",
   and a token identical to the one just sent is that signal; it should break continuity rather
   than be re-sent. `Client::new`'s own default is still `Budget::unlimited()`, so a caller other
   than the plugin inherits no bound at all. Tests:
   `should_follow_a_continue_token_that_never_advances_until_something_else_stops_it` (domain),
   `should_end_an_invocation_whose_server_never_stops_paginating` (plugin).
4. **A get does not check that it got what it asked for** — `transport::Client::get`. §17.1
   addresses one object by name; the returned object's `metadata` is taken as-is with no
   comparison against the requested locator, so a server may answer a `get pods/checkout` with a
   Secret named `somebody-else` in `kube-system` and the provider reports it under that identity.
   The identity is honest about what arrived, which is the right half; the mismatch is not
   reported, which is the missing half — and combined with finding 1 it is how a hostile server
   chooses which §22 rule applies to bytes it is sending. Test:
   `should_report_the_object_the_server_actually_sent_rather_than_the_one_that_was_asked_for`.
5. **The submitted half of an admission diff is not redacted** — `mutation::admission_differences_of`.
   The *returned* half is guarded on purpose, and the function exists for that reason; the
   `requested` half is included verbatim, so an apply of a Secret whose payload admission changed
   reports the submitted bytes beside `<redacted>`. §22.3 says "Secret bytes MUST NOT flow into
   ordinary command history, terminal scrollback capture or provider logs by default" and does not
   except bytes the operator typed. Test:
   `should_show_a_submitted_secret_value_in_an_admission_difference`.

**Two things held up that are worth naming, because they were attacked deliberately.** The
redaction discipline is structural and it survived every accessor tried against it — `Projection`
walks every leaf of a document and finds `<redacted>`, place URIs and relationship evidence carry
names rather than values, and a Secret arriving as a watch frame is guarded exactly like one from a
list. And depth is not a way in: `serde_json`'s 128-level bound refuses a 10 000-level object and a
10 000-level schema before either recurses, so nothing here overflows a stack.

**No new dependency.** The workspace's dev-dependencies are unchanged.

## Alternatives considered

**Sanitise in the provider.** Rejected, and it is the tempting one. It would be defence in depth
against a host that forgot, but it destroys the round trip §35.3 requires — a name containing an
escape would render as `\u{1b}` and parse back as the literal text `\u{1b}` — and it puts a second,
weaker sanitiser in the tree beside core's, which is how the two come to disagree. Where the
provider does build a message quoting attacker text, `{:?}` is used, which escapes without
destroying (`FrameError::UnknownClass`), and the test asserts that the refusal carries no live
control character.

**Refuse a hostile name at the boundary instead of carrying it.** Rejected: it is §5.3's
newest-version assumption in another costume. Kubernetes validates names, an aggregated API server
may not, and a provider that refused to *show* an object it can read would hide the one object an
operator most needs to see. Carrying it as data and letting the renderer neutralise it is both
honest and safe.

**Bound the watch decoder by cutting rather than refusing, as the log decoder does.** Rejected: a
watch frame is a JSON document and half of one is not a frame. Handing over a truncated frame would
mean either fabricating an event or emitting one that says nothing, and §19.4's rule against
stitching a history over bytes nobody accounted for applies to a hole this decoder created just as
much as to one a `410` created.

**Bound the log decoder by refusing rather than cutting.** Rejected for the mirror reason: a
container's output has no line-length contract, so a refusal would be this provider deciding that a
legitimate log is malformed. Cutting loses nothing and says so.

**Fix the four routed findings here.** Rejected under the working split: `transport.rs`,
`query.rs` and `mutation.rs` are owned by concurrent workers, and two agents editing one file is
how a green tree stops being one. Pinning the behaviour in a test is strictly better than a note,
because the fix has something to turn red.

**Add `proptest` and a `fuzz/` directory to match core.** Rejected on the input spaces, as above.
Symmetry with core is not a reason: core fuzzes a parser it wrote, and the parser on this path
belongs to `serde_json`.

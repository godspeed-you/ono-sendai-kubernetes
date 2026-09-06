# ADR-0039: A capability is reported in two halves, and the session half is earned from evidence or says it was not gathered

- Status: accepted
- Date: 2026-09-06
- Spec refs: §4 invariant 13, §11.1, §11.5, §21.1, §21.2, §21.3, §21.4, §21.6, §34.3, §35.5, §42.1, §42.3, §42.4, §42.5, §51.1, §57, §57.1, §61.1
- Decided by: agent (autonomous)

## Context

§57.1 is one sentence and one example, and both are normative in shape:

> **§57.1 Dynamic capability reporting.** Runtime diagnostics MUST distinguish manifest-declared
> potential capability from session-effective capability.
>
> ```text
> watch: supported by provider, available on resource
> mutate deployment: supported by provider, denied for current user
> exec auth: supported by provider, blocked by local KUANG policy
> ```

The sentence before it, in §57, sketches the manifest half as a list of words — `discovery`,
`watch`, `relationships`, `mutations`, `remote_logs`, `remote_exec`, `port_forward` and the rest —
and then defers the schema: "Exact manifest schema follows the generic provider/extension
contract."

The inherited contract says the same thing in the generic vocabulary. §26.1 of
`external-system-provider.md` in core:

> Capabilities exist at two layers:
>
> 1. package-declared support;
> 2. runtime-available support under current configuration, API version, scope and permission.
>
> The host MUST distinguish them.

and §26.4, which is §57.1's third line stated as a rule:

> A provider MAY support mutation generally while the current principal cannot perform it. The
> host should present:
>
> ```text
> provider supports action
> current session not authorized
> ```
>
> rather than `unsupported`.

**Nothing in this package reported any of it.** `k8s-cluster` said which cluster this is, whether
it answers, as whom, and what could not be determined; it said nothing about what could be *done*
here. The operator's three failure modes therefore arrived as one shrug — `near` that answers
nothing, a watch that fails on first use, and an `exec` this build will never have — with three
different fixes: a different grant, a different cluster, a different provider.

Three things made the shape of the answer the hard part.

**The two halves must not be derived from one another.** A single word for a capability makes "this
build does not implement exec" and "this cluster serves no watch" the same value, which is exactly
the collapse §26.1 forbids the host from making.

**Discovery is not an authorization oracle.** §21.1 forbids a substitute RBAC evaluator, §21.2
makes even `SelfSubjectAccessReview` advisory and per action, and §21.3 says a rules summary is
never a complete oracle. A resource list saying `patch` says the *resource offers the verb*. That
is a different sentence from "this identity may patch this object", and §57.1's second example is
written in the second sentence's words.

**Missing evidence is a state.** §4 invariant 13 and §21.4 keep `not queried` apart from a denial
and from an absence, and a capability report is the easiest place in the package to lose that: a
default of `false` reads as "this cluster cannot", and a default of `true` reads as a promise.

## Decision

**`k8s-cluster` carries a `capabilities` map: one entry per capability, each value a two-part
statement in §57.1's own shape — what the provider supports, then what this session found.**

**The vocabulary of the first half is §57.1's, and it is a constant of the build.**
`supported by provider` for `watch`, `relationships`, `mutations`, `remote logs` and
`subject access review`; `not supported by provider` for `remote exec`, `attach` and
`port forward`. §42.6 forbids a hidden `kubectl` subprocess and this package speaks its own
HTTP/1.1 over a brokered byte connection, so upstream's three stream protocols are refusals in the
type system (ADR-0018, `logs::SessionRequest::open` returning `Infallible`) rather than features
awaiting a permission. They are reported rather than omitted because §57's manifest sketch lists
them and an operator asking whether this thing can exec is owed the answer.

**The vocabulary of the second half is a closed set, and every word names the evidence it was
earned from:**

| word | earned from |
|---|---|
| `available on resource` | a resource this cluster serves offers the verb or subresource (§11.1) |
| `granted by local KUANG policy` | the host answered `Granted` for the grant (§51.1) |
| `blocked by local KUANG policy` | the host answered `Denied`, or `Ask`, which is not a grant |
| `denied for current user` | the API server refused this identity the evidence with `401`/`403` (§21.4) |
| `not served by cluster` | the evidence read, and nothing this cluster serves offers it (§11.5) |
| `not determined: <outcome>` | nothing was gathered, in §21.4's words — `disconnected`, `request failed`, `not queried` |
| `unavailable in any session` | the provider does not implement it (§26.3 of the inherited contract) |

**Three sources, one per capability, and all three are used:**

- **discovery**, for `watch` (a served resource lists the `watch` verb), `mutations` (one lists
  `patch` or `delete`), `remote logs` (`pods/log` is served, §42.1) and `subject access review`
  (`authorization.k8s.io` serves `selfsubjectaccessreviews` and it accepts `create`, §21.2);
- **the host's grant**, for `relationships`. `relation.write` is never granted by default, this
  package contributes thirty-three relation shapes, and a package without the grant contributes no
  edge at all — so `near` answers nothing and, until now, nobody said why. That is §57.1's third
  line exactly;
- **this build's construction**, for `remote exec`, `attach` and `port forward`.

**A capability the provider does not implement cannot be reported as available at all.**
`CapabilityStatement::new` replaces whatever session evidence a caller passes with
`unavailable in any session` when `ProviderCapability::support` is `NotByProvider`. No
accumulation of cluster evidence and no grant can produce an `exec` that an operator might think
they could reach by fixing their RBAC.

**`available on resource` is a statement about the resource and never about the identity.** The
schema documentation says so in as many words, and the closed set above has no member meaning
"allowed": a test asserts that no statement this package can build contains the words *allowed*,
*authorized*, *permitted* or *may*. The per-object answer is the preflight check `k8s-plan`
carries (§21.2, §21.6, ADR-0032), which asks the API server about one verb on one object and
treats the answer as advisory until the request itself is made.

**The grant is asked before the cluster is touched**, with `Ctx::check_capability`, which does not
prompt (spec §31.61 in core). So the host's half of the report is available even for a cluster
that never answered, and a diagnostic can never become a permission dialogue.

**No manifest `capabilities:` block is invented.** §57 defers the schema to the generic contract
and `package/manifest.yaml` already encodes the same facts in KUANG's vocabulary — the grants it
requests, the relation shapes it declares, the commands that carry a risk. §57.1 requires the
*report*, and the report is what this adds.

## Consequences

`get k8s-cluster` answers eight capability statements against any cluster, including one that
cannot be reached: the four discovery-derived ones then read `not determined: disconnected`, the
host's grant still reads, and the three unsupported ones still say so. The diagnostic that already
had to work when the cluster does not now says what could be done if it came back.

One request is added to the diagnostic, and only where discovery says the group exists: the
resource list of `authorization.k8s.io`. It is recorded as a probe like every other request
(§34.3), so its latency and outcome are visible rather than folded into "the cluster".

`unknowns` is unchanged. A capability that was not determined carries its own reason inside its
own statement, and duplicating it into the unknowns list would make one fact two entries that can
drift apart.

The report is per provider instance, which is what this record is. It is not per object and it is
not a plan: an operator who needs to know whether *this* deployment may be scaled asks for the
change, and the plan's preflight answers with the API server's word (§21.2).

Adding a capability later means adding a member to `ProviderCapability`, its support constant and
the evidence that earns its session half. The set is closed and every member is reported every
time, so a capability that is added and never gathered says `not queried` rather than silently
vanishing from the map.

## Alternatives considered

**A boolean per capability.** The shape §26.1 forbids: it makes an unsupported capability, an
unserved one, an ungranted one and an unasked one the same `false`, and it is precisely the
collapse §57.1 exists to prevent.

**Deriving the session half from the manifest.** Free, and a lie: a manifest declares what the
package *may* do, and reading it back as what the session *can* do would report `relationships` as
available on every load, including the loads where the host drops every edge.

**Answering `mutations` from `SelfSubjectAccessReview`.** Tempting, because §57.1's second example
is a per-user denial. Refused: an access review is per verb, per resource and per object (§21.2),
and this record is per provider instance. A review of `patch` on `deployments` in one namespace
cannot be reported as "you may mutate deployments" without asserting something the API server
never said. What the report does instead is say whether the *review itself* can be asked — which
is a capability, and true — and leave the per-object answer to preflight.

**Reporting through `Session::negotiate`.** `session::Capability` is the set of optional *protocol*
behaviours a session agrees with a server — aggregated discovery, watch bookmarks, streaming
lists — and negotiating one is a decision about how to make the next request. §57.1 asks a
different question, about what an operator can do here, and answering both through one enum would
put `port forward` beside `allowWatchBookmarks`. The two stay separate; the protocol negotiation
keeps its own vocabulary and its own tests.

**Omitting exec, attach and port forward.** They are the capabilities an operator is most likely
to ask about and the ones this provider most definitely does not have. §26.3 of the inherited
contract requires a structured unsupported result rather than a vague absence, and silence is the
vaguest absence available.

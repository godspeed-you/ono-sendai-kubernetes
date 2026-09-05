# ADR-0010: A generic noun reaches every kind, because a static document cannot name one invented later — and its records carry one declared schema

- Status: accepted
- Date: 2026-09-05
- Spec refs: §11.5, §12.1, §12.3, §12.5, §13.1, §13.2, §13.3, §13.4, §13.5, §15.1, §15.5, §21.4, §33.1, §33.3, §35.8, §61.2 (K1), §62.1 (Gate A), §62.2 (Gate B); core spec §31.23, §31.68; core ADR-0582
- Decided by: agent (autonomous)

## Context

Two requirements decide K1 and neither was reachable from the shell: §15.1's *arbitrary
discovered readable resources*, and CRD support. The domain layer was not the obstacle.
`schema.rs` already parses an OpenAPI v3 schema and a `CustomResourceDefinition`, projects any
object through any schema, and degrades precision without dropping a field — with tests. What was
missing was a route from a target word to that code.

The obstacle is a genuine tension between two specifications, and `package/contributions/
targets.yaml` recorded it as an open question before this decision was taken.

Core §31.68 registers a package's contributed targets **from a document on disk, read before the
package runs**: `installed manifest -> registry placeholders -> first invocation -> runtime load`.
That is what makes `get k8s-pod` typeable, helpable and completable on a shell that has never
loaded this package. §33.1 requires that "a newly installed CRD MUST be discoverable without
rebuilding Ono".

A CRD invented after the package was built cannot appear in a document written before it. So the
static registration that makes a noun cheap is the same property that makes a noun unable to name
a kind nobody had invented yet.

Three options were weighed against the core that exists, in a checkout of it, rather than against
the core that would be nicest.

**Handshake-time contribution — the plugin discovers CRDs at load and contributes a target per
kind — does not work, for two independent reasons.** First, the SDK builds the whole `Plugin`,
contributions and all, before `run()` opens the host session: there is no point at which a
package has both a brokered connection and an unsent contribution list, so the CRDs cannot be
known when the contributions are made. Second, even if they could be, core does not turn a
handshake target contribution into an invocable word. `ono-kuang-supervisor`'s `load()` checks a
contributed target's schema id for a package-or-core prefix, stores it, and mounts a
`PluginProvider` for it in the `ProviderRegistry`; the thing that makes `get <word>` *resolve* is
`ono-cli`'s `plugin_registry::target_declarations()`, which reads the on-disk document and
synthesises one `ContributedCommand` per entry. A handshake-only target name yields a provider
entry that nothing can spell. This is a finding about core, recorded on the board, and not a
failure of this repository.

**A schema id naming the kind is refused by the host, twice.** The supervisor sets
`Expected::Schema(<the target's declared schema>)` for a query and, on every emitted value,
decodes it against a registry holding the builtins plus the package's *contributed* schemas. A
record claiming `…kubernetes.sprocket/1` fails to decode at all — "no schema is registered as …"
— and a record that decodes but does not match the target's declaration is a
`runtime.schema_violation`. Since contributions are fixed before any cluster is reached, a schema
named after a discovered kind can never be among them.

## Decision

**One statically declared noun, `k8s-resource`, whose kind is a query option; and one statically
declared schema, `io.github.godspeed-you.kubernetes.resource/1`, that every dynamic record
carries.**

```text
get k8s-resource --kind Sprocket --group menagerie.example
get k8s-resource --resource spr  --group menagerie.example --version v1
```

The word is typeable, helpable and completable without loading anything, because it is in the
document §31.68 reads. It reaches anything discovery finds, because the kind is data. It costs
the user a more verbose spelling than `get k8s-pod`, and that is the whole of the price.

Four consequences of that shape are decided here rather than left to the implementation.

**The kind is resolved against the cluster, and an ambiguous one is refused.** With no `group`,
the search covers the preferred version of every group the server lists — one version per group,
because two served versions of one resource are one resource and counting them as two candidates
would make §13.4's version choice look like §35.8's ambiguity. A kind that two groups both serve
answers `resolve.ambiguous` (core's own `Ono-Sendai-E0103`) carrying the candidates and the
option spelling that selects each. §35.8 forbids resolving by an arbitrary type priority, and
§13.5 is why the situation arises at all. A kind is matched exactly; a plural or a short name is
matched case-insensitively, because those are the typing convenience §13.5 describes and a kind
is not.

**Not served, not listable, ambiguous and empty are four answers.** `provider.unsupported` for a
resource the cluster does not serve and for one it serves without `list`; `resolve.ambiguous` for
a name several types share and for a query that named no kind at all — which is answered with the
cluster's own catalogue, the only honest reply to "which resource?" from a provider that compiles
in no list of them. None of them is an empty stream (§11.5, §21.4).

**Typing comes from the API server's OpenAPI v3 document for the resolved group-version, and its
absence degrades precision rather than removing fields.** One request types a built-in and a
custom resource identically, which is exactly what §33.1 requires and what makes reading the
`CustomResourceDefinition` object unnecessary — so no permission on `customresourcedefinitions`
is needed to understand a custom resource. The component is found by what it declares in
`x-kubernetes-group-version-kind` (§13.2), never by a naming convention over the component key.
Where no document is published, the typing is `Schema::absent()`, every field still projects, and
the record says `schema_source: absent`, `precision: unknown` and lists the pointers of the
fields nothing described.

**Every dynamic record carries `io.github.godspeed-you.kubernetes.resource/1`.** This is the
subtlest part, and it is a deliberate loss. The Ono schema id no longer distinguishes one custom
kind from another — a `Sprocket` and a `Widget` are records of the same schema. What
distinguishes them is *inside* the record, as §13.2's canonical host type: `api_group`, `kind`,
`resource_name` and `scope`, beside the `api_version` the object was read under. A consumer that
wants one kind filters on those fields rather than on the schema. The alternative was a record
that lies about what it is, and the host would reject it anyway.

## Consequences

- **Gate A is provable without a cluster and without recompiling.** `tests/query.rs` drives the
  real binary under `TestHost` against a recorded server offering an invented group, kind, plural,
  short name and field set. `should_name_the_invented_kind_nowhere_in_the_implementation` asserts
  that none of those words appears in any source file of the plugin crate, so the kind is reached
  because it is data and the test fails the day anyone special-cases it.
- **Gate B is provable in both directions.** With a published schema the record is structural:
  `format: date-time` makes an instant, `type: integer` an integer, a described list of objects a
  list of maps, `untyped` empty. Without one every field survives with its own JSON shape, the
  same date stays text, and `untyped` names each undescribed pointer. Precision degraded; nothing
  was dropped.
- **Type identity survives one shared schema, and Ono-level type identity does not.** Two
  different custom kinds are indistinguishable to anything that keys on the schema id alone —
  including, potentially, a future default view or a `where` clause written against a schema.
  That is the price, and it is stated here rather than discovered later.
- **`precision` and `untyped` cover the resource's own content, not its metadata.** This package
  projects `metadata` itself from §14's common projection, so a schema's silence about `metadata`
  leaves no gap in what is reported. Counting it would make every resource on every server read
  as undescribed, which would be a worse lie than the one it avoided.
- **A curated noun is now a better answer for a kind rather than the only answer for it.** The
  five wired targets keep their richer, kind-specific schemas; `k8s-resource` is the floor beneath
  them, and §15.5's separation of "readable dynamically" from "semantically curated" is a
  statement about which of the two answered.
- **A group whose resource list does not read fails the query.** With no `group` the search reads
  every group's resource list, and one that fails is not skipped: an incomplete search that
  resolved to one candidate would be indistinguishable from an unambiguous one. §34.2's failure
  isolation for aggregated API servers is therefore not yet honoured on this path, and naming
  `group` is the way to keep a broken aggregated API out of the search. Recorded on the board.
- **The dynamic route crosses the same redaction boundary.** `Guarded::hold` is still the only
  door, so a Secret reached generically has had its payload destroyed before the record is built;
  a test asserts the payload appears nowhere in a `--kind Secret --group ''` answer.
- **The shell cannot pass the options yet.** Core's `invoke_contributed` issues
  `provider.query` for a contributed target with an empty options map, and core ADR-0582 says so
  explicitly. That blocks `--kind` today exactly as it already blocks `--context` for `get
  k8s-pod`, so it is a pre-existing gap this decision inherits rather than one it creates.
  Recorded on the board as a finding about core.

## Alternatives considered

**A target contributed at handshake time, one per discovered CRD.** The most attractive shape:
`get sprocket` with a real word, real help and real completion. It does not work — the SDK fixes
contributions before the session exists, and core registers invocable words only from the on-disk
document. If both were changed it would still cost a load of every cluster's CRDs before the
shell could resolve a word, which is the opposite of §31.68's reason for existing. Left as a
finding for core rather than approximated here.

**Both: a generic noun as the floor, and a discovered CRD additionally earning a name.** The
right long-term answer and the one this decision is shaped to allow — `k8s-resource` is the floor
and nothing about it prevents a named noun later. It needs the core change above, so the half
that works now is the half that was implemented.

**Nineteen more static nouns, one per Tier 2 kind.** Not an answer to the question. It postpones
the same wall by one tier and leaves §33.1 unmet, because the wall is CRDs rather than
uncurated built-ins.

**A schema id derived from the GVK, registered on the fly.** Refused by the host at two points
(above), and it would be dishonest even if it were not: §31.23's contributed schema is a promise
made before the records exist, and a promise made after the fact is a different thing wearing its
name.

**`kind` defaulting to something when the query names none.** Any default is this package
choosing a resource on the operator's behalf, which is the same class of invention as defaulting
an API server endpoint (ADR-0009). The refusal carries the cluster's catalogue instead, so the
operator gets the list rather than a guess.

**Matching a kind case-insensitively.** `pods` would then find the kind `Pod`, which puts a GVR's
plural and a GVK's kind one keystroke apart — the exact confusion §13.1 exists to prevent. Only
the plural and the short name, which *are* typing conveniences, are matched loosely.

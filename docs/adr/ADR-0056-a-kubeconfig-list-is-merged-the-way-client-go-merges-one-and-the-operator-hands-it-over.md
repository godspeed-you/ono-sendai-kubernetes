# ADR-0056: A kubeconfig list is merged the way client-go merges one, and the operator hands it over

- Status: accepted
- Date: 2026-09-07
- Spec refs: §7.1, §7.2, §7.4, §7.5, §8.4, §57.1; §7 of the generic provider contract
- Decided by: agent (autonomous)

## Context

§7.2 is two sentences with two different forces:

> If the host chooses to honor `KUBECONFIG` multi-file merge semantics, it SHOULD match standard
> Kubernetes client behavior closely enough that a context usable by `kubectl` resolves
> predictably in Ono.
>
> Any intentional deviation MUST be documented and surfaced by `explain provider` or equivalent
> diagnostics.

Until now this provider read the first file only and surfaced *that* as the deviation:
`get k8s-cluster` reported `kubeconfig merge: not supported by provider`. An operator whose
`KUBECONFIG` names an overlay of a base config and a per-cluster file — the ordinary managed-cloud
arrangement — got a context that `kubectl` resolves and Ono did not.

Two facts shape the fix. First, client-go's merge is a small, exact set of rules, not a vague
"match kubectl". Second, **the package never sees the operator's `KUBECONFIG` environment
variable**: the supervisor sanitises a package's environment to `PATH`, `HOME`, `LC_ALL` and `TZ`
(core `crates/ono-kuang-supervisor/src/sandbox.rs`), so there is nothing in the environment for
this package to read. A `KUBECONFIG` value has to arrive as configuration.

A third fact is a concurrent core change. Core ADR-0593 makes the *host* expand a leading `~/`
against the operator's real home. This package used to expand `~/` itself, reading `HOME` — which
in the sandbox is the sandbox working directory, the wrong home entirely. That expansion has to
stop.

## Decision

**The merge is implemented in the domain crate; the list is handed over as the `kubeconfig`
option; and the one surviving deviation — the environment variable — is what the diagnostic now
surfaces.**

`Kubeconfig::merge` takes an ordered list of `(path, text)` documents and follows client-go's
loading rules:

- files load in list order, and for `clusters`, `users` and `contexts` the **first file to define
  a name wins**;
- `current-context` is the **first non-empty** one across the list;
- an empty document is skipped;
- a *missing* file is the caller's to skip before it reaches the merge — client-go ignores a
  nonexistent file in the list — while an existing file that does not parse is a
  `ConfigError::Malformed` **naming the file**, because "one of several is broken" is not a fix
  anyone can act on;
- relative `certificate-authority`, `client-certificate`, `client-key` and `exec` `command` paths
  resolve against the **directory of the file that defined them**. A command resolves only when it
  names a path (contains a separator) — a bare `aws` stays a `PATH` lookup — which is client-go's
  own rule. An absolute path and a `~/`-anchored one pass through unchanged;
- a context's `namespace` default is per context (§7.5);
- each entry records which file supplied it (`source_of_context`, `source_of_cluster`), so a
  diagnostic can say so.

The package reads the list through the host's `filesystem.read` capability, one file at a time, in
`Endpoint::from_kubeconfig`. A file the host reports as `io.not_found` is skipped; a denied read is
reported, because "you did not grant this path" and "this path is not there" are different states
(§21.4). The `kubeconfig` option accepts the colon-separated `KUBECONFIG` syntax; an operator
passes `--kubeconfig $KUBECONFIG` to hand over their list, and a single path is a list of one.

`expand_home` is deleted. A `~/` path is passed to `filesystem.read` verbatim, for the host to
resolve against the operator's real home (core ADR-0593). `DEFAULT_KUBECONFIG` stays
`~/.kube/config`.

The `get k8s-cluster` capability report keeps its `kubeconfig merge` line, now reading
`supported by provider, deviates from kubectl: this package cannot read the KUBECONFIG environment
variable, so a multi-file list is passed explicitly as --kubeconfig $KUBECONFIG`. The deviation
being surfaced changed; the obligation to surface one did not.

## Spec deviation

- Section: §7.2
- Text: "If the host chooses to honor `KUBECONFIG` multi-file merge semantics, it SHOULD match
  standard Kubernetes client behavior closely enough that a context usable by `kubectl` resolves
  predictably in Ono."
- Instead: the merge matches client-go's rules, but the file list is supplied through the
  `kubeconfig` option rather than read from the `KUBECONFIG` environment variable, because the
  supervisor sanitises the environment away before this package runs. This is the intentional
  deviation §7.2's second sentence requires to be surfaced, and `get k8s-cluster` surfaces it.
- Why: a package cannot read the operator's environment (core `sandbox.rs`), so "honor
  `KUBECONFIG`" cannot mean "read `$KUBECONFIG`"; it means "accept and merge the list the operator
  hands over".

## Consequences

- A `KUBECONFIG` overlay resolves the way `kubectl` resolves it. `Kubeconfig::merge`'s domain
  tests pin first-wins, first-non-empty `current-context`, empty-document skipping, the
  file-naming parse error and every relative-path rule; the package tests
  `should_resolve_a_context_a_second_kubeconfig_of_a_colon_list_defines`,
  `should_skip_a_missing_first_kubeconfig_and_read_the_next` and
  `should_read_a_relative_certificate_authority_against_its_own_file_s_directory` prove the list
  reaches the wire, a missing file is skipped, and a relative CA resolves against its own file.
- `~/` no longer breaks against the sandbox home. Against the core pinned when this was written
  it changed nothing that passed before — the package matched a literal `~/.kube/config` and was
  denied — and it became correct when `ADR-0593 (core)` landed, which it has: the demo connects
  with no `--kubeconfig`.
- Preferences are not modeled: nothing in this provider reads kubeconfig `preferences`, so there
  is no first-wins to apply to a field no code consults.

## Alternatives considered

**Keep reading the first file and keep surfacing "no merge".** Rejected: it leaves the ordinary
managed-cloud arrangement — a base config plus a per-cluster overlay — resolving differently from
`kubectl`, which is precisely what §7.2's `SHOULD` asks to avoid.

**Resolve relative paths eagerly to absolute at merge time and drop the origin.** Rejected: the
origin directory is also what a diagnostic needs to say which file supplied an entry, and
resolving lazily in `connection()` keeps a single place that knows both.

**Read `KUBECONFIG` from the environment.** Impossible: the supervisor sanitises it away, and a
package that depended on an environment variable it can never see would be broken by construction.

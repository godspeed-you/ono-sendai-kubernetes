# ADR-0070: A person is asked in their own words, and the helper is asked for at first use

- Status: accepted
- Date: 2026-09-08
- Spec refs: §8.2, §8.3, §35.5, §51.1–§51.4, §57, §62 Gates I and N; §21.4, §27.2, §27.3 of the
  generic provider contract; core's `docs/kuang11/kuang11-plugin-installation-permissions-spec.md`
  (K11P) §6, §7, §14, §16, §26, §33 Gate X; `ADR-0600 (core)` through `ADR-0605 (core)`; ADR-0024,
  ADR-0054, ADR-0066
- Decided by: agent (autonomous)

## Context

Until this decision, using this provider meant typing its reverse-DNS id, a `path:` source and
`--confirm`, then four to six `grant capability` lines naming `network.connect`, `filesystem.read`
with a path scope, `secret.use`, `relation.write` and — for a managed cloud — `process.exec`, before
`get k8s-pod` answered anything. Every one of those grants was right, and K11P §1.2 names what the
sequence produces anyway: a person trained to approve six identifiers they do not understand
approves the seventh too.

Core now carries a permission layer over the same broker (`ADR-0600 (core)`): a manifest under
`kuang-package/2` declares permissions in a person's words, each resolving to exact capabilities,
grouped into access profiles; the host classifies every capability and a package cannot lower the
class; `install plugin <name>` is one transaction that ends ready; a just-in-time permission is put
to the person at the moment of use, for the concrete value the call names; and `set permission` is
how a decision is made or revisited. K11P §26 names this provider as the reference and states the
mapping it must be equivalent to. This ADR records how the package meets it and what changed in the
code that reads the host's answers.

## Decision

### 1. The manifest declares seven permissions and three profiles, and the words are the manifest's

`package/manifest.yaml` is `kuang-package/2`, version `0.2.0`, `kuang_api ">=11.2 <12"`. Its
`permissions` section is K11P §26.1's table, verbatim in intent:

| permission | kind | phase | grants | in `recommended` |
|---|---|---|---|---|
| `cluster-access` — Connect to Kubernetes clusters | external-observe | install | `network.connect`, runtime-derived | yes |
| `kubeconfig-read` — Read Kubernetes configuration | filesystem-read | install | `filesystem.read` `{paths: [~/.kube/config, ~/.kube/*.yaml]}` | yes |
| `credential-use` — Use Kubernetes credentials | secret-use | install | `secret.use` | yes |
| `spatial-relations` — Add Kubernetes relationships to Ono | local-contribution | automatic | `relation.write`, package-contributions | included |
| `plugin-state` — Keep plugin state and read the clock | local-contribution | automatic | `state.persist`, `clock.read` | included |
| `credential-helper` — Run an external login helper | execute-helper | jit | `process.exec`, runtime-derived | no — in no profile; asked when needed |
| `cluster-mutation` — Change Kubernetes resources | external-change | explicit | `provider.mutate`, provider-instance | **no** |

`minimal` holds the two automatic permissions; `recommended` adds the three install-phase
permissions; `operate` adds `cluster-mutation`. The JIT helper is in no profile — the host
refuses a `recommended` profile that carries one (K11P §9.1) — and is decided at the moment of
use whatever the profile. The capability list above the
section is unchanged: a permission maps onto capabilities the manifest already declares, and the
host refuses one that does not. Nothing here can put `provider.mutate` into `recommended` — the
host's class table forbids it and the parser refuses the manifest — so K11P §26.4's "must not be
silently enabled" holds by construction rather than by this package's discipline.

### 2. `spatial-relations` is automatic because the authority is bounded

`relation.write` was "never granted by default" here (ADR-0024's manifest comment, §35.5) because
an unscoped grant could name another provider's relation. Under `ADR-0600 (core)` the family has a
`relations` scope and `package-contributions` binds it to the relation ids this package's own
sixty-four shapes derive to, with provenance the host stamps. That is class A, and K11P §7.1 puts
class A in the automatic phase: `install plugin kubernetes` includes it without a prompt, and
`near` has exits without a `relation.write` anybody typed (K11P §26.2). A person who does not want
the graph denies the permission by name — `set permission kubernetes spatial-relations --decision
deny` — and the place has no exits, which is the filter-before-merge §35.5 requires, reached through
a decision rather than through an omission.

### 3. The helper is asked for at first use, and `ask` proceeds

`credentials.rs` read `capabilities.check` as a boolean: anything but `Granted` was a refusal that
told the operator to reload with `--grant process.exec`. The host now answers **`ask`** when the
`credential-helper` permission decides the family just in time and nothing has decided it yet
(`ADR-0603 (core)`), and the package's reading changes to match:

- **`Granted` and `Ask` proceed.** The `process.exec` call names the one program the kubeconfig
  names, and the host puts exactly that to the person — once, this session, or always for that
  program — or answers `permission.required` where nobody can be asked. The refusal reaches the
  caller as the host wrote it, naming the permission, the program and the `set permission` line
  that would allow it. Nothing runs until somebody says so, and the package composed the request
  because the host asked it to.
- **`Denied` is a decision already made** — a deny recorded against the permission, or a policy —
  and the package refuses before the program name is assembled, as it always did (§21.4). The
  remedy it names is the permission in a person's words: `set permission kubernetes
  credential-helper --decision allow --scope programs=<helper>`. The raw `--grant process.exec`
  is gone from every message this package writes.
- **`Unknown` and a failed check refuse**, naming the host as older than `kuang-host/11.2`.

The negative §8.2 asks for — no program runs without an explicit process-execution capability —
is unchanged: the fixture's `ran` record is empty under both refusals, and one entry under one
`once` answer.

### 4. `get k8s-cluster` still prompts for nothing

The cluster diagnostic's `local_grant` keeps reading `Ask` as *withheld*: a diagnostic is not the
place a prompt may appear, and "would need to ask" is not "held now". The relations half of the
diagnostic therefore reports what an unprompted invocation would find, which is the truthful
answer for a report.

### 5. The suites install the package the way an operator does

`tests/live_cluster.rs` and `tests/spatial_shell.rs` lay the package out in a source directory and
run one `install plugin path:… --confirm` — `--access operate --confirm` where the tests write to
the cluster, because K11P §7.4 wants the profile named rather than a flag that means yes to
everything. No suite grants a capability by hand any more; `load plugin` carries no `--grant`. The
`TestHost` suites keep their explicit grants, which is the test host's contract, and `isolation.rs`
gains the three shapes of the helper decision: allowed by a person at first use through
`ScriptedConsent`, refused because nobody can be asked, refused because it was denied.

## Consequences

- An operator's first session is `install plugin kubernetes` then `get k8s-pod --context prod`.
  The README, `scripts/demo.sh`, `docs/STATE.md` and `docs/coverage.md` say so, and the old
  grant-by-hand sequence appears nowhere as the normal path.
- `grant capability` / `revoke capability` remain the raw mechanism under the layer and are
  documented as advanced; `get permission kubernetes --all` shows how each permission maps onto
  them.
- A `kuang-package/1` host refuses this manifest at the unknown `permissions` field and says which
  format it reads. The pinned core revision is the one that carries the layer, and CI builds the
  shell from it.
- Gate N's window is unchanged; Gate X of K11P holds in core, where no Kubernetes word appears in
  the code that classifies, plans, prompts or decides — every word in the table above lives in
  this package.
- Encoded by `isolation.rs` (`should_run_the_credential_plugin_once_a_person_allows_that_helper_at_first_use`,
  `should_refuse_to_run_a_credential_plugin_when_nobody_can_be_asked_for_it`,
  `should_refuse_to_run_a_credential_plugin_when_the_permission_is_denied`), `contributions.rs`
  (`should_declare_the_permissions_k11p_names_for_the_reference_provider`), `spatial_shell.rs`
  (`should_open_no_exit_from_a_kubernetes_place_when_its_spatial_relations_are_denied`) and the
  live suite's install-once fixture.

## Alternatives considered

- **Keeping `credential-helper` at install phase, granted blind with the recommended profile.**
  K11P §26.3 says the user was not asked for generic `process.exec` during install, and §8.2's
  "explicit" is about the program, which is unknown until a context names it.
- **Reading `Ask` as a refusal, as before.** Would make the JIT prompt unreachable from this
  package: the host asks only when the call arrives.
- **Making `spatial-relations` an install-phase prompt.** Bounded to the package's own shapes it
  is extension-local authority; a prompt for it is the capability fatigue K11P §1.2 names.

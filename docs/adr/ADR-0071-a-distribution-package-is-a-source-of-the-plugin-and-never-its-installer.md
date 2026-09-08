# ADR-0071: A distribution package is a source of the plugin, and never its installer

- Status: accepted
- Date: 2026-09-08
- Spec refs: §51, §57, §62 Gate N; §27 of the generic provider contract; core's
  `docs/specs/kuang11/kuang11-plugin-package-acquisition-system-distribution.md` (K11A) §5, §8,
  §11, §15, §17, §22, §23; `ADR-0606 (core)`, `ADR-0607 (core)`; ADR-0070
- Decided by: agent (autonomous)

## Context

K11A §22 asks this provider to be the first reference plugin demonstrating all three acquisition
paths — a catalog artifact, a local directory, and an operating-system package — and names the
Linux package `ono-plugin-kubernetes`. Core decided what a system-provided payload is (`ADR-0606
(core)`): a versioned candidate under `/usr/lib/ono-sendai/plugin-sources/<id>/<version>/`, read
but never run in place, that `install plugin kubernetes` verifies, asks about and copies. What is
left to this repository is how the wrapper is built and what it must not contain.

## Decision

### 1. The wrapper places one payload and does nothing else

`crates/ono-kubernetes-plugin/Cargo.toml` carries `[package.metadata.deb]` and
`[package.metadata.generate-rpm]` for `ono-plugin-kubernetes`. Both install the same files:
`manifest.yaml`, `contributions/*.yaml`, `runtime/ono-kubernetes` and `signature.yaml` under
`/usr/lib/ono-sendai/plugin-sources/io.github.godspeed-you.kubernetes/<version>/`, and the sidecar
`<version>.origin.yaml` (`kuang-system-origin/1`, naming the outer package and its manager) beside
it. The version directory is this crate's version, which `package/manifest.yaml` declares too, and
`scripts/package.sh` refuses to build when the two disagree. Nothing lands in `/usr/bin`: the
runtime runs only from Ono's own copy (K11A §16.3).

There is **no maintainer script** and no scriptlet. The package manager creates directories and
copies files, which is the passive integration K11A §11.3 allows; it enables nothing, loads
nothing, trusts nobody and grants nothing. `tests/packaging.rs` holds the metadata to that.

### 2. The payload is signed, unchanged, and says its digest

`scripts/package.sh --key <signing key>` builds the runtime in the release profile, stages the
payload under `target/payload/`, signs it with `kuang-sign`, writes the sidecar, prints the
content digest `kuang-sign digest` computes — the number a catalog release states — and drives
`cargo deb` and `cargo generate-rpm`. An unsigned wrapper is refused: a distribution package that
installs under local-development semantics is a contradiction of K11A §17.2. The same payload,
packed with `kuang-sign pack`, is the `.kuang` artifact a catalog entry names (`ADR-0607 (core)`),
so the three paths carry one signed payload with one digest (K11A §5, §22).

### 3. The lower bound is advice; the manifest is the contract

The `.deb` depends on `ono (>= 0.4.3)` and the `.rpm` requires the same: the first core release
that reads `kuang-package/2` and the permission layer. K11A §17.3 makes this preflight assistance
and nothing more; `kuang_api: ">=11.2 <12"` in the manifest is what Ono enforces.

## Consequences

- `sudo apt install ono-plugin-kubernetes` then `install plugin kubernetes` is the enterprise and
  offline path; the prompt says `Source: system package (ono-plugin-kubernetes)`, and `apt upgrade`
  changes a candidate, never the running package. `remove plugin kubernetes` says the system source
  remains. The README documents both layers, and that the package manager grants Ono nothing.
- The workspace version moves to `0.2.0`, the version the manifest has declared since ADR-0070;
  the wrapper's version directory follows it.
- CI does not build the wrappers yet; `scripts/package.sh` is the build, and a release run signs
  with the project's key. The bootstrap catalog in core keeps its `git:` artifact until a `.kuang`
  is published beside the `.deb` and the `.rpm`.
- Encoded by `tests/packaging.rs`: name, payload placement, no maintainer script, no `/usr/bin`,
  the lower bound, the signing and the digest.

## Alternatives considered

- **A `postinst` that runs `ono install plugin kubernetes --confirm`.** K11A §11.3 forbids it in
  as many words: a maintainer script may not activate plugin code or write consent on a user's
  behalf, and root installing a package is not the user deciding.
- **Installing the runtime into `/usr/bin` and pointing the manifest at it.** A mutable,
  unversioned reference into package-manager-owned files, which K11A §8.3 calls non-conforming.
- **Shipping the payload unsigned and letting the distribution's repository signature stand in.**
  §11.2: an outer signature is additional evidence and never a substitute for the package's own.

#!/usr/bin/env bash
# Builds the distribution wrappers of K11A §8, §17, §22 (`ADR-0606 (core)`, ADR-0071): a `.deb`
# and an `.rpm` named `ono-plugin-kubernetes` that place the KUANG/11 payload under the system
# source root — `/usr/lib/ono-sendai/plugin-sources/<id>/<version>/` — beside a sidecar naming
# the outer package. Installing either grants Ono nothing: the payload is a candidate that
# `install plugin kubernetes` verifies, asks about and copies (K11A §9, §12).
#
#   scripts/package.sh --keyless           [--deb | --rpm]
#   scripts/package.sh --key <signing key> [--deb | --rpm]
#
# The payload is signed, always: a wrapper preserves the package's own signature unchanged
# (K11A §17.2), and an unsigned payload would install under local-development semantics, which
# is not what a distribution package is for.
#
# `--keyless` is what a release uses and what this project has no key for: `kuang-sign describe`
# writes the bytes a signature covers and `cosign sign-blob` signs them against a short-lived
# certificate issued to the workflow, so nothing here keeps a private key (`ADR-0609 (core)`).
# It needs an OIDC token, which exists inside a GitHub Actions run and not on a laptop.
#
# `--key <file>` is the ed25519 path of `ADR-0311 (core)`, for a local build or a publisher who
# does keep a key. `kuang-sign keygen --out <file>` makes one.
#
# The tools are `cargo deb` and `cargo generate-rpm`, as in core; the runtime is built in the
# release profile first.
set -euo pipefail
cd "$(dirname "$0")/.."

key=""; keyless=0; want_deb=1; want_rpm=1
while [ $# -gt 0 ]; do
  case "$1" in
    --key) key="$2"; shift 2 ;;
    --keyless) keyless=1; shift ;;
    --deb) want_rpm=0; shift ;;
    --rpm) want_deb=0; shift ;;
    *) echo "package.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
if [ -z "$key" ] && [ "$keyless" = 0 ]; then
  echo "package.sh: name how the payload is signed: --keyless in a release workflow, or --key <file> locally (K11A §17.2)" >&2
  exit 2
fi
if [ -n "$key" ] && [ "$keyless" = 1 ]; then
  echo "package.sh: --keyless and --key are two ways to sign the same payload; name one" >&2
  exit 2
fi
if [ "$keyless" = 1 ] && ! command -v cosign >/dev/null 2>&1; then
  echo "package.sh: --keyless needs cosign; the release workflow installs it at a pinned version" >&2
  exit 2
fi
sign=$(command -v kuang-sign || true)
if [ -z "$sign" ]; then
  for candidate in ../ono-sendai/target/release/kuang-sign ../ono-sendai/target/debug/kuang-sign; do
    [ -x "$candidate" ] && sign="$candidate" && break
  done
fi
if [ -z "$sign" ]; then
  echo "package.sh: no kuang-sign; build core's ono-kuang-sdk or put kuang-sign on PATH" >&2
  exit 2
fi

id=$(sed -n 's/^  id: //p' package/manifest.yaml | head -1)
version=$(sed -n 's/^  version: //p' package/manifest.yaml | head -1)
crate_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
if [ "$version" != "$crate_version" ]; then
  echo "package.sh: package/manifest.yaml declares $version and Cargo.toml $crate_version; the payload directory is the version, and the two must agree" >&2
  exit 1
fi

echo "== the runtime, release profile =="
cargo build --release -p ono-kubernetes-plugin

echo "== the payload: $id $version =="
payload="target/payload/$id/$version"
rm -rf "target/payload/$id"
mkdir -p "$payload/contributions" "$payload/runtime"
cp package/manifest.yaml "$payload/"
cp package/contributions/*.yaml "$payload/contributions/"
cp target/release/ono-kubernetes "$payload/runtime/ono-kubernetes"
if [ "$keyless" = 1 ]; then
  # The bytes a signature covers, written out so something other than kuang-sign can sign them,
  # and then signed against a certificate issued to this run. No key is created and none is kept.
  "$sign" describe "$payload" --out "target/payload/$id-$version.description"
  cosign sign-blob --yes \
    --bundle "$payload/signature.sigstore.json" \
    "target/payload/$id-$version.description"
  cosign verify-blob \
    --bundle "$payload/signature.sigstore.json" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/godspeed-you/ono-sendai-kubernetes/\.github/workflows/release\.yml@refs/tags/v' \
    "target/payload/$id-$version.description"
  rm -f "target/payload/$id-$version.description"
else
  "$sign" sign "$payload" --key "$key"
fi
# The sidecar: data about the outer package, beside the payload and outside the signed set
# (K11A §10.1). `apt/dpkg` for the .deb; the .rpm is the same payload and says `dnf/rpm`.
printf 'format: kuang-system-origin/1\npackage: ono-plugin-kubernetes\nmanager: apt/dpkg\n' \
  > "target/payload/$id/$version.origin.yaml"
echo "content digest: $("$sign" digest "$payload")   (what a catalog release states)"
"$sign" pack "$payload" --out "target/payload/$id-$version.kuang"

if [ "$want_deb" = 1 ]; then
  echo "== ono-plugin-kubernetes_${version}.deb =="
  cargo deb --manifest-path crates/ono-kubernetes-plugin/Cargo.toml --no-build --no-strip
fi
if [ "$want_rpm" = 1 ]; then
  printf 'format: kuang-system-origin/1\npackage: ono-plugin-kubernetes\nmanager: dnf/rpm\n' \
    > "target/payload/$id/$version.origin.yaml"
  echo "== ono-plugin-kubernetes-${version}.rpm =="
  cargo generate-rpm -p crates/ono-kubernetes-plugin
fi

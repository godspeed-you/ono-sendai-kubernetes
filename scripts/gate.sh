#!/usr/bin/env bash
# The quality gate of AGENTS.md section 10. Every increment must pass this before it is
# committed. Runs identically on a developer machine and in CI.
#
# The document checks below came first, when this repository held a specification and nothing
# else. The Rust steps joined them when the first crate landed, which is the direction section 10
# requires: the gate grows with the repository and never shrinks to match it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31m%s\033[0m\n' "$*" >&2; problems=$((problems + 1)); }
problems=0

# Section 10 puts the gate *before* the commit, so what it is asked about is the working tree —
# tracked files plus files that are new and not ignored. Reading only the index would let a new
# ADR, a new document or a new broken link pass unchecked until the commit that adds it is
# already made, which is the wrong side of the gate.
tracked_and_new() { git ls-files --cached --others --exclude-standard -- "$1" | sort -u; }

SPEC="docs/architecture/kubernetes-provider.md"

# --- branch guard ------------------------------------------------------------------------------
# Implementation belongs on a feature branch so the whole run stays disposable (AGENTS.md §11).
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
if [[ "$branch" == "main" && "${ONO_ALLOW_MAIN:-0}" != "1" ]]; then
  cat >&2 <<'GUARD'
gate: refusing to run on `main`.

Implementation belongs on the `implementation` branch, so that the run can be discarded and
restarted from a clean `main` at any time (AGENTS.md section 11):

    git switch implementation || git switch --create implementation main

If you are the user working on the specification or the instructions themselves, run the gate
with ONO_ALLOW_MAIN=1.
GUARD
  exit 1
fi

# --- the specification is untouched ------------------------------------------------------------
# The rule is checked rather than trusted: a written rule is easy to forget halfway through a long
# session (AGENTS.md §5.2).
step "specification"
manifest="docs/architecture/spec.sha256"
if [[ ! -f "$manifest" ]]; then
  fail "$manifest is missing; the specification can no longer be proven untouched"
elif [[ ! -s "$manifest" ]]; then
  fail "$manifest is empty; an empty manifest verifies successfully and proves nothing"
elif [[ ! -f "$SPEC" ]]; then
  # The half a checksum cannot answer: a manifest naming a file that is not there would otherwise
  # be reported by `sha256sum -c` as a missing-file warning that is easy to lose in a log. In core
  # this exact shape — documents moving out from under their discovery root — nearly left nine
  # immutable specifications unguarded behind a green gate (ADR-0581 in core).
  fail "$SPEC does not exist, so nothing the manifest names is being verified"
elif ! ( cd docs/architecture && sha256sum --check --strict --status spec.sha256 ); then
  fail "the specification has been modified. It is IMMUTABLE (AGENTS.md section 5.1): restore it
with \`git checkout -- $SPEC\` and record the decision in an ADR instead. If the user replaced the
specification deliberately, they update $manifest."
else
  echo "specification: unmodified"
fi

# --- every relative markdown link resolves -----------------------------------------------------
step "links"
links=0
while IFS= read -r file; do
  # Skip the immutable specification: a dangling path inside it could never be repaired, and
  # demanding it would only make the gate unpassable (AGENTS.md §5.1).
  [[ "$file" == "$SPEC" ]] && continue
  while IFS= read -r link; do
    [[ -z "$link" ]] && continue
    if [[ ! -e "$(dirname "$file")/$link" ]]; then
      fail "$file: the link \`$link\` does not resolve"
    fi
    links=$((links + 1))
  done < <(grep -oE '\]\(([^)#h][^)]*)\)' "$file" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//; s/#.*//')
done < <(tracked_and_new '*.md')
echo "links: $links relative links resolve"

# --- ADRs ---------------------------------------------------------------------------------------
step "decisions"
adrs=0
if [[ -d docs/adr ]]; then
  previous=0
  for path in $(tracked_and_new 'docs/adr/*.md'); do
    name="$(basename "$path")"
    if [[ ! "$name" =~ ^ADR-[0-9]{4}-[a-z0-9-]+\.md$ ]]; then
      fail "docs/adr/$name does not match ADR-NNNN-kebab-title.md (AGENTS.md section 8)"
      continue
    fi
    number=$((10#${name:4:4}))
    if (( number == previous )); then
      fail "docs/adr/$name reuses number $number; ADR numbers are monotonic"
    fi
    previous=$number
    for heading in "## Context" "## Decision" "## Consequences"; do
      grep -qF "$heading" "$path" || fail "docs/adr/$name has no \`$heading\` section"
    done
    grep -qE '^- Status: ' "$path" || fail "docs/adr/$name has no \`- Status:\` line"
    adrs=$((adrs + 1))
  done
fi
echo "decisions: $adrs records"

# --- the instructions name the specification ---------------------------------------------------
# A specification the instructions do not name is one no agent reads — the failure core's
# narrative check exists to prevent (ADR-0423, ADR-0026 in core).
step "instructions"
for file in README.md AGENTS.md CLAUDE.md; do
  if [[ ! -f "$file" ]]; then
    fail "$file is missing"
  elif ! grep -qF "$SPEC" "$file"; then
    fail "$file does not reference the specification \`$SPEC\`"
  fi
done
echo "instructions: README.md, AGENTS.md and CLAUDE.md name the specification"

# --- every skip is declared, and every declaration is still a skip --------------------------------
# `docs/contracts/expected_test_skips.yaml` is the register, and this is what makes it one. A live
# integration test is allowed to skip where its cluster is absent (AGENTS.md section 7), but only
# visibly: cargo reports a test that returned early as a pass, so an undeclared skip is a green
# result nobody earned. Core reached the same conclusion in ADR-0513 and this repository borrows
# its marker rather than inventing a second one.
#
# Checked in both directions, because each catches what the other cannot:
#
#   tree -> register   a skip site nobody declared is a quiet escape hatch;
#   register -> tree   a row whose test is gone, or which no longer skips, is a register that has
#                      fallen behind the suite and can no longer be trusted about the rest.
#
# A skip site is a call to `announce_skip("<test>", "<category>", …)`. The test name and the
# category are literals at the call site precisely so this check can read them without running
# anything; rustfmt wraps the call across lines, hence the newline squeeze before the match.
step "skips"
register="docs/contracts/expected_test_skips.yaml"
if [[ ! -f "$register" ]]; then
  fail "$register is missing; every test that can skip has to be declared somewhere"
else
  sites="$(mktemp)"; declared="$(mktemp)"
  trap 'rm -f "$sites" "$declared"' EXIT
  while IFS= read -r file; do
    [[ -f "$file" ]] || continue
    while IFS= read -r found; do
      [[ -z "$found" ]] && continue
      test_name="${found%% *}"
      category="${found#* }"
      printf '%s::%s %s\n' "$file" "$test_name" "$category" >> "$sites"
    done < <(tr '\n' ' ' < "$file" \
      | grep -oE 'announce_skip\( *"[a-z0-9_]+", *"[a-z_]+"' \
      | sed -E 's/announce_skip\( *"//; s/", *"/ /; s/"$//')
    # The ad-hoc form ADR-0513 in core replaced. It reads like a skip and carries no category, so
    # nothing can check it. Comment lines are stripped first: a file is allowed to *describe* the
    # shape it no longer uses, and the module documentation of `spatial_shell.rs` does.
    if sed -E 's|^[[:space:]]*//.*||' "$file" | grep -q 'eprintln!("skipped'; then
      fail "$file announces a skip without a category; use \`announce_skip\` (ADR-0513 in core)"
    fi
  done < <(tracked_and_new 'crates/*/tests/*.rs')
  sed -nE 's/^  - id: "(.*)"$/\1/p' "$register" > "$declared"
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    if ! grep -qF "$id " "$sites"; then
      fail "$register declares \`$id\`, which no longer announces a skip"
      continue
    fi
    path="${id%%::*}"
    name="${id##*::}"
    grep -qE "fn $name\(" "$path" 2>/dev/null \
      || fail "$register declares \`$id\`, and $path has no \`fn $name\`"
    row_category="$(awk -v id="$id" '
      $0 ~ "^  - id: \"" id "\"$" { found = 1; next }
      found && /^    category: / { print $2; exit }' "$register")"
    site_category="$(grep -F "$id " "$sites" | head -1 | awk '{print $2}')"
    [[ "$row_category" == "$site_category" ]] \
      || fail "$register declares \`$id\` as \`$row_category\`; it announces \`$site_category\`"
  done < "$declared"
  while IFS= read -r site; do
    [[ -z "$site" ]] && continue
    id="${site%% *}"
    grep -qxF "$id" "$declared" \
      || fail "$id can announce a skip and $register does not declare it"
  done < "$sites"
  echo "skips: $(wc -l < "$declared" | tr -d ' ') declared, $(sort -u "$sites" | wc -l | tr -d ' ') announced in the tree"
fi

# --- the code ------------------------------------------------------------------------------------
# Skipped only when there is no workspace to build, so that this script keeps working in a
# checkout that predates the first crate. It is not a way to opt out of the Rust bar.
if [[ -f Cargo.toml ]]; then
  step "format"
  cargo fmt --all -- --check || fail "cargo fmt --check found formatting the tree does not use"

  step "lint"
  cargo clippy --all-targets --all-features -- -D warnings || fail "clippy found warnings"

  step "test"
  cargo test --workspace --all-features || fail "the test suite is not green"

  step "docs"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --quiet \
    || fail "cargo doc found warnings"
else
  step "code"
  echo "code: no Cargo workspace yet — nothing to build"
fi

# --- verdict ------------------------------------------------------------------------------------
if (( problems > 0 )); then
  printf '\n\033[31mgate: %d problem(s)\033[0m\n' "$problems"
  exit 1
fi
printf '\n\033[1;32mgate: green\033[0m\n'

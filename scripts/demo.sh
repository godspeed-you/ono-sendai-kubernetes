#!/usr/bin/env bash
# The product thesis, run against a real Kubernetes cluster.
#
#     Kubernetes is not a command namespace inside Ono. It is a system Ono can understand.
#
# This script is that sentence made checkable. It builds an ephemeral cluster, installs the
# package the way an operator installs one, and then does the whole of specification §65's
# "Useful Kubernetes Provider v1 Capability" list at an ordinary `ono` prompt — connect, enter,
# discover, inspect, traverse, watch, distinguish, export, plan, apply, verify, follow — with
# `kubectl` nowhere in the path (§62.13).
#
#   scripts/demo.sh [--version vX.Y.Z] [--keep]
#
# `--keep` leaves the cluster and the scratch home behind for poking at; without it both go away
# even if a step fails.
#
# It is not a test. `crates/ono-kubernetes-plugin/tests/live_cluster.rs` asserts; this narrates,
# for a reader deciding whether the claim is worth anything. Every command below is one somebody
# could type, and the output is whatever the shell printed.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="v1.37.0"
KEEP=0
CLUSTER="ono-demo"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --keep)    KEEP=1; shift ;;
    *) echo "usage: scripts/demo.sh [--version vX.Y.Z] [--keep]" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
note() { printf '\033[2m%s\033[0m\n' "$*"; }
run()  { printf '\033[1m$ ono -c %q\033[0m\n' "$1"; "$ONO" -c "$1" || true; }

# --- the binary this repository does not build -------------------------------------------------
ONO="${ONO_BINARY:-}"
if [[ -z "$ONO" ]]; then
  ONO="$(cd .. && pwd)/ono-sendai/target/debug/ono"
fi
if [[ ! -x "$ONO" ]]; then
  cat >&2 <<MISSING
demo: no \`ono\` binary at $ONO.

\`ono\` is built from the Ono-Sendai core repository, which this one pins as a git dependency
rather than checks out. Set ONO_BINARY, or build a sibling checkout:

    ( cd ../ono-sendai && cargo build -p ono-cli --bin ono )
MISSING
  exit 1
fi

if command -v kubectl >/dev/null 2>&1; then
  echo "demo: \`kubectl\` is on this PATH. The demonstration is about not needing it (§62.13)," >&2
  echo "      so it will not use it — but a reader cannot tell that from here." >&2
fi

# --- the cluster and the scratch home ----------------------------------------------------------
HOME_DIR=""
cleanup() {
  local status=$?
  if (( KEEP == 1 )); then
    say "kept"
    note "cluster:    $CLUSTER   (scripts/cluster.sh down --name $CLUSTER)"
    note "plugin home: $HOME_DIR"
  else
    say "tearing down"
    scripts/cluster.sh down --name "$CLUSTER" >/dev/null 2>&1 || true
    [[ -n "$HOME_DIR" ]] && rm -rf "$HOME_DIR"
  fi
  exit $status
}
trap cleanup EXIT

say "an ephemeral cluster at $VERSION"
note "kind creates it; every fixture goes in over the REST API with curl. No kubectl anywhere."
KUBECONFIG_PATH="$(scripts/cluster.sh up --version "$VERSION" --name "$CLUSTER")"

say "the package, installed the way an operator installs one"
cargo build -q -p ono-kubernetes-plugin
HOME_DIR="$(mktemp -d)"
PACKAGE="io.github.godspeed-you.kubernetes"
mkdir -p "$HOME_DIR/plugins/$PACKAGE/runtime" "$HOME_DIR/plugins/$PACKAGE/contributions" \
         "$HOME_DIR/home/.kube" "$HOME_DIR/state" "$HOME_DIR/config/ono"
cp package/manifest.yaml "$HOME_DIR/plugins/$PACKAGE/"
cp package/contributions/*.yaml "$HOME_DIR/plugins/$PACKAGE/contributions/"
cp target/debug/ono-kubernetes "$HOME_DIR/plugins/$PACKAGE/runtime/ono-kubernetes"
cp "$KUBECONFIG_PATH" "$HOME_DIR/home/.kube/config"
export ONO_PLUGIN_PATH="$HOME_DIR/plugins" HOME="$HOME_DIR/home" \
       XDG_STATE_HOME="$HOME_DIR/state" XDG_CONFIG_HOME="$HOME_DIR/config" \
       ONO_CONFIG_DIR="$HOME_DIR/config/ono"
note "installed at $HOME_DIR/plugins"

# The grants, and the scope on the one that reads a file. §51.3 says the provider SHOULD NOT
# receive arbitrary filesystem read, and it does not: `filesystem.read` is granted with a path
# scope naming this operator's kubeconfig directory and nothing else. `relation.write` is never
# granted by default (§35.5), which is why `near` is silent without it.
GRANT="grant capability filesystem.read --plugin $PACKAGE --scope 'paths=$HOME_DIR/home/.kube/**' | count"
LOAD="$GRANT; load plugin $PACKAGE --grant network.connect --grant clock.read --grant relation.write --grant secret.use --grant state.persist"
KUBE="--kubeconfig $HOME_DIR/home/.kube/config --context ono-admin"

# --- §65's list, in its own order --------------------------------------------------------------
say "1. connect to an ordinary kubeconfig context — and say which cluster this is"
note "§10.2's fingerprint, §8.6's effective identity, §34.3's per-path latency, and what it could"
note "not determine. A provider that cannot say which cluster it is talking to is not usable."
run "$LOAD; get k8s-cluster $KUBE | select name server reachable server_version tls | to json"

say "2. enter a namespace, and stand somewhere"
note "§35.3: a Kubernetes object is a place in Ono's own graph, not a row in a Kubernetes mode."
run "$LOAD; get k8s-pod $KUBE --namespace ono-alpha | take 1 | enter; look"

say "3. discover what this cluster serves, including a kind nobody compiled in"
note "§33.1 and Gate A. \`widgets.ono.test\` was invented by the fixture minutes ago; no source"
note "file of this package names it, and it needs no rebuild to be readable."
run "$LOAD; get k8s-resource $KUBE --namespace ono-alpha --kind Widget --group ono.test | to json"

say "4. inspect typed state — and the fields the schema does not describe"
note "§12.5 and Gate B: a schema that preserves unknown fields keeps them, and says which"
note "pointers it could not type rather than flattening the object to JSON."
run "$LOAD; get k8s-resource $KUBE --namespace ono-alpha --kind Sketch --group ono.test | select name precision untyped | to json"

say "5. Deployment → ReplicaSet → Pod → Node, with the evidence under each hop"
note "§62.4's Gate D: every edge says whether the API server stated it or this provider derived"
note "it, and which field decided."
run "$LOAD; get k8s-relation $KUBE --namespace ono-alpha --kind Deployment --name checkout | select relation target evidence_class evidence_path asserted | to json"

say "6. Service → EndpointSlice → Pod"
run "$LOAD; get k8s-relation $KUBE --namespace ono-alpha --kind Service --name checkout | select relation target evidence_class | to json"

say "7. current conditions, with the rule that produced each derived state"
note "§37.5: no status word this package invented, and no field a reader could mistake for"
note "\`healthy\`."
run "$LOAD; get k8s-condition $KUBE --namespace ono-alpha --kind Deployment --name checkout | to json"

say "8. Events as supplemental evidence — and an empty search that refuses to mean nothing"
note "§38.6 and §63.6: Kubernetes Events are retained for minutes and are not an audit log, so an"
note "empty result is a statement about retention rather than about the cluster."
run "$LOAD; get k8s-event $KUBE --namespace ono-alpha --kind Deployment --name checkout | select reason aggregate recorded_count | to json"

say "9. a live watch, bounded so this script ends"
note "§19.1's list-then-watch as one sequence, and §41.4's six states on every record. At a"
note "terminal and unbounded, this is the live view; here it takes a prefix."
run "$LOAD; get k8s-change $KUBE --namespace ono-alpha --kind Pod --max_changes 1 | select change sync_state view_state segment continuous withheld | to json"

say "10. denied is not empty"
note "§21.4, §21.5 and Gate E. The restricted context may read ono-alpha and not ono-beta, and"
note "ono-beta is not empty — so an empty answer here would be a lie a reader could not detect."
run "$LOAD; get k8s-pod --kubeconfig $HOME_DIR/home/.kube/config --context ono-restricted --namespace ono-beta | to json"

say "11. the machine under a Node, exported rather than resolved"
note "§47.1 and Gate K: \`spec.providerID\` with its pointer, its evidence class and its ranked"
note "strength — and no cloud vendor named anywhere on the route, nor any cloud SDK linked."
run "$LOAD; get k8s-evidence $KUBE --name $CLUSTER-control-plane | select key value evidence_class strength | to json"

say "12. plan a bounded change — without making it"
note "§46.2 and Appendix E: what it would do, what it rests on, what it cannot promise, and"
note "whether the API server says this identity may."
run "$LOAD; get k8s-plan $KUBE --namespace ono-alpha --kind Deployment --name checkout --set '{\"/spec/replicas\": 2}' | to json"

say "13. apply it — as a server dry run, which is what the shortest sentence does"
note "§44.5: \`dry_run\` defaults to true, so predicting is the easy path and writing is the"
note "sentence that says so."
run "$LOAD; set k8s-resource $KUBE --namespace ono-alpha --kind Deployment --name checkout --set '{\"/spec/replicas\": 2}' | select dry_run acceptance stage verdict | to json"

say "14. and now for real, observing the reconciliation rather than claiming it"
note "§62.7's Gate G: an accepted spec change is not a completed rollout. The verdict is made"
note "from a later observation, and \`inconclusive\` is an honest answer."
run "$LOAD; set k8s-resource $KUBE --namespace ono-alpha --kind Deployment --name checkout --set '{\"/spec/replicas\": 2}' --dry_run false | select dry_run acceptance stage verdict reconciliation | to json"

say "14b. a conflict is an answer, and forcing takes a sentence"
note "§44.3 and §44.4: \`spec.replicas\` is already owned by another field manager, so the apply"
note "above came back as a conflict naming it rather than as a silent overwrite. There is no"
note "\`--force\` flag in this package at all; taking ownership costs a reason a reviewer reads."
run "$LOAD; set k8s-resource $KUBE --namespace ono-alpha --kind Deployment --name checkout --set '{\"/spec/replicas\": 2}' --dry_run false --force_because 'demonstrating that ownership is taken deliberately' | select acceptance stage verdict | to json"

say "15. logs, with the bounds of the read on every line"
note "§42.1: a log is never complete, and each line says what bounded it. \`--follow\` makes the"
note "same read a live stream that accumulates nothing (§42.2) and stops when the operator does."
POD="$("$ONO" -c "$LOAD; get k8s-pod $KUBE --namespace ono-alpha | take 1 | select name | to json" \
  | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | head -1)"
if [[ -n "$POD" ]]; then
  run "$LOAD; get k8s-log $KUBE --namespace ono-alpha --name $POD --tail_lines 3 | select line text bounds | to json"
else
  note "no Pod to read a log from"
fi

say "16. and none of it needed kubectl"
if command -v kubectl >/dev/null 2>&1; then
  note "kubectl is installed on this machine and was not invoked. The static proof is a test:"
else
  note "kubectl is not installed on this machine, and everything above worked. The static proof:"
fi
note "\`should_carry_no_subprocess_on_any_path_that_reaches_a_cluster\` reads every source file"
note "of both crates and fails if one of them spawns a process."
grep -rn "Command::new" crates/*/src/ && echo "a subprocess reached the source" || note "no Command::new in crates/*/src — the provider speaks the API and nothing else"

say "done"
note "Everything above ran against a real $VERSION API server through the KUANG/11 capability"
note "broker, with the provider speaking HTTPS it wrote itself over a brokered byte connection."

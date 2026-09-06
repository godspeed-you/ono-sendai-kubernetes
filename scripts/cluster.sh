#!/usr/bin/env bash
# An ephemeral Kubernetes cluster, and the fixtures the live acceptance gates are driven against.
#
# Specification §59.3 ("CI SHOULD additionally run integration tests against disposable local
# Kubernetes clusters such as kind or an equivalent project-approved mechanism. These tests
# validate real API behavior not faithfully represented by fixtures") and §59.4 ("Local
# integration SHOULD cover the provider's declared upstream support window at release
# qualification time").
#
#   scripts/cluster.sh up   [--version vX.Y.Z] [--name <cluster>]
#   scripts/cluster.sh down [--name <cluster>]
#
# `up` prints the path of the kubeconfig it wrote on stdout, and nothing else; progress goes to
# stderr, so `ONO_K8S_KUBECONFIG=$(scripts/cluster.sh up)` is the whole of the setup.
#
# **Nothing here runs `kubectl`, and that is the point.** §62.13's Gate M is "core conformance
# works on a machine where `kubectl` is absent", and a harness that installed its own fixtures
# with `kubectl` would prove the gate on a machine that has it. So every object below is created
# by `curl` against the API server, with the client certificate out of kind's own kubeconfig —
# the same REST surface the provider itself speaks. `kind` is the cluster's own installer and
# `docker` is what it runs on; neither is a Kubernetes client.
#
# **The fixtures are the ones the gates need**, and each is here because a gate names it:
#
#   two namespaces                  §9.2, and a denial that cannot be an empty success: `ono-beta`
#                                   holds objects, so a restricted identity reading it has
#                                   something to have been denied
#   three CRDs invented here        Gate A (§62.1) and Gate B (§62.2): a namespaced structural
#                                   one with an OpenAPI schema, a cluster-scoped one, and one
#                                   whose schema preserves unknown fields (§12.5)
#   Deployment/Service and what     the relationship gates (§23, §24): a real control plane makes
#   the control plane derives       the ReplicaSet, the Pods and the EndpointSlices, so the edges
#                                   the provider reports were not written by this script
#   ConfigMap, Secret,              §15.2's Tier 1 set, so a live read crosses redaction (Gate I)
#   ServiceAccount                  and identity as well as workload
#   StorageClass, PV, bound PVC     §15.3, and a binding this script waits for rather than assumes
#   a ConfigMap held by a           Gate H (§62.8): deletion accepted with finalizers is
#   finalizer                       "terminating", never "deleted"
#   a ConfigMap named `lifetime`    Gate C (§62.3): the object the delete/recreate sequence runs
#                                   on
#   a restricted identity, in a     Gate E (§62.5): a `403` on `ono-beta` is a denial and never an
#   second kubeconfig context       empty result
#
# **Derived objects are waited for, not assumed.** A Pod that has not been scheduled has no node
# to be related to and no address to appear in an EndpointSlice, so `up` polls for each derived
# object with a bounded timeout and fails loudly rather than handing the tests a cluster that is
# still catching up.
#
# **A failed `up` leaves nothing running.** The trap deletes the cluster it created, so a
# half-built fixture set is never left behind for the next run to inherit.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
readonly REPO="$PWD"

# --- what a caller can choose -------------------------------------------------------------------

# The newest of the declared support window (§0.5, §5.1). `--version` names another end of it.
DEFAULT_VERSION="v1.37.0"
DEFAULT_NAME="ono-k8s"

# The two namespaces, and the objects a test names. Fixed rather than generated: the tests read
# them by name, and a name that changed per run would be a second thing to pass between the two.
readonly NS_ALPHA="ono-alpha"
readonly NS_BETA="ono-beta"

# The two kubeconfig contexts `up` writes. `ono-restricted` carries the bound ServiceAccount
# token; `ono-admin` carries kind's client certificate.
readonly CTX_ADMIN="ono-admin"
readonly CTX_RESTRICTED="ono-restricted"

# How long a derived object may take before the run is a failure rather than a wait.
readonly WAIT_SECONDS=180

# --- plumbing ------------------------------------------------------------------------------------

say() { printf '\033[1m==\033[0m %s\n' "$*" >&2; }
note() { printf '   %s\n' "$*" >&2; }
die() { printf '\033[31mcluster: %s\033[0m\n' "$*" >&2; exit 1; }

KIND=""
find_tools() {
  if command -v kind >/dev/null 2>&1; then
    KIND="$(command -v kind)"
  elif [[ -x "$HOME/.local/bin/kind" ]]; then
    KIND="$HOME/.local/bin/kind"
  else
    die "kind is not installed. See https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
  fi
  command -v docker >/dev/null 2>&1 || die "docker is not available, and kind runs its nodes on it"
  command -v curl >/dev/null 2>&1 || die "curl is not available, and the fixtures are installed over the API"
  command -v jq >/dev/null 2>&1 || die "jq is not available, and the fixture waits read JSON"
  command -v openssl >/dev/null 2>&1 || command -v base64 >/dev/null 2>&1 \
    || die "neither openssl nor base64 is available to decode the kubeconfig credentials"
}

usage() {
  cat >&2 <<'USAGE'
usage: scripts/cluster.sh up   [--version vX.Y.Z] [--name <cluster>]
       scripts/cluster.sh down [--name <cluster>]

up    creates a kind cluster, installs the fixtures over the Kubernetes API with no `kubectl`,
      waits for the objects the control plane derives, and prints the kubeconfig path on stdout.
down  deletes the cluster and the kubeconfig `up` wrote.
USAGE
  exit 2
}

# --- the API, spoken directly --------------------------------------------------------------------

# Set by `materialise`: where the decoded credentials live, and the server they authenticate to.
MATERIAL=""
SERVER=""

# One request, as the cluster administrator. `$1` is the method, `$2` the path; a body, when the
# method takes one, arrives on stdin.
api() {
  local method="$1" path="$2"
  curl --silent --show-error --fail-with-body \
    --cacert "$MATERIAL/ca.crt" --cert "$MATERIAL/client.crt" --key "$MATERIAL/client.key" \
    --header 'Content-Type: application/json' --header 'Accept: application/json' \
    --request "$method" --data-binary @- "$SERVER$path"
}

api_get() {
  curl --silent --show-error \
    --cacert "$MATERIAL/ca.crt" --cert "$MATERIAL/client.crt" --key "$MATERIAL/client.key" \
    --header 'Accept: application/json' "$SERVER$1"
}

# Creates one object from the JSON on stdin. An object that is already there is success: `up` is
# idempotent against a cluster a previous run left half-built.
create() {
  local path="$1" what="$2" body out reason
  body="$(cat)"
  if ! out="$(printf '%s' "$body" | api POST "$path" 2>&1)"; then
    reason="$(printf '%s' "$out" | jq -r '.reason // empty' 2>/dev/null || true)"
    if [[ "$reason" == "AlreadyExists" ]]; then
      note "$what: already there"
      return 0
    fi
    die "$what could not be created at $path: $out"
  fi
  note "$what"
}

# Polls until a jq filter is true of what a path answers, or fails loudly. The point of §59.3 is
# real API behaviour, and real API behaviour is asynchronous: the control plane produces the
# ReplicaSet, the Pods and the EndpointSlices some time after the Deployment is accepted.
wait_for() {
  local what="$1" path="$2" filter="$3" deadline last=""
  deadline=$(( SECONDS + WAIT_SECONDS ))
  while (( SECONDS < deadline )); do
    last="$(api_get "$path" 2>&1 || true)"
    if printf '%s' "$last" | jq -e "$filter" >/dev/null 2>&1; then
      note "$what: ready"
      return 0
    fi
    sleep 2
  done
  printf '%s\n' "$last" | head -c 2000 >&2
  die "timed out after ${WAIT_SECONDS}s waiting for $what"
}

# --- the credentials, out of kind's kubeconfig ---------------------------------------------------

decode_field() {
  local field="$1" file="$2" value
  value="$(grep -m1 -E "^[[:space:]]*${field}:" "$file" | sed -E 's/^[^:]*:[[:space:]]*//')"
  [[ -n "$value" ]] || die "kind's kubeconfig carries no \`$field\`"
  printf '%s' "$value"
}

# Writes kind's client certificate, its key and the cluster's certificate authority out as PEM
# files, so `curl` can present them. `kind get kubeconfig` is kind's own accessor for the cluster
# it created; nothing here is a Kubernetes client.
materialise() {
  local name="$1" raw="$2"
  "$KIND" get kubeconfig --name "$name" > "$raw"
  MATERIAL="$(mktemp -d "${TMPDIR:-/tmp}/ono-cluster-material.XXXXXXXX")"
  chmod 700 "$MATERIAL"
  SERVER="$(grep -m1 -E '^[[:space:]]*server:' "$raw" | sed -E 's/^[^:]*:[[:space:]]*//')"
  [[ -n "$SERVER" ]] || die "kind's kubeconfig names no server"
  decode_field 'certificate-authority-data' "$raw" | base64 -d > "$MATERIAL/ca.crt"
  decode_field 'client-certificate-data' "$raw" | base64 -d > "$MATERIAL/client.crt"
  decode_field 'client-key-data' "$raw" | base64 -d > "$MATERIAL/client.key"
  chmod 600 "$MATERIAL"/*
}

# --- the fixtures ---------------------------------------------------------------------------------

install_namespaces() {
  say "namespaces"
  local ns
  for ns in "$NS_ALPHA" "$NS_BETA"; do
    create "/api/v1/namespaces" "namespace $ns" <<JSON
{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"$ns","labels":{"ono.test/fixture":"true"}}}
JSON
  done
}

# Three kinds this provider was not built against, which is Gate A's whole question. The schemas
# are real OpenAPI v3, so §12.2's dynamic typed projection has something to type from, and the
# third preserves unknown fields so §12.5 has a record carrying what its schema does not describe.
install_crds() {
  say "custom resource definitions"
  create "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" "CRD widgets.ono.test (namespaced, structural)" <<'JSON'
{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition",
 "metadata":{"name":"widgets.ono.test"},
 "spec":{"group":"ono.test","scope":"Namespaced",
   "names":{"plural":"widgets","singular":"widget","kind":"Widget","listKind":"WidgetList","shortNames":["wdg"]},
   "versions":[{"name":"v1","served":true,"storage":true,
     "schema":{"openAPIV3Schema":{"type":"object","description":"A thing invented for the acceptance gates.",
       "properties":{
         "spec":{"type":"object","required":["size"],"properties":{
           "size":{"type":"integer","description":"How many units this widget holds."},
           "colour":{"type":"string","description":"What colour it is painted."},
           "retired":{"type":"boolean","description":"Whether it is still in service."}}},
         "status":{"type":"object","properties":{"phase":{"type":"string"}}}}}},
     "subresources":{"status":{}}}]}}
JSON
  create "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" "CRD constellations.ono.test (cluster-scoped)" <<'JSON'
{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition",
 "metadata":{"name":"constellations.ono.test"},
 "spec":{"group":"ono.test","scope":"Cluster",
   "names":{"plural":"constellations","singular":"constellation","kind":"Constellation","listKind":"ConstellationList"},
   "versions":[{"name":"v1","served":true,"storage":true,
     "schema":{"openAPIV3Schema":{"type":"object","description":"A cluster-scoped kind, so a place has no namespace slot.",
       "properties":{
         "spec":{"type":"object","properties":{
           "arms":{"type":"integer","description":"How many arms it has."},
           "brightest":{"type":"string","description":"The brightest star in it."}}}}}}}]}}
JSON
  create "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" "CRD sketches.ono.test (preserves unknown fields)" <<'JSON'
{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition",
 "metadata":{"name":"sketches.ono.test"},
 "spec":{"group":"ono.test","scope":"Namespaced",
   "names":{"plural":"sketches","singular":"sketch","kind":"Sketch","listKind":"SketchList"},
   "versions":[{"name":"v1","served":true,"storage":true,
     "schema":{"openAPIV3Schema":{"type":"object","description":"A kind whose schema describes less than its records carry.",
       "properties":{
         "spec":{"type":"object","x-kubernetes-preserve-unknown-fields":true,
           "properties":{"title":{"type":"string","description":"What the sketch is called."}}}}}}}]}}
JSON

  local crd
  for crd in widgets constellations sketches; do
    wait_for "CRD $crd.ono.test established" \
      "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/$crd.ono.test" \
      '[.status.conditions[]? | select(.type=="Established" and .status=="True")] | length > 0'
  done
}

install_custom_resources() {
  say "custom resources"
  create "/apis/ono.test/v1/namespaces/$NS_ALPHA/widgets" "Widget $NS_ALPHA/gauge" <<JSON
{"apiVersion":"ono.test/v1","kind":"Widget","metadata":{"name":"gauge","namespace":"$NS_ALPHA","labels":{"app":"checkout"}},
 "spec":{"size":3,"colour":"amber","retired":false}}
JSON
  # In the namespace the restricted identity may not read, so that a denial there has something
  # to have been denied (§21.4, Gate E).
  create "/apis/ono.test/v1/namespaces/$NS_BETA/widgets" "Widget $NS_BETA/beacon" <<JSON
{"apiVersion":"ono.test/v1","kind":"Widget","metadata":{"name":"beacon","namespace":"$NS_BETA"},
 "spec":{"size":9,"colour":"green"}}
JSON
  create "/apis/ono.test/v1/constellations" "Constellation orion (cluster-scoped)" <<'JSON'
{"apiVersion":"ono.test/v1","kind":"Constellation","metadata":{"name":"orion"},
 "spec":{"arms":4,"brightest":"rigel"}}
JSON
  # `pressure` and `medium` are described by no property of the schema. A provider that typed the
  # record from the schema alone would drop them; §12.5 says it must not.
  create "/apis/ono.test/v1/namespaces/$NS_ALPHA/sketches" "Sketch $NS_ALPHA/outline (undescribed fields)" <<JSON
{"apiVersion":"ono.test/v1","kind":"Sketch","metadata":{"name":"outline","namespace":"$NS_ALPHA"},
 "spec":{"title":"first pass","pressure":"heavy","medium":{"kind":"graphite","grade":"2B"}}}
JSON
}

install_workload() {
  say "workload, and what the control plane derives from it"
  create "/api/v1/namespaces/$NS_ALPHA/serviceaccounts" "ServiceAccount $NS_ALPHA/checkout-sa" <<JSON
{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"checkout-sa","namespace":"$NS_ALPHA"}}
JSON
  create "/api/v1/namespaces/$NS_ALPHA/configmaps" "ConfigMap $NS_ALPHA/settings" <<JSON
{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"settings","namespace":"$NS_ALPHA"},
 "data":{"currency":"EUR","retries":"3"}}
JSON
  create "/api/v1/namespaces/$NS_BETA/configmaps" "ConfigMap $NS_BETA/settings" <<JSON
{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"settings","namespace":"$NS_BETA"},
 "data":{"currency":"GBP"}}
JSON
  # Not a real credential, and it never leaves the ephemeral cluster. Its point is that a live
  # read of a Secret crosses the redaction boundary (§8.1, Gate I).
  create "/api/v1/namespaces/$NS_ALPHA/secrets" "Secret $NS_ALPHA/api-token" <<JSON
{"apiVersion":"v1","kind":"Secret","metadata":{"name":"api-token","namespace":"$NS_ALPHA"},
 "type":"Opaque","stringData":{"token":"not-a-real-credential"}}
JSON
  # Held by a finalizer nothing will ever remove, so a deletion of it stays observably pending
  # (§14.6, Gate H).
  create "/api/v1/namespaces/$NS_ALPHA/configmaps" "ConfigMap $NS_ALPHA/held (finalizer)" <<JSON
{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"held","namespace":"$NS_ALPHA",
  "finalizers":["ono.test/hold"]},
 "data":{"why":"a finalizer no controller will remove"}}
JSON
  # Gate C's object: the tests delete it and put one of the same name back.
  create "/api/v1/namespaces/$NS_ALPHA/configmaps" "ConfigMap $NS_ALPHA/lifetime" <<JSON
{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"lifetime","namespace":"$NS_ALPHA",
  "labels":{"ono.test/lifetime":"first"}},
 "data":{"generation":"first"}}
JSON

  create "/apis/apps/v1/namespaces/$NS_ALPHA/deployments" "Deployment $NS_ALPHA/checkout" <<JSON
{"apiVersion":"apps/v1","kind":"Deployment",
 "metadata":{"name":"checkout","namespace":"$NS_ALPHA","labels":{"app":"checkout"}},
 "spec":{"replicas":1,"selector":{"matchLabels":{"app":"checkout"}},
  "template":{"metadata":{"labels":{"app":"checkout"}},
   "spec":{"serviceAccountName":"checkout-sa","terminationGracePeriodSeconds":1,
    "containers":[{"name":"pause","image":"registry.k8s.io/pause:3.10","imagePullPolicy":"IfNotPresent",
      "ports":[{"name":"http","containerPort":8080}]}]}}}}
JSON
  create "/api/v1/namespaces/$NS_ALPHA/services" "Service $NS_ALPHA/checkout" <<JSON
{"apiVersion":"v1","kind":"Service","metadata":{"name":"checkout","namespace":"$NS_ALPHA"},
 "spec":{"selector":{"app":"checkout"},
  "ports":[{"name":"http","port":80,"targetPort":8080,"protocol":"TCP"}]}}
JSON

  wait_for "ReplicaSet of $NS_ALPHA/checkout" \
    "/apis/apps/v1/namespaces/$NS_ALPHA/replicasets?labelSelector=app%3Dcheckout" \
    '[.items[]? | select(.metadata.ownerReferences != null)] | length > 0'
  wait_for "a scheduled, addressed Pod of $NS_ALPHA/checkout" \
    "/api/v1/namespaces/$NS_ALPHA/pods?labelSelector=app%3Dcheckout" \
    '[.items[]? | select((.spec.nodeName // "") != "" and (.status.podIP // "") != "")] | length > 0'
  wait_for "an EndpointSlice of $NS_ALPHA/checkout naming a Pod" \
    "/apis/discovery.k8s.io/v1/namespaces/$NS_ALPHA/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3Dcheckout" \
    '[.items[]? | select([.endpoints[]? | select(.targetRef != null)] | length > 0)] | length > 0'
}

install_storage() {
  say "storage"
  create "/apis/storage.k8s.io/v1/storageclasses" "StorageClass ono-manual" <<'JSON'
{"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":{"name":"ono-manual"},
 "provisioner":"kubernetes.io/no-provisioner","volumeBindingMode":"Immediate","reclaimPolicy":"Retain"}
JSON
  create "/api/v1/persistentvolumes" "PersistentVolume ono-archive" <<'JSON'
{"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"ono-archive"},
 "spec":{"capacity":{"storage":"64Mi"},"accessModes":["ReadWriteOnce"],
  "persistentVolumeReclaimPolicy":"Retain","storageClassName":"ono-manual",
  "hostPath":{"path":"/tmp/ono-archive","type":"DirectoryOrCreate"}}}
JSON
  create "/api/v1/namespaces/$NS_ALPHA/persistentvolumeclaims" "PersistentVolumeClaim $NS_ALPHA/archive" <<JSON
{"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"archive","namespace":"$NS_ALPHA"},
 "spec":{"accessModes":["ReadWriteOnce"],"storageClassName":"ono-manual","volumeName":"ono-archive",
  "resources":{"requests":{"storage":"64Mi"}}}}
JSON
  wait_for "PersistentVolumeClaim $NS_ALPHA/archive bound" \
    "/api/v1/namespaces/$NS_ALPHA/persistentvolumeclaims/archive" \
    '.status.phase == "Bound"'
}

# The identity that proves a denial is a denial. `get`/`list` in one namespace and nothing at all
# in the other, so a read of `ono-beta` is a `403` over a namespace that demonstrably holds
# objects — §4 invariant 13's distinction between "not permitted" and "empty", with the
# alternative reading ruled out by the fixtures.
RESTRICTED_TOKEN=""
install_restricted_identity() {
  say "restricted identity"
  create "/api/v1/namespaces/$NS_ALPHA/serviceaccounts" "ServiceAccount $NS_ALPHA/reader" <<JSON
{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"reader","namespace":"$NS_ALPHA"}}
JSON
  create "/apis/rbac.authorization.k8s.io/v1/namespaces/$NS_ALPHA/roles" "Role $NS_ALPHA/reader" <<JSON
{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"$NS_ALPHA"},
 "rules":[
  {"apiGroups":[""],"resources":["configmaps","pods","services","serviceaccounts","persistentvolumeclaims"],"verbs":["get","list","watch"]},
  {"apiGroups":["apps"],"resources":["deployments","replicasets"],"verbs":["get","list","watch"]},
  {"apiGroups":["discovery.k8s.io"],"resources":["endpointslices"],"verbs":["get","list","watch"]},
  {"apiGroups":["ono.test"],"resources":["widgets","sketches"],"verbs":["get","list","watch"]}]}
JSON
  create "/apis/rbac.authorization.k8s.io/v1/namespaces/$NS_ALPHA/rolebindings" "RoleBinding $NS_ALPHA/reader" <<JSON
{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"reader","namespace":"$NS_ALPHA"},
 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},
 "subjects":[{"kind":"ServiceAccount","name":"reader","namespace":"$NS_ALPHA"}]}
JSON

  local answer
  answer="$(api POST "/api/v1/namespaces/$NS_ALPHA/serviceaccounts/reader/token" <<'JSON'
{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{"expirationSeconds":7200}}
JSON
)" || die "the API server refused to mint a token for $NS_ALPHA/reader"
  RESTRICTED_TOKEN="$(printf '%s' "$answer" | jq -r '.status.token // empty')"
  [[ -n "$RESTRICTED_TOKEN" ]] || die "the TokenRequest answered without a token"
  note "bound token for $NS_ALPHA/reader, valid for two hours"
}

# --- the kubeconfig the tests are handed ----------------------------------------------------------

# Written rather than patched. kind's own kubeconfig has one context; the tests need two, and
# assembling the file from the values already extracted is shorter than editing YAML in place —
# and it is the file `ono` reads, so its shape is part of what §7.1 is proven against.
write_kubeconfig() {
  local path="$1" cluster="$2" raw="$3" ca crt key
  ca="$(decode_field 'certificate-authority-data' "$raw")"
  crt="$(decode_field 'client-certificate-data' "$raw")"
  key="$(decode_field 'client-key-data' "$raw")"
  umask 077
  cat > "$path" <<YAML
# Written by scripts/cluster.sh for the ephemeral cluster \`$cluster\`. Two contexts:
#
#   $CTX_ADMIN        the cluster administrator, on kind's client certificate
#   $CTX_RESTRICTED   a ServiceAccount that may read $NS_ALPHA and nothing else
#
# Both default to the \`$NS_ALPHA\` namespace, so a query that names no namespace is answered in
# the context's own (specification section 7.5).
apiVersion: v1
kind: Config
clusters:
- name: $cluster
  cluster:
    server: $SERVER
    certificate-authority-data: $ca
users:
- name: $CTX_ADMIN
  user:
    client-certificate-data: $crt
    client-key-data: $key
- name: $CTX_RESTRICTED
  user:
    token: $RESTRICTED_TOKEN
contexts:
- name: $CTX_ADMIN
  context:
    cluster: $cluster
    user: $CTX_ADMIN
    namespace: $NS_ALPHA
- name: $CTX_RESTRICTED
  context:
    cluster: $cluster
    user: $CTX_RESTRICTED
    namespace: $NS_ALPHA
current-context: $CTX_ADMIN
YAML
  chmod 600 "$path"
}

# --- the two verbs ---------------------------------------------------------------------------------

cluster_exists() {
  "$KIND" get clusters 2>/dev/null | grep -qx "$1"
}

kubeconfig_path() {
  printf '%s/target/kind/%s.kubeconfig' "$REPO" "$1"
}

# Removes whatever this run made, and nothing it did not.
CREATED=""
SUCCEEDED=0
cleanup() {
  local status=$?
  [[ -n "$MATERIAL" ]] && rm -rf "$MATERIAL"
  if (( SUCCEEDED == 0 )) && [[ -n "$CREATED" ]]; then
    printf '\033[31mcluster: `up` failed; deleting the cluster it created\033[0m\n' >&2
    "$KIND" delete cluster --name "$CREATED" >&2 || true
    rm -f "$(kubeconfig_path "$CREATED")"
  fi
  exit "$status"
}

up() {
  local version="$DEFAULT_VERSION" name="$DEFAULT_NAME"
  while (( $# )); do
    case "$1" in
      --version) version="${2:-}"; [[ -n "$version" ]] || usage; shift 2 ;;
      --name) name="${2:-}"; [[ -n "$name" ]] || usage; shift 2 ;;
      *) usage ;;
    esac
  done

  find_tools
  trap cleanup EXIT

  # Idempotent: a cluster of this name from an earlier run is replaced rather than reused, because
  # a half-installed fixture set is indistinguishable from a complete one until a test fails on it.
  if cluster_exists "$name"; then
    say "an earlier cluster \`$name\` is running; replacing it"
    "$KIND" delete cluster --name "$name" >&2
  fi

  say "creating kind cluster \`$name\` on kindest/node:$version"
  CREATED="$name"
  "$KIND" create cluster --name "$name" --image "kindest/node:$version" --wait 180s >&2

  local raw kubeconfig
  mkdir -p "$REPO/target/kind"
  kubeconfig="$(kubeconfig_path "$name")"
  raw="$(mktemp "${TMPDIR:-/tmp}/ono-cluster-raw.XXXXXXXX")"
  materialise "$name" "$raw"
  say "API server at $SERVER"

  install_namespaces
  install_crds
  install_custom_resources
  install_workload
  install_storage
  install_restricted_identity

  write_kubeconfig "$kubeconfig" "kind-$name" "$raw"
  rm -f "$raw"

  SUCCEEDED=1
  say "cluster \`$name\` is up, fixtures installed, kubeconfig written"
  note "run the live suite with:"
  note "  ONO_K8S_KUBECONFIG=$kubeconfig cargo test -p ono-kubernetes-plugin --test live_cluster"
  printf '%s\n' "$kubeconfig"
}

down() {
  local name="$DEFAULT_NAME"
  while (( $# )); do
    case "$1" in
      --name) name="${2:-}"; [[ -n "$name" ]] || usage; shift 2 ;;
      *) usage ;;
    esac
  done
  find_tools
  if cluster_exists "$name"; then
    say "deleting kind cluster \`$name\`"
    "$KIND" delete cluster --name "$name" >&2
  else
    say "no kind cluster \`$name\` is running"
  fi
  rm -f "$(kubeconfig_path "$name")"
}

case "${1:-}" in
  up) shift; up "$@" ;;
  down) shift; down "$@" ;;
  *) usage ;;
esac

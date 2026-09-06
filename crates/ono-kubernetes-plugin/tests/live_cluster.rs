//! The acceptance gates, driven through the real `ono` binary against a real API server (§59.3).
//!
//! Everything else in this suite answers from a fixture or from a recorded socket, and §59.1
//! requires that: *"All mandatory provider conformance tests MUST run without production
//! credentials."* This file is the other half of §59.3 — *"CI SHOULD additionally run integration
//! tests against disposable local Kubernetes clusters such as kind or an equivalent
//! project-approved mechanism. These tests validate real API behavior not faithfully represented
//! by fixtures."*
//!
//! What a recorded document cannot answer, and these tests can:
//!
//! * a CRD is **established** by a real apiextensions controller before its records can be typed,
//!   and the OpenAPI document those records are typed from is one the cluster generated from a
//!   schema nobody wrote into this repository (Gates A and B, §62.1, §62.2);
//! * a Deployment becomes a ReplicaSet, the ReplicaSet becomes a Pod, the Pod is scheduled onto a
//!   Node and an EndpointSlice controller writes the Pod's address into a slice. Every edge this
//!   suite walks was asserted by a control plane rather than by a fixture author (§23, §24);
//! * a `403` comes from real RBAC evaluated on a real bound token, so "denied" is the API
//!   server's word and not a recorded string (Gate E, §62.5);
//! * a deletion held by a finalizer is left `terminating` by the garbage collector rather than by
//!   a document that says so (Gate H, §62.8);
//! * `metadata.uid` is minted by the API server, so a name reused after a deletion carries a
//!   different lifetime because the cluster made one (Gate C, §62.3).
//!
//! **The cluster is not this suite's to create.** `scripts/cluster.sh up` makes one with `kind`,
//! installs the fixtures over the Kubernetes API — with no `kubectl` anywhere, which is Gate M's
//! point (§62.13) — and prints the kubeconfig it wrote. `ONO_K8S_KUBECONFIG` names that file:
//!
//! ```text
//! ONO_K8S_KUBECONFIG=$(scripts/cluster.sh up --version v1.37.0) \
//!   cargo test -p ono-kubernetes-plugin --test live_cluster
//! ```
//!
//! Without it every test here **announces a skip and returns**, in core's vocabulary
//! (`ADR-0513 (core)`): `SKIPPED <test>: <category>: <detail>`. A test that returned silently
//! would be a pass nobody earned, and `docs/contracts/expected_test_skips.yaml` declares every
//! row below so `scripts/gate.sh` can check the register against the tree in both directions.
//!
//! **The harness spawns `curl` and never `kubectl`.** Two gates need an object *created* while
//! the tests run — Gate C's second lifetime, and the create the CRD watch must observe — and this
//! provider deliberately creates nothing it was not asked to change, so the create is the
//! harness's own work. It goes over the same REST API with the same client certificate the
//! kubeconfig carries. `curl` is an HTTP client; `kubectl` is a Kubernetes client, and the
//! difference is exactly what §62.13 is about.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed precondition in a test should abort the test loudly"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use serde_json::Value as Json;

/// The package this repository builds, as an operator installs it.
const PACKAGE: &str = "io.github.godspeed-you.kubernetes";
/// The package binary, built by `cargo test` before this file runs.
const PLUGIN: &str = env!("CARGO_BIN_EXE_ono-kubernetes");
/// The real manifest, byte for byte, because a fixture manifest proves something about a fixture.
const MANIFEST: &str = include_str!("../../../package/manifest.yaml");
/// The real target contributions.
const TARGETS: &str = include_str!("../../../package/contributions/targets.yaml");
/// The real schema contributions.
const SCHEMAS: &str = include_str!("../../../package/contributions/schemas.yaml");
/// The real command contributions.
const COMMANDS: &str = include_str!("../../../package/contributions/commands.yaml");

/// The namespace `scripts/cluster.sh` fills, and the one the restricted identity may read.
const ALPHA: &str = "ono-alpha";
/// The namespace the restricted identity may not read — and which holds objects, so that a
/// denial there cannot be mistaken for an absence (§4 invariant 13).
const BETA: &str = "ono-beta";
/// The kubeconfig context carrying the cluster administrator's client certificate.
const ADMIN: &str = "ono-admin";
/// The kubeconfig context carrying the bound ServiceAccount token of `ono-alpha/reader`.
const RESTRICTED: &str = "ono-restricted";
/// The API group of the three kinds `scripts/cluster.sh` invents.
const GROUP: &str = "ono.test";

// --- the skip marker -------------------------------------------------------------------------

/// Announces a skip the way `ADR-0513 (core)` writes one, so that one vocabulary covers the
/// observation and `docs/contracts/expected_test_skips.yaml`'s declaration of it.
///
/// The test's own name and its §38.4 category are passed as literals rather than derived, because
/// `scripts/gate.sh` reads these call sites to find every test that can skip and which category
/// it announces. A skip that only the running process can name is a skip no register can be
/// checked against. Every prerequisite here is a tool or a file the host has to supply, so the
/// category is always `external_tool_unavailable`.
fn announce_skip(test: &str, category: &str, detail: &str) {
    eprintln!("SKIPPED {test}: {category}: {detail}");
}

// --- what a live run needs -------------------------------------------------------------------

/// The three things a live run needs, resolved once: the shell, the cluster and an HTTP client.
struct Live {
    /// The `ono` binary, built from core.
    binary: PathBuf,
    /// The kubeconfig `scripts/cluster.sh up` wrote.
    kubeconfig: PathBuf,
    /// Its text, which is also where the client certificate for [`Live::create`] comes from.
    document: String,
}

impl Live {
    /// Resolves the preconditions, or names the first one that is missing.
    fn open() -> Result<Self, String> {
        let binary = ono()?;
        let named = std::env::var_os("ONO_K8S_KUBECONFIG").ok_or_else(|| {
            "`ONO_K8S_KUBECONFIG` is not set. Create an ephemeral cluster and its fixtures with \
             `scripts/cluster.sh up`, which prints the kubeconfig path it wrote, and set the \
             variable to it."
                .to_owned()
        })?;
        let kubeconfig = PathBuf::from(named);
        if !kubeconfig.is_file() {
            return Err(format!(
                "`ONO_K8S_KUBECONFIG` names `{}`, which is not a file. `scripts/cluster.sh up` \
                 writes it and `scripts/cluster.sh down` removes it.",
                kubeconfig.display()
            ));
        }
        if which("curl").is_none() {
            return Err(
                "`curl` is not on `PATH`, and two of these tests create an object over the \
                 Kubernetes API while they run. Install curl."
                    .to_owned(),
            );
        }
        let document = std::fs::read_to_string(&kubeconfig).map_err(|error| {
            format!(
                "the kubeconfig at `{}` did not read: {error}",
                kubeconfig.display()
            )
        })?;
        Ok(Self {
            binary,
            kubeconfig,
            document,
        })
    }

    /// One value out of the kubeconfig, by the key that carries it.
    fn field(&self, key: &str) -> String {
        self.document
            .lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{key}: ")))
            .unwrap_or_else(|| panic!("the kubeconfig carries no `{key}`"))
            .trim()
            .to_owned()
    }

    /// Creates one object over the API server's REST interface, and answers with its `uid`.
    ///
    /// The harness's own work, not the provider's: this package refuses to create an object it
    /// was not asked to change (§21.3 of the generic provider contract), so a gate that needs a
    /// *second* object of a name has to make one some other way. It uses the same endpoint, the
    /// same trust anchor and the same client certificate the kubeconfig names.
    fn create(&self, path: &str, body: &str) -> String {
        let scratch = Scratch::new("credential");
        let write = |name: &str, key: &str| -> PathBuf {
            let at = scratch.path().join(name);
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(self.field(key))
                .unwrap_or_else(|error| panic!("`{key}` is not base64: {error}"));
            let mut file = std::fs::File::create(&at).expect("a temporary credential file");
            file.write_all(&bytes).expect("the credential is written");
            at
        };
        let ca = write("ca.crt", "certificate-authority-data");
        let certificate = write("client.crt", "client-certificate-data");
        let key = write("client.key", "client-key-data");
        let output = Command::new("curl")
            .args(["--silent", "--show-error", "--fail-with-body"])
            .arg("--cacert")
            .arg(&ca)
            .arg("--cert")
            .arg(&certificate)
            .arg("--key")
            .arg(&key)
            .args(["--header", "Content-Type: application/json"])
            .args(["--request", "POST"])
            .args(["--data-binary", body])
            .arg(format!("{}{path}", self.field("server")))
            .output()
            .expect("curl runs");
        let answered = String::from_utf8_lossy(&output.stdout).into_owned();
        let document: Json = serde_json::from_str(&answered)
            .unwrap_or_else(|error| panic!("the API server answered `{answered}`: {error}"));
        document["metadata"]["uid"]
            .as_str()
            .unwrap_or_else(|| panic!("the API server did not create the object: {document}"))
            .to_owned()
    }
}

/// The `ono` binary, or the sentence a skip should carry.
///
/// `ono` is built from core, which this repository pins as a git dependency rather than checks
/// out, so a test that built a second workspace to run would make `cargo test` here depend on a
/// checkout nobody promised is present.
fn ono() -> Result<PathBuf, String> {
    if let Some(named) = std::env::var_os("ONO_BINARY") {
        let path = PathBuf::from(named);
        if path.is_file() {
            return Ok(path);
        }
        panic!(
            "`ONO_BINARY` names `{}`, which is not a file",
            path.display()
        );
    }
    let sibling = workspace()
        .parent()
        .map(|parent| parent.join("ono-sendai/target/debug/ono"));
    match sibling {
        Some(path) if path.is_file() => Ok(path),
        _ => Err(
            "no `ono` binary. `ono` is built from the core repository, which this one pins as a \
             git dependency rather than checks out. Set `ONO_BINARY`, or put a built core \
             checkout beside this one."
                .to_owned(),
        ),
    }
}

/// This repository's root.
fn workspace() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

/// Where an executable of this name sits on `PATH`, if anywhere.
///
/// Written here rather than shelled out to, because [`should_answer_a_live_read_on_a_machine_with_no_kubectl`]
/// asks the question `which` would have answered and a helper that needed `which` to prove
/// `kubectl` is absent would have swapped one external tool for another.
fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

// --- the plugin home -----------------------------------------------------------------------------

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    /// Makes one, named for the test that owns it.
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ono-kubernetes-live-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&path).expect("the test may write a temporary directory");
        Self(path)
    }

    /// Where it is.
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Lays this repository's package out the way an operator installs one, with the cluster's
/// kubeconfig where an operator keeps theirs.
///
/// The documents are the real ones. The kubeconfig is copied into the scratch home rather than
/// read where it lies, because §7.1 is about the file an operator has and the grant below is
/// about the directory it is in — and a test that pointed the package at a path under `target/`
/// would be proving something about `target/`.
fn plugin_home(live: &Live, name: &str) -> Scratch {
    let scratch = Scratch::new(name);
    let package = scratch.path().join("plugins").join(PACKAGE);
    std::fs::create_dir_all(package.join("runtime")).expect("the runtime directory");
    std::fs::create_dir_all(package.join("contributions")).expect("the contributions directory");
    std::fs::write(package.join("manifest.yaml"), MANIFEST).expect("the manifest");
    std::fs::write(package.join("contributions/targets.yaml"), TARGETS).expect("the targets");
    std::fs::write(package.join("contributions/schemas.yaml"), SCHEMAS).expect("the schemas");
    std::fs::write(package.join("contributions/commands.yaml"), COMMANDS).expect("the commands");
    std::fs::copy(PLUGIN, package.join("runtime/ono-kubernetes")).expect("the package binary");
    for directory in ["home/.kube", "state", "config/ono"] {
        std::fs::create_dir_all(scratch.path().join(directory)).expect("the scratch directories");
    }
    std::fs::copy(&live.kubeconfig, kubeconfig_in(&scratch)).expect("the kubeconfig");
    scratch
}

/// Where the package will read the kubeconfig from.
fn kubeconfig_in(home: &Scratch) -> PathBuf {
    home.path().join("home/.kube/config")
}

/// What one `ono -c` run printed.
struct Run {
    /// Everything on stdout.
    stdout: String,
    /// Everything on stderr, which is where a refusal goes.
    stderr: String,
}

impl Run {
    /// The last JSON document on stdout, for a script whose earlier statements printed prose.
    fn last_json(&self) -> Json {
        let line = self
            .stdout
            .lines()
            .rev()
            .find(|line| line.starts_with('[') || line.starts_with('{'))
            .unwrap_or_else(|| panic!("a `to json` document on stdout, got {self:?}"));
        serde_json::from_str(line).unwrap_or_else(|error| panic!("{error}: {line}"))
    }

    /// The records the last statement answered with.
    fn rows(&self) -> Vec<Json> {
        match self.last_json() {
            Json::Array(rows) => rows,
            other => panic!("a sequence of records, got {other}"),
        }
    }

    /// Exactly one record, for a query that named one object.
    fn only(&self) -> Json {
        let rows = self.rows();
        assert_eq!(rows.len(), 1, "one record, got {self:?}");
        rows.into_iter().next().expect("the one record")
    }

    /// Everything the run said, on either stream.
    fn said(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

impl std::fmt::Debug for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout, self.stderr
        )
    }
}

/// Runs one script under `ono`, with the scratch home as the whole of its world.
///
/// The script is prefixed with the two decisions an operator takes before any of this is
/// reachable, and both are the real mechanism rather than a test hook:
///
/// * the **scope of `filesystem.read`**. The manifest declares `~/.kube/config` and
///   `~/.kube/*.yaml`, and the supervisor matches a granted path as a glob against the path the
///   package actually asks for — so an operator whose kubeconfig is anywhere else widens the
///   grant deliberately with `grant capability --scope`, which is what §27.3 of the generic
///   provider contract asks for and what happens here;
/// * the **grants the package loads with**. `relation.write` is never granted by default (§31.19,
///   §35.5), so the relationship tests below name it and the reads do not need it.
fn shell(live: &Live, home: &Scratch, script: &str) -> Run {
    let root = home.path();
    let full = format!(
        "grant capability filesystem.read --plugin {PACKAGE} --scope 'paths={}/.kube/**' | count; \
         load plugin {PACKAGE} --grant network.connect --grant clock.read --grant relation.write; \
         {script}",
        root.join("home").display()
    );
    let output = Command::new(&live.binary)
        .args(["-c", &full])
        .env("ONO_PLUGIN_PATH", root.join("plugins"))
        .env("HOME", root.join("home"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("ONO_CONFIG_DIR", root.join("config/ono"))
        .output()
        .expect("the shell runs");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// The words that name the administrator's context and the file it lives in.
fn as_admin(home: &Scratch) -> String {
    format!(
        "--context {ADMIN} --kubeconfig {}",
        kubeconfig_in(home).display()
    )
}

/// The same, for the identity that may read one namespace only.
fn as_reader(home: &Scratch) -> String {
    format!(
        "--context {RESTRICTED} --kubeconfig {}",
        kubeconfig_in(home).display()
    )
}

/// The first edge of a given relationship word, or a panic naming what was there instead.
fn edge<'a>(rows: &'a [Json], relation: &str) -> &'a Json {
    rows.iter()
        .find(|row| row["relation"].as_str() == Some(relation))
        .unwrap_or_else(|| {
            let words: Vec<&str> = rows
                .iter()
                .filter_map(|row| row["relation"].as_str())
                .collect();
            panic!("an edge `{relation}`, got {words:?}")
        })
}

// --- the tests -----------------------------------------------------------------------------------

#[test]
fn should_reach_a_cluster_a_kubeconfig_context_names_and_report_the_version_it_serves() {
    // §7.1, §10.2, §11.1 and Gate N (§62.14). The whole chain, live: a kubeconfig read under the
    // host's `filesystem.read`, TLS verified against the authority the file pins, a client
    // certificate presented, and discovery answered by a real API server. `server_version` is
    // asserted against `ONO_K8S_EXPECT_VERSION` when CI names one, which is how a matrix leg
    // proves it ran against the end of the support window it claims (§5.1, §5.5).
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_reach_a_cluster_a_kubeconfig_context_names_and_report_the_version_it_serves",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "cluster");
    let run = shell(
        &live,
        &home,
        &format!("get k8s-cluster {} | to json", as_admin(&home)),
    );
    let cluster = run.only();
    assert_eq!(
        cluster["reachable"].as_bool(),
        Some(true),
        "the cluster answered, got {run:?}"
    );
    assert_eq!(
        cluster["tls"].as_str(),
        Some("verified"),
        "the session verified the certificate the kubeconfig pinned (§8.4), got {cluster}"
    );
    let version = cluster["server_version"]
        .as_str()
        .unwrap_or_else(|| panic!("a server version, got {cluster}"));
    assert!(
        version.starts_with("v1."),
        "a Kubernetes version, got {version}"
    );
    if let Ok(expected) = std::env::var("ONO_K8S_EXPECT_VERSION") {
        assert_eq!(
            version, expected,
            "the matrix leg claims {expected}; the cluster serves {version}"
        );
    }
    assert!(
        cluster["effective_groups"]
            .as_array()
            .is_some_and(|groups| !groups.is_empty()),
        "the effective identity is the one the credential resolved to (§8.6), got {cluster}"
    );
}

#[test]
fn should_list_a_built_in_kind_and_read_one_object_at_its_own_endpoint() {
    // K0/K1 against real behaviour: a collection listed, and then one object read at its own REST
    // endpoint rather than filtered out of the collection (§17.1, ADR-0012). The two namespaces
    // `scripts/cluster.sh` made are among the ones the cluster serves, alongside the ones kind
    // made, so nothing here is reading its own fixture back.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_list_a_built_in_kind_and_read_one_object_at_its_own_endpoint",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "builtin");
    let listed = shell(
        &live,
        &home,
        &format!("get k8s-namespace {} | to json", as_admin(&home)),
    );
    let names: Vec<String> = listed
        .rows()
        .iter()
        .filter_map(|row| row["name"].as_str().map(str::to_owned))
        .collect();
    for expected in [ALPHA, BETA, "kube-system"] {
        assert!(
            names.iter().any(|name| name == expected),
            "the cluster serves the namespace `{expected}`, got {names:?}"
        );
    }

    let one = shell(
        &live,
        &home,
        &format!(
            "get k8s-configmap {} --namespace {ALPHA} --name settings | to json",
            as_admin(&home)
        ),
    );
    let settings = one.only();
    assert_eq!(settings["name"].as_str(), Some("settings"));
    assert_eq!(settings["namespace"].as_str(), Some(ALPHA));
    assert!(
        settings["uid"].as_str().is_some_and(|uid| uid.len() > 8),
        "the API server minted a uid for it (§14.2), got {settings}"
    );
}

#[test]
fn should_type_a_custom_kind_the_cluster_learned_after_this_package_was_built() {
    // Gate A (§62.1) and Gate B (§62.2), against a cluster rather than a recording. Three kinds
    // that exist nowhere in this repository's code: a namespaced structural one, a cluster-scoped
    // one, and one whose schema preserves unknown fields. Nothing was recompiled between the CRD
    // being installed and these records being typed — the schema came from the cluster's own
    // OpenAPI document (§12.2), which is what `schema_source` names.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_type_a_custom_kind_the_cluster_learned_after_this_package_was_built",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "crd");

    let widget = shell(
        &live,
        &home,
        &format!(
            "get k8s-resource {} --kind Widget --group {GROUP} --namespace {ALPHA} --name gauge \
             | to json",
            as_admin(&home)
        ),
    )
    .only();
    assert_eq!(widget["kind"].as_str(), Some("Widget"));
    assert_eq!(widget["api_version"].as_str(), Some("ono.test/v1"));
    assert_eq!(
        widget["schema_source"].as_str(),
        Some("openapi-v3"),
        "the type came from the cluster's own schema document, got {widget}"
    );
    assert_eq!(
        widget["precision"].as_str(),
        Some("structural"),
        "a structural schema types the record completely (§12.3), got {widget}"
    );
    assert_eq!(
        widget["spec"]["size"].as_i64(),
        Some(3),
        "and `size` is an integer rather than the string a raw-JSON collapse would leave (§62.2), \
         got {widget}"
    );
    assert_eq!(widget["spec"]["colour"].as_str(), Some("amber"));

    let constellation = shell(
        &live,
        &home,
        &format!(
            "get k8s-resource {} --kind Constellation --group {GROUP} --name orion | to json",
            as_admin(&home)
        ),
    )
    .only();
    assert_eq!(
        constellation["scope"].as_str(),
        Some("cluster"),
        "discovery said this kind is cluster-scoped, not a compile-time table (§9.5), got \
         {constellation}"
    );
    assert!(
        constellation["namespace"].is_null(),
        "a cluster-scoped object has no namespace slot to fill (ADR-0008), got {constellation}"
    );
    assert_eq!(constellation["spec"]["arms"].as_i64(), Some(4));

    let sketch = shell(
        &live,
        &home,
        &format!(
            "get k8s-resource {} --kind Sketch --group {GROUP} --namespace {ALPHA} --name outline \
             | to json",
            as_admin(&home)
        ),
    )
    .only();
    assert_eq!(
        sketch["precision"].as_str(),
        Some("unknown"),
        "a schema that preserves unknown fields describes this record incompletely, and the \
         record says so rather than pretending otherwise (§12.3, §12.5), got {sketch}"
    );
    assert_eq!(
        sketch["spec"]["pressure"].as_str(),
        Some("heavy"),
        "a field the schema does not describe is preserved rather than dropped (§12.5), got \
         {sketch}"
    );
    let untyped: Vec<&str> = sketch["untyped"]
        .as_array()
        .unwrap_or_else(|| panic!("a list of untyped pointers, got {sketch}"))
        .iter()
        .filter_map(Json::as_str)
        .collect();
    assert!(
        untyped.contains(&"/spec/pressure") && untyped.contains(&"/spec/medium"),
        "and each undescribed field is named as one (§12.5), got {untyped:?}"
    );
}

#[test]
fn should_enter_a_custom_kind_the_cluster_learned_after_this_package_was_built() {
    // **Gate A's fifth verb**, and the last of the five to be proven. §62.1 asks that a CRD
    // invented after Ono is built can be "installed, discovered, queried, entered and watched
    // without recompiling Ono". The other four are proven above and beside; nothing entered one,
    // and the coverage map recorded it as very likely a missing test rather than a missing
    // capability — which is exactly why it had to be written instead of assumed.
    //
    // What makes it work is `ADR-0584 (core)`: every schema a package declares is a kind of
    // place, keyed on the schema id. `k8s-resource` declares one and identifies by `uid`, so a
    // Widget is a place for the same reason a Pod is, and the shell needed no word about
    // Kubernetes to make it one.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_enter_a_custom_kind_the_cluster_learned_after_this_package_was_built",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "enter-crd");

    let run = shell(
        &live,
        &home,
        &format!(
            "get k8s-resource {} --kind Widget --group {GROUP} --namespace {ALPHA} --name gauge \
             | enter; look | to json",
            as_admin(&home)
        ),
    );
    let here = run.only();
    let place = &here["place"];

    assert_eq!(
        place["object_type"].as_str(),
        Some("io.github.godspeed-you.kubernetes.resource/1"),
        "the kind of place is the schema the package declared for a discovered kind, got {place}"
    );
    let uid = place["identity"]["uid"]
        .as_str()
        .unwrap_or_else(|| panic!("the place is identified by uid, got {place}"));
    assert!(
        !uid.is_empty(),
        "and the uid is the cluster's, not a name standing in for one: {place}"
    );
    assert_eq!(
        place["identity_tier"].as_str(),
        Some("lifetime"),
        "§35.4: a place is bound to one resource lifetime, for a Widget exactly as for a Pod, \
         got {place}"
    );

    assert_eq!(
        place["canonical_ref"]["uid"].as_str(),
        Some(uid),
        "and an action can revalidate through it (§33.2), got {place}"
    );
    assert!(
        place["tombstone"].is_null(),
        "a Widget the cluster is still serving is not reported as gone, got {place}"
    );
}

#[test]
fn should_keep_two_lifetimes_of_one_name_apart_across_a_delete_and_a_recreate() {
    // Gate C (§62.3), driven end to end on a live cluster: read the object, delete it through the
    // provider's own `remove k8s-resource`, put one of the same name back, read it again. The two
    // `metadata.uid` values were minted by the API server and they differ, which is §4 invariants
    // 4–5: a name is not a lifetime.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_keep_two_lifetimes_of_one_name_apart_across_a_delete_and_a_recreate",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "lifetime");
    let read = format!(
        "get k8s-configmap {} --namespace {ALPHA} --name lifetime | to json",
        as_admin(&home)
    );

    let first = shell(&live, &home, &read).only();
    let before = first["uid"]
        .as_str()
        .unwrap_or_else(|| panic!("a uid, got {first}"))
        .to_owned();

    let removed = shell(
        &live,
        &home,
        &format!(
            "remove k8s-resource {} --kind ConfigMap --namespace {ALPHA} --name lifetime \
             --dry_run false | to json",
            as_admin(&home)
        ),
    )
    .only();
    assert_eq!(
        removed["dry_run"].as_bool(),
        Some(false),
        "the deletion was written rather than predicted, got {removed}"
    );
    assert_eq!(
        removed["preconditions"]["uid"].as_str(),
        Some(before.as_str()),
        "and it was aimed at the lifetime that was read (§56.3), got {removed}"
    );
    assert_eq!(
        removed["verdict"].as_str(),
        Some("confirmed"),
        "the follow-up read confirmed the lifetime ended (§46), got {removed}"
    );

    let after = live.create(
        &format!("/api/v1/namespaces/{ALPHA}/configmaps"),
        &format!(
            r#"{{"apiVersion":"v1","kind":"ConfigMap","metadata":{{"name":"lifetime","namespace":"{ALPHA}","labels":{{"ono.test/lifetime":"second"}}}},"data":{{"generation":"second"}}}}"#
        ),
    );
    assert_ne!(
        before, after,
        "the API server minted a second lifetime for the reused name"
    );

    let second = shell(&live, &home, &read).only();
    assert_eq!(
        second["uid"].as_str(),
        Some(after.as_str()),
        "and the provider reads the new lifetime rather than the name it remembers, got {second}"
    );
    assert_ne!(
        second["uid"].as_str(),
        Some(before.as_str()),
        "which is the discontinuity Gate C asks for"
    );
}

#[test]
fn should_report_a_denied_namespace_as_a_denial_rather_than_an_empty_result() {
    // Gate E (§62.5) and §4 invariant 13, on real RBAC: `ono-alpha/reader` holds a Role granting
    // `get`/`list` in one namespace, and the token in the `ono-restricted` context is bound to
    // it. `ono-beta` demonstrably holds ConfigMaps — the administrator reads them in the same
    // test — so an empty answer there would be a false one, and the run ends with the denial
    // named instead.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_report_a_denied_namespace_as_a_denial_rather_than_an_empty_result",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "denial");

    let visible = shell(
        &live,
        &home,
        &format!(
            "get k8s-configmap {} --namespace {BETA} | to json",
            as_admin(&home)
        ),
    );
    assert!(
        !visible.rows().is_empty(),
        "`{BETA}` holds objects, so an empty answer from the restricted identity would be a \
         false one: {visible:?}"
    );

    let allowed = shell(
        &live,
        &home,
        &format!(
            "get k8s-configmap {} --namespace {ALPHA} | to json",
            as_reader(&home)
        ),
    );
    assert!(
        !allowed.rows().is_empty(),
        "the restricted identity reads the namespace its Role names, got {allowed:?}"
    );

    let denied = shell(
        &live,
        &home,
        &format!(
            "get k8s-configmap {} --namespace {BETA} | to json",
            as_reader(&home)
        ),
    );
    let said = denied.said();
    assert!(
        said.contains("denied"),
        "the refusal names the denial rather than completing empty, got {denied:?}"
    );
    assert!(
        said.contains(BETA),
        "and it names the scope that was denied, got {denied:?}"
    );
    assert!(
        !denied.stdout.contains("[]"),
        "an empty sequence is never how a denial is rendered (§21.4, ADR-0025), got {denied:?}"
    );
}

#[test]
fn should_report_a_deletion_held_by_a_finalizer_as_terminating_rather_than_deleted() {
    // Gate H (§62.8) and §14.6. The ConfigMap `held` carries `ono.test/hold`, and no controller
    // in this cluster will ever remove it — so the API server accepts the deletion, sets
    // `deletionTimestamp`, and the object stays. The wrong answer is "deleted"; the right one
    // names the finalizer that has to go first, and a read afterwards still finds the object.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_report_a_deletion_held_by_a_finalizer_as_terminating_rather_than_deleted",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "finalizer");
    let removed = shell(
        &live,
        &home,
        &format!(
            "remove k8s-resource {} --kind ConfigMap --namespace {ALPHA} --name held \
             --dry_run false | to json",
            as_admin(&home)
        ),
    )
    .only();
    assert_eq!(removed["dry_run"].as_bool(), Some(false));
    let state = removed["deletion_state"]
        .as_str()
        .unwrap_or_else(|| panic!("a deletion state, got {removed}"));
    assert!(
        state.contains("terminating"),
        "an accepted deletion held by a finalizer is terminating, got `{state}`"
    );
    assert!(
        !state.contains("absent"),
        "and never absent while the object is still served, got `{state}`"
    );
    assert!(
        removed["finalizers"]
            .as_array()
            .is_some_and(|held| held.iter().any(|one| one == "ono.test/hold")),
        "the finalizer that holds it is named, got {removed}"
    );

    let still_there = shell(
        &live,
        &home,
        &format!(
            "get k8s-configmap {} --namespace {ALPHA} --name held | to json",
            as_admin(&home)
        ),
    )
    .only();
    assert_eq!(
        still_there["terminating"].as_bool(),
        Some(true),
        "the object is still served, and it says it is going, got {still_there}"
    );
}

#[test]
fn should_walk_a_deployment_to_the_node_over_objects_a_control_plane_produced() {
    // §23, §24 and Gate D's evidence classes, over a graph nobody wrote down: the ReplicaSet, the
    // Pod and the scheduling decision below were all made by controllers after
    // `scripts/cluster.sh` posted one Deployment. Each hop is asked for by name, so the walk is
    // four separate reads of what the cluster actually says rather than one derivation.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_walk_a_deployment_to_the_node_over_objects_a_control_plane_produced",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "workload");
    let relations = |kind: &str, group: &str, name: &str| -> Vec<Json> {
        let group = if group.is_empty() {
            String::new()
        } else {
            format!("--group {group} ")
        };
        shell(
            &live,
            &home,
            &format!(
                "get k8s-relation {} --kind {kind} {group}--namespace {ALPHA} --name {name} \
                 | to json",
                as_admin(&home)
            ),
        )
        .rows()
    };

    let controls = edge(&relations("Deployment", "apps", "checkout"), "controls").clone();
    assert_eq!(controls["target_kind"].as_str(), Some("ReplicaSet"));
    assert_eq!(
        controls["evidence_class"].as_str(),
        Some("owner-reference"),
        "the edge is an owner reference and says so (§23.1), got {controls}"
    );
    assert_eq!(
        controls["target_resolved"].as_bool(),
        Some(true),
        "and the far end was read rather than assumed, got {controls}"
    );
    let replicaset = controls["target_name"]
        .as_str()
        .expect("the ReplicaSet's name")
        .to_owned();

    let owns_pod = edge(&relations("ReplicaSet", "apps", &replicaset), "owns").clone();
    assert_eq!(owns_pod["target_kind"].as_str(), Some("Pod"));
    assert_eq!(
        owns_pod["evidence_class"].as_str(),
        Some("owner-reference"),
        "got {owns_pod}"
    );
    let pod = owns_pod["target_name"]
        .as_str()
        .expect("the Pod's name")
        .to_owned();

    let pod_edges = relations("Pod", "", &pod);
    let scheduled = edge(&pod_edges, "scheduled-on");
    assert_eq!(scheduled["target_kind"].as_str(), Some("Node"));
    assert_eq!(
        scheduled["evidence_class"].as_str(),
        Some("native-field"),
        "the scheduler wrote `spec.nodeName`, and that field is the evidence (§23.1), got \
         {scheduled}"
    );
    assert_eq!(
        scheduled["evidence_path"].as_str(),
        Some("/spec/nodeName"),
        "named as the field it is, got {scheduled}"
    );
    let node = scheduled["target_name"].as_str().expect("the Node's name");

    let nodes = shell(
        &live,
        &home,
        &format!("get k8s-node {} --name {node} | to json", as_admin(&home)),
    )
    .only();
    assert_eq!(
        nodes["name"].as_str(),
        Some(node),
        "and the far end of the last hop is an object this provider can read, got {nodes}"
    );
    assert_eq!(
        edge(&pod_edges, "controlled-by")["target_name"].as_str(),
        Some(replicaset.as_str()),
        "the walk is reversible: the Pod names the ReplicaSet the ReplicaSet named"
    );
}

#[test]
fn should_reach_the_pod_behind_a_service_through_the_endpointslice_the_cluster_wrote() {
    // §24 and Gate D again, on the other half of the graph and with three different evidence
    // classes in one answer: a Service *selects* Pods by evaluating a selector, it is
    // *represented-by* an EndpointSlice found through a well-known label, and the slice is an
    // *endpoint-for* a Pod because `targetRef` says so. §23 requires those three to stay
    // distinguishable, and a live EndpointSlice controller is what makes the second and third
    // exist at all.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_reach_the_pod_behind_a_service_through_the_endpointslice_the_cluster_wrote",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "service");
    let service = shell(
        &live,
        &home,
        &format!(
            "get k8s-relation {} --kind Service --namespace {ALPHA} --name checkout | to json",
            as_admin(&home)
        ),
    )
    .rows();

    let selects = edge(&service, "selects");
    assert_eq!(selects["target_kind"].as_str(), Some("Pod"));
    assert_eq!(
        selects["evidence_class"].as_str(),
        Some("selector"),
        "a selector match is a selector match and never an owner reference (§23.2), got {selects}"
    );
    assert_eq!(
        selects["asserted"].as_bool(),
        Some(false),
        "the cluster asserted no such edge; the provider evaluated it (§23.4), got {selects}"
    );

    let represented = edge(&service, "represented-by");
    assert_eq!(represented["target_kind"].as_str(), Some("EndpointSlice"));
    assert_eq!(
        represented["evidence_class"].as_str(),
        Some("convention"),
        "the label `kubernetes.io/service-name` is a convention, not a native field (§23.3), got \
         {represented}"
    );
    let slice = represented["target_name"]
        .as_str()
        .expect("the slice's name")
        .to_owned();

    let endpoints = shell(
        &live,
        &home,
        &format!(
            "get k8s-relation {} --kind EndpointSlice --group discovery.k8s.io --namespace {ALPHA} \
             --name {slice} | to json",
            as_admin(&home)
        ),
    )
    .rows();
    let endpoint_for = edge(&endpoints, "endpoint-for");
    assert_eq!(endpoint_for["target_kind"].as_str(), Some("Pod"));
    assert_eq!(
        endpoint_for["evidence_class"].as_str(),
        Some("native-field"),
        "`targetRef` is a field the endpoint controller wrote, got {endpoint_for}"
    );
    assert_eq!(
        endpoint_for["target_name"].as_str(),
        selects["target_name"].as_str(),
        "and both routes arrive at the same Pod, got {endpoint_for} against {selects}"
    );
}

#[test]
fn should_observe_a_real_create_on_a_watch_of_a_kind_invented_for_the_test() {
    // Gate A's "watched", and §19.1's list-then-watch as one sequence. The watch is bounded with
    // `max_changes` at one more than the collection holds, so the run ends after the *create*
    // that happens while it is open — an object this test makes over the API a few seconds after
    // the watch is established. What comes back is `added` with the uid the API server minted,
    // continuous and in sync: a change nobody recorded in advance.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_observe_a_real_create_on_a_watch_of_a_kind_invented_for_the_test",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    let home = plugin_home(&live, "watch");
    let held = shell(
        &live,
        &home,
        &format!(
            "get k8s-resource {} --kind Widget --group {GROUP} --namespace {ALPHA} | to json",
            as_admin(&home)
        ),
    )
    .rows()
    .len();

    let name = format!("arrival-{}", std::process::id());
    let created = std::thread::scope(|scope| {
        let arrival = scope.spawn(|| {
            // Long enough for the shell to load the package, resolve the kubeconfig, discover the
            // group and finish the initial list. A create that landed before that would be part
            // of the listing rather than a change observed on the stream, and the assertion
            // below would say so rather than passing quietly.
            std::thread::sleep(std::time::Duration::from_secs(10));
            live.create(
                &format!("/apis/{GROUP}/v1/namespaces/{ALPHA}/widgets"),
                &format!(
                    r#"{{"apiVersion":"ono.test/v1","kind":"Widget","metadata":{{"name":"{name}","namespace":"{ALPHA}"}},"spec":{{"size":7,"colour":"blue"}}}}"#
                ),
            )
        });
        let run = shell(
            &live,
            &home,
            &format!(
                "get k8s-change {} --kind Widget --group {GROUP} --namespace {ALPHA} \
                 --max_changes {} | to json",
                as_admin(&home),
                held + 1
            ),
        );
        let uid = arrival.join().expect("the create finishes");
        (uid, run)
    });
    let (uid, run) = created;

    let changes = run.rows();
    assert_eq!(
        changes.len(),
        held + 1,
        "the watch answered with the bound it was given, got {run:?}"
    );
    let added = changes
        .iter()
        .find(|change| change["change"].as_str() == Some("added"))
        .unwrap_or_else(|| panic!("one `added` change, got {run:?}"));
    assert_eq!(
        added["name"].as_str(),
        Some(name.as_str()),
        "the object the test created is the one the watch saw, got {added}"
    );
    assert_eq!(
        added["uid"].as_str(),
        Some(uid.as_str()),
        "with the lifetime identity the API server minted for it, got {added}"
    );
    assert_eq!(
        added["continuous"].as_bool(),
        Some(true),
        "and nothing was missed between the list and the change (§19.4), got {added}"
    );
    assert!(
        changes
            .iter()
            .take(held)
            .all(|change| change["change"].as_str() == Some("listed")),
        "the records before it are the initial listing, got {run:?}"
    );
}

#[test]
fn should_answer_a_live_read_on_a_machine_with_no_kubectl() {
    // Gate M (§62.13): "core conformance works on a machine where `kubectl` is absent". Asserted
    // rather than assumed — the test looks for the binary on `PATH` itself and fails the run when
    // it finds one, because a gate that passes on a machine that has `kubectl` proves nothing
    // about a machine that has not. Then it does the thing `kubectl` would have been reached for.
    let live = match Live::open() {
        Ok(live) => live,
        Err(missing) => {
            return announce_skip(
                "should_answer_a_live_read_on_a_machine_with_no_kubectl",
                "external_tool_unavailable",
                &missing,
            );
        }
    };
    if let Some(found) = which("kubectl") {
        panic!(
            "Gate M asks whether this works where `kubectl` is absent, and `{}` is present. \
             Remove it from `PATH` for the run.",
            found.display()
        );
    }
    let home = plugin_home(&live, "no-kubectl");
    let run = shell(
        &live,
        &home,
        &format!(
            "get k8s-pod {} --namespace {ALPHA} | to json",
            as_admin(&home)
        ),
    );
    assert!(
        !run.rows().is_empty(),
        "the Pods of `{ALPHA}` were read over the API with no Kubernetes client on the machine, \
         got {run:?}"
    );
}

#[test]
fn should_carry_no_subprocess_on_any_path_that_reaches_a_cluster() {
    // The static half of Gate M, and §51.4 with it: a subprocess is allowed for an exec
    // credential plugin and for nothing else, so no module that reaches a cluster may spawn one
    // at all. This half needs no cluster, which is why it is the half that runs everywhere — the
    // live half above proves the machine had no `kubectl`, and this one proves the code would not
    // have used one if it had.
    let mut checked = 0;
    for crate_directory in ["ono-provider-kubernetes", "ono-kubernetes-plugin"] {
        let source = workspace().join("crates").join(crate_directory).join("src");
        let files = std::fs::read_dir(&source).expect("the crate has sources");
        for file in files.flatten() {
            let path = file.path();
            if path.extension().and_then(|kind| kind.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("the source reads");
            for forbidden in ["Command::new", "std::process::Command"] {
                assert!(
                    !text.contains(forbidden),
                    "§51.4 and Gate M: `{forbidden}` has no place in {}",
                    path.display()
                );
            }
            checked += 1;
        }
    }
    assert!(
        checked > 20,
        "the scan read {checked} files, which is too few to have read the tree"
    );
}

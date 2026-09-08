//! The distribution wrapper (K11A §8, §11.3, §17, §22; `ADR-0606 (core)`, ADR-0071): what the
//! `.deb` and the `.rpm` named `ono-plugin-kubernetes` place, where, and — above all — what they
//! do not do. Read from the packaging metadata and the script, because the security invariants
//! of K11A §23 are about the absence of things: a maintainer script, an activation, a grant.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md §16)"
)]

const CRATE_MANIFEST: &str = include_str!("../Cargo.toml");
const WORKSPACE: &str = include_str!("../../../Cargo.toml");
const PACKAGE_MANIFEST: &str = include_str!("../../../package/manifest.yaml");
const SCRIPT: &str = include_str!("../../../scripts/package.sh");

const ROOT: &str = "usr/lib/ono-sendai/plugin-sources/io.github.godspeed-you.kubernetes/";

fn package_version() -> String {
    PACKAGE_MANIFEST
        .lines()
        .find_map(|line| line.strip_prefix("  version: "))
        .expect("the manifest declares a version")
        .trim()
        .to_owned()
}

/// The `[package.metadata.<tool>]` table, as text.
fn table(name: &str) -> String {
    let start = CRATE_MANIFEST
        .find(&format!("[package.metadata.{name}]"))
        .unwrap_or_else(|| panic!("Cargo.toml carries [package.metadata.{name}]"));
    let rest = &CRATE_MANIFEST[start + 1..];
    let end = rest.find("\n[").map_or(rest.len(), |offset| offset + 1);
    CRATE_MANIFEST[start..start + 1 + end].to_owned()
}

#[test]
fn should_name_the_wrapper_ono_plugin_kubernetes_and_place_the_payload_under_the_system_root() {
    // K11A §8.1, §8.2: the distribution name is `ono-plugin-<short-name>`, which is not the
    // KUANG/11 identity; the payload sits under `<root>/<id>/<version>/` with the version this
    // crate and the manifest both declare.
    let version = package_version();
    assert!(
        WORKSPACE.contains(&format!("version = \"{version}\"")),
        "the crate version is the payload directory, and the manifest says {version}"
    );
    for tool in ["deb", "generate-rpm"] {
        let text = table(tool);
        assert!(
            text.contains("name = \"ono-plugin-kubernetes\""),
            "[{tool}] is named for the short name"
        );
        for file in [
            "manifest.yaml",
            "contributions/",
            "runtime/ono-kubernetes",
            "signature.yaml",
        ] {
            assert!(
                text.contains(&format!(
                    "target/payload/io.github.godspeed-you.kubernetes/{version}/{file}"
                )),
                "[{tool}] takes {file} from the staged, signed payload"
            );
        }
        assert!(
            text.matches(&format!("{ROOT}{version}/")).count() >= 4,
            "[{tool}] places the payload's files under the versioned directory"
        );
        assert!(
            text.contains(&format!("{version}.origin.yaml")) && text.contains(ROOT),
            "[{tool}] places the sidecar beside the payload"
        );
        assert!(
            !text.contains("/usr/bin/") && !text.contains("\"usr/bin/\""),
            "[{tool}] installs no program anywhere a shell finds it: the runtime runs from Ono's \
             copy only (K11A §16.3)"
        );
    }
}

#[test]
fn should_carry_no_maintainer_script_and_grant_nothing() {
    // K11A §11.3, §17.5, §23 invariants 3–4: no `preinst`/`postinst`/scriptlet; nothing the
    // package manager runs touches Ono's trust, permission or lifecycle state.
    let deb = table("deb");
    let rpm = table("generate-rpm");
    assert!(
        !deb.contains("maintainer-scripts"),
        "the .deb carries no maintainer scripts"
    );
    for hook in [
        "pre_install_script",
        "post_install_script",
        "pre_uninstall_script",
        "post_uninstall_script",
    ] {
        assert!(!rpm.contains(hook), "the .rpm carries no {hook}");
    }
    for word in [
        "grant capability",
        "set permission",
        "trust.yaml",
        "policy.yaml",
        "load plugin",
    ] {
        assert!(
            !deb.contains(word)
                && !rpm.contains(word)
                && !SCRIPT.contains(&format!("ono -c '{word}")),
            "nothing in the wrapper decides `{word}` on a user's behalf"
        );
    }
}

#[test]
fn should_depend_on_a_core_that_reads_the_permission_contract() {
    // K11A §17.3: a lower bound as preflight assistance; the manifest's `kuang_api` stays the
    // authority Ono reads.
    assert!(
        table("deb").contains("depends = \"ono (>= 0.4.3)\""),
        "the .deb names the first core release with the permission layer"
    );
    assert!(
        table("generate-rpm").contains("requires = { ono = \">= 0.4.3\" }"),
        "and so does the .rpm"
    );
    assert!(
        PACKAGE_MANIFEST.contains("kuang_api: \">=11.2 <12\""),
        "the manifest's own declaration is what Ono enforces"
    );
}

#[test]
fn should_sign_the_payload_it_wraps_and_state_the_digest_a_catalog_needs() {
    // K11A §5, §17.2, §22: the wrapper carries the same signed payload a catalog install would
    // verify, unchanged, and the script prints the content digest a catalog release states.
    assert!(
        SCRIPT.contains("\"$sign\" sign \"$payload\" --key \"$key\""),
        "the payload is signed before it is wrapped"
    );
    assert!(
        SCRIPT.contains("--key <signing key> is required"),
        "and an unsigned wrapper is refused"
    );
    assert!(
        SCRIPT.contains("\"$sign\" digest \"$payload\""),
        "the content digest is printed for the catalog entry"
    );
    assert!(
        SCRIPT.contains("kuang-system-origin/1")
            && SCRIPT.contains("package: ono-plugin-kubernetes"),
        "the sidecar names the outer package"
    );
}

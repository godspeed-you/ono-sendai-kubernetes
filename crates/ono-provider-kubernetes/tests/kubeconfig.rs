//! Resolving a kubeconfig into the connection identity a provider instance is built from.
//!
//! Specification §7 (kubeconfig and connection configuration) and §8 (authentication and
//! credential handling). The rules that matter most here are not about YAML: a credential must
//! never reach a place a human or a log can read it (§8.1), TLS validation is on unless someone
//! asked for it not to be (§8.4), and a namespace default is a starting point rather than a
//! permission boundary (§7.5).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::kubeconfig::{Credential, Kubeconfig, Trust};

/// Two clusters, two identities, two contexts — the shape every kubeconfig has.
const TWO_CONTEXTS: &str = r#"
apiVersion: v1
kind: Config
current-context: dev
clusters:
  - name: dev-cluster
    cluster:
      server: https://dev.example.test:6443
      certificate-authority-data: ZGV2LWNh
  - name: prod-cluster
    cluster:
      server: https://prod.example.test:6443
users:
  - name: dev-user
    user:
      token: dev-secret-token
  - name: prod-user
    user:
      token: prod-secret-token
contexts:
  - name: dev
    context:
      cluster: dev-cluster
      user: dev-user
      namespace: shop
  - name: prod
    context:
      cluster: prod-cluster
      user: prod-user
"#;

#[test]
fn should_resolve_a_context_into_a_connection() {
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");
    let dev = config
        .connection("dev")
        .expect("`dev` is a context in this file");

    assert_eq!(dev.server(), "https://dev.example.test:6443");
    assert_eq!(dev.context(), "dev");
    assert_eq!(dev.namespace(), Some("shop"));
}

#[test]
fn should_offer_current_context_as_a_default_rather_than_a_rule() {
    // §7.1: current context is "an optional default". A caller that names a context gets that
    // context, and a caller that names none may fall back to this one.
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");
    assert_eq!(config.current_context(), Some("dev"));

    let prod = config
        .connection("prod")
        .expect("`prod` is a context in this file");
    assert_eq!(
        prod.context(),
        "prod",
        "naming a context must beat current-context"
    );
}

#[test]
fn should_report_a_context_that_is_not_there_rather_than_inventing_one() {
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");
    let error = config
        .connection("staging")
        .expect_err("`staging` is not a context in this file");
    assert!(
        format!("{error}").contains("staging"),
        "the error must name the context that was asked for, got {error}"
    );
}

#[test]
fn should_keep_two_contexts_apart_even_when_they_share_a_server() {
    // §6.2: two contexts pointing at the same API server remain separate provider instances,
    // because credentials, impersonation and default namespace may differ. Collapsing them by
    // server URL is how a query runs as the wrong identity.
    let shared = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://one.example.test:6443}}
users:
  - {name: reader, user: {token: reader-token}}
  - {name: writer, user: {token: writer-token}}
contexts:
  - {name: read, context: {cluster: c, user: reader}}
  - {name: write, context: {cluster: c, user: writer}}
"#;
    let config = Kubeconfig::parse(shared).expect("the kubeconfig parses");
    let read = config.connection("read").expect("`read` resolves");
    let write = config.connection("write").expect("`write` resolves");

    assert_eq!(
        read.server(),
        write.server(),
        "the fixture shares one server"
    );
    assert_ne!(
        read.instance_id(),
        write.instance_id(),
        "same server, different identity: these are two provider instances (§6.2)"
    );
}

#[test]
fn should_name_the_context_in_the_instance_identity() {
    // §7.4: "Selecting a kubeconfig context MUST be visible in the provider instance identity".
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");
    let dev = config.connection("dev").expect("`dev` resolves");
    assert_eq!(dev.instance_id(), "kubernetes:dev");
}

#[test]
fn should_never_let_a_credential_reach_a_debug_rendering() {
    // §8.1: credential bytes must not appear in typed values, logs, crash diagnostics, history,
    // provider manifests or serialized session state. `Debug` is every one of those at once —
    // it is what a panic message, a `dbg!` and a tracing field all reach for.
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");
    let dev = config.connection("dev").expect("`dev` resolves");

    let rendered = format!("{dev:?}");
    assert!(
        !rendered.contains("dev-secret-token"),
        "the token reached a Debug rendering: {rendered}"
    );
    assert!(
        rendered.contains("dev"),
        "redaction must not cost the diagnostic its context, got {rendered}"
    );
}

#[test]
fn should_describe_a_credential_without_disclosing_it() {
    // Diagnostics may state the credential's *source and kind* — that is what answers "who am I
    // to this system right now" (§8.6) — while the bytes stay unreachable.
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");
    let dev = config.connection("dev").expect("`dev` resolves");

    match dev.credential() {
        Credential::BearerToken => {}
        other => panic!("a `token:` user is a bearer credential, got {other:?}"),
    }
}

#[test]
fn should_validate_tls_unless_someone_asked_otherwise() {
    // §8.4: "TLS certificate validation MUST be enabled by default."
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");

    let dev = config.connection("dev").expect("`dev` resolves");
    assert_eq!(
        dev.trust(),
        &Trust::CertificateAuthority(b"dev-ca".to_vec()),
        "the fixture pins a CA, so that is what the connection trusts"
    );
    assert!(!dev.is_insecure(), "a CA-pinned connection is not insecure");

    let prod = config.connection("prod").expect("`prod` resolves");
    assert_eq!(
        prod.trust(),
        &Trust::SystemRoots,
        "no CA in the file means the system trust store, never no verification"
    );
    assert!(!prod.is_insecure());
}

#[test]
fn should_make_an_insecure_connection_say_so() {
    // §8.4: an insecure mode is honoured only when explicitly configured, and "the active
    // insecure state MUST be visible in provider diagnostics".
    let skips = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://one.example.test:6443, insecure-skip-tls-verify: true}}
users:
  - {name: u, user: {token: t}}
contexts:
  - {name: risky, context: {cluster: c, user: u}}
"#;
    let config = Kubeconfig::parse(skips).expect("the kubeconfig parses");
    let risky = config.connection("risky").expect("`risky` resolves");

    assert_eq!(risky.trust(), &Trust::Insecure);
    assert!(
        risky.is_insecure(),
        "the state must be answerable, not inferred"
    );
    assert!(
        format!("{risky:?}").to_lowercase().contains("insecure"),
        "an insecure connection must be visible in diagnostics (§8.4), got {risky:?}"
    );
}

#[test]
fn should_treat_a_namespace_default_as_a_starting_point_not_a_boundary() {
    // §7.5: a context's namespace "MUST NOT be mistaken for an authorization boundary. Users MAY
    // navigate to other namespaces if allowed." So the connection reports it and claims nothing.
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");

    assert_eq!(config.connection("dev").unwrap().namespace(), Some("shop"));
    assert_eq!(
        config.connection("prod").unwrap().namespace(),
        None,
        "no namespace in the context is unknown, never `default` invented on the caller's behalf"
    );
}

#[test]
fn should_reject_a_context_whose_cluster_or_user_is_missing() {
    // A dangling reference is a broken file, and it must fail before anything opens a socket.
    let dangling = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://one.example.test:6443}}
users: []
contexts:
  - {name: broken, context: {cluster: c, user: ghost}}
"#;
    let config = Kubeconfig::parse(dangling).expect("the kubeconfig parses as YAML");
    let error = config
        .connection("broken")
        .expect_err("`ghost` is not a user in this file");
    assert!(
        format!("{error}").contains("ghost"),
        "the error must name what is missing, got {error}"
    );
}

#[test]
fn should_hand_over_an_inline_client_certificate_for_the_connection_to_present() {
    // §7.1: "client certificates where configured". A kubeadm cluster's admin context is exactly
    // this shape, so a provider that resolves everything except this one cannot reach the most
    // common self-hosted cluster there is.
    let certificates = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://one.example.test:6443}}
users:
  - name: admin
    user:
      client-certificate-data: Y2VydC1wZW0=
      client-key-data: a2V5LXBlbQ==
contexts:
  - {name: admin, context: {cluster: c, user: admin}}
"#;
    let config = Kubeconfig::parse(certificates).expect("the kubeconfig parses");
    let admin = config.connection("admin").expect("`admin` resolves");

    assert_eq!(admin.credential(), Credential::ClientCertificate);
    let (certificate, key) = admin
        .client_certificate()
        .expect("the context carries both halves inline");
    assert_eq!(certificate, b"cert-pem");
    assert_eq!(key.expose(), "key-pem");
    assert!(
        admin.client_certificate_files().is_empty(),
        "nothing has to be read from disk for this context"
    );
}

#[test]
fn should_keep_an_inline_client_key_out_of_a_debug_rendering() {
    let certificates = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://one.example.test:6443}}
users:
  - name: admin
    user:
      client-certificate-data: Y2VydC1wZW0=
      client-key-data: c2VjcmV0LWtleS1tYXRlcmlhbA==
contexts:
  - {name: admin, context: {cluster: c, user: admin}}
"#;
    let config = Kubeconfig::parse(certificates).expect("the kubeconfig parses");
    let admin = config.connection("admin").expect("`admin` resolves");

    let rendered = format!("{admin:?}");
    assert!(
        !rendered.contains("secret-key-material"),
        "a private key is credential material (§8.1): {rendered}"
    );
}

#[test]
fn should_name_the_files_a_context_expects_its_client_certificate_to_be_read_from() {
    // This module opens no files, and the paths are reported rather than resolved: reading them
    // needs a capability the caller holds, and a caller that cannot read them has to be able to
    // say *which* read it could not make.
    let paths = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://one.example.test:6443}}
users:
  - name: admin
    user:
      client-certificate: /etc/kubernetes/pki/admin.crt
      client-key: /etc/kubernetes/pki/admin.key
contexts:
  - {name: admin, context: {cluster: c, user: admin}}
"#;
    let config = Kubeconfig::parse(paths).expect("the kubeconfig parses");
    let admin = config.connection("admin").expect("`admin` resolves");

    assert_eq!(admin.credential(), Credential::ClientCertificate);
    assert!(
        admin.client_certificate().is_none(),
        "nothing is inline, and the resolver does not read the files to make it so"
    );
    assert_eq!(
        admin.client_certificate_files(),
        vec![
            "/etc/kubernetes/pki/admin.crt",
            "/etc/kubernetes/pki/admin.key"
        ]
    );
}

#[test]
fn should_refuse_client_certificate_data_that_is_not_base64() {
    let broken = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://one.example.test:6443}}
users:
  - name: admin
    user:
      client-certificate-data: "!!! not base64 !!!"
      client-key-data: a2V5
contexts:
  - {name: admin, context: {cluster: c, user: admin}}
"#;
    let config = Kubeconfig::parse(broken).expect("the kubeconfig parses");
    let error = config
        .connection("admin")
        .expect_err("material that is not base64 is a broken file, not an empty certificate");
    assert!(
        format!("{error}").contains("client-certificate-data"),
        "the error must name the field that does not read, got {error}"
    );
}

#[test]
fn should_report_a_context_with_no_client_certificate_as_having_none() {
    let config = Kubeconfig::parse(TWO_CONTEXTS).expect("the kubeconfig parses");
    let dev = config.connection("dev").expect("`dev` resolves");

    assert!(dev.client_certificate().is_none());
    assert!(dev.client_certificate_files().is_empty());
}

// --- KUBECONFIG multi-file merge (§7.2, ADR-0056) ----------------------------------------------

/// A `(path, text)` document, so a merge reads as a list of files.
fn doc(path: &str, text: &str) -> (String, String) {
    (path.to_owned(), text.to_owned())
}

#[test]
fn should_let_the_first_file_to_define_a_name_win() {
    // §7.2, client-go's rule: files load in list order and the first file to define a cluster, a
    // user or a context wins. The second file's `shared` must not overwrite the first's.
    let first = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: shared, cluster: {server: https://first.example.test:6443}}
users:
  - {name: shared, user: {token: first-token}}
contexts:
  - {name: shared, context: {cluster: shared, user: shared}}
"#;
    let second = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: shared, cluster: {server: https://second.example.test:6443}}
users:
  - {name: shared, user: {token: second-token}}
contexts:
  - {name: shared, context: {cluster: shared, user: shared}}
"#;
    let config = Kubeconfig::merge(&[
        doc("/home/op/.kube/first", first),
        doc("/home/op/.kube/second", second),
    ])
    .expect("the merge succeeds");

    let shared = config.connection("shared").expect("`shared` resolves");
    assert_eq!(
        shared.server(),
        "https://first.example.test:6443",
        "the first file to define `shared` wins"
    );
    assert_eq!(
        config.source_of_cluster("shared"),
        Some("/home/op/.kube/first"),
        "the merge records which file supplied the cluster"
    );
}

#[test]
fn should_resolve_a_context_defined_only_in_the_second_file() {
    // The list is a union: a context in the second file is reachable, which is the whole point of
    // a `KUBECONFIG` list.
    let first = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: a, cluster: {server: https://a.example.test:6443}}
users:
  - {name: a, user: {token: a-token}}
contexts:
  - {name: a, context: {cluster: a, user: a}}
"#;
    let second = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: b, cluster: {server: https://b.example.test:6443}}
users:
  - {name: b, user: {token: b-token}}
contexts:
  - {name: b, context: {cluster: b, user: b, namespace: warehouse}}
"#;
    let config = Kubeconfig::merge(&[doc("/k/first", first), doc("/k/second", second)])
        .expect("the merge succeeds");

    let b = config
        .connection("b")
        .expect("`b` from the second file resolves");
    assert_eq!(b.server(), "https://b.example.test:6443");
    assert_eq!(b.namespace(), Some("warehouse"), "namespace is per context");
    assert_eq!(config.source_of_context("b"), Some("/k/second"));
}

#[test]
fn should_take_current_context_from_the_first_file_that_sets_one() {
    // §7.2: `current-context` is the first non-empty one across the list.
    let first = "apiVersion: v1\nkind: Config\n";
    let second = "apiVersion: v1\nkind: Config\ncurrent-context: from-second\n";
    let third = "apiVersion: v1\nkind: Config\ncurrent-context: from-third\n";
    let config = Kubeconfig::merge(&[
        doc("/k/first", first),
        doc("/k/second", second),
        doc("/k/third", third),
    ])
    .expect("the merge succeeds");
    assert_eq!(
        config.current_context(),
        Some("from-second"),
        "the first file to set a non-empty current-context wins"
    );
}

#[test]
fn should_skip_an_empty_document() {
    // An empty `KUBECONFIG` list entry (or a file a caller omitted) is skipped rather than failing
    // the merge.
    let real = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://c.example.test:6443}}
users:
  - {name: u, user: {token: t}}
contexts:
  - {name: only, context: {cluster: c, user: u}}
"#;
    let config = Kubeconfig::merge(&[doc("/k/empty", "   "), doc("/k/real", real)])
        .expect("an empty document does not fail the merge");
    assert!(config.connection("only").is_ok());
}

#[test]
fn should_name_the_file_that_does_not_parse() {
    // An existing file that does not parse is an error naming the file — "one of them is broken"
    // is not a fix anyone can act on when a list has several.
    let good = "apiVersion: v1\nkind: Config\n";
    let broken = "this: is: not: valid: yaml: at: all: [";
    let error = Kubeconfig::merge(&[doc("/k/good", good), doc("/k/broken.yaml", broken)])
        .expect_err("a document that does not parse fails the merge");
    assert!(
        format!("{error}").contains("/k/broken.yaml"),
        "the error names the file that did not parse, got {error}"
    );
}

#[test]
fn should_resolve_a_relative_certificate_authority_against_its_own_file_s_directory() {
    // §7.2, client-go's rule: a relative `certificate-authority` resolves against the directory of
    // the file that defined it, because a caller reads it there.
    let text = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://c.example.test:6443, certificate-authority: ca.crt}}
users:
  - {name: u, user: {token: t}}
contexts:
  - {name: ctx, context: {cluster: c, user: u}}
"#;
    let config = Kubeconfig::merge(&[doc("/home/op/.kube/clusters/prod", text)])
        .expect("the merge succeeds");
    let ctx = config.connection("ctx").expect("`ctx` resolves");
    assert_eq!(
        ctx.trust(),
        &Trust::CertificateAuthorityFile("/home/op/.kube/clusters/ca.crt".to_owned()),
        "the relative CA path resolved against the defining file's directory"
    );
}

#[test]
fn should_resolve_relative_client_certificate_paths_against_their_own_file_s_directory() {
    let text = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://c.example.test:6443}}
users:
  - name: u
    user:
      client-certificate: pki/admin.crt
      client-key: pki/admin.key
contexts:
  - {name: ctx, context: {cluster: c, user: u}}
"#;
    let config = Kubeconfig::merge(&[doc("/etc/k8s/config", text)]).expect("the merge succeeds");
    let ctx = config.connection("ctx").expect("`ctx` resolves");
    assert_eq!(
        ctx.client_certificate_files(),
        vec!["/etc/k8s/pki/admin.crt", "/etc/k8s/pki/admin.key"],
        "relative client-certificate paths resolve against the defining file's directory"
    );
}

#[test]
fn should_leave_an_absolute_or_tilde_path_unchanged() {
    // An absolute path is already resolved; a `~/`-anchored one is the host's to expand against
    // the operator's home (core ADR-0593), not this provider's.
    let text = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: a, cluster: {server: https://a:6443, certificate-authority: /abs/ca.crt}}
  - {name: b, cluster: {server: https://b:6443, certificate-authority: ~/.kube/ca.crt}}
users:
  - {name: u, user: {token: t}}
contexts:
  - {name: abs, context: {cluster: a, user: u}}
  - {name: home, context: {cluster: b, user: u}}
"#;
    let config = Kubeconfig::merge(&[doc("/etc/k8s/config", text)]).expect("the merge succeeds");
    assert_eq!(
        config.connection("abs").unwrap().trust(),
        &Trust::CertificateAuthorityFile("/abs/ca.crt".to_owned())
    );
    assert_eq!(
        config.connection("home").unwrap().trust(),
        &Trust::CertificateAuthorityFile("~/.kube/ca.crt".to_owned()),
        "`~/` passes through verbatim for the host to expand"
    );
}

#[test]
fn should_resolve_an_exec_command_against_its_file_only_when_it_names_a_path() {
    // client-go resolves an `exec` command against the file's directory only when it contains a
    // path separator; a bare `aws` stays a `PATH` lookup.
    let pathful = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://c:6443}}
users:
  - name: u
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: ./helpers/get-token
contexts:
  - {name: ctx, context: {cluster: c, user: u}}
"#;
    let config = Kubeconfig::merge(&[doc("/home/op/.kube/config", pathful)]).expect("merge");
    let plugin = config
        .connection("ctx")
        .expect("`ctx` resolves")
        .exec()
        .expect("it names a plugin")
        .clone();
    assert_eq!(
        plugin.command(),
        "/home/op/.kube/./helpers/get-token",
        "a command that names a path resolves against the file's directory"
    );

    let bare = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://c:6443}}
users:
  - name: u
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: aws
contexts:
  - {name: ctx, context: {cluster: c, user: u}}
"#;
    let config = Kubeconfig::merge(&[doc("/home/op/.kube/config", bare)]).expect("merge");
    assert_eq!(
        config.connection("ctx").unwrap().exec().unwrap().command(),
        "aws",
        "a bare command stays a PATH lookup"
    );
}

#[test]
fn should_leave_relative_paths_relative_in_a_single_document_parse() {
    // `parse` knows no file, so there is nothing to resolve a relative path against: it stays
    // relative, which is what every existing single-document test relies on.
    let text = r#"
apiVersion: v1
kind: Config
clusters:
  - {name: c, cluster: {server: https://c:6443, certificate-authority: ca.crt}}
users:
  - {name: u, user: {token: t}}
contexts:
  - {name: ctx, context: {cluster: c, user: u}}
"#;
    let config = Kubeconfig::parse(text).expect("the document parses");
    assert_eq!(
        config.connection("ctx").unwrap().trust(),
        &Trust::CertificateAuthorityFile("ca.crt".to_owned()),
        "a single-document parse leaves a relative path relative"
    );
}

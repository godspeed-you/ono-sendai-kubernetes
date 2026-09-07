//! Resolving a kubeconfig into the connection identity a provider instance is built from.
//!
//! Specification §7 and §8. This module reads configuration and produces a [`Connection`]; it
//! opens no socket and executes no credential helper. That separation is why a malformed file, a
//! dangling context reference or a missing user fails before anything reaches the network.
//!
//! The type that carries the most weight here is [`Secret`]. §8.1 requires that credential bytes
//! stay out of typed values, logs, crash diagnostics, history and serialized session state, and
//! the reliable way to get that is to make the bytes hard to reach by accident: `Secret` renders
//! as `<redacted>` under `Debug`, and the only way to the material is [`Secret::expose`], which
//! is one grep away from an audit.

use std::collections::HashMap;
use std::fmt;

use base64::Engine as _;
use serde::Deserialize;

use crate::exec::ExecPlugin;

/// What went wrong before a connection could be described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The document is not a kubeconfig this provider can read.
    Malformed(String),
    /// A context was asked for that the file does not define.
    NoSuchContext(String),
    /// A context names a cluster the file does not define.
    NoSuchCluster {
        /// The context that carries the dangling reference.
        context: String,
        /// The cluster name that resolves to nothing.
        cluster: String,
    },
    /// A context names a user the file does not define.
    NoSuchUser {
        /// The context that carries the dangling reference.
        context: String,
        /// The user name that resolves to nothing.
        user: String,
    },
    /// A field that must be present to reach a cluster is missing.
    Incomplete {
        /// The context whose definition cannot be completed.
        context: String,
        /// What is missing.
        detail: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "the kubeconfig cannot be read: {detail}"),
            Self::NoSuchContext(name) => write!(
                f,
                "the kubeconfig defines no context `{name}`; naming a context that is not there \
                 is a different answer from connecting to the wrong one"
            ),
            Self::NoSuchCluster { context, cluster } => write!(
                f,
                "context `{context}` names cluster `{cluster}`, which the kubeconfig does not \
                 define"
            ),
            Self::NoSuchUser { context, user } => write!(
                f,
                "context `{context}` names user `{user}`, which the kubeconfig does not define"
            ),
            Self::Incomplete { context, detail } => {
                write!(f, "context `{context}` cannot be completed: {detail}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Credential material that must not reach a log, a diagnostic or a serialized session.
///
/// `Debug` renders `<redacted>` rather than the bytes, so a `dbg!`, a panic message, a tracing
/// field and a derived `Debug` on any enclosing type are all safe by construction (§8.1).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wraps material that must stay unreadable by accident.
    #[must_use]
    pub fn new(material: impl Into<String>) -> Self {
        Self(material.into())
    }

    /// The material itself.
    ///
    /// Deliberately not `as_str`, `get` or `Deref`: reaching credential bytes should be a visible
    /// act in the source, so that `grep expose` finds every place that does it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// How the connection proves who it is — the kind, never the material.
///
/// This answers "who am I to this system right now" (§8.6) at the resolution stage, and it is
/// safe to render anywhere because it carries no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// A bearer token from the kubeconfig.
    BearerToken,
    /// A client certificate and key.
    ClientCertificate,
    /// An `exec` credential plugin, which runs only under an explicit process capability (§8.2).
    ExecPlugin,
    /// The context names no credential. The API server decides what that means.
    Anonymous,
}

/// What the connection will verify the API server against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// The platform trust store. The default when the kubeconfig pins nothing.
    SystemRoots,
    /// A certificate authority pinned by the kubeconfig, already base64-decoded.
    CertificateAuthority(Vec<u8>),
    /// A certificate authority to be read from a path at connect time.
    CertificateAuthorityFile(String),
    /// Verification disabled, because the kubeconfig explicitly asked for it (§8.4).
    Insecure,
}

/// One resolved context: everything needed to open a session, and nothing that may be logged.
///
/// `Debug` is written by hand rather than derived. A derived one would print the credential
/// material the moment a field holding it were added, and the rule in §8.1 is exactly the kind
/// that a future field breaks silently.
#[derive(Clone)]
pub struct Connection {
    context: String,
    server: String,
    namespace: Option<String>,
    credential: Credential,
    material: Option<Secret>,
    client_certificate: Option<(Vec<u8>, Secret)>,
    client_certificate_files: Vec<String>,
    trust: Trust,
    /// The `exec` block, where the context authenticates through a credential plugin (§8.2).
    ///
    /// The block and never its output: reading a kubeconfig runs nothing, which is the separation
    /// this module's own header is about. What runs the helper is the package, under an explicit
    /// `process.exec` grant.
    exec: Option<ExecPlugin>,
}

impl Connection {
    /// The kubeconfig context this connection was resolved from.
    #[must_use]
    pub fn context(&self) -> &str {
        &self.context
    }

    /// The API server endpoint.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The context's default namespace, where it declares one.
    ///
    /// A starting point for navigation and never an authorization boundary (§7.5). Absent means
    /// the context declares none, which is unknown rather than `default` invented on the caller's
    /// behalf.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// How this connection proves who it is.
    #[must_use]
    pub fn credential(&self) -> Credential {
        self.credential
    }

    /// The credential plugin this context authenticates through, where it names one (§8.2).
    ///
    /// `None` means the context names no plugin, and nothing else. A block this provider refuses
    /// to read — an unknown contract, an unknown interaction mode — never reaches here: it is a
    /// [`ConfigError::Incomplete`] naming the refusal, raised where the file is read, because
    /// "this context names no plugin" and "this context names one I will not run" are different
    /// answers (§21.4) and the second is fixed in the file the operator can see.
    #[must_use]
    pub fn exec(&self) -> Option<&ExecPlugin> {
        self.exec.as_ref()
    }

    /// The credential material, where the kubeconfig carries it inline.
    #[must_use]
    pub fn material(&self) -> Option<&Secret> {
        self.material.as_ref()
    }

    /// The client certificate and its key, where the kubeconfig carries both inline, in PEM.
    ///
    /// `None` when the context has no client certificate at all, and also when it names either
    /// half as a *file*: this module opens none. [`Self::client_certificate_files`] then names
    /// the paths, so a caller that cannot read them can say which read it could not make rather
    /// than reporting a context with no credential.
    #[must_use]
    pub fn client_certificate(&self) -> Option<(&[u8], &Secret)> {
        self.client_certificate
            .as_ref()
            .map(|(certificate, key)| (certificate.as_slice(), key))
    }

    /// The paths a context names for client certificate material it does not carry inline.
    ///
    /// Reported rather than read. Reading one needs the host's `filesystem.read` capability, and
    /// hiding that read inside a config resolver would put a capability decision somewhere no
    /// reviewer looks (§8.1, §27.3 of the generic provider contract).
    #[must_use]
    pub fn client_certificate_files(&self) -> Vec<&str> {
        self.client_certificate_files
            .iter()
            .map(String::as_str)
            .collect()
    }

    /// What the API server's certificate is checked against.
    #[must_use]
    pub fn trust(&self) -> &Trust {
        &self.trust
    }

    /// Whether certificate verification is off.
    ///
    /// Answerable rather than inferable: §8.4 requires the active insecure state to be visible in
    /// diagnostics, and a caller should not have to pattern-match [`Trust`] to find out.
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        matches!(self.trust, Trust::Insecure)
    }

    /// The provider instance this connection belongs to, as §6.2 spells it.
    ///
    /// Keyed on the context rather than the server: two contexts may reach one API server with
    /// different credentials, impersonation or default namespace, and they are two instances.
    #[must_use]
    pub fn instance_id(&self) -> String {
        format!("kubernetes:{}", self.context)
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rendered = f.debug_struct("Connection");
        rendered
            .field("context", &self.context)
            .field("server", &self.server)
            .field("namespace", &self.namespace)
            .field("credential", &self.credential);
        // Named rather than shown: a reader of a diagnostic needs to know a credential exists and
        // what kind it is, and must not be handed the bytes (§8.1).
        rendered.field("material", &self.material);
        // `Secret` redacts itself, so the pair renders as the certificate's length and
        // `<redacted>`; the certificate is public material and the key never is.
        rendered.field(
            "client_certificate",
            &self.client_certificate.as_ref().map(|(certificate, _)| {
                format!("{} bytes of PEM, key <redacted>", certificate.len())
            }),
        );
        if self.is_insecure() {
            rendered.field("tls", &"insecure: certificate verification disabled");
        } else {
            rendered.field("trust", &self.trust);
        }
        rendered.finish()
    }
}

/// One kubeconfig entry, with the file that supplied it (§7.2, §7.4, ADR-0056).
///
/// The origin is two facts about the same file: the *directory* it lives in, against which its
/// own relative `certificate-authority`, `client-certificate`, `client-key` and `exec` paths
/// resolve (client-go's rule), and the *path* itself, so a diagnostic can say which file of a
/// merged set a name came from. In a single-document parse both are empty, and relative paths
/// then stay relative — there is no file to resolve them against.
#[derive(Debug, Clone)]
struct Sourced<T> {
    spec: T,
    /// The directory of the file that defined this entry, or empty for a document with no path.
    dir: String,
    /// The path of the file that defined this entry, or empty likewise.
    source: String,
}

/// A parsed kubeconfig, or a merge of several (§7.2, ADR-0056).
#[derive(Debug, Clone)]
pub struct Kubeconfig {
    current_context: Option<String>,
    clusters: HashMap<String, Sourced<ClusterSpec>>,
    users: HashMap<String, Sourced<UserSpec>>,
    contexts: HashMap<String, Sourced<ContextSpec>>,
    order: Vec<String>,
}

impl Kubeconfig {
    /// Reads a single kubeconfig document.
    ///
    /// A document with no path on disk: relative `certificate-authority`, `client-certificate`,
    /// `client-key` and `exec` paths stay relative, because there is no file directory to resolve
    /// them against. [`Self::merge`] is the entry point that has one.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Malformed`] when the document is not YAML this provider can read.
    pub fn parse(yaml: &str) -> Result<Self, ConfigError> {
        Self::from_documents(&[(None, yaml)])
    }

    /// Merges several kubeconfig documents the way `KUBECONFIG` asks for (§7.2, ADR-0056).
    ///
    /// Each element is a `(path, text)` pair, in `KUBECONFIG` list order. The merge follows
    /// client-go's loading rules:
    ///
    /// - files are loaded in list order, and for `clusters`, `users` and `contexts` **the first
    ///   file to define a name wins**;
    /// - `current-context` is the **first non-empty** one across the list;
    /// - a document whose text is empty is skipped — a missing file that a caller chose to omit
    ///   contributes nothing rather than failing the merge;
    /// - relative `certificate-authority`, `client-certificate`, `client-key` and `exec` paths
    ///   resolve against the directory of the file that defined them, resolved when a context is
    ///   turned into a [`Connection`];
    /// - each entry remembers which file supplied it, so [`Self::source_of_context`] and its
    ///   siblings can say so in a diagnostic.
    ///
    /// A *missing* file is the caller's to skip before it reaches here (client-go ignores
    /// nonexistent files in the list); an existing file that does not parse is the caller's to
    /// pass in, and it becomes a [`ConfigError::Malformed`] naming the file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Malformed`], naming the file, when one of the documents is not YAML this
    /// provider can read.
    pub fn merge(documents: &[(String, String)]) -> Result<Self, ConfigError> {
        let prepared: Vec<(Option<&str>, &str)> = documents
            .iter()
            .map(|(path, text)| (Some(path.as_str()), text.as_str()))
            .collect();
        Self::from_documents(&prepared)
    }

    /// The merge itself, over documents that each may or may not know their own path.
    fn from_documents(documents: &[(Option<&str>, &str)]) -> Result<Self, ConfigError> {
        let mut current_context: Option<String> = None;
        let mut clusters: HashMap<String, Sourced<ClusterSpec>> = HashMap::new();
        let mut users: HashMap<String, Sourced<UserSpec>> = HashMap::new();
        let mut contexts: HashMap<String, Sourced<ContextSpec>> = HashMap::new();
        let mut order: Vec<String> = Vec::new();

        for (path, text) in documents {
            // An empty document is skipped rather than parsed: an empty `KUBECONFIG` list entry
            // and a file a caller decided to omit both arrive as empty text, and neither is a
            // kubeconfig to fail over.
            if text.trim().is_empty() {
                continue;
            }
            let raw: RawConfig = serde_yaml_ng::from_str(text).map_err(|error| {
                // An existing file that does not parse names itself, because a merged set may have
                // many and "one of them is broken" is not a fix anyone can act on.
                match path {
                    Some(source) => {
                        ConfigError::Malformed(format!("`{source}` cannot be read: {error}"))
                    }
                    None => ConfigError::Malformed(error.to_string()),
                }
            })?;
            let dir = path.map(directory_of).unwrap_or_default();
            let source = (*path).unwrap_or_default().to_owned();

            // First non-empty wins.
            if current_context.is_none()
                && let Some(named) = raw.current_context.filter(|name| !name.is_empty())
            {
                current_context = Some(named);
            }
            for NamedCluster { name, cluster } in raw.clusters {
                clusters.entry(name).or_insert_with(|| Sourced {
                    spec: cluster,
                    dir: dir.clone(),
                    source: source.clone(),
                });
            }
            for NamedUser { name, user } in raw.users {
                users.entry(name).or_insert_with(|| Sourced {
                    spec: user,
                    dir: dir.clone(),
                    source: source.clone(),
                });
            }
            for NamedContext { name, context } in raw.contexts {
                if let std::collections::hash_map::Entry::Vacant(slot) = contexts.entry(name) {
                    order.push(slot.key().clone());
                    slot.insert(Sourced {
                        spec: context,
                        dir: dir.clone(),
                        source: source.clone(),
                    });
                }
            }
        }

        Ok(Self {
            current_context,
            clusters,
            users,
            contexts,
            order,
        })
    }

    /// The `current-context`, which is a default a caller may take rather than one it must (§7.1).
    #[must_use]
    pub fn current_context(&self) -> Option<&str> {
        self.current_context.as_deref()
    }

    /// Every context the file defines, in the order it defines them.
    pub fn contexts(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(String::as_str)
    }

    /// Which file of a merged set supplied a context, where one did (§7.2, ADR-0056).
    ///
    /// Empty string for an entry from a single-document parse, which knew no path. `None` when no
    /// such context exists.
    #[must_use]
    pub fn source_of_context(&self, context: &str) -> Option<&str> {
        self.contexts
            .get(context)
            .map(|sourced| sourced.source.as_str())
    }

    /// Which file of a merged set supplied a cluster, where one did (§7.2, ADR-0056).
    #[must_use]
    pub fn source_of_cluster(&self, cluster: &str) -> Option<&str> {
        self.clusters
            .get(cluster)
            .map(|sourced| sourced.source.as_str())
    }

    /// Resolves one context into a connection.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NoSuchContext`] when the file defines no such context, and
    /// [`ConfigError::NoSuchCluster`] / [`ConfigError::NoSuchUser`] when the context's references
    /// dangle. Each is distinguishable, because "you named a context that is not here" and "the
    /// context is here but broken" call for different corrections.
    pub fn connection(&self, context: &str) -> Result<Connection, ConfigError> {
        let entry = self
            .contexts
            .get(context)
            .ok_or_else(|| ConfigError::NoSuchContext(context.to_owned()))?;

        let cluster =
            self.clusters
                .get(&entry.spec.cluster)
                .ok_or_else(|| ConfigError::NoSuchCluster {
                    context: context.to_owned(),
                    cluster: entry.spec.cluster.clone(),
                })?;

        let user = match entry.spec.user.as_deref() {
            None => None,
            Some(name) => Some(
                self.users
                    .get(name)
                    .ok_or_else(|| ConfigError::NoSuchUser {
                        context: context.to_owned(),
                        user: name.to_owned(),
                    })?,
            ),
        };
        // The directory each half was defined in, for resolving that half's own relative paths
        // (§7, ADR-0056). A merged set may take its cluster from one file and its user from
        // another, so the two dirs are looked up separately.
        let cluster_dir = cluster.dir.as_str();
        let user_dir = user.map(|user| user.dir.as_str()).unwrap_or_default();
        let user_spec = user.map(|user| &user.spec);

        let server = cluster
            .spec
            .server
            .clone()
            .ok_or_else(|| ConfigError::Incomplete {
                context: context.to_owned(),
                detail: "its cluster declares no `server`".to_owned(),
            })?;

        let (credential, material) = classify(user_spec);
        let (client_certificate, client_certificate_files) =
            client_certificate_of(user_spec, user_dir)?;
        // §8.2's block, read but not run. A block this provider refuses — an unknown contract, an
        // unknown interaction mode — is a *configuration* error and is reported here rather than
        // at connection time, because an operator fixes it in the file they can see.
        let exec = match user_spec.and_then(|user| user.exec.as_ref()) {
            None => None,
            Some(block) => Some(
                ExecPlugin::parse(block)
                    // client-go resolves an `exec` command against the file's directory only when
                    // the command names a path — a bare `aws` stays a `PATH` lookup (§8.2).
                    .map(|plugin| plugin.resolve_command_against(user_dir))
                    .map_err(|refusal| ConfigError::Incomplete {
                        context: context.to_owned(),
                        detail: format!("its credential plugin cannot be run: {refusal}"),
                    })?,
            ),
        };

        Ok(Connection {
            context: context.to_owned(),
            server,
            namespace: entry.spec.namespace.clone(),
            credential,
            material,
            client_certificate,
            client_certificate_files,
            trust: trust_of(&cluster.spec, cluster_dir)?,
            exec,
        })
    }
}

/// Resolves a kubeconfig-relative path against the directory of the file that named it (§7).
///
/// An absolute path and a `~/`-anchored one pass through unchanged: the first is already
/// resolved, and the second is the host's to expand against the operator's home (core ADR-0593),
/// not this provider's. An empty directory — a single-document parse that knew no file — also
/// leaves the path unchanged, because there is nothing to resolve it against.
fn resolve_path(dir: &str, path: &str) -> String {
    if dir.is_empty() || path.starts_with('/') || path.starts_with("~/") {
        path.to_owned()
    } else {
        format!("{}/{path}", dir.trim_end_matches('/'))
    }
}

/// The directory a file path lives in, or empty where it names no directory.
fn directory_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_owned(),
        Some(at) => path[..at].to_owned(),
        None => String::new(),
    }
}

/// What a user entry proves identity with, and the material where the file carries it inline.
fn classify(user: Option<&UserSpec>) -> (Credential, Option<Secret>) {
    let Some(user) = user else {
        return (Credential::Anonymous, None);
    };
    if let Some(token) = &user.token {
        return (Credential::BearerToken, Some(Secret::new(token.clone())));
    }
    if user.exec.is_some() {
        // The material arrives from the helper at session time and never from the file, so there
        // is nothing to carry here (§8.2, §8.3).
        return (Credential::ExecPlugin, None);
    }
    if user.client_certificate_data.is_some()
        || user.client_certificate.is_some()
        || user.client_key_data.is_some()
        || user.client_key.is_some()
    {
        return (Credential::ClientCertificate, None);
    }
    (Credential::Anonymous, None)
}

/// The client certificate a user entry carries inline, and the paths it names instead.
///
/// Both halves are needed for the material to be usable, so a context that carries one inline and
/// names the other as a file reports *no* inline certificate and both locations — a half-resolved
/// identity would fail at the handshake for a reason nothing here had recorded.
type ClientCertificate = (Option<(Vec<u8>, Secret)>, Vec<String>);

fn client_certificate_of(
    user: Option<&UserSpec>,
    dir: &str,
) -> Result<ClientCertificate, ConfigError> {
    let Some(user) = user else {
        return Ok((None, Vec::new()));
    };
    let certificate = decode(
        user.client_certificate_data.as_deref(),
        "client-certificate-data",
    )?;
    let key = decode(user.client_key_data.as_deref(), "client-key-data")?;
    let mut files = Vec::new();
    if let (Some(certificate), Some(key)) = (certificate, key) {
        return Ok((
            Some((
                certificate,
                // The key is the only half that is credential material; the certificate is
                // published to every peer that connects (§8.1).
                Secret::new(String::from_utf8_lossy(&key).into_owned()),
            )),
            files,
        ));
    }
    // The file paths are resolved against the file that named them (§7, ADR-0056), because a
    // caller reads them through its own capability against the real filesystem and a relative
    // path there means "beside this kubeconfig".
    if let Some(path) = &user.client_certificate {
        files.push(resolve_path(dir, path));
    }
    if let Some(path) = &user.client_key {
        files.push(resolve_path(dir, path));
    }
    Ok((None, files))
}

/// Base64 material from the kubeconfig, or a named failure.
fn decode(encoded: Option<&str>, field: &str) -> Result<Option<Vec<u8>>, ConfigError> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map(Some)
        .map_err(|error| ConfigError::Malformed(format!("`{field}` is not base64: {error}")))
}

/// What the API server's certificate is checked against.
///
/// `insecure-skip-tls-verify` wins where it is set, because it is the only field a human sets
/// deliberately; everything else resolves to verification against something (§8.4).
fn trust_of(cluster: &ClusterSpec, dir: &str) -> Result<Trust, ConfigError> {
    if cluster.insecure_skip_tls_verify.unwrap_or(false) {
        return Ok(Trust::Insecure);
    }
    if let Some(encoded) = &cluster.certificate_authority_data {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|error| {
                ConfigError::Malformed(format!(
                    "`certificate-authority-data` is not base64: {error}"
                ))
            })?;
        return Ok(Trust::CertificateAuthority(decoded));
    }
    if let Some(path) = &cluster.certificate_authority {
        // Resolved against the file that named it (§7, ADR-0056): a relative
        // `certificate-authority` means "beside this kubeconfig", and the caller reads it there.
        return Ok(Trust::CertificateAuthorityFile(resolve_path(dir, path)));
    }
    Ok(Trust::SystemRoots)
}

// --- the document as it is written on disk -------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(rename = "current-context")]
    current_context: Option<String>,
    #[serde(default)]
    clusters: Vec<NamedCluster>,
    #[serde(default)]
    users: Vec<NamedUser>,
    #[serde(default)]
    contexts: Vec<NamedContext>,
}

#[derive(Debug, Deserialize)]
struct NamedCluster {
    name: String,
    cluster: ClusterSpec,
}

#[derive(Debug, Deserialize)]
struct NamedUser {
    name: String,
    user: UserSpec,
}

#[derive(Debug, Deserialize)]
struct NamedContext {
    name: String,
    context: ContextSpec,
}

#[derive(Debug, Clone, Deserialize)]
struct ClusterSpec {
    server: Option<String>,
    #[serde(rename = "certificate-authority")]
    certificate_authority: Option<String>,
    #[serde(rename = "certificate-authority-data")]
    certificate_authority_data: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify")]
    insecure_skip_tls_verify: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct UserSpec {
    token: Option<String>,
    #[serde(rename = "client-certificate")]
    client_certificate: Option<String>,
    #[serde(rename = "client-certificate-data")]
    client_certificate_data: Option<String>,
    #[serde(rename = "client-key")]
    client_key: Option<String>,
    #[serde(rename = "client-key-data")]
    client_key_data: Option<String>,
    exec: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct ContextSpec {
    cluster: String,
    user: Option<String>,
    namespace: Option<String>,
}

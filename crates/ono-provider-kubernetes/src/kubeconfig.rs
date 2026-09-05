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

/// A parsed kubeconfig.
#[derive(Debug, Clone)]
pub struct Kubeconfig {
    current_context: Option<String>,
    clusters: HashMap<String, ClusterSpec>,
    users: HashMap<String, UserSpec>,
    contexts: HashMap<String, ContextSpec>,
    order: Vec<String>,
}

impl Kubeconfig {
    /// Reads a kubeconfig document.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Malformed`] when the document is not YAML this provider can read.
    pub fn parse(yaml: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = serde_yaml_ng::from_str(yaml)
            .map_err(|error| ConfigError::Malformed(error.to_string()))?;

        let order = raw
            .contexts
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        Ok(Self {
            current_context: raw.current_context,
            clusters: raw
                .clusters
                .into_iter()
                .map(|entry| (entry.name, entry.cluster))
                .collect(),
            users: raw
                .users
                .into_iter()
                .map(|entry| (entry.name, entry.user))
                .collect(),
            contexts: raw
                .contexts
                .into_iter()
                .map(|entry| (entry.name, entry.context))
                .collect(),
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
                .get(&entry.cluster)
                .ok_or_else(|| ConfigError::NoSuchCluster {
                    context: context.to_owned(),
                    cluster: entry.cluster.clone(),
                })?;

        let user = match entry.user.as_deref() {
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

        let server = cluster
            .server
            .clone()
            .ok_or_else(|| ConfigError::Incomplete {
                context: context.to_owned(),
                detail: "its cluster declares no `server`".to_owned(),
            })?;

        let (credential, material) = classify(user);
        let (client_certificate, client_certificate_files) = client_certificate_of(user)?;

        Ok(Connection {
            context: context.to_owned(),
            server,
            namespace: entry.namespace.clone(),
            credential,
            material,
            client_certificate,
            client_certificate_files,
            trust: trust_of(cluster)?,
        })
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

fn client_certificate_of(user: Option<&UserSpec>) -> Result<ClientCertificate, ConfigError> {
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
    if let Some(path) = &user.client_certificate {
        files.push(path.clone());
    }
    if let Some(path) = &user.client_key {
        files.push(path.clone());
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
fn trust_of(cluster: &ClusterSpec) -> Result<Trust, ConfigError> {
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
        return Ok(Trust::CertificateAuthorityFile(path.clone()));
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

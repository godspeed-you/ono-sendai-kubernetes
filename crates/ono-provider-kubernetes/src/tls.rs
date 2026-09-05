//! A TLS session, seen as one more [`ByteStream`].
//!
//! Specification §8.4. `ADR-0002` records why this is the package's work rather than the host's:
//! KUANG/11 brokers a *connection* and deliberately serves no `network.request` (core
//! `ADR-0573`), so the host verifies the destination and never the protocol. The certificate
//! check has nowhere else to live.
//!
//! The shape follows from what [`crate::transport`] already says: TLS sits *below* HTTP. A
//! [`TlsStream`] wraps the brokered [`ByteStream`], completes its handshake in
//! [`TlsStream::connect`], and then presents the same two methods — bytes out, bytes in — so
//! `HttpConnection` cannot tell the difference and never sees a certificate.
//!
//! **This module performs no I/O of its own.** It opens no file and resolves no path. A
//! kubeconfig may name its certificate authority as a *path*
//! ([`Trust::CertificateAuthorityFile`]), and reading that path needs the host's
//! `filesystem.read` capability, which is a decision the caller has to take visibly rather than
//! one hidden under a TLS constructor. So [`Anchors`] carries certificates and never paths, and
//! [`Anchors::for_trust`] refuses the file variant by naming the file the caller must read.
//!
//! **Verification is off in exactly one place.** §8.4 allows an insecure mode only when it is
//! explicitly configured, so there is no boolean anywhere in this module that could turn
//! verification off as an argument. [`Anchors::for_trust`] refuses [`Trust::Insecure`], and the
//! only way to an unverified session is [`TlsSettings::without_certificate_verification`], whose
//! name is what a reviewer greps for.
//!
//! What is *not* here: bearer tokens and impersonation headers. Those are HTTP, and putting them
//! in a TLS module would be the first step towards a transport that knows about credentials.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme,
};

use crate::kubeconfig::{Secret, Trust};
use crate::transport::{ByteStream, StreamError};

/// What stopped a TLS session before it could carry a byte.
///
/// Every variant is a refusal with a name, because the corrections differ: a malformed authority
/// is a broken kubeconfig, a file variant is a read the caller owes, and an unknown issuer is a
/// server this provider will not talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// The pinned certificate authority is not a usable PEM certificate bundle.
    ///
    /// Deliberately fatal. Falling back to the platform store here would verify against
    /// something the operator did not name, and nothing in the session would say so.
    CertificateAuthority(String),
    /// The trust setting names a file, and this module reads none. The path is carried so the
    /// caller can read it under the host's `filesystem.read` capability and pin the bytes.
    CertificateAuthorityFile(String),
    /// Certificate verification would have had to be disabled, and no general-purpose
    /// constructor does that (§8.4).
    InsecureNotRequestedExplicitly,
    /// The client certificate or its private key cannot be used.
    ClientIdentity(String),
    /// The name the server certificate would be checked against is not one TLS can check.
    ServerName(String),
    /// `rustls` refused the configuration itself.
    Configuration(String),
    /// The handshake failed — an unknown issuer, a name mismatch, an expired certificate, or a
    /// connection that broke while it was being established.
    Handshake(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateAuthority(detail) => write!(
                f,
                "the pinned certificate authority is not a usable PEM certificate bundle: \
                 {detail}. Verification is not silently downgraded to the platform trust store, \
                 because that would check the server against something the kubeconfig never named"
            ),
            Self::CertificateAuthorityFile(path) => write!(
                f,
                "the certificate authority lives in the file `{path}`, and the TLS layer opens \
                 no files; read it under the host's `filesystem.read` capability and pin the \
                 bytes instead"
            ),
            Self::InsecureNotRequestedExplicitly => f.write_str(
                "certificate verification cannot be disabled through this path; \
                 `TlsSettings::without_certificate_verification` is the only constructor that \
                 does it, and §8.4 allows it only where it was explicitly configured",
            ),
            Self::ClientIdentity(detail) => {
                write!(f, "the client certificate cannot be used: {detail}")
            }
            Self::ServerName(detail) => write!(
                f,
                "`{detail}` is not a name a server certificate can be checked against"
            ),
            Self::Configuration(detail) => {
                write!(f, "the TLS configuration was refused: {detail}")
            }
            Self::Handshake(detail) => write!(f, "the TLS handshake failed: {detail}"),
        }
    }
}

impl std::error::Error for TlsError {}

// --- trust anchors -----------------------------------------------------------------------------

/// What a session will verify the API server against, with every certificate already in memory.
///
/// The difference from [`Trust`] is the point of the type. `Trust` is what a kubeconfig *says*,
/// and it may say "the certificate authority is at this path" or "check nothing at all".
/// `Anchors` is what a session can *use*: certificates, parsed, here, now — with no file left to
/// open and no way to spell "unverified". Converting one to the other is [`Anchors::for_trust`],
/// and what it refuses is as important as what it accepts.
///
/// Constructed only through the functions below, so an `Anchors` that exists is one that
/// verified: a bundle that does not parse never becomes a value that a later step could mistake
/// for an empty store.
#[derive(Clone)]
pub struct Anchors {
    store: Arc<RootCertStore>,
    pinned: bool,
}

impl Anchors {
    /// The platform trust store, as `webpki-roots` publishes it.
    ///
    /// What a managed cluster with a publicly issued certificate needs, and what a kubeconfig
    /// that pins nothing asks for.
    #[must_use]
    pub fn system() -> Self {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self {
            store: Arc::new(store),
            pinned: false,
        }
    }

    /// One PEM bundle, pinned as the only issuer that can vouch for the server.
    ///
    /// Pinned *instead of* the platform store, never beside it: a cluster whose kubeconfig names
    /// its own authority should not additionally be reachable by anything a laptop happens to
    /// trust.
    ///
    /// # Errors
    ///
    /// [`TlsError::CertificateAuthority`] when the bundle is not PEM, holds no certificate, or
    /// holds one `rustls` refuses. Every one of those is fatal rather than a reason to fall back
    /// to the platform store: the fallback would verify the server against something the
    /// kubeconfig never named, and nothing in the session would say so.
    pub fn pinned(pem: &[u8]) -> Result<Self, TlsError> {
        let mut store = RootCertStore::empty();
        for certificate in certificates(pem)? {
            store.add(certificate).map_err(|error| {
                TlsError::CertificateAuthority(format!(
                    "one of its certificates was refused: {error}"
                ))
            })?;
        }
        if store.is_empty() {
            return Err(TlsError::CertificateAuthority(
                "it holds no certificate".to_owned(),
            ));
        }
        Ok(Self {
            store: Arc::new(store),
            pinned: true,
        })
    }

    /// The anchors a kubeconfig's trust setting asks for.
    ///
    /// # Errors
    ///
    /// [`TlsError::CertificateAuthorityFile`] for [`Trust::CertificateAuthorityFile`], because
    /// this module opens no files; [`TlsError::InsecureNotRequestedExplicitly`] for
    /// [`Trust::Insecure`], because no constructor a caller reaches by default may produce an
    /// unverified session (§8.4); and [`TlsError::CertificateAuthority`] for a pinned bundle that
    /// does not read.
    pub fn for_trust(trust: &Trust) -> Result<Self, TlsError> {
        match trust {
            Trust::SystemRoots => Ok(Self::system()),
            Trust::CertificateAuthority(pem) => Self::pinned(pem),
            Trust::CertificateAuthorityFile(path) => {
                Err(TlsError::CertificateAuthorityFile(path.clone()))
            }
            Trust::Insecure => Err(TlsError::InsecureNotRequestedExplicitly),
        }
    }

    /// How many certificates can vouch for the server.
    #[must_use]
    pub fn count(&self) -> usize {
        self.store.len()
    }

    /// Whether the kubeconfig pinned these anchors, rather than them being the platform store.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        self.pinned
    }
}

impl fmt::Debug for Anchors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anchors")
            .field("pinned", &self.pinned)
            .field("count", &self.store.len())
            .finish()
    }
}

/// Reads a PEM bundle into certificates, refusing anything that is not one.
fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut reader = pem;
    let mut certificates = Vec::new();
    for certificate in rustls_pemfile::certs(&mut reader) {
        certificates.push(certificate.map_err(|error| {
            TlsError::CertificateAuthority(format!("its PEM does not read: {error}"))
        })?);
    }
    if certificates.is_empty() {
        return Err(TlsError::CertificateAuthority(
            "it holds no `BEGIN CERTIFICATE` block".to_owned(),
        ));
    }
    Ok(certificates)
}

// --- the client's own certificate --------------------------------------------------------------

/// A client certificate chain and the private key that proves it (§7.1, §8.1).
///
/// The key is taken as a [`Secret`] and parsed immediately: a key that cannot be used should fail
/// where the kubeconfig is resolved rather than in the middle of a handshake, and the parsed form
/// never reaches [`fmt::Debug`].
pub struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl ClientIdentity {
    /// Parses a PEM certificate chain and a PEM private key.
    ///
    /// # Errors
    ///
    /// [`TlsError::ClientIdentity`] when the chain holds no certificate or the key is not a
    /// PKCS#8, PKCS#1 or SEC1 private key.
    pub fn new(certificate_chain: &[u8], key: &Secret) -> Result<Self, TlsError> {
        let chain = certificates(certificate_chain).map_err(|error| {
            TlsError::ClientIdentity(format!("its certificate chain does not read: {error}"))
        })?;
        let mut reader = key.expose().as_bytes();
        // The errors below carry no key material: they say which block was expected, never what
        // was in it (§8.1).
        let key = rustls_pemfile::private_key(&mut reader)
            .map_err(|error| {
                TlsError::ClientIdentity(format!("its private key does not read: {error}"))
            })?
            .ok_or_else(|| {
                TlsError::ClientIdentity(
                    "its private key holds no PKCS#8, PKCS#1 or SEC1 block".to_owned(),
                )
            })?;
        Ok(Self { chain, key })
    }

    /// How many certificates the chain holds.
    #[must_use]
    pub fn chain_length(&self) -> usize {
        self.chain.len()
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("chain_length", &self.chain.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Clone for ClientIdentity {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
        }
    }
}

// --- the configuration ---------------------------------------------------------------------

/// A ready `rustls` client configuration, and what it does or does not check.
///
/// Cheap to clone: one connection per request path shares one configuration, which is also how
/// `rustls` wants its session cache used.
#[derive(Clone)]
pub struct TlsSettings {
    config: Arc<ClientConfig>,
    verifies: bool,
    anchors: usize,
    client_certificate: bool,
}

impl TlsSettings {
    /// A configuration that verifies the server against `anchors`.
    ///
    /// This is the constructor every ordinary path takes, and it cannot produce an unverified
    /// session: [`Anchors`] has no variant that means "check nothing".
    ///
    /// # Errors
    ///
    /// [`TlsError::CertificateAuthority`] when the pinned bundle does not read,
    /// [`TlsError::ClientIdentity`] when the client certificate and its key do not match, and
    /// [`TlsError::Configuration`] when `rustls` refuses the result.
    pub fn verifying(
        anchors: &Anchors,
        identity: Option<&ClientIdentity>,
    ) -> Result<Self, TlsError> {
        let anchor_count = anchors.count();
        let config = builder()?.with_root_certificates(Arc::clone(&anchors.store));
        let config = match identity {
            None => config.with_no_client_auth(),
            Some(identity) => config
                .with_client_auth_cert(identity.chain.clone(), identity.key.clone_key())
                .map_err(|error| TlsError::ClientIdentity(error.to_string()))?,
        };
        Ok(Self {
            config: Arc::new(config),
            verifies: true,
            anchors: anchor_count,
            client_certificate: identity.is_some(),
        })
    }

    /// A configuration that accepts **any** server certificate.
    ///
    /// The consequence, stated plainly because the name alone cannot: the session is encrypted
    /// and unauthenticated. Anything able to route the connection can present its own
    /// certificate, read every request and answer with whatever it likes; a token sent over such
    /// a session is a token handed to whoever intercepted it. §8.4 permits this only where it
    /// was explicitly configured — `insecure-skip-tls-verify: true` in a kubeconfig — and
    /// [`crate::kubeconfig::Connection::is_insecure`] exists so a diagnostic can say so
    /// prominently rather than having to infer it.
    ///
    /// There is deliberately no way to reach this from [`Anchors`] or from [`Trust`]: a caller
    /// that wants an unverified session names this function, and every such call site is one
    /// grep away.
    ///
    /// # Errors
    ///
    /// [`TlsError::ClientIdentity`] when the client certificate and its key do not match, and
    /// [`TlsError::Configuration`] when `rustls` refuses the result.
    pub fn without_certificate_verification(
        identity: Option<&ClientIdentity>,
    ) -> Result<Self, TlsError> {
        let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        let config = builder()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer { algorithms }));
        let config = match identity {
            None => config.with_no_client_auth(),
            Some(identity) => config
                .with_client_auth_cert(identity.chain.clone(), identity.key.clone_key())
                .map_err(|error| TlsError::ClientIdentity(error.to_string()))?,
        };
        Ok(Self {
            config: Arc::new(config),
            verifies: false,
            anchors: 0,
            client_certificate: identity.is_some(),
        })
    }

    /// Whether the server's certificate is checked at all (§8.4).
    ///
    /// Answerable rather than inferable, for the same reason
    /// [`crate::kubeconfig::Connection::is_insecure`] is: a diagnostic that has to pattern-match
    /// a configuration to find out will eventually stop asking.
    #[must_use]
    pub fn verifies_certificates(&self) -> bool {
        self.verifies
    }

    /// How many trust anchors the session verifies against; zero when it verifies nothing.
    #[must_use]
    pub fn trust_anchor_count(&self) -> usize {
        self.anchors
    }

    /// Whether the session presents a client certificate (§7.1).
    #[must_use]
    pub fn has_client_certificate(&self) -> bool {
        self.client_certificate
    }
}

impl fmt::Debug for TlsSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rendered = f.debug_struct("TlsSettings");
        if self.verifies {
            rendered.field("trust_anchors", &self.anchors);
        } else {
            rendered.field("tls", &"insecure: certificate verification disabled");
        }
        rendered
            .field("client_certificate", &self.client_certificate)
            .finish()
    }
}

/// The half of the builder chain both constructors share.
fn builder() -> Result<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>, TlsError> {
    // The provider is named rather than defaulted: `ADR-0353` in core picked `ring`, and a
    // process-wide default provider installed by somebody else is not something this package
    // wants to inherit silently.
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| TlsError::Configuration(error.to_string()))
}

/// The verifier behind [`TlsSettings::without_certificate_verification`].
///
/// It answers "valid" to every certificate. Signature verification is still real, because a
/// forged signature is a broken session rather than an unauthenticated one, and leaving it out
/// would fail obscurely instead of insecurely.
struct AcceptAnyServer {
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for AcceptAnyServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `rustls` requires `Debug` on a verifier and prints it in its own diagnostics, so what
        // it says is the sentence an operator will read there.
        f.write_str("AcceptAnyServer { certificate verification disabled }")
    }
}

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// --- a byte stream, seen as `std::io` -----------------------------------------------------------

/// A [`ByteStream`] presented as [`std::io::Read`] and [`std::io::Write`].
///
/// `rustls` drives an ordinary blocking socket, and the brokered connection is not one. This is
/// the whole adaptation: `read` and `write` forward, a stream failure becomes an
/// [`io::Error`] carrying what the transport said, and `flush` does nothing because a
/// [`ByteStream`] has no buffer of its own to empty.
#[derive(Debug)]
pub struct IoBridge<S: ByteStream> {
    stream: S,
}

impl<S: ByteStream> IoBridge<S> {
    /// Presents `stream` as `std::io`.
    pub const fn new(stream: S) -> Self {
        Self { stream }
    }

    /// The stream underneath, for a fixture to be inspected.
    pub const fn get_ref(&self) -> &S {
        &self.stream
    }

    /// The stream underneath.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: ByteStream> Read for IoBridge<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream
            .read(buf)
            .map_err(|error| io::Error::other(error.message().to_owned()))
    }
}

impl<S: ByteStream> Write for IoBridge<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream
            .write_all(buf)
            .map(|()| buf.len())
            .map_err(|error| io::Error::other(error.message().to_owned()))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// --- the session ---------------------------------------------------------------------------

/// A TLS session over another byte stream.
///
/// Implements [`ByteStream`] itself, which is what lets `HttpConnection` be written as if TLS did
/// not exist: the handshake, the trust store and the server certificate are settled in
/// [`Self::connect`], before the first request line is written.
pub struct TlsStream<S: ByteStream> {
    connection: ClientConnection,
    bridge: IoBridge<S>,
}

impl<S: ByteStream> TlsStream<S> {
    /// Opens a session over `stream` and completes its handshake.
    ///
    /// The handshake happens here rather than lazily on first write, so that an unknown issuer,
    /// a name mismatch or an expired certificate is reported as what it is instead of surfacing
    /// later as a failed request.
    ///
    /// `server_name` is checked against the certificate. It is the host from the kubeconfig's
    /// `server` URL — an IP address is accepted, because a kubeconfig routinely names one.
    ///
    /// # Errors
    ///
    /// [`TlsError::ServerName`] when the name cannot be checked against a certificate at all,
    /// and [`TlsError::Handshake`] when the peer's certificate is refused or the connection
    /// fails while the session is being established.
    pub fn connect(stream: S, server_name: &str, settings: &TlsSettings) -> Result<Self, TlsError> {
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| TlsError::ServerName(server_name.to_owned()))?;
        let mut connection = ClientConnection::new(Arc::clone(&settings.config), name)
            .map_err(|error| TlsError::Configuration(error.to_string()))?;
        let mut bridge = IoBridge::new(stream);
        connection
            .complete_io(&mut bridge)
            .map_err(|error| TlsError::Handshake(error.to_string()))?;
        Ok(Self { connection, bridge })
    }

    /// The stream underneath, for a fixture to be inspected.
    pub const fn get_ref(&self) -> &S {
        self.bridge.get_ref()
    }

    /// The stream underneath, once the session is done with it.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.bridge.into_inner()
    }
}

impl<S: ByteStream> fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Written by hand rather than derived, so that a stream underneath does not have to be
        // `Debug` and, more importantly, so that no future field can print itself into a
        // diagnostic without somebody deciding it should (§8.1).
        f.debug_struct("TlsStream")
            .field("handshaking", &self.connection.is_handshaking())
            .finish()
    }
}

impl<S: ByteStream> ByteStream for TlsStream<S> {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        rustls::Stream::new(&mut self.connection, &mut self.bridge)
            .write_all(bytes)
            .map_err(|error| StreamError::new(error.to_string()))
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, StreamError> {
        match rustls::Stream::new(&mut self.connection, &mut self.bridge).read(buf) {
            Ok(read) => Ok(read),
            // A peer that vanishes without a `close_notify` has not ended the message, it has
            // stopped mid-sentence. Reporting that as end of stream would let a truncated
            // response read as a complete one, which is the whole reason the alert exists.
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(StreamError::new(
                "the API server closed the TLS session without a `close_notify`, so what \
                 arrived cannot be known to be all of it",
            )),
            Err(error) => Err(StreamError::new(error.to_string())),
        }
    }
}

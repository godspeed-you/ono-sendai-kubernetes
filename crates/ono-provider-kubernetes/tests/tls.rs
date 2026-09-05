//! TLS as a byte stream: which trust anchors a kubeconfig produces, and a real handshake.
//!
//! Specification §8.4 (TLS validation is on by default, insecure modes only when explicitly
//! configured) and §7.1 (client certificates where configured). `ADR-0002` is why this lives in
//! the package at all: KUANG/11 brokers bytes rather than requests, so the certificate check has
//! nowhere else to happen.
//!
//! Two kinds of test, and the difference matters. The configuration tests touch no network and
//! no disk: they assert what a given [`Trust`] *becomes*, including the refusals. The handshake
//! tests run a real `rustls` server on the other end of an in-memory byte stream, so the wrapper
//! is proven to speak TLS rather than merely to compile against it.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::io::{Read as _, Write as _};
use std::sync::Arc;

use ono_provider_kubernetes::kubeconfig::{Secret, Trust};
use ono_provider_kubernetes::tls::{
    Anchors, ClientIdentity, IoBridge, TlsError, TlsSettings, TlsStream,
};
use ono_provider_kubernetes::transport::{ByteStream, FixtureStream, StreamError};

// --- certificates, generated for the test ------------------------------------------------------

/// A certificate authority, a server certificate it signed, and the key for each, in PEM.
///
/// Generated rather than checked in: a PEM in the repository expires on a date nobody chose, and
/// the suite then fails for a reason that has nothing to do with the code.
struct Authority {
    ca_pem: String,
    server_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
    client_certificate_pem: String,
    client_key_pem: String,
}

fn authority(server_name: &str) -> Authority {
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::new()).expect("a CA needs no subject alternative name");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ono-sendai test authority");
    let ca_key = rcgen::KeyPair::generate().expect("a key pair is generated");
    let ca_certificate = ca_params.self_signed(&ca_key).expect("the CA signs itself");

    let server_params = rcgen::CertificateParams::new(vec![server_name.to_owned()])
        .expect("the server name is a DNS name");
    let server_key = rcgen::KeyPair::generate().expect("a key pair is generated");
    let server_certificate = server_params
        .signed_by(&server_key, &ca_certificate, &ca_key)
        .expect("the CA signs the server certificate");

    let client_params = rcgen::CertificateParams::new(vec!["ono-sendai".to_owned()])
        .expect("the client name is a DNS name");
    let client_key = rcgen::KeyPair::generate().expect("a key pair is generated");
    let client_certificate = client_params
        .signed_by(&client_key, &ca_certificate, &ca_key)
        .expect("the CA signs the client certificate");

    Authority {
        ca_pem: ca_certificate.pem(),
        server_chain: vec![server_certificate.der().clone()],
        server_key: rustls::pki_types::PrivateKeyDer::try_from(server_key.serialize_der())
            .expect("rcgen writes a PKCS#8 key"),
        client_certificate_pem: client_certificate.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

// --- the server on the other end ---------------------------------------------------------------

/// A `rustls` server reachable as a [`ByteStream`], driven inside the caller's thread.
///
/// Every write hands the bytes to the server connection and every read takes whatever the server
/// produced, so one thread runs both ends and the test is deterministic. No socket, no timing,
/// no sleep: §59.1's "no cluster" applied to a handshake.
struct LoopbackServer {
    connection: rustls::ServerConnection,
    outbound: Vec<u8>,
    received: Vec<u8>,
    reply: Vec<u8>,
    replied: bool,
}

impl LoopbackServer {
    fn new(authority: &Authority, reply: &[u8]) -> Self {
        Self::with_client_auth(authority, reply, false)
    }

    /// A server that demands a client certificate signed by the same authority.
    fn demanding_a_client_certificate(authority: &Authority, reply: &[u8]) -> Self {
        Self::with_client_auth(authority, reply, true)
    }

    fn with_client_auth(authority: &Authority, reply: &[u8], client_auth: bool) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("the ring provider supports the default versions");
        let builder = if client_auth {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in
                rustls_pemfile::certs(&mut authority.ca_pem.as_bytes()).map(Result::unwrap)
            {
                roots.add(certificate).expect("the CA is usable as a root");
            }
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                )
                .build()
                .expect("the client verifier builds"),
            )
        } else {
            builder.with_no_client_auth()
        };
        let config = builder
            .with_single_cert(
                authority.server_chain.clone(),
                authority.server_key.clone_key(),
            )
            .expect("the server certificate matches its key");
        Self {
            connection: rustls::ServerConnection::new(Arc::new(config))
                .expect("the server configuration is usable"),
            outbound: Vec::new(),
            received: Vec::new(),
            reply: reply.to_vec(),
            replied: false,
        }
    }

    /// What the server decrypted out of the session.
    fn received(&self) -> &[u8] {
        &self.received
    }

    /// The certificate the client presented, where the server asked for one.
    fn peer_certificates(&self) -> usize {
        self.connection
            .peer_certificates()
            .map_or(0, <[rustls::pki_types::CertificateDer<'_>]>::len)
    }

    /// Moves whatever the server wants to say into [`Self::outbound`].
    fn pump(&mut self) {
        while self.connection.wants_write() {
            if self.connection.write_tls(&mut self.outbound).is_err() {
                return;
            }
        }
    }
}

impl ByteStream for LoopbackServer {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let mut cursor = bytes;
        while !cursor.is_empty() {
            self.connection
                .read_tls(&mut cursor)
                .map_err(|error| StreamError::new(error.to_string()))?;
            self.connection
                .process_new_packets()
                .map_err(|error| StreamError::new(error.to_string()))?;
        }
        let mut plaintext = Vec::new();
        // `WouldBlock` is "nothing decrypted yet", which is the normal case mid-handshake.
        let _ = self.connection.reader().read_to_end(&mut plaintext);
        if !plaintext.is_empty() {
            self.received.extend_from_slice(&plaintext);
            if !self.replied {
                self.replied = true;
                self.connection
                    .writer()
                    .write_all(&self.reply)
                    .map_err(|error| StreamError::new(error.to_string()))?;
            }
        }
        self.pump();
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, StreamError> {
        if self.outbound.is_empty() {
            self.pump();
        }
        let wanted = buf.len().min(self.outbound.len());
        buf[..wanted].copy_from_slice(&self.outbound[..wanted]);
        self.outbound.drain(..wanted);
        Ok(wanted)
    }
}

// --- a stream that only fails --------------------------------------------------------------

/// A byte stream whose every operation fails, for the adapter's error path.
struct BrokenStream;

impl ByteStream for BrokenStream {
    fn write_all(&mut self, _bytes: &[u8]) -> Result<(), StreamError> {
        Err(StreamError::new("the broker refused the write"))
    }

    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, StreamError> {
        Err(StreamError::new("the broker refused the read"))
    }
}

// --- trust anchors ---------------------------------------------------------------------------

#[test]
fn should_pin_the_kubeconfigs_certificate_authority_as_the_only_root() {
    let authority = authority("cluster.test");
    let anchors = Anchors::for_trust(&Trust::CertificateAuthority(
        authority.ca_pem.clone().into_bytes(),
    ))
    .expect("a PEM certificate authority is usable");
    let settings = TlsSettings::verifying(&anchors, None).expect("the settings build");

    assert!(settings.verifies_certificates());
    // Exactly one: a pinned CA replaces the platform store rather than joining it. A cluster
    // whose kubeconfig names its own CA is not additionally reachable by anything a laptop
    // happens to trust.
    assert_eq!(settings.trust_anchor_count(), 1);
}

#[test]
fn should_trust_the_platform_store_when_the_kubeconfig_pins_nothing() {
    let anchors = Anchors::for_trust(&Trust::SystemRoots).expect("system roots are available");
    let settings = TlsSettings::verifying(&anchors, None).expect("the settings build");

    assert!(settings.verifies_certificates());
    // The number is whatever the bundled root set holds; what this asserts is that it is a
    // populated store and not an empty one that would refuse every cluster.
    assert!(
        settings.trust_anchor_count() > 20,
        "the platform store should hold the usual public roots, and it held {}",
        settings.trust_anchor_count()
    );
}

#[test]
fn should_refuse_a_malformed_certificate_authority_rather_than_falling_back_to_the_platform_store()
{
    // The silent downgrade this pins down: a kubeconfig pins a CA, the bytes do not parse, and a
    // lenient implementation quietly verifies against the platform store instead. The operator
    // asked for one thing and got another, and nothing said so.
    let error = Anchors::for_trust(&Trust::CertificateAuthority(b"not a certificate".to_vec()))
        .expect_err("a CA that is not a PEM certificate is refused");

    assert!(matches!(error, TlsError::CertificateAuthority(_)));
    assert!(
        error.to_string().contains("certificate authority"),
        "the message should say what was refused: {error}"
    );
}

#[test]
fn should_refuse_an_empty_certificate_authority_bundle() {
    // A PEM file that parses but holds no certificate is the same downgrade with better
    // punctuation: an empty root store trusts nothing, and an implementation that treats it as
    // "no pin" trusts everything the platform does.
    let error = Anchors::for_trust(&Trust::CertificateAuthority(
        b"-----BEGIN CERTIFICATE-----\n".to_vec(),
    ))
    .expect_err("a bundle with no certificate in it is refused");

    assert!(matches!(error, TlsError::CertificateAuthority(_)));
}

#[test]
fn should_refuse_to_read_a_certificate_authority_from_a_file() {
    // This module performs no I/O. The caller reads the file — under the host's `filesystem.read`
    // capability, which is the whole reason the read is not hidden down here.
    let error = Anchors::for_trust(&Trust::CertificateAuthorityFile(
        "/etc/k8s/ca.crt".to_owned(),
    ))
    .expect_err("this module opens no files");

    match &error {
        TlsError::CertificateAuthorityFile(path) => assert_eq!(path, "/etc/k8s/ca.crt"),
        other => panic!("the refusal should name the path, and it was {other:?}"),
    }
    assert!(
        error.to_string().contains("/etc/k8s/ca.crt"),
        "the message should name the file the caller has to read: {error}"
    );
}

#[test]
fn should_not_disable_verification_through_the_ordinary_constructor() {
    // §8.4: insecure TLS is honoured only when explicitly configured. `Trust::Insecure` is
    // explicit in the kubeconfig, and it still does not flow into a configuration through the
    // path every other trust setting takes — the caller has to name the insecure constructor.
    let error = Anchors::for_trust(&Trust::Insecure)
        .expect_err("the ordinary path never produces an unverified session");

    assert!(matches!(error, TlsError::InsecureNotRequestedExplicitly));
    assert!(
        error
            .to_string()
            .contains("without_certificate_verification"),
        "the refusal should name the constructor that does it: {error}"
    );
}

#[test]
fn should_disable_verification_only_through_the_constructor_that_says_so() {
    let settings = TlsSettings::without_certificate_verification(None)
        .expect("the insecure configuration builds");

    assert!(!settings.verifies_certificates());
    // Nothing is trusted because nothing is checked: an anchor count above zero here would
    // suggest a verification that is not happening.
    assert_eq!(settings.trust_anchor_count(), 0);
    assert!(
        format!("{settings:?}").contains("insecure"),
        "a diagnostic must be able to say so prominently (§8.4): {settings:?}"
    );
}

// --- client certificates ---------------------------------------------------------------------

#[test]
fn should_carry_a_client_certificate_into_the_configuration() {
    let authority = authority("cluster.test");
    let identity = ClientIdentity::new(
        authority.client_certificate_pem.as_bytes(),
        &Secret::new(authority.client_key_pem.clone()),
    )
    .expect("an rcgen certificate and its key are usable");
    let anchors = Anchors::for_trust(&Trust::CertificateAuthority(
        authority.ca_pem.clone().into_bytes(),
    ))
    .expect("the CA is usable");
    let settings = TlsSettings::verifying(&anchors, Some(&identity)).expect("the settings build");

    assert!(settings.has_client_certificate());
    assert_eq!(identity.chain_length(), 1);
    assert!(
        !TlsSettings::verifying(&anchors, None)
            .expect("the settings build")
            .has_client_certificate(),
        "a context with no client certificate must not acquire one"
    );
}

#[test]
fn should_keep_a_client_key_out_of_a_diagnostic() {
    let authority = authority("cluster.test");
    let identity = ClientIdentity::new(
        authority.client_certificate_pem.as_bytes(),
        &Secret::new(authority.client_key_pem.clone()),
    )
    .expect("the identity is usable");

    let rendered = format!("{identity:?}");
    assert!(
        !rendered.contains("PRIVATE KEY"),
        "a private key must not reach a diagnostic (§8.1): {rendered}"
    );
    assert!(rendered.contains("redacted"), "{rendered}");
}

#[test]
fn should_refuse_a_client_key_that_is_not_a_private_key() {
    let authority = authority("cluster.test");
    let error = ClientIdentity::new(
        authority.client_certificate_pem.as_bytes(),
        &Secret::new("-----BEGIN CERTIFICATE-----\nnonsense\n".to_owned()),
    )
    .expect_err("a certificate is not a private key");

    assert!(matches!(error, TlsError::ClientIdentity(_)));
}

#[test]
fn should_refuse_a_client_certificate_that_is_not_a_certificate() {
    let authority = authority("cluster.test");
    let error = ClientIdentity::new(
        b"not a certificate",
        &Secret::new(authority.client_key_pem.clone()),
    )
    .expect_err("a client identity needs a certificate");

    assert!(matches!(error, TlsError::ClientIdentity(_)));
}

// --- the std::io adapter -----------------------------------------------------------------------

#[test]
fn should_read_and_write_a_byte_stream_through_the_std_io_adapter() {
    let mut bridge = IoBridge::new(FixtureStream::new(b"hello from the server"));
    bridge
        .write_all(b"GET /api HTTP/1.1\r\n\r\n")
        .expect("the fixture takes the bytes");
    bridge.flush().expect("a byte stream has nothing to flush");

    let mut received = Vec::new();
    bridge
        .read_to_end(&mut received)
        .expect("the fixture replays what it holds");

    assert_eq!(received, b"hello from the server");
    assert_eq!(
        bridge.get_ref().written_text(),
        "GET /api HTTP/1.1\r\n\r\n",
        "everything written must reach the stream underneath"
    );
    // `read_to_end` stopped because the fixture ended, which is `read(2)`'s `Ok(0)`.
    assert_eq!(bridge.read(&mut [0_u8; 8]).expect("end of stream"), 0);
}

#[test]
fn should_report_a_failing_byte_stream_as_an_io_error() {
    let mut bridge = IoBridge::new(BrokenStream);
    let error = bridge
        .write_all(b"anything")
        .expect_err("the stream refuses everything");

    assert!(
        error.to_string().contains("the broker refused the write"),
        "what the transport said must survive the adapter: {error}"
    );
}

// --- the handshake -----------------------------------------------------------------------------

#[test]
fn should_complete_a_handshake_and_carry_bytes_both_ways() {
    let authority = authority("cluster.test");
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let server = LoopbackServer::new(&authority, reply);
    let anchors = Anchors::for_trust(&Trust::CertificateAuthority(
        authority.ca_pem.clone().into_bytes(),
    ))
    .expect("the CA is usable");
    let settings = TlsSettings::verifying(&anchors, None).expect("the settings build");

    let mut session = TlsStream::connect(server, "cluster.test", &settings)
        .expect("the server certificate chains to the pinned authority");
    session
        .write_all(b"GET /api HTTP/1.1\r\nHost: cluster.test\r\n\r\n")
        .expect("the request goes out encrypted");

    let mut received = vec![0_u8; reply.len()];
    let mut filled = 0;
    while filled < reply.len() {
        let read = session
            .read(&mut received[filled..])
            .expect("the answer arrives");
        assert_ne!(read, 0, "the session ended before the answer was complete");
        filled += read;
    }

    assert_eq!(received, reply);
    // The server saw plaintext, which it can only have done by decrypting: the bytes on the
    // stream were not the bytes the caller wrote.
    assert!(
        String::from_utf8_lossy(session.get_ref().received()).starts_with("GET /api"),
        "the server should have decrypted the request"
    );
}

#[test]
fn should_refuse_a_server_certificate_from_an_authority_the_kubeconfig_does_not_pin() {
    let cluster = authority("cluster.test");
    let stranger = authority("cluster.test");
    let server = LoopbackServer::new(&cluster, b"never sent");
    // The right name, the wrong authority: exactly the case certificate validation exists for.
    let anchors = Anchors::for_trust(&Trust::CertificateAuthority(
        stranger.ca_pem.clone().into_bytes(),
    ))
    .expect("the CA is usable");
    let settings = TlsSettings::verifying(&anchors, None).expect("the settings build");

    let error = TlsStream::connect(server, "cluster.test", &settings)
        .expect_err("an unknown issuer is not a cluster this provider talks to");

    assert!(matches!(error, TlsError::Handshake(_)), "{error:?}");
}

#[test]
fn should_refuse_a_certificate_issued_for_another_name() {
    let authority = authority("cluster.test");
    let server = LoopbackServer::new(&authority, b"never sent");
    let anchors = Anchors::for_trust(&Trust::CertificateAuthority(
        authority.ca_pem.clone().into_bytes(),
    ))
    .expect("the CA is usable");
    let settings = TlsSettings::verifying(&anchors, None).expect("the settings build");

    let error = TlsStream::connect(server, "other.test", &settings)
        .expect_err("a certificate for one cluster does not vouch for another");

    assert!(matches!(error, TlsError::Handshake(_)), "{error:?}");
}

#[test]
fn should_reach_an_unverifiable_server_only_when_verification_was_explicitly_disabled() {
    let cluster = authority("cluster.test");
    let stranger = authority("cluster.test");
    let reply = b"ok";

    // Verifying: refused, because the authority is unknown.
    let anchors = Anchors::for_trust(&Trust::CertificateAuthority(
        stranger.ca_pem.clone().into_bytes(),
    ))
    .expect("the CA is usable");
    let verifying = TlsSettings::verifying(&anchors, None).expect("the settings build");
    assert!(
        TlsStream::connect(
            LoopbackServer::new(&cluster, reply),
            "cluster.test",
            &verifying
        )
        .is_err()
    );

    // Insecure: reached, and the settings say out loud that nothing was checked.
    let insecure = TlsSettings::without_certificate_verification(None).expect("the settings build");
    let mut session = TlsStream::connect(
        LoopbackServer::new(&cluster, reply),
        "cluster.test",
        &insecure,
    )
    .expect("verification is off, so an unknown authority is not an obstacle");
    session.write_all(b"hello").expect("the request goes out");
    let mut received = [0_u8; 2];
    session.read(&mut received).expect("the answer comes back");
    assert_eq!(&received, reply);
}

#[test]
fn should_present_the_client_certificate_to_a_server_that_asks_for_one() {
    // The configuration test asserts the certificate reached the settings; this asserts it
    // reached the *server*, which is the claim §7.1 actually makes.
    let authority = authority("cluster.test");
    let reply = b"ok";
    let server = LoopbackServer::demanding_a_client_certificate(&authority, reply);
    let identity = ClientIdentity::new(
        authority.client_certificate_pem.as_bytes(),
        &Secret::new(authority.client_key_pem.clone()),
    )
    .expect("the identity is usable");
    let anchors = Anchors::for_trust(&Trust::CertificateAuthority(
        authority.ca_pem.clone().into_bytes(),
    ))
    .expect("the CA is usable");
    let settings = TlsSettings::verifying(&anchors, Some(&identity)).expect("the settings build");

    let mut session = TlsStream::connect(server, "cluster.test", &settings)
        .expect("both ends trust the same authority");
    // TLS 1.3 sends the client certificate with the client's first flight, and the server sees it
    // once it has processed application data.
    session.write_all(b"hello").expect("the request goes out");
    let mut received = [0_u8; 2];
    session.read(&mut received).expect("the answer comes back");

    assert_eq!(&received, reply);
    assert_eq!(
        session.get_ref().peer_certificates(),
        1,
        "the server should have been shown the context's client certificate"
    );
}

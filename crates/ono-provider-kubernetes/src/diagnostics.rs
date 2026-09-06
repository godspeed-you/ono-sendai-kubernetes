//! Which cluster is this, can it be reached, who am I to it, and what could not be determined.
//!
//! Specification §8.5, §8.6, §10, §34.3 and the last requirement of §61.1. A provider that can
//! read a cluster but cannot say *which* cluster it read is one context switch away from
//! answering a question about production with an answer from staging, and nothing in the value
//! stream would look wrong.
//!
//! Three rules shape everything below.
//!
//! **No signal is universally available.** §10.2 lists the evidence a cluster fingerprint *may*
//! rest on and then says in one sentence that none of it may be treated as always obtainable. So
//! a [`Fingerprint`] is not a value that is either present or absent: it is a set of named
//! signals, each of which is either obtained or unavailable *for a stated reason*, and the
//! composed digest says which parts it was built from. A cluster whose `kube-system` namespace
//! the caller may not read still has a fingerprint — a weaker one, and it says so.
//!
//! **A reason for not knowing is [`Outcome`], not a second vocabulary.** `coverage::Outcome`
//! already distinguishes the eight ways to come back with nothing, and "the API server refused
//! it" and "the API server does not serve it" are the same two states here that they are for a
//! listing (§21.4, §4 invariant 13). A diagnostic with its own words for the same distinctions
//! would let the two drift apart.
//!
//! **Failing to learn any of this is never fatal.** §8.6 says outright that failure to obtain the
//! effective identity MUST NOT block ordinary read operations, and the same reasoning covers the
//! rest: a diagnostic is an observation about the session, and an observation that cannot be made
//! is a stated unknown. Nothing in this module returns an error that a caller has to handle to
//! keep reading a cluster.

use std::fmt;
use std::time::Duration;

use crate::coverage::Outcome;
use crate::discovery::{Discovery, Verb};

// --- the signals a cluster can be recognised by --------------------------------------------------

/// One piece of evidence about which upstream cluster a provider instance is talking to (§10.2).
///
/// The three the specification names. A fourth would go here rather than into a caller, because
/// the point of a closed set is that two instances can be compared signal by signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Signal {
    /// The normalised API server origin — scheme, host and port, with the scheme's default port
    /// dropped so that `https://api.example:443` and `https://api.example` are one address.
    Origin,
    /// A SHA-256 over the server certificate's `SubjectPublicKeyInfo`.
    ///
    /// The public key rather than the whole certificate: a renewed certificate for the same
    /// cluster keeps its key far more often than not, and fingerprinting the certificate would
    /// report an ordinary rotation as a cluster replacement (§10.4).
    ServerPublicKey,
    /// The UID of the `kube-system` namespace, where the caller may read it.
    ///
    /// The closest thing Kubernetes has to a cluster identifier: it is created with the cluster
    /// and never recreated in a healthy one. It is also readable only with permission, which is
    /// why it is one signal among several rather than the answer.
    KubeSystemUid,
}

impl Signal {
    /// The word this signal is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::ServerPublicKey => "server-public-key",
            Self::KubeSystemUid => "kube-system-uid",
        }
    }

    /// Whether disagreement on this signal is evidence that two instances are different clusters.
    ///
    /// The origin is not. Two contexts can reach one cluster through an internal address and an
    /// external one, and a bastion, a load balancer or a `port-forward` changes the address
    /// without changing the cluster. So an origin that differs proves nothing, while an origin
    /// that matches is still worth reporting — that is exactly the accidental aliasing §10.2 is
    /// about. The two cryptographic and API-server-issued signals do decide.
    #[must_use]
    pub fn is_decisive(self) -> bool {
        matches!(self, Self::ServerPublicKey | Self::KubeSystemUid)
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Something the provider either learned, or did not learn for a reason it can name.
///
/// The alternative — `Option<T>` — makes "the API server refused it", "the API server does not
/// serve it" and "nobody asked" the same value, which is the collapse §21.4 forbids for objects
/// and which is no more acceptable for a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Known<T> {
    /// The provider obtained it.
    Obtained(T),
    /// It could not be obtained, and this is why.
    Unavailable(Outcome),
}

impl<T> Known<T> {
    /// The value, where there is one.
    #[must_use]
    pub fn obtained(&self) -> Option<&T> {
        match self {
            Self::Obtained(value) => Some(value),
            Self::Unavailable(_) => None,
        }
    }

    /// Why there is none, where there is none.
    #[must_use]
    pub fn outcome(&self) -> Option<Outcome> {
        match self {
            Self::Obtained(_) => None,
            Self::Unavailable(outcome) => Some(*outcome),
        }
    }

    /// Whether the provider learned it.
    #[must_use]
    pub fn is_obtained(&self) -> bool {
        matches!(self, Self::Obtained(_))
    }
}

impl<T> Default for Known<T> {
    /// Nobody asked. The starting state of every signal, so that a diagnostic which never runs a
    /// probe reports "not queried" rather than an absence it did not observe.
    fn default() -> Self {
        Self::Unavailable(Outcome::NotQueried)
    }
}

// --- the fingerprint -----------------------------------------------------------------------------

/// A non-secret fingerprint of the upstream cluster, composed of whatever was obtainable (§10.2).
///
/// Every field is a [`Known`], so the fingerprint of a cluster whose `kube-system` namespace is
/// unreadable is not missing — it is a fingerprint built from fewer signals, and
/// [`Fingerprint::obtained_signals`] says which. That distinction is the whole of §10.2's closing
/// sentence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fingerprint {
    origin: Known<String>,
    server_public_key: Known<String>,
    kube_system_uid: Known<String>,
}

impl Fingerprint {
    /// A fingerprint with nothing obtained yet: every signal is `not queried`.
    #[must_use]
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Records the normalised API server origin.
    #[must_use]
    pub fn with_origin(mut self, origin: Known<String>) -> Self {
        self.origin = origin;
        self
    }

    /// Records the server certificate's public-key fingerprint.
    #[must_use]
    pub fn with_server_public_key(mut self, key: Known<String>) -> Self {
        self.server_public_key = key;
        self
    }

    /// Records the `kube-system` namespace UID.
    #[must_use]
    pub fn with_kube_system_uid(mut self, uid: Known<String>) -> Self {
        self.kube_system_uid = uid;
        self
    }

    /// One signal, obtained or not.
    #[must_use]
    pub fn signal(&self, signal: Signal) -> &Known<String> {
        match signal {
            Signal::Origin => &self.origin,
            Signal::ServerPublicKey => &self.server_public_key,
            Signal::KubeSystemUid => &self.kube_system_uid,
        }
    }

    /// Every signal, in a fixed order, so that two fingerprints are compared the same way twice.
    #[must_use]
    pub fn signals() -> [Signal; 3] {
        [
            Signal::Origin,
            Signal::ServerPublicKey,
            Signal::KubeSystemUid,
        ]
    }

    /// The signals this fingerprint actually holds.
    #[must_use]
    pub fn obtained_signals(&self) -> Vec<Signal> {
        Self::signals()
            .into_iter()
            .filter(|signal| self.signal(*signal).is_obtained())
            .collect()
    }

    /// Whether any signal at all was obtained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.obtained_signals().is_empty()
    }

    /// A single token over the signals that were obtained, or `None` when none were.
    ///
    /// `None` rather than a digest of nothing: a hash of the empty string is a perfectly stable
    /// value that every unidentifiable cluster would share, and two clusters that agree only in
    /// having told the provider nothing are not an observed alias.
    ///
    /// The token is not the comparison. [`Fingerprint::compare`] works signal by signal, because
    /// two instances may hold different subsets of the evidence and a digest over different
    /// subsets differs for a reason that has nothing to do with the cluster.
    #[must_use]
    pub fn digest(&self) -> Option<String> {
        let mut material = String::new();
        for signal in Self::signals() {
            if let Some(value) = self.signal(signal).obtained() {
                material.push_str(signal.as_str());
                material.push('=');
                material.push_str(value);
                material.push('\n');
            }
        }
        if material.is_empty() {
            return None;
        }
        Some(sha256_hex(material.as_bytes()))
    }

    /// Whether two provider instances appear to be pointed at one cluster (§10.3).
    ///
    /// The verdict names the signals it rests on, because "possible alias" from a shared origin
    /// and "possible alias" from a shared `kube-system` UID are the same word for very different
    /// evidence.
    ///
    /// There is deliberately no operation on this type that merges two instances. §10.3 forbids
    /// it in one sentence — credentials and effective permissions differ, so what one instance
    /// may read says nothing about the other — and a function nobody can call is a stronger
    /// guarantee than a comment saying not to.
    #[must_use]
    pub fn compare(&self, other: &Self) -> AliasVerdict {
        let mut agreed = Vec::new();
        let mut disagreed = Vec::new();
        for signal in Self::signals() {
            let (Some(mine), Some(theirs)) = (
                self.signal(signal).obtained(),
                other.signal(signal).obtained(),
            ) else {
                continue;
            };
            if mine == theirs {
                agreed.push(signal);
            } else {
                disagreed.push(signal);
            }
        }
        let verdict = if disagreed.iter().any(|signal| signal.is_decisive()) {
            Alias::Distinct
        } else if agreed.iter().any(|signal| signal.is_decisive()) || !agreed.is_empty() {
            Alias::Possible
        } else {
            Alias::Undetermined
        };
        AliasVerdict {
            verdict,
            agreed,
            disagreed,
        }
    }
}

/// What comparing two fingerprints concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alias {
    /// The evidence they share agrees: they may be one cluster, reached twice.
    ///
    /// "May". §10.3 permits reporting the possibility and forbids acting on it, so this is never
    /// a licence to treat the two instances as one.
    Possible,
    /// A decisive signal disagrees: they are different clusters.
    Distinct,
    /// They share no signal, or share only an origin that differs. Nothing can be said.
    Undetermined,
}

impl Alias {
    /// The words this verdict is reported in.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Possible => "possible alias",
            Self::Distinct => "different clusters",
            Self::Undetermined => "undetermined",
        }
    }
}

/// A comparison of two fingerprints, with the evidence it rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasVerdict {
    verdict: Alias,
    agreed: Vec<Signal>,
    disagreed: Vec<Signal>,
}

impl AliasVerdict {
    /// The conclusion.
    #[must_use]
    pub fn verdict(&self) -> Alias {
        self.verdict
    }

    /// The signals both instances obtained and agree on.
    #[must_use]
    pub fn agreed(&self) -> &[Signal] {
        &self.agreed
    }

    /// The signals both instances obtained and disagree on.
    #[must_use]
    pub fn disagreed(&self) -> &[Signal] {
        &self.disagreed
    }

    /// The verdict and its evidence, in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        let words = |signals: &[Signal]| {
            signals
                .iter()
                .map(|signal| signal.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match (self.agreed.is_empty(), self.disagreed.is_empty()) {
            (true, true) => format!("{}: no signal in common", self.verdict.as_str()),
            (false, true) => format!("{}: {} agree", self.verdict.as_str(), words(&self.agreed)),
            (true, false) => format!(
                "{}: {} disagree",
                self.verdict.as_str(),
                words(&self.disagreed)
            ),
            (false, false) => format!(
                "{}: {} agree, {} disagree",
                self.verdict.as_str(),
                words(&self.agreed),
                words(&self.disagreed)
            ),
        }
    }
}

/// The API server origin, normalised so that two spellings of one address compare equal (§10.2).
///
/// Lower-cases the scheme and the host, drops a trailing dot from a fully qualified name, and
/// writes the port only where it is not the scheme's own. An address that is written differently
/// in two kubeconfigs is the ordinary case, not the exception, and an unnormalised origin would
/// make the weakest signal weaker still.
#[must_use]
pub fn normalised_origin(scheme: &str, host: &str, port: u16) -> String {
    let scheme = scheme.to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let default = match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => 0,
    };
    if port == default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

/// A SHA-256 over the `SubjectPublicKeyInfo` of a DER-encoded X.509 certificate.
///
/// The key rather than the certificate, for the reason [`Signal::ServerPublicKey`] gives. The
/// structure is walked rather than parsed by a library because the walk is six fields deep and
/// adding an X.509 parser to reach one of them would widen the supply chain for a hash.
///
/// Returns `None` for anything that is not a certificate this walk understands — a fingerprint
/// that cannot be computed is a signal that was not obtained, never a failure that stops a read.
#[must_use]
pub fn public_key_fingerprint(certificate_der: &[u8]) -> Option<String> {
    Some(sha256_hex(subject_public_key_info(certificate_der)?))
}

/// The raw `SubjectPublicKeyInfo` of a DER-encoded X.509 certificate.
///
/// `Certificate` is a `SEQUENCE` whose first element is the `TBSCertificate`, itself a `SEQUENCE`
/// of an optional `[0] version`, a serial number, and then four `SEQUENCE`s — signature
/// algorithm, issuer, validity, subject — before the key. Nothing before the key is variable
/// enough to need decoding, so each is skipped by its own length.
fn subject_public_key_info(certificate_der: &[u8]) -> Option<&[u8]> {
    let mut certificate = Der::new(sequence_body(certificate_der)?);
    let mut tbs = Der::new(sequence_body(certificate.next()?)?);
    // `[0] EXPLICIT Version` opens every v2 and v3 certificate; a v1 one opens at the serial
    // number, which is why the first element is examined rather than counted.
    if tbs.next()?.first() == Some(&0xA0) {
        tbs.next()?;
    }
    // Signature algorithm, issuer, validity and subject stand between the serial number and the
    // key. None of them is variable enough to need decoding, so each is skipped by its length.
    for _ in 0..4 {
        tbs.next()?;
    }
    tbs.next()
}

/// The contents of a DER `SEQUENCE`, or `None` for anything else.
fn sequence_body(der: &[u8]) -> Option<&[u8]> {
    if der.first() != Some(&0x30) {
        return None;
    }
    let (_, body) = split_element(der)?;
    Some(body)
}

/// A reader over a sequence of DER elements, handing back each one whole — tag, length and all.
struct Der<'der> {
    rest: &'der [u8],
}

impl<'der> Der<'der> {
    const fn new(der: &'der [u8]) -> Self {
        Self { rest: der }
    }

    /// The next element, or `None` at the end of the input and on anything malformed.
    fn next(&mut self) -> Option<&'der [u8]> {
        let (length, _) = split_element(self.rest)?;
        let taken = self.rest.get(..length)?;
        self.rest = self.rest.get(length..)?;
        Some(taken)
    }
}

/// Splits one DER element into its total length and its contents.
///
/// Long-form lengths of more than four bytes are refused rather than accumulated: a certificate
/// field longer than four gigabytes is not a certificate, and an unbounded shift is how a length
/// parser overflows.
fn split_element(der: &[u8]) -> Option<(usize, &[u8])> {
    let first_length_byte = *der.get(1)?;
    let (header, length) = if first_length_byte < 0x80 {
        (2usize, usize::from(first_length_byte))
    } else {
        let count = usize::from(first_length_byte & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = der.get(2..2 + count)?;
        let mut length = 0usize;
        for byte in bytes {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        (2 + count, length)
    };
    let total = header.checked_add(length)?;
    let body = der.get(header..total)?;
    Some((total, body))
}

/// A SHA-256 in lower-case hexadecimal.
///
/// `ring` because the TLS stack this crate already carries is built on it: a second hash
/// implementation would widen the supply chain to compute a digest the first one can compute.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        // Two hexadecimal digits per byte, written rather than formatted, so the width is not a
        // format string away from being wrong.
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    hex
}

/// The digits of lower-case hexadecimal.
const HEX: &[u8; 16] = b"0123456789abcdef";

// --- who the API server thinks the request is ----------------------------------------------------

/// The user information an API server associates with a request (§8.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    username: String,
    uid: Option<String>,
    groups: Vec<String>,
}

impl Subject {
    /// A subject with a username and whatever else was stated.
    #[must_use]
    pub fn new(username: impl Into<String>, uid: Option<String>, groups: Vec<String>) -> Self {
        Self {
            username: username.into(),
            uid,
            groups,
        }
    }

    /// What the API server calls this request's user.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The user's UID, where the authenticator provides one. Most do not.
    #[must_use]
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }

    /// The groups the request is a member of, as the API server resolved them.
    #[must_use]
    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    /// Reads a `SelfSubjectReview` response (§8.6).
    ///
    /// `None` for a body that is not one — including a `Status`, which is what an API server
    /// answers when it refuses. The caller has the status code and knows which of §21.4's states
    /// that was; this function is not the place to guess it from a body.
    #[must_use]
    pub fn from_self_subject_review(body: &[u8]) -> Option<Self> {
        let document: serde_json::Value = serde_json::from_slice(body).ok()?;
        let user = document.pointer("/status/userInfo")?;
        let username = user.get("username")?.as_str()?.to_owned();
        let uid = user
            .get("uid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let groups = user
            .get("groups")
            .and_then(serde_json::Value::as_array)
            .map(|groups| {
                groups
                    .iter()
                    .filter_map(|group| Some(group.as_str()?.to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self::new(username, uid, groups))
    }
}

/// Whether the session is asking the API server to act as somebody else (§8.5).
///
/// Nothing in this build sets [`Impersonation::Active`], and the variant exists anyway. §8.5's
/// requirement is that the credential identity and the effective identity be *impossible to
/// confuse*, and a shape that has one identity field today grows a second one the day
/// impersonation is added — at which point every reader of the diagnostic silently changes
/// meaning, because the field they were reading stops being the one they thought. Two fields from
/// the start cost one line each and cannot be misread later: when nothing is impersonated they
/// carry the same answer, and when something is they cannot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Impersonation {
    /// The request is made as the credential's own identity.
    #[default]
    Inactive,
    /// The request asks the API server to act as another subject.
    Active {
        /// The `Impersonate-User` the request carries.
        user: String,
        /// The `Impersonate-Group` headers it carries.
        groups: Vec<String>,
    },
}

impl Impersonation {
    /// Whether impersonation is configured. Always knowable locally, so never an unknown.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    /// The subject being impersonated, where there is one.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        match self {
            Self::Inactive => None,
            Self::Active { user, .. } => Some(user),
        }
    }
}

/// Who the provider is to this cluster (§8.5, §8.6).
///
/// Two identities, held apart. Without impersonation both are answered by the one
/// `SelfSubjectReview` the provider issues and carry the same subject; with impersonation the
/// credential identity is what a review issued *without* the impersonation headers reports and
/// the effective identity is what one issued *with* them reports. The two are therefore never the
/// same field, and a reader cannot mistake one for the other by reading the only one that exists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    credential: Known<Subject>,
    effective: Known<Subject>,
    impersonation: Impersonation,
}

impl Identity {
    /// An identity nothing has been learned about yet.
    #[must_use]
    pub fn unknown() -> Self {
        Self::default()
    }

    /// The identity of the credential itself, before any impersonation.
    #[must_use]
    pub fn with_credential(mut self, credential: Known<Subject>) -> Self {
        self.credential = credential;
        self
    }

    /// The identity the API server associates with the requests this session makes.
    #[must_use]
    pub fn with_effective(mut self, effective: Known<Subject>) -> Self {
        self.effective = effective;
        self
    }

    /// What the session is impersonating, if anything.
    #[must_use]
    pub fn with_impersonation(mut self, impersonation: Impersonation) -> Self {
        self.impersonation = impersonation;
        self
    }

    /// The credential's own identity.
    #[must_use]
    pub fn credential(&self) -> &Known<Subject> {
        &self.credential
    }

    /// The identity the API server acts on.
    #[must_use]
    pub fn effective(&self) -> &Known<Subject> {
        &self.effective
    }

    /// Whether the two can differ.
    #[must_use]
    pub fn impersonation(&self) -> &Impersonation {
        &self.impersonation
    }
}

// --- health ----------------------------------------------------------------------------------------

/// What `/version` reports about the API server.
///
/// Kept as the server wrote it. §5.3 forbids rejecting a cluster whose `gitVersion` is unfamiliar,
/// and the reliable way not to reject one is not to interpret the string at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerVersion {
    git_version: String,
    major: Option<String>,
    minor: Option<String>,
    platform: Option<String>,
}

impl ServerVersion {
    /// Reads a `/version` response.
    ///
    /// `None` for a body that carries no `gitVersion`, which is the only field this provider
    /// treats as the version.
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        let document: serde_json::Value = serde_json::from_slice(body).ok()?;
        let text = |key: &str| {
            document
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        Some(Self {
            git_version: text("gitVersion")?,
            major: text("major"),
            minor: text("minor"),
            platform: text("platform"),
        })
    }

    /// The version string the server reports, verbatim.
    #[must_use]
    pub fn git_version(&self) -> &str {
        &self.git_version
    }

    /// The major version, where the server states one separately.
    #[must_use]
    pub fn major(&self) -> Option<&str> {
        self.major.as_deref()
    }

    /// The minor version, where the server states one separately.
    ///
    /// Kept as text: upstream writes `32+` for a patched build, and a number cannot hold that.
    #[must_use]
    pub fn minor(&self) -> Option<&str> {
        self.minor.as_deref()
    }

    /// The platform the API server runs on, where it states one.
    #[must_use]
    pub fn platform(&self) -> Option<&str> {
        self.platform.as_deref()
    }
}

/// How one request to the API server ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// The server answered, with this status code. A `403` is an answer.
    Answered(u16),
    /// It did not answer, for a reason in the shared vocabulary.
    DidNotAnswer(Outcome),
}

impl ProbeStatus {
    /// The words this status is reported in.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Answered(code) => format!("answered {code}"),
            Self::DidNotAnswer(outcome) => outcome.as_str().to_owned(),
        }
    }

    /// Whether the server answered at all, whatever it said.
    #[must_use]
    pub fn is_answer(self) -> bool {
        matches!(self, Self::Answered(_))
    }
}

/// One request, its source and how long it took (§34.3).
///
/// The source is the path rather than "the cluster": an aggregated API server behind
/// `/apis/metrics.k8s.io` has its own availability, and attributing its timeout to the cluster
/// sends an operator to look at the wrong thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    source: String,
    status: ProbeStatus,
    latency: Option<Duration>,
}

impl Probe {
    /// Records one request.
    #[must_use]
    pub fn new(source: impl Into<String>, status: ProbeStatus, latency: Option<Duration>) -> Self {
        Self {
            source: source.into(),
            status,
            latency,
        }
    }

    /// Which endpoint answered, or did not.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// How it ended.
    #[must_use]
    pub fn status(&self) -> ProbeStatus {
        self.status
    }

    /// How long it took, where the caller measured it.
    #[must_use]
    pub fn latency(&self) -> Option<Duration> {
        self.latency
    }

    /// The source and what happened, in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        match self.latency {
            None => format!("{}: {}", self.source, self.status.describe()),
            Some(latency) => format!(
                "{}: {} in {} ms",
                self.source,
                self.status.describe(),
                latency.as_millis()
            ),
        }
    }
}

/// Whether the cluster answers, what it says it is, and which of its endpoints were reached.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Health {
    version: Known<ServerVersion>,
    probes: Vec<Probe>,
}

impl Health {
    /// A cluster nothing has been asked of yet.
    #[must_use]
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Records what `/version` reported.
    #[must_use]
    pub fn with_version(mut self, version: Known<ServerVersion>) -> Self {
        self.version = version;
        self
    }

    /// Records one request's source, outcome and latency.
    pub fn record(&mut self, probe: Probe) {
        self.probes.push(probe);
    }

    /// What the server says it is.
    #[must_use]
    pub fn version(&self) -> &Known<ServerVersion> {
        &self.version
    }

    /// Every request this diagnostic made, in the order it made them.
    #[must_use]
    pub fn probes(&self) -> &[Probe] {
        &self.probes
    }

    /// Whether the API server answered anything at all.
    ///
    /// Derived from the probes rather than stored, so that "reachable" cannot claim something no
    /// request supports. A `403` counts: a server that refuses is a server that is there, and the
    /// two are different problems with different fixes (§21.4).
    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.probes.iter().any(|probe| probe.status.is_answer())
    }
}

// --- the TLS posture, which §8.4 requires a diagnostic to show ---------------------------------

/// What protects the session, as the diagnostic must state it (§8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPosture {
    /// A TLS session whose server certificate was verified.
    Verified,
    /// A TLS session with certificate verification deliberately disabled.
    ///
    /// §8.4 requires the active insecure state to be visible in provider diagnostics, which is
    /// why this is a state of its own rather than `Verified` with a flag somewhere else.
    InsecureSkipVerify,
    /// No TLS at all, which reaches an API server only through a local proxy.
    None,
}

impl TlsPosture {
    /// The words this posture is reported in.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::InsecureSkipVerify => "insecure: certificate verification disabled",
            Self::None => "none: plain HTTP/1.1",
        }
    }

    /// Whether the session is protected by a verified certificate.
    #[must_use]
    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

// --- what this provider can do, and what this session found (§57, §57.1) -----------------------

/// One capability this provider reports on, in the words §57's manifest sketch lists it under.
///
/// A closed set, and every member of it is reported every time. §57 sketches a manifest that
/// declares `watch`, `relationships`, `mutations`, `remote_logs`, `remote_exec` and
/// `port_forward`; an operator who asks "can this thing exec" is owed the answer *no* rather than
/// silence, so the three this provider refuses by construction are in the list beside the ones it
/// implements (§42.3 to §42.5, ADR-0018).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderCapability {
    /// Observing a collection as it changes (§19).
    Watch,
    /// Contributing the spatial edges `near` and `follow` travel along (§35.5, §35.6).
    Relationships,
    /// Changing an object through the API server (§43).
    Mutations,
    /// Reading container logs (§42.1).
    RemoteLogs,
    /// Asking the API server whether this identity may perform an action (§21.2).
    SubjectAccessReview,
    /// Running a command inside a container (§42.3).
    RemoteExec,
    /// Attaching to a running container's streams (§42.4).
    Attach,
    /// Forwarding a local port into the cluster (§42.5).
    PortForward,
}

impl ProviderCapability {
    /// The word this capability is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Relationships => "relationships",
            Self::Mutations => "mutations",
            Self::RemoteLogs => "remote logs",
            Self::SubjectAccessReview => "subject access review",
            Self::RemoteExec => "remote exec",
            Self::Attach => "attach",
            Self::PortForward => "port forward",
        }
    }

    /// Whether the *package* implements this at all — §26.1's first layer of the inherited
    /// contract, and the half §57's manifest declares.
    ///
    /// A constant of this build rather than an observation. §42.6 forbids reaching a cluster
    /// through a `kubectl` subprocess and this package speaks HTTP/1.1 of its own, so the three
    /// stream protocols upstream carries over SPDY or WebSocket are refusals in the type system
    /// (ADR-0018) — and no cluster, grant or permission can turn one of them into a capability.
    #[must_use]
    pub fn support(self) -> Support {
        match self {
            Self::Watch
            | Self::Relationships
            | Self::Mutations
            | Self::RemoteLogs
            | Self::SubjectAccessReview => Support::ByProvider,
            Self::RemoteExec | Self::Attach | Self::PortForward => Support::NotByProvider,
        }
    }

    /// Every capability this provider reports on, in one fixed order.
    #[must_use]
    pub fn all() -> [Self; 8] {
        [
            Self::Watch,
            Self::Relationships,
            Self::Mutations,
            Self::RemoteLogs,
            Self::SubjectAccessReview,
            Self::RemoteExec,
            Self::Attach,
            Self::PortForward,
        ]
    }
}

impl fmt::Display for ProviderCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the package implements a capability, independently of any session (§26.1, §57).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// The package implements it. Whether *this* session has it is the other half.
    ByProvider,
    /// The package does not implement it, so no cluster and no grant can supply it (§26.3).
    NotByProvider,
}

impl Support {
    /// The words this half is reported in — §57.1's own.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ByProvider => "supported by provider",
            Self::NotByProvider => "not supported by provider",
        }
    }
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the host answered when asked whether a grant is in place (§51.1).
///
/// Three states because the host has three answers and asking never prompts: a capability the
/// operator has not decided about is withheld *now* and is not a refusal, and a host that cannot
/// say has denied nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// The grant is in place.
    Held,
    /// It is not. Either the operator denied it, or nothing has granted it and a prompt would be
    /// needed — which is not a grant.
    Withheld,
    /// The host could not say.
    Undetermined,
}

/// What *this session* found for one capability — §26.1's second layer.
///
/// Every variant names the evidence it was earned from, and there is no variant meaning "this
/// identity is authorized". Authorization is per object and the API server's to answer (§21.1,
/// §21.2); the strongest thing discovery supports is that a resource *offers* a verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// A resource this cluster serves offers the verb or subresource the capability needs.
    ///
    /// §57.1's own words, and they are a statement about the resource. `patch` appearing in a
    /// resource's verb list does not mean the current identity may send one.
    AvailableOnResource,
    /// The host holds the grant this capability needs.
    GrantedByLocalPolicy,
    /// The host withholds it. §57.1's third line, and §26.4 of the inherited contract: a package
    /// that supports something the host blocks is not an unsupported package.
    BlockedByLocalPolicy,
    /// The API server refused this identity the evidence the capability rests on (§21.4).
    DeniedForCurrentUser,
    /// The evidence was read, and nothing this cluster serves offers it (§11.5).
    NotServedByCluster,
    /// No evidence was gathered, with §21.4's word for why. `not queried` is the ordinary one,
    /// and it is a different answer from a denial and from an absence (§4 invariant 13).
    NotDetermined(Outcome),
    /// The provider does not implement it, so no session has it (§26.3).
    UnavailableInAnySession,
}

impl Availability {
    /// What a resource list says about a verb any resource might offer (§11.1).
    ///
    /// Available when one served resource offers one of `verbs`. The snapshot is discovery's
    /// answer rather than this build's assumption, so a cluster that serves no writable resource
    /// reports that rather than a capability that fails on first use.
    #[must_use]
    pub fn offered_verb(served: &Discovery, verbs: &[Verb]) -> Self {
        let offered = served
            .all()
            .any(|resource| verbs.iter().any(|verb| resource.supports(*verb)));
        if offered {
            Self::AvailableOnResource
        } else {
            Self::NotServedByCluster
        }
    }

    /// What a resource list says about one kind and one verb (§11.1).
    #[must_use]
    pub fn offered_on(served: &Discovery, group_version: &str, kind: &str, verb: Verb) -> Self {
        match served.by_kind(group_version, kind) {
            Some(resource) if resource.supports(verb) => Self::AvailableOnResource,
            Some(_) | None => Self::NotServedByCluster,
        }
    }

    /// What a resource list says about a subresource — `pods/log` for §42.1's logs.
    #[must_use]
    pub fn offered_subresource(
        served: &Discovery,
        group_version: &str,
        plural: &str,
        subresource: &str,
    ) -> Self {
        match served.resource(group_version, plural) {
            Some(resource) if resource.subresources().iter().any(|sub| sub == subresource) => {
                Self::AvailableOnResource
            }
            Some(_) | None => Self::NotServedByCluster,
        }
    }

    /// What the host's answer about a grant says (§51.1, §57.1).
    #[must_use]
    pub fn from_grant(grant: Grant) -> Self {
        match grant {
            Grant::Held => Self::GrantedByLocalPolicy,
            Grant::Withheld => Self::BlockedByLocalPolicy,
            // A host that cannot say has denied nothing, and reading its silence as a refusal is
            // the collapse §4 invariant 13 forbids.
            Grant::Undetermined => Self::NotDetermined(Outcome::NotQueried),
        }
    }

    /// The words this half is reported in.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::AvailableOnResource => "available on resource".to_owned(),
            Self::GrantedByLocalPolicy => "granted by local KUANG policy".to_owned(),
            Self::BlockedByLocalPolicy => "blocked by local KUANG policy".to_owned(),
            Self::DeniedForCurrentUser => "denied for current user".to_owned(),
            Self::NotServedByCluster => "not served by cluster".to_owned(),
            Self::NotDetermined(outcome) => format!("not determined: {}", outcome.as_str()),
            Self::UnavailableInAnySession => "unavailable in any session".to_owned(),
        }
    }
}

/// One capability, what the provider supports, and what this session found (§57.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityStatement {
    capability: ProviderCapability,
    availability: Availability,
}

impl CapabilityStatement {
    /// One capability's two halves.
    ///
    /// The session half of a capability the provider does not implement is
    /// [`Availability::UnavailableInAnySession`] whatever the caller passes, so no accumulation
    /// of cluster evidence can report an `exec` this build refuses as something an operator
    /// might get by fixing their RBAC (§26.3, ADR-0018).
    #[must_use]
    pub fn new(capability: ProviderCapability, availability: Availability) -> Self {
        let availability = match capability.support() {
            Support::ByProvider => availability,
            Support::NotByProvider => Availability::UnavailableInAnySession,
        };
        Self {
            capability,
            availability,
        }
    }

    /// Which capability this is about.
    #[must_use]
    pub fn capability(&self) -> ProviderCapability {
        self.capability
    }

    /// What the package implements.
    #[must_use]
    pub fn support(&self) -> Support {
        self.capability.support()
    }

    /// What this session found.
    #[must_use]
    pub fn availability(&self) -> Availability {
        self.availability
    }

    /// Both halves, in §57.1's shape.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{}, {}",
            self.support().as_str(),
            self.availability.describe()
        )
    }
}

/// Every capability, with both halves of each (§57.1).
///
/// Built by starting from what nothing has determined and recording each piece of evidence as it
/// arrives, so a capability whose evidence was never gathered says `not queried` rather than
/// inheriting a neighbour's answer or defaulting to available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    statements: Vec<CapabilityStatement>,
}

impl CapabilityReport {
    /// Every capability, with nothing gathered about any of them.
    #[must_use]
    pub fn unknown() -> Self {
        Self::undetermined(Outcome::NotQueried)
    }

    /// Every capability, with one reason why nothing about it could be gathered — `disconnected`
    /// for a cluster that never answered.
    #[must_use]
    pub fn undetermined(outcome: Outcome) -> Self {
        Self {
            statements: ProviderCapability::all()
                .into_iter()
                .map(|capability| {
                    CapabilityStatement::new(capability, Availability::NotDetermined(outcome))
                })
                .collect(),
        }
    }

    /// Records what one capability's evidence proved.
    #[must_use]
    pub fn with(mut self, capability: ProviderCapability, availability: Availability) -> Self {
        let statement = CapabilityStatement::new(capability, availability);
        for existing in &mut self.statements {
            if existing.capability() == capability {
                *existing = statement;
                return self;
            }
        }
        self.statements.push(statement);
        self
    }

    /// Every statement, in [`ProviderCapability::all`]'s order.
    #[must_use]
    pub fn statements(&self) -> &[CapabilityStatement] {
        &self.statements
    }

    /// One capability's statement.
    ///
    /// # Panics
    ///
    /// Never: a report holds a statement for every member of the closed set, and `with` replaces
    /// rather than appends.
    #[must_use]
    pub fn statement(&self, capability: ProviderCapability) -> &CapabilityStatement {
        self.statements
            .iter()
            .find(|statement| statement.capability() == capability)
            .unwrap_or_else(|| unreachable!("every capability is reported"))
    }

    /// What this session found for one capability.
    #[must_use]
    pub fn availability(&self, capability: ProviderCapability) -> Availability {
        self.statement(capability).availability()
    }
}

// --- the whole answer ----------------------------------------------------------------------------

/// One thing the provider could not determine, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    subject: String,
    outcome: Outcome,
}

impl Unknown {
    /// What could not be determined, and why.
    #[must_use]
    pub fn new(subject: impl Into<String>, outcome: Outcome) -> Self {
        Self {
            subject: subject.into(),
            outcome,
        }
    }

    /// What could not be determined.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Why not.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Both, in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}: {}", self.subject, self.outcome.as_str())
    }
}

/// Which cluster this provider instance is talking to, whether it answers, and who it is to it.
///
/// The answer to §61.1's last requirement, and it is one value rather than several because the
/// question an operator asks is one question. A diagnostic that answered "which cluster" without
/// "as whom" would be read as an authorisation answer it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterDiagnostic {
    instance: String,
    fingerprint: Fingerprint,
    identity: Identity,
    health: Health,
    tls: TlsPosture,
    capabilities: CapabilityReport,
}

impl ClusterDiagnostic {
    /// A diagnostic for one provider instance, before anything has been observed.
    ///
    /// The instance id is §10.1's stable local identity — `kubernetes:<context>` — and it is the
    /// one thing here that never comes from the cluster. That is deliberate: it is what stays
    /// stable across reconnects, and what two instances of one upstream cluster differ in.
    #[must_use]
    pub fn for_instance(instance: impl Into<String>, tls: TlsPosture) -> Self {
        Self {
            instance: instance.into(),
            fingerprint: Fingerprint::unknown(),
            identity: Identity::unknown(),
            health: Health::unknown(),
            tls,
            capabilities: CapabilityReport::unknown(),
        }
    }

    /// Records the cluster fingerprint.
    #[must_use]
    pub fn with_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    /// Records who the provider is to the cluster.
    #[must_use]
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = identity;
        self
    }

    /// Records what answered and what did not.
    #[must_use]
    pub fn with_health(mut self, health: Health) -> Self {
        self.health = health;
        self
    }

    /// Records what the provider supports and what this session found (§57.1).
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: CapabilityReport) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// The provider instance this describes (§6.2, §10.1).
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// What identifies the upstream cluster (§10.2).
    #[must_use]
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Who the provider is to it (§8.5, §8.6).
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Whether it answers, and what answered (§34.3).
    #[must_use]
    pub fn health(&self) -> &Health {
        &self.health
    }

    /// What protects the session (§8.4).
    #[must_use]
    pub fn tls(&self) -> TlsPosture {
        self.tls
    }

    /// What the provider supports, beside what this session found (§57.1).
    ///
    /// Two halves per capability, and neither is derived from the other. A diagnostic that has
    /// observed nothing reports `not queried` for every capability the provider implements —
    /// which is the answer, not a placeholder for one (§4 invariant 13, §21.4).
    #[must_use]
    pub fn capabilities(&self) -> &CapabilityReport {
        &self.capabilities
    }

    /// Everything this diagnostic could not determine, each with the reason.
    ///
    /// Derived from the observations rather than accumulated beside them, so the list cannot
    /// drift out of step with the fields it describes: a signal that is unavailable is in this
    /// list by construction, and one that is obtained cannot be.
    #[must_use]
    pub fn unknowns(&self) -> Vec<Unknown> {
        let mut unknowns = Vec::new();
        for signal in Fingerprint::signals() {
            if let Some(outcome) = self.fingerprint.signal(signal).outcome() {
                unknowns.push(Unknown::new(
                    format!("cluster fingerprint: {}", signal.as_str()),
                    outcome,
                ));
            }
        }
        if let Some(outcome) = self.health.version().outcome() {
            unknowns.push(Unknown::new("server version", outcome));
        }
        if let Some(outcome) = self.identity.credential().outcome() {
            unknowns.push(Unknown::new("credential identity", outcome));
        }
        if let Some(outcome) = self.identity.effective().outcome() {
            unknowns.push(Unknown::new("effective identity", outcome));
        }
        for probe in self.health.probes() {
            if let ProbeStatus::DidNotAnswer(outcome) = probe.status() {
                unknowns.push(Unknown::new(probe.source(), outcome));
            }
        }
        unknowns
    }
}

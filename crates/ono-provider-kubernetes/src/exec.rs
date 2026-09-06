//! Credential plugins: what the kubeconfig asks to be run, and what it must say back.
//!
//! Specification §8.2 and §8.3. Managed Kubernetes services almost all authenticate this way — a
//! kubeconfig names a helper, the helper prints an `ExecCredential`, and the token or certificate
//! inside it is what reaches the API server. Without it an EKS, GKE or AKS kubeconfig connects to
//! nothing at all.
//!
//! **Nothing here runs anything.** This module decides *whether* a helper may run, *what* it would
//! be run with, and *what* its output means; the running is a host call in the package, under an
//! explicit `process.exec` grant, because §8.2 requires exactly that:
//!
//! > Execution MUST occur only through an explicit KUANG/11 process-execution capability.
//!
//! That separation is the same one the rest of this crate is built on, and it is what makes the
//! three rules below testable without a subprocess: an interaction mode that refuses, an output
//! that is not an `ExecCredential`, and a credential that has already expired are all decisions
//! about values.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

use crate::kubeconfig::Secret;
use crate::transport::ObservedAt;

/// The API versions of the `ExecCredential` contract this provider speaks.
///
/// Both, because a kubeconfig written for an older cluster still names `v1beta1` and the two are
/// identical in the fields read here. An `apiVersion` outside this list is refused rather than
/// read hopefully: §8.3 says the output is "the Kubernetes `ExecCredential` contract, not
/// arbitrary CLI text", and a document claiming to be something else is not that contract.
const SPOKEN: &[&str] = &[
    "client.authentication.k8s.io/v1",
    "client.authentication.k8s.io/v1beta1",
];

/// When a credential plugin may take over the terminal (§8.2).
///
/// The three words are the kubeconfig's own. What makes them worth a type is the last rule of
/// §8.2: "a provider operating in a non-interactive context MUST NOT fake interactive stdin
/// availability" — so `Always` in a shell that has no terminal to lend is a refusal, not a
/// silently non-interactive run that will hang or fail confusingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InteractiveMode {
    /// The plugin never needs a terminal. Safe to run anywhere.
    #[default]
    Never,
    /// The plugin uses a terminal where one is available and copes without.
    IfAvailable,
    /// The plugin requires a terminal — a browser-based login flow, typically.
    Always,
}

impl InteractiveMode {
    /// The mode a kubeconfig spells, or [`None`] for a word this provider does not know.
    ///
    /// An unknown word is not defaulted to `Never`. `Never` is the permissive answer here — it is
    /// the one that lets the helper run — and defaulting an unrecognised mode to the permissive
    /// value is how a future spelling of "this needs a terminal" would come to run without one.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "Never" => Some(Self::Never),
            "IfAvailable" => Some(Self::IfAvailable),
            "Always" => Some(Self::Always),
            _ => None,
        }
    }

    /// The word this mode is written as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "Never",
            Self::IfAvailable => "IfAvailable",
            Self::Always => "Always",
        }
    }
}

impl fmt::Display for InteractiveMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a credential plugin was not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecRefusal {
    /// The kubeconfig's `exec` block does not read as one.
    Malformed(String),
    /// The `apiVersion` is not an `ExecCredential` contract this provider speaks.
    UnknownContract(String),
    /// The plugin requires a terminal and this invocation has none (§8.2).
    NeedsTerminal,
    /// The mode word is one this provider does not know, so whether it needs a terminal is
    /// unknown — and an unknown answer to that question is not a yes.
    UnknownMode(String),
    /// The helper answered with something that is not an `ExecCredential`.
    NotACredential(String),
    /// The helper answered with an `ExecCredential` carrying no credential at all.
    NoCredential,
    /// The credential the helper returned had already expired when it arrived.
    Expired {
        /// When it expired, as the helper stated it.
        at: String,
    },
}

impl fmt::Display for ExecRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "the `exec` block does not read: {detail}"),
            Self::UnknownContract(version) => write!(
                f,
                "`{version}` is not an `ExecCredential` contract this provider speaks"
            ),
            Self::NeedsTerminal => f.write_str(
                "the credential plugin declares `interactiveMode: Always` and this invocation has \
                 no terminal to give it",
            ),
            Self::UnknownMode(word) => {
                write!(f, "`{word}` is not an interaction mode this provider knows")
            }
            Self::NotACredential(detail) => {
                write!(
                    f,
                    "the credential plugin did not answer with an `ExecCredential`: {detail}"
                )
            }
            Self::NoCredential => f.write_str(
                "the credential plugin answered with an `ExecCredential` that carries neither a \
                 token nor a client certificate",
            ),
            Self::Expired { at } => {
                write!(f, "the credential the plugin returned expired at {at}")
            }
        }
    }
}

impl std::error::Error for ExecRefusal {}

/// What a kubeconfig's `exec` block asks to be run (§8.2).
///
/// The environment is the block's own `env` entries and nothing inherited: §51.3's least
/// authority applied to a subprocess, and the reason a helper that reads `AWS_PROFILE` from the
/// operator's shell will not see it. That is a deviation from `kubectl`'s behaviour and it is the
/// safe direction — a helper given an environment it did not ask for is a helper acting as
/// somebody the operator did not choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlugin {
    api_version: String,
    command: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    interactive_mode: InteractiveMode,
    provide_cluster_info: bool,
}

impl ExecPlugin {
    /// Reads a kubeconfig `exec` block.
    ///
    /// # Errors
    ///
    /// [`ExecRefusal::Malformed`] where the block is not one, [`ExecRefusal::UnknownContract`]
    /// where its `apiVersion` is not one of §8.3's, and [`ExecRefusal::UnknownMode`] where its
    /// `interactiveMode` is a word this provider does not know.
    pub fn parse(block: &serde_yaml_ng::Value) -> Result<Self, ExecRefusal> {
        let raw: RawExec = serde_yaml_ng::from_value(block.clone())
            .map_err(|error| ExecRefusal::Malformed(error.to_string()))?;
        if !SPOKEN.contains(&raw.api_version.as_str()) {
            return Err(ExecRefusal::UnknownContract(raw.api_version));
        }
        if raw.command.trim().is_empty() {
            return Err(ExecRefusal::Malformed(
                "the block names no command to run".to_owned(),
            ));
        }
        // Absent is `Never` — the kubeconfig contract's own default, and the one word here whose
        // absence has a documented meaning. A *present* word this provider does not know is a
        // refusal, because it is a statement whose content is unavailable.
        let interactive_mode = match raw.interactive_mode.as_deref() {
            None => InteractiveMode::Never,
            Some(word) => InteractiveMode::parse(word)
                .ok_or_else(|| ExecRefusal::UnknownMode(word.to_owned()))?,
        };
        Ok(Self {
            api_version: raw.api_version,
            command: raw.command,
            args: raw.args.unwrap_or_default(),
            env: raw
                .env
                .unwrap_or_default()
                .into_iter()
                .map(|entry| (entry.name, entry.value))
                .collect(),
            interactive_mode,
            provide_cluster_info: raw.provide_cluster_info.unwrap_or(false),
        })
    }

    /// The `ExecCredential` contract version this plugin speaks.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// The program to run.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Its arguments, in order.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// The environment the block declares, and nothing else.
    #[must_use]
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// When the plugin needs a terminal.
    #[must_use]
    pub fn interactive_mode(&self) -> InteractiveMode {
        self.interactive_mode
    }

    /// Whether the plugin asked to be told which cluster it is authenticating to.
    #[must_use]
    pub fn provides_cluster_info(&self) -> bool {
        self.provide_cluster_info
    }

    /// Whether this plugin may run where `interactive` says whether a terminal is available.
    ///
    /// § 8.2's last rule, as a decision rather than as a comment: `Always` without a terminal is a
    /// refusal. The alternative — running it anyway — is what "faking interactive stdin
    /// availability" means in practice, and its failure mode is a helper that blocks on a prompt
    /// nobody can see.
    ///
    /// # Errors
    ///
    /// [`ExecRefusal::NeedsTerminal`].
    pub fn may_run(&self, interactive: bool) -> Result<(), ExecRefusal> {
        match self.interactive_mode {
            InteractiveMode::Never | InteractiveMode::IfAvailable => Ok(()),
            InteractiveMode::Always if interactive => Ok(()),
            InteractiveMode::Always => Err(ExecRefusal::NeedsTerminal),
        }
    }
}

/// A kubeconfig `exec` block, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExec {
    #[serde(rename = "apiVersion")]
    api_version: String,
    command: String,
    args: Option<Vec<String>>,
    env: Option<Vec<RawEnv>>,
    #[serde(rename = "interactiveMode")]
    interactive_mode: Option<String>,
    #[serde(rename = "provideClusterInfo")]
    provide_cluster_info: Option<bool>,
    #[serde(rename = "installHint")]
    _install_hint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawEnv {
    name: String,
    value: String,
}

/// What a credential plugin answered with (§8.3).
///
/// The material is a [`Secret`] for the same reason every other credential in this crate is: §8.1
/// forbids it reaching a typed value, a log, a crash diagnostic, history or serialized session
/// state, and the way to keep it out of all five is to give it a type whose `Debug` does not
/// print it.
#[derive(Debug, Clone)]
pub struct ExecCredential {
    token: Option<Secret>,
    client_certificate: Option<Secret>,
    client_key: Option<Secret>,
    expires_at: Option<String>,
}

impl ExecCredential {
    /// Reads a credential plugin's stdout.
    ///
    /// # Errors
    ///
    /// [`ExecRefusal::NotACredential`] where the output is not an `ExecCredential` document,
    /// [`ExecRefusal::UnknownContract`] where it claims a contract this provider does not speak,
    /// and [`ExecRefusal::NoCredential`] where it carries neither form of credential.
    pub fn parse(stdout: &str) -> Result<Self, ExecRefusal> {
        let raw: RawCredential = serde_json::from_str(stdout.trim())
            .map_err(|error| ExecRefusal::NotACredential(error.to_string()))?;
        if raw.kind.as_deref() != Some("ExecCredential") {
            return Err(ExecRefusal::NotACredential(format!(
                "its `kind` is {}",
                raw.kind.as_deref().unwrap_or("absent")
            )));
        }
        if !SPOKEN.contains(&raw.api_version.as_str()) {
            return Err(ExecRefusal::UnknownContract(raw.api_version));
        }
        let status = raw.status.ok_or(ExecRefusal::NoCredential)?;
        let credential = Self {
            token: status.token.map(Secret::new),
            client_certificate: status.client_certificate_data.map(Secret::new),
            client_key: status.client_key_data.map(Secret::new),
            expires_at: status.expiration_timestamp,
        };
        if credential.token.is_none()
            && !(credential.client_certificate.is_some() && credential.client_key.is_some())
        {
            return Err(ExecRefusal::NoCredential);
        }
        Ok(credential)
    }

    /// The bearer token, where the plugin returned one.
    #[must_use]
    pub fn token(&self) -> Option<&Secret> {
        self.token.as_ref()
    }

    /// The client certificate and its key, where the plugin returned that form instead.
    #[must_use]
    pub fn client_certificate(&self) -> Option<(&Secret, &Secret)> {
        Some((self.client_certificate.as_ref()?, self.client_key.as_ref()?))
    }

    /// When this credential expires, as the plugin stated it.
    #[must_use]
    pub fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }

    /// Whether the credential had already expired at `now` (§8.3).
    ///
    /// A credential with no `expirationTimestamp` never expires *as far as this provider can
    /// tell*, which is not the same as never expiring: the API server will refuse it and that
    /// refusal is a `401` this provider reports rather than a state it predicted. Reporting one
    /// it cannot see would be the inference §4 forbids.
    ///
    /// # Errors
    ///
    /// [`ExecRefusal::Expired`] with the instant the plugin stated.
    pub fn check_expiry(&self, now: ObservedAt) -> Result<(), ExecRefusal> {
        let Some(stated) = &self.expires_at else {
            return Ok(());
        };
        let Some(expires) = rfc3339_millis(stated) else {
            // An `expirationTimestamp` that does not parse is not an expiry this provider can
            // check, and refusing on it would refuse a credential that may be perfectly good.
            return Ok(());
        };
        if expires <= now.unix_millis() {
            return Err(ExecRefusal::Expired { at: stated.clone() });
        }
        Ok(())
    }
}

/// An `ExecCredential` document, as a plugin prints one.
#[derive(Debug, Deserialize)]
struct RawCredential {
    kind: Option<String>,
    #[serde(rename = "apiVersion", default)]
    api_version: String,
    status: Option<RawStatus>,
}

#[derive(Debug, Deserialize)]
struct RawStatus {
    token: Option<String>,
    #[serde(rename = "clientCertificateData")]
    client_certificate_data: Option<String>,
    #[serde(rename = "clientKeyData")]
    client_key_data: Option<String>,
    #[serde(rename = "expirationTimestamp")]
    expiration_timestamp: Option<String>,
}

/// An RFC 3339 instant in UTC as Unix milliseconds, or [`None`] where it does not read as one.
///
/// Deliberately narrow: `2026-09-07T10:11:12Z` and its fractional-second form, which is what a
/// credential plugin writes. An offset other than `Z` is not read rather than being read wrongly —
/// a timestamp misread by an hour is worse than one not read at all, because the first silently
/// accepts an expired credential or refuses a good one.
fn rfc3339_millis(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if date.next().is_some() {
        return None;
    }
    let (time, fraction) = time.split_once('.').unwrap_or((time, "0"));
    let millis: u64 = format!("{fraction:0<3}")
        .get(..3)
        .and_then(|three| three.parse().ok())?;
    let mut clock = time.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next()?.parse().ok()?;
    if clock.next().is_some() {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds)
        .ok()?
        .checked_mul(1_000)?
        .checked_add(millis)
}

/// Days since the Unix epoch, by Howard Hinnant's civil-calendar algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

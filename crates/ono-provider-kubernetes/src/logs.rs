//! Container logs as observations, and the three remote sessions this transport cannot open.
//!
//! Specification §42, with §51.1, §51.4, §57 and §61.5 (Gate L) behind it. §42 is the section
//! where a provider is most tempted to grow into a terminal multiplexer, and it draws the line in
//! six places:
//!
//! ```text
//! §42.1  logs MAY be exposed as a typed/byte stream, and MUST carry target/provenance metadata
//! §42.2  logs may contain secrets, and are never silently persisted as cache or temporal history
//! §42.3  exec is NOT an ordinary mutation; its cluster, namespace, Pod and container are
//!        explicit before execution
//! §42.4  attach shares the remote-session path rather than being an opaque provider callback
//! §42.5  port forward is a job/session with clear local and remote endpoints
//! §42.6  a hidden subprocess shelling out to the upstream command-line client is an anti-pattern
//! ```
//!
//! Three of those are expressed in the shape of the types here rather than in a warning comment.
//!
//! **A retrieved log is never the output of a container.** The container runtime rotated and
//! truncated it long before this provider asked, `tailLines` and `sinceSeconds` cut it further,
//! and `previous` reaches exactly one prior instance because that is all the kubelet retains. So
//! [`Retrieved::bounds`] is never empty — [`Bound::RuntimeRetention`] is always in it — and there
//! is no accessor whose name would license "this is everything it printed". A search over the
//! lines answers [`Matched`], whose empty case carries an [`Outcome`] and never
//! [`Outcome::Absent`], the same discipline `events.rs` applies to Events (§63.6).
//!
//! **A line is bytes.** A container writes whatever it writes, and `String::from_utf8_lossy`
//! would hand a caller a line that looks like text while differing from what the container
//! produced — evidence edited on the way past. [`LogLine`] keeps the bytes and [`LineText`] says
//! whether they decode and where decoding stopped.
//!
//! **Exec, attach and port forward are modelled and refused.** They need `101 Switching
//! Protocols` and a multiplexed channel codec over the upgraded connection; this package has a
//! brokered byte connection and an HTTP/1.1 request/response client over it, and neither the
//! upgrade nor the codec exists. Rather than a stub that hands back a session which silently does
//! nothing, [`SessionRequest::open`] returns [`Unavailable`] naming each missing piece, and its
//! success type is uninhabited so that no caller anywhere can hold a session. The request that
//! *would* be sent is still built, because a named gap with the request written down is worth
//! more than a gap nobody can act on. `ADR-0018` records this.
//!
//! Nothing here does I/O, spawns anything, or reads a clock.

use std::convert::Infallible;
use std::fmt;

use crate::coverage::{Outcome, Scope};
use crate::discovery::Gvr;
use crate::transport::{Request, object_path};

/// The REST collection every subresource here hangs off.
fn pods() -> Gvr {
    Gvr::new("", "v1", "pods")
}

// --- the target (§42.1 provenance, §42.3 explicit target) ---------------------------------------

/// Which container, in which Pod, in which namespace, of which cluster.
///
/// One type for logs and for remote sessions, because §42.1 and §42.3 ask for the same four facts
/// for opposite reasons: a log is an observation that means nothing without knowing what it
/// observed, and an exec is an execution that must not begin until the operator has seen where.
///
/// The provider instance is part of it (§6.2, §6.5). A Pod name is unique within a namespace of
/// one cluster and nowhere else, and a log line attributed to the identically named Pod in the
/// staging cluster is the most expensive kind of wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodTarget {
    provider_instance: String,
    namespace: String,
    pod: String,
    container: Option<String>,
}

impl PodTarget {
    /// A Pod in a namespace of one cluster, with the container left to the server.
    #[must_use]
    pub fn new(
        provider_instance: impl Into<String>,
        namespace: impl Into<String>,
        pod: impl Into<String>,
    ) -> Self {
        Self {
            provider_instance: provider_instance.into(),
            namespace: namespace.into(),
            pod: pod.into(),
            container: None,
        }
    }

    /// Names the container, which §42.1 lists and §42.3 requires.
    #[must_use]
    pub fn in_container(mut self, container: impl Into<String>) -> Self {
        self.container = Some(container.into());
        self
    }

    /// Which cluster this provider instance is (§6.2).
    #[must_use]
    pub fn provider_instance(&self) -> &str {
        &self.provider_instance
    }

    /// The namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The Pod.
    #[must_use]
    pub fn pod(&self) -> &str {
        &self.pod
    }

    /// The container, where one was named.
    ///
    /// [`None`] means the API server picks, which it does silently for a single-container Pod.
    /// That is acceptable for a log and not for an execution, which is why
    /// [`Missing::ExplicitContainer`] exists.
    #[must_use]
    pub fn container(&self) -> Option<&str> {
        self.container.as_deref()
    }

    /// Where the Pod lives on the REST surface.
    #[must_use]
    pub fn path(&self, subresource: &str) -> String {
        format!(
            "{}/{subresource}",
            object_path(&pods(), &Scope::in_namespace(&self.namespace), &self.pod)
        )
    }

    /// The four facts, in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        let container = self.container.as_ref().map_or_else(
            || "container unstated, the API server chooses".to_owned(),
            |name| format!("container {name}"),
        );
        format!(
            "{} {}/{} ({container})",
            self.provider_instance, self.namespace, self.pod
        )
    }
}

impl fmt::Display for PodTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

// --- the request (§42.1) -------------------------------------------------------------------------

/// Which run of the container is being read.
///
/// Two variants and no third. The kubelet retains the terminated container of one prior run, and
/// `previous=true` reaches exactly that one — so an ordinal selector would name runs the cluster
/// cannot produce, and would answer every one of them with the same log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instance {
    /// The container running now, or the one that most recently was.
    Current,
    /// The one prior run the kubelet still holds.
    Previous,
}

impl Instance {
    /// The word this run is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Previous => "previous",
        }
    }
}

impl fmt::Display for Instance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a log request as stated cannot be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogRequestError {
    /// `follow` on the prior run. The API server accepts the pair and ignores `follow`, so the
    /// body closes at once — and a caller watching for more reads that as a container it just saw
    /// stop. A run that has already ended cannot produce another line.
    FollowPrevious,
}

impl fmt::Display for LogRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FollowPrevious => f.write_str(
                "the prior run's log cannot be followed: it has stopped growing, and the server \
                 answers the request by closing the body immediately",
            ),
        }
    }
}

impl std::error::Error for LogRequestError {}

/// Something that kept this retrieval from being everything the container wrote.
///
/// [`Self::RuntimeRetention`] is in every list, which is the point: an unbounded request is not an
/// unbounded answer, because rotation and truncation happened in the container runtime before
/// anybody asked (§42.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// The container runtime rotates and truncates. Always present.
    RuntimeRetention,
    /// `tailLines`: only the last so many lines were asked for.
    Tail(u32),
    /// `sinceSeconds`: only lines from the last so many seconds were asked for.
    Since(u64),
    /// `limitBytes`: the server stopped after so many bytes.
    Bytes(u64),
}

impl Bound {
    /// What this bound removed, in words.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::RuntimeRetention => {
                "the container runtime rotated and truncated this log before it was read".to_owned()
            }
            Self::Tail(lines) => format!("only the last {lines} lines were requested"),
            Self::Since(seconds) => format!("only the last {seconds} seconds were requested"),
            Self::Bytes(bytes) => format!("the server stopped after {bytes} bytes"),
        }
    }
}

/// A request for a Pod container's log (§42.1).
///
/// Held as a value rather than assembled straight into an HTTP request, because everything
/// downstream needs it: the decoder needs to know whether timestamps were asked for, and a
/// retrieval needs the target and the bounds to say what it is. [`Self::http_request`] is the one
/// place the parameters become a URL, and the one place they are checked against each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRequest {
    target: PodTarget,
    instance: Instance,
    follow: bool,
    timestamps: bool,
    tail_lines: Option<u32>,
    since_seconds: Option<u64>,
    limit_bytes: Option<u64>,
}

impl LogRequest {
    /// The current run's log, unbounded, without timestamps, not followed.
    #[must_use]
    pub fn new(target: PodTarget) -> Self {
        Self {
            target,
            instance: Instance::Current,
            follow: false,
            timestamps: false,
            tail_lines: None,
            since_seconds: None,
            limit_bytes: None,
        }
    }

    /// Reads the one prior run the kubelet retains (§42.1).
    #[must_use]
    pub fn of_previous_instance(mut self) -> Self {
        self.instance = Instance::Previous;
        self
    }

    /// Keeps the body open as the container writes (§42.1 follow mode).
    #[must_use]
    pub fn following(mut self) -> Self {
        self.follow = true;
        self
    }

    /// Asks the server to prefix each line with the container runtime's clock.
    #[must_use]
    pub fn with_timestamps(mut self) -> Self {
        self.timestamps = true;
        self
    }

    /// Bounds the answer to the last `lines` lines (§42.1 bounded tail).
    #[must_use]
    pub fn tail_lines(mut self, lines: u32) -> Self {
        self.tail_lines = Some(lines);
        self
    }

    /// Bounds the answer to the last `seconds` seconds (§42.1 bounded since).
    #[must_use]
    pub fn since_seconds(mut self, seconds: u64) -> Self {
        self.since_seconds = Some(seconds);
        self
    }

    /// Bounds the answer to `bytes` bytes, which §50.6 wants for a default view.
    #[must_use]
    pub fn limit_bytes(mut self, bytes: u64) -> Self {
        self.limit_bytes = Some(bytes);
        self
    }

    /// What is being read (§42.1 provenance).
    #[must_use]
    pub fn target(&self) -> &PodTarget {
        &self.target
    }

    /// Which run.
    #[must_use]
    pub fn instance(&self) -> Instance {
        self.instance
    }

    /// Whether the body stays open.
    #[must_use]
    pub fn is_following(&self) -> bool {
        self.follow
    }

    /// Whether the server prefixes each line with a timestamp.
    ///
    /// The decoder needs this and must not guess it: an application that prints its own
    /// timestamps would otherwise lose its first word to a prefix the server never wrote.
    #[must_use]
    pub fn has_timestamps(&self) -> bool {
        self.timestamps
    }

    /// Everything that keeps this request's answer short of the container's output.
    ///
    /// Never empty. [`Bound::RuntimeRetention`] leads, and the requested bounds follow.
    #[must_use]
    pub fn bounds(&self) -> Vec<Bound> {
        let mut bounds = vec![Bound::RuntimeRetention];
        bounds.extend(self.tail_lines.map(Bound::Tail));
        bounds.extend(self.since_seconds.map(Bound::Since));
        bounds.extend(self.limit_bytes.map(Bound::Bytes));
        bounds
    }

    /// The HTTP request this becomes.
    ///
    /// # Errors
    ///
    /// [`LogRequestError::FollowPrevious`] for a followed prior run, which the server accepts and
    /// answers in a way that misleads.
    pub fn http_request(&self) -> Result<Request, LogRequestError> {
        if self.follow && self.instance == Instance::Previous {
            return Err(LogRequestError::FollowPrevious);
        }
        let mut request = Request::get(self.target.path("log"));
        if let Some(container) = self.target.container() {
            request = request.query("container", container);
        }
        if self.follow {
            request = request.query("follow", "true");
        }
        if self.timestamps {
            request = request.query("timestamps", "true");
        }
        if self.instance == Instance::Previous {
            request = request.query("previous", "true");
        }
        if let Some(lines) = self.tail_lines {
            request = request.query("tailLines", lines.to_string());
        }
        if let Some(seconds) = self.since_seconds {
            request = request.query("sinceSeconds", seconds.to_string());
        }
        if let Some(bytes) = self.limit_bytes {
            request = request.query("limitBytes", bytes.to_string());
        }
        Ok(request)
    }
}

// --- lines (§42.1) -------------------------------------------------------------------------------

/// Whether a line's bytes are text, and where they stopped being text.
///
/// An enum rather than a lossy `String`, for §12.5's reason applied to a stream: a decoder that
/// substitutes U+FFFD hands back something that reads like the container's output and is not it,
/// and nothing downstream can tell that a substitution happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineText<'a> {
    /// The bytes decode as UTF-8.
    Utf8(&'a str),
    /// They do not, and this is how far decoding got.
    NotUtf8 {
        /// The number of leading bytes that were valid UTF-8.
        valid_up_to: usize,
    },
}

impl<'a> LineText<'a> {
    /// The text, where there is text. [`None`] rather than an approximation of it.
    #[must_use]
    pub fn as_str(self) -> Option<&'a str> {
        match self {
            Self::Utf8(text) => Some(text),
            Self::NotUtf8 { .. } => None,
        }
    }

    /// What happened, in words a reader can act on.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Utf8(text) => text.to_owned(),
            Self::NotUtf8 { valid_up_to } => format!(
                "the line is not UTF-8 after byte {valid_up_to}; its bytes are kept unchanged"
            ),
        }
    }
}

/// One line of a container's output, as bytes, with what the server said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    stamp: Option<String>,
    bytes: Vec<u8>,
    terminated: bool,
}

impl LogLine {
    /// The bytes the container wrote, without the newline and without the timestamp prefix.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether those bytes are text.
    #[must_use]
    pub fn text(&self) -> LineText<'_> {
        match std::str::from_utf8(&self.bytes) {
            Ok(text) => LineText::Utf8(text),
            Err(error) => LineText::NotUtf8 {
                valid_up_to: error.valid_up_to(),
            },
        }
    }

    /// The timestamp the server prefixed, when timestamps were requested.
    ///
    /// Kept as the string it arrived as, and deliberately not parsed into an instant: it is the
    /// container runtime's clock, on the node, and comparing it with this provider's observations
    /// or with another node's would be the cross-clock timeline §39.2 forbids.
    #[must_use]
    pub fn stamp(&self) -> Option<&str> {
        self.stamp.as_deref()
    }

    /// Whether the server sent the newline that ends this line.
    ///
    /// False for the remainder of a body that stopped mid-line. Presenting that remainder as a
    /// line would show half a message as one the container finished writing.
    #[must_use]
    pub fn is_terminated(&self) -> bool {
        self.terminated
    }
}

/// Turns the bytes of a log response into lines.
///
/// The simpler cousin of `watch::WatchDecoder`, and separate from [`LogFollow`] for the same
/// reason: framing answers "what did the server send", and the follow answers "what may be shown
/// now". Chunked transfer flushes wherever the server's writer did, so a chunk boundary lands
/// mid-line as a matter of course and a partial line is held rather than guessed at.
#[derive(Debug, Clone)]
pub struct LogDecoder {
    timestamps: bool,
    buffer: Vec<u8>,
}

impl LogDecoder {
    /// A decoder for a response with no timestamp prefixes.
    #[must_use]
    pub fn plain() -> Self {
        Self {
            timestamps: false,
            buffer: Vec::new(),
        }
    }

    /// A decoder for a response the server prefixed with timestamps.
    #[must_use]
    pub fn timestamped() -> Self {
        Self {
            timestamps: true,
            buffer: Vec::new(),
        }
    }

    /// A decoder that matches what the request asked for.
    #[must_use]
    pub fn for_request(request: &LogRequest) -> Self {
        if request.has_timestamps() {
            Self::timestamped()
        } else {
            Self::plain()
        }
    }

    /// Decodes every whole line this chunk completes, holding any remainder.
    pub fn decode(&mut self, chunk: &[u8]) -> Vec<LogLine> {
        self.buffer.extend_from_slice(chunk);
        let mut lines = Vec::new();
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let raw: Vec<u8> = self.buffer.drain(..=end).collect();
            lines.push(self.line(&raw[..raw.len() - 1], true));
        }
        lines
    }

    /// Hands over what is left once the body has ended, as an unterminated line.
    ///
    /// [`None`] when the body ended on a line boundary, which is the ordinary case.
    pub fn finish(&mut self) -> Option<LogLine> {
        let rest = std::mem::take(&mut self.buffer);
        if rest.is_empty() {
            return None;
        }
        Some(self.line(&rest, false))
    }

    /// How many bytes are held back as an incomplete line.
    ///
    /// The difference between a quiet container and a stalled stream.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    fn line(&self, raw: &[u8], terminated: bool) -> LogLine {
        let (stamp, bytes) = self.split_stamp(raw);
        LogLine {
            stamp,
            bytes,
            terminated,
        }
    }

    /// Splits the server's timestamp prefix off, and only when there is one to split.
    ///
    /// Two conditions, both required. Timestamps must have been requested, because otherwise the
    /// prefix is the application's own first word. And the prefix must look like the RFC 3339
    /// instant the API server writes, because a container may print a line the request never
    /// asked to be prefixed at all — a `sinceSeconds` boundary, a restart banner — and eating its
    /// first token would silently shorten it.
    fn split_stamp(&self, raw: &[u8]) -> (Option<String>, Vec<u8>) {
        if !self.timestamps {
            return (None, raw.to_vec());
        }
        let Some(space) = raw.iter().position(|byte| *byte == b' ') else {
            return (None, raw.to_vec());
        };
        let (head, rest) = raw.split_at(space);
        if !looks_like_an_instant(head) {
            return (None, raw.to_vec());
        }
        match std::str::from_utf8(head) {
            Ok(stamp) => (Some(stamp.to_owned()), rest[1..].to_vec()),
            Err(_) => (None, raw.to_vec()),
        }
    }
}

/// Whether these bytes are shaped like the RFC 3339 instant the API server prefixes.
fn looks_like_an_instant(head: &[u8]) -> bool {
    head.len() >= 20
        && head[..4].iter().all(u8::is_ascii_digit)
        && head[4] == b'-'
        && head.ends_with(b"Z")
}

// --- following (§42.1 cancellation, §61.5 Gate L) -----------------------------------------------

/// What a followed log is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowState {
    /// The body is open and lines are being delivered.
    Streaming,
    /// The reader stopped. Gate L: a follow terminates promptly when Ono cancels it.
    Cancelled,
    /// The response body ended.
    ///
    /// Which is a fact about the connection and not about the workload. A container exiting, a
    /// proxy dropping an idle stream and a node rebooting all look identical from here, and only
    /// one of them is something to say about the Pod.
    Closed,
    /// The connection or the server failed, with what it said.
    Failed(String),
}

impl FollowState {
    /// The state in words.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Streaming => "streaming",
            Self::Cancelled => "cancelled",
            Self::Closed => "the response body ended",
            Self::Failed(detail) => detail,
        }
    }

    /// Whether lines are still being delivered.
    #[must_use]
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::Streaming)
    }
}

impl fmt::Display for FollowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One followed log: its request, its framing, and what it stopped doing.
///
/// It holds no lines. A followed log is unbounded by construction, and a type that accumulated it
/// would be a cache of exactly the kind §42.2 forbids — so lines are handed to the caller as they
/// decode and this keeps only counters.
#[derive(Debug, Clone)]
pub struct LogFollow {
    request: LogRequest,
    decoder: LogDecoder,
    state: FollowState,
    delivered: usize,
    discarded: usize,
}

impl LogFollow {
    /// A follow of this request, before any bytes arrive.
    #[must_use]
    pub fn open(request: LogRequest) -> Self {
        let decoder = LogDecoder::for_request(&request);
        Self {
            request,
            decoder,
            state: FollowState::Streaming,
            delivered: 0,
            discarded: 0,
        }
    }

    /// Decodes a chunk into whatever lines it completes.
    ///
    /// Empty once the follow has stopped, and the bytes are counted rather than dropped in
    /// silence: bytes still arriving at a cancelled follow mean something upstream has not yet
    /// been told to stop, which is what Gate L is about.
    pub fn receive(&mut self, chunk: &[u8]) -> Vec<LogLine> {
        if !self.state.is_streaming() {
            self.discarded += chunk.len();
            return Vec::new();
        }
        let lines = self.decoder.decode(chunk);
        self.delivered += lines.len();
        lines
    }

    /// Stops the follow because the reader asked (§61.5, Gate L).
    pub fn cancel(&mut self) {
        if self.state.is_streaming() {
            self.state = FollowState::Cancelled;
        }
    }

    /// Records that the response body ended.
    pub fn closed(&mut self) {
        if self.state.is_streaming() {
            self.state = FollowState::Closed;
        }
    }

    /// Records that the stream failed, with what the transport said.
    pub fn failed(&mut self, detail: impl Into<String>) {
        if self.state.is_streaming() {
            self.state = FollowState::Failed(detail.into());
        }
    }

    /// What this follow is doing.
    #[must_use]
    pub fn state(&self) -> &FollowState {
        &self.state
    }

    /// The request being followed, still carrying its provenance.
    #[must_use]
    pub fn request(&self) -> &LogRequest {
        &self.request
    }

    /// How many whole lines were handed over.
    #[must_use]
    pub fn delivered_lines(&self) -> usize {
        self.delivered
    }

    /// How many bytes arrived after the follow stopped receiving.
    #[must_use]
    pub fn discarded_bytes(&self) -> usize {
        self.discarded
    }

    /// How the ending would be recorded on a retrieval.
    #[must_use]
    pub fn ending(&self) -> Ending {
        match &self.state {
            FollowState::Streaming => Ending::StillOpen,
            FollowState::Cancelled => Ending::Cancelled,
            FollowState::Closed => Ending::BodyEnded,
            FollowState::Failed(detail) => Ending::Failed(detail.clone()),
        }
    }

    /// The follow in one line: what it is reading and what became of it.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "following {}: {}, {} lines delivered",
            self.request.target.describe(),
            self.state.as_str(),
            self.delivered
        )
    }
}

// --- a retrieval (§42.1, §42.2) -------------------------------------------------------------------

/// Why the lines stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    /// The response body ended. Not a statement about the container (see [`FollowState::Closed`]).
    BodyEnded,
    /// The reader stopped, so what follows this line was never read.
    Cancelled,
    /// The stream failed, with what the transport said.
    Failed(String),
    /// Nothing has stopped: this is a snapshot of a follow still in progress.
    StillOpen,
}

impl Ending {
    /// The ending in words.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::BodyEnded => "the response body ended".to_owned(),
            Self::Cancelled => "the read was cancelled, so later lines were never seen".to_owned(),
            Self::Failed(detail) => format!("the stream failed: {detail}"),
            Self::StillOpen => "the stream is still open".to_owned(),
        }
    }
}

/// What a search of a retrieval came back with.
///
/// An enum rather than a possibly-empty list, for §63.6's reason applied to logs: `if
/// matches.is_empty() { "it never printed that" }` is false whenever rotation discarded the line,
/// `tailLines` cut it off, the process wrote it to a file, or the container had not reached it
/// yet. A bare `Vec` invites that sentence; this type makes it need a second thought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matched<'a> {
    /// Lines matching the question were observed.
    Observed(Vec<&'a LogLine>),
    /// None were, and here is what that does and does not mean.
    NotObserved(Outcome),
}

impl<'a> Matched<'a> {
    /// What was observed — empty when nothing was.
    #[must_use]
    pub fn observed(&self) -> &[&'a LogLine] {
        match self {
            Self::Observed(lines) => lines,
            Self::NotObserved(_) => &[],
        }
    }

    /// Whether anything was observed.
    #[must_use]
    pub fn is_observed(&self) -> bool {
        matches!(self, Self::Observed(_))
    }

    /// Why nothing was observed, or [`None`] where something was.
    ///
    /// Never [`Outcome::Absent`], at any input. What was retrieved was bounded before it was
    /// requested, so a line that is not here was not looked for rather than not written — and
    /// [`Outcome::is_evidence_of_absence`] answers `false` for it.
    #[must_use]
    pub fn outcome(&self) -> Option<Outcome> {
        match self {
            Self::Observed(_) => None,
            Self::NotObserved(outcome) => Some(*outcome),
        }
    }
}

/// Lines that were read, what they were read from, and everything that was cut off first.
///
/// Deliberately not [`Clone`]. §42.2 forbids a log becoming provider cache or temporal history,
/// and the cheapest route to both is a type that copies into a map without anyone deciding to
/// keep it. Moving it is still possible; doing so accidentally is not.
#[derive(Debug)]
pub struct Retrieved {
    target: PodTarget,
    instance: Instance,
    bounds: Vec<Bound>,
    lines: Vec<LogLine>,
    ending: Ending,
}

impl Retrieved {
    /// What one read of a log produced, keeping the request's provenance and bounds.
    #[must_use]
    pub fn of(request: &LogRequest, lines: Vec<LogLine>, ending: Ending) -> Self {
        Self {
            target: request.target.clone(),
            instance: request.instance,
            bounds: request.bounds(),
            lines,
            ending,
        }
    }

    /// What was read from (§42.1 provenance).
    #[must_use]
    pub fn target(&self) -> &PodTarget {
        &self.target
    }

    /// Which run of the container.
    #[must_use]
    pub fn instance(&self) -> Instance {
        self.instance
    }

    /// The lines that were read, in the order the server sent them.
    #[must_use]
    pub fn lines(&self) -> &[LogLine] {
        &self.lines
    }

    /// How many lines were read.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Everything that kept this short of the container's output. Never empty (§42.1).
    #[must_use]
    pub fn bounds(&self) -> &[Bound] {
        &self.bounds
    }

    /// Why the lines stopped.
    #[must_use]
    pub fn ending(&self) -> &Ending {
        &self.ending
    }

    /// Whether the shell must treat these bytes as possibly secret. Always yes (§42.2).
    ///
    /// A constant rather than a scan of the content, because whether a log carries a credential is
    /// not decidable from the log: the secret may be base64, a fragment across two lines, or a URL
    /// with a token in its query. A method that sometimes answered `false` would be a filter that
    /// is wrong exactly when it matters.
    #[must_use]
    pub fn may_contain_secrets(&self) -> bool {
        true
    }

    /// The lines matching a question, and what an empty answer means (§63.6).
    #[must_use]
    pub fn matching(&self, predicate: impl Fn(&LogLine) -> bool) -> Matched<'_> {
        let matched: Vec<&LogLine> = self.lines.iter().filter(|line| predicate(line)).collect();
        if matched.is_empty() {
            // Never `Absent`: see `Matched::outcome`.
            Matched::NotObserved(Outcome::NotQueried)
        } else {
            Matched::Observed(matched)
        }
    }

    /// What this is, where it came from, and what it is not.
    #[must_use]
    pub fn describe(&self) -> String {
        let bounds: Vec<String> = self.bounds.iter().map(|bound| bound.describe()).collect();
        format!(
            "{} lines from {} [{} run]; {}; {}",
            self.lines.len(),
            self.target.describe(),
            self.instance.as_str(),
            self.ending.describe(),
            bounds.join("; ")
        )
    }
}

// --- exec, attach and port forward (§42.3, §42.4, §42.5) ----------------------------------------

/// What a remote session would let its holder do.
///
/// Named on the type rather than left to a policy table elsewhere, because §51 gates these on
/// what they *are*: a capability whose risk is implicit is one a host grants by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Reads bytes something already wrote. Still not harmless — §42.2 — but it starts nothing.
    Observation,
    /// Runs an arbitrary command inside the container, with that container's identity, service
    /// account token and network position (§42.3).
    CodeExecution,
    /// Writes arbitrary input to the standard input of a process the operator did not start
    /// (§42.4). Not a new process, and not a read either.
    ProcessInput,
    /// Opens a path from this machine into the cluster's network to an address the cluster's own
    /// policies expected to be reachable only from inside it (§42.5).
    NetworkPath,
}

impl Risk {
    /// The word this risk is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::CodeExecution => "code execution in the container",
            Self::ProcessInput => "input to a running process",
            Self::NetworkPath => "a network path into the cluster",
        }
    }

    /// Whether holding this capability changes nothing.
    ///
    /// Only [`Self::Observation`]. The mistake this exists to stop is classifying attach with the
    /// logs it resembles: both stream a container's output, and only one of them also writes.
    #[must_use]
    pub fn is_read_only(self) -> bool {
        matches!(self, Self::Observation)
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which of §42's three remote sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Run a command in a container (§42.3).
    Exec,
    /// Attach to a running container's streams (§42.4).
    Attach,
    /// Forward a local port to a port in the Pod (§42.5).
    PortForward,
}

impl SessionKind {
    /// The word this session is reported under, and the Pod subresource it uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Attach => "attach",
            Self::PortForward => "portforward",
        }
    }

    /// What holding this session would let its holder do (§51).
    #[must_use]
    pub fn risk(self) -> Risk {
        match self {
            Self::Exec => Risk::CodeExecution,
            Self::Attach => Risk::ProcessInput,
            Self::PortForward => Risk::NetworkPath,
        }
    }

    /// The manifest key §57 declares this capability under, as `conditional`.
    #[must_use]
    pub fn manifest_capability(self) -> &'static str {
        match self {
            Self::Exec | Self::Attach => "remote_exec",
            Self::PortForward => "port_forward",
        }
    }
}

impl fmt::Display for SessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One local port and the Pod port it would reach (§42.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapping {
    local: u16,
    remote: u16,
}

impl PortMapping {
    /// A mapping from a local port to a port in the Pod.
    #[must_use]
    pub fn new(local: u16, remote: u16) -> Self {
        Self { local, remote }
    }

    /// The port on this machine.
    #[must_use]
    pub fn local(self) -> u16 {
        self.local
    }

    /// The port in the Pod.
    #[must_use]
    pub fn remote(self) -> u16 {
        self.remote
    }

    /// Both endpoints, which §42.5 requires to be clear.
    #[must_use]
    pub fn describe(self) -> String {
        format!("local {} to Pod port {}", self.local, self.remote)
    }
}

/// One thing a remote session needs that this provider does not have.
///
/// Each variant is a specific, checkable absence rather than "unsupported". A named gap is
/// actionable: three of these are code that could be written here, one is a host capability that
/// would have to be granted, and one is a decision the caller can fix before asking again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// `101 Switching Protocols`. `transport::HttpConnection` speaks request/response and reads a
    /// body framed by `Content-Length`, chunked transfer or end-of-stream; it has no path that
    /// hands the raw byte stream back to a caller after an upgrade, and its buffered remainder
    /// would be lost if it did.
    ProtocolUpgrade,
    /// The channel codec above the upgraded connection: SPDY/3.1, or WebSocket with the
    /// `v4.channel.k8s.io` subprotocol, either of which multiplexes stdin, stdout, stderr, a
    /// resize channel and an error channel over one connection. Neither exists in this package.
    /// The WebSocket route additionally needs per-frame masking keys from a random source, and
    /// §51.1 grants this provider no entropy capability.
    StreamMultiplexing,
    /// Ono's terminal and job-control integration, which §42.3 requires an exec to run inside and
    /// §42.5 requires a forward's lifecycle to be represented as. It lives in core, and §0.4
    /// forbids inventing a Kubernetes-shaped exception there from this side.
    TerminalJobControl,
    /// A local listening socket for a forward's near end. KUANG/11 brokers outbound connections
    /// (`ADR-0573` in core); it does not broker a listener, so there is nowhere for the local
    /// endpoint of §42.5 to exist.
    LocalListener,
    /// The host capability itself. §57 declares `remote_exec` and `port_forward` as
    /// *conditional*, and §57.1 separates a declared capability from an effective one — this
    /// build's manifest grants neither, so the effective answer is no whatever the code could do.
    HostCapability,
    /// The container was not named. §42.3 requires cluster, namespace, Pod and container to be
    /// explicit before execution; letting the API server choose works until the Pod grows a
    /// sidecar, and then the command runs somewhere nobody named.
    ExplicitContainer,
}

impl Missing {
    /// The token this absence is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolUpgrade => "protocol_upgrade",
            Self::StreamMultiplexing => "stream_multiplexing",
            Self::TerminalJobControl => "terminal_job_control",
            Self::LocalListener => "local_listener",
            Self::HostCapability => "host_capability",
            Self::ExplicitContainer => "explicit_container",
        }
    }

    /// What exactly is absent, in words somebody could act on.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::ProtocolUpgrade => {
                "the HTTP client here speaks request/response and cannot complete a 101 Switching \
                 Protocols upgrade or hand the raw stream back afterwards"
            }
            Self::StreamMultiplexing => {
                "no channel codec exists in this package: the upgraded connection carries SPDY/3.1 \
                 or the v4.channel.k8s.io WebSocket subprotocol, and the WebSocket route also needs \
                 masking keys from a random source this provider is not granted"
            }
            Self::TerminalJobControl => {
                "Ono's terminal and job-control integration is core's, and a remote session has to \
                 run inside it rather than beside it"
            }
            Self::LocalListener => {
                "the host brokers outbound connections and not listening sockets, so the local end \
                 of a forward has nowhere to exist"
            }
            Self::HostCapability => {
                "the manifest declares this capability conditional and this build grants it to \
                 nobody"
            }
            Self::ExplicitContainer => {
                "no container was named, and the target must be explicit before anything runs"
            }
        }
    }
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A remote session that was asked for and cannot be opened.
///
/// It carries the kind, its risk and every missing piece, so the refusal reads as a report rather
/// than as a failure: what was asked for, what it would have granted, and precisely what is in
/// the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    kind: SessionKind,
    target: PodTarget,
    missing: Vec<Missing>,
}

impl Unavailable {
    /// Which session was asked for.
    #[must_use]
    pub fn kind(&self) -> SessionKind {
        self.kind
    }

    /// What it would have granted (§51).
    #[must_use]
    pub fn risk(&self) -> Risk {
        self.kind.risk()
    }

    /// Where it would have run.
    #[must_use]
    pub fn target(&self) -> &PodTarget {
        &self.target
    }

    /// Everything that is in the way.
    #[must_use]
    pub fn missing(&self) -> &[Missing] {
        &self.missing
    }

    /// The refusal as a report.
    #[must_use]
    pub fn describe(&self) -> String {
        let missing: Vec<String> = self
            .missing
            .iter()
            .map(|item| format!("{}: {}", item.as_str(), item.describe()))
            .collect();
        format!(
            "{} into {}/{} would grant {}, and cannot be opened here — {}",
            self.kind.as_str(),
            self.target.namespace(),
            self.target.pod(),
            self.risk().as_str(),
            missing.join("; ")
        )
    }
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

impl std::error::Error for Unavailable {}

/// A request for one of §42's three remote sessions.
///
/// It builds the HTTP request the API server would be sent, and refuses to open it. Both halves
/// matter: the request is what the day the transport can upgrade will need, and the refusal is
/// what today's caller gets instead of a handle that appears to work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequest {
    kind: SessionKind,
    target: PodTarget,
    command: Vec<String>,
    ports: Vec<PortMapping>,
    stdin: bool,
    tty: bool,
}

impl SessionRequest {
    /// Run a command in a container (§42.3).
    #[must_use]
    pub fn exec(target: PodTarget, command: Vec<String>) -> Self {
        Self {
            kind: SessionKind::Exec,
            target,
            command,
            ports: Vec::new(),
            stdin: false,
            tty: false,
        }
    }

    /// Attach to a running container's streams (§42.4).
    #[must_use]
    pub fn attach(target: PodTarget) -> Self {
        Self {
            kind: SessionKind::Attach,
            target,
            command: Vec::new(),
            ports: Vec::new(),
            stdin: false,
            tty: false,
        }
    }

    /// Forward local ports to ports in the Pod (§42.5).
    #[must_use]
    pub fn port_forward(target: PodTarget, ports: Vec<PortMapping>) -> Self {
        Self {
            kind: SessionKind::PortForward,
            target,
            command: Vec::new(),
            ports,
            stdin: false,
            tty: false,
        }
    }

    /// Asks for the session's standard input to be connected.
    #[must_use]
    pub fn with_stdin(mut self) -> Self {
        self.stdin = true;
        self
    }

    /// Asks for a TTY.
    #[must_use]
    pub fn with_tty(mut self) -> Self {
        self.tty = true;
        self
    }

    /// Which session.
    #[must_use]
    pub fn kind(&self) -> SessionKind {
        self.kind
    }

    /// Where it would run (§42.3).
    #[must_use]
    pub fn target(&self) -> &PodTarget {
        &self.target
    }

    /// The command, for an exec.
    #[must_use]
    pub fn command(&self) -> &[String] {
        &self.command
    }

    /// The port mappings, for a forward.
    #[must_use]
    pub fn ports(&self) -> &[PortMapping] {
        &self.ports
    }

    /// What this session would grant (§51).
    #[must_use]
    pub fn risk(&self) -> Risk {
        self.kind.risk()
    }

    /// The HTTP request the API server would be sent.
    ///
    /// Written down rather than left implicit, because "unsupported" is a dead end and this is
    /// not: it is the exact request, with the exact parameters, that the upgrade path will send.
    #[must_use]
    pub fn http_request(&self) -> Request {
        let mut request = Request::get(self.target.path(self.kind.as_str()));
        if let Some(container) = self.target.container() {
            request = request.query("container", container);
        }
        match self.kind {
            SessionKind::Exec | SessionKind::Attach => {
                request = request
                    .query("stdin", bool_word(self.stdin))
                    .query("stdout", "true")
                    .query("stderr", "true")
                    .query("tty", bool_word(self.tty));
                for argument in &self.command {
                    request = request.query("command", argument);
                }
            }
            SessionKind::PortForward => {
                for mapping in &self.ports {
                    request = request.query("ports", mapping.remote.to_string());
                }
            }
        }
        request
    }

    /// Opens the session.
    ///
    /// The success type is [`Infallible`], which is the honest signature: there is no combination
    /// of inputs under which this returns a session, so no caller can be written that holds one
    /// and no downstream code can grow around a handle that does not work. When the upgrade path
    /// exists, this signature changes and every caller has to be revisited — which is correct,
    /// because acquiring the ability to execute code in a container is not a silent upgrade.
    ///
    /// # Errors
    ///
    /// Always [`Unavailable`], naming each missing piece (`ADR-0018`).
    #[allow(
        clippy::result_large_err,
        reason = "the lint exists to stop a large failure taxing the successful case, and \
                  `Infallible` says there is no successful case to tax; boxing here would add an \
                  allocation to a value that is only ever read as a report"
    )]
    pub fn open(&self) -> Result<Infallible, Unavailable> {
        let mut missing = vec![Missing::ProtocolUpgrade, Missing::StreamMultiplexing];
        match self.kind {
            SessionKind::Exec | SessionKind::Attach => {
                missing.push(Missing::TerminalJobControl);
                if self.target.container().is_none() {
                    missing.push(Missing::ExplicitContainer);
                }
            }
            SessionKind::PortForward => {
                missing.push(Missing::TerminalJobControl);
                missing.push(Missing::LocalListener);
            }
        }
        missing.push(Missing::HostCapability);
        Err(Unavailable {
            kind: self.kind,
            target: self.target.clone(),
            missing,
        })
    }

    /// What was asked for, where, and what it would grant.
    #[must_use]
    pub fn describe(&self) -> String {
        let detail = match self.kind {
            SessionKind::Exec => format!("running [{}]", self.command.join(" ")),
            SessionKind::Attach => "attaching to the running streams".to_owned(),
            SessionKind::PortForward => {
                let mappings: Vec<String> = self
                    .ports
                    .iter()
                    .map(|mapping| mapping.describe())
                    .collect();
                format!("forwarding {}", mappings.join(", "))
            }
        };
        format!(
            "{} on {}, {detail}; grants {}",
            self.kind.as_str(),
            self.target.describe(),
            self.risk().as_str()
        )
    }
}

/// The API server's spelling of a boolean query parameter.
fn bool_word(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

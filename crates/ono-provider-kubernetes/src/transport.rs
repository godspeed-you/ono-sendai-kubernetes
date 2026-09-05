//! HTTP/1.1 over a byte stream, Kubernetes requests over that, and what a read knows about
//! itself.
//!
//! Specification §17, §18, §19.1, §20.1, §20.2 and §21.4. Core `ADR-0573` is why this module
//! exists at all: KUANG/11 brokers a *connection* and deliberately serves no `network.request`,
//! because "a request is a protocol, HTTP today, whatever else tomorrow, spoken over a connection
//! the host brokers". The host verified the destination, not the protocol — so the protocol is
//! this package's, written here, once.
//!
//! Nothing below names a socket. Everything is expressed against [`ByteStream`]: bytes out, bytes
//! in, synchronous. That is what lets §59.2's fixtures cover pagination, RBAC denial, `410 Gone`
//! and a watch stream with recorded bytes and no cluster — and it is also where the brokered
//! connection is wired in later, as one more implementation of the same three-method trait.
//!
//! **TLS is not here, and that is deliberate.** §8.4 puts certificate validation in this package
//! rather than in the host, and it belongs *below* this module: a TLS session is a [`ByteStream`]
//! that wraps the brokered [`ByteStream`], so the handshake, the trust store and the server
//! certificate are settled before the first request line is written. This module never sees a
//! certificate, which is the only way it can be tested against plain recorded bytes.
//!
//! What this module does not decide: the watch state machine (§19.2 onwards), the caches
//! themselves (§20.1), and how a result renders. It hands each of those the facts they need —
//! chunk frames, freshness, coverage — and stops there.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value as Json;

use crate::coverage::{Coverage, Gap, Outcome, Scope};
use crate::discovery::Gvr;
use crate::object::Object;

// --- the byte stream ---------------------------------------------------------------------------

/// A byte stream that could not carry the message.
///
/// One string, because everything below this module is somebody else's transport and the only
/// honest thing to report is what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamError {
    message: String,
}

impl StreamError {
    /// Records why the stream failed.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// What the stream said.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StreamError {}

/// Bytes out and bytes in: everything this provider needs of a connection.
///
/// Two methods rather than an HTTP client, because `ADR-0573` gives this package a brokered byte
/// connection and nothing else. A socket, a TLS session and a fixture all satisfy it, which is
/// what keeps the whole request path testable without a cluster (§59.1).
///
/// [`Self::read`] follows the read(2) convention this provider then has to respect everywhere:
/// it returns *what arrived*, not what was asked for, and `Ok(0)` means the peer closed. Code
/// that treats one read as one message is the oldest bug on this path.
pub trait ByteStream {
    /// Writes every byte, or fails.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when the connection cannot take them.
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), StreamError>;

    /// Reads what has arrived, up to `buf.len()` bytes. `Ok(0)` is end of stream.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when the connection fails.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, StreamError>;
}

/// A stream that replays recorded server bytes and keeps what was written to it.
///
/// §59.2's fixture transport. The recorded responses are concatenated exactly as a keep-alive
/// connection delivers them, so a pagination sequence is one fixture rather than a mock per call,
/// and [`Self::with_read_size`] can chop the delivery into pieces no message boundary respects.
#[derive(Debug, Clone, Default)]
pub struct FixtureStream {
    recorded: Vec<u8>,
    position: usize,
    written: Vec<u8>,
    read_size: Option<usize>,
}

impl FixtureStream {
    /// A stream that replays one recorded response.
    #[must_use]
    pub fn new(recorded: impl AsRef<[u8]>) -> Self {
        Self {
            recorded: recorded.as_ref().to_vec(),
            position: 0,
            written: Vec::new(),
            read_size: None,
        }
    }

    /// A stream that replays several responses in order, as one connection would deliver them.
    #[must_use]
    pub fn replaying(responses: &[impl AsRef<[u8]>]) -> Self {
        let mut recorded = Vec::new();
        for response in responses {
            recorded.extend_from_slice(response.as_ref());
        }
        Self {
            recorded,
            position: 0,
            written: Vec::new(),
            read_size: None,
        }
    }

    /// Hands over at most `size` bytes per read, the way a real connection does.
    #[must_use]
    pub fn with_read_size(mut self, size: usize) -> Self {
        self.read_size = Some(size.max(1));
        self
    }

    /// Every byte the client wrote, in order.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Every byte the client wrote, as text, so a test can read the requests it made.
    #[must_use]
    pub fn written_text(&self) -> String {
        String::from_utf8_lossy(&self.written).into_owned()
    }
}

impl ByteStream for FixtureStream {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        self.written.extend_from_slice(bytes);
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, StreamError> {
        let remaining = self.recorded.len().saturating_sub(self.position);
        let mut wanted = remaining.min(buf.len());
        if let Some(size) = self.read_size {
            wanted = wanted.min(size);
        }
        buf[..wanted].copy_from_slice(&self.recorded[self.position..self.position + wanted]);
        self.position += wanted;
        Ok(wanted)
    }
}

// --- time --------------------------------------------------------------------------------------

/// When an observation was made, in milliseconds since the Unix epoch.
///
/// A provider fact rather than a cluster one: it is when *this* provider saw the object, never
/// something derived from `resourceVersion`, which §14.3 says is not a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservedAt {
    unix_millis: u64,
}

impl ObservedAt {
    /// An instant, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn from_unix_millis(unix_millis: u64) -> Self {
        Self { unix_millis }
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub fn unix_millis(self) -> u64 {
        self.unix_millis
    }
}

/// Where `observed_at` comes from.
///
/// Injected rather than read from the wall clock in place, because a fixture test that cannot fix
/// the time cannot assert freshness at all — and freshness is half of what §17.1 requires a read
/// to carry.
pub trait Clock {
    /// Now.
    fn now(&self) -> ObservedAt;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> ObservedAt {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_millis())
            .unwrap_or(0);
        ObservedAt::from_unix_millis(u64::try_from(millis).unwrap_or(u64::MAX))
    }
}

/// A clock that always answers the same instant, for fixtures (§59.2).
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    at: ObservedAt,
}

impl FixedClock {
    /// A clock stopped at this instant.
    #[must_use]
    pub fn at_unix_millis(unix_millis: u64) -> Self {
        Self {
            at: ObservedAt::from_unix_millis(unix_millis),
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> ObservedAt {
        self.at
    }
}

// --- HTTP/1.1 ------------------------------------------------------------------------------------

/// An HTTP method, limited to the ones a Kubernetes API server answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Read.
    Get,
    /// Create.
    Post,
    /// Replace.
    Put,
    /// Change part of an object.
    Patch,
    /// Remove.
    Delete,
}

impl Method {
    /// The word that goes on the request line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// One HTTP request, before it becomes bytes.
///
/// Query parameters are held apart from the path so that encoding happens once, here. A
/// `continue` token is an opaque server blob that routinely contains `+`, `/` and `=` (§18.1),
/// and pasting one into a URL raw corrupts it in a way that only shows up as a short collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl Request {
    /// A request with a method and a path.
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            query: Vec::new(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// A `GET`.
    #[must_use]
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::Get, path)
    }

    /// Adds a query parameter, whose value is encoded when the target is built.
    #[must_use]
    pub fn query(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.push((name.into(), value.into()));
        self
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the body. `Content-Length` follows from it and is never written by hand.
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// The method.
    #[must_use]
    pub fn method(&self) -> Method {
        self.method
    }

    /// The path, without the query string.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The request target: path and encoded query string.
    #[must_use]
    pub fn target(&self) -> String {
        if self.query.is_empty() {
            return self.path.clone();
        }
        let query: Vec<String> = self
            .query
            .iter()
            .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
            .collect();
        format!("{}?{}", self.path, query.join("&"))
    }

    /// The request as an HTTP/1.1 message.
    ///
    /// CRLF everywhere and an empty line before the body: an API server answers nothing else, and
    /// the framing is this package's to get right now that the host does not speak it
    /// (`ADR-0573`).
    #[must_use]
    pub fn serialise(&self, host: &str) -> Vec<u8> {
        let mut wire = format!("{} {} HTTP/1.1\r\n", self.method.as_str(), self.target());
        wire.push_str(&format!("Host: {host}\r\n"));
        for (name, value) in &self.headers {
            wire.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = &self.body {
            wire.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        wire.push_str("\r\n");
        let mut bytes = wire.into_bytes();
        if let Some(body) = &self.body {
            bytes.extend_from_slice(body);
        }
        bytes
    }
}

/// Percent-encodes everything outside RFC 3986's unreserved set.
///
/// Deliberately conservative. Encoding a character that did not need it costs nothing; missing
/// one silently changes a selector or truncates a paginated collection.
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte));
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

/// One HTTP response, body included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    /// The status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The reason phrase, which servers may leave empty.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// One header, matched without regard to case as HTTP requires.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// How a body's end is recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// The server stated a length.
    Length(usize),
    /// Chunked transfer encoding, which is how a watch stream arrives (§19).
    Chunked,
    /// Neither, so the body ends when the connection does.
    ToEnd,
}

/// The status line and headers of a response, before its body is read.
#[derive(Debug, Clone)]
struct Head {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    framing: Framing,
}

/// An HTTP/1.1 conversation over one byte stream.
///
/// Buffered, because [`ByteStream::read`] returns what arrived rather than what was asked for and
/// every message boundary here has to be found rather than assumed.
#[derive(Debug)]
pub struct HttpConnection<S: ByteStream> {
    stream: S,
    host: String,
    buffer: Vec<u8>,
}

impl<S: ByteStream> HttpConnection<S> {
    /// A connection that writes `Host: host` on every request.
    #[must_use]
    pub fn new(stream: S, host: impl Into<String>) -> Self {
        Self {
            stream,
            host: host.into(),
            buffer: Vec::new(),
        }
    }

    /// The stream underneath, for a fixture to be inspected.
    #[must_use]
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// The stream underneath.
    #[must_use]
    pub fn into_stream(self) -> S {
        self.stream
    }

    /// The host this connection addresses.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Sends a request and reads the whole response.
    ///
    /// The status code is *not* judged here: a `403` is a well-formed response, and turning it
    /// into an error at this level would lose the body that says which permission was missing.
    ///
    /// # Errors
    ///
    /// [`ApiError::Stream`] when the connection fails or ends mid-message, and
    /// [`ApiError::Protocol`] when the bytes are not an HTTP/1.1 response.
    pub fn send(&mut self, request: &Request) -> Result<Response, ApiError> {
        let head = self.write_and_read_head(request)?;
        let body = match head.framing {
            Framing::Length(length) => self.take(length)?,
            Framing::Chunked => {
                let mut body = Vec::new();
                while let Some(chunk) = self.next_chunk_bytes()? {
                    body.extend_from_slice(&chunk);
                }
                body
            }
            Framing::ToEnd => self.take_to_end()?,
        };
        Ok(Response {
            status: head.status,
            reason: head.reason,
            headers: head.headers,
            body,
        })
    }

    /// Sends a request and hands back the body frame by frame.
    ///
    /// What a watch needs (§19.1): a stream that never ends cannot be buffered before it is read,
    /// and the caller must see each frame as it arrives.
    ///
    /// # Errors
    ///
    /// As [`Self::send`], for the head.
    pub fn open(&mut self, request: &Request) -> Result<ResponseStream<'_, S>, ApiError> {
        let head = self.write_and_read_head(request)?;
        Ok(ResponseStream {
            connection: self,
            head,
            finished: false,
        })
    }

    fn write_and_read_head(&mut self, request: &Request) -> Result<Head, ApiError> {
        let wire = request.serialise(&self.host);
        self.stream
            .write_all(&wire)
            .map_err(|error| ApiError::Stream(error.message().to_owned()))?;
        self.read_head()
    }

    fn read_head(&mut self) -> Result<Head, ApiError> {
        let block = self.read_until(b"\r\n\r\n")?;
        let text = String::from_utf8_lossy(&block).into_owned();
        let mut lines = text.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| ApiError::Protocol("the response has no status line".to_owned()))?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/") {
            return Err(ApiError::Protocol(format!(
                "the response does not start with an HTTP status line: {status_line:?}"
            )));
        }
        let status: u16 = parts
            .next()
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| ApiError::Protocol(format!("no status code in {status_line:?}")))?;
        let reason = parts.next().unwrap_or_default().to_owned();

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(ApiError::Protocol(format!("malformed header: {line:?}")));
            };
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }

        let framing = framing_of(status, &headers)?;
        Ok(Head {
            status,
            reason,
            headers,
            framing,
        })
    }

    /// Reads one chunk of a chunked body, or `None` at the terminating zero-length chunk.
    fn next_chunk_bytes(&mut self) -> Result<Option<Vec<u8>>, ApiError> {
        let line = self.read_until(b"\r\n")?;
        let text = String::from_utf8_lossy(&line).into_owned();
        let size_text = text.split(';').next().unwrap_or(&text).trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| ApiError::Protocol(format!("not a chunk size: {size_text:?}")))?;
        if size == 0 {
            // Trailers, then the empty line that ends them.
            while !self.read_until(b"\r\n")?.is_empty() {}
            return Ok(None);
        }
        let chunk = self.take(size)?;
        let terminator = self.take(2)?;
        if terminator != b"\r\n" {
            return Err(ApiError::Protocol(
                "a chunk did not end with CRLF".to_owned(),
            ));
        }
        Ok(Some(chunk))
    }

    /// Everything up to `needle`, consuming the needle too.
    fn read_until(&mut self, needle: &[u8]) -> Result<Vec<u8>, ApiError> {
        loop {
            if let Some(at) = position(&self.buffer, needle) {
                let found: Vec<u8> = self.buffer.drain(..at).collect();
                self.buffer.drain(..needle.len());
                return Ok(found);
            }
            if self.fill()? == 0 {
                return Err(ApiError::Stream(
                    "the connection closed before the message ended".to_owned(),
                ));
            }
        }
    }

    /// Exactly `length` bytes, or a stream failure. A short body is not a small answer.
    fn take(&mut self, length: usize) -> Result<Vec<u8>, ApiError> {
        while self.buffer.len() < length {
            if self.fill()? == 0 {
                return Err(ApiError::Stream(format!(
                    "the connection closed after {} of {length} body bytes",
                    self.buffer.len()
                )));
            }
        }
        Ok(self.buffer.drain(..length).collect())
    }

    /// Everything until the connection closes.
    fn take_to_end(&mut self) -> Result<Vec<u8>, ApiError> {
        while self.fill()? != 0 {}
        Ok(std::mem::take(&mut self.buffer))
    }

    fn fill(&mut self) -> Result<usize, ApiError> {
        let mut chunk = [0_u8; 4096];
        let read = self
            .stream
            .read(&mut chunk)
            .map_err(|error| ApiError::Stream(error.message().to_owned()))?;
        self.buffer.extend_from_slice(&chunk[..read]);
        Ok(read)
    }
}

/// Which framing the head declares.
fn framing_of(status: u16, headers: &[(String, String)]) -> Result<Framing, ApiError> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    if header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return Ok(Framing::Chunked);
    }
    if let Some(length) = header("content-length") {
        return length
            .trim()
            .parse()
            .map(Framing::Length)
            .map_err(|_| ApiError::Protocol(format!("not a content length: {length:?}")));
    }
    if status == 204 || status == 304 {
        return Ok(Framing::Length(0));
    }
    Ok(Framing::ToEnd)
}

fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A response whose body is read frame by frame.
///
/// The frames are handed over exactly as the server framed them. What a frame *means* — an
/// `ADDED`, a `BOOKMARK`, a `Status` announcing `410 Gone` — is §19's question, not this
/// module's, and answering it here would put the watch state machine inside the transport.
#[derive(Debug)]
pub struct ResponseStream<'a, S: ByteStream> {
    connection: &'a mut HttpConnection<S>,
    head: Head,
    finished: bool,
}

impl<S: ByteStream> ResponseStream<'_, S> {
    /// The status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.head.status
    }

    /// One header of the response.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head
            .headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The next frame, or `None` when the body has ended.
    ///
    /// A returned error also ends the body: a stream whose framing has been lost cannot be
    /// resynchronised, and pretending otherwise would hand the caller invented boundaries.
    pub fn next_chunk(&mut self) -> Option<Result<Vec<u8>, ApiError>> {
        if self.finished {
            return None;
        }
        let outcome = match self.head.framing {
            Framing::Chunked => match self.connection.next_chunk_bytes() {
                Ok(Some(chunk)) => Ok(chunk),
                Ok(None) => {
                    self.finished = true;
                    return None;
                }
                Err(error) => Err(error),
            },
            Framing::Length(0) => {
                self.finished = true;
                return None;
            }
            Framing::Length(length) => {
                self.finished = true;
                self.connection.take(length)
            }
            Framing::ToEnd => match self.connection.take_to_end() {
                Ok(rest) if rest.is_empty() => {
                    self.finished = true;
                    return None;
                }
                Ok(rest) => Ok(rest),
                Err(error) => Err(error),
            },
        };
        if outcome.is_err() {
            self.finished = true;
        }
        Some(outcome)
    }
}

// --- Kubernetes errors ---------------------------------------------------------------------------

/// A Kubernetes `Status`, as the server sends it when it refuses.
///
/// Kept whole rather than reduced to a code: the message is the part that names the missing
/// permission or the expired token, and it is the part an operator can act on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    code: Option<u16>,
    reason: Option<String>,
    message: Option<String>,
    details_kind: Option<String>,
    details_name: Option<String>,
}

impl Status {
    /// Reads a `Status` document, or `None` when the body is something else entirely.
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        let json: Json = serde_json::from_slice(body).ok()?;
        if json.get("kind").and_then(Json::as_str) != Some("Status") {
            return None;
        }
        let details = json.get("details");
        Some(Self {
            code: json
                .get("code")
                .and_then(Json::as_u64)
                .and_then(|code| u16::try_from(code).ok()),
            reason: text(json.get("reason")),
            message: text(json.get("message")),
            details_kind: text(details.and_then(|details| details.get("kind"))),
            details_name: text(details.and_then(|details| details.get("name"))),
        })
    }

    /// What is known when the server did not send a `Status` at all — a proxy's error page, say.
    #[must_use]
    pub fn from_http(code: u16, reason: &str) -> Self {
        Self {
            code: Some(code),
            reason: None,
            message: (!reason.is_empty()).then(|| reason.to_owned()),
            details_kind: None,
            details_name: None,
        }
    }

    /// The code the `Status` states, which need not equal the HTTP one.
    #[must_use]
    pub fn code(&self) -> Option<u16> {
        self.code
    }

    /// The machine-readable reason, such as `Forbidden` or `Expired`.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The human-readable message.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The resource the details name, where the server gave one.
    #[must_use]
    pub fn details_kind(&self) -> Option<&str> {
        self.details_kind.as_deref()
    }

    /// The object name the details name, where the server gave one.
    #[must_use]
    pub fn details_name(&self) -> Option<&str> {
        self.details_name.as_deref()
    }
}

fn text(value: Option<&Json>) -> Option<String> {
    value.and_then(Json::as_str).map(str::to_owned)
}

/// Which operation asked, because the answer to a refusal depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// One object by name.
    Get,
    /// A collection.
    List,
}

/// What the API server, or the connection under it, answered instead of data.
///
/// The variants exist so that §4 invariant 13 survives the transport: a denial, an absence, an
/// expired continuity token and a throttled request are four different answers, and the moment
/// they share a variant they start sharing a rendering too.
///
/// The [`Status`] payloads are boxed because every read on this path returns a `Result` carrying
/// this type, and the failure being larger than the answer would tax the successful case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The connection failed or ended mid-message.
    Stream(String),
    /// The bytes are not an HTTP/1.1 response this client can read.
    Protocol(String),
    /// The response arrived and is not the Kubernetes document it should be.
    Malformed(String),
    /// `403`: authorization refused (§21.4).
    Denied(Box<Status>),
    /// `404`: the object, the namespace or the endpoint is not there.
    NotFound(Box<Status>),
    /// `410`: the `resourceVersion` or `continue` token is too old (§18.2, §19.4).
    ContinuityExpired(Box<Status>),
    /// `429`: the request has not happened yet.
    RateLimited {
        /// What the server said about itself.
        status: Box<Status>,
        /// The `Retry-After` header, verbatim, because guessing a backoff makes an overloaded
        /// control plane worse.
        retry_after: Option<String>,
    },
    /// Any other status the server answered with.
    Failed {
        /// The HTTP status code.
        code: u16,
        /// What the server said about itself.
        status: Box<Status>,
    },
}

impl ApiError {
    /// The HTTP status code behind this answer, where there was one.
    #[must_use]
    pub fn code(&self) -> Option<u16> {
        match self {
            Self::Stream(_) | Self::Protocol(_) | Self::Malformed(_) => None,
            Self::Denied(_) => Some(403),
            Self::NotFound(_) => Some(404),
            Self::ContinuityExpired(_) => Some(410),
            Self::RateLimited { .. } => Some(429),
            Self::Failed { code, .. } => Some(*code),
        }
    }

    /// What the server said about itself, where it said anything.
    #[must_use]
    pub fn status(&self) -> Option<&Status> {
        match self {
            Self::Stream(_) | Self::Protocol(_) | Self::Malformed(_) => None,
            Self::Denied(status)
            | Self::NotFound(status)
            | Self::ContinuityExpired(status)
            | Self::RateLimited { status, .. }
            | Self::Failed { status, .. } => Some(status),
        }
    }

    /// Whether this answer broke a continuity token rather than a request.
    ///
    /// The distinction §18.2 and §19.4 both turn on: a `410` means the snapshot the caller was
    /// walking is gone, so continuing is not retrying — it is starting a different collection.
    #[must_use]
    pub fn is_continuity_expiry(&self) -> bool {
        matches!(self, Self::ContinuityExpired(_))
    }

    /// The coverage outcome this answer amounts to, for the operation that asked (§21.4).
    ///
    /// The operation matters: the same `403` is a refused read for a get and a refused list for a
    /// collection, and §21.4 keeps those apart because they are different things to ask for.
    /// A `404` splits the same way — one object being absent is a fact about the cluster, while a
    /// collection endpoint that is not there is an unserved API (§11.5), which is a fact about
    /// what this cluster can answer at all.
    ///
    /// `410` becomes [`Outcome::RequestFailed`] because the coverage vocabulary has no word for
    /// continuity; the error itself keeps the distinction, and §19.4's gap is the watch's to
    /// record.
    #[must_use]
    pub fn outcome(&self, operation: Operation) -> Outcome {
        match self {
            Self::Stream(_) => Outcome::Disconnected,
            Self::Protocol(_) | Self::Malformed(_) => Outcome::RequestFailed,
            Self::Denied(_) => match operation {
                Operation::Get => Outcome::ReadDenied,
                Operation::List => Outcome::ListDenied,
            },
            Self::NotFound(status) => {
                if status.details_kind() == Some("namespaces") {
                    Outcome::NamespaceAbsent
                } else {
                    match operation {
                        Operation::Get => Outcome::Absent,
                        Operation::List => Outcome::TypeNotServed,
                    }
                }
            }
            Self::ContinuityExpired(_) | Self::RateLimited { .. } | Self::Failed { .. } => {
                Outcome::RequestFailed
            }
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(detail) => write!(f, "the connection failed: {detail}"),
            Self::Protocol(detail) => write!(f, "the response is not HTTP/1.1: {detail}"),
            Self::Malformed(detail) => {
                write!(f, "the response is not a Kubernetes document: {detail}")
            }
            Self::Denied(status) => write!(f, "the API server refused: {}", said(status)),
            Self::NotFound(status) => write!(f, "not found: {}", said(status)),
            Self::ContinuityExpired(status) => {
                write!(f, "the continuity token expired: {}", said(status))
            }
            Self::RateLimited {
                status,
                retry_after,
            } => match retry_after {
                Some(after) => write!(f, "rate limited, retry after {after}: {}", said(status)),
                None => write!(f, "rate limited: {}", said(status)),
            },
            Self::Failed { code, status } => {
                write!(f, "the request failed with {code}: {}", said(status))
            }
        }
    }
}

fn said(status: &Status) -> &str {
    status.message().unwrap_or("the server gave no message")
}

impl std::error::Error for ApiError {}

/// Turns a non-2xx response into the answer it actually is.
fn classify(response: Response) -> Result<Response, ApiError> {
    let code = response.status();
    if (200..300).contains(&code) {
        return Ok(response);
    }
    let retry_after = response.header("retry-after").map(str::to_owned);
    let status = Status::parse(response.body())
        .unwrap_or_else(|| Status::from_http(code, response.reason()));
    let status = Box::new(status);
    Err(match code {
        403 => ApiError::Denied(status),
        404 => ApiError::NotFound(status),
        410 => ApiError::ContinuityExpired(status),
        429 => ApiError::RateLimited {
            status,
            retry_after,
        },
        other => ApiError::Failed {
            code: other,
            status,
        },
    })
}

// --- freshness -------------------------------------------------------------------------------------

/// Which REST surface answered: the source endpoint category §17.1 requires a read to carry.
///
/// Recorded once, here, rather than left as a path for every consumer to parse again — and §20.1
/// needs it, because a cache whose entries cannot say where they came from cannot have
/// independent validity rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointCategory {
    /// The core group under `/api` (§13.3).
    Core,
    /// A named group under `/apis`, which includes every CRD and aggregated API.
    Group,
}

impl EndpointCategory {
    /// Which surface this collection lives on.
    #[must_use]
    pub fn of(gvr: &Gvr) -> Self {
        if gvr.group().is_empty() {
            Self::Core
        } else {
            Self::Group
        }
    }
}

/// How this provider came by the object.
///
/// §20.2's requirement in one word: the user MUST be able to tell a direct read from a cached
/// observation, and a value that cannot say which it is cannot be trusted to be either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The API server answered this request.
    DirectRead,
    /// A cache answered, from an earlier read (§20.1).
    Cache,
    /// A watch event carried it (§19.3).
    WatchEvent,
}

/// What a read knows about its own age and provenance (§17.1, §20.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freshness {
    observed_at: ObservedAt,
    resource_version: Option<String>,
    provider_instance: String,
    scope: Scope,
    endpoint: EndpointCategory,
    origin: Origin,
    watch_synced: Option<bool>,
}

impl Freshness {
    /// What a direct read carries.
    #[must_use]
    pub fn direct_read(
        observed_at: ObservedAt,
        resource_version: Option<String>,
        provider_instance: impl Into<String>,
        scope: Scope,
        endpoint: EndpointCategory,
    ) -> Self {
        Self {
            observed_at,
            resource_version,
            provider_instance: provider_instance.into(),
            scope,
            endpoint,
            origin: Origin::DirectRead,
            watch_synced: None,
        }
    }

    /// When this provider observed the object.
    #[must_use]
    pub fn observed_at(&self) -> ObservedAt {
        self.observed_at
    }

    /// The `resourceVersion` observed, an opaque continuity token and never a clock (§14.3).
    #[must_use]
    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    /// Which provider instance observed it (§6.2).
    #[must_use]
    pub fn provider_instance(&self) -> &str {
        &self.provider_instance
    }

    /// What was asked about.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Which REST surface answered.
    #[must_use]
    pub fn endpoint(&self) -> EndpointCategory {
        self.endpoint
    }

    /// How the value was come by.
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.origin
    }

    /// Whether a watch was in sync when a cache served this, where a watch applies (§20.2).
    #[must_use]
    pub fn watch_synced(&self) -> Option<bool> {
        self.watch_synced
    }

    /// Whether the API server answered this request, rather than a cache.
    #[must_use]
    pub fn is_direct_read(&self) -> bool {
        self.origin == Origin::DirectRead
    }

    /// The same observation, as a cache would later serve it.
    ///
    /// `observed_at` is deliberately carried over rather than refreshed: the object is as old as
    /// the read that produced it, and stamping a cache hit with the time it was served is how an
    /// hour-old object comes to look current (§20.2).
    #[must_use]
    pub fn as_cached(&self, watch_synced: bool) -> Self {
        Self {
            origin: Origin::Cache,
            watch_synced: Some(watch_synced),
            ..self.clone()
        }
    }

    /// The same observation, as a watch delivered it (§19.3).
    #[must_use]
    pub fn as_watch_event(&self) -> Self {
        Self {
            origin: Origin::WatchEvent,
            watch_synced: Some(true),
            ..self.clone()
        }
    }
}

// --- Kubernetes requests -----------------------------------------------------------------------

/// What a list asks for beyond the collection itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListOptions {
    limit: Option<u32>,
    continue_token: Option<String>,
    label_selector: Option<String>,
    field_selector: Option<String>,
    resource_version: Option<String>,
    max_pages: Option<usize>,
}

impl ListOptions {
    /// Everything the server would default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The page size to ask for (§18.1).
    #[must_use]
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Continues a paginated sequence from a token the server issued.
    #[must_use]
    pub fn continue_from(mut self, token: impl Into<String>) -> Self {
        self.continue_token = Some(token.into());
        self
    }

    /// A Kubernetes label selector, passed through unchanged (§17.4).
    #[must_use]
    pub fn label_selector(mut self, selector: impl Into<String>) -> Self {
        self.label_selector = Some(selector.into());
        self
    }

    /// A Kubernetes field selector, passed through unchanged (§17.5).
    #[must_use]
    pub fn field_selector(mut self, selector: impl Into<String>) -> Self {
        self.field_selector = Some(selector.into());
        self
    }

    /// Asks the server to answer from a particular `resourceVersion`.
    #[must_use]
    pub fn at_resource_version(mut self, resource_version: impl Into<String>) -> Self {
        self.resource_version = Some(resource_version.into());
        self
    }

    /// How many pages the caller intends to consume (§18.4, §18.5).
    ///
    /// Stopping here is the pipeline's decision and not provider incompleteness, so it is
    /// recorded as "more may exist upstream" rather than as a gap — `first 20` must not cry wolf,
    /// and a truncated view must not read as the whole cluster.
    #[must_use]
    pub fn max_pages(mut self, pages: usize) -> Self {
        self.max_pages = Some(pages);
        self
    }

    /// The page budget, where the caller set one.
    #[must_use]
    pub fn page_budget(&self) -> Option<usize> {
        self.max_pages
    }

    /// The continue token this request would send.
    #[must_use]
    pub fn continue_token(&self) -> Option<&str> {
        self.continue_token.as_deref()
    }

    fn apply(&self, mut request: Request) -> Request {
        if let Some(limit) = self.limit {
            request = request.query("limit", limit.to_string());
        }
        if let Some(token) = &self.continue_token {
            request = request.query("continue", token);
        }
        if let Some(selector) = &self.label_selector {
            request = request.query("labelSelector", selector);
        }
        if let Some(selector) = &self.field_selector {
            request = request.query("fieldSelector", selector);
        }
        if let Some(version) = &self.resource_version {
            request = request.query("resourceVersion", version);
        }
        request
    }
}

/// Where a collection lives on the API server, for this scope.
///
/// Built from [`Gvr::path`] rather than beside it: the namespace is interleaved between the
/// version and the resource, which is a shape only the REST surface knows, and a second place
/// that assembles these paths is a second place to get `/api` versus `/apis` wrong (§13.3).
/// A scope with no namespace — cluster-scoped, or every namespace — is the collection endpoint
/// itself; §9.2 forbids inventing a namespace for the first, and §9.4 requires the second to be
/// deliberate rather than a default.
#[must_use]
pub fn collection_path(gvr: &Gvr, scope: &Scope) -> String {
    let base = gvr.path();
    let Some(namespace) = scope.namespace() else {
        return base;
    };
    match base.rsplit_once('/') {
        Some((prefix, resource)) => format!("{prefix}/namespaces/{namespace}/{resource}"),
        None => base,
    }
}

/// Where one object lives: its collection, then its name (§17.1).
#[must_use]
pub fn object_path(gvr: &Gvr, scope: &Scope, name: &str) -> String {
    format!("{}/{}", collection_path(gvr, scope), name)
}

/// The request that reads one object.
#[must_use]
pub fn get_request(gvr: &Gvr, scope: &Scope, name: &str) -> Request {
    Request::get(object_path(gvr, scope, name))
}

/// The request that reads one page of a collection.
#[must_use]
pub fn list_request(gvr: &Gvr, scope: &Scope, options: &ListOptions) -> Request {
    options.apply(Request::get(collection_path(gvr, scope)))
}

/// The request that opens a watch from a `resourceVersion` (§19.1).
///
/// The request shape only. Where the version comes from, what happens when the stream breaks and
/// how a `410` is reported are §19's, and they are a state machine rather than a request.
///
/// `allowWatchBookmarks` is asked for because bookmarks are what let a reconnect resume from a
/// checkpoint instead of relisting; a watch opened without a `resourceVersion` starts from "now"
/// and silently loses everything in between.
#[must_use]
pub fn watch_request(
    gvr: &Gvr,
    scope: &Scope,
    options: &ListOptions,
    from_resource_version: Option<&str>,
) -> Request {
    let mut request = options
        .apply(Request::get(collection_path(gvr, scope)))
        .query("watch", "true")
        .query("allowWatchBookmarks", "true");
    if let Some(version) = from_resource_version {
        request = request.query("resourceVersion", version);
    }
    request
}

// --- results -----------------------------------------------------------------------------------

/// One object, and what the read knows about itself (§17.1).
#[derive(Debug, Clone, PartialEq)]
pub struct Read {
    object: Object,
    freshness: Freshness,
}

impl Read {
    /// The object.
    #[must_use]
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// How fresh it is and where it came from.
    #[must_use]
    pub fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    /// Both halves.
    #[must_use]
    pub fn into_parts(self) -> (Object, Freshness) {
        (self.object, self.freshness)
    }
}

/// One page of a collection, with the list metadata §17.2 requires kept.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    objects: Vec<Object>,
    resource_version: Option<String>,
    continue_token: Option<String>,
    remaining: Option<i64>,
    freshness: Freshness,
}

impl Page {
    /// The objects on this page.
    #[must_use]
    pub fn objects(&self) -> &[Object] {
        &self.objects
    }

    /// The objects, moved out.
    #[must_use]
    pub fn into_objects(self) -> Vec<Object> {
        self.objects
    }

    /// The collection's `resourceVersion`, which is the snapshot a continued sequence walks.
    #[must_use]
    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    /// The token that reaches the next page, where there is one.
    #[must_use]
    pub fn continue_token(&self) -> Option<&str> {
        self.continue_token.as_deref()
    }

    /// What the server said is still to come, where it said anything.
    #[must_use]
    pub fn remaining_item_count(&self) -> Option<i64> {
        self.remaining
    }

    /// How fresh the page is.
    #[must_use]
    pub fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    /// Whether this page is the whole collection.
    ///
    /// §18.1: a continue token means incomplete, and a single page presented as a complete list
    /// is the expensive mistake here — a shorter answer that reads as a whole one.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.continue_token.is_none()
    }
}

/// Why a paginated sequence stopped being one snapshot (§18.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakReason {
    /// The server expired the `continue` token, so the snapshot it pointed into is gone.
    TokenExpired,
    /// A page came back from a different collection `resourceVersion` than the sequence started
    /// in.
    SnapshotChanged,
}

/// Whether the pages of a listing form one consistent snapshot (§18.2).
///
/// A separate question from coverage. Coverage says which scopes answered; continuity says
/// whether the answers belong together. A listing can be complete and discontinuous — every page
/// arrived, from two different moments — and reporting only the first would present a collection
/// that may hold one object twice and miss another as if it were a clean read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continuity {
    /// Every page came from the same snapshot.
    Intact,
    /// The sequence stopped being one snapshot, for this reason.
    Broken(BreakReason),
}

impl Continuity {
    /// Whether the pages belong together.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        matches!(self, Self::Intact)
    }
}

/// A whole collection, as far as it could be read.
#[derive(Debug, Clone, PartialEq)]
pub struct Listing {
    objects: Vec<Object>,
    coverage: Coverage,
    resource_version: Option<String>,
    continuity: Continuity,
    error: Option<ApiError>,
    freshness: Freshness,
    pages: usize,
}

impl Listing {
    /// The objects that arrived.
    #[must_use]
    pub fn objects(&self) -> &[Object] {
        &self.objects
    }

    /// The objects, moved out.
    #[must_use]
    pub fn into_objects(self) -> Vec<Object> {
        self.objects
    }

    /// What was observed and what was not (§18.3, §21.5).
    #[must_use]
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// The snapshot the sequence walked.
    #[must_use]
    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    /// Whether the pages form one snapshot (§18.2).
    #[must_use]
    pub fn continuity(&self) -> &Continuity {
        &self.continuity
    }

    /// The error that ended the sequence, attached to the collection as §18.3 requires.
    #[must_use]
    pub fn error(&self) -> Option<&ApiError> {
        self.error.as_ref()
    }

    /// How fresh the listing is.
    #[must_use]
    pub fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    /// How many pages were read.
    #[must_use]
    pub fn pages(&self) -> usize {
        self.pages
    }
}

// --- the client ------------------------------------------------------------------------------------

/// Reads Kubernetes objects over one byte stream.
///
/// Everything is synchronous and nothing is retried here. Retry policy, backoff and reconnection
/// are decisions with cluster-wide consequences (§19.5), and burying them under a read would make
/// them invisible to the caller who has to answer for them.
pub struct Client<S: ByteStream, C: Clock = SystemClock> {
    connection: HttpConnection<S>,
    provider_instance: String,
    clock: C,
    default_headers: Vec<(String, String)>,
}

impl<S: ByteStream> Client<S, SystemClock> {
    /// A client on the wall clock.
    #[must_use]
    pub fn new(stream: S, host: impl Into<String>, provider_instance: impl Into<String>) -> Self {
        Self::with_clock(stream, host, provider_instance, SystemClock)
    }
}

impl<S: ByteStream, C: Clock> Client<S, C> {
    /// A client on a clock the caller chooses, which is what makes freshness assertable (§59.2).
    #[must_use]
    pub fn with_clock(
        stream: S,
        host: impl Into<String>,
        provider_instance: impl Into<String>,
        clock: C,
    ) -> Self {
        Self {
            connection: HttpConnection::new(stream, host),
            provider_instance: provider_instance.into(),
            clock,
            default_headers: vec![("Accept".to_owned(), "application/json".to_owned())],
        }
    }

    /// Adds a header sent on every request — an `Authorization`, typically.
    ///
    /// The value never reaches [`fmt::Debug`] (§8.1, §4 invariant 21): a bearer token is exactly
    /// the kind of thing a derived `Debug` writes into a log line, and the leak is silent until
    /// somebody reads the log.
    #[must_use]
    pub fn with_default_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.default_headers.push((name.into(), value.into()));
        self
    }

    /// Which provider instance this client speaks for (§6.2).
    #[must_use]
    pub fn provider_instance(&self) -> &str {
        &self.provider_instance
    }

    /// The stream underneath, for a fixture to be inspected.
    #[must_use]
    pub fn stream(&self) -> &S {
        self.connection.stream()
    }

    /// The connection underneath, for a watch to stream over (§19).
    pub fn connection(&mut self) -> &mut HttpConnection<S> {
        &mut self.connection
    }

    /// The stream underneath.
    #[must_use]
    pub fn into_stream(self) -> S {
        self.connection.into_stream()
    }

    /// Reads one object (§17.1).
    ///
    /// # Errors
    ///
    /// [`ApiError`], which distinguishes a denial from an absence from a failed connection —
    /// §21.4's whole point.
    pub fn get(&mut self, gvr: &Gvr, scope: &Scope, name: &str) -> Result<Read, ApiError> {
        let request = self.decorate(get_request(gvr, scope, name));
        let response = classify(self.connection.send(&request)?)?;
        let observed_at = self.clock.now();
        let text = std::str::from_utf8(response.body())
            .map_err(|error| ApiError::Malformed(error.to_string()))?;
        let object = Object::parse(&self.provider_instance, text)
            .map_err(|error| ApiError::Malformed(error.to_string()))?;
        let freshness = Freshness::direct_read(
            observed_at,
            object.resource_version().map(str::to_owned),
            &self.provider_instance,
            scope.clone(),
            EndpointCategory::of(gvr),
        );
        Ok(Read { object, freshness })
    }

    /// Reads one page of a collection (§17.2, §18.1).
    ///
    /// # Errors
    ///
    /// [`ApiError`] as [`Self::get`].
    pub fn list_page(
        &mut self,
        gvr: &Gvr,
        scope: &Scope,
        options: &ListOptions,
    ) -> Result<Page, ApiError> {
        let request = self.decorate(list_request(gvr, scope, options));
        let response = classify(self.connection.send(&request)?)?;
        let observed_at = self.clock.now();
        let document: Json = serde_json::from_slice(response.body())
            .map_err(|error| ApiError::Malformed(error.to_string()))?;
        let metadata = document.get("metadata");
        let resource_version = text(metadata.and_then(|meta| meta.get("resourceVersion")));
        let continue_token =
            text(metadata.and_then(|meta| meta.get("continue"))).filter(|token| !token.is_empty());
        let remaining = metadata
            .and_then(|meta| meta.get("remainingItemCount"))
            .and_then(Json::as_i64);

        let item_api_version = text(document.get("apiVersion"));
        let item_kind = text(document.get("kind"))
            .map(|kind| kind.strip_suffix("List").unwrap_or(&kind).to_owned());
        let items = document
            .get("items")
            .and_then(Json::as_array)
            .ok_or_else(|| ApiError::Malformed("the collection has no `items`".to_owned()))?;

        let mut objects = Vec::with_capacity(items.len());
        for item in items {
            let item = identify(
                item.clone(),
                item_api_version.as_deref(),
                item_kind.as_deref(),
            );
            objects.push(
                Object::from_json(&self.provider_instance, item)
                    .map_err(|error| ApiError::Malformed(error.to_string()))?,
            );
        }

        let freshness = Freshness::direct_read(
            observed_at,
            resource_version.clone(),
            &self.provider_instance,
            scope.clone(),
            EndpointCategory::of(gvr),
        );
        Ok(Page {
            objects,
            resource_version,
            continue_token,
            remaining,
            freshness,
        })
    }

    /// Reads a whole collection, following `continue` tokens (§18).
    ///
    /// Never fails as a whole: a sequence that dies on page N+1 still knows about pages 1..N, and
    /// §18.3 says those may be returned as long as coverage is partial and the error is attached.
    /// The sequence is never restarted here — a fresh list mixed into a continued one is exactly
    /// what §18.2 forbids without a continuity break, so an expired token ends the walk and says
    /// so.
    pub fn list(&mut self, gvr: &Gvr, scope: &Scope, options: &ListOptions) -> Listing {
        let mut coverage = Coverage::complete(scope.clone());
        let mut objects: Vec<Object> = Vec::new();
        let mut continuity = Continuity::Intact;
        let mut error = None;
        let mut snapshot: Option<String> = None;
        let mut observed_at = self.clock.now();
        let mut pages = 0_usize;
        let mut page_options = options.clone();

        loop {
            match self.list_page(gvr, scope, &page_options) {
                Ok(page) => {
                    pages += 1;
                    observed_at = page.freshness().observed_at();
                    match (&snapshot, page.resource_version()) {
                        (None, version) => snapshot = version.map(str::to_owned),
                        (Some(first), Some(version)) if first != version => {
                            continuity = Continuity::Broken(BreakReason::SnapshotChanged);
                        }
                        _ => {}
                    }
                    let token = page.continue_token().map(str::to_owned);
                    objects.extend(page.into_objects());
                    coverage.observed(scope.clone());
                    let Some(token) = token else {
                        break;
                    };
                    if options.page_budget().is_some_and(|budget| pages >= budget) {
                        // §18.4: the pipeline stopped asking. Not a gap, and not silence either.
                        coverage.more_available();
                        break;
                    }
                    page_options = page_options.continue_from(token);
                }
                Err(failure) => {
                    if failure.is_continuity_expiry() {
                        continuity = Continuity::Broken(BreakReason::TokenExpired);
                    }
                    coverage.record(Gap::new(scope.clone(), failure.outcome(Operation::List)));
                    error = Some(failure);
                    break;
                }
            }
        }

        let freshness = Freshness::direct_read(
            observed_at,
            snapshot.clone(),
            &self.provider_instance,
            scope.clone(),
            EndpointCategory::of(gvr),
        );
        Listing {
            objects,
            coverage,
            resource_version: snapshot,
            continuity,
            error,
            freshness,
            pages,
        }
    }

    fn decorate(&self, mut request: Request) -> Request {
        for (name, value) in &self.default_headers {
            request = request.header(name, value);
        }
        request
    }
}

impl<S: ByteStream, C: Clock> fmt::Debug for Client<S, C> {
    /// Names the headers and never their values (§8.1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<&str> = self
            .default_headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        f.debug_struct("Client")
            .field("host", &self.connection.host())
            .field("provider_instance", &self.provider_instance)
            .field("default_headers", &headers)
            .finish()
    }
}

/// Gives a list item the `apiVersion` and `kind` the list's own identity implies.
///
/// The API server omits both on the items of a collection, because the list states them once.
/// Reading the items bare would lose the GVK altogether; taking the list's kind verbatim would
/// type every Pod as a `PodList`. Neither is overwritten where the server did send one — an
/// aggregated or mixed list is entitled to disagree with its envelope.
fn identify(mut item: Json, api_version: Option<&str>, kind: Option<&str>) -> Json {
    let Some(object) = item.as_object_mut() else {
        return item;
    };
    if !object.contains_key("apiVersion")
        && let Some(api_version) = api_version
    {
        object.insert(
            "apiVersion".to_owned(),
            Json::String(api_version.to_owned()),
        );
    }
    if !object.contains_key("kind")
        && let Some(kind) = kind
    {
        object.insert("kind".to_owned(), Json::String(kind.to_owned()));
    }
    item
}

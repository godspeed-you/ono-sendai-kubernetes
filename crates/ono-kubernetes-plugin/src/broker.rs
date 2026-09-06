//! The host's brokered connection, as the [`ByteStream`] everything above it is written against.
//!
//! Core's `ADR-0573` gives a package a *connection* and deliberately no `network.request`: "a
//! request is a protocol, HTTP today, whatever else tomorrow, spoken over a connection the host
//! brokers". `ono_provider_kubernetes::transport` takes that literally and expresses the whole
//! request path against three synchronous methods. This module is the thirty lines that join the
//! two: `network.connect` for the socket, `streams.emit` to write, `streams.next` to read.
//!
//! **Reads are exposed synchronously, so nothing here is faked.** `streams.next` blocks up to a
//! deadline and answers `{values, complete, error}`. The `complete` flag is what makes the
//! adapter honest: `read(2)`'s `Ok(0)` means *the peer closed*, and a deadline that expired with
//! no bytes is a different thing entirely. Collapsing the two would end every slow response as a
//! truncated one. This stream reports the first as end of stream and the second as a failure that
//! says so.
//!
//! **The borrow lasts one call, not one connection.** A read is a host call, so a read needs the
//! invocation context — and so does `Ctx::emit`. When the stream *held* `&mut Ctx` for as long
//! as the connection lived, nothing could be emitted while a response body was open, which is
//! why `k8s-change` could only ever answer with a bounded observation (`ADR-0022` §5). The
//! context is therefore held here in a [`Lease`]: the stream borrows it for the duration of one
//! `streams.next`, gives it back, and the handler emits between two reads with the connection
//! still open. Nothing about the shape of [`ByteStream`] had to change, because the borrow was
//! never a property of the trait — it was a property of what this struct chose to keep.
//!
//! The lease is checked rather than assumed: it hands the context out one caller at a time, and
//! an overlap is a refusal that names itself rather than a panic or a silent second borrow. A
//! read *inside* an emission would be that overlap, and the watch loop is written so that the
//! two alternate.
//!
//! **A read policy is part of a connection rather than a constant.** A request/response exchange
//! that goes silent is a broken server, and three empty windows say so. A watch that goes silent
//! is a healthy watch — nothing changed — so silence is where the invocation looks for its
//! cancellation instead (§62.12). One constant cannot mean both, so [`ReadPolicy`] says which.
//!
//! **TLS wraps this stream rather than living in it.** A Kubernetes API server speaks HTTPS, and
//! §8.4 puts certificate validation in this package rather than in the host. That session is
//! `ono_provider_kubernetes::tls::TlsStream` over a [`BrokeredStream`], built from the trust
//! anchors of the kubeconfig context [`crate::query`] resolved, and it is itself a [`ByteStream`]
//! — so nothing here knows a certificate exists. A query that names a `host` instead of a context
//! has no kubeconfig and therefore no anchors, and speaks plain HTTP/1.1 straight over these
//! bytes: enough for an API server reached through `kubectl proxy`, and nothing else.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;

use ono_kuang_sdk::Ctx;
use ono_kuang_sdk::protocol::{WireError, method};
use ono_provider_kubernetes::transport::{ByteStream, StreamError};
use serde_json::{Value as Json, json};

/// How long one read of a request/response exchange waits for the first byte, in seconds.
const REQUEST_DEADLINE_SECONDS: f64 = 30.0;

/// How many empty deadline windows such a read tolerates before it calls the connection dead.
///
/// One is not enough: a host under load can answer an inbound pull with nothing and still have a
/// live socket. Unbounded is worse — a hung server would hang the invocation, and §62.12 wants a
/// query that terminates. Three windows is a bound with a reason rather than a round number.
const IDLE_WINDOWS: u32 = 3;

/// How long one read of an open watch waits before it comes back with nothing, in seconds.
///
/// Short, and short for one reason: this is the window in which a cancellation is observed. The
/// host serves one call at a time, so an invocation parked in a thirty-second read cannot be
/// told that the operator has stopped it until that read returns — and a watch spends almost all
/// of its life parked in a read. A quarter of a second costs four cheap host calls a second on
/// an idle watch and buys §62.12's "promptly".
const WATCH_POLL_SECONDS: f64 = 0.25;

/// How many chunks one `streams.next` asks for.
const CHUNKS_PER_READ: u64 = 16;

/// How a connection reads: how long one read waits, and what silence means.
///
/// Two policies rather than one constant, because the two conversations this package holds
/// disagree about silence. An API server that has accepted a request and then says nothing for
/// ninety seconds is broken. A watch that says nothing for ninety seconds is a collection in
/// which nothing happened, which is the ordinary case and not a fault (§19).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadPolicy {
    deadline_seconds: f64,
    idle_windows: Option<u32>,
    /// After how many quiet windows the read hands control back without ending anything.
    ///
    /// `None` is "wait as long as it takes", which is right for a request. A *watch* needs the
    /// other answer: it spends its life blocked here, and a caller that never regains control
    /// during silence cannot say anything about the silence — which is what §41.4's `stale`
    /// is, and what its "MUST not leave a frozen table" needs somebody to be able to notice.
    quiet_windows: Option<u32>,
}

impl ReadPolicy {
    /// A request and its response: a long window, and silence that eventually means failure.
    #[must_use]
    pub const fn request() -> Self {
        Self {
            deadline_seconds: REQUEST_DEADLINE_SECONDS,
            idle_windows: Some(IDLE_WINDOWS),
            quiet_windows: None,
        }
    }

    /// An open watch: a short window, and silence that means nothing has changed.
    ///
    /// No window limit at all. A watch is ended by the operator, by the server closing it, or by
    /// a budget the query named — never by this provider deciding that a quiet cluster is a
    /// broken one (§4 invariant 13 applied to time rather than to scope).
    ///
    /// It does hand control back after one quiet window, which is a different thing from ending:
    /// [`QUIET`] says "nothing this window", the connection stays open and unconsumed, and the
    /// caller resumes reading where it was. That is what lets a watch notice something about its
    /// own silence — §41.4 asks a live view not to look live while it is not, and a reader learns
    /// only from records that arrive.
    #[must_use]
    pub const fn watch() -> Self {
        Self {
            deadline_seconds: WATCH_POLL_SECONDS,
            idle_windows: None,
            quiet_windows: Some(1),
        }
    }
}

impl Default for ReadPolicy {
    fn default() -> Self {
        Self::request()
    }
}

/// The invocation context, lent to one caller at a time.
///
/// This is the whole of the change `ADR-0023` records. A brokered read and an emission both need
/// `&mut Ctx`, and they need it at alternating moments rather than at the same moment — so the
/// context is owned here and borrowed per call, instead of being held by whichever of the two
/// took it first. What the compiler cannot check across a `ByteStream` implementation the lease
/// checks at the point of use: an overlap is refused and says what overlapped.
pub struct Lease<'ctx, 'io> {
    ctx: RefCell<&'ctx mut Ctx<'io>>,
}

impl<'ctx, 'io> Lease<'ctx, 'io> {
    /// Takes the invocation context for the length of one handler.
    #[must_use]
    pub fn new(ctx: &'ctx mut Ctx<'io>) -> Self {
        Self {
            ctx: RefCell::new(ctx),
        }
    }

    /// Lends the context to `action` for exactly the length of that call.
    ///
    /// # Errors
    ///
    /// A refusal when the context is already lent out — a read and an emission that overlapped,
    /// which is a defect in this package rather than anything a cluster or a host can cause.
    pub fn with<T>(&self, action: impl FnOnce(&mut Ctx<'io>) -> T) -> Result<T, WireError> {
        let mut borrowed = self
            .ctx
            .try_borrow_mut()
            .map_err(|_| overlapping_borrow())?;
        Ok(action(&mut borrowed))
    }

    /// Whether the host has cancelled this invocation (§62.12).
    ///
    /// False while the context is lent out, which is only ever *during* a call that would itself
    /// have observed the cancellation. Nothing is lost by not answering it twice.
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.ctx.try_borrow().is_ok_and(|ctx| ctx.cancelled())
    }
}

impl fmt::Debug for Lease<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("lent", &self.ctx.try_borrow().is_err())
            .finish()
    }
}

/// A brokered connection, seen as bytes out and bytes in.
///
/// Holds a *reference* to the leased context rather than the context itself: the package never
/// receives a descriptor, which is the whole point of the broker (spec §31.21), but it also
/// never needs to hold the invocation for longer than one call. What survives between two reads
/// is the handle and whatever bytes have arrived and not been consumed — state, not a borrow.
pub struct BrokeredStream<'lease, 'ctx, 'io> {
    lease: &'lease Lease<'ctx, 'io>,
    connection: u64,
    pending: VecDeque<u8>,
    ended: bool,
    policy: ReadPolicy,
}

impl<'lease, 'ctx, 'io> BrokeredStream<'lease, 'ctx, 'io> {
    /// Opens a connection to `host:port` through the host's broker.
    ///
    /// # Errors
    ///
    /// The host's structured refusal — `capability.denied` without a `network.connect` grant, or
    /// with one whose scope does not cover this endpoint (spec §31.19).
    pub fn connect(
        lease: &'lease Lease<'ctx, 'io>,
        host: &str,
        port: u16,
        policy: ReadPolicy,
    ) -> Result<Self, WireError> {
        let answer = lease.with(|ctx| {
            ctx.host_call(
                method::NETWORK_CONNECT,
                json!({"host": host, "port": port, "protocol": "tcp"}),
            )
        })??;
        let connection = answer
            .get("handle")
            .and_then(Json::as_u64)
            .ok_or_else(|| protocol_error("the host answered `network.connect` with no handle"))?;
        Ok(Self {
            lease,
            connection,
            pending: VecDeque::new(),
            ended: false,
            policy,
        })
    }

    /// The handle the host gave this connection.
    #[must_use]
    pub const fn handle(&self) -> u64 {
        self.connection
    }

    /// Whether the host still holds this connection open.
    ///
    /// Asked before closing, because `network.close` on a handle the host has already retired is
    /// a protocol violation that quarantines the package — and the host retires a connection by
    /// itself the moment the peer closes it.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        !self.ended
    }

    /// Pulls one batch of received bytes into [`Self::pending`].
    ///
    /// The context is borrowed for the length of this call and given back before it returns,
    /// which is what lets a caller emit between two of them.
    fn pull(&mut self) -> Result<usize, StreamError> {
        let handle = self.connection;
        let deadline = self.policy.deadline_seconds;
        let answer = self
            .lease
            .with(|ctx| {
                ctx.host_call(
                    method::STREAMS_NEXT,
                    json!({
                        "handle": handle,
                        "max": CHUNKS_PER_READ,
                        "deadline": deadline,
                    }),
                )
            })
            .map_err(|busy| StreamError::new(busy.message))?
            .map_err(|error| StreamError::new(error.message))?;
        let mut arrived = 0;
        for value in answer
            .get("values")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            let hex = value
                .get("bytes")
                .and_then(|bytes| bytes.get("$bytes"))
                .and_then(Json::as_str)
                .unwrap_or_default();
            let chunk = decode_hex(hex).ok_or_else(|| {
                StreamError::new("the host delivered a chunk that is not hexadecimal bytes")
            })?;
            arrived += chunk.len();
            self.pending.extend(chunk);
        }
        if answer.get("complete").and_then(Json::as_bool) == Some(true) {
            // The host has taken the handle out of its table; asking again would be a protocol
            // violation, and closing it would be another.
            self.ended = true;
            if let Some(error) = answer.get("error").and_then(|error| error.get("message")) {
                return Err(StreamError::new(
                    error.as_str().unwrap_or("the connection failed"),
                ));
            }
        }
        Ok(arrived)
    }
}

impl ByteStream for BrokeredStream<'_, '_, '_> {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        if self.ended {
            return Err(StreamError::new("the brokered connection is closed"));
        }
        let handle = self.connection;
        // Hexadecimal rather than text: a request body is bytes, and `String::from_utf8` on the
        // way out would decide the encoding of something the caller never said was text.
        self.lease
            .with(|ctx| {
                ctx.host_call(
                    method::STREAMS_EMIT,
                    json!({
                        "handle": handle,
                        "values": [{"$bytes": encode_hex(bytes)}],
                    }),
                )
            })
            .map_err(|busy| StreamError::new(busy.message))?
            .map(|_| ())
            .map_err(|error| StreamError::new(error.message))
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, StreamError> {
        let mut idle = 0;
        while self.pending.is_empty() {
            if self.ended {
                return Ok(0);
            }
            if self.pull()? == 0 && self.pending.is_empty() && !self.ended {
                // A window that brought nothing is where a cancellation is noticed. §62.12 asks
                // for prompt termination, and a watch spends most of its life here rather than
                // in the emission path where the SDK would report it.
                if self.lease.cancelled() {
                    return Err(StreamError::new(CANCELLED));
                }
                idle += 1;
                // Nothing arrived, the peer has not gone away, and the caller asked to be told.
                // The buffer is untouched and the connection is still open, so resuming the read
                // continues exactly where it stopped — this is a yield, not an end.
                if self.policy.quiet_windows.is_some_and(|limit| idle >= limit) {
                    return Err(StreamError::quiet(QUIET));
                }
                if self.policy.idle_windows.is_some_and(|limit| idle >= limit) {
                    return Err(StreamError::new(format!(
                        "the API server sent nothing for {}s across {idle} reads, and the \
                         connection is still open — a silent peer is not an end of stream",
                        self.policy.deadline_seconds
                    )));
                }
            }
        }
        let wanted = buf.len().min(self.pending.len());
        for slot in buf.iter_mut().take(wanted) {
            *slot = self.pending.pop_front().unwrap_or(0);
        }
        Ok(wanted)
    }
}

/// Bytes as lowercase hexadecimal, the `$bytes` encoding of the wire.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Hexadecimal back into bytes, or `None` for anything that is not a whole run of hex digits.
#[must_use]
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digits = text.as_bytes();
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        bytes.push(u8::try_from(high * 16 + low).ok()?);
    }
    Some(bytes)
}

/// What a read reports when a window passed and the peer said nothing (§41.4).
///
/// The message beside `StreamError::quiet`, which is what a caller actually matches on: the
/// transport carries the distinction as a flag on its own error type rather than as a string this
/// implementation invented, so nothing above has to know which `ByteStream` it is reading.
/// Everything about the connection is unchanged — the caller may read again immediately and
/// continue mid-frame.
pub const QUIET: &str = "the connection produced nothing in this window";

/// What a read reports when the invocation was cancelled while the connection was open.
///
/// A cancellation is not a transport fault, so a caller checks [`Lease::cancelled`] rather than
/// reading this string. It exists so that a failure that escapes anyway says what happened.
pub const CANCELLED: &str = "the invocation was cancelled while the connection was open";

/// The context was asked for while it was already lent out.
fn overlapping_borrow() -> WireError {
    WireError {
        code: "Ono-Sendai-K11201".to_owned(),
        name: "runtime.trap".to_owned(),
        message: "the invocation context was asked for while a read of the brokered connection \
                  still held it"
            .to_owned(),
        help: Some(
            "A read and an emission overlapped. This is a defect in the Kubernetes provider, \
             not in the cluster or the host."
                .to_owned(),
        ),
        metadata: Box::default(),
    }
}

/// The host answered something the protocol does not allow.
fn protocol_error(message: &str) -> WireError {
    WireError {
        code: "Ono-Sendai-K11204".to_owned(),
        name: "runtime.protocol_violation".to_owned(),
        message: message.to_owned(),
        help: None,
        metadata: Box::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_hex, encode_hex};

    #[test]
    fn should_round_trip_every_byte_through_the_wire_encoding() {
        let all: Vec<u8> = (0..=255).collect();
        let text = encode_hex(&all);
        assert_eq!(text.len(), all.len() * 2);
        assert_eq!(decode_hex(&text).as_deref(), Some(all.as_slice()));
    }

    #[test]
    fn should_refuse_a_chunk_that_is_not_whole_hexadecimal_bytes() {
        // A half byte or a stray character is the host contradicting the contract, and the
        // stream says so rather than delivering a request body with a hole in it.
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex(""), Some(Vec::new()));
    }

    #[test]
    fn should_encode_a_request_line_the_way_the_host_reads_it_back() {
        assert_eq!(encode_hex(b"GET /api"), "474554202f617069");
    }
}

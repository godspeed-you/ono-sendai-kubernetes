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
//! **What is still missing, and is not here.** A Kubernetes API server speaks HTTPS. §8.4 puts
//! certificate validation in this package rather than in the host, which means a TLS session
//! wrapping this stream — `rustls` over a [`BrokeredStream`], with the kubeconfig's trust anchors
//! — has to exist before a production cluster is reachable. It does not exist yet, so the plugin
//! speaks HTTP/1.1 straight over the brokered bytes. That is enough for an API server reached
//! through a local proxy and not enough for anything else, and [`crate::query`] says so out loud
//! rather than connecting and failing obscurely.

use std::collections::VecDeque;

use ono_kuang_sdk::Ctx;
use ono_kuang_sdk::protocol::{WireError, method};
use ono_provider_kubernetes::transport::{ByteStream, StreamError};
use serde_json::{Value as Json, json};

/// How long one read waits for the first byte, in seconds, as `streams.next` counts it.
const READ_DEADLINE_SECONDS: u64 = 30;

/// How many empty deadline windows a read tolerates before it calls the connection dead.
///
/// One is not enough: a host under load can answer an inbound pull with nothing and still have a
/// live socket. Unbounded is worse — a hung server would hang the invocation, and §62.12 wants a
/// query that terminates. Three windows is a bound with a reason rather than a round number.
const IDLE_WINDOWS: u32 = 3;

/// How many chunks one `streams.next` asks for.
const CHUNKS_PER_READ: u64 = 16;

/// A brokered connection, seen as bytes out and bytes in.
///
/// Borrows the invocation context because every byte travels as a host call: the package never
/// receives a descriptor, which is the whole point of the broker (spec §31.21).
pub struct BrokeredStream<'ctx, 'io> {
    ctx: &'ctx mut Ctx<'io>,
    connection: u64,
    pending: VecDeque<u8>,
    ended: bool,
}

impl<'ctx, 'io> BrokeredStream<'ctx, 'io> {
    /// Opens a connection to `host:port` through the host's broker.
    ///
    /// # Errors
    ///
    /// The host's structured refusal — `capability.denied` without a `network.connect` grant, or
    /// with one whose scope does not cover this endpoint (spec §31.19).
    pub fn connect(ctx: &'ctx mut Ctx<'io>, host: &str, port: u16) -> Result<Self, WireError> {
        let answer = ctx.host_call(
            method::NETWORK_CONNECT,
            json!({"host": host, "port": port, "protocol": "tcp"}),
        )?;
        let connection = answer
            .get("handle")
            .and_then(Json::as_u64)
            .ok_or_else(|| protocol_error("the host answered `network.connect` with no handle"))?;
        Ok(Self {
            ctx,
            connection,
            pending: VecDeque::new(),
            ended: false,
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
    fn pull(&mut self) -> Result<usize, StreamError> {
        let answer = self
            .ctx
            .host_call(
                method::STREAMS_NEXT,
                json!({
                    "handle": self.connection,
                    "max": CHUNKS_PER_READ,
                    "deadline": READ_DEADLINE_SECONDS,
                }),
            )
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

impl ByteStream for BrokeredStream<'_, '_> {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        if self.ended {
            return Err(StreamError::new("the brokered connection is closed"));
        }
        // Hexadecimal rather than text: a request body is bytes, and `String::from_utf8` on the
        // way out would decide the encoding of something the caller never said was text.
        self.ctx
            .host_call(
                method::STREAMS_EMIT,
                json!({
                    "handle": self.connection,
                    "values": [{"$bytes": encode_hex(bytes)}],
                }),
            )
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
                idle += 1;
                if idle >= IDLE_WINDOWS {
                    return Err(StreamError::new(format!(
                        "the API server sent nothing for {}s across {IDLE_WINDOWS} reads, and \
                         the connection is still open — a silent peer is not an end of stream",
                        READ_DEADLINE_SECONDS
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

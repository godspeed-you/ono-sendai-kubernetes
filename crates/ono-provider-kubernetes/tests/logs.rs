//! Logs as observations, and exec, attach and port-forward as refusals that name what is missing.
//!
//! Specification §42, §51.1, §57 and §61.5 (Gate L). §42 is the section where a provider is most
//! tempted to become a terminal multiplexer, and every subsection of it draws a line:
//!
//! ```text
//! §42.1  logs are observations and carry target/provenance metadata
//! §42.2  logs may contain secrets and are never silently persisted as cache or history
//! §42.3  exec is not an ordinary mutation, and its target is explicit before execution
//! §42.4  attach shares remote-session infrastructure rather than being a provider callback
//! §42.5  port forward is a job/session with clear local and remote endpoints
//! §42.6  no hidden `kubectl` subprocess
//! ```
//!
//! So most of these tests are refusals, and each names the plausible mistake it stops. The three
//! that matter most: a retrieved log is never the complete output of a container, because the
//! runtime rotated and truncated it before anyone asked (§42.1); a log line is bytes, and a
//! decoder that replaces what does not decode has changed the evidence (§12.5's discipline
//! applied to a stream); and a remote session that cannot be opened says so rather than returning
//! a handle that appears to work (§42.3, §57.1).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::logs::{
    Bound, Ending, Instance, LineText, LogDecoder, LogFollow, LogRequest, LogRequestError, Matched,
    Missing, PodTarget, PortMapping, Retrieved, Risk, SessionKind, SessionRequest,
};
use ono_provider_kubernetes::transport::{FixtureStream, HttpConnection};

const INSTANCE: &str = "kubernetes:prod-eu";
const HOST: &str = "kubernetes.default.svc";

/// The Pod and container every test here reads from, named in full because §42.1 requires the
/// provenance and §42.3 requires the target to be explicit before anything runs.
fn target() -> PodTarget {
    PodTarget::new(INSTANCE, "shop", "checkout-7f9d").in_container("api")
}

/// The path a log source has to read to check that the module says what it does.
fn module_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/logs.rs");
    std::fs::read_to_string(path).expect("the module this test covers is readable")
}

// --- the request (§42.1) -------------------------------------------------------------------------

/// §42.1 lists container selection, previous, timestamps, follow and bounded tail/since as the
/// parameters a log capability supports. The plausible mistake is spelling one of them as a
/// Kubernetes query parameter that does not exist — `tail` rather than `tailLines`, `since`
/// rather than `sinceSeconds` — which the API server answers by ignoring it, so a caller asking
/// for the last ten lines silently receives the whole retained log.
#[test]
fn should_ask_the_log_subresource_with_every_parameter_it_was_given() {
    let request = LogRequest::new(target())
        .following()
        .with_timestamps()
        .tail_lines(100)
        .since_seconds(600)
        .limit_bytes(65_536)
        .http_request()
        .expect("a followed log of the current instance is a legal request");

    let wire = request.target();
    assert!(
        wire.starts_with("/api/v1/namespaces/shop/pods/checkout-7f9d/log?"),
        "the log is a subresource of the Pod, not a collection of its own: {wire}"
    );
    for parameter in [
        "container=api",
        "follow=true",
        "timestamps=true",
        "tailLines=100",
        "sinceSeconds=600",
        "limitBytes=65536",
    ] {
        assert!(wire.contains(parameter), "{wire} is missing {parameter}");
    }
    assert!(
        !wire.contains("previous"),
        "a request for the current instance must not ask for the previous one: {wire}"
    );
}

/// §42.1 says `previous` reaches the previous container, singular. The plausible mistake is a
/// numeric instance selector — "two restarts ago" — which reads like a history the API server
/// does not have: the kubelet retains the terminated container of exactly one prior instance, and
/// a parameter that promised more would return the same log under a different label.
#[test]
fn should_reach_exactly_one_prior_instance_and_no_further() {
    let request = LogRequest::new(target())
        .of_previous_instance()
        .http_request()
        .expect("a previous-instance log is a legal request");

    assert!(
        request.target().contains("previous=true"),
        "the prior instance is selected by a flag: {}",
        request.target()
    );

    let source = module_source();
    for invented in [
        "restartCount",
        "instances_ago",
        "nth_previous",
        "instance_index",
    ] {
        assert!(
            !source.contains(invented),
            "`{invented}` would offer a prior instance the kubelet does not retain (§42.1)"
        );
    }
}

/// A terminated instance's log cannot grow, so following it is a request that waits forever on a
/// body the server closes immediately. The plausible mistake is passing both through: the API
/// server accepts the combination and ignores `follow`, so the caller sees a stream that ends at
/// once and reads it as a container that just exited.
#[test]
fn should_refuse_to_follow_a_previous_instance() {
    let refused = LogRequest::new(target())
        .of_previous_instance()
        .following()
        .http_request();

    assert_eq!(refused.unwrap_err(), LogRequestError::FollowPrevious);
}

// --- what a retrieval is not (§42.1, §42.2) -----------------------------------------------------

/// The rule §42 exists for. A container's log is rotated and truncated by the runtime before this
/// provider asks for it, so there is no request whose answer is "everything the container wrote".
/// The plausible mistake is treating an unbounded request as an unbounded answer, and the type
/// stops it by always naming at least one bound.
#[test]
fn should_name_a_bound_even_when_the_request_asked_for_none() {
    let request = LogRequest::new(target());
    let retrieved = Retrieved::of(&request, Vec::new(), Ending::BodyEnded);

    assert!(
        retrieved.bounds().contains(&Bound::RuntimeRetention),
        "an unbounded request is still bounded by what the runtime kept: {:?}",
        retrieved.bounds()
    );
    assert!(
        !retrieved.bounds().is_empty(),
        "a retrieval with no bounds at all would read as the whole output of the container"
    );
}

/// The same rule for the case that looks most complete: a previous instance has terminated, so
/// its log can no longer change, and it is tempting to call that log final. It is not — rotation
/// already discarded part of it and the kubelet keeps only what fitted.
#[test]
fn should_bound_a_previous_instance_retrieval_too() {
    let request = LogRequest::new(target()).of_previous_instance();
    let retrieved = Retrieved::of(&request, Vec::new(), Ending::BodyEnded);

    assert_eq!(retrieved.instance(), Instance::Previous);
    assert!(retrieved.bounds().contains(&Bound::RuntimeRetention));
}

/// §42.1's provenance requirement. The plausible mistake is a bare list of lines: two logs from
/// two clusters look identical once the target is dropped, and a line attributed to the wrong Pod
/// is worse than no line at all.
#[test]
fn should_carry_the_target_it_was_read_from() {
    let request = LogRequest::new(target());
    let retrieved = Retrieved::of(&request, Vec::new(), Ending::BodyEnded);

    let described = retrieved.describe();
    for fact in [INSTANCE, "shop", "checkout-7f9d", "api"] {
        assert!(described.contains(fact), "{described} does not name {fact}");
    }
}

/// §42.2. The plausible mistake is deciding secrecy from content — no `password` in the bytes, so
/// it is safe to persist. Whether a log carries a secret is not decidable from the log, so the
/// answer is the same for every retrieval including an empty one.
#[test]
fn should_treat_every_log_as_possibly_secret_whatever_it_holds() {
    let request = LogRequest::new(target());
    let empty = Retrieved::of(&request, Vec::new(), Ending::BodyEnded);

    assert!(
        empty.may_contain_secrets(),
        "§42.2 is a property of the channel, not of the bytes that came down it"
    );
}

/// §42.2 forbids silently persisting a log as provider cache or temporal history. The plausible
/// mistake is a cache that stores logs "for the session" — the same convenience that makes lists
/// fast makes a Secret printed once readable for as long as the process lives.
#[test]
fn should_not_be_reachable_from_anything_that_persists() {
    for module in ["session.rs", "watch.rs", "coverage.rs"] {
        let path = format!("{}/src/{module}", env!("CARGO_MANIFEST_DIR"));
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        for reference in ["logs::", "LogFollow", "Retrieved"] {
            assert!(
                !source.contains(reference),
                "{module} references `{reference}`; §42.2 forbids a log becoming cache or history"
            );
        }
    }
}

/// The type must not offer the sentence §42.1 forbids. The plausible mistake is a convenience
/// accessor — `is_complete`, `full_output`, `all_lines` — whose name licenses exactly the
/// conclusion the runtime's rotation makes unavailable.
#[test]
fn should_offer_no_way_to_call_a_retrieval_the_whole_log() {
    let source = module_source();
    for forbidden in [
        "fn is_complete",
        "fn full_output",
        "fn all_lines",
        "fn entire_log",
    ] {
        assert!(
            !source.contains(forbidden),
            "`{forbidden}` would let a caller present a rotated log as the container's output"
        );
    }
}

/// §63.6's discipline applied to a stream, the way `events.rs` applies it to Events. The
/// plausible mistake is `if matches.is_empty() { "the container never logged an error" }`, which
/// is false whenever `tailLines` cut the line off, rotation discarded it, or the process wrote it
/// to a file rather than to stdout.
#[test]
fn should_not_read_an_empty_search_as_proof_the_container_never_printed_it() {
    let request = LogRequest::new(target()).tail_lines(10);
    let mut decoder = LogDecoder::for_request(&request);
    let lines = decoder.decode(b"listening on :8080\nready\n");
    let retrieved = Retrieved::of(&request, lines, Ending::BodyEnded);

    let found = retrieved.matching(|line| line.bytes().starts_with(b"panic"));
    assert!(matches!(found, Matched::NotObserved(_)));
    let outcome = found
        .outcome()
        .expect("a search that matched nothing says why");
    assert!(
        !outcome.is_evidence_of_absence(),
        "a log that does not contain a line is not a container that never wrote one (§42.1)"
    );
}

// --- a line is bytes (§42.1) ---------------------------------------------------------------------

/// A container writes bytes. The plausible mistake is `String::from_utf8_lossy`, which turns a
/// byte nobody can read into U+FFFD and hands the caller a line that looks like text and is not
/// the line the container wrote — evidence quietly edited on the way past.
#[test]
fn should_keep_a_line_that_is_not_utf8_as_bytes_and_say_where_it_stopped_decoding() {
    let mut decoder = LogDecoder::plain();
    let lines = decoder.decode(b"ok \xff\xfe tail\n");
    assert_eq!(lines.len(), 1);

    assert_eq!(lines[0].bytes(), b"ok \xff\xfe tail");
    match lines[0].text() {
        LineText::NotUtf8 { valid_up_to } => assert_eq!(valid_up_to, 3),
        LineText::Utf8(text) => panic!("{text:?} is not what the container wrote"),
    }
    assert!(lines[0].text().as_str().is_none());
    assert!(
        !lines[0]
            .bytes()
            .windows(3)
            .any(|window| window == [0xEF, 0xBF, 0xBD]),
        "U+FFFD must never be substituted into the bytes the container wrote"
    );
}

/// The counterpart: a line that does decode is text, and the type says so rather than making
/// every caller re-validate.
#[test]
fn should_read_a_utf8_line_as_text() {
    let mut decoder = LogDecoder::plain();
    let lines = decoder.decode("готово\n".as_bytes());

    assert_eq!(lines[0].text().as_str(), Some("готово"));
}

/// Chunked transfer flushes wherever the server's writer did, so a chunk boundary lands mid-line
/// as a matter of course. The plausible mistake is treating one chunk as one line, which splits a
/// stack trace across two records and loses the join.
#[test]
fn should_hold_a_line_that_arrives_across_two_chunks() {
    let mut decoder = LogDecoder::plain();

    assert!(decoder.decode(b"connection refu").is_empty());
    assert_eq!(decoder.pending_bytes(), 15);

    let lines = decoder.decode(b"sed\nretrying\n");
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].bytes(), b"connection refused");
    assert_eq!(decoder.pending_bytes(), 0);
}

/// A followed log's body can stop mid-line. The plausible mistake is flushing the remainder as if
/// it were a whole line, which presents half a message as a message the container finished
/// writing.
#[test]
fn should_mark_a_trailing_partial_line_as_unterminated() {
    let mut decoder = LogDecoder::plain();
    let _ = decoder.decode(b"done\nhalf a mess");

    let remainder = decoder
        .finish()
        .expect("the buffered remainder is handed over");
    assert_eq!(remainder.bytes(), b"half a mess");
    assert!(
        !remainder.is_terminated(),
        "a line the server never terminated is not a line the container completed"
    );
    assert!(
        decoder.finish().is_none(),
        "the remainder is handed over once"
    );
}

/// `timestamps=true` prefixes each line with the *container runtime's* clock. The plausible
/// mistake is splitting that prefix off unconditionally, which eats the first word of every line
/// from an application that prints its own timestamps.
#[test]
fn should_split_a_timestamp_only_when_timestamps_were_requested() {
    let stamped = "2026-09-05T09:14:02.113344Z listening on :8080\n";

    let mut plain = LogDecoder::plain();
    let unrequested = plain.decode(stamped.as_bytes());
    assert_eq!(unrequested[0].stamp(), None);
    assert_eq!(
        unrequested[0].text().as_str(),
        Some("2026-09-05T09:14:02.113344Z listening on :8080")
    );

    let mut timestamped = LogDecoder::timestamped();
    let requested = timestamped.decode(stamped.as_bytes());
    assert_eq!(requested[0].stamp(), Some("2026-09-05T09:14:02.113344Z"));
    assert_eq!(requested[0].text().as_str(), Some("listening on :8080"));
}

// --- follow and cancellation (§42.1, §61.5) -----------------------------------------------------

/// Gate L: a log follow terminates promptly under cancellation. The plausible mistake is a
/// cancelled follow that keeps decoding whatever the socket still delivers, so lines arrive after
/// the caller stopped reading and land in a record nobody is watching.
#[test]
fn should_stop_delivering_lines_once_the_follow_is_cancelled() {
    let request = LogRequest::new(target()).following();
    let mut follow = LogFollow::open(request);

    assert_eq!(follow.receive(b"first\n").len(), 1);
    follow.cancel();

    assert!(
        follow.receive(b"second\n").is_empty(),
        "a cancelled follow delivers nothing further"
    );
    assert_eq!(follow.delivered_lines(), 1);
    assert_eq!(follow.discarded_bytes(), 7);
    assert!(!follow.state().is_streaming());
}

/// A followed log's body ending means the connection ended. The plausible mistake is reading it
/// as the container having exited: a proxy closing an idle stream and a process terminating look
/// exactly the same from here, and only one of them is a fact about the workload.
#[test]
fn should_not_read_a_closed_body_as_a_container_that_stopped() {
    let request = LogRequest::new(target()).following();
    let mut follow = LogFollow::open(request);
    follow.receive(b"working\n");
    follow.closed();

    let described = follow.describe();
    assert!(
        described.contains("body ended"),
        "{described} must name what actually happened"
    );
    assert!(
        !described.contains("exited") && !described.contains("terminated"),
        "{described} claims something about the container the transport cannot see"
    );
}

/// A body that ends mid-line ends mid-line. The plausible mistake is a follow that drops what it
/// was holding when the connection went away, so the last thing the container wrote disappears —
/// silently, and exactly where a reader is looking hardest. It is handed over as an unterminated
/// line, which is what the bounded read already does with the same bytes.
#[test]
fn should_hand_over_what_a_followed_body_ended_mid_line_on() {
    let request = LogRequest::new(target()).following();
    let mut follow = LogFollow::open(request);

    assert_eq!(follow.receive(b"whole\nhalf of a").len(), 1);
    follow.closed();

    let rest = follow
        .finish()
        .expect("the bytes held back when the body ended are a line, not nothing");
    assert_eq!(rest.bytes(), b"half of a");
    assert!(
        !rest.is_terminated(),
        "the server never sent the newline that would end it, and saying it did would show half \
         a message as one the container finished writing"
    );
    assert_eq!(follow.delivered_lines(), 2);
    assert!(
        follow.finish().is_none(),
        "and there is nothing left to hand over twice"
    );
}

/// Provenance survives the follow, because the lines outlive the request that produced them.
#[test]
fn should_hand_a_follow_over_as_a_retrieval_that_still_names_its_target() {
    let request = LogRequest::new(target()).following().tail_lines(5);
    let mut follow = LogFollow::open(request);
    let lines = follow.receive(b"a\nb\n");
    follow.cancel();

    let retrieved = Retrieved::of(follow.request(), lines, Ending::Cancelled);
    assert_eq!(retrieved.target().pod(), "checkout-7f9d");
    assert_eq!(retrieved.line_count(), 2);
    assert!(retrieved.bounds().contains(&Bound::Tail(5)));
    assert_eq!(retrieved.ending(), &Ending::Cancelled);
}

/// The whole path over recorded bytes, as §59.2 requires: a chunked response from a fixture
/// stream, read frame by frame, decoded into lines. The plausible mistake is a decoder tested
/// only against whole lines, which passes until a real server flushes mid-word.
#[test]
fn should_decode_a_chunked_log_body_from_recorded_bytes() {
    let recorded = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/plain\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "9\r\nstarting\n\r\n",
        "8\r\nready\nwo\r\n",
        "6\r\nrking\n\r\n",
        "0\r\n\r\n",
    );
    let mut connection = HttpConnection::new(FixtureStream::new(recorded), HOST);
    let request = LogRequest::new(target()).following();
    let mut decoder = LogDecoder::for_request(&request);
    let http = request
        .http_request()
        .expect("a followed current-instance log is a legal request");

    let mut stream = connection
        .open(&http)
        .expect("the fixture answers the log request");
    assert_eq!(stream.status(), 200);
    let mut lines = Vec::new();
    while let Some(chunk) = stream.next_chunk() {
        lines.extend(decoder.decode(&chunk.expect("the fixture frames are well formed")));
    }

    let texts: Vec<Option<&str>> = lines.iter().map(|line| line.text().as_str()).collect();
    assert_eq!(
        texts,
        vec![Some("starting"), Some("ready"), Some("working")]
    );
    assert_eq!(decoder.pending_bytes(), 0);
}

// --- exec, attach and port forward (§42.3, §42.4, §42.5) ----------------------------------------

/// §42.3: exec is not an ordinary resource mutation. The plausible mistake is classifying it with
/// the reads it sits next to in this module, because it arrives over the same HTTP surface — and
/// a capability listed as a read is one nobody gates.
#[test]
fn should_classify_exec_as_code_execution_rather_than_a_read() {
    assert_eq!(SessionKind::Exec.risk(), Risk::CodeExecution);
    assert!(!SessionKind::Exec.risk().is_read_only());
    assert!(!SessionKind::Attach.risk().is_read_only());
    assert_eq!(SessionKind::PortForward.risk(), Risk::NetworkPath);
    assert!(!SessionKind::PortForward.risk().is_read_only());
}

/// §57.1 distinguishes declared capability from effective capability, and the honest answer here
/// is that none of the three is reachable over a brokered byte connection that speaks HTTP/1.1
/// request/response only. The plausible mistake is a stub that returns a session handle which
/// silently does nothing, so the gap is found in production rather than here.
#[test]
fn should_refuse_to_open_a_remote_session_and_name_what_is_missing() {
    let refusal = SessionRequest::exec(target(), vec!["/bin/sh".to_owned(), "-c".to_owned()])
        .open()
        .expect_err("no remote session can be opened over this transport");

    assert_eq!(refusal.kind(), SessionKind::Exec);
    assert_eq!(refusal.risk(), Risk::CodeExecution);
    for missing in [
        Missing::ProtocolUpgrade,
        Missing::StreamMultiplexing,
        Missing::TerminalJobControl,
        Missing::HostCapability,
    ] {
        assert!(
            refusal.missing().contains(&missing),
            "{:?} does not name {missing:?}",
            refusal.missing()
        );
    }
    let described = refusal.describe();
    assert!(
        described.contains("101") && described.contains("shop/checkout-7f9d"),
        "{described} must name both the protocol step and the target"
    );
}

/// §42.3: the target is explicit *before* execution. The plausible mistake is letting the API
/// server pick the container, which it does for a single-container Pod — so a command that ran
/// somewhere nobody named works right up until the Pod grows a sidecar.
#[test]
fn should_name_an_unstated_container_before_executing_anything() {
    let without_container = PodTarget::new(INSTANCE, "shop", "checkout-7f9d");
    let refusal = SessionRequest::exec(without_container, vec!["/bin/sh".to_owned()])
        .open()
        .expect_err("no remote session opens");

    assert!(refusal.missing().contains(&Missing::ExplicitContainer));
}

/// A named gap is worth more than a stub, and it is worth more still when the request it would
/// have sent is written down: the day the transport can upgrade, this is the request to send.
#[test]
fn should_still_state_the_request_it_would_send() {
    let exec = SessionRequest::exec(
        target(),
        vec!["/bin/sh".to_owned(), "-c".to_owned(), "ps aux".to_owned()],
    )
    .with_stdin()
    .with_tty();

    let wire = exec.http_request().target();
    assert!(wire.starts_with("/api/v1/namespaces/shop/pods/checkout-7f9d/exec?"));
    for parameter in [
        "container=api",
        "stdin=true",
        "tty=true",
        "command=%2Fbin%2Fsh",
        "command=-c",
        "command=ps%20aux",
    ] {
        assert!(wire.contains(parameter), "{wire} is missing {parameter}");
    }
}

/// §42.5: a port forward is a job/session with clear local and remote endpoints. The plausible
/// mistake is modelling it as a Kubernetes resource, which makes an ephemeral local socket look
/// like cluster state that outlives the process holding it.
#[test]
fn should_state_both_endpoints_of_a_port_forward() {
    let forward = SessionRequest::port_forward(target(), vec![PortMapping::new(18080, 8080)]);

    assert_eq!(forward.kind(), SessionKind::PortForward);
    let described = forward.describe();
    assert!(
        described.contains("18080") && described.contains("8080"),
        "{described} must name the local and the remote port"
    );
    assert!(
        forward.http_request().target().contains("ports=8080"),
        "the remote port is what the API server is asked for"
    );

    let refusal = forward.open().expect_err("no session opens");
    assert!(
        refusal.missing().contains(&Missing::LocalListener),
        "a forward needs a local listening socket the host does not broker: {:?}",
        refusal.missing()
    );
}

/// §42.4: attach shares the remote-session path rather than being an opaque provider callback.
/// The plausible mistake is treating attach as read-only because it looks like `logs` — it writes
/// to the standard input of a process the operator did not start.
#[test]
fn should_treat_attach_as_the_same_kind_of_thing_as_exec() {
    let attach = SessionRequest::attach(target());

    assert_eq!(attach.risk(), Risk::ProcessInput);
    let refusal = attach.open().expect_err("no session opens");
    assert!(refusal.missing().contains(&Missing::ProtocolUpgrade));
    assert!(refusal.missing().contains(&Missing::TerminalJobControl));
}

/// §42.6, and Gate M with it. The plausible mistake is the shortcut that makes all of the above
/// work this afternoon: shell out to `kubectl logs`. It also breaks §51.4, which allows a
/// subprocess for exec credential plugins and for nothing else.
#[test]
fn should_not_reach_for_a_subprocess() {
    let source = module_source();
    for forbidden in ["kubectl", "std::process", "Command::new"] {
        assert!(
            !source.contains(forbidden),
            "§42.6 and §51.4: `{forbidden}` has no place on this path"
        );
    }
}

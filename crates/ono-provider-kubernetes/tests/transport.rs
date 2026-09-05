//! HTTP over the brokered byte connection, and what a read knows about itself.
//!
//! Specification §17 (read operations), §18 (pagination), §19.1 (list/watch request shape),
//! §20.1 and §20.2 (cache classes and object freshness), §21.4 (denied reads), §59.2 (fixture
//! transport). Core `ADR-0573` settles why this provider owns an HTTP client at all: the host
//! brokers a byte connection and speaks no protocol over it, so the protocol is ours.
//!
//! Every test here feeds recorded bytes to a fixture stream. Nothing opens a socket, nothing
//! awaits, and no cluster is required — which is the only way §59's fixtures can cover pagination
//! failure, RBAC denial, `410 Gone` and a watch stream at all.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use ono_provider_kubernetes::coverage::{Outcome, Scope};
use ono_provider_kubernetes::discovery::Gvr;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::transport::{
    ApiError, BreakReason, Client, Continuity, EndpointCategory, FixedClock, FixtureStream,
    Freshness, HttpConnection, ListOptions, Method, ObservedAt, Operation, Origin, Read, Request,
    get_request, list_request, watch_request,
};

// --- fixtures ---------------------------------------------------------------------------------

const INSTANCE: &str = "kubernetes:prod-eu";
const HOST: &str = "kubernetes.default.svc";
const OBSERVED: u64 = 1_700_000_000_000;

fn clock() -> FixedClock {
    FixedClock::at_unix_millis(OBSERVED)
}

/// A response with a `Content-Length` body, framed the way a server frames one.
fn response(status_line: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut text = format!("HTTP/1.1 {status_line}\r\n");
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    text.push_str(body);
    text
}

fn json_response(status_line: &str, body: &str) -> String {
    response(status_line, &[("Content-Type", "application/json")], body)
}

/// A chunked response, as a watch stream arrives.
fn chunked_response(chunks: &[&str]) -> String {
    let mut text =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_owned();
    for chunk in chunks {
        text.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
    }
    text.push_str("0\r\n\r\n");
    text
}

fn pod(name: &str, uid: &str, resource_version: &str) -> String {
    format!(
        r#"{{"metadata":{{"name":"{name}","namespace":"shop","uid":"{uid}","resourceVersion":"{resource_version}"}},"spec":{{}}}}"#
    )
}

fn pod_list(resource_version: &str, continue_token: Option<&str>, items: &[String]) -> String {
    let continues = match continue_token {
        Some(token) => format!(r#","continue":"{token}","remainingItemCount":7"#),
        None => String::new(),
    };
    format!(
        r#"{{"apiVersion":"v1","kind":"PodList","metadata":{{"resourceVersion":"{resource_version}"{continues}}},"items":[{}]}}"#,
        items.join(",")
    )
}

fn pods() -> Gvr {
    Gvr::new("", "v1", "pods")
}

fn deployments() -> Gvr {
    Gvr::new("apps", "v1", "deployments")
}

fn status(code: u16, reason: &str, message: &str) -> String {
    format!(
        r#"{{"kind":"Status","apiVersion":"v1","status":"Failure","message":"{message}","reason":"{reason}","code":{code}}}"#
    )
}

fn client(responses: &[String]) -> Client<FixtureStream, FixedClock> {
    let stream = FixtureStream::replaying(responses);
    Client::with_clock(stream, HOST, INSTANCE, clock())
}

/// The request lines the fixture recorded, in the order they were written.
fn request_lines(stream: &FixtureStream) -> Vec<String> {
    stream
        .written_text()
        .lines()
        .filter(|line| line.starts_with("GET ") || line.starts_with("POST "))
        .map(str::to_owned)
        .collect()
}

// --- HTTP/1.1 request serialisation -----------------------------------------------------------

#[test]
fn should_serialise_a_request_as_an_http_1_1_message_with_crlf_framing() {
    // The host brokers bytes and speaks nothing over them (core ADR-0573), so the framing is
    // ours to get exactly right. A message framed with bare newlines, or without the empty line
    // that ends the headers, is one an API server will not answer — and it would be easy to
    // write, because Rust's `writeln!` produces exactly that.
    let request = Request::get("/api/v1/namespaces/shop/pods").header("Accept", "application/json");

    let wire = String::from_utf8(request.serialise(HOST)).expect("a serialised request is UTF-8");

    assert_eq!(
        wire,
        "GET /api/v1/namespaces/shop/pods HTTP/1.1\r\n\
         Host: kubernetes.default.svc\r\n\
         Accept: application/json\r\n\
         \r\n"
    );
}

#[test]
fn should_percent_encode_query_values_because_a_continue_token_is_not_url_safe() {
    // §18.1's continue token is an opaque server-issued blob that routinely carries `+`, `/` and
    // `=`. Pasting it into a query string raw corrupts it — `+` decodes as a space server-side —
    // and the failure surfaces much later as a truncated collection rather than as a bad request.
    let request = Request::get("/api/v1/pods")
        .query("continue", "abc+/=xyz")
        .query("labelSelector", "app=shop,tier in (web)");

    let target = request.target();

    assert!(
        target.contains("continue=abc%2B%2F%3Dxyz"),
        "the continue token must survive encoding: {target}"
    );
    assert!(
        target.contains("labelSelector=app%3Dshop%2Ctier%20in%20%28web%29"),
        "a label selector is Kubernetes syntax and must arrive unchanged: {target}"
    );
}

#[test]
fn should_declare_a_body_length_when_a_request_carries_one() {
    // A body without `Content-Length` leaves the server waiting for bytes that never come. The
    // plausible mistake is to write the body and stop, which works for GET and hangs for POST.
    let request = Request::new(Method::Post, "/api/v1/namespaces/shop/pods").body(b"{}".to_vec());

    let wire = String::from_utf8(request.serialise(HOST)).expect("a serialised request is UTF-8");

    assert!(wire.contains("POST /api/v1/namespaces/shop/pods HTTP/1.1\r\n"));
    assert!(wire.contains("Content-Length: 2\r\n"));
    assert!(wire.ends_with("\r\n\r\n{}"));
}

// --- HTTP/1.1 response parsing ----------------------------------------------------------------

#[test]
fn should_read_a_content_length_framed_response() {
    // The ordinary case, and the one that decides whether the body ends where the server said it
    // does. Reading "until the stream goes quiet" would appear to work against a fixture and
    // would hang against a keep-alive connection that stays open for the next request.
    let mut connection = HttpConnection::new(
        FixtureStream::new(json_response("200 OK", r#"{"kind":"Pod"}"#)),
        HOST,
    );

    let response = connection
        .send(&Request::get("/api/v1/namespaces/shop/pods/web"))
        .expect("the fixture answers");

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.body(), br#"{"kind":"Pod"}"#);
}

#[test]
fn should_reassemble_a_response_that_arrives_in_small_reads() {
    // A brokered byte connection returns what it has, not what was asked for. Treating one read
    // as one message is the classic socket bug: it passes every fixture that hands over the
    // response in a single piece and fails the first time a real message is split.
    let mut connection = HttpConnection::new(
        FixtureStream::new(json_response("200 OK", r#"{"kind":"Pod","spec":{}}"#))
            .with_read_size(3),
        HOST,
    );

    let response = connection
        .send(&Request::get("/api/v1/namespaces/shop/pods/web"))
        .expect("the fixture answers across many reads");

    assert_eq!(response.body(), br#"{"kind":"Pod","spec":{}}"#);
}

#[test]
fn should_decode_a_chunked_body_because_a_watch_stream_has_no_content_length() {
    // §19 watches stream indefinitely, so the server cannot state a length and uses chunked
    // transfer encoding instead. A client that ignores `Transfer-Encoding` hands the chunk-size
    // lines to the JSON parser, which then reports the cluster's data as malformed.
    let mut connection = HttpConnection::new(
        FixtureStream::new(chunked_response(&[
            r#"{"type":"ADDED"}"#,
            r#"{"type":"MODIFIED"}"#,
        ])),
        HOST,
    );

    let response = connection
        .send(&Request::get("/api/v1/pods").query("watch", "true"))
        .expect("the fixture answers");

    assert_eq!(
        response.body(),
        br#"{"type":"ADDED"}{"type":"MODIFIED"}"#,
        "the chunk framing belongs to the transport, not to the body"
    );
}

#[test]
fn should_hand_over_chunks_one_at_a_time_so_a_watch_need_not_wait_for_the_end() {
    // §19.1's watch never ends on its own. Buffering the whole body first is not a slow path, it
    // is a path that never returns, so the transport must expose frames as they arrive. The state
    // machine that interprets them is not this module's business.
    let mut connection = HttpConnection::new(
        FixtureStream::new(chunked_response(&[
            r#"{"type":"ADDED"}"#,
            r#"{"type":"DELETED"}"#,
        ])),
        HOST,
    );

    let mut stream = connection
        .open(&Request::get("/api/v1/pods").query("watch", "true"))
        .expect("the fixture answers");

    assert_eq!(stream.status(), 200);
    let first = stream
        .next_chunk()
        .expect("a first chunk")
        .expect("decoded");
    assert_eq!(first, br#"{"type":"ADDED"}"#);
    let second = stream
        .next_chunk()
        .expect("a second chunk")
        .expect("decoded");
    assert_eq!(second, br#"{"type":"DELETED"}"#);
    assert!(
        stream.next_chunk().is_none(),
        "the terminating zero-length chunk ends the body"
    );
}

#[test]
fn should_report_a_truncated_response_as_a_failure_rather_than_a_short_body() {
    // The connection dropping mid-message is §21.4's `provider disconnected`, not a small answer.
    // Returning the bytes that did arrive would present half a JSON document as the cluster's
    // reply, and the caller would report a parse error against the wrong cause.
    let truncated = "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{\"kind\":\"Pod\"";
    let mut connection = HttpConnection::new(FixtureStream::new(truncated), HOST);

    let error = connection
        .send(&Request::get("/api/v1/pods"))
        .expect_err("a truncated message is not an answer");

    assert!(matches!(error, ApiError::Stream(_)), "got {error:?}");
    assert_eq!(error.outcome(Operation::List), Outcome::Disconnected);
}

// --- Kubernetes request building ---------------------------------------------------------------

#[test]
fn should_interleave_the_namespace_into_a_namespaced_collection_path() {
    // The namespace sits between the version and the resource, not at the end and not in the
    // query string. `/api/v1/pods?namespace=shop` is a plausible-looking URL that silently lists
    // every namespace the caller can see — §9.4's forbidden fan-out, dressed as a scoped query.
    let request = list_request(&pods(), &Scope::in_namespace("shop"), &ListOptions::new());

    assert_eq!(request.path(), "/api/v1/namespaces/shop/pods");
}

#[test]
fn should_keep_a_named_group_under_apis_when_a_namespace_is_interleaved() {
    // §13.3: the core group lives under `/api` and every named group under `/apis`. `Gvr::path`
    // already knows that, and rebuilding the path by hand here is how the two surfaces get
    // confused for a resource that is both namespaced and grouped.
    let request = list_request(
        &deployments(),
        &Scope::in_namespace("shop"),
        &ListOptions::new(),
    );

    assert_eq!(request.path(), "/apis/apps/v1/namespaces/shop/deployments");
}

#[test]
fn should_give_a_cluster_scoped_collection_no_namespace_segment() {
    // §9.2: a cluster-scoped resource must never be given a fake namespace. Defaulting an absent
    // namespace to `default` is the mistake, and it produces a 404 that reads as absence.
    let cluster = list_request(
        &Gvr::new("", "v1", "nodes"),
        &Scope::cluster(),
        &ListOptions::new(),
    );
    let every = list_request(&pods(), &Scope::all_namespaces(), &ListOptions::new());

    assert_eq!(cluster.path(), "/api/v1/nodes");
    assert_eq!(
        every.path(),
        "/api/v1/pods",
        "an all-namespace list is the unscoped collection endpoint"
    );
}

#[test]
fn should_address_a_single_object_below_its_collection() {
    // A get is the collection path plus the name (§17.1). Building it from the kind rather than
    // from the resource — `/api/v1/namespaces/shop/Pod/web` — is the GVK/GVR confusion §13.1
    // exists to prevent, and it fails only at request time.
    let request = get_request(&pods(), &Scope::in_namespace("shop"), "web-7f9");

    assert_eq!(request.path(), "/api/v1/namespaces/shop/pods/web-7f9");
}

#[test]
fn should_send_the_selectors_the_caller_asked_for_unchanged() {
    // §17.3 and §17.4: a selector is pushed to the server only when it means the same thing
    // there. Rewriting the expression — splitting an `in (...)` set into several requests, say —
    // changes the semantics and loses the fan-out metadata that would have made it honest.
    let request = list_request(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new()
            .label_selector("tier in (web)")
            .field_selector("status.phase=Running")
            .limit(500),
    );

    let target = request.target();
    assert!(
        target.contains("labelSelector=tier%20in%20%28web%29"),
        "{target}"
    );
    assert!(
        target.contains("fieldSelector=status.phase%3DRunning"),
        "{target}"
    );
    assert!(target.contains("limit=500"), "{target}");
}

#[test]
fn should_build_a_watch_request_from_the_resource_version_a_list_returned() {
    // §19.1: a watch continues from the collection `resourceVersion` the list reported. A watch
    // opened without one starts from "now" and silently drops everything that happened in
    // between — a gap that never announces itself. The state machine around this request lives
    // elsewhere; the request shape is the transport's.
    let request = watch_request(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new(),
        Some("18446744073709551615"),
    );

    let target = request.target();
    assert!(
        target.starts_with("/api/v1/namespaces/shop/pods?"),
        "{target}"
    );
    assert!(target.contains("watch=true"), "{target}");
    assert!(
        target.contains("resourceVersion=18446744073709551615"),
        "{target}"
    );
    assert!(
        target.contains("allowWatchBookmarks=true"),
        "bookmarks are what let a reconnect keep a checkpoint: {target}"
    );
}

// --- reads and freshness -------------------------------------------------------------------------

#[test]
fn should_carry_the_freshness_a_read_result_must_state() {
    // §17.1 lists what a get carries: observed_at, resourceVersion, provider instance, scope and
    // the source endpoint category. An object returned bare is an object whose age nobody can
    // judge, and stale data that looks live is worse than an admitted gap.
    let mut client = client(&[json_response(
        "200 OK",
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web-7f9","namespace":"shop","uid":"u-1","resourceVersion":"4711"}}"#,
    )]);

    let read = client
        .get(&pods(), &Scope::in_namespace("shop"), "web-7f9")
        .expect("the fixture answers");

    assert_eq!(read.object().name(), "web-7f9");
    let freshness = read.freshness();
    assert_eq!(
        freshness.observed_at(),
        ObservedAt::from_unix_millis(OBSERVED)
    );
    assert_eq!(freshness.resource_version(), Some("4711"));
    assert_eq!(freshness.provider_instance(), INSTANCE);
    assert_eq!(freshness.scope(), &Scope::in_namespace("shop"));
    assert_eq!(freshness.endpoint(), EndpointCategory::Core);
    assert_eq!(freshness.origin(), Origin::DirectRead);
}

#[test]
fn should_name_the_endpoint_category_a_grouped_read_came_from() {
    // §17.1's source endpoint category, and §20.1's separate cache validity rules, both need to
    // know which REST surface answered. Recording only the path leaves every consumer to parse it
    // again, and each one will decide differently what `/apis/...` means.
    let mut client = client(&[json_response(
        "200 OK",
        r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"shop","namespace":"shop","uid":"u-2","resourceVersion":"99"}}"#,
    )]);

    let read = client
        .get(&deployments(), &Scope::in_namespace("shop"), "shop")
        .expect("the fixture answers");

    assert_eq!(read.freshness().endpoint(), EndpointCategory::Group);
}

#[test]
fn should_distinguish_a_cached_observation_from_a_direct_read() {
    // §20.2: the user MUST be able to tell one from the other, and a cached object keeps the
    // observed_at of the read that produced it rather than the time it was served again. Stamping
    // a cache hit with "now" is the mistake that makes an hour-old object look current.
    let mut client = client(&[json_response(
        "200 OK",
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web","namespace":"shop","uid":"u-1","resourceVersion":"4711"}}"#,
    )]);
    let read = client
        .get(&pods(), &Scope::in_namespace("shop"), "web")
        .expect("the fixture answers");

    let cached = read.freshness().as_cached(true);

    assert!(read.freshness().is_direct_read());
    assert!(!cached.is_direct_read());
    assert_eq!(cached.origin(), Origin::Cache);
    assert_eq!(
        cached.observed_at(),
        read.freshness().observed_at(),
        "a cached observation is old, and says so"
    );
    assert_eq!(cached.watch_synced(), Some(true));
    assert_eq!(
        read.freshness().watch_synced(),
        None,
        "a direct read has no watch to be synced with"
    );
}

// --- pagination ------------------------------------------------------------------------------

#[test]
fn should_treat_a_page_carrying_a_continue_token_as_an_incomplete_collection() {
    // §18.1: the collection is incomplete until every page is consumed. A single page that looks
    // like a complete list is the most expensive possible mistake here, because it is a *shorter*
    // answer that reads as a whole one.
    let mut client = client(&[json_response(
        "200 OK",
        &pod_list("1000", Some("tok-2"), &[pod("a", "u-a", "1")]),
    )]);

    let page = client
        .list_page(
            &pods(),
            &Scope::in_namespace("shop"),
            &ListOptions::new().limit(1),
        )
        .expect("the fixture answers");

    assert_eq!(page.objects().len(), 1);
    assert!(!page.is_complete());
    assert_eq!(page.continue_token(), Some("tok-2"));
    assert_eq!(page.remaining_item_count(), Some(7));
    assert_eq!(page.resource_version(), Some("1000"));
}

#[test]
fn should_follow_continue_tokens_until_the_collection_is_complete() {
    // §18.1 again, from the driving end: the second request must carry the token the first
    // returned, and the result must be one collection rather than two. Sending the same request
    // twice, or dropping the token, loops or truncates.
    let mut client = client(&[
        json_response(
            "200 OK",
            &pod_list("1000", Some("tok-2"), &[pod("a", "u-a", "1")]),
        ),
        json_response("200 OK", &pod_list("1000", None, &[pod("b", "u-b", "2")])),
    ]);

    let listing = client.list(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new().limit(1),
    );

    assert_eq!(listing.objects().len(), 2);
    assert!(listing.coverage().is_complete());
    assert_eq!(listing.continuity(), &Continuity::Intact);
    assert_eq!(listing.resource_version(), Some("1000"));
    let lines = request_lines(client.stream());
    assert_eq!(lines.len(), 2, "one request per page: {lines:?}");
    assert!(
        !lines[0].contains("continue="),
        "the first page has no token: {lines:?}"
    );
    assert!(
        lines[1].contains("continue=tok-2"),
        "the second page continues: {lines:?}"
    );
}

#[test]
fn should_give_a_list_item_the_identity_the_list_kind_implies() {
    // The API server omits `apiVersion` and `kind` on the items of a list, because the list's own
    // kind states them. Reading items as bare documents therefore loses the GVK entirely; taking
    // the list kind verbatim would instead type every Pod as a `PodList`.
    let mut client = client(&[json_response(
        "200 OK",
        &pod_list("1000", None, &[pod("a", "u-a", "1")]),
    )]);

    let listing = client.list(&pods(), &Scope::in_namespace("shop"), &ListOptions::new());

    let object = &listing.objects()[0];
    assert_eq!(object.gvk().kind(), "Pod");
    assert_eq!(object.gvk().version(), "v1");
    assert_eq!(object.uid(), Some("u-a"));
}

#[test]
fn should_mark_a_continuity_break_when_a_later_page_belongs_to_another_snapshot() {
    // §18.2: paginated list requests give a consistent snapshot, and mixing an unrelated fresh
    // list into the middle of the sequence MUST be marked. Concatenating the pages silently is
    // how a collection ends up containing an object twice and missing another, with nothing in
    // the result to say so.
    let mut client = client(&[
        json_response(
            "200 OK",
            &pod_list("1000", Some("tok-2"), &[pod("a", "u-a", "1")]),
        ),
        json_response("200 OK", &pod_list("2000", None, &[pod("b", "u-b", "2")])),
    ]);

    let listing = client.list(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new().limit(1),
    );

    assert_eq!(listing.objects().len(), 2);
    assert_eq!(
        listing.continuity(),
        &Continuity::Broken(BreakReason::SnapshotChanged)
    );
}

#[test]
fn should_return_the_pages_that_arrived_with_partial_coverage_when_a_later_one_fails() {
    // §18.3: pages 1..N may be returned when N+1 fails, and coverage MUST be partial with the
    // error attached. Two opposite mistakes are available — discarding everything, and returning
    // the objects as a complete list — and the second one is the one that lies.
    let mut client = client(&[
        json_response(
            "200 OK",
            &pod_list("1000", Some("tok-2"), &[pod("a", "u-a", "1")]),
        ),
        json_response(
            "500 Internal Server Error",
            &status(500, "InternalError", "etcd unavailable"),
        ),
    ]);

    let listing = client.list(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new().limit(1),
    );

    assert_eq!(listing.objects().len(), 1);
    assert!(!listing.coverage().is_complete(), "a failed page is a gap");
    assert_eq!(
        listing.coverage().gaps()[0].outcome(),
        Outcome::RequestFailed
    );
    assert!(
        listing.error().is_some(),
        "§18.3 attaches the error to the collection"
    );
}

#[test]
fn should_report_an_expired_continue_token_as_a_continuity_break_not_a_failed_request() {
    // §18.2 and §19.4: `410 Gone` means the snapshot the token pointed into is no longer there.
    // Restarting the sequence transparently would mix two snapshots — exactly what §18.2
    // forbids — so the sequence stops and says the continuity broke.
    let mut client = client(&[
        json_response(
            "200 OK",
            &pod_list("1000", Some("tok-2"), &[pod("a", "u-a", "1")]),
        ),
        json_response(
            "410 Gone",
            &status(410, "Expired", "continue parameter is too old"),
        ),
    ]);

    let listing = client.list(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new().limit(1),
    );

    assert_eq!(listing.objects().len(), 1);
    assert_eq!(
        listing.continuity(),
        &Continuity::Broken(BreakReason::TokenExpired)
    );
    assert!(!listing.coverage().is_complete());
    assert!(
        listing.error().is_some_and(ApiError::is_continuity_expiry),
        "410 is not an ordinary request failure"
    );
    assert_eq!(
        request_lines(client.stream()).len(),
        2,
        "no third, fresh list"
    );
}

#[test]
fn should_not_call_a_deliberately_limited_listing_incomplete() {
    // §18.4: a pipeline that stops consuming is not provider incompleteness — but the stream
    // SHOULD still know more exists upstream. Recording a gap here would cry wolf on `first 20`;
    // recording nothing would present a truncated view as the whole cluster.
    let mut client = client(&[json_response(
        "200 OK",
        &pod_list("1000", Some("tok-2"), &[pod("a", "u-a", "1")]),
    )]);

    let listing = client.list(
        &pods(),
        &Scope::in_namespace("shop"),
        &ListOptions::new().limit(1).max_pages(1),
    );

    assert_eq!(listing.objects().len(), 1);
    assert!(
        listing.coverage().is_complete(),
        "stopping early is a decision, not a hole"
    );
    assert!(listing.coverage().may_have_more());
    assert_eq!(listing.continuity(), &Continuity::Intact);
    assert_eq!(request_lines(client.stream()).len(), 1);
}

// --- structured errors -------------------------------------------------------------------------

#[test]
fn should_map_403_to_a_denial_that_names_which_verb_was_refused() {
    // §21.4: a denial is not an absence, and a refused get is not a refused list. Collapsing
    // either pair turns a permission boundary into "there is nothing there" — wrong in the
    // direction that costs an operator the most, because it looks like information.
    let mut denied_get = client(&[json_response(
        "403 Forbidden",
        &status(403, "Forbidden", "pods is forbidden"),
    )]);
    let error = denied_get
        .get(&pods(), &Scope::in_namespace("shop"), "web")
        .expect_err("403 is not an object");

    assert!(matches!(error, ApiError::Denied(_)), "got {error:?}");
    assert_eq!(error.outcome(Operation::Get), Outcome::ReadDenied);
    assert_eq!(error.outcome(Operation::List), Outcome::ListDenied);
    assert_eq!(error.code(), Some(403));
}

#[test]
fn should_map_404_to_absence_and_keep_it_apart_from_denial() {
    // §21.4 again. These are the two answers most often merged into "no result", and an operator
    // acts on them differently: one calls for a different name, the other for different rights.
    let mut client = client(&[json_response(
        "404 Not Found",
        &status(404, "NotFound", r#"pods "web" not found"#),
    )]);

    let error = client
        .get(&pods(), &Scope::in_namespace("shop"), "web")
        .expect_err("404 is not an object");

    assert!(matches!(error, ApiError::NotFound(_)), "got {error:?}");
    assert_eq!(error.outcome(Operation::Get), Outcome::Absent);
    assert_eq!(
        error.outcome(Operation::List),
        Outcome::TypeNotServed,
        "a collection endpoint that is not there is an unserved API, not an empty one (§11.5)"
    );
}

#[test]
fn should_map_429_to_rate_limiting_and_keep_the_servers_retry_advice() {
    // A throttled request is a request that has not happened yet, not a resource that is absent
    // or denied. Dropping `Retry-After` leaves a caller to guess a backoff the server already
    // stated, and guessing wrong is how a provider makes an overloaded control plane worse.
    let mut client = client(&[response(
        "429 Too Many Requests",
        &[("Retry-After", "3"), ("Content-Type", "application/json")],
        &status(429, "TooManyRequests", "please try again later"),
    )]);

    let error = client
        .list_page(&pods(), &Scope::in_namespace("shop"), &ListOptions::new())
        .expect_err("429 is not a collection");

    match &error {
        ApiError::RateLimited { retry_after, .. } => {
            assert_eq!(retry_after.as_deref(), Some("3"));
        }
        other => panic!("429 must be its own answer: {other:?}"),
    }
    assert_eq!(error.outcome(Operation::List), Outcome::RequestFailed);
    assert!(!error.is_continuity_expiry());
}

#[test]
fn should_keep_what_the_status_object_said() {
    // A `Status` is the server explaining itself (§59.2 requires fixtures for it). Reducing it to
    // a status code throws away the message that names the missing permission or the offending
    // field — the part an operator can act on.
    let mut client = client(&[json_response(
        "403 Forbidden",
        &status(
            403,
            "Forbidden",
            r#"pods is forbidden: User cannot list resource pods"#,
        ),
    )]);

    let error = client
        .list_page(&pods(), &Scope::in_namespace("shop"), &ListOptions::new())
        .expect_err("403 is not a collection");

    let ApiError::Denied(status) = &error else {
        panic!("403 is a denial: {error:?}");
    };
    assert_eq!(status.reason(), Some("Forbidden"));
    assert_eq!(status.code(), Some(403));
    assert!(
        status
            .message()
            .unwrap_or_default()
            .contains("cannot list resource pods")
    );
}

#[test]
fn should_report_a_body_that_is_not_a_kubernetes_object_as_malformed() {
    // A 200 carrying an HTML error page from a proxy is not an object, and it is not absence
    // either. Parsing it into an empty object would invent a cluster fact out of a middlebox.
    let mut client = client(&[response(
        "200 OK",
        &[("Content-Type", "text/html")],
        "<html/>",
    )]);

    let error = client
        .get(&pods(), &Scope::in_namespace("shop"), "web")
        .expect_err("HTML is not an object");

    assert!(matches!(error, ApiError::Malformed(_)), "got {error:?}");
    assert_eq!(error.outcome(Operation::Get), Outcome::RequestFailed);
}

// --- credentials --------------------------------------------------------------------------------

#[test]
fn should_never_print_a_default_header_value() {
    // §8.1 and §4 invariant 21: a credential never becomes a value. The bearer token this client
    // sends on every request is exactly the kind of thing a `#[derive(Debug)]` leaks into a log
    // line, and the leak is silent until someone reads the log.
    let client = client(&[]).with_default_header("Authorization", "Bearer s3cr3t");

    let rendered = format!("{client:?}");

    assert!(!rendered.contains("s3cr3t"), "the token leaked: {rendered}");
    assert!(
        rendered.contains("Authorization"),
        "the header's presence is not the secret: {rendered}"
    );
}

#[test]
fn should_send_default_headers_on_every_request() {
    // The counterpart of the test above: redaction must not be achieved by dropping the header.
    // A client that prints nothing because it sends nothing passes the leak test and fails to
    // authenticate.
    let mut client = client(&[
        json_response("200 OK", &pod_list("1", None, &[])),
        json_response("200 OK", &pod_list("1", None, &[])),
    ])
    .with_default_header("Authorization", "Bearer s3cr3t");

    let _ = client.list_page(&pods(), &Scope::all_namespaces(), &ListOptions::new());
    let _ = client.list_page(&pods(), &Scope::all_namespaces(), &ListOptions::new());

    let written = client.stream().written_text();
    assert_eq!(written.matches("Authorization: Bearer s3cr3t").count(), 2);
}

#[test]
fn should_build_a_cached_observation_without_calling_it_a_direct_read() {
    // §20.2: "the user MUST be able to distinguish a direct read from a cached observation".
    // A cache that has to construct its freshness through the direct-read constructor and correct
    // it afterwards is one refactor away from forgetting the correction, and the mistake is
    // silent — the value looks exactly like a read that just happened. So the cached observation
    // has a constructor of its own, and it carries the sync state a cache hit is only as good as.
    let cached = Freshness::cached(
        ObservedAt::from_unix_millis(OBSERVED),
        Some("18010".to_owned()),
        INSTANCE,
        Scope::in_namespace("shop"),
        EndpointCategory::Core,
        true,
    );

    assert_eq!(cached.origin(), Origin::Cache);
    assert!(!cached.is_direct_read());
    assert_eq!(cached.watch_synced(), Some(true));
    assert_eq!(
        cached.observed_at().unix_millis(),
        OBSERVED,
        "a cache hit is as old as the read that filled it, never as young as the hit"
    );
    assert_eq!(cached.resource_version(), Some("18010"));
    assert_eq!(cached.provider_instance(), INSTANCE);
}

#[test]
fn should_carry_a_cached_object_in_the_same_shape_a_direct_read_uses() {
    // §20.2 again, from the other side. The distinction belongs in the *value*, not in the type:
    // if a cache hit had a type of its own, every consumer would need two code paths and the one
    // that forgot the second would render a cached object as a fresh one. One `Read`, whose
    // freshness says how it was come by.
    let object = Object::parse(
        INSTANCE,
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"checkout-1","namespace":"shop","uid":"uid-1","resourceVersion":"18010"}}"#,
    )
    .expect("the fixture Pod parses");
    let read = Read::new(
        object.clone(),
        Freshness::cached(
            ObservedAt::from_unix_millis(OBSERVED),
            Some("18010".to_owned()),
            INSTANCE,
            Scope::in_namespace("shop"),
            EndpointCategory::Core,
            false,
        ),
    );

    assert_eq!(read.object().name(), "checkout-1");
    assert!(!read.freshness().is_direct_read());
    assert_eq!(
        read.freshness().watch_synced(),
        Some(false),
        "an unsynced cache says so rather than presenting itself as authoritative"
    );
}

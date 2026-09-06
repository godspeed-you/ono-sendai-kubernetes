//! What this provider *costs*, measured rather than asserted.
//!
//! Specification §17.6 (query planning), §18.1 to §18.5 (pagination, user limits, memory bounds),
//! §19.6 and §19.7 (watch fan-out and lifecycle), §20.1 to §20.4 (cache classes), §49.1 and §49.5
//! (respecting the API server, client-side throttling), §50.1 to §50.6 (performance
//! requirements), and §30 of the inherited generic contract (performance and resource
//! management). `ADR-0044` records the numbers below and says which of them are contracts.
//!
//! The rest of this crate's suite proves *behaviour*. §50 is about cost, and a provider that is
//! correct and unusable against a real cluster has failed a requirement rather than a preference.
//! So every test here builds a fixture that is *large* — a hundred thousand objects, two hundred
//! pages, ten thousand watch events, a twenty-megabyte object — and asks what the provider held
//! and how many requests it sent.
//!
//! **Nothing here is timed as an assertion.** A wall-clock threshold in a suite that runs on
//! whatever machine CI gave it is a flake with a stopwatch. What is asserted is countable and
//! deterministic: requests on the wire, pages walked, objects retained, bytes transferred. Where a
//! number is worth knowing and has no contract behind it, the test *prints* it and asserts only a
//! ceiling loose enough that only a change of asymptotic behaviour can reach it — `cargo test -p
//! ono-provider-kubernetes --test performance -- --nocapture` shows them all.
//!
//! The fixtures are generated rather than checked in. A hundred thousand recorded objects in the
//! tree would be twenty-five megabytes nobody reads and a `git diff` nobody can review.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test states its preconditions directly (AGENTS.md section 16)"
)]

use std::time::Instant;

use ono_provider_kubernetes::budget::Budget;
use ono_provider_kubernetes::coverage::Scope;
use ono_provider_kubernetes::discovery::{Gvk, Gvr};
use ono_provider_kubernetes::kubeconfig::Credential;
use ono_provider_kubernetes::live::LiveView;
use ono_provider_kubernetes::object::Object;
use ono_provider_kubernetes::schema::Schema;
use ono_provider_kubernetes::session::Session;
use ono_provider_kubernetes::transport::{
    ApiError, Client, FixedClock, FixtureStream, ListOptions, Page, Reader, Walk,
};
use ono_provider_kubernetes::watch::ResourceVersion;

const INSTANCE: &str = "kubernetes:prod-eu";
const HOST: &str = "kubernetes.default.svc";
const OBSERVED: u64 = 1_700_000_000_000;

/// The collection every page fixture below serves.
fn pods() -> Gvr {
    Gvr::new("", "v1", "pods")
}

fn shop() -> Scope {
    Scope::in_namespace("shop")
}

fn clock() -> FixedClock {
    FixedClock::at_unix_millis(OBSERVED)
}

// --- generated fixtures -------------------------------------------------------------------------

/// One Pod, as an API server writes it inside a collection: no `apiVersion`, no `kind`.
///
/// Deliberately an ordinary object rather than a minimal one — labels, an owner reference and a
/// status — because the cost being measured is the cost of the objects an operator actually
/// lists, and a two-field stand-in would understate every byte count in this file.
fn pod(index: usize) -> String {
    format!(
        r#"{{"metadata":{{"name":"api-{index:06}","namespace":"shop","uid":"00000000-0000-0000-0000-{index:012}","resourceVersion":"{version}","creationTimestamp":"2026-09-01T09:00:00Z","labels":{{"app":"api","pod-template-hash":"7d9f"}},"ownerReferences":[{{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"api-7d9f","uid":"a1a1a1a1-0000-0000-0000-000000000001","controller":true,"blockOwnerDeletion":true}}]}},"spec":{{"nodeName":"node-a","containers":[{{"name":"api"}}]}},"status":{{"phase":"Running","podIP":"10.1.2.3"}}}}"#,
        version = 100_000 + index
    )
}

/// One HTTP/1.1 response carrying one page of a Pod collection.
fn page_response(first: usize, count: usize, continue_token: Option<&str>) -> String {
    let items: Vec<String> = (first..first + count).map(pod).collect();
    let continues = continue_token
        .map(|token| format!(r#","continue":"{token}","remainingItemCount":1"#))
        .unwrap_or_default();
    let body = format!(
        r#"{{"apiVersion":"v1","kind":"PodList","metadata":{{"resourceVersion":"90210"{continues}}},"items":[{}]}}"#,
        items.join(",")
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// A whole paginated collection: `pages` pages of `per_page` objects, the last one with no token.
fn paginated(pages: usize, per_page: usize) -> Vec<String> {
    (0..pages)
        .map(|page| {
            let token = (page + 1 < pages).then(|| format!("page-{}", page + 1));
            page_response(page * per_page, per_page, token.as_deref())
        })
        .collect()
}

/// A collection whose server hands back the *same* `continue` token on every page.
///
/// Not a hypothetical: a proxy that rewrites list responses, or an aggregated API server with a
/// broken continuation implementation, produces exactly this. §18.1 says the collection is
/// incomplete "until all required pages have been consumed or the operation is explicitly
/// cancelled/limited", and this fixture is what decides whether that limit is load-bearing.
fn stuck_token(pages: usize, per_page: usize) -> Vec<String> {
    (0..pages)
        .map(|page| page_response(page * per_page, per_page, Some("always-the-same")))
        .collect()
}

fn serving(responses: &[String]) -> Client<FixtureStream, FixedClock> {
    Client::with_clock(FixtureStream::replaying(responses), HOST, INSTANCE, clock())
}

/// How many HTTP requests went down the wire.
///
/// Counted off the bytes the client *wrote*, which is the only honest place to count one: what
/// the provider believes it sent is exactly the thing under test.
fn requests(stream: &FixtureStream) -> usize {
    stream
        .written_text()
        .lines()
        .filter(|line| line.starts_with("GET ") || line.starts_with("POST "))
        .count()
}

/// A reader that keeps nothing and remembers what it saw (§18.5).
///
/// The instrument for "how many objects are held at once". It counts, it measures the page it was
/// handed, and then the page is dropped at the end of `page` — so anything still alive after the
/// walk is being held by the provider rather than by the caller.
#[derive(Debug, Default)]
struct Counting {
    pages: usize,
    objects: usize,
    bytes: u64,
    largest_page: usize,
    stop_after: Option<usize>,
}

impl Reader for Counting {
    fn page(&mut self, page: Page) -> Walk {
        self.pages += 1;
        self.largest_page = self.largest_page.max(page.objects().len());
        self.objects += page.objects().len();
        self.bytes += page.bytes();
        if self.stop_after == Some(self.pages) {
            return Walk::Stop;
        }
        Walk::Continue
    }
}

/// A reader that keeps every object, the way a caller §18.5 exempts does.
#[derive(Debug, Default)]
struct Keeping {
    objects: Vec<Object>,
}

impl Reader for Keeping {
    fn page(&mut self, page: Page) -> Walk {
        self.objects.extend(page.into_objects());
        Walk::Continue
    }
}

/// Roughly how many bytes a set of objects retains, measured through the objects' own accessor.
///
/// The native JSON is what an `Object` holds on to, so re-serialising it is a closer estimate of
/// retention than `size_of` and a far more deterministic one than process RSS, which depends on
/// the allocator, the machine and whatever else the test binary is doing (§18.5, §50.5).
fn retained_bytes<'a>(objects: impl Iterator<Item = &'a Object>) -> u64 {
    objects
        .map(|object| serde_json::to_string(object.native()).map_or(0, |text| text.len() as u64))
        .sum()
}

// --- §50.2 and §18.1: what a hundred thousand objects cost in requests ---------------------------

#[test]
fn should_send_one_request_per_page_and_none_per_object_over_a_hundred_thousand_object_collection()
{
    // §18.1: "When the API server returns a `continue` token, the provider MUST treat the
    // collection as incomplete until all required pages have been consumed." §49.1: "Ono is an
    // interactive shell, not a load generator. The provider MUST bound concurrency and SHOULD use
    // efficient list/watch patterns."
    //
    // The falsehood this prevents is the one that never shows up in a small test: a per-object
    // round trip. Two pods and two requests look identical to two pods and four; a hundred
    // thousand pods and two hundred requests cannot be confused with a hundred thousand pods and
    // a hundred thousand and two. So the count is asserted as a *number*, and the number is the
    // page count.
    let mut client = serving(&paginated(200, 500));
    let mut reader = Counting::default();
    let listing = client.walk(
        &pods(),
        &shop(),
        &ListOptions::new().limit(500),
        &mut reader,
    );

    assert_eq!(reader.objects, 100_000, "every object arrived");
    assert_eq!(listing.pages(), 200, "in two hundred pages");
    assert_eq!(
        requests(client.stream()),
        200,
        "and in two hundred requests: one per page, none per object (§49.1, §50.2)"
    );
    assert!(
        listing.coverage().is_complete(),
        "a collection walked to its last page is complete: {}",
        listing.coverage().describe()
    );
    println!(
        "listing 100 000 objects: {} requests, {} pages, {} bytes transferred",
        requests(client.stream()),
        listing.pages(),
        reader.bytes
    );
}

#[test]
fn should_hold_one_page_at_a_time_while_a_reader_streams_a_hundred_thousand_objects() {
    // §18.5: "The provider SHOULD stream pages into the Ono pipeline rather than buffering entire
    // large clusters unless an operation explicitly requires a complete set." §30.4 of the
    // inherited contract puts it as a MUST: "Enumeration and watch implementations MUST avoid
    // retaining entire remote inventories when streaming semantics suffice."
    //
    // The measurement is what the *provider* retains, which is the honest one available without a
    // profiler. The reader below drops each page as it is handed over, so the largest number of
    // objects alive at any instant is one page — and the listing that comes back at the end holds
    // no objects at all, which is the difference between streaming and a fast buffer.
    let mut client = serving(&paginated(200, 500));
    let mut reader = Counting::default();
    let listing = client.walk(
        &pods(),
        &shop(),
        &ListOptions::new().limit(500),
        &mut reader,
    );

    assert_eq!(
        reader.largest_page, 500,
        "the most objects in flight at once is one page"
    );
    assert!(
        listing.objects().is_empty(),
        "and the walk kept none of the hundred thousand it passed on: {} retained",
        listing.objects().len()
    );
    println!(
        "streamed listing: peak {} objects held at once out of {} delivered",
        reader.largest_page, reader.objects
    );
}

#[test]
fn should_ask_the_reader_before_it_asks_the_server_for_the_second_page() {
    // §50.1: "Connecting a large cluster MUST NOT freeze parser, prompt or unrelated local shell
    // operations." §18.4: a user limit "is not provider incompleteness if the pipeline
    // intentionally stops consumption".
    //
    // Time to first result, expressed as a count rather than as a stopwatch: a reader that stops
    // on page one must cost exactly one request. A provider that walked the collection and
    // consulted the reader afterwards would have sent two hundred, and the operator who asked for
    // twenty rows would have waited for a hundred thousand.
    let mut client = serving(&paginated(200, 500));
    let mut reader = Counting {
        stop_after: Some(1),
        ..Counting::default()
    };
    let listing = client.walk(
        &pods(),
        &shop(),
        &ListOptions::new().limit(500),
        &mut reader,
    );

    assert_eq!(
        requests(client.stream()),
        1,
        "one page was wanted, so one request was made (§50.1)"
    );
    assert_eq!(reader.objects, 500, "and one page of objects crossed");
    assert!(
        listing.coverage().may_have_more(),
        "a consumer that stopped asking is §18.4's decision, and the stream still knows more \
         exists upstream: {}",
        listing.coverage().describe()
    );
    assert!(
        listing.coverage().is_complete(),
        "a decision is not a hole: {}",
        listing.coverage().describe()
    );
}

#[test]
fn should_stop_a_two_hundred_page_collection_at_the_page_budget_the_query_named() {
    // §18.4: "User-requested limits ... are not provider incompleteness if the pipeline
    // intentionally stops consumption. The value stream SHOULD still know that more upstream
    // results may exist."
    //
    // The bound is the operator's, and this is the number it produces: ten pages, ten requests,
    // five thousand objects, and an answer that says it is not the whole collection. A limit that
    // stopped at ten pages and reported completeness would be §63.7's silent truncation with a
    // knob on it.
    let mut client = serving(&paginated(200, 500));
    let mut reader = Counting::default();
    let listing = client.walk(
        &pods(),
        &shop(),
        &ListOptions::new().limit(500).max_pages(10),
        &mut reader,
    );

    assert_eq!(listing.pages(), 10, "the page budget is what it says");
    assert_eq!(
        requests(client.stream()),
        10,
        "and it bounds the round trips"
    );
    assert_eq!(reader.objects, 5_000, "five thousand of a hundred thousand");
    assert!(
        listing.coverage().may_have_more(),
        "and the answer says the other ninety-five thousand exist: {}",
        listing.coverage().describe()
    );
}

#[test]
fn should_stop_a_collection_whose_continue_token_never_changes_at_the_interactive_page_bound() {
    // §18.1 again, and §49.1's bound. A server that answers every continued request with the same
    // `continue` token describes a collection that is never fully consumed, so §18.1's "until all
    // required pages have been consumed" is a condition that never becomes true. The clause that
    // saves the shell is the second one — "or the operation is explicitly cancelled/limited" —
    // and this asserts that the *default* interactive budget is such a limit.
    //
    // Sixteen pages is `Budget::interactive`'s page bound. The fixture offers forty, so nothing
    // but the budget can be what stopped the walk.
    let mut client = serving(&stuck_token(40, 100));
    client.spend(Budget::interactive());
    let mut reader = Counting::default();
    let listing = client.walk(
        &pods(),
        &shop(),
        &ListOptions::new().limit(100),
        &mut reader,
    );

    assert_eq!(
        listing.pages(),
        16,
        "the interactive page bound stopped a walk that had no other end"
    );
    let overrun = listing
        .overrun()
        .expect("a walk stopped by a budget says a budget stopped it");
    assert_eq!(overrun.allowed(), 16);
    assert!(
        !listing.coverage().is_complete(),
        "and what it did not read is a stated gap rather than silence: {}",
        listing.coverage().describe()
    );

    // FINDING: nothing in `Client::walk` notices that the token it was handed is the token it
    // just sent. Under `Budget::unlimited` and with no `max_pages`, the walk below consumes every
    // page the fixture holds and stops only because the recorded bytes ran out — against a real
    // server it would repeat forever. The bound is the operator's default rather than a property
    // of the loop, so a caller that legitimately raises `max_pages` for a large collection raises
    // the ceiling on this too. A cheap fix is to break continuity when a page returns the token
    // that produced it, the way `Continuity::Broken(BreakReason::SnapshotChanged)` already
    // handles the other malformed-pagination case. Left for the owner of `transport.rs`.
    let mut unbounded = serving(&stuck_token(40, 100));
    let mut counting = Counting::default();
    let ran_on = unbounded.walk(
        &pods(),
        &shop(),
        &ListOptions::new().limit(100),
        &mut counting,
    );
    assert_eq!(
        ran_on.pages(),
        40,
        "with no bound the walk follows the same token for as many pages as it is given"
    );
    assert!(
        ran_on.error().is_some(),
        "and it ends because the connection did, not because it noticed"
    );
}

#[test]
fn should_hold_the_whole_collection_only_where_the_caller_asked_to_buffer_it() {
    // §18.5's exemption: streaming is the rule "unless an operation explicitly requires a
    // complete set". `Client::list` is that operation — a listing that seeds a watched cache
    // (§19.1) or evaluates a selector over a whole collection (§23.3) has no streaming form.
    //
    // The number is worth having in the open: buffering fifty thousand ordinary Pods retains
    // about twenty-six megabytes of native JSON — five hundred and twenty-eight bytes an object —
    // which is just inside `Budget::interactive`'s thirty-two-megabyte transfer bound and would
    // not be at sixty thousand. The assertion is the ceiling; the print is the observation.
    let mut client = serving(&paginated(100, 500));
    let mut reader = Keeping::default();
    client.walk(
        &pods(),
        &shop(),
        &ListOptions::new().limit(500),
        &mut reader,
    );

    assert_eq!(reader.objects.len(), 50_000);
    let bytes = retained_bytes(reader.objects.iter());
    println!(
        "buffered listing: {} objects retained, {bytes} bytes of native JSON ({} bytes/object)",
        reader.objects.len(),
        bytes / reader.objects.len() as u64
    );
    assert!(
        bytes < 64 * 1024 * 1024,
        "a buffered listing of fifty thousand ordinary objects stays well inside the byte \
         budget a query runs under: {bytes} bytes"
    );
}

// --- §18.5 and §50.5: one very large object ------------------------------------------------------

#[test]
fn should_pass_a_twenty_megabyte_object_on_without_retaining_it() {
    // §50.5: "Resources with very large object payloads or very large populations SHOULD support
    // field projection/lazy expansion where Ono's generic value model allows it." §30.4 of the
    // inherited contract is the harder half: a streaming enumeration must not retain the
    // inventory it passes through.
    //
    // A twenty-megabyte ConfigMap is the population-of-one case, and it is the one where a single
    // retained copy is the whole problem. What is asserted is that the walk keeps none of it; the
    // transferred size is printed, because how many megabytes a cluster will hand over is the
    // cluster's business rather than this provider's.
    let payload = "x".repeat(20 * 1024 * 1024);
    let body = format!(
        r#"{{"apiVersion":"v1","kind":"ConfigMapList","metadata":{{"resourceVersion":"90210"}},"items":[{{"metadata":{{"name":"bulk","namespace":"shop","uid":"c0c0c0c0-0000-0000-0000-000000000001","resourceVersion":"4711"}},"data":{{"blob":"{payload}"}}}}]}}"#
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let configmaps = Gvr::new("", "v1", "configmaps");

    let mut client = serving(&[response]);
    let mut reader = Counting::default();
    let listing = client.walk(&configmaps, &shop(), &ListOptions::new(), &mut reader);

    assert_eq!(reader.objects, 1);
    assert!(
        listing.objects().is_empty(),
        "the walk retains nothing, whatever the object weighed"
    );
    assert!(
        reader.bytes > 20 * 1024 * 1024,
        "the page really was twenty megabytes: {} bytes",
        reader.bytes
    );
    println!(
        "single large object: {} bytes transferred, 0 bytes retained by the walk",
        reader.bytes
    );

    // FINDING: the object itself is retained whole for as long as the reader holds it, because
    // `Object` keeps the parsed `native()` JSON and there is no projection that would let a
    // consumer take `metadata` and drop `data`. §50.5's "field projection/lazy expansion" has no
    // implementation, so a caller that buffers — `Client::list`, a watched cache — holds every
    // byte of a twenty-megabyte ConfigMap. The bound today is `Budget::interactive`'s
    // thirty-two-megabyte transfer limit, which stops *two* of these and not one.
    let mut buffering = serving(&[format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )]);
    let held = buffering.list(&configmaps, &shop(), &ListOptions::new());
    let retained = retained_bytes(held.objects().iter());
    assert!(
        retained > 20 * 1024 * 1024,
        "a buffered read of it holds the whole payload: {retained} bytes"
    );
    println!("single large object, buffered: {retained} bytes retained");
}

// --- §12.4, §20.1 and §50.3: what a session's caches hold ---------------------------------------

#[test]
fn should_hold_one_schema_per_group_version_however_large_the_schema_is() {
    // §50.3: "The provider MAY load detailed schemas lazily by group/type to avoid making first
    // connection depend on full OpenAPI processing." §12.4 gives the cache its rule, and §20.1
    // requires each cache class to have independent validity.
    //
    // A CRD with a very large structural schema is the case §50.5 names, and the cost that
    // matters is that it is paid once. The retained count is what a cache can be asked for
    // without a profiler: entries, not bytes, because the entry is what the cache keys on.
    let mut fields = Vec::with_capacity(4_000);
    for index in 0..4_000 {
        fields.push(format!(
            r#""field{index:05}":{{"type":"string","description":"{}"}}"#,
            "a described field of a very large custom resource, ".repeat(12)
        ));
    }
    let document = format!(
        r#"{{"type":"object","properties":{{"spec":{{"type":"object","properties":{{{}}}}}}}}}"#,
        fields.join(",")
    );
    assert!(
        document.len() > 2 * 1024 * 1024,
        "the fixture really is a large schema: {} bytes",
        document.len()
    );

    let started = Instant::now();
    let schema = Schema::from_openapi_v3(&document).expect("a large schema still parses");
    let parsed_in = started.elapsed();
    let gvk = Gvk::new("menagerie.example", "v1", "Sprocket");

    let mut session = Session::for_endpoint(
        INSTANCE,
        "https://cluster.test:6443",
        Some("shop"),
        Credential::Anonymous,
    );
    session.cache_schema(gvk.clone(), schema);
    assert_eq!(session.schemas().len(), 1);
    session.cache_schema(gvk.clone(), Schema::absent());
    assert_eq!(
        session.schemas().len(),
        1,
        "a second read of one group-version's schema replaces the entry rather than adding one \
         (§12.4, §50.2)"
    );
    let held = session
        .schema(&gvk)
        .expect("the cached schema answers for its own GVK");
    assert!(held.is_absent(), "and the newer document is the one held");

    println!(
        "schema cache: a {}-byte OpenAPI document parsed in {parsed_in:?}, held as 1 entry",
        document.len()
    );
    assert!(
        parsed_in.as_secs() < 10,
        "a ceiling loose enough that only a change of asymptotic behaviour reaches it: \
         {parsed_in:?}"
    );
}

#[test]
fn should_retain_every_object_of_a_synchronised_cache_and_be_able_to_say_how_many() {
    // §20.3: "An informer/reflector-style synchronized cache MAY be used for active resource
    // sets. The provider MUST know whether the cache has completed initial synchronization."
    // §30.5 of the inherited contract: "index size and invalidation MUST be bounded and
    // observable."
    //
    // Observable it is: `object_count` is the accessor, and this is the number it gives for a
    // twenty-thousand-object namespace. Bounded it is not — see the finding below.
    let mut client = serving(&paginated(40, 500));
    let listing = client.list(&pods(), &shop(), &ListOptions::new().limit(500));
    assert_eq!(listing.objects().len(), 20_000);
    let bytes = retained_bytes(listing.objects().iter());

    let mut session = Session::for_endpoint(
        INSTANCE,
        "https://cluster.test:6443",
        Some("shop"),
        Credential::Anonymous,
    );
    session
        .synchronise(&pods(), &shop(), listing)
        .expect("a complete listing may seed a cache");
    let stream = session
        .watch_stream(&pods(), &shop())
        .expect("the session holds the stream it just seeded");

    assert_eq!(
        stream.object_count(),
        20_000,
        "an informer cache holds the collection it synchronised, and says how much that is"
    );
    println!(
        "synchronised cache: {} objects retained, about {bytes} bytes of native JSON",
        stream.object_count()
    );

    // FINDING: `WatchStream` has no capacity. A watched collection of any size is held whole, and
    // the only thing standing between a shell and a hundred-thousand-Pod namespace is that
    // `Budget::interactive` refuses the listing that would seed it — a bound on the *transfer*
    // rather than on the cache. `LiveView::capacity` bounds what a reader is shown and nothing
    // bounds what the session holds, so the plugin's `VIEW_CAPACITY` of two thousand is not the
    // memory bound it reads as. Left for the owner of `watch.rs` and `session.rs`.
    assert!(
        bytes > 5 * 1024 * 1024,
        "the retained set really is large: {bytes} bytes"
    );
}

// --- §19.6 and §50.1: ten thousand watch events -------------------------------------------------

/// One watch frame, newline-terminated as the API server writes one.
fn frame(class: &str, index: usize, version: usize) -> String {
    format!(
        r#"{{"type":"{class}","object":{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"api-{index:06}","namespace":"shop","uid":"00000000-0000-0000-0000-{index:012}","resourceVersion":"{version}"}},"spec":{{}},"status":{{"phase":"Running"}}}}}}"#
    ) + "\n"
}

#[test]
fn should_apply_ten_thousand_watch_events_without_discarding_one() {
    // §19.6: "Watching every discovered GVR in a large cluster can be expensive and is not
    // required. Watches SHOULD be demand-driven." §50.1: "All remote work MUST be
    // asynchronous/cancellable according to Ono host semantics", and the half of it this can
    // measure is that the provider keeps up: an event stream the decoder falls behind on is a
    // live view that silently stops being live.
    //
    // Ten thousand events over five hundred distinct objects, fed in the chunks a transport hands
    // over rather than one frame at a time — a chunk boundary lands mid-frame as a matter of
    // course, and that is the path a real watch takes.
    let mut session = Session::for_endpoint(
        INSTANCE,
        "https://cluster.test:6443",
        Some("shop"),
        Credential::Anonymous,
    );
    let seed: Vec<Object> = (0..500)
        .map(|index| {
            Object::parse(
                INSTANCE,
                &format!(
                    r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"api-{index:06}","namespace":"shop","uid":"00000000-0000-0000-0000-{index:012}","resourceVersion":"1"}},"spec":{{}}}}"#
                ),
            )
            .expect("the seed object parses")
        })
        .collect();
    session
        .watch(&pods(), &shop())
        .listed(seed, ResourceVersion::new("90210"));

    let mut wire = String::new();
    for event in 0..10_000_usize {
        wire.push_str(&frame("MODIFIED", event % 500, 200_000 + event));
    }
    let bytes = wire.into_bytes();

    let started = Instant::now();
    let mut applied = 0_usize;
    for chunk in bytes.chunks(4_096) {
        applied += session
            .feed_watch(&pods(), &shop(), chunk)
            .expect("a well-formed frame decodes")
            .len();
    }
    let elapsed = started.elapsed();

    assert_eq!(applied, 10_000, "every event was received and applied");
    let stream = session
        .watch_stream(&pods(), &shop())
        .expect("the stream is there");
    assert_eq!(
        stream.discarded_events(),
        0,
        "a live stream discards nothing (§19.3)"
    );
    assert_eq!(
        stream.object_count(),
        500,
        "and the cache is bounded by the collection rather than by the event count: ten thousand \
         modifications of five hundred objects are five hundred objects"
    );
    println!(
        "watch: 10 000 events over {} bytes applied in {elapsed:?}; cache holds {} objects, \
         change log holds {} entries",
        bytes.len(),
        stream.object_count(),
        stream.continuous_changes().len()
    );
    assert!(
        elapsed.as_secs() < 30,
        "a ceiling loose enough that only a change of asymptotic behaviour reaches it: {elapsed:?}"
    );

    // FINDING: the change log is unbounded. `Segment::changes` grows by one `ObservedChange` per
    // event and is never trimmed, so a watch left open overnight retains one entry per event for
    // the lifetime of the session — about a hundred bytes each here, and §19.4's segment model
    // needs the *segment boundaries* rather than every change inside them. The generic contract's
    // §30.4 ("MUST avoid retaining entire remote inventories when streaming semantics suffice")
    // reads on this as much as on a listing. A bound with a reported `withheld`, the way
    // `LiveView` bounds its rows, would keep §19.4 intact. Left for the owner of `watch.rs`.
    assert_eq!(
        stream.continuous_changes().len(),
        10_000,
        "one retained change per event, with nothing trimming it"
    );
}

#[test]
fn should_bound_a_live_view_at_its_capacity_and_name_everything_it_did_not_admit() {
    // §18.5's memory bound, expressed where a reader meets it, and §41.4's rule that a bounded
    // view must never look like a complete one. §30.5 of the inherited contract: "index size and
    // invalidation MUST be bounded and observable."
    //
    // Ten thousand objects into a two-thousand-row view — the capacity the package's live-change
    // query runs at. The rows are the contract. The withheld list is the observation, and it is
    // the interesting one: bounding the rows does not bound the view.
    let mut stream = ono_provider_kubernetes::watch::WatchStream::new(pods(), shop());
    let objects: Vec<Object> = (0..10_000)
        .map(|index| {
            Object::parse(
                INSTANCE,
                &format!(
                    r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"api-{index:06}","namespace":"shop","uid":"00000000-0000-0000-0000-{index:012}","resourceVersion":"1"}},"spec":{{}}}}"#
                ),
            )
            .expect("the object parses")
        })
        .collect();
    stream.listed(objects, ResourceVersion::new("90210"));

    let mut view = LiveView::new(pods(), shop(), 2_000, std::time::Duration::from_secs(30));
    let started = Instant::now();
    view.refresh(&stream, &clock());
    let refreshed_in = started.elapsed();

    assert_eq!(
        view.row_count(),
        2_000,
        "the view holds its capacity and not one row more (§18.5)"
    );
    assert_eq!(
        view.withheld().len(),
        8_000,
        "and it names every object it had no room for rather than showing a fraction of a \
         namespace as if it were all of it"
    );
    assert!(
        !view.shown(&clock()).is_current(),
        "a truncated view is never a current one"
    );
    println!(
        "live view: 10 000 objects -> {} rows + {} withheld identities, refreshed in \
         {refreshed_in:?}",
        view.row_count(),
        view.withheld().len()
    );

    // FINDING: `LiveView::refresh` is O(objects in the stream) and clones up to `capacity`
    // objects, and the package's change query calls it *once per emitted record*. A watched
    // collection of ten thousand objects therefore pays ten thousand object clones per change
    // event; the observation above is one refresh, and a live view emitting a thousand events
    // pays it a thousand times. Nothing here is wrong per §41, and §50.1's "MUST NOT freeze" is
    // the requirement it strains. Rebuilding only the rows a change touched, or refreshing on a
    // cadence rather than per record, would remove the multiplication. Left for the owners of
    // `live.rs` and `changes.rs`.
    assert!(
        refreshed_in.as_secs() < 10,
        "a ceiling loose enough that only a change of asymptotic behaviour reaches it: \
         {refreshed_in:?}"
    );

    // And the second half of the finding: the withheld list is itself proportional to the
    // collection. Eight thousand identities is the bound's own cost, and it is not bounded.
    let withheld_bytes: usize = view
        .withheld()
        .iter()
        .map(|identity| identity.name().len() + identity.uid().map_or(0, str::len))
        .sum();
    println!("live view: withheld identities cost about {withheld_bytes} bytes of names alone");
}

// --- §18.3 and §50.1: a failure at scale still answers -------------------------------------------

#[test]
fn should_keep_the_pages_that_crossed_when_a_page_deep_into_a_large_collection_fails() {
    // §18.3: "If pages 1..N succeed and page N+1 fails, the provider MAY return the already
    // received values, but coverage MUST be `partial` and the error MUST be attached to the
    // collection result. A default table MUST NOT look identical to a complete result."
    //
    // The behavioural version of this exists at two pages. What scale adds is the number: fifty
    // pages of a two-hundred-page collection is twenty-five thousand objects a consumer already
    // holds, and the cost of getting the reporting wrong grows with it.
    let mut responses = paginated(200, 500);
    let refusal = r#"{"kind":"Status","apiVersion":"v1","status":"Failure","message":"pods is forbidden","reason":"Forbidden","code":403}"#;
    responses[50] = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{refusal}",
        refusal.len()
    );

    let mut client = serving(&responses);
    let mut reader = Counting::default();
    let listing = client.walk(
        &pods(),
        &shop(),
        &ListOptions::new().limit(500),
        &mut reader,
    );

    assert_eq!(reader.objects, 25_000, "fifty pages crossed and they stand");
    assert_eq!(listing.pages(), 50);
    assert!(
        !listing.coverage().is_complete(),
        "and the answer is partial: {}",
        listing.coverage().describe()
    );
    assert!(
        matches!(listing.error(), Some(ApiError::Denied(_))),
        "with the refusal attached to the collection rather than replacing it"
    );
}

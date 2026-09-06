//! The Kubernetes provider for Ono-Sendai.
//!
//! Kubernetes as typed resources, relationships and places rather than as a command namespace.
//! The specification this implements is `docs/architecture/kubernetes-provider.md`.
//!
//! The modules are layered the way §58.1 lays them out, and none of them performs I/O: the
//! transport is written against a byte stream, and everything above it is a function of bytes
//! already received. That is what lets the whole provider be tested without a cluster (§59.1).
//!
//! ```text
//! transport     HTTP/1.1 over a byte stream, pagination, freshness, API errors
//! discovery     what the server serves; GVK and GVR kept apart
//! schema        OpenAPI and CRD structural schemas, dynamic typing
//! object        one object: projected metadata, identity, unknown fields preserved
//! watch         list/watch continuity, 410 gaps, reconciliation evidence
//! relationship  edges and the evidence each rests on
//! evidence      what a Node states about the machine under it, for someone else to resolve
//! events        best-effort observations, and everything they are not
//! workload      curated controller, service and routing relationships
//! condition     desired versus observed, cited from the fields it depends on
//! redaction     Secret payloads, destroyed at the boundary rather than filtered
//! place         resources as addresses, and what is near them
//! coverage      what a query observed, and what it did not
//! budget        what a query may cost, and what it says when it stops
//! diagnostics   which cluster this is, whether it answers, and who the provider is to it
//! kubeconfig    a context becomes a connection identity
//! live          a bounded view of a watch, and the states it may honestly show
//! logs          container logs as observations, and the remote sessions this cannot open
//! plan          a change described before it is made, and what it refuses to claim
//! mutation      what a change is sent as, what came back, and what that still does not prove
//! tls           a TLS session, wrapping the brokered byte stream below HTTP
//! session       what one provider instance holds between two invocations
//! temporal      the window an answer observed, the holes in it, and which clock wrote each time
//! causal        what `why` may say about a link, and the rung above which it cannot climb
//! ```

pub mod budget;
pub mod causal;
pub mod condition;
pub mod coverage;
pub mod diagnostics;
pub mod discovery;
pub mod events;
pub mod evidence;
pub mod kubeconfig;
pub mod live;
pub mod logs;
pub mod mutation;
pub mod object;
pub mod place;
pub mod plan;
pub mod redaction;
pub mod relationship;
pub mod schema;
pub mod session;
pub mod temporal;
pub mod tls;
pub mod transport;
pub mod watch;
pub mod workload;

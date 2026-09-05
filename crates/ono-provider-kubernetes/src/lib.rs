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
//! workload      curated controller, service and routing relationships
//! condition     desired versus observed, cited from the fields it depends on
//! redaction     Secret payloads, destroyed at the boundary rather than filtered
//! place         resources as addresses, and what is near them
//! coverage      what a query observed, and what it did not
//! kubeconfig    a context becomes a connection identity
//! ```

pub mod condition;
pub mod coverage;
pub mod discovery;
pub mod kubeconfig;
pub mod object;
pub mod place;
pub mod redaction;
pub mod relationship;
pub mod schema;
pub mod transport;
pub mod watch;
pub mod workload;

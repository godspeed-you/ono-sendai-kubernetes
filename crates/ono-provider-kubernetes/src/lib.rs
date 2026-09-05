//! The Kubernetes provider for Ono-Sendai.
//!
//! Kubernetes as typed resources, relationships and places rather than as a command namespace.
//! The specification this implements is `docs/architecture/kubernetes-provider.md`.

pub mod discovery;
pub mod kubeconfig;
pub mod object;

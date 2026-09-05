//! The KUANG/11 plugin binary: `runtime/ono-kubernetes` as `package/manifest.yaml` names it.
//!
//! It speaks the protocol on stdin and stdout and does nothing else, so that everything worth
//! testing is reachable from the library rather than only from a spawned process.

fn main() {
    ono_kubernetes_plugin::plugin().run();
}

//! Isolated-egress orchestration.
//!
//! Open-core boundary. The real per-node egress mechanism (network isolation,
//! tunnels, transparent routing) is a private drop-in (`private.rs`, git-ignored)
//! that `build.rs` selects when it is present. A public checkout has only
//! `baseline.rs` (direct egress, no isolation), so the open build compiles and
//! runs but does not apply isolated egress. Isolated egress is a platform
//! feature.
//!
//! Both implementations expose the same small surface, so `lib.rs` is identical
//! regardless of which is compiled:
//!   - [`process_network_config`] ingests a node's network config,
//!   - [`bring_up`] applies egress and returns a [`TunnelGuard`],
//!   - [`TunnelGuard`] tears everything down on `Drop`.
//!
//! Proxies are the other way a node's traffic can leave, and they live here in the
//! open ([`state`], [`gateway`]). The platform can set a node to send through one
//! HTTP, HTTPS, SOCKS4 or SOCKS5 proxy. The node then runs a gateway on loopback,
//! leases it to each op, and wraps the op's engine request so the engine sends every
//! connection through that lease. Nothing a proxied node sends for an op goes out from
//! its own address: when it cannot be sent through the proxy, it is not sent.

// One `mod`, with the path chosen by cfg, rather than two cfg-gated `mod imp;`
// declarations. Both forms compile identically, but tools that resolve modules
// without evaluating cfg (rustfmt, rustdoc, rust-analyzer) tried to read BOTH
// arms of the old form and hard-errored on a public checkout, where private.rs
// does not exist:
//
//     error: couldn't read core/src/egress/private.rs: No such file or directory
//
// That made `cargo fmt` and `cargo doc` unusable for outside contributors.
#[cfg_attr(egress_private, path = "private.rs")]
#[cfg_attr(not(egress_private), path = "baseline.rs")]
mod imp;

pub mod gateway;
pub mod state;

#[cfg(test)]
pub(crate) mod testkit;

pub use imp::{TunnelGuard, bring_up};

/// Ingest a node's network config: the tunnel selection the egress impl applies.
///
/// `tunnel_hooks` is the node's own `tunnel_hooks` setting (see `Config::tunnel_hooks`):
/// whether a tunnel config may run its own scripts on this host.
pub fn process_network_config(
    raw: &serde_json::Value,
    net_dir: &std::path::Path,
    tunnel_hooks: bool,
) -> Option<crate::NetworkConfig> {
    imp::process_network_config(raw, net_dir, tunnel_hooks)
}

//! Isolated-egress baseline (open build): direct egress, no isolation.
//!
//! Parses and returns a node's network config so it round-trips across runs, but
//! performs no network-namespace or tunnel setup. Isolated egress is a platform
//! feature; this open build routes directly. If a node is configured for a
//! non-direct egress, it says so plainly rather than silently pretending.

use crate::NetworkConfig;

/// Opaque teardown guard. In the open build there is nothing to tear down.
pub struct TunnelGuard;

/// Ingest a node's network config. The open build keeps the config (so a node
/// still knows its intended egress) but applies no tunnel mechanism.
pub fn process_network_config(
    raw: &serde_json::Value,
    net_dir: &std::path::Path,
    tunnel_hooks: bool,
) -> Option<NetworkConfig> {
    let _ = (net_dir, tunnel_hooks);
    if !raw.is_object() {
        return None;
    }
    let net: NetworkConfig = serde_json::from_value(raw.clone()).unwrap_or_default();
    if !net.kind.is_empty() && net.kind != "direct" {
        println!(
            "[network] isolated egress ({}) is a platform feature; this build routes directly.",
            net.kind
        );
    }
    Some(net)
}

/// Apply egress for a configured node. The open build performs no isolation and
/// routes directly, so there is nothing to guard.
pub fn bring_up(
    net: &NetworkConfig,
    net_dir: &std::path::Path,
    node_id: &str,
    tunnel_hooks: bool,
) -> Option<TunnelGuard> {
    let _ = (net, net_dir, node_id, tunnel_hooks);
    None
}

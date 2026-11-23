//! Isolated-egress baseline: the config kept as sent, and no isolation.
//!
//! Parses and returns a node's network config so it round-trips across runs. Applying
//! it is the egress helper's (see `helper.rs`); without one, the node routes directly,
//! or refuses to send when the config's kill switch is on (see `isolation.rs`).

use crate::NetworkConfig;

/// Ingest a node's network config: kept, so a node still knows its intended egress,
/// and nothing applied.
pub fn process_network_config(
    raw: &serde_json::Value,
    net_dir: &std::path::Path,
    tunnel_hooks: bool,
) -> Option<NetworkConfig> {
    let _ = (net_dir, tunnel_hooks);
    if !raw.is_object() {
        return None;
    }
    Some(serde_json::from_value(raw.clone()).unwrap_or_default())
}

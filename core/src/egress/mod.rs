//! Isolated-egress orchestration.
//!
//! Isolated egress is applied by the egress helper, a separate program installed beside
//! the binaries ([`helper`]), which the node asks to take a network config and to hold
//! egress up for the daemon's life ([`isolation`]). Without one that answers, the node
//! keeps its config and sends directly (`baseline.rs`), and says why; with the config's
//! kill switch on, it sends nothing until one answers.
//!
//! The surface:
//!   - [`process_network_config`] ingests a node's network config,
//!   - [`bring_up`] applies egress and returns an [`Isolation`],
//!   - [`Isolation`] tears everything down on `Drop`.
//!
//! Proxies are the other way a node's traffic can leave, and they live here in the
//! open ([`state`], [`gateway`]). The platform can set a node to send through one
//! HTTP, HTTPS, SOCKS4 or SOCKS5 proxy. The node then runs a gateway on loopback,
//! leases it to each op, and wraps the op's engine request so the engine sends every
//! connection through that lease. Nothing a proxied node sends for an op goes out from
//! its own address: when it cannot be sent through the proxy, it is not sent.

mod baseline;
pub mod gateway;
pub mod state;

#[cfg(test)]
pub(crate) mod testkit;

/// The egress helper's file name beside the binaries.
pub const HELPER: &str = "cfx-egress";

pub mod helper;
pub mod isolation;

pub use isolation::Isolation;

/// The config as the platform last sent it, so a helper that answers only later is
/// handed it as sent.
static GIVEN: std::sync::Mutex<Option<serde_json::Value>> = std::sync::Mutex::new(None);

/// Ingest a node's network config: the tunnel selection the egress impl applies.
///
/// `tunnel_hooks` is the node's own `tunnel_hooks` setting (see `Config::tunnel_hooks`):
/// whether a tunnel config may run its own scripts on this host.
pub fn process_network_config(
    raw: &serde_json::Value,
    net_dir: &std::path::Path,
    tunnel_hooks: bool,
) -> Option<crate::NetworkConfig> {
    if let Ok(mut given) = GIVEN.lock() {
        *given = Some(raw.clone());
    }
    let setup = isolation::Setup::for_this_process();
    let why = match helper::find(&setup.exe) {
        Ok(found) => match helper::config(&found, raw, net_dir, tunnel_hooks, setup.limits) {
            Ok((_, net)) => return net,
            Err(why) => why,
        },
        Err(why) => why,
    };
    let net = baseline::process_network_config(raw, net_dir, tunnel_hooks);
    if let Some(n) = net
        .as_ref()
        .filter(|n| !n.kind.is_empty() && n.kind != "direct")
    {
        println!(
            "[network] Isolated egress ({}): {why}. The config is kept as sent.",
            n.kind
        );
    }
    net
}

/// Apply egress for a configured node, and hold it up until the [`Isolation`] is
/// dropped. How it runs is said in the node's log and in
/// [`state::EgressState::isolation`], which refuses every op while a kill switch has no
/// helper to keep it.
pub fn bring_up(
    net: &crate::NetworkConfig,
    net_dir: &std::path::Path,
    node_id: &str,
    tunnel_hooks: bool,
) -> Isolation {
    let raw = GIVEN.lock().ok().and_then(|g| g.clone());
    isolation::start(
        isolation::Asked {
            raw,
            net: net.clone(),
            net_dir: net_dir.to_path_buf(),
            node_id: node_id.to_string(),
            tunnel_hooks,
        },
        isolation::Setup::for_this_process(),
        std::sync::Arc::clone(state::global()),
    )
}

//! Isolated-egress orchestration.
//!
//! Open-core boundary. Isolated egress is applied by the egress helper, a separate
//! program installed beside the binaries ([`helper`]), which the node asks to take a
//! network config and to hold egress up for the daemon's life ([`isolation`]). Without
//! one that answers, the node keeps its config and sends directly, as the open build
//! does (`baseline.rs`), and says why; with the config's kill switch on, it sends nothing
//! until one answers. A first-party build still compiles the private drop-in
//! (`private.rs`, git-ignored) in its place, which `build.rs` selects when it is present.
//!
//! The surface is the same either way, so `lib.rs` is identical whichever runs:
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

/// The egress helper's file name beside the binaries.
pub const HELPER: &str = "cfx-egress";

#[cfg(not(egress_private))]
pub mod helper;
#[cfg(not(egress_private))]
pub mod isolation;

#[cfg(not(egress_private))]
pub use isolation::Isolation;

/// The config as the platform last sent it, so a helper that answers only later is
/// handed it as sent.
#[cfg(not(egress_private))]
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
    #[cfg(not(egress_private))]
    {
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
        let net = imp::process_network_config(raw, net_dir, tunnel_hooks);
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
    #[cfg(egress_private)]
    imp::process_network_config(raw, net_dir, tunnel_hooks)
}

/// Apply egress for a configured node, and hold it up until the [`Isolation`] is
/// dropped. How it runs is said in the node's log and in
/// [`state::EgressState::isolation`], which refuses every op while a kill switch has no
/// helper to keep it.
#[cfg(not(egress_private))]
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

/// Egress as the drop-in compiled into this build applies it.
#[cfg(egress_private)]
pub struct Isolation {
    _guard: Option<imp::TunnelGuard>,
}

#[cfg(egress_private)]
pub fn bring_up(
    net: &crate::NetworkConfig,
    net_dir: &std::path::Path,
    node_id: &str,
    tunnel_hooks: bool,
) -> Isolation {
    let direct = net.kind.is_empty() || net.kind == "direct";
    let (outcome, guard) = match imp::bring_up(net, net_dir, node_id, tunnel_hooks) {
        Ok(guard) => (Ok(if direct { "direct" } else { "built in" }), guard),
        Err(why) => (Err(format!("egress not up: {why}")), None),
    };
    state::global().set_isolation(state::Isolated::of(
        net.kill_switch,
        outcome.as_ref().map(|s| *s).map_err(String::as_str),
    ));
    Isolation { _guard: guard }
}

/// With the drop-in compiled in, egress that cannot come up holds the kill switch as
/// the helper's does. As root this would really bring egress up, so it runs as any
/// other user only.
#[cfg(all(test, egress_private))]
mod built_in_tests {
    #[test]
    fn egress_that_is_not_up_holds_the_kill_switch() {
        if crate::is_root() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let net: crate::NetworkConfig = serde_json::from_value(serde_json::json!({
            "kind": "openvpn", "kill_switch": true, "config_path": t.path().join("x.ovpn"),
        }))
        .unwrap();
        let _held = super::bring_up(&net, t.path(), "node-test", false);
        let isolated = super::state::global().isolation();
        assert!(
            isolated
                .refusal
                .as_deref()
                .is_some_and(|r| r.starts_with("egress: refused (kill switch on, egress not up: ")),
            "{isolated:?}"
        );
    }
}

//! BYO residential / mobile egress proxy.
//!
//! Unlike the tunnel kinds (tor / openvpn / wireguard), a residential proxy is
//! applied at the HTTP-client level, not as a network namespace: the engines'
//! `transport` layer routes through whatever `CROSSFYRE_EGRESS_PROXY` names. This
//! module is the node side of that: it materialises the proxy URL from the node's
//! network config into a systemd `EnvironmentFile` the per-user engine services
//! read. Shared across the baseline and private egress builds (nothing secret
//! here - the URL is operator-supplied, the mechanism is a plain env var).

use crate::NetworkConfig;
use crate::toolchain::sudo_user::chown_to_invoking_user;

/// Path of the env file the engine service units source
/// (`EnvironmentFile=-<home>/.config/crossfyre/egress.env` on Linux; on macOS and
/// Windows the engine host reads it, see `toolchain::service::host`).
fn env_file() -> std::path::PathBuf {
    crate::toolchain::config::egress_env_path()
}

/// Write or clear the egress-proxy env file from the node's network config.
/// A non-empty `proxy` writes `CROSSFYRE_EGRESS_PROXY=<url>`; anything else
/// removes the file, so switching a node back to direct/tunnel egress stops
/// routing engine traffic through a stale proxy.
pub fn apply(net: &NetworkConfig) {
    let path = env_file();
    match net
        .proxy
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        Some(url) => {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            // systemd EnvironmentFile format: bare KEY=VALUE, no quoting (a proxy
            // URL never contains whitespace).
            if std::fs::write(&path, format!("CROSSFYRE_EGRESS_PROXY={url}\n")).is_ok() {
                chown_to_invoking_user(&path);
                println!(
                    "[network] residential egress: engine traffic routes through the configured proxy."
                );
            }
        }
        None => {
            let _ = std::fs::remove_file(&path);
        }
    }
}

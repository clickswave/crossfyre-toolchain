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
pub fn process_network_config(
    raw: &serde_json::Value,
    net_dir: &std::path::Path,
) -> Option<crate::NetworkConfig> {
    imp::process_network_config(raw, net_dir)
}

/// The variable older nodes wrote into the engines' environment file.
const LEGACY_VAR: &str = "CROSSFYRE_EGRESS_PROXY";

/// Whether `text` is exactly what an older node wrote to `egress.env`: one line,
/// `CROSSFYRE_EGRESS_PROXY=<url>`, and a newline.
fn is_legacy_env(text: &str) -> bool {
    let Some(line) = text.strip_suffix('\n') else {
        return false;
    };
    !line.contains('\n')
        && line
            .strip_prefix(LEGACY_VAR)
            .and_then(|r| r.strip_prefix('='))
            .is_some_and(|url| !url.trim().is_empty())
}

/// Remove the engines' environment file at `path` when an older node wrote it.
///
/// Those nodes copied a residential proxy URL from the network config into it, and the
/// engines sent every request of every op through whatever it named. A node's proxy is
/// now a per-op lease, so that file would only route a direct node's traffic through a
/// proxy nobody switched on. A file with anything else in it was written by a person
/// and is left alone. Returns whether the file was removed.
pub fn cleanup_legacy_env_file_at(path: &std::path::Path) -> std::io::Result<bool> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !is_legacy_env(&text) {
        return Ok(false);
    }
    std::fs::remove_file(path)?;
    Ok(true)
}

/// [`cleanup_legacy_env_file_at`] for the file the engine services read. Run once when
/// the daemon starts.
pub fn cleanup_legacy_env_file() {
    let path = crate::toolchain::config::egress_env_path();
    match cleanup_legacy_env_file_at(&path) {
        Ok(true) => println!(
            "[egress] removed {}, which an older node wrote to send every engine request \
             through a proxy. A proxy is now set per node on the platform. Engines already \
             running keep the old setting until they restart.",
            path.display()
        ),
        Ok(false) => {}
        Err(e) => eprintln!("[egress] could not check {}: {e}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact file an older node wrote is removed; a file a person
    /// wrote, or edited, is kept.
    #[test]
    fn legacy_env_file_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("egress.env");
        assert!(
            !cleanup_legacy_env_file_at(&path).unwrap(),
            "no file is nothing to do"
        );

        std::fs::write(
            &path,
            "CROSSFYRE_EGRESS_PROXY=socks5://u:p@gw.example.net:1080\n",
        )
        .unwrap();
        assert!(cleanup_legacy_env_file_at(&path).unwrap());
        assert!(!path.exists());

        for kept in [
            "# my proxy\nCROSSFYRE_EGRESS_PROXY=http://proxy.corp:3128\n",
            "CROSSFYRE_EGRESS_PROXY=http://proxy.corp:3128\nHTTPS_PROXY=http://proxy.corp:3128\n",
            "CROSSFYRE_EGRESS_PROXY=http://proxy.corp:3128",
            "HTTPS_PROXY=http://proxy.corp:3128\n",
            "CROSSFYRE_EGRESS_PROXY=\n",
            "",
        ] {
            std::fs::write(&path, kept).unwrap();
            assert!(
                !cleanup_legacy_env_file_at(&path).unwrap(),
                "{kept:?} was removed"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), kept);
        }
    }
}

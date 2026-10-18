// `crossfyre doctor` - environment checks for the things that actually break
// in the field: missing docker/unzip, dead daemons, unreachable control
// plane, leftover OrionChain installs.

use super::packaging::Found;
use super::ui::{dim, done, error, fail, ok, section, step, title, warn};
use super::{ENGINES, config};
use std::path::Path;

/// Render one check as a styled status line. Returns true when the check
/// passed, so the caller can tally failures for the summary. A failing check
/// prints its remediation hint dimmed underneath.
fn check(label: &str, is_ok: bool, fix: &str) -> bool {
    if is_ok {
        ok(label);
    } else {
        fail(label);
        if !fix.is_empty() {
            println!("      {}", dim(&format!("-> {fix}")));
        }
    }
    is_ok
}

fn has_binary(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(name).is_file())
}

fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(300),
    )
    .is_ok()
}

pub async fn run(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    title("Crossfyre doctor", "environment checks");

    let mut failed = 0usize;

    // -- Host tooling -----------------------------------------------------
    section("Host tooling");
    if !check(
        "docker available",
        has_binary("docker"),
        "install Docker (the toolchain database runs in a container)",
    ) {
        failed += 1;
    }
    if !check(
        "unzip available",
        has_binary("unzip"),
        "install unzip (used to unpack extension downloads)",
    ) {
        failed += 1;
    }
    #[cfg(target_os = "linux")]
    if !check(
        "iproute2 (`ip`) available",
        has_binary("ip"),
        "install iproute2 (needed for VPN network namespaces)",
    ) {
        failed += 1;
    }

    // -- How this crossfyre was installed ---------------------------------------
    section("Install");
    let bin_dir = config::get_bin_dir();
    match super::packaging::found() {
        Found::None => step(&format!(
            "installer layout {}",
            dim(&format!("(binaries in {})", bin_dir.display()))
        )),
        Found::Packaged(p) => ok(&format!(
            "installed by {} {}",
            p.manager,
            dim(&format!(
                "(owns {}; binaries in {}; {})",
                p.owned().join(", "),
                bin_dir.display(),
                p.file.display()
            ))
        )),
        Found::Ignored { file, why } => {
            if !check(
                &format!("{} is not used", file.display()),
                false,
                &format!(
                    "{why}; give it to root, or to the owner of crossfyre, with mode 644, or remove it"
                ),
            ) {
                failed += 1;
            }
        }
    }

    // -- Toolchain config ---------------------------------------------------
    section("Config");
    let config_path = config::get_config_path();
    if config_path.exists() {
        let label = format!(
            "toolchain config parses {}",
            dim(&format!("({})", config_path.display()))
        );
        if !check(
            &label,
            config::load_config().is_ok(),
            "fix or delete the file; a fresh default is written on next init/db command",
        ) {
            failed += 1;
        }
    } else {
        step(&format!(
            "no toolchain config yet {}",
            dim(&format!(
                "({}) - created on first init",
                config_path.display()
            ))
        ));
    }

    // -- Daemons ------------------------------------------------------------
    section("Daemons");
    for e in ENGINES {
        if config::is_extension_installed(e.id) {
            let label = format!("{} daemon listening on {}", e.name, e.port);
            if !check(
                &label,
                port_open(e.port),
                &format!("crossfyre extension start {}", e.name),
            ) {
                failed += 1;
            }
        } else {
            step(&format!("{} {}", e.name, dim("not installed")));
        }
    }
    if let Ok(c) = config::load_config() {
        let label = format!("postgres listening on {}", c.postgres.port);
        if !check(&label, port_open(c.postgres.port), "crossfyre db start") {
            failed += 1;
        }
    }

    // -- Connectivity ---------------------------------------------------------
    section("Connectivity");
    let cdn = super::install::BASE_URL;
    let cdn_ok = reqwest::get(format!("{cdn}/manifest.json"))
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    let label = format!("release CDN reachable {}", dim(&format!("({cdn})")));
    if !check(
        &label,
        cdn_ok,
        "check network/DNS; installs and updates need this",
    ) {
        failed += 1;
    }

    // Control plane, per registered node config.
    if let Ok(ids) = crate::discover_nodes(base) {
        for id in ids {
            let paths = crate::NodePaths::new(base, &id);
            let Ok(text) = std::fs::read_to_string(&paths.config) else {
                continue;
            };
            let Ok(cfg) = toml::from_str::<crate::Config>(&text) else {
                continue;
            };
            let reachable = reqwest::Client::new()
                .get(format!("{}/api/v1", cfg.api_url))
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .is_ok();
            let short = &id[..id.len().min(8)];
            let label = format!(
                "control plane reachable for node {} {}",
                short,
                dim(&format!("({})", cfg.api_url))
            );
            if !check(
                &label,
                reachable,
                "check the api_url in this node's config and your network",
            ) {
                failed += 1;
            }
        }
    } else {
        step(&format!(
            "no nodes registered yet {}",
            dim("(run `crossfyre node init`)")
        ));
    }

    // -- Legacy OrionChain leftovers ------------------------------------------
    section("Legacy");
    let legacy_opt = Path::new("/opt/orionchain").exists();
    let legacy_cfg = super::sudo_user::invoking_user_config_dir()
        .join("orionchain")
        .exists();
    if legacy_opt || legacy_cfg {
        warn("legacy OrionChain install detected");
        println!(
            "      {}",
            dim(
                "-> re-run `sudo crossfyre node init` to migrate, or remove /opt/orionchain and ~/.config/orionchain manually"
            )
        );
    } else {
        ok("no legacy OrionChain leftovers");
    }

    // -- Summary --------------------------------------------------------------
    println!();
    if failed == 0 {
        done("All checks passed");
    } else {
        let plural = if failed == 1 { "" } else { "s" };
        error(&format!("{failed} check{plural} failed"));
    }
    println!();
    Ok(())
}

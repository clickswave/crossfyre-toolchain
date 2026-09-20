// `crossfyre status [nodes|extensions|db]` - the one place to look when
// something is off. Read-only: probes ports, pid files, and the container,
// never mutates state.

use super::config::{ext_bin_path, is_extension_installed, load_config};
use super::{EXTENSION_PORTS, service};
use std::path::Path;

fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(300),
    )
    .is_ok()
}

/// `crossfyre status` - everything at a glance.
pub fn overview(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Crossfyre Status");
    println!("================");
    println!();
    nodes(base)?;
    extensions()?;
    db()?;
    Ok(())
}

/// Print which control plane this data directory is signed in to.
///
/// Without it the only way to tell production from a local stack is to read
/// auth.toml by hand, and `node init` enrols against whatever it says. A host
/// with no nodes yet is exactly when someone is about to run it.
fn control_plane(base: &Path) {
    use super::ui::*;

    println!();
    section("Control plane");
    match crate::auth::load_account(base) {
        Some(account) => {
            let url = account.api_url.trim_end_matches('/').to_string();
            let local = url.contains("localhost") || url.contains("127.0.0.1");
            let marker = if local {
                dim("local")
            } else {
                format!("{YELLOW}live{RESET}")
            };
            println!("{}", row(&check(), &url, &marker, &dim(&account.username)));
        }
        None => {
            println!("{}", row(&dot(), "-", "", &dim("not signed in")));
            hint("Run crossfyre login to choose one.");
        }
    }
}

/// `crossfyre node status` - registered nodes on this machine.
pub fn nodes(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::*;

    let ids = match crate::discover_nodes(base) {
        Ok(ids) => ids,
        Err(e) => {
            title("Crossfyre node status", "");
            section("Nodes");
            println!("{}", row(&dot(), "-", "", &dim("no nodes registered")));
            hint(&e.to_string());
            control_plane(base);
            end();
            return Ok(());
        }
    };

    title("Crossfyre node status", &format!("{} local", ids.len()));
    section("Nodes");
    if ids.is_empty() {
        println!("{}", row(&dot(), "-", "", &dim("none registered")));
        hint("Run crossfyre node init to register this host.");
    }
    for id in ids {
        let paths = crate::NodePaths::new(base, &id);
        let (sym, state, pid) = match std::fs::read_to_string(&paths.pid)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        {
            Some(pid) if Path::new(&format!("/proc/{pid}")).exists() => {
                (check(), format!("{GREEN}running{RESET}"), pid.to_string())
            }
            Some(_) => (bang(), format!("{YELLOW}stale pid{RESET}"), "-".to_string()),
            None => (dot(), dim("stopped"), "-".to_string()),
        };
        let mid = if pid == "-" {
            String::new()
        } else {
            dim(&format!("pid {pid}"))
        };
        println!("{}", row(&sym, &id, &mid, &state));
    }

    control_plane(base);

    println!();
    section("Service");
    if service::node_service_exists() {
        println!(
            "{}",
            row(
                &check(),
                "node",
                "",
                &format!("{GREEN}installed{RESET}  {}", dim("crossfyre-node.service"))
            )
        );
    } else {
        println!("{}", row(&dot(), "node", "", &dim("not installed")));
        hint("Nodes only run while crossfyre node up is open.");
    }
    end();
    Ok(())
}

/// `crossfyre status extensions` - per-extension install + daemon health.
pub fn extensions() -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::*;

    title(
        "Crossfyre extensions",
        &format!("{} available", EXTENSION_PORTS.len()),
    );
    section("Extensions");
    for (ext, port) in EXTENSION_PORTS {
        let installed = is_extension_installed(ext);
        let daemon = if installed {
            service::daemon_status(ext)
        } else {
            "-".to_string()
        };
        let listening = if installed {
            if port_open(*port) { "yes" } else { "no" }
        } else {
            "-"
        };

        let mid = dim(&format!("port {port}"));
        let (sym, status) = if !installed {
            (dot(), dim("not installed"))
        } else {
            let listen_note = if listening == "yes" {
                dim("listening")
            } else {
                dim("not listening")
            };
            match daemon.as_str() {
                "running" => (check(), format!("{GREEN}running{RESET}  {listen_note}")),
                "failed" => (bang(), format!("{YELLOW}failed{RESET}  {listen_note}")),
                "stopped" => (dot(), format!("{}  {}", dim("stopped"), listen_note)),
                other => (dot(), format!("{}  {}", dim(other), listen_note)),
            }
        };
        println!("{}", row(&sym, ext, &mid, &status));
    }
    end();
    Ok(())
}

/// `crossfyre status db` - Postgres container state.
pub fn db() -> Result<(), Box<dyn std::error::Error>> {
    match load_config() {
        Ok(config) => {
            let listening = port_open(config.postgres.port);
            println!(
                "  postgres: port {} {}",
                config.postgres.port,
                if listening {
                    "(accepting connections)"
                } else {
                    "(not reachable)"
                }
            );
            if let Some(ref id) = config.container.id {
                println!("  container: {}", &id[..id.len().min(12)]);
            } else {
                println!("  container: none recorded - `crossfyre db up` to create one");
            }
            // Extension binaries are useless without the db; nudge if it's down.
            if !listening && super::EXTENSIONS.iter().any(|e| ext_bin_path(e).exists()) {
                println!(
                    "  hint: extensions are installed but the database is down - `crossfyre db start`"
                );
            }
        }
        Err(_) => {
            println!(
                "  postgres: no toolchain config yet - created on first `crossfyre node init` or `crossfyre db up`"
            );
        }
    }
    println!();
    Ok(())
}

// `crossfyre status [nodes|extensions|db]` - the one place to look when
// something is off. Probes ports, pid files, and the container. The one thing
// it changes is a pid file naming a process that is gone, which it removes.

use super::config::{is_extension_installed, load_config};
use super::{ENGINES, service, sudo_user};
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

/// What a node's pid file says about it.
#[derive(Debug, PartialEq)]
enum PidState {
    Running(u32),
    /// The file names a process that no longer exists; `cleared` when it was removed.
    Stale {
        cleared: bool,
    },
    Stopped,
}

/// Reads the pid file at `pid`, and removes it when the process it names is gone.
///
/// A pid file naming a process that no longer exists is leftover runtime state, not user
/// data. Reporting it forever with no way to act on it is how a host ends up with three
/// of four nodes reading "stale pid" indefinitely, so it is cleared and the caller says
/// that is what happened.
///
/// Run as root, or elevated on Windows, the file is in the operator's nodes.d, so it is
/// read and removed without following a link the operator could leave on the way.
fn pid_state(pid: &Path) -> PidState {
    match sudo_user::read_to_string(pid)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    {
        Some(n) if crate::os::process_alive(n) => PidState::Running(n),
        Some(_) => PidState::Stale {
            cleared: sudo_user::remove_file(pid).is_ok(),
        },
        None => PidState::Stopped,
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
        let (sym, state, pid) = match pid_state(&paths.pid) {
            PidState::Running(pid) => (check(), format!("{GREEN}running{RESET}"), pid.to_string()),
            PidState::Stale { cleared } => {
                let label = if cleared {
                    format!("{YELLOW}stale pid, cleared{RESET}")
                } else {
                    format!("{YELLOW}stale pid{RESET}")
                };
                (bang(), label, "-".to_string())
            }
            PidState::Stopped => (dot(), dim("stopped"), "-".to_string()),
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
        &format!("{} available", ENGINES.len()),
    );
    section("Extensions");
    for e in ENGINES {
        let (ext, port) = (e.id, &e.port);
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
        println!("{}", row(&sym, e.name, &mid, &status));
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
            if !listening && super::EXTENSIONS.iter().any(|e| is_extension_installed(e)) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::sudo_user::act_as_root;
    use std::fs;

    /// No process has this id: Linux caps pids far below it, and so do the others.
    const DEAD: &str = "999999999\n";

    #[test]
    fn a_stale_pid_file_is_cleared() {
        let t = tempfile::tempdir().expect("tempdir");
        let pid = t.path().join("n.pid");
        fs::write(&pid, DEAD).expect("pid");
        let _root = act_as_root();
        assert_eq!(pid_state(&pid), PidState::Stale { cleared: true });
        assert!(!pid.exists());
    }

    #[test]
    fn a_missing_pid_file_reads_as_stopped() {
        let t = tempfile::tempdir().expect("tempdir");
        assert_eq!(pid_state(&t.path().join("n.pid")), PidState::Stopped);
    }

    /// Run as root, `crossfyre status` reads and clears pid files in the operator's
    /// nodes.d, which the operator can swap for a link to a directory of root's.
    #[cfg(unix)]
    #[test]
    fn an_elevated_status_will_not_clear_a_pid_file_through_a_linked_directory() {
        let t = tempfile::tempdir().expect("tempdir");
        let victim = t.path().join("victim");
        fs::create_dir(&victim).expect("victim");
        fs::write(victim.join("n.pid"), DEAD).expect("victim file");
        let data = t.path().join("crossfyre");
        fs::create_dir(&data).expect("data");
        std::os::unix::fs::symlink(&victim, data.join("nodes.d")).expect("link");

        let _root = act_as_root();
        pid_state(&data.join("nodes.d").join("n.pid"));

        assert!(victim.join("n.pid").exists(), "removed through a link");
    }

    #[cfg(windows)]
    #[test]
    fn an_elevated_status_will_not_clear_a_pid_file_through_a_junction() {
        let t = tempfile::tempdir().expect("tempdir");
        let victim = t.path().join("victim");
        fs::create_dir(&victim).expect("victim");
        fs::write(victim.join("n.pid"), DEAD).expect("victim file");
        let data = t.path().join("crossfyre");
        fs::create_dir(&data).expect("data");
        crate::toolchain::sudo_user::junction(&data.join("nodes.d"), &victim);

        let _root = act_as_root();
        pid_state(&data.join("nodes.d").join("n.pid"));

        assert!(victim.join("n.pid").exists(), "removed through a junction");
    }
}

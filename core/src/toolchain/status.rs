// `crossfyre status [nodes|extensions|db]` - the one place to look when
// something is off. Probes ports, pid files, and the database. The one thing
// it changes is a pid file naming a process that is gone, which it removes.

use super::config::is_extension_installed;
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
    // The same header every other command prints, in place of a ruled line of its own.
    super::ui::title("Crossfyre status", "");
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
    section("Signed in to");
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
            hint("Run `crossfyre login` to sign in.");
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
        let (ext, port) = (e.name, &e.port);
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

/// `crossfyre status db` and `crossfyre db status`: which database the engines use, and
/// whether it runs.
pub fn db() -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::*;

    section("Database");
    match super::db::status() {
        Err(e) => println!("{}", row(&cross(), "database", "", &e.to_string())),
        Ok(None) => {
            println!(
                "{}",
                row(&dot(), "database", "", &dim("no config.toml yet"))
            );
            hint("`crossfyre db up` makes the local database.");
        }
        Ok(Some(db)) => {
            let at = db.settings.address();
            match (&db.settings.backend, &db.cluster) {
                (cfx_db::Backend::External { .. }, _) if db.running => println!(
                    "{}",
                    row(&check(), "external", &at, &format!("{GREEN}answers{RESET}"))
                ),
                (cfx_db::Backend::External { .. }, _) => {
                    println!("{}", row(&cross(), "external", &at, "does not answer"));
                    hint(
                        "It is a database you run: start it, or record another with `crossfyre db external`.",
                    );
                }
                (cfx_db::Backend::Local, None) => {
                    println!("{}", row(&dot(), "local", &at, &dim("not made yet")));
                    hint("`crossfyre db up` makes it.");
                }
                (cfx_db::Backend::Local, Some((dir, major))) => {
                    let made_by = major
                        .map(|m| format!(", PostgreSQL {m}"))
                        .unwrap_or_default();
                    let mid = format!("{at}  {}", dim(&format!("{}{made_by}", dir.display())));
                    if db.running {
                        println!(
                            "{}",
                            row(&check(), "local", &mid, &format!("{GREEN}running{RESET}"))
                        );
                    } else if db.port_taken {
                        println!(
                            "{}",
                            row(
                                &bang(),
                                "local",
                                &mid,
                                &format!(
                                    "{YELLOW}stopped{RESET}, and something else holds its port"
                                )
                            )
                        );
                        hint(
                            "If that is the crossfyre-postgres container an earlier version made, `docker rm -f crossfyre-postgres` removes it.",
                        );
                    } else {
                        println!("{}", row(&dot(), "local", &mid, &dim("stopped")));
                        hint("`crossfyre db up` starts it.");
                    }
                }
            }
        }
    }
    end();
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

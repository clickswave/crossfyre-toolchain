// `crossfyre uninstall` - remove everything the toolchain put on this host:
// extension daemons + binaries, the node service, the Postgres container,
// and (with --purge) the config root including registered node configs.
//
// Also home of the legacy OrionChain cleanup used by `init` to migrate hosts
// that were set up before the orion -> crossfyre merge.

use super::config::{file_name, get_bin_dir, get_toolchain_dir};
use super::packaging::{Packaging, remove_note};
use super::sudo_user::cmd_as_invoking_user;
use super::{ENGINES, EXTENSIONS, install, service};
use std::path::{Path, PathBuf};

/// Where the installer puts everything, and what uninstall removes whole when no package
/// has files in it.
const INSTALL_ROOT: &str = "/opt/crossfyre";

pub fn run(purge: bool) -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::*;

    let confirmed = dialoguer::Confirm::new()
        .with_prompt(if purge {
            "Remove all Crossfyre services, binaries, the database container AND all config/node registrations?"
        } else {
            "Remove all Crossfyre services, binaries and the database container? (config root is kept)"
        })
        .default(false)
        .interact()?;
    if !confirmed {
        warn("Aborted, nothing was removed.");
        return Ok(());
    }

    title(
        "Crossfyre uninstall",
        if purge {
            "services, binaries, database, config"
        } else {
            "services, binaries, database"
        },
    );

    // Extensions: stop, disable, deregister, delete binaries. Then the node
    // service (system scope). Each sub-call prints its own per-item lines.
    section("Services");
    for ext in EXTENSIONS {
        let _ = install::remove(ext);
    }
    // Drop-in directories beside the units, under the public name and the legacy
    // one. `remove` leaves them, since a person wrote them and a reinstall wants
    // them back; uninstalling everything is the moment they go too.
    if let Some(dir) = service::user_unit_dir() {
        for e in ENGINES {
            for key in std::iter::once(e.name).chain(e.legacy) {
                let d = dir.join(format!("crossfyre-{key}.service.d"));
                if d.is_dir() && std::fs::remove_dir_all(&d).is_ok() {
                    ok(&format!("Removed {}", d.display()));
                }
            }
        }
    }
    let _ = service::remove_node_service();

    // Database container.
    section("Database");
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", "crossfyre-postgres"])
        .output();
    ok("Removed database container (if it existed).");

    // The install dir (binaries are already gone; this removes the tree,
    // including the crossfyre binary itself - fine, we're already loaded).
    // A package's own files stay where it put them, for it to remove.
    #[cfg(not(windows))]
    {
        section("Binaries");
        let root = Path::new(INSTALL_ROOT);
        match super::packaging::current() {
            None => {
                let _ = std::fs::remove_dir_all(root);
                ok(&format!("Removed {INSTALL_ROOT}."));
            }
            Some(p) => {
                let bin = get_bin_dir();
                for f in unowned_files(&bin, p) {
                    let _ = std::fs::remove_file(f);
                }
                let cli = std::env::current_exe().ok();
                if bin.starts_with(root) && !has_files_under(p, &bin, root, cli.as_deref()) {
                    let _ = std::fs::remove_dir_all(root);
                    ok(&format!("Removed {INSTALL_ROOT}."));
                } else {
                    ok(&format!(
                        "Removed what Crossfyre fetched into {}.",
                        bin.display()
                    ));
                }
                warn(&format!(
                    "Kept {}: {}",
                    p.owned().join(", "),
                    remove_note(p.manager)
                ));
            }
        }
    }

    section("Config");
    if purge {
        let dir = get_toolchain_dir();
        let _ = std::fs::remove_dir_all(&dir);
        ok(&format!(
            "Purged config root {} (node registrations included).",
            dir.display()
        ));
    } else {
        warn(&format!(
            "Config root {} kept. Re-run with --purge to remove it.",
            get_toolchain_dir().display()
        ));
    }

    done("Uninstalled");
    end();
    Ok(())
}

/// Every file name a component may have in the bin directory, with the name of its version
/// sidecar: the CLI, the node, cfx-script, and each engine under its public name and the
/// name it had before.
fn component_files(component: &str) -> Vec<String> {
    let mut names = vec![component.to_string()];
    if let Some(old) = super::engine(component).and_then(|e| e.legacy) {
        names.push(old.to_string());
    }
    names
        .into_iter()
        .flat_map(|n| [file_name(&n), format!("{n}.version")])
        .collect()
}

/// The components uninstall may find in the bin directory, by public name.
fn components() -> Vec<&'static str> {
    let mut out = vec!["crossfyre", "node", "cfx-script"];
    out.extend(ENGINES.iter().map(|e| e.name));
    out
}

/// What uninstall removes from `bin_dir` for a packaged install: the files of every
/// component the package does not own, which the CLI fetched there.
fn unowned_files(bin_dir: &Path, p: &Packaging) -> Vec<PathBuf> {
    components()
        .into_iter()
        .filter(|c| !p.owns(c))
        .flat_map(component_files)
        .map(|f| bin_dir.join(f))
        .collect()
}

/// Does the package have a file under `root`: its packaging.json, the CLI at `cli` when
/// it owns that, or another component it owns in `bin_dir`?
fn has_files_under(p: &Packaging, bin_dir: &Path, root: &Path, cli: Option<&Path>) -> bool {
    let owned_in_bin = components()
        .into_iter()
        .any(|c| c != "crossfyre" && p.owns(c));
    p.file.starts_with(root)
        || (p.owns("crossfyre") && cli.is_some_and(|c| c.starts_with(root)))
        || (bin_dir.starts_with(root) && owned_in_bin)
}

/// Best-effort migration cleanup for hosts initialized before the
/// orion -> crossfyre merge. Stops and removes the old orion services,
/// the old install dir, config dir, and the old database container.
/// Called from `init` when leftovers are detected; every step is optional.
pub fn cleanup_legacy_orionchain() {
    let legacy_bin = Path::new("/opt/orionchain");
    let legacy_cfg = super::sudo_user::invoking_user_config_dir().join("orionchain");
    if !legacy_bin.exists() && !legacy_cfg.exists() {
        return;
    }

    println!("[migrate] Legacy OrionChain install detected - cleaning up...");

    #[cfg(target_os = "linux")]
    for tool in EXTENSIONS {
        let svc = format!("orion-{tool}.service");
        let _ = cmd_as_invoking_user("systemctl")
            .args(["--user", "stop", &svc])
            .output();
        let _ = cmd_as_invoking_user("systemctl")
            .args(["--user", "disable", &svc])
            .output();
        let unit = super::sudo_user::invoking_user_home()
            .join(".config/systemd/user")
            .join(&svc);
        if unit.exists() {
            let _ = std::fs::remove_file(&unit);
            println!("[migrate] Removed old service {svc}");
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = cmd_as_invoking_user("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
    }

    #[cfg(target_os = "macos")]
    for tool in EXTENSIONS {
        let plist = super::sudo_user::invoking_user_home()
            .join("Library/LaunchAgents")
            .join(format!("com.orionchain.{}.plist", tool));
        if plist.exists() {
            let _ = cmd_as_invoking_user("launchctl")
                .args(["unload", "-w", &plist.to_string_lossy()])
                .output();
            let _ = std::fs::remove_file(&plist);
            println!("[migrate] Removed old launchd agent for {}", tool);
        }
    }

    // Old database container. Scan state is per-host and disposable; the new
    // container is provisioned fresh by init.
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", "orion-postgres"])
        .output();

    if legacy_bin.exists() {
        match std::fs::remove_dir_all(legacy_bin) {
            Ok(_) => println!("[migrate] Removed /opt/orionchain"),
            Err(e) => {
                eprintln!("[migrate] Could not remove /opt/orionchain: {e} (remove it manually)")
            }
        }
    }
    if legacy_cfg.exists() {
        match std::fs::remove_dir_all(&legacy_cfg) {
            Ok(_) => println!("[migrate] Removed {}", legacy_cfg.display()),
            Err(e) => eprintln!("[migrate] Could not remove {}: {}", legacy_cfg.display(), e),
        }
    }
    println!("[migrate] Legacy cleanup complete.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packaging(json: &str, file: &str) -> Packaging {
        Packaging::parse(json, PathBuf::from(file), true).expect("parses")
    }

    #[test]
    fn an_apt_install_loses_what_the_cli_fetched_and_keeps_the_cli() {
        let apt = packaging(
            r#"{"manager":"apt","owns":["crossfyre"]}"#,
            "/usr/lib/crossfyre/packaging.json",
        );
        let bin = Path::new("/opt/crossfyre/bin");
        let gone = unowned_files(bin, &apt);
        for f in [
            "node",
            "node.version",
            "cfx-script",
            "plessor",
            "plessor.version",
            "cortex",
        ] {
            assert!(gone.contains(&bin.join(f)), "{f} in {gone:?}");
        }
        assert!(!gone.iter().any(|f| f.ends_with("crossfyre")), "{gone:?}");
        // apt's files are in /usr, so the whole of /opt/crossfyre is the CLI's to remove.
        let root = Path::new(INSTALL_ROOT);
        let cli = Path::new("/usr/bin/crossfyre");
        assert!(!has_files_under(&apt, bin, root, Some(cli)));
    }

    #[test]
    fn a_package_that_keeps_its_files_in_opt_crossfyre_keeps_them() {
        let image = packaging(
            r#"{"manager":"container","owns":["crossfyre","node","cfx-script","ambulo",
                "voyage","doorward","toolmark","plessor"]}"#,
            "/opt/crossfyre/bin/packaging.json",
        );
        let bin = Path::new("/opt/crossfyre/bin");
        assert!(unowned_files(bin, &image).is_empty());
        let root = Path::new(INSTALL_ROOT);
        assert!(has_files_under(
            &image,
            bin,
            root,
            Some(&bin.join("crossfyre"))
        ));
        // Even with its packaging.json somewhere else, the CLI it owns keeps the tree.
        let elsewhere = packaging(
            r#"{"manager":"pacman","owns":["crossfyre"]}"#,
            "/usr/lib/crossfyre/packaging.json",
        );
        assert!(has_files_under(
            &elsewhere,
            bin,
            root,
            Some(&bin.join("crossfyre"))
        ));
    }
}

// `crossfyre uninstall` - remove everything the toolchain put on this host:
// extension daemons + binaries, the node service, the Postgres container,
// and (with --purge) the config root including registered node configs.
// --keep-data leaves the container, and --yes skips the question, which is how a
// package's removal script runs it.

#[cfg(any(not(windows), test))]
use super::config::file_name;
use super::config::{get_bin_dir, get_toolchain_dir};
#[cfg(any(not(windows), test))]
use super::packaging::Packaging;
#[cfg(not(windows))]
use super::packaging::remove_note;
use super::{ENGINES, install, service};
use std::path::{Path, PathBuf};

/// Where the installer puts everything, and what uninstall removes whole when no package
/// has files in it.
#[cfg(any(not(windows), test))]
const INSTALL_ROOT: &str = "/opt/crossfyre";

/// What `crossfyre uninstall` removes besides the services and binaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    /// The config root too, node registrations included.
    pub purge: bool,
    /// Leave the database container, and the scan state in it, in place.
    pub keep_data: bool,
}

impl Scope {
    fn question(self) -> &'static str {
        match (self.purge, self.keep_data) {
            (true, _) => {
                "Remove all Crossfyre services, binaries, the database container AND all config/node registrations?"
            }
            (false, true) => {
                "Remove all Crossfyre services and binaries? (the database container and config root are kept)"
            }
            (false, false) => {
                "Remove all Crossfyre services, binaries and the database container? (config root is kept)"
            }
        }
    }

    fn what(self) -> &'static str {
        match (self.purge, self.keep_data) {
            (true, _) => "services, binaries, database, config",
            (false, true) => "services, binaries",
            (false, false) => "services, binaries, database",
        }
    }
}

/// Uninstall, asking first unless `yes`.
pub fn run(scope: Scope, yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::*;

    if scope.purge && scope.keep_data {
        return Err("--purge removes the config root and --keep-data keeps it: pick one".into());
    }
    let confirmed = yes
        || dialoguer::Confirm::new()
            .with_prompt(scope.question())
            .default(false)
            .interact()?;
    if !confirmed {
        warn("Aborted, nothing was removed.");
        return Ok(());
    }

    title("Crossfyre uninstall", scope.what());

    // Extensions: stop, disable, deregister, delete binaries. Then the node
    // service (system scope). Each sub-call prints its own per-item lines.
    section("Services");
    for e in ENGINES {
        if let Err(err) = install::remove(e.name) {
            warn(&format!("could not remove {}: {err}", e.name));
        }
    }
    // Drop-in directories beside the units. `remove` leaves them, since a person
    // wrote them and a reinstall wants them back; uninstalling everything is the
    // moment they go too.
    if let Some(dir) = service::user_unit_dir() {
        for e in ENGINES {
            let d = dir.join(format!("crossfyre-{}.service.d", e.name));
            if d.is_dir() && super::sudo_user::remove_dir_all(&d).is_ok() {
                ok(&format!("Removed {}", d.display()));
            }
        }
    }
    #[cfg(target_os = "linux")]
    match super::linger::undo() {
        Some(Ok(name)) => ok(&format!(
            "Lingering turned off for {name}, as crossfyre had turned it on for the engines."
        )),
        Some(Err(e)) => warn(&format!("could not turn lingering off: {e}")),
        None => {}
    }
    let _ = service::remove_node_service();

    // Database container.
    section("Database");
    if scope.keep_data {
        warn("Database container kept (--keep-data).");
    } else {
        let removed = super::db::remove_all();
        if removed.is_empty() {
            ok("No database container to remove.");
        }
        for name in removed {
            ok(&format!("Removed database container {name} and its data."));
        }
    }

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
                if !p.owns("cfx-script")
                    && let Some(python) = fetched_python(&bin)
                {
                    let _ = std::fs::remove_dir_all(python);
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
    // Windows keeps everything in %ProgramFiles%\Crossfyre. A program that is running,
    // this crossfyre.exe for one, cannot be removed while it runs, so whatever is still
    // held open is removed at the next restart instead, and everything else now.
    #[cfg(windows)]
    {
        section("Binaries");
        let bin = get_bin_dir();
        let root = bin.parent().unwrap_or(&bin).to_path_buf();
        let mut held = Vec::new();
        clear_tree(&root, &mut |p| {
            remove_at_restart(p);
            held.push(p.to_path_buf());
        });
        ok(&format!("Removed {}.", root.display()));
        let files: Vec<String> = held
            .iter()
            .filter(|p| !p.is_dir())
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        if !files.is_empty() {
            warn(&format!(
                "{} still in use, so removed at the next restart along with the folder.",
                files.join(", ")
            ));
        }
    }

    section("Config");
    if scope.purge {
        let dir = get_toolchain_dir();
        // The operator's directory, removed elevated or as root: no following a link on
        // the way there.
        let _ = super::sudo_user::remove_dir_all(&dir);
        ok(&format!(
            "Purged config root {} (node registrations included).",
            dir.display()
        ));
        // A node run as root keeps its tunnel config and credentials outside the
        // config root, in a directory of root's.
        match super::node_config::purge_root_network_dirs() {
            Ok(Some(d)) => ok(&format!(
                "Removed {} (the tunnel configs of nodes run as root).",
                d.display()
            )),
            Ok(None) => {}
            Err(e) => warn(&format!(
                "Kept the tunnel configs of nodes run as root: {e}"
            )),
        }
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

/// Have Windows remove the file or the empty directory at `path` when the machine next
/// starts. Queued deepest first, so each directory is empty by its turn.
///
/// A file is first renamed aside, which Windows allows for a running executable, and
/// the new name is what gets queued. Queueing the original name meant that installing
/// again before the restart put the new crossfyre.exe exactly where the queued delete
/// pointed, and the restart removed the fresh install.
#[cfg(windows)]
fn remove_at_restart(path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
    let aside;
    let path = if path.is_dir() {
        path
    } else {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        aside = aside_name(path, &format!("{}-{nanos}", std::process::id()));
        if std::fs::rename(path, &aside).is_ok() {
            aside.as_path()
        } else {
            path
        }
    };
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: a NUL-terminated path, and NULL as the new name, which is how MoveFileExW
    // is asked to delete.
    unsafe {
        MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

/// Where `remove_at_restart` moves a file it cannot remove now: beside it, under a name
/// no install writes, so the delete queued for the restart can only ever hit this copy.
/// Same directory, so the rename never crosses a volume.
#[cfg(any(windows, test))]
fn aside_name(path: &Path, tag: &str) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.removed-{tag}"))
}

/// Remove `dir` and everything in it that can be removed now, and hand to `later`
/// whatever cannot, deepest first so a directory comes after what is in it. Returns
/// whether anything was handed over. A file that cannot be removed does not stop the
/// rest being removed, as it does in `remove_dir_all`, which gives up at the first.
#[cfg(any(windows, test))]
fn clear_tree(dir: &Path, later: &mut dyn FnMut(&Path)) -> bool {
    let mut handed = false;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            // A link to a directory is removed as a link, not followed.
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                handed |= clear_tree(&path, later);
            } else if std::fs::remove_file(&path).is_err() && path.exists() {
                later(&path);
                handed = true;
            }
        }
    }
    if std::fs::remove_dir(dir).is_err() && dir.exists() {
        later(dir);
        handed = true;
    }
    handed
}

/// Every file name a component may have in the bin directory, with the name of its version
/// sidecar: the CLI, the node, cfx-script and each engine.
/// cfx-script also has the record of a release that could not start.
#[cfg(any(not(windows), test))]
fn component_files(component: &str) -> Vec<String> {
    let mut files = vec![file_name(component), format!("{component}.version")];
    if component == "cfx-script" {
        files.push("cfx-script.cannot-start".to_string());
    }
    files
}

/// The components uninstall may find in the bin directory.
#[cfg(any(not(windows), test))]
fn components() -> Vec<&'static str> {
    let mut out = vec!["crossfyre", "node", "cfx-script"];
    out.extend(ENGINES.iter().map(|e| e.name));
    out
}

/// What uninstall removes from `bin_dir` for a packaged install: the files of every
/// component the package does not own, which the CLI fetched there.
#[cfg(any(not(windows), test))]
fn unowned_files(bin_dir: &Path, p: &Packaging) -> Vec<PathBuf> {
    components()
        .into_iter()
        .filter(|c| !p.owns(c))
        .flat_map(component_files)
        .map(|f| bin_dir.join(f))
        .collect()
}

/// The python folder the CLI put beside a cfx-script it fetched into `bin_dir`, when it is
/// one: a directory, not a link, with a libpython in its lib folder. Anything else of that
/// name is not ours, and a package's bin_dir may be shared with other files.
#[cfg(not(windows))]
fn fetched_python(bin_dir: &Path) -> Option<PathBuf> {
    let dir = bin_dir.join(crate::executor::BUNDLED_PYTHON_DIR);
    if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
        return None;
    }
    let has_libpython = std::fs::read_dir(dir.join("lib"))
        .ok()?
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("libpython3"));
    has_libpython.then_some(dir)
}

/// Does the package have a file under `root`: its packaging.json, the CLI at `cli` when
/// it owns that, or another component it owns in `bin_dir`?
#[cfg(any(not(windows), test))]
fn has_files_under(p: &Packaging, bin_dir: &Path, root: &Path, cli: Option<&Path>) -> bool {
    let owned_in_bin = components()
        .into_iter()
        .any(|c| c != "crossfyre" && p.owns(c));
    p.file.starts_with(root)
        || (p.owns("crossfyre") && cli.is_some_and(|c| c.starts_with(root)))
        || (bin_dir.starts_with(root) && owned_in_bin)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The delete Windows runs at the restart must point at a name an install never
    // writes, or reinstalling before the restart loses the new crossfyre.exe.
    #[test]
    fn a_file_left_for_the_restart_is_queued_under_a_name_no_install_writes() {
        let exe = Path::new("C:/Users/a/AppData/Local/Crossfyre/bin/crossfyre.exe");
        let aside = aside_name(exe, "4242-17");
        assert_eq!(
            aside.parent(),
            exe.parent(),
            "same directory, so the rename stays on one volume"
        );
        assert_ne!(aside, exe);
        assert_eq!(aside.file_name().unwrap(), "crossfyre.exe.removed-4242-17");
        for c in components() {
            for f in component_files(c) {
                assert_ne!(
                    aside.file_name().unwrap().to_string_lossy(),
                    f,
                    "{c} installs {f}"
                );
            }
        }
    }

    // A directory others cannot write stands in for a program Windows will not let go
    // of: what is in it cannot be removed, and nothing else should wait for a restart.
    #[cfg(unix)]
    #[test]
    fn only_what_cannot_be_removed_now_is_left_for_the_restart() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root removes it regardless
        }
        let scratch = tempfile::tempdir().expect("scratch");
        let root = scratch.path().join("Crossfyre");
        let bin = root.join("bin");
        let held = bin.join("held");
        std::fs::create_dir_all(&bin).expect("dirs");
        for name in [
            "oast.exe",
            "ambulo.exe",
            "voyage.exe",
            "node.version",
            "plessor.exe",
        ] {
            std::fs::write(bin.join(name), "x").expect("file");
        }
        // Made after the files, which puts it first in a tmpfs listing: a removal that
        // gives up at the first failure then leaves every other file behind.
        std::fs::create_dir(&held).expect("dir");
        std::fs::write(held.join("crossfyre.exe"), "x").expect("file");
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o555)).expect("lock");

        let mut later = Vec::new();
        let deferred = clear_tree(&root, &mut |p| later.push(p.to_path_buf()));
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o755)).expect("unlock");

        assert!(deferred);
        assert_eq!(
            later,
            vec![
                held.join("crossfyre.exe"),
                held.clone(),
                bin.clone(),
                root.clone()
            ],
            "only the held file and the directories above it wait"
        );
        assert!(
            !bin.join("oast.exe").exists(),
            "a file nothing holds goes now"
        );
        assert!(!clear_tree(&root, &mut |_| panic!("nothing is left")));
    }

    #[test]
    fn keeping_the_data_and_purging_it_are_not_both_asked_for() {
        let both = Scope {
            purge: true,
            keep_data: true,
        };
        let err = run(both, true).expect_err("refused before anything is removed");
        assert!(err.to_string().contains("pick one"), "{err}");
        let keep = Scope {
            purge: false,
            keep_data: true,
        };
        assert!(!keep.what().contains("database"), "{}", keep.what());
        assert!(
            keep.question()
                .contains("database container and config root are kept")
        );
    }

    fn packaging(json: &str, file: &str) -> Packaging {
        Packaging::parse(json, PathBuf::from(file), true).expect("parses")
    }

    // Unix only: packaged installs and their systemd units are a Linux and macOS layout.
    #[cfg(unix)]
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
            "cfx-script.cannot-start",
            "plessor",
            "plessor.version",
        ] {
            assert!(gone.contains(&bin.join(f)), "{f} in {gone:?}");
        }
        assert!(!gone.iter().any(|f| f.ends_with("crossfyre")), "{gone:?}");
        // apt's files are in /usr, so the whole of /opt/crossfyre is the CLI's to remove.
        let root = Path::new(INSTALL_ROOT);
        let cli = Path::new("/usr/bin/crossfyre");
        assert!(!has_files_under(&apt, bin, root, Some(cli)));
    }

    #[cfg(unix)]
    #[test]
    fn only_a_python_folder_with_a_libpython_in_it_is_taken_for_the_fetched_one() {
        let bin = std::env::temp_dir().join(format!("cfx-uninstall-python-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&bin);
        std::fs::create_dir_all(&bin).expect("mkdir");
        assert_eq!(fetched_python(&bin), None);
        // /usr/bin/python is a link to python3 on many systems.
        std::os::unix::fs::symlink("python3", bin.join("python")).expect("link");
        assert_eq!(fetched_python(&bin), None);
        std::fs::remove_file(bin.join("python")).expect("unlink");
        std::fs::create_dir_all(bin.join("python").join("lib")).expect("mkdir");
        assert_eq!(fetched_python(&bin), None, "a folder without a libpython");
        std::fs::write(bin.join("python/lib/libpython3.13.so.1.0"), b"").expect("write");
        assert_eq!(fetched_python(&bin), Some(bin.join("python")));
        let _ = std::fs::remove_dir_all(&bin);
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

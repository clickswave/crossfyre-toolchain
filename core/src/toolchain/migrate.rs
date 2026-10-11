// Carry a machine's installed engines over to the names they have now.
//
// An engine that has been renamed (`legacy` is set in its `ENGINES` row) may still be
// installed under its legacy name: a binary at `<bin>/<legacy>`, a version sidecar
// beside it, a service registered as `crossfyre-<legacy>`, and on Linux possibly a
// hand-written drop-in directory `crossfyre-<legacy>.service.d/` holding settings the
// engine needs (the OAST endpoint, for one). An older CLI that updates itself through a
// manifest alias entry leaves the machine exactly like that.
//
// For each such engine this, idempotently:
//
//   1. stops and disables the legacy service, before anything else can start on the
//      same port;
//   2. moves the binary to its public name and the version sidecar with it, and leaves
//      a symlink at the legacy path so the old command keeps working;
//   3. moves the drop-in directory to the new unit's name, so its settings follow;
//   4. removes the legacy service and registers the new one, enabled and started if
//      the legacy one existed;
//
// and once for the host, rewrites `config.toml` so `[extensions]` uses public names.
// `nodes.d` is left alone: it holds engine ids, which never change.
//
// Modelled on `uninstall::cleanup_legacy_orionchain`, and called from the same places
// plus the start of `crossfyre update` and `crossfyre extension install`.

use super::Engine;
use super::config::{file_name, is_regular_file};
use std::fs;
use std::path::{Path, PathBuf};

/// Where things live on the machine being migrated.
#[derive(Debug, Clone)]
pub struct Layout {
    /// The directory holding the engine binaries and their `.version` sidecars.
    pub bin_dir: PathBuf,
    /// The systemd user unit directory, whose `<unit>.d/` drop-in directories are
    /// moved. `None` where there are no drop-ins (macOS, Windows).
    pub unit_dir: Option<PathBuf>,
    /// The toolchain `config.toml`.
    pub config_path: PathBuf,
}

impl Layout {
    /// This machine.
    pub fn host() -> Self {
        Self {
            bin_dir: super::config::get_bin_dir(),
            unit_dir: super::service::user_unit_dir(),
            config_path: super::config::get_config_path(),
        }
    }
}

/// The service manager, as the migration needs it. A unit is addressed by `key`, the
/// name inside its unit name (`crossfyre-<key>.service`, `io.crossfyre.<key>`,
/// `Crossfyre-<key>`), so a legacy unit can be reached after the table has moved on.
pub trait Units {
    fn exists(&self, key: &str) -> bool;
    fn stop(&self, key: &str);
    fn disable(&self, key: &str);
    fn enable(&self, key: &str);
    fn start(&self, key: &str);
    /// Deregister the unit (and reload the manager).
    fn remove(&self, key: &str);
    /// Register engine `id`'s unit under its public name (and reload the manager).
    fn create(&self, id: &str);
}

/// What happened to one engine.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub id: &'static str,
    pub from: &'static str,
    pub to: &'static str,
    /// The binary was moved to its public name (or a newer one was already there and
    /// the legacy copy was removed).
    pub binary: bool,
    /// A symlink was left at the legacy path.
    pub linked: bool,
    /// The drop-in directory was moved to the new unit's name.
    pub dropin: bool,
    /// The legacy service was replaced by the new one.
    pub unit: bool,
    /// Why this engine was left as it was, when it was.
    pub skipped: Option<String>,
}

/// Migrate this machine, printing one line per engine that changed. Never fails: a
/// step that cannot be taken is reported and the rest of the command carries on.
pub fn renamed_engines() {
    let layout = Layout::host();
    let outcomes = migrate_in(super::ENGINES, &layout, &super::service::HostUnits);
    for o in &outcomes {
        if let Some(why) = &o.skipped {
            eprintln!("[migrate] {} is now {}, not moved yet: {why}", o.from, o.to);
            continue;
        }
        let mut done = Vec::new();
        if o.binary {
            done.push("binary".to_string());
        }
        if o.unit {
            done.push("service".to_string());
        }
        if o.dropin {
            done.push(format!("crossfyre-{}.service.d", o.to));
        }
        println!(
            "[migrate] {} is now {}: moved {}",
            o.from,
            o.to,
            done.join(", ")
        );
        if o.linked {
            println!(
                "[migrate] {} still runs it, through a link that the next release removes",
                layout.bin_dir.join(file_name(o.from)).display()
            );
        }
    }
    match super::config::rewrite_legacy_keys(&layout.config_path) {
        Ok(true) => println!(
            "[migrate] {} now names engines by their current names",
            layout.config_path.display()
        ),
        Ok(false) => {}
        Err(e) => eprintln!(
            "[migrate] could not rewrite {}: {e}",
            layout.config_path.display()
        ),
    }
}

/// Migrate every renamed engine in `table` on the machine `layout` describes. Returns
/// an outcome for each engine that had anything under its legacy name.
pub fn migrate_in(table: &[Engine], layout: &Layout, units: &dyn Units) -> Vec<Outcome> {
    let mut out = Vec::new();
    for e in table {
        let Some(old) = e.legacy else { continue };
        if let Some(o) = migrate_one(e, old, layout, units) {
            out.push(o);
        }
    }
    out
}

fn migrate_one(
    e: &Engine,
    old: &'static str,
    layout: &Layout,
    units: &dyn Units,
) -> Option<Outcome> {
    let old_bin = layout.bin_dir.join(file_name(old));
    let new_bin = layout.bin_dir.join(file_name(e.name));
    let old_is_file = is_regular_file(&old_bin);
    let had_old_unit = units.exists(old);

    // Something to carry over: the binary under the legacy name, or a legacy unit
    // left beside a binary already under the public one. A legacy unit with no binary
    // behind it under either name has nothing to be moved to.
    let legacy_unit_beside_new = had_old_unit && new_bin.exists();
    if !(old_is_file || legacy_unit_beside_new) {
        return None;
    }

    let mut o = Outcome {
        id: e.id,
        from: old,
        to: e.name,
        ..Outcome::default()
    };

    // Checked before anything is stopped, so a run without the rights to finish (a
    // `crossfyre update` without sudo) leaves the engine running as it was.
    if old_is_file && !writable(&layout.bin_dir) {
        o.skipped = Some(format!(
            "{} is not writable here (run it with sudo)",
            layout.bin_dir.display()
        ));
        return Some(o);
    }

    // The legacy daemon goes down first. The new unit listens on the same port, and
    // started beside the old one it fails to bind and loops on Restart=on-failure.
    if had_old_unit {
        units.stop(old);
        units.disable(old);
    }

    if old_is_file {
        let moved = if new_bin.exists() {
            // A binary under the public name is already in place (an install made
            // before this ran), and it is the one to keep.
            fs::remove_file(&old_bin)
        } else {
            fs::rename(&old_bin, &new_bin)
        };
        if let Err(err) = moved {
            if had_old_unit {
                units.enable(old);
                units.start(old);
            }
            o.skipped = Some(format!("could not move {}: {err}", old_bin.display()));
            return Some(o);
        }
        o.binary = true;
        move_sidecar(&layout.bin_dir, old, e.name);
        o.linked = link(&old_bin, &new_bin);
    }

    if let Some(dir) = &layout.unit_dir {
        let old_d = dir.join(format!("crossfyre-{old}.service.d"));
        let new_d = dir.join(format!("crossfyre-{}.service.d", e.name));
        if old_d.is_dir() && !new_d.exists() && fs::rename(&old_d, &new_d).is_ok() {
            o.dropin = true;
        }
    }

    if had_old_unit {
        units.remove(old);
    }
    units.create(e.id);
    if had_old_unit {
        units.enable(e.name);
        units.start(e.name);
        o.unit = true;
    }
    Some(o)
}

/// Move `<old>.version` to `<new>.version`. A sidecar already under the new name
/// describes the binary there and wins.
fn move_sidecar(bin_dir: &Path, old: &str, new: &str) {
    let old_v = bin_dir.join(format!("{old}.version"));
    let new_v = bin_dir.join(format!("{new}.version"));
    if !old_v.exists() {
        return;
    }
    if new_v.exists() {
        let _ = fs::remove_file(&old_v);
    } else {
        let _ = fs::rename(&old_v, &new_v);
    }
}

/// Leave `old` as a relative symlink to `new`, so the old command keeps running the
/// engine. Windows is skipped: a symlink there needs a privilege the CLI may not have,
/// and the old name is only a convenience.
fn link(old: &Path, new: &Path) -> bool {
    #[cfg(unix)]
    {
        let Some(target) = new.file_name() else {
            return false;
        };
        std::os::unix::fs::symlink(target, old).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = (old, new);
        false
    }
}

/// Can files be created and renamed in `dir`?
fn writable(dir: &Path) -> bool {
    let probe = dir.join(".crossfyre-migrate-probe");
    match fs::File::create(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A table in which one engine has been renamed and one has not.
    const TABLE: &[Engine] = &[
        Engine {
            id: "cortex",
            name: "fresh",
            legacy: Some("cortex"),
            port: 4445,
            about: "",
        },
        Engine {
            id: "voyage",
            name: "voyage",
            legacy: None,
            port: 4442,
            about: "",
        },
    ];

    /// A service manager that records what it was asked to do, in order.
    #[derive(Default)]
    struct Recorder {
        units: RefCell<Vec<String>>,
        calls: RefCell<Vec<String>>,
    }

    impl Recorder {
        fn with(units: &[&str]) -> Self {
            let r = Self::default();
            r.units
                .replace(units.iter().map(|u| u.to_string()).collect());
            r
        }
        fn log(&self, what: &str, key: &str) {
            self.calls.borrow_mut().push(format!("{what} {key}"));
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
        fn position(&self, call: &str) -> usize {
            self.calls()
                .iter()
                .position(|c| c == call)
                .unwrap_or_else(|| panic!("no `{call}` in {:?}", self.calls()))
        }
    }

    impl Units for Recorder {
        fn exists(&self, key: &str) -> bool {
            self.units.borrow().iter().any(|u| u == key)
        }
        fn stop(&self, key: &str) {
            self.log("stop", key);
        }
        fn disable(&self, key: &str) {
            self.log("disable", key);
        }
        fn enable(&self, key: &str) {
            self.log("enable", key);
        }
        fn start(&self, key: &str) {
            self.log("start", key);
        }
        fn remove(&self, key: &str) {
            self.log("remove", key);
            self.units.borrow_mut().retain(|u| u != key);
        }
        fn create(&self, id: &str) {
            self.log("create", id);
            let name = super::super::find_engine(TABLE, id)
                .map(|e| e.name)
                .unwrap_or(id);
            self.units.borrow_mut().push(name.to_string());
        }
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "cfx-migrate-test-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("bin")).expect("bin dir");
            fs::create_dir_all(p.join("units")).expect("unit dir");
            Self(p)
        }
        fn layout(&self) -> Layout {
            Layout {
                bin_dir: self.0.join("bin"),
                unit_dir: Some(self.0.join("units")),
                config_path: self.0.join("config.toml"),
            }
        }
        fn bin(&self, name: &str) -> PathBuf {
            self.0.join("bin").join(file_name(name))
        }
        fn unit(&self, name: &str) -> PathBuf {
            self.0.join("units").join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A machine as an older CLI leaves it: the binary, its sidecar, a running unit and
    /// a drop-in, all under the legacy name.
    fn legacy_machine(s: &Scratch) {
        fs::write(s.bin("cortex"), b"engine-0.0.23").expect("binary");
        fs::write(s.0.join("bin/cortex.version"), b"0.0.23").expect("sidecar");
        fs::create_dir_all(s.unit("crossfyre-cortex.service.d")).expect("drop-in dir");
        fs::write(
            s.unit("crossfyre-cortex.service.d/oast.conf"),
            b"[Service]\nEnvironment=OAST=1\n",
        )
        .expect("drop-in");
    }

    #[cfg(unix)]
    #[test]
    fn a_machine_on_the_old_names_moves_to_the_new_ones() {
        // The real table, on a machine as 0.1.30 left it.
        let s = Scratch::new("real");
        fs::write(s.bin("cortex"), b"engine").expect("binary");
        fs::write(s.0.join("bin/cortex.version"), b"0.0.23").expect("sidecar");
        fs::create_dir_all(s.unit("crossfyre-cortex.service.d")).expect("drop-in dir");
        fs::write(s.unit("crossfyre-cortex.service.d/oast.conf"), b"x").expect("drop-in");
        fs::write(s.bin("voyage"), b"engine").expect("an engine never renamed");
        let units = Recorder::with(&["cortex", "voyage"]);

        let out = migrate_in(super::super::ENGINES, &s.layout(), &units);

        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!((out[0].from, out[0].to), ("cortex", "plessor"));
        assert!(units.position("stop cortex") < units.position("start plessor"));
        assert!(is_regular_file(&s.bin("plessor")));
        assert_eq!(
            fs::read_link(s.bin("cortex")).expect("link"),
            PathBuf::from("plessor")
        );
        assert!(s.unit("crossfyre-plessor.service.d/oast.conf").exists());
        assert!(is_regular_file(&s.bin("voyage")), "voyage is left as it is");
        assert!(!units.calls().iter().any(|c| c.ends_with("voyage")));
    }

    #[test]
    fn the_legacy_unit_is_stopped_before_the_new_one_starts() {
        let s = Scratch::new("order");
        legacy_machine(&s);
        let units = Recorder::with(&["cortex"]);

        let out = migrate_in(TABLE, &s.layout(), &units);

        assert_eq!(out.len(), 1, "only the renamed engine is touched: {out:?}");
        let stop_old = units.position("stop cortex");
        let disable_old = units.position("disable cortex");
        let start_new = units.position("start fresh");
        assert!(stop_old < start_new, "{:?}", units.calls());
        assert!(disable_old < start_new, "{:?}", units.calls());
        assert!(units.position("remove cortex") < start_new);
        assert!(units.position("create cortex") < start_new);
        assert!(!units.calls().contains(&"start cortex".to_string()));
        assert!(out[0].unit && out[0].binary && out[0].linked && out[0].dropin);
    }

    #[cfg(unix)]
    #[test]
    fn the_binary_moves_and_a_link_is_left_at_the_old_path() {
        let s = Scratch::new("binary");
        legacy_machine(&s);
        migrate_in(TABLE, &s.layout(), &Recorder::with(&["cortex"]));

        assert_eq!(fs::read(s.bin("fresh")).expect("moved"), b"engine-0.0.23");
        assert!(is_regular_file(&s.bin("fresh")));
        let link = fs::read_link(s.bin("cortex")).expect("the old path is a symlink");
        assert_eq!(
            link,
            PathBuf::from("fresh"),
            "relative, so the directory can move"
        );
        assert_eq!(
            fs::read(s.bin("cortex")).expect("through the link"),
            b"engine-0.0.23"
        );

        assert_eq!(
            fs::read_to_string(s.0.join("bin/fresh.version")).expect("sidecar moved"),
            "0.0.23"
        );
        assert!(!s.0.join("bin/cortex.version").exists());
    }

    #[test]
    fn the_drop_in_directory_follows_the_unit() {
        let s = Scratch::new("dropin");
        legacy_machine(&s);
        migrate_in(TABLE, &s.layout(), &Recorder::with(&["cortex"]));

        assert_eq!(
            fs::read(s.unit("crossfyre-fresh.service.d/oast.conf")).expect("moved"),
            b"[Service]\nEnvironment=OAST=1\n"
        );
        assert!(!s.unit("crossfyre-cortex.service.d").exists());
    }

    #[test]
    fn running_it_again_changes_nothing() {
        let s = Scratch::new("again");
        legacy_machine(&s);
        let units = Recorder::with(&["cortex"]);
        migrate_in(TABLE, &s.layout(), &units);
        let first = units.calls();

        let out = migrate_in(TABLE, &s.layout(), &units);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(
            units.calls(),
            first,
            "no service was touched the second time"
        );
    }

    #[test]
    fn a_machine_with_nothing_under_the_old_name_is_left_alone() {
        let s = Scratch::new("fresh");
        fs::write(s.bin("fresh"), b"engine").expect("binary");
        let units = Recorder::with(&["fresh"]);
        assert!(migrate_in(TABLE, &s.layout(), &units).is_empty());
        assert!(units.calls().is_empty());
        assert!(
            !s.bin("cortex").exists(),
            "no link is made on a fresh install"
        );
    }

    #[test]
    fn a_newer_binary_under_the_new_name_is_kept() {
        // `crossfyre extension install --force` before the migration ran: the newer
        // binary is under the public name, and the legacy copy is the stale one.
        let s = Scratch::new("both");
        legacy_machine(&s);
        fs::write(s.bin("fresh"), b"engine-0.0.24").expect("newer binary");
        fs::write(s.0.join("bin/fresh.version"), b"0.0.24").expect("newer sidecar");
        migrate_in(TABLE, &s.layout(), &Recorder::with(&["cortex", "fresh"]));

        assert_eq!(fs::read(s.bin("fresh")).expect("kept"), b"engine-0.0.24");
        assert_eq!(
            fs::read_to_string(s.0.join("bin/fresh.version")).expect("kept"),
            "0.0.24"
        );
        assert!(!s.0.join("bin/cortex.version").exists());
    }

    #[test]
    fn an_existing_drop_in_under_the_new_name_is_not_overwritten() {
        let s = Scratch::new("dropin-both");
        legacy_machine(&s);
        fs::create_dir_all(s.unit("crossfyre-fresh.service.d")).expect("new drop-in dir");
        fs::write(s.unit("crossfyre-fresh.service.d/own.conf"), b"mine").expect("own");
        let out = migrate_in(TABLE, &s.layout(), &Recorder::with(&["cortex"]));

        assert!(!out[0].dropin);
        assert_eq!(
            fs::read(s.unit("crossfyre-fresh.service.d/own.conf")).expect("kept"),
            b"mine"
        );
        assert!(
            s.unit("crossfyre-cortex.service.d/oast.conf").exists(),
            "left for a person"
        );
    }

    #[test]
    fn a_legacy_unit_left_beside_a_migrated_binary_is_replaced() {
        // The binary was moved, but the legacy unit is still registered: two units
        // for one port. The legacy one goes.
        let s = Scratch::new("unit-only");
        fs::write(s.bin("fresh"), b"engine").expect("binary");
        let units = Recorder::with(&["cortex"]);
        let out = migrate_in(TABLE, &s.layout(), &units);

        assert_eq!(out.len(), 1);
        assert!(units.position("stop cortex") < units.position("start fresh"));
        assert!(units.calls().contains(&"remove cortex".to_string()));
        assert!(!out[0].binary);
    }

    #[cfg(unix)]
    #[test]
    fn a_bin_dir_it_cannot_write_leaves_the_engine_running() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("readonly");
        legacy_machine(&s);
        let bin = s.0.join("bin");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o555)).expect("chmod");
        // Root writes anyway, and then there is nothing to prove.
        if fs::File::create(bin.join(".probe")).is_ok() {
            let _ = fs::remove_file(bin.join(".probe"));
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod");
            return;
        }
        let units = Recorder::with(&["cortex"]);
        let out = migrate_in(TABLE, &s.layout(), &units);
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod");

        assert!(out[0].skipped.is_some(), "{out:?}");
        assert!(
            units.calls().is_empty(),
            "nothing was stopped: {:?}",
            units.calls()
        );
        assert!(is_regular_file(&s.bin("cortex")));
    }
}

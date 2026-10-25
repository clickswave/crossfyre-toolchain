// Packaged mode: a crossfyre that a package manager installed.
//
// The installer puts every binary in /opt/crossfyre/bin, and from then on the CLI keeps
// them current itself. A package manager (apt, pacman, Homebrew, Nix, a container image)
// works the other way round. It owns the files it installed, and a CLI that replaced one
// of them would leave the package database describing a file that is no longer there:
// the next upgrade overwrites the newer binary, or a check of the package reports it as
// modified. So a package says what it installed, in a `packaging.json`, and every command
// that would install, update or remove one of those components leaves it to the package
// manager and carries on with the rest.
//
//   {
//     "manager": "apt",
//     "owns": ["crossfyre"],
//     "bin_dir": "/usr/lib/crossfyre/bin",
//     "cli_path": "/usr/bin/crossfyre"
//   }
//
// `manager` is one of apt, pacman, brew, nix and container. `owns` lists components by
// name: crossfyre, node, cfx-script and the engines. `bin_dir`, optional, is where node,
// cfx-script and the engines live instead of /opt/crossfyre/bin, whether the package
// installed them there or the CLI fetches them into it. `cli_path`, optional, is the path
// to name the CLI by in what outlives this run, such as a service unit, for a package
// whose binary sits at a versioned path that the next upgrade removes.
//
// The file is looked for at `<dir>/../lib/crossfyre/packaging.json`, then at
// `<dir>/packaging.json`, where <dir> is the directory of the real executable with
// symlinks resolved. It counts only when it can be trusted: a regular file owned by root
// or by whoever owns the executable, and neither it nor its directory writable by group
// or others. Whoever owns the executable can already replace it, so believing their file
// gives them nothing they did not have, and that is what lets a Linuxbrew prefix, which
// belongs to the brew user rather than to root, describe itself. A process running as
// root follows `bin_dir` and `cli_path` only from a file that root owns, because they say
// where the binaries root runs are put and found.
//
// The node worker is fetched by the CLI rather than installed beside it, so it cannot
// find the file from its own location. The node unit names the CLI that set it up in
// `CROSSFYRE_CLI`, and the node reads the file from there (`set_cli`).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The file a package installs to describe itself.
pub const FILE_NAME: &str = "packaging.json";

/// The variable the node unit sets to the CLI that wrote it.
pub const CLI_ENV: &str = "CROSSFYRE_CLI";

/// A package manager that can own Crossfyre components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Apt,
    Pacman,
    Brew,
    Nix,
    Container,
}

impl Manager {
    const ALL: [Manager; 5] = [
        Manager::Apt,
        Manager::Pacman,
        Manager::Brew,
        Manager::Nix,
        Manager::Container,
    ];

    /// The name in `packaging.json`, which is also the name a person knows it by.
    pub fn name(self) -> &'static str {
        match self {
            Manager::Apt => "apt",
            Manager::Pacman => "pacman",
            Manager::Brew => "brew",
            Manager::Nix => "nix",
            Manager::Container => "container",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == name)
    }
}

impl std::fmt::Display for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What a command says instead of updating a component a package owns.
pub fn update_note(manager: Manager) -> String {
    format!("installed by {manager}; update it with {manager}")
}

/// What a command says instead of removing a component a package owns.
pub fn remove_note(manager: Manager) -> String {
    format!("installed by {manager}; remove it with {manager}")
}

/// The components a package may own, by public name.
const COMPONENTS: [&str; 3] = ["crossfyre", "node", "cfx-script"];

/// The public name of a component a package may own, given any of its names.
fn component(name: &str) -> Option<&'static str> {
    if let Some(e) = super::engine(name) {
        return Some(e.name);
    }
    COMPONENTS.into_iter().find(|c| *c == name)
}

/// A `packaging.json` that was found and trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packaging {
    pub manager: Manager,
    owns: Vec<&'static str>,
    bin_dir: Option<PathBuf>,
    cli_path: Option<PathBuf>,
    /// Where it was read from.
    pub file: PathBuf,
    /// Root owns the file and its directory, so a root process may follow `bin_dir` and
    /// `cli_path`.
    pub root_owned: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    manager: String,
    owns: Vec<String>,
    #[serde(default)]
    bin_dir: Option<PathBuf>,
    #[serde(default)]
    cli_path: Option<PathBuf>,
}

impl Packaging {
    /// Read a `packaging.json`. Anything it does not recognise is an error rather than
    /// something to pass over: a misspelt `owns` read as owning nothing would let the CLI
    /// overwrite the package's files.
    pub fn parse(text: &str, file: PathBuf, root_owned: bool) -> Result<Self, String> {
        let raw: Raw = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let manager = Manager::parse(&raw.manager).ok_or_else(|| {
            let known: Vec<&str> = Manager::ALL.iter().map(|m| m.name()).collect();
            format!(
                "manager '{}' is not one of {}",
                raw.manager,
                known.join(", ")
            )
        })?;
        if raw.owns.is_empty() {
            return Err("owns is empty, so the package would own nothing".into());
        }
        let mut owns = Vec::new();
        for name in &raw.owns {
            let c = component(name)
                .ok_or_else(|| format!("owns names '{name}', which is not a component"))?;
            if !owns.contains(&c) {
                owns.push(c);
            }
        }
        for (field, path) in [("bin_dir", &raw.bin_dir), ("cli_path", &raw.cli_path)] {
            if let Some(p) = path
                && !p.is_absolute()
            {
                return Err(format!("{field} {} is not an absolute path", p.display()));
            }
        }
        Ok(Self {
            manager,
            owns,
            bin_dir: raw.bin_dir,
            cli_path: raw.cli_path,
            file,
            root_owned,
        })
    }

    /// Does the package own `component`, given by any of its names?
    pub fn owns(&self, component_name: &str) -> bool {
        component(component_name).is_some_and(|c| self.owns.contains(&c))
    }

    /// What the package owns, by public name, in the order the file lists them.
    pub fn owned(&self) -> &[&'static str] {
        &self.owns
    }

    /// `bin_dir`, when this process may follow it.
    pub fn bin_dir(&self) -> Option<&Path> {
        self.bin_dir.as_deref().filter(|_| self.followed_by(euid()))
    }

    /// `cli_path`, when this process may follow it.
    pub fn cli_path(&self) -> Option<&Path> {
        self.cli_path
            .as_deref()
            .filter(|_| self.followed_by(euid()))
    }

    /// May a process running as `uid` follow the paths in this file? Root follows only a
    /// file that root owns.
    fn followed_by(&self, uid: u32) -> bool {
        uid != 0 || self.root_owned
    }
}

/// What looking for a `packaging.json` came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// There is none: the installer's layout, or a build run from a checkout.
    None,
    Packaged(Packaging),
    /// There is one, and it cannot be used. Commands carry on as if there were none, and
    /// say so.
    Ignored {
        file: PathBuf,
        why: String,
    },
}

/// Where a `packaging.json` for the executable at `exe` may be, in the order they are
/// tried.
fn candidates(exe: &Path) -> Vec<PathBuf> {
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(prefix) = dir.parent() {
        out.push(prefix.join("lib").join("crossfyre").join(FILE_NAME));
    }
    out.push(dir.join(FILE_NAME));
    out
}

/// Look for the `packaging.json` that describes the executable at `exe`.
pub fn discover_from(exe: &Path) -> Found {
    let exe = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    let Some(file) = candidates(&exe)
        .into_iter()
        .find(|p| std::fs::symlink_metadata(p).is_ok())
    else {
        return Found::None;
    };
    let ignored = |why: String| Found::Ignored {
        file: file.clone(),
        why,
    };
    let root_owned = match trust(&file, &exe) {
        Ok(r) => r,
        Err(why) => return ignored(why),
    };
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => return ignored(format!("it cannot be read: {e}")),
    };
    match Packaging::parse(&text, file.clone(), root_owned) {
        Ok(p) => Found::Packaged(p),
        Err(why) => ignored(why),
    }
}

/// One path whose owner and mode decide whether a `packaging.json` is believed.
struct Checked {
    path: PathBuf,
    uid: u32,
    mode: u32,
}

/// Can the file described by `checked` be believed for an executable owned by
/// `exe_owner`? `Ok(true)` when root owns every path checked.
fn judge(checked: &[Checked], exe_owner: u32) -> Result<bool, String> {
    let mut root_owned = true;
    for c in checked {
        if c.uid != 0 && c.uid != exe_owner {
            return Err(format!(
                "{} belongs to uid {}, which is neither root nor the owner of the executable",
                c.path.display(),
                c.uid
            ));
        }
        if c.mode & 0o022 != 0 {
            return Err(format!(
                "{} is writable by group or others",
                c.path.display()
            ));
        }
        root_owned &= c.uid == 0;
    }
    Ok(root_owned)
}

/// Is the `packaging.json` at `file` one to believe for the executable at `exe`? The file
/// is checked where its symlinks lead, along with the directory that holds it there and
/// the directory that holds the name that was looked up.
#[cfg(unix)]
fn trust(file: &Path, exe: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let exe_owner = std::fs::metadata(exe)
        .map_err(|e| format!("the executable cannot be read: {e}"))?
        .uid();
    let real = std::fs::canonicalize(file).map_err(|e| format!("it cannot be resolved: {e}"))?;
    let meta = std::fs::metadata(&real).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", real.display()));
    }
    let mut checked = vec![Checked {
        path: real.clone(),
        uid: meta.uid(),
        mode: meta.mode(),
    }];
    for dir in [real.parent(), file.parent()].into_iter().flatten() {
        if checked.iter().any(|c| c.path == dir) {
            continue;
        }
        let m = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        checked.push(Checked {
            path: dir.to_path_buf(),
            uid: m.uid(),
            mode: m.mode(),
        });
    }
    judge(&checked, exe_owner)
}

#[cfg(not(unix))]
fn trust(_file: &Path, _exe: &Path) -> Result<bool, String> {
    Err("packaged mode is read on Unix only".into())
}

#[cfg(unix)]
fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn euid() -> u32 {
    u32::MAX
}

/// The CLI the node unit named, when this process is the node.
static CLI: OnceLock<PathBuf> = OnceLock::new();

/// What this process found, worked out once.
static CURRENT: OnceLock<Found> = OnceLock::new();

/// Tell this process that it belongs to the CLI at `path`: the node calls this with
/// `CROSSFYRE_CLI` before anything reads the packaging, so it uses the CLI's
/// `packaging.json` rather than looking beside its own binary. A later call is ignored.
pub fn set_cli(path: PathBuf) {
    let _ = CLI.set(path);
}

/// The CLI the node unit named, if this process was told of one.
pub fn named_cli() -> Option<&'static Path> {
    CLI.get().map(PathBuf::as_path)
}

// What a test on this thread has the process find instead. Per thread, because tests run
// side by side and most of them want none.
#[cfg(test)]
thread_local! {
    static PRETEND: std::cell::Cell<Option<&'static Found>> = const { std::cell::Cell::new(None) };
}

/// Have this thread find `found`, for a test of what a packaged install does.
#[cfg(test)]
pub(crate) fn pretend(found: Found) {
    PRETEND.with(|p| p.set(Some(Box::leak(Box::new(found)))));
}

/// What this process found: from the CLI named by `set_cli` if there is one, and
/// otherwise from the running executable. A file that is there but cannot be used is
/// reported once, on stderr.
pub fn found() -> &'static Found {
    #[cfg(test)]
    if let Some(f) = PRETEND.with(|p| p.get()) {
        return f;
    }
    CURRENT.get_or_init(|| {
        let anchor = match CLI.get() {
            Some(p) => p.clone(),
            None => match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return Found::None,
            },
        };
        let found = discover_from(&anchor);
        if let Found::Ignored { file, why } = &found {
            eprintln!("[!] ignoring {}: {why}", file.display());
        }
        found
    })
}

/// The packaging this process runs under, if a package manager installed it.
pub fn current() -> Option<&'static Packaging> {
    match found() {
        Found::Packaged(p) => Some(p),
        _ => None,
    }
}

/// The package manager that owns `component`, if one does.
pub fn owner(component_name: &str) -> Option<Manager> {
    current()
        .filter(|p| p.owns(component_name))
        .map(|p| p.manager)
}

/// The bin directory a package named, when there is one this process may follow.
pub fn bin_dir() -> Option<&'static Path> {
    current().and_then(Packaging::bin_dir)
}

/// The path to name the running CLI by, given the running executable `exe`. A packaged
/// CLI is named by `cli_path` when the package gives one this process may follow, and
/// otherwise by where it is. The installer's CLI is not named here: it is copied to the
/// bin directory first, and named by that copy.
pub fn cli_path_for(exe: &Path) -> PathBuf {
    current()
        .and_then(Packaging::cli_path)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| exe.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parse(json: &str) -> Result<Packaging, String> {
        Packaging::parse(
            json,
            PathBuf::from("/usr/lib/crossfyre/packaging.json"),
            true,
        )
    }

    #[test]
    fn an_apt_package_owns_the_cli_and_nothing_else() {
        let p = parse(r#"{"manager":"apt","owns":["crossfyre"]}"#).expect("parses");
        assert_eq!(p.manager, Manager::Apt);
        assert!(p.owns("crossfyre"));
        assert!(!p.owns("node"));
        assert!(!p.owns("plessor"));
        assert_eq!(p.bin_dir(), None);
    }

    #[test]
    fn a_package_that_owns_everything_names_its_bin_dir() {
        let p = parse(
            r#"{"manager":"nix","owns":["crossfyre","node","cfx-script","ambulo","voyage",
                "doorward","toolmark","plessor"],"bin_dir":"/nix/store/x-crossfyre/libexec",
                "cli_path":"/run/current-system/sw/bin/crossfyre"}"#,
        )
        .expect("parses");
        for c in ["crossfyre", "node", "cfx-script", "ambulo", "plessor"] {
            assert!(p.owns(c), "{c}");
        }
        // An engine is owned by every name it answers to.
        assert!(p.owns("cortex") && p.owns("mach"));
        assert_eq!(
            p.bin_dir(),
            Some(Path::new("/nix/store/x-crossfyre/libexec"))
        );
        assert_eq!(
            p.cli_path(),
            Some(Path::new("/run/current-system/sw/bin/crossfyre"))
        );
    }

    #[test]
    fn an_engine_listed_by_an_old_name_is_kept_under_its_public_one() {
        let p = parse(r#"{"manager":"container","owns":["cortex","plessor"]}"#).expect("parses");
        assert_eq!(p.owned(), ["plessor"]);
    }

    #[test]
    fn a_file_it_cannot_make_sense_of_is_refused() {
        for (json, said) in [
            (r#"{"manager":"snap","owns":["crossfyre"]}"#, "not one of"),
            (r#"{"manager":"apt","owns":[]}"#, "owns is empty"),
            (
                r#"{"manager":"apt","owns":["crossfyre","nodejs"]}"#,
                "'nodejs'",
            ),
            (r#"{"manager":"apt"}"#, "owns"),
            (
                r#"{"manager":"apt","owns":["crossfyre"],"bin_dir":"lib/bin"}"#,
                "not an absolute path",
            ),
            (
                r#"{"manager":"apt","owns":["crossfyre"],"cli_path":"crossfyre"}"#,
                "not an absolute path",
            ),
            // A misspelt field is not silently dropped.
            (r#"{"manager":"apt","own":["crossfyre"]}"#, "own"),
            ("manager = apt", "expected"),
        ] {
            let err = parse(json).expect_err(json);
            assert!(err.contains(said), "{json}: {err}");
        }
    }

    #[test]
    fn root_follows_paths_only_from_a_file_root_owns() {
        let json = r#"{"manager":"brew","owns":["crossfyre"],"bin_dir":"/home/linuxbrew/b"}"#;
        let file = PathBuf::from("/home/linuxbrew/.linuxbrew/lib/crossfyre/packaging.json");
        let brew = Packaging::parse(json, file.clone(), false).expect("parses");
        assert!(brew.followed_by(1000), "the brew user follows its own file");
        assert!(
            !brew.followed_by(0),
            "root does not follow a file another user owns"
        );
        let system = Packaging::parse(json, file, true).expect("parses");
        assert!(system.followed_by(0));
    }

    fn checked(path: &str, uid: u32, mode: u32) -> Checked {
        Checked {
            path: PathBuf::from(path),
            uid,
            mode,
        }
    }

    #[test]
    fn a_file_belonging_to_the_owner_of_the_executable_is_believed() {
        // A Linuxbrew prefix belongs to the brew user, and so does the CLI in it.
        let ok = judge(
            &[
                checked(
                    "/home/linuxbrew/c/lib/crossfyre/packaging.json",
                    1000,
                    0o100644,
                ),
                checked("/home/linuxbrew/c/lib/crossfyre", 1000, 0o40755),
            ],
            1000,
        );
        assert_eq!(ok, Ok(false), "believed, and not owned by root");
        let system = judge(
            &[
                checked("/usr/lib/crossfyre/packaging.json", 0, 0o100644),
                checked("/usr/lib/crossfyre", 0, 0o40755),
            ],
            0,
        );
        assert_eq!(system, Ok(true));
    }

    #[test]
    fn a_file_others_could_have_written_is_not_believed() {
        for (c, said) in [
            (
                checked("/p/packaging.json", 0, 0o100666),
                "writable by group or others",
            ),
            (
                checked("/p/packaging.json", 0, 0o100664),
                "writable by group or others",
            ),
            (checked("/p/packaging.json", 1001, 0o100644), "uid 1001"),
        ] {
            let err = judge(&[c, checked("/p", 0, 0o40755)], 1000).expect_err(said);
            assert!(err.contains(said), "{err}");
        }
        // The directory counts as much as the file: whoever can write it can replace it.
        let err = judge(
            &[
                checked("/tmp/packaging.json", 1000, 0o100644),
                checked("/tmp", 0, 0o41777),
            ],
            1000,
        )
        .expect_err("a world-writable directory");
        assert!(err.contains("/tmp is writable"), "{err}");
    }

    /// A prefix laid out as a package lays it out, under a scratch directory.
    #[cfg(unix)]
    struct Prefix {
        dir: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl Prefix {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().expect("scratch"),
            }
        }
        fn path(&self, rel: &str) -> PathBuf {
            self.dir.path().join(rel)
        }
        /// Write `rel` with `mode`, creating its directories 0755.
        fn file(&self, rel: &str, body: &str, mode: u32) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;
            let p = self.path(rel);
            let mut dir = p.parent().expect("parent").to_path_buf();
            fs::create_dir_all(&dir).expect("dirs");
            while dir != self.dir.path() {
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
                dir = dir.parent().expect("parent").to_path_buf();
            }
            fs::write(&p, body).expect("write");
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).expect("chmod");
            p
        }
    }

    #[cfg(unix)]
    const APT: &str = r#"{"manager":"apt","owns":["crossfyre"]}"#;

    #[cfg(unix)]
    #[test]
    fn a_cli_in_usr_bin_finds_the_file_in_usr_lib() {
        let p = Prefix::new();
        let exe = p.file("usr/bin/crossfyre", "binary", 0o755);
        let file = p.file("usr/lib/crossfyre/packaging.json", APT, 0o644);
        match discover_from(&exe) {
            Found::Packaged(pkg) => {
                assert_eq!(pkg.manager, Manager::Apt);
                // The file is found from the executable's real path, and the scratch
                // directory may be reached through a symlink: /var is /private/var
                // on macOS.
                assert_eq!(
                    fs::canonicalize(&pkg.file).expect("found file"),
                    fs::canonicalize(&file).expect("written file")
                );
                assert!(pkg.owns("crossfyre"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_beside_the_binary_is_found_when_there_is_none_in_lib() {
        // The container image keeps everything in /opt/crossfyre/bin.
        let p = Prefix::new();
        let exe = p.file("opt/crossfyre/bin/crossfyre", "binary", 0o755);
        p.file(
            "opt/crossfyre/bin/packaging.json",
            r#"{"manager":"container","owns":["crossfyre","node"]}"#,
            0o644,
        );
        assert!(matches!(discover_from(&exe), Found::Packaged(pkg) if pkg.owns("node")));
    }

    #[cfg(unix)]
    #[test]
    fn the_executable_is_found_through_a_symlink() {
        // Homebrew links bin/crossfyre to the Cellar, and the file sits beside the
        // real binary rather than beside the link.
        let p = Prefix::new();
        let exe = p.file("Cellar/crossfyre/0.1.33/libexec/crossfyre", "binary", 0o755);
        p.file(
            "Cellar/crossfyre/0.1.33/lib/crossfyre/packaging.json",
            r#"{"manager":"brew","owns":["crossfyre"]}"#,
            0o644,
        );
        fs::create_dir_all(p.path("bin")).expect("bin");
        let link = p.path("bin/crossfyre");
        std::os::unix::fs::symlink(&exe, &link).expect("link");
        // Owned by whoever runs the test, which is root only in a container.
        assert!(matches!(
            discover_from(&link),
            Found::Packaged(pkg) if pkg.manager == Manager::Brew && pkg.root_owned == (euid() == 0)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_world_writable_file_is_ignored() {
        let p = Prefix::new();
        let exe = p.file("usr/bin/crossfyre", "binary", 0o755);
        p.file("usr/lib/crossfyre/packaging.json", APT, 0o666);
        match discover_from(&exe) {
            Found::Ignored { why, .. } => assert!(why.contains("writable"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_in_a_group_writable_directory_is_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let p = Prefix::new();
        let exe = p.file("usr/bin/crossfyre", "binary", 0o755);
        p.file("usr/lib/crossfyre/packaging.json", APT, 0o644);
        fs::set_permissions(
            p.path("usr/lib/crossfyre"),
            fs::Permissions::from_mode(0o775),
        )
        .expect("chmod");
        assert!(matches!(discover_from(&exe), Found::Ignored { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_it_cannot_parse_is_ignored_and_says_why() {
        let p = Prefix::new();
        let exe = p.file("usr/bin/crossfyre", "binary", 0o755);
        p.file(
            "usr/lib/crossfyre/packaging.json",
            r#"{"manager":"apt","owns":["nodejs"]}"#,
            0o644,
        );
        match discover_from(&exe) {
            Found::Ignored { why, .. } => assert!(why.contains("nodejs"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_installer_layout_has_no_packaging() {
        let p = Prefix::new();
        let exe = p.file("opt/crossfyre/bin/crossfyre", "binary", 0o755);
        assert_eq!(discover_from(&exe), Found::None);
    }

    #[test]
    fn the_notes_name_the_manager_twice() {
        assert_eq!(
            update_note(Manager::Apt),
            "installed by apt; update it with apt"
        );
        assert_eq!(
            remove_note(Manager::Pacman),
            "installed by pacman; remove it with pacman"
        );
    }
}

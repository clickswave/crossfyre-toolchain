//! The local backend: a PostgreSQL cluster in the toolchain directory, made and run
//! with the PostgreSQL programs installed on this machine, which nothing here downloads.

use crate::NotReady;
use crate::account::Account;
use crate::settings::{LOOPBACK, Settings};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The cluster's directory, in the toolchain directory.
pub(crate) const DATA_DIR: &str = "postgres";

/// The server's log, in the cluster's directory.
const LOG_FILE: &str = "server.log";

/// What a cluster is made and run with.
const PROGRAMS: [&str; 3] = ["initdb", "pg_ctl", "postgres"];

/// How long `pg_ctl` waits for the server to start or stop.
const PG_CTL_WAIT: &str = "60";

/// The transient unit the server in `data` runs in where the user's service manager
/// runs. Started by an engine, it would otherwise run in that engine's unit, and
/// stopping or restarting the engine would stop it for every engine. It is named after
/// the data directory, so that two clusters of one user never claim the same unit.
fn scope(data: &std::path::Path) -> String {
    // FNV-1a over the path: a stable name, not a secret.
    let hash = data
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .fold(0x811c_9dc5_u32, |h, b| {
            (h ^ u32::from(*b)).wrapping_mul(0x0100_0193)
        });
    format!("crossfyre-postgres-{hash:08x}")
}

/// PostgreSQL's programs, as found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Postgres {
    /// The directory that holds initdb, pg_ctl and postgres.
    pub dir: PathBuf,
    /// Their major version, such as 17.
    pub major: u32,
}

impl Postgres {
    fn program(&self, name: &str) -> PathBuf {
        self.dir.join(exe(name))
    }
}

/// `name` as a file name on this OS.
fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// PostgreSQL's programs here: the newest, or with `major` the ones of that version, which
/// a cluster made by it needs.
pub fn find_postgres(account: &dyn Account, major: Option<u32>) -> Result<Postgres, NotReady> {
    let dirs = candidates(std::env::var_os("PATH").as_deref());
    find_in(account, dirs, major).map_err(|other| {
        let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        match major {
            Some(want) if !other.is_empty() => {
                let found: Vec<String> = other.iter().map(u32::to_string).collect();
                NotReady::new(
                    format!(
                        "the local database was made by PostgreSQL {want}, and this machine \
                         has the programs of PostgreSQL {} only",
                        found.join(", ")
                    ),
                    install_command(&os_release, Some(want)).as_deref(),
                )
            }
            _ => not_installed(&os_release),
        }
    })
}

/// The first of `dirs` that holds all three programs, of version `major` when it is given.
/// Otherwise the other versions found, newest first.
fn find_in(
    account: &dyn Account,
    dirs: Vec<PathBuf>,
    major: Option<u32>,
) -> Result<Postgres, Vec<u32>> {
    let mut other = Vec::new();
    for dir in dirs {
        if !PROGRAMS.iter().all(|p| dir.join(exe(p)).is_file()) {
            continue;
        }
        let Some(found) = version_in(account, &dir) else {
            continue;
        };
        match major {
            Some(want) if want != found => {
                if !other.contains(&found) {
                    other.push(found);
                }
            }
            _ => return Ok(Postgres { dir, major: found }),
        }
    }
    other.sort_by(|a, b| b.cmp(a));
    Err(other)
}

/// The message for a machine without PostgreSQL's programs.
fn not_installed(os_release: &str) -> NotReady {
    let looked = if cfg!(target_os = "linux") {
        "on PATH or in /usr/lib/postgresql/*/bin"
    } else if cfg!(target_os = "macos") {
        "on PATH or in Homebrew's postgresql folders"
    } else if cfg!(windows) {
        "on PATH or in the PostgreSQL folder in Program Files"
    } else {
        "on PATH"
    };
    let problem = format!(
        "PostgreSQL is not installed here: nothing {looked} holds initdb, pg_ctl and postgres"
    );
    let instead = "point crossfyre at a database you run yourself with \
                   `crossfyre db external HOST PORT USER`";
    match install_command(os_release, None) {
        Some(install) => NotReady::new(problem, Some(&install)).or(instead),
        None => NotReady::new(
            format!(
                "{problem}. Install its server package with this system's package manager, \
                 or {instead}"
            ),
            None,
        ),
    }
}

/// The command that installs PostgreSQL's programs on this machine, of version `major`
/// when it is given, as the `os_release` of a Linux system names it.
fn install_command(os_release: &str, major: Option<u32>) -> Option<String> {
    if cfg!(target_os = "macos") {
        return Some(format!("brew install postgresql@{}", major.unwrap_or(17)));
    }
    if cfg!(windows) {
        return Some(format!(
            "winget install PostgreSQL.PostgreSQL.{}",
            major.unwrap_or(17)
        ));
    }
    if !cfg!(target_os = "linux") {
        return None;
    }
    linux_install_command(os_release, major)
}

/// [`install_command`] for the Linux system `os_release` describes.
fn linux_install_command(os_release: &str, major: Option<u32>) -> Option<String> {
    let value = |key: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_ascii_lowercase())
            .unwrap_or_default()
    };
    let (id, like) = (value("ID"), value("ID_LIKE"));
    let family: Vec<&str> = std::iter::once(id.as_str())
        .chain(like.split_whitespace())
        .collect();
    let is = |names: &[&str]| family.iter().any(|f| names.contains(f));
    if is(&["debian", "ubuntu"]) {
        return Some(match major {
            Some(m) => format!("sudo apt install postgresql-{m}"),
            None => "sudo apt install postgresql".to_string(),
        });
    }
    // The distributions below package one version at a time.
    if major.is_some() {
        return None;
    }
    if is(&["fedora", "rhel", "centos"]) {
        Some("sudo dnf install postgresql-server".to_string())
    } else if is(&["arch"]) {
        Some("sudo pacman -S postgresql".to_string())
    } else if is(&["suse", "opensuse"]) {
        Some("sudo zypper install postgresql-server".to_string())
    } else if is(&["alpine"]) {
        Some("sudo apk add postgresql".to_string())
    } else {
        None
    }
}

/// Directories that may hold PostgreSQL's programs, in the order they are tried: PATH,
/// then where Debian's packages put each version, then Homebrew's, then the PostgreSQL
/// installer's on Windows. Within each, the newest version comes first.
fn candidates(path_var: Option<&OsStr>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = path_var
        .map(|p| std::env::split_paths(p).collect())
        .unwrap_or_default();
    if cfg!(target_os = "linux") {
        dirs.extend(
            versions(Path::new("/usr/lib/postgresql"), |name| name.parse().ok())
                .into_iter()
                .map(|v| v.join("bin")),
        );
    }
    if cfg!(target_os = "macos") {
        for prefix in ["/opt/homebrew/opt", "/usr/local/opt"] {
            dirs.extend(
                versions(Path::new(prefix), homebrew_version)
                    .into_iter()
                    .map(|v| v.join("bin")),
            );
        }
    }
    if cfg!(windows) {
        let program_files =
            std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
        let root = PathBuf::from(program_files).join("PostgreSQL");
        dirs.extend(
            versions(&root, |name| name.parse().ok())
                .into_iter()
                .map(|v| v.join("bin")),
        );
    }
    dirs
}

/// The version of a Homebrew folder named `postgresql@17`, or 0 for `postgresql`, the
/// one that follows Homebrew's newest.
fn homebrew_version(name: &str) -> Option<u32> {
    match name.strip_prefix("postgresql")? {
        "" => Some(0),
        v => v.strip_prefix('@')?.parse().ok(),
    }
}

/// The directories in `root` that `version` reads a version from, newest first. An
/// unversioned one reads as 0 and so comes last.
fn versions(root: &Path, version: impl Fn(&str) -> Option<u32>) -> Vec<PathBuf> {
    let mut found: Vec<(u32, PathBuf)> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let v = version(entry.file_name().to_str()?)?;
            Some((v, entry.path()))
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found.into_iter().map(|(_, dir)| dir).collect()
}

/// The major version of the programs in `dir`, from what `pg_ctl --version` says, such
/// as "pg_ctl (PostgreSQL) 17.6 (Debian 17.6-1)".
fn version_in(account: &dyn Account, dir: &Path) -> Option<u32> {
    let out = account
        .command(&dir.join(exe("pg_ctl")))
        .arg("--version")
        .output()
        .ok()?;
    major_of(&String::from_utf8_lossy(&out.stdout))
}

fn major_of(version: &str) -> Option<u32> {
    let number = version.split("(PostgreSQL)").nth(1)?.trim_start();
    let digits: String = number.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Whether something answers on 127.0.0.1:`port`.
pub(crate) fn answers(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

/// The message for a port the local database cannot have.
pub(crate) fn port_taken(port: u16) -> NotReady {
    NotReady::new(
        format!(
            "something else is listening on {LOOPBACK}:{port}, the port config.toml gives the \
             local database. The likely cause is the crossfyre-postgres container an earlier \
             version made"
        ),
        Some("docker rm -f crossfyre-postgres"),
    )
}

/// The cluster in the toolchain directory.
pub(crate) struct Cluster {
    data: PathBuf,
}

impl Cluster {
    pub(crate) fn in_toolchain(dir: &Path) -> Self {
        Self {
            data: dir.join(DATA_DIR),
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.data
    }

    /// Whether the cluster has been made.
    pub(crate) fn exists(&self) -> bool {
        self.data.join("PG_VERSION").is_file()
    }

    /// The major version of PostgreSQL that made the cluster.
    pub(crate) fn major(&self, account: &dyn Account) -> Option<u32> {
        account
            .read_to_string(&self.data.join("PG_VERSION"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Whether its server's pid file is there, which a server keeps for as long as it runs.
    pub(crate) fn has_pid_file(&self) -> bool {
        self.data.join("postmaster.pid").is_file()
    }

    /// Whether its server says it runs: its pid file is there, and its port answers.
    pub(crate) fn seems_running(&self, port: u16) -> bool {
        self.has_pid_file() && answers(port)
    }

    /// Make the cluster, with `settings`' user as its superuser and their password the
    /// one it asks for, over TCP and on its own socket alike.
    pub(crate) fn make(
        &self,
        pg: &Postgres,
        settings: &Settings,
        account: &dyn Account,
    ) -> Result<(), NotReady> {
        if std::fs::read_dir(&self.data).is_ok_and(|mut d| d.next().is_some()) {
            return Err(NotReady::new(
                format!(
                    "{} is there but holds no database. Move it aside, and the next \
                     `crossfyre db up` makes one",
                    self.data.display()
                ),
                None,
            ));
        }
        let password = settings.password.as_deref().unwrap_or_default();
        let pwfile = self
            .data
            .with_file_name(format!(".{DATA_DIR}-password-{}", std::process::id()));
        account
            .write_private(&pwfile, password.as_bytes())
            .map_err(|e| NotReady::new(format!("cannot write {}: {e}", pwfile.display()), None))?;
        let made = account
            .command(&pg.program("initdb"))
            .arg("-D")
            .arg(&self.data)
            .args(["-U", &settings.user])
            .arg(format!("--pwfile={}", pwfile.display()))
            .args(["--auth=scram-sha-256", "--encoding=UTF8", "--no-locale"])
            .output();
        let _ = account.remove_file(&pwfile);
        let out = made.map_err(|e| not_run("initdb", pg, &e))?;
        if !out.status.success() {
            return Err(NotReady::new(
                format!(
                    "making the local database in {} failed: {}",
                    self.data.display(),
                    last_words(&out.stderr)
                ),
                None,
            ));
        }
        Ok(())
    }

    /// Whether its server runs, as `pg_ctl status` says.
    pub(crate) fn running(&self, pg: &Postgres, account: &dyn Account) -> Result<bool, NotReady> {
        let out = account
            .command(&pg.program("pg_ctl"))
            .arg("status")
            .arg("-D")
            .arg(&self.data)
            .output()
            .map_err(|e| not_run("pg_ctl", pg, &e))?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(3) => Ok(false),
            _ => Err(NotReady::new(
                format!(
                    "pg_ctl could not tell whether the local database in {} runs: {}",
                    self.data.display(),
                    last_words(&out.stderr)
                ),
                None,
            )),
        }
    }

    /// Start its server on 127.0.0.1:`port`, and nowhere else.
    pub(crate) fn start(
        &self,
        pg: &Postgres,
        port: u16,
        account: &dyn Account,
    ) -> Result<(), NotReady> {
        if answers(port) {
            return Err(port_taken(port));
        }
        let log = self.data.join(LOG_FILE);
        // Its own socket is turned off where it would go in a folder of root's, as
        // Debian's servers have it, and everything else reaches it over TCP. Windows
        // makes none to begin with.
        let mut options = format!("-h {LOOPBACK} -p {port}");
        if cfg!(unix) {
            options.push_str(" -k ''");
        }
        let mut cmd = match scope_runner(account) {
            Some(systemd_run) => {
                let mut cmd = account.command(&systemd_run);
                cmd.args(["--user", "--scope", "--quiet", "--collect"])
                    .arg(format!("--unit={}", scope(&self.data)))
                    .arg("--")
                    .arg(pg.program("pg_ctl"));
                cmd
            }
            None => account.command(&pg.program("pg_ctl")),
        };
        cmd.args(["start", "-w", "-t", PG_CTL_WAIT, "-D"])
            .arg(&self.data)
            .arg("-l")
            .arg(&log)
            .arg("-o")
            .arg(options);
        let started = if cfg!(windows) {
            // pg_ctl hands the server what it inherited on Windows, so a pipe given to it
            // would stay open until the server stopped. What went wrong is in the log.
            cmd.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| (status, Vec::new()))
        } else {
            cmd.output().map(|out| (out.status, out.stderr))
        };
        let (status, stderr) = started.map_err(|e| not_run("pg_ctl", pg, &e))?;
        if status.success() {
            return Ok(());
        }
        let said = std::fs::read(&log).unwrap_or_default();
        let said = String::from_utf8_lossy(&said);
        if said.contains("could not bind") || said.contains("Address already in use") {
            return Err(port_taken(port));
        }
        let why = match last_words(said.as_bytes()) {
            w if w.is_empty() => last_words(&stderr),
            w => w,
        };
        Err(NotReady::new(
            format!(
                "the local database in {} did not start: {why} (its log is {})",
                self.data.display(),
                log.display()
            ),
            None,
        ))
    }

    /// Stop its server, and say whether it ran.
    pub(crate) fn stop(&self, pg: &Postgres, account: &dyn Account) -> Result<bool, NotReady> {
        if !self.running(pg, account)? {
            return Ok(false);
        }
        let out = account
            .command(&pg.program("pg_ctl"))
            .args(["stop", "-m", "fast", "-w", "-t", PG_CTL_WAIT, "-D"])
            .arg(&self.data)
            .output()
            .map_err(|e| not_run("pg_ctl", pg, &e))?;
        if !out.status.success() {
            return Err(NotReady::new(
                format!(
                    "the local database in {} did not stop: {}",
                    self.data.display(),
                    last_words(&out.stderr)
                ),
                None,
            ));
        }
        Ok(true)
    }
}

/// `systemd-run`, to run the server in a scope of its own, when the account's service
/// manager answers on its bus. Elsewhere, as in a container or on macOS and Windows,
/// the server is left to `pg_ctl`, which detaches it from whoever started it.
fn scope_runner(account: &dyn Account) -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    if !account.runtime_dir()?.join("bus").exists() {
        return None;
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()))
        .map(|d| d.join("systemd-run"))
        .find(|p| p.is_file())
}

fn not_run(program: &str, pg: &Postgres, e: &std::io::Error) -> NotReady {
    NotReady::new(
        format!("could not run {}: {e}", pg.dir.join(exe(program)).display()),
        None,
    )
}

/// The last few lines a program wrote, on one line.
fn last_words(text: &[u8]) -> String {
    let text = String::from_utf8_lossy(text);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines[lines.len().saturating_sub(3)..].join(" / ")
}

#[cfg(test)]
mod tests {
    #[test]
    fn each_cluster_has_a_scope_of_its_own() {
        let one = super::scope(std::path::Path::new("/home/a/.config/crossfyre/postgres"));
        assert_eq!(
            one,
            super::scope(std::path::Path::new("/home/a/.config/crossfyre/postgres"))
        );
        assert_ne!(
            one,
            super::scope(std::path::Path::new("/tmp/t/crossfyre/postgres"))
        );
        assert!(
            one.starts_with("crossfyre-postgres-") && one.len() == "crossfyre-postgres-".len() + 8
        );
    }

    use super::*;

    const DEBIAN: &str = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n";
    const KALI: &str = "ID=kali\nID_LIKE=debian\nVERSION_ID=\"2026.3\"\n";
    const UBUNTU: &str = "ID=ubuntu\nID_LIKE=debian\n";
    const ALMA: &str = "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n";
    const ARCH: &str = "ID=arch\n";

    #[test]
    fn the_package_is_named_for_the_distribution() {
        let cmd = |os: &str| linux_install_command(os, None);
        for os in [DEBIAN, KALI, UBUNTU] {
            assert_eq!(
                cmd(os).as_deref(),
                Some("sudo apt install postgresql"),
                "{os}"
            );
        }
        assert_eq!(
            cmd(ALMA).as_deref(),
            Some("sudo dnf install postgresql-server")
        );
        assert_eq!(cmd(ARCH).as_deref(), Some("sudo pacman -S postgresql"));
        assert_eq!(cmd("ID=plan9\n"), None);
    }

    #[test]
    fn a_version_is_named_where_the_distribution_packages_each_one() {
        assert_eq!(
            linux_install_command(KALI, Some(17)).as_deref(),
            Some("sudo apt install postgresql-17")
        );
        assert_eq!(linux_install_command(ALMA, Some(17)), None);
    }

    #[test]
    fn the_version_is_read_from_what_pg_ctl_says() {
        assert_eq!(
            major_of("pg_ctl (PostgreSQL) 17.6 (Debian 17.6-1)\n"),
            Some(17)
        );
        assert_eq!(major_of("pg_ctl (PostgreSQL) 18.6\n"), Some(18));
        assert_eq!(major_of("pg_ctl (PostgreSQL) 19devel\n"), Some(19));
        assert_eq!(major_of("something else\n"), None);
    }

    #[test]
    fn the_last_lines_are_kept_on_one_line() {
        assert_eq!(last_words(b"a\n\nb\nc\nd\n"), "b / c / d");
        assert_eq!(last_words(b""), "");
    }

    #[cfg(unix)]
    mod with_programs {
        use super::super::*;
        use crate::account::ThisAccount;
        use std::os::unix::fs::PermissionsExt;

        /// A directory with stand-ins for PostgreSQL's programs, where pg_ctl says it is
        /// version `major`.
        fn programs(root: &Path, name: &str, major: u32) -> PathBuf {
            let dir = root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            for p in PROGRAMS {
                let script = dir.join(p);
                std::fs::write(
                    &script,
                    format!("#!/bin/sh\necho \"{p} (PostgreSQL) {major}.1\"\n"),
                )
                .unwrap();
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
                runs(&script);
            }
            dir
        }

        /// Wait until `program` runs. A child another test's thread was starting while it
        /// was written holds a copy of the handle that wrote it until that child runs its
        /// own program, and until then running this one fails as busy (ETXTBSY).
        fn runs(program: &Path) {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                match std::process::Command::new(program).output() {
                    Ok(_) => return,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{} does not run: {e}", program.display()),
                }
            }
        }

        fn found_on(path: &[&Path], major: Option<u32>) -> Result<Postgres, Vec<u32>> {
            let dirs = path.iter().map(|d| d.to_path_buf()).collect();
            find_in(&ThisAccount::new().unwrap(), dirs, major)
        }

        #[test]
        fn the_first_folder_with_all_three_programs_is_used() {
            let root = tempfile::tempdir().unwrap();
            // Its pg_ctl answers, so only the check for all three programs skips it.
            let partial = programs(root.path(), "partial", 18);
            std::fs::remove_file(partial.join("initdb")).unwrap();
            let whole = programs(root.path(), "whole", 17);
            let found = found_on(&[&partial, &whole], None).unwrap();
            assert_eq!(
                found,
                Postgres {
                    dir: whole,
                    major: 17
                }
            );
        }

        #[test]
        fn a_cluster_gets_the_programs_of_the_version_that_made_it() {
            let root = tempfile::tempdir().unwrap();
            let new = programs(root.path(), "18", 18);
            let old = programs(root.path(), "17", 17);
            assert_eq!(found_on(&[&new, &old], None).unwrap().major, 18);
            assert_eq!(found_on(&[&new, &old], Some(17)).unwrap().dir, old);
            assert_eq!(found_on(&[&new], Some(17)), Err(vec![18]));
        }

        #[test]
        fn versioned_folders_are_tried_newest_first() {
            let root = tempfile::tempdir().unwrap();
            for v in ["9", "17", "16", "notes"] {
                std::fs::create_dir_all(root.path().join(v)).unwrap();
            }
            let order: Vec<String> = versions(root.path(), |n| n.parse().ok())
                .iter()
                .map(|d| d.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            assert_eq!(order, ["17", "16", "9"]);
        }

        #[test]
        fn homebrew_s_unversioned_postgresql_comes_after_its_versioned_ones() {
            let root = tempfile::tempdir().unwrap();
            for v in [
                "postgresql",
                "postgresql@16",
                "postgresql@17",
                "python@3.12",
            ] {
                std::fs::create_dir_all(root.path().join(v)).unwrap();
            }
            let order: Vec<String> = versions(root.path(), homebrew_version)
                .iter()
                .map(|d| d.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            assert_eq!(order, ["postgresql@17", "postgresql@16", "postgresql"]);
        }

        #[test]
        fn a_port_something_else_holds_is_said_with_the_likely_cause() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let root = tempfile::tempdir().unwrap();
            let pg = Postgres {
                dir: programs(root.path(), "bin", 17),
                major: 17,
            };
            let cluster = Cluster::in_toolchain(root.path());
            let e = cluster
                .start(&pg, port, &ThisAccount::new().unwrap())
                .unwrap_err();
            assert_eq!(
                e.problem(),
                format!(
                    "something else is listening on 127.0.0.1:{port}, the port config.toml \
                     gives the local database. The likely cause is the crossfyre-postgres \
                     container an earlier version made"
                )
            );
            assert_eq!(e.fix(), Some("docker rm -f crossfyre-postgres"));
        }

        #[test]
        fn a_folder_that_holds_something_else_is_not_made_into_a_database() {
            let root = tempfile::tempdir().unwrap();
            let cluster = Cluster::in_toolchain(root.path());
            std::fs::create_dir_all(cluster.dir()).unwrap();
            std::fs::write(cluster.dir().join("notes.txt"), "mine").unwrap();
            let pg = Postgres {
                dir: programs(root.path(), "bin", 17),
                major: 17,
            };
            let e = cluster
                .make(&pg, &Settings::default(), &ThisAccount::new().unwrap())
                .unwrap_err();
            assert!(
                e.problem().contains("is there but holds no database"),
                "{e}"
            );
            assert_eq!(
                std::fs::read_to_string(cluster.dir().join("notes.txt")).unwrap(),
                "mine"
            );
        }
    }
}

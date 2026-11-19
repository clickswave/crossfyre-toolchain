// `crossfyre db`: the database the engines keep their state in. By default it is the
// local one, a PostgreSQL cluster in the toolchain directory that belongs to the user the
// engines run as; otherwise it is a server the user runs, recorded with
// `crossfyre db external`. cfx_db does the work. This is the commands, and the account
// they act as, which as root is the user crossfyre was run for, never root itself.

use super::config::{get_toolchain_dir, load_config, load_or_create_config_at, save_config_at};
use super::sudo_user;
use cfx_db::{Account, Backend, Settings, Stop, Toolchain, Up};

/// The variable `crossfyre db external` reads the password from, in place of asking.
pub const PASSWORD_ENV: &str = "CROSSFYRE_DB_PASSWORD";

/// `crossfyre db <command>`.
pub async fn run(command: &crate::DbCommands) -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::{ok, warn};
    match command {
        crate::DbCommands::Up => {
            let back = use_local_in(&get_toolchain_dir())?;
            match back {
                Back::Already => {}
                Back::Kept => {
                    ok("config.toml names the local database again, with the settings it had.")
                }
                Back::New => ok("config.toml names the local database now."),
            }
            let (settings, up) = with_toolchain(|t| t.up())?;
            say_up(&settings, up);
            if back != Back::Already {
                restart_engines();
            }
        }
        crate::DbCommands::Stop => match with_toolchain(|t| t.stop())? {
            Stop::Stopped => ok("Stopped the local database."),
            Stop::NotRunning => warn("The local database was not running."),
            Stop::NotMade => warn("There is no local database yet. `crossfyre db up` makes one."),
            Stop::External => warn(&format!(
                "Nothing to stop: config.toml names the database you run at {}.",
                load_config()?.postgres.address()
            )),
        },
        crate::DbCommands::Restart => {
            let (settings, up) = restart()?;
            say_up(&settings, up);
            if up == Up::External {
                check_external(&settings).await?;
            }
        }
        crate::DbCommands::Status => super::status::db()?,
        crate::DbCommands::External { host, port, user } => {
            external(host, *port, user).await?;
        }
    }
    Ok(())
}

/// Make the local database when it is missing and start it when it is stopped, as
/// `crossfyre db up` does, for `node init` and the dashboard's start action.
pub fn up() -> Result<Up, Box<dyn std::error::Error>> {
    Ok(with_toolchain(|t| t.up())?.1)
}

/// Stop the local database and start it again, on the port config.toml gives it now.
pub fn restart() -> Result<(Settings, Up), Box<dyn std::error::Error>> {
    with_toolchain(|t| {
        t.stop()?;
        t.up()
    })
}

/// What config.toml names and whether it runs, for `crossfyre status`, `db status` and
/// `doctor`. None without a config.toml.
pub fn status() -> Result<Option<cfx_db::Status>, Box<dyn std::error::Error>> {
    with_toolchain(|t| t.status())
}

/// Stop the local database and remove it with its data, for `crossfyre uninstall`. Says
/// where it was, or None when there was none.
pub fn remove_local() -> Result<Option<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let account = account()?;
    let toolchain = Toolchain::new(get_toolchain_dir(), account.as_ref());
    let dir = toolchain.cluster_dir();
    if !dir.exists() {
        return Ok(None);
    }
    if let Err(e) = toolchain.stop() {
        // Removing its files from under a server that still runs is how a database is
        // lost half way, so it is left as it is.
        return Err(format!("the local database did not stop, so it is kept: {e}").into());
    }
    sudo_user::remove_dir_all(&dir)?;
    Ok(Some(dir))
}

/// `f` on the toolchain directory, acted on as the account the database belongs to.
fn with_toolchain<T>(
    f: impl FnOnce(&Toolchain) -> Result<T, cfx_db::NotReady>,
) -> Result<T, Box<dyn std::error::Error>> {
    let account = account()?;
    let toolchain = Toolchain::new(get_toolchain_dir(), account.as_ref());
    Ok(f(&toolchain)?)
}

fn say_up(settings: &Settings, up: Up) {
    use super::ui::ok;
    let at = settings.address();
    match up {
        Up::Made => ok(&format!(
            "Made the local database in {} and started it on {at}.",
            get_toolchain_dir().join("postgres").display()
        )),
        Up::Started => ok(&format!("Started the local database on {at}.")),
        Up::Running => ok(&format!("The local database is running on {at}.")),
        Up::External => ok(&format!(
            "config.toml names the database you run at {at}: nothing here to make or start."
        )),
    }
}

/// Say whether the database the user runs lets the settings in.
async fn check_external(settings: &Settings) -> Result<(), Box<dyn std::error::Error>> {
    cfx_db::check(settings, Some(&super::config::get_config_path())).await?;
    super::ui::ok(&format!(
        "It answers on {}, and lets {} in.",
        settings.address(),
        settings.user
    ));
    Ok(())
}

/// `crossfyre db external`: record a database the user runs as the one the engines use,
/// once it lets them in.
async fn external(host: &str, port: u16, user: &str) -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::{ok, warn};
    let password = external_password(host, user)?;
    let stopped = external_in(&get_toolchain_dir(), host, port, user, password).await?;
    let config = load_config()?;
    ok(&format!(
        "config.toml now names the database you run at {}.",
        config.postgres.address()
    ));
    if matches!(stopped, Stop::Stopped | Stop::NotRunning) {
        warn(&format!(
            "The local database is not used now, and is stopped. It stays in {} with its \
             settings, and `crossfyre db up` goes back to it.",
            get_toolchain_dir().join("postgres").display()
        ));
    }
    restart_engines();
    ok(&format!(
        "It answers on {}, and lets {} in.",
        config.postgres.address(),
        config.postgres.user
    ));
    Ok(())
}

/// Record the database at `host`:`port` as the one the engines use, in the toolchain
/// directory `dir`, once it lets `user` in with `password`. Otherwise nothing changes.
pub(crate) async fn external_in(
    dir: &std::path::Path,
    host: &str,
    port: u16,
    user: &str,
    password: String,
) -> Result<Stop, Box<dyn std::error::Error>> {
    let settings = Settings {
        backend: Backend::External {
            host: host.to_string(),
        },
        port,
        user: user.to_string(),
        password: (!password.is_empty()).then_some(password),
        ..Settings::default()
    };
    cfx_db::check(&settings, None)
        .await
        .map_err(|e| format!("{e}. Nothing was recorded, and config.toml is as it was"))?;
    record_external_in(dir, settings)
}

/// config.toml in `dir` names the database `settings` describe, keeping the database name
/// it had. A local database that runs is stopped, since nothing uses it now.
fn record_external_in(
    dir: &std::path::Path,
    settings: Settings,
) -> Result<Stop, Box<dyn std::error::Error>> {
    let path = dir.join("config.toml");
    let mut config = load_or_create_config_at(&path)?;
    let account = account()?;
    let toolchain = Toolchain::new(dir.to_path_buf(), account.as_ref());
    // The local database's settings stay with it, so `crossfyre db up` can go back to it.
    let stopped = match config.postgres.backend {
        Backend::Local => {
            toolchain.keep_local(&config.postgres)?;
            toolchain.stop()?
        }
        Backend::External { .. } => Stop::External,
    };
    config.postgres = Settings {
        db_name: config.postgres.db_name,
        ..settings
    };
    save_config_at(&path, &config)?;
    Ok(stopped)
}

/// What going back to the local database found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Back {
    /// config.toml named it already.
    Already,
    /// One had been made, and the settings kept with it are config.toml's again.
    Kept,
    /// None had been made, so config.toml names a new one, with a new password.
    New,
}

/// config.toml in `dir` names the local database, going back to it from a database the
/// user runs: the one made before, with the settings kept with it, or a new one.
pub(crate) fn use_local_in(dir: &std::path::Path) -> Result<Back, Box<dyn std::error::Error>> {
    let path = dir.join("config.toml");
    let mut config = load_or_create_config_at(&path)?;
    if config.postgres.backend == Backend::Local {
        return Ok(Back::Already);
    }
    let account = account()?;
    let toolchain = Toolchain::new(dir.to_path_buf(), account.as_ref());
    let back = match toolchain.kept_local()? {
        Some(kept) => {
            config.postgres = kept;
            Back::Kept
        }
        None => {
            let mut local = Settings {
                db_name: config.postgres.db_name.clone(),
                ..Settings::default()
            };
            local.ensure_password()?;
            config.postgres = local;
            Back::New
        }
    };
    save_config_at(&path, &config)?;
    Ok(back)
}

/// The password for `user` at `host`: from [`PASSWORD_ENV`] when it is set, otherwise
/// asked for at a terminal without showing it, or read as one line of stdin.
fn external_password(host: &str, user: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;
    if let Ok(password) = std::env::var(PASSWORD_ENV) {
        return Ok(password);
    }
    if std::io::stdin().is_terminal() {
        return Ok(dialoguer::Password::new()
            .with_prompt(format!("Password for {user} at {host}"))
            .allow_empty_password(true)
            .interact()?);
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Restart the installed engine daemons, whose open connections are to the database
/// config.toml named when they started.
pub fn restart_engines() {
    for ext in super::ENGINES.iter().map(|e| e.name) {
        if super::config::is_extension_installed(ext) && super::service::has_service_file(ext) {
            if let Err(e) = super::service::restart(ext) {
                super::ui::warn(&format!(
                    "{ext} did not restart ({e}); restart it so it uses the new database: \
                     crossfyre extension restart {ext}"
                ));
            }
        }
    }
}

/// The account the database belongs to: this process's, or as root the user crossfyre
/// was run for through sudo, whom the node's service acts for as well. Never root.
pub fn account() -> Result<Box<dyn Account>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    if crate::os::is_elevated() {
        let Some((uid, gid, _, _)) = sudo_user::sudo_user_info() else {
            return Err(
                "as root, with no sudo user to act for, there is nobody to make the \
                        database for. Run this as the user whose engines use it"
                    .into(),
            );
        };
        return Ok(Box::new(InvokingUser { uid, gid }));
    }
    #[cfg(windows)]
    if crate::os::process_account().is_none() {
        return Err(
            "the node's service runs as LocalSystem, and the database belongs to \
                    the operator: the engines start it as their own account"
                .into(),
        );
    }
    Ok(Box::new(cfx_db::ThisAccount::new()?))
}

/// The user crossfyre was run for through sudo, acted for by a process that runs as root:
/// programs are run as them, and what is made is handed to them, without following a
/// link they could have put on the way.
#[cfg(unix)]
struct InvokingUser {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl Account for InvokingUser {
    fn command(&self, program: &std::path::Path) -> std::process::Command {
        sudo_user::cmd_as_invoking_user(program)
    }

    fn create_dir_all(&self, dir: &std::path::Path) -> std::io::Result<()> {
        sudo_user::create_dir_all_for_invoking_user(dir)
    }

    fn read_to_string(&self, path: &std::path::Path) -> std::io::Result<String> {
        sudo_user::read_to_string(path)
    }

    fn write_private(&self, path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
        sudo_user::write_for_invoking_user(path, contents, 0o600)
    }

    fn remove_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        sudo_user::remove_file(path)
    }

    fn try_lock(&self, path: &std::path::Path) -> std::io::Result<Option<std::fs::File>> {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;
        let file = super::root_fs::open_lock(path, 0o600)?;
        // Handed to the user below, so it has to be a file of its own: a hard link to
        // someone else's file would be handed over with it.
        let meta = file.metadata()?;
        if !lock_file_usable(
            meta.file_type().is_file(),
            meta.nlink(),
            meta.uid(),
            self.uid,
        ) {
            return Err(std::io::Error::other(
                "it is not a file of its own that belongs to this account; remove it",
            ));
        }
        if unsafe { libc::fchown(file.as_raw_fd(), self.uid, self.gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        cfx_db::lock_file(file)
    }

    fn runtime_dir(&self) -> Option<std::path::PathBuf> {
        Some(std::path::PathBuf::from(format!("/run/user/{}", self.uid)))
    }
}

/// Whether a lock file root opened may be handed to the user `user`: a file with no
/// second name, that belongs to root or to them already.
#[cfg(unix)]
fn lock_file_usable(is_file: bool, links: u64, owner: u32, user: u32) -> bool {
    is_file && links == 1 && (owner == 0 || owner == user)
}

#[cfg(test)]
mod tests {
    const LOCAL: &str = "[postgres]\nbackend = \"local\"\nport = 4440\nuser = \"postgres\"\n\
                         password = \"local-pw\"\ndb_name = \"crossfyre\"\n";

    #[test]
    fn a_database_one_runs_keeps_the_local_one_s_settings_to_go_back_to() {
        use super::{Backend, Settings};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, LOCAL).unwrap();
        std::fs::create_dir_all(dir.path().join("postgres")).unwrap();
        std::fs::write(dir.path().join("postgres/PG_VERSION"), "17\n").unwrap();
        let theirs = Settings {
            backend: Backend::External {
                host: "db.internal".to_string(),
            },
            port: 5432,
            user: "cfx".to_string(),
            password: Some("their-pw".to_string()),
            ..Settings::default()
        };
        super::record_external_in(dir.path(), theirs).unwrap();
        let recorded = super::super::config::load_config_at(&path)
            .unwrap()
            .postgres;
        assert_eq!(recorded.address(), "db.internal:5432");

        assert_eq!(super::use_local_in(dir.path()).unwrap(), super::Back::Kept);
        let back = super::super::config::load_config_at(&path)
            .unwrap()
            .postgres;
        assert_eq!(back.backend, Backend::Local);
        assert_eq!(back.address(), "127.0.0.1:4440");
        assert_eq!(back.password.as_deref(), Some("local-pw"));
        assert_eq!(
            super::use_local_in(dir.path()).unwrap(),
            super::Back::Already
        );
    }

    #[test]
    fn going_back_with_no_local_database_made_gives_a_new_password() {
        use super::Backend;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[postgres]\nbackend = \"external\"\nhost = \"db\"\nport = 5432\nuser = \"u\"\n\
             password = \"theirs\"\ndb_name = \"scans\"\n",
        )
        .unwrap();
        assert_eq!(super::use_local_in(dir.path()).unwrap(), super::Back::New);
        let back = super::super::config::load_config_at(&path)
            .unwrap()
            .postgres;
        assert_eq!(back.backend, Backend::Local);
        assert_eq!(back.db_name, "scans");
        assert_eq!(back.password.map(|p| p.len()), Some(64));
    }

    #[tokio::test]
    async fn a_database_that_does_not_answer_is_not_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, LOCAL).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let e = super::external_in(dir.path(), "127.0.0.1", port, "postgres", "pw".to_string())
            .await
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "nothing is listening on 127.0.0.1:{port}. Nothing was recorded, and \
                 config.toml is as it was"
            )
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), LOCAL);
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_file_is_handed_to_the_user_only_when_it_is_one_of_its_own() {
        use super::lock_file_usable;
        assert!(lock_file_usable(true, 1, 0, 1000), "made by root just now");
        assert!(lock_file_usable(true, 1, 1000, 1000), "the user's already");
        assert!(
            !lock_file_usable(true, 2, 0, 1000),
            "a second name for a file of root's"
        );
        assert!(!lock_file_usable(true, 1, 1001, 1000), "someone else's");
        assert!(!lock_file_usable(false, 1, 1000, 1000), "not a file");
    }

    #[cfg(unix)]
    #[test]
    fn root_does_not_follow_a_link_to_the_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, "").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join("db.lock")).unwrap();
        let _root = super::sudo_user::act_as_root();
        let account = super::InvokingUser {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        };
        assert!(
            cfx_db::Account::try_lock(&account, &dir.path().join("db.lock")).is_err(),
            "followed the link"
        );
    }
}

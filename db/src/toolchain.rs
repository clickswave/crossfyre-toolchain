//! The database of one toolchain directory: config.toml's settings, and with the local
//! backend the cluster beside it.

use crate::NotReady;
use crate::account::{Account, Lock};
use crate::local::{Cluster, Postgres, answers, find_postgres};
use crate::settings::{Backend, CONFIG_FILE, Settings};
use std::path::{Path, PathBuf};

/// A toolchain directory, acted on as the account it belongs to.
pub struct Toolchain<'a> {
    dir: PathBuf,
    account: &'a dyn Account,
}

/// What [`Toolchain::up`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Up {
    /// Made the local database, which was missing, and started it.
    Made,
    /// Started the local database, which was stopped.
    Started,
    /// Nothing: the local database was running.
    Running,
    /// Nothing: config.toml names a database the user runs.
    External,
}

/// What [`Toolchain::stop`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Stopped,
    /// Nothing: the local database was not running.
    NotRunning,
    /// Nothing: there is no local database yet.
    NotMade,
    /// Nothing: config.toml names a database the user runs.
    External,
}

/// What [`Toolchain::status`] finds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub settings: Settings,
    /// For the local backend, the cluster's directory and the version that made it, when
    /// it has been made.
    pub cluster: Option<(PathBuf, Option<u32>)>,
    /// The local database's server runs, or the external one answers on its port.
    pub running: bool,
    /// Something that is not the local database listens on its port.
    pub port_taken: bool,
}

impl<'a> Toolchain<'a> {
    pub fn new(dir: PathBuf, account: &'a dyn Account) -> Self {
        Self { dir, account }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// config.toml.
    pub fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }

    /// The local database's directory.
    pub fn cluster_dir(&self) -> PathBuf {
        Cluster::in_toolchain(&self.dir).dir().to_path_buf()
    }

    /// config.toml's settings, or None when there is no config.toml.
    pub fn read_settings(&self) -> Result<Option<Settings>, NotReady> {
        let path = self.config_path();
        match self.account.read_to_string(&path) {
            Ok(text) => Settings::parse(&text, &path).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(NotReady::new(
                format!("cannot read {}: {e}", path.display()),
                None,
            )),
        }
    }

    /// config.toml's settings, making the file first when there is none: the local
    /// database, with a new password, readable by the account alone.
    pub fn settings(&self) -> Result<Settings, NotReady> {
        if let Some(settings) = self.read_settings()? {
            return Ok(settings);
        }
        let _lock = Lock::hold(self.account, &self.dir)?;
        // Made by another process while this one waited.
        if let Some(settings) = self.read_settings()? {
            return Ok(settings);
        }
        let mut settings = Settings::default();
        settings
            .ensure_password()
            .map_err(|e| NotReady::new(e.to_string(), None))?;
        let path = self.config_path();
        self.account
            .write_private(&path, settings.to_file().as_bytes())
            .map_err(|e| NotReady::new(format!("cannot write {}: {e}", path.display()), None))?;
        Ok(settings)
    }

    /// Make the database usable: config.toml first when there is none, and then with the
    /// local backend the cluster when it is missing, started when it is not running. What
    /// is there is never replaced or emptied.
    pub fn up(&self) -> Result<(Settings, Up), NotReady> {
        let settings = self.settings()?;
        if let Backend::External { .. } = settings.backend {
            return Ok((settings, Up::External));
        }
        if settings.password.as_deref().is_none_or(str::is_empty) {
            return Err(NotReady::new(
                format!(
                    "{} gives the local database no password. Add one, or remove the file and \
                     the next `crossfyre db up` writes a new one",
                    self.config_path().display()
                ),
                None,
            ));
        }
        let _lock = Lock::hold(self.account, &self.dir)?;
        let cluster = Cluster::in_toolchain(&self.dir);
        let pg = self.programs(&cluster)?;
        let made = !cluster.exists();
        if made {
            cluster.make(&pg, &settings, self.account)?;
        } else if cluster.running(&pg, self.account)? {
            return Ok((settings, Up::Running));
        }
        cluster.start(&pg, settings.port, self.account)?;
        Ok((settings, if made { Up::Made } else { Up::Started }))
    }

    /// Stop the local database.
    pub fn stop(&self) -> Result<Stop, NotReady> {
        if let Some(Settings {
            backend: Backend::External { .. },
            ..
        }) = self.read_settings()?
        {
            return Ok(Stop::External);
        }
        let cluster = Cluster::in_toolchain(&self.dir);
        if !cluster.exists() {
            return Ok(Stop::NotMade);
        }
        let _lock = Lock::hold(self.account, &self.dir)?;
        let pg = self.programs(&cluster)?;
        Ok(if cluster.stop(&pg, self.account)? {
            Stop::Stopped
        } else {
            Stop::NotRunning
        })
    }

    /// Which database config.toml names and whether it runs, found without changing
    /// anything; None when there is no config.toml.
    pub fn status(&self) -> Result<Option<Status>, NotReady> {
        let Some(settings) = self.read_settings()? else {
            return Ok(None);
        };
        let status = match settings.backend {
            Backend::Local => {
                let cluster = Cluster::in_toolchain(&self.dir);
                let made = cluster.exists();
                let running = made && cluster.seems_running(settings.port);
                Status {
                    cluster: made
                        .then(|| (cluster.dir().to_path_buf(), cluster.major(self.account))),
                    running,
                    port_taken: !running && answers(settings.port),
                    settings,
                }
            }
            Backend::External { .. } => Status {
                running: settings.answers(),
                cluster: None,
                port_taken: false,
                settings,
            },
        };
        Ok(Some(status))
    }

    /// The programs for `cluster`: of the version that made it, or the newest.
    fn programs(&self, cluster: &Cluster) -> Result<Postgres, NotReady> {
        let major = if cluster.exists() {
            cluster.major(self.account)
        } else {
            None
        };
        find_postgres(self.account, major)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::ThisAccount;

    #[test]
    fn a_missing_config_is_made_for_the_local_database_with_a_password() {
        let dir = tempfile::tempdir().unwrap();
        let account = ThisAccount::new().unwrap();
        let toolchain = Toolchain::new(dir.path().join("crossfyre"), &account);
        let settings = toolchain.settings().unwrap();
        assert_eq!(settings.backend, Backend::Local);
        assert_eq!(settings.port, 4440);
        assert_eq!(settings.password.as_ref().map(String::len), Some(64));
        assert_eq!(toolchain.read_settings().unwrap(), Some(settings.clone()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(toolchain.config_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Made once: read back after that, not made again.
        assert_eq!(toolchain.settings().unwrap(), settings);
    }

    #[test]
    fn a_config_that_is_there_is_never_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);
        let text = "[postgres]\nbackend = \"external\"\nhost = \"db\"\nport = 5432\n\
                    user = \"u\"\ndb_name = \"crossfyre\"\n\n[extensions]\nvoyage = 5000\n";
        std::fs::write(&path, text).unwrap();
        let account = ThisAccount::new().unwrap();
        let toolchain = Toolchain::new(dir.path().to_path_buf(), &account);
        assert_eq!(toolchain.up().unwrap().1, Up::External);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn stopping_or_asking_after_a_database_never_made_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let account = ThisAccount::new().unwrap();
        let toolchain = Toolchain::new(dir.path().join("crossfyre"), &account);
        assert_eq!(toolchain.status().unwrap(), None);
        assert_eq!(toolchain.stop().unwrap(), Stop::NotMade);
        assert!(!toolchain.dir().exists(), "made something");
    }

    #[test]
    fn two_processes_that_find_no_config_write_one() {
        let dir = tempfile::tempdir().unwrap();
        let toolchain_dir = dir.path().join("crossfyre");
        let made: Vec<Settings> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let d = toolchain_dir.clone();
                    s.spawn(move || {
                        let account = ThisAccount::new().unwrap();
                        Toolchain::new(d, &account).settings().unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(made.windows(2).all(|w| w[0] == w[1]), "{made:?}");
    }
}

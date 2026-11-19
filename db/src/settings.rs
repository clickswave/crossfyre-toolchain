//! The `[postgres]` section of the toolchain's config.toml.

use crate::NotReady;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgConnectOptions;
use std::path::{Path, PathBuf};

/// The file in the toolchain directory the settings are in.
const CONFIG_FILE: &str = "config.toml";

/// The command that writes config.toml when there is none and makes the database it
/// names, as `crossfyre` makes it on this machine.
pub(crate) const DB_UP: &str = "crossfyre db up";

/// Where the database server is and how to log in to it: the `[postgres]` section of
/// config.toml. `crossfyre` holds it in the config it writes, and the engines read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// `crossfyre` gives the settings one when they have none: see
    /// [`Settings::ensure_password`].
    pub password: Option<String>,
    /// The database `crossfyre` makes the server with.
    pub db_name: String,
}

impl Default for Settings {
    /// The toolchain's own database on this machine, before it has a password.
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 4440,
            user: "postgres".to_string(),
            password: None,
            db_name: "crossfyre".to_string(),
        }
    }
}

impl Settings {
    /// Give the settings a new password when they have none, and say whether they got
    /// one. An empty password counts as none.
    pub fn ensure_password(&mut self) -> std::io::Result<bool> {
        if self.password.as_deref().is_some_and(|p| !p.is_empty()) {
            return Ok(false);
        }
        self.password = Some(new_password()?);
        Ok(true)
    }

    /// The settings in the config.toml at `path`. An engine reads the file as the user it
    /// runs as. `crossfyre` reads the whole file its own way, since it may run as root,
    /// and this section of it into the same type.
    pub(crate) fn read(path: &Path) -> Result<Self, NotReady> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NotReady::new(
                    format!("there is no toolchain config at {}", path.display()),
                    Some(DB_UP),
                )
            } else {
                NotReady::new(format!("cannot read {}: {e}", path.display()), None)
            }
        })?;
        #[derive(Deserialize)]
        struct File {
            postgres: Settings,
        }
        toml::from_str::<File>(&text)
            .map(|file| file.postgres)
            .map_err(|e| {
                let line = e
                    .span()
                    .and_then(|span| text.get(..span.start))
                    .map(|before| before.matches('\n').count() + 1);
                let at = line.map(|n| format!(" (line {n})")).unwrap_or_default();
                NotReady::new(
                    format!(
                        "{} is not a valid toolchain config: {}{at}",
                        path.display(),
                        e.message()
                    ),
                    None,
                )
            })
    }

    /// The server's address as it is typed: `host:port`, with an IPv6 host in brackets.
    pub(crate) fn address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// How to connect to `database` on the server.
    pub(crate) fn options(&self, database: &str) -> PgConnectOptions {
        let options = PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .username(&self.user)
            .database(database);
        match self.password.as_deref() {
            Some(password) => options.password(password),
            None => options,
        }
    }
}

/// Where config.toml is: in the toolchain directory, found by `dguard::toolchain_dir`.
pub(crate) fn config_path() -> Result<PathBuf, NotReady> {
    dguard::toolchain_dir()
        .map(|dir| dir.join(CONFIG_FILE))
        .ok_or_else(|| {
            NotReady::new(
                format!(
                    "there is no home directory to find the toolchain config in. Set {} \
                     to the directory that holds {CONFIG_FILE}",
                    dguard::TOOLCHAIN_DIR_ENV
                ),
                None,
            )
        })
}

/// A new random password for the database: 32 bytes as 64 hex digits.
pub fn new_password() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| {
        std::io::Error::other(format!("no randomness for a database password: {e}"))
    })?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    /// What `crossfyre` writes: its own sections around this one.
    #[test]
    fn the_section_is_read_from_the_file_crossfyre_writes() {
        let (_dir, path) = written(
            "[postgres]\nhost = \"localhost\"\nport = 4440\nuser = \"postgres\"\n\
             password = \"abc\"\ndb_name = \"crossfyre\"\n\n[container]\nid = \"f00\"\n\n\
             [extensions]\nambulo = 4441\nvoyage = 4442\n",
        );
        assert_eq!(
            Settings::read(&path).unwrap(),
            Settings {
                password: Some("abc".to_string()),
                ..Settings::default()
            }
        );
    }

    /// What a person writes for a database of their own, as CI does: nothing else.
    #[test]
    fn the_section_alone_is_a_whole_config() {
        let (_dir, path) = written(
            "[postgres]\nhost = \"127.0.0.1\"\nport = 5432\nuser = \"crossfyre\"\n\
             password = \"crossfyre\"\ndb_name = \"crossfyre\"\n",
        );
        let settings = Settings::read(&path).unwrap();
        assert_eq!(settings.address(), "127.0.0.1:5432");
        assert_eq!(settings.user, "crossfyre");
    }

    #[test]
    fn the_section_is_read_back_as_it_was_written() {
        let settings = Settings {
            host: "db.internal".to_string(),
            port: 5433,
            user: "cfx".to_string(),
            password: Some("p\"w".to_string()),
            db_name: "scans".to_string(),
        };
        let mut text = String::from("[postgres]\n");
        text.push_str(&toml::to_string(&settings).unwrap());
        let (_dir, path) = written(&text);
        assert_eq!(Settings::read(&path).unwrap(), settings);
    }

    #[test]
    fn a_missing_file_says_where_it_looked_and_what_writes_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);
        let e = Settings::read(&path).unwrap_err();
        assert_eq!(
            e.problem(),
            format!("there is no toolchain config at {}", path.display())
        );
        assert_eq!(e.fix(), Some("crossfyre db up"));
    }

    #[test]
    fn a_file_that_cannot_be_read_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let e = Settings::read(dir.path()).unwrap_err();
        assert!(
            e.problem()
                .starts_with(&format!("cannot read {}: ", dir.path().display())),
            "{e}"
        );
        assert_eq!(e.fix(), None);
    }

    #[test]
    fn a_section_without_a_port_names_the_file_the_line_and_the_key() {
        let (_dir, path) = written(
            "[extensions]\nambulo = 4441\n\n[postgres]\nhost = \"localhost\"\n\
             user = \"postgres\"\ndb_name = \"crossfyre\"\n",
        );
        let e = Settings::read(&path).unwrap_err();
        assert_eq!(
            e.problem(),
            format!(
                "{} is not a valid toolchain config: missing field `port` (line 4)",
                path.display()
            )
        );
        assert_eq!(e.fix(), None);
    }

    #[test]
    fn a_new_password_is_64_hex_digits_and_never_the_same_twice() {
        let a = new_password().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, new_password().unwrap());
    }

    #[test]
    fn settings_without_a_password_get_one_once() {
        let mut settings = Settings::default();
        assert!(settings.ensure_password().unwrap());
        let first = settings.password.clone().expect("a password");
        assert_eq!(first.len(), 64);
        assert!(!settings.ensure_password().unwrap());
        assert_eq!(settings.password, Some(first));
    }

    #[test]
    fn an_empty_password_counts_as_none() {
        let mut settings = Settings {
            password: Some(String::new()),
            ..Settings::default()
        };
        assert!(settings.ensure_password().unwrap());
        assert_eq!(settings.password.map(|p| p.len()), Some(64));
    }

    #[test]
    fn an_operator_s_password_is_kept() {
        let mut settings = Settings {
            password: Some("mine".to_string()),
            ..Settings::default()
        };
        assert!(!settings.ensure_password().unwrap());
        assert_eq!(settings.password.as_deref(), Some("mine"));
    }

    #[test]
    fn an_ipv6_host_is_bracketed_in_the_address() {
        let settings = Settings {
            host: "::1".to_string(),
            ..Settings::default()
        };
        assert_eq!(settings.address(), "[::1]:4440");
    }
}

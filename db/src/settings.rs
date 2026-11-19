//! The `[postgres]` section of the toolchain's config.toml.

use crate::NotReady;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgConnectOptions;
use std::path::Path;

/// The file in the toolchain directory the settings are in.
pub(crate) const CONFIG_FILE: &str = "config.toml";

/// The address the local database listens on, and only there.
pub(crate) const LOOPBACK: &str = "127.0.0.1";

/// Which database the engines use, and how to log in to it: the `[postgres]` section of
/// config.toml. `crossfyre` holds it in the config it writes, and the engines read it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Written in the section as `backend = "local"` or `"external"`, with `host` beside
    /// it for an external one.
    #[serde(flatten)]
    pub backend: Backend,
    pub port: u16,
    pub user: String,
    /// `crossfyre` gives the local database one when it is made: see
    /// [`Settings::ensure_password`].
    pub password: Option<String>,
    /// The database `crossfyre` keeps for its own use on the server.
    pub db_name: String,
}

/// Whose database it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum Backend {
    /// A cluster crossfyre makes in the toolchain directory and runs as the user that
    /// directory belongs to, listening on 127.0.0.1 only.
    Local,
    /// A server the user runs themselves, at `host`, in Docker or anywhere else.
    External { host: String },
}

/// Printed for a log or an error, the settings say whether there is a password, never
/// what it is.
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("backend", &self.backend)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<hidden>"))
            .field("db_name", &self.db_name)
            .finish()
    }
}

impl Default for Settings {
    /// The local database, before it has a password.
    fn default() -> Self {
        Self {
            backend: Backend::Local,
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

    /// The host the server is reached at: 127.0.0.1 for the local database.
    pub fn host(&self) -> &str {
        match &self.backend {
            Backend::Local => LOOPBACK,
            Backend::External { host } => host,
        }
    }

    /// The server's address as it is typed: `host:port`, with an IPv6 host in brackets.
    pub fn address(&self) -> String {
        let host = self.host();
        if host.contains(':') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Whether something accepts a TCP connection where the settings put the server.
    pub fn answers(&self) -> bool {
        use std::net::ToSocketAddrs;
        (self.host(), self.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .is_some_and(|addr| {
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500))
                    .is_ok()
            })
    }

    /// The settings in `text`, the contents of the config.toml at `path`.
    pub(crate) fn parse(text: &str, path: &Path) -> Result<Self, NotReady> {
        #[derive(Deserialize)]
        struct File {
            postgres: Settings,
        }
        toml::from_str::<File>(text)
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

    /// config.toml holding these settings and nothing else, as it is made when missing.
    pub(crate) fn to_file(&self) -> String {
        #[derive(Serialize)]
        struct File<'a> {
            postgres: &'a Settings,
        }
        toml::to_string(&File { postgres: self }).expect("settings serialise")
    }

    /// How to connect to `database` on the server.
    pub(crate) fn options(&self, database: &str) -> PgConnectOptions {
        let options = PgConnectOptions::new()
            .host(self.host())
            .port(self.port)
            .username(&self.user)
            .database(database);
        match self.password.as_deref() {
            Some(password) => options.password(password),
            None => options,
        }
    }
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

    fn parsed(text: &str) -> Result<Settings, NotReady> {
        Settings::parse(text, Path::new("/t/config.toml"))
    }

    fn external(host: &str) -> Settings {
        Settings {
            backend: Backend::External {
                host: host.to_string(),
            },
            port: 5433,
            user: "cfx".to_string(),
            password: Some("p\"w".to_string()),
            db_name: "scans".to_string(),
        }
    }

    /// Settings end up in errors and logs, and the password must not go with them.
    #[test]
    fn printed_settings_never_show_the_password() {
        let settings = Settings {
            password: Some("s3cret-pw".to_string()),
            ..Settings::default()
        };
        let printed = format!("{settings:?} {settings:#?}");
        assert!(!printed.contains("s3cret-pw"), "{printed}");
        assert!(printed.contains("<hidden>"), "{printed}");
        assert!(format!("{:?}", Settings::default()).contains("password: None"));
    }

    /// What `crossfyre` writes: its own section beside this one.
    #[test]
    fn the_local_section_is_read_from_the_file_crossfyre_writes() {
        let settings = parsed(
            "[postgres]\nbackend = \"local\"\nport = 4440\nuser = \"postgres\"\n\
             password = \"abc\"\ndb_name = \"crossfyre\"\n\n\
             [extensions]\nambulo = 4441\nvoyage = 4442\n",
        )
        .unwrap();
        assert_eq!(
            settings,
            Settings {
                password: Some("abc".to_string()),
                ..Settings::default()
            }
        );
        assert_eq!(settings.address(), "127.0.0.1:4440");
    }

    /// What a person writes for a database of their own, as CI does: nothing else.
    #[test]
    fn an_external_section_alone_is_a_whole_config() {
        let settings = parsed(
            "[postgres]\nbackend = \"external\"\nhost = \"db.internal\"\nport = 5432\n\
             user = \"crossfyre\"\npassword = \"crossfyre\"\ndb_name = \"crossfyre\"\n",
        )
        .unwrap();
        assert_eq!(settings.address(), "db.internal:5432");
        assert_eq!(settings.user, "crossfyre");
    }

    #[test]
    fn each_backend_is_read_back_as_it_was_written() {
        for settings in [
            Settings {
                password: Some("p\"w".to_string()),
                ..Settings::default()
            },
            external("db.internal"),
        ] {
            let text = settings.to_file();
            assert_eq!(parsed(&text).unwrap(), settings, "{text}");
        }
    }

    /// The backend comes first, so the file reads the way it is decided.
    #[test]
    fn the_backend_is_the_first_line_of_the_section() {
        assert!(
            Settings::default()
                .to_file()
                .starts_with("[postgres]\nbackend = \"local\"\n")
        );
        assert!(
            external("h")
                .to_file()
                .starts_with("[postgres]\nbackend = \"external\"\nhost = \"h\"\n")
        );
    }

    #[test]
    fn a_section_without_a_backend_is_refused_with_the_key_it_lacks() {
        let e = parsed(
            "[postgres]\nport = 4440\nuser = \"postgres\"\npassword = \"x\"\n\
             db_name = \"crossfyre\"\n",
        )
        .unwrap_err();
        assert!(
            e.problem().contains("missing field `backend`"),
            "{}",
            e.problem()
        );
    }

    #[test]
    fn an_external_database_needs_a_host() {
        let e = parsed(
            "[postgres]\nbackend = \"external\"\nport = 5432\nuser = \"u\"\n\
             db_name = \"crossfyre\"\n",
        )
        .unwrap_err();
        assert!(
            e.problem().contains("missing field `host`"),
            "{}",
            e.problem()
        );
    }

    #[test]
    fn a_section_without_a_port_names_the_file_the_line_and_the_key() {
        let e = parsed(
            "[extensions]\nambulo = 4441\n\n[postgres]\nbackend = \"local\"\n\
             user = \"postgres\"\ndb_name = \"crossfyre\"\n",
        )
        .unwrap_err();
        assert_eq!(
            e.problem(),
            "/t/config.toml is not a valid toolchain config: missing field `port` (line 4)"
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
        assert_eq!(external("::1").address(), "[::1]:5433");
    }
}

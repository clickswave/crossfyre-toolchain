//! Reaching the database, or saying why it cannot be reached.

use crate::settings::{DB_UP, Settings, config_path};
use sqlx::Connection;
use sqlx::postgres::{PgConnection, PgPool, PgPoolOptions};
use std::path::Path;
use std::time::Duration;

/// How long the server has to answer a connection.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// The database every Postgres server has, which an engine's own is made from.
const MAINTENANCE_DB: &str = "postgres";

/// Why the database cannot be used, and the one command that fixes it when one does.
///
/// It names where it looked, which "pool timed out while waiting for an open connection",
/// what sqlx says when nothing listens on the port, does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotReady {
    problem: String,
    fix: Option<String>,
}

impl NotReady {
    pub(crate) fn new(problem: String, fix: Option<&str>) -> Self {
        Self {
            problem,
            fix: fix.map(str::to_string),
        }
    }

    /// What is wrong, and where.
    pub fn problem(&self) -> &str {
        &self.problem
    }

    /// The command that fixes it, when one does.
    pub fn fix(&self) -> Option<&str> {
        self.fix.as_deref()
    }
}

impl std::fmt::Display for NotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.problem)?;
        if let Some(fix) = &self.fix {
            write!(f, ". Run `{fix}`")?;
        }
        Ok(())
    }
}

impl std::error::Error for NotReady {}

/// A pool on the database called `database` on the toolchain's database server, made
/// there first if it is missing.
///
/// The server is the one config.toml names, in the toolchain directory
/// (`dguard::toolchain_dir`). The file is read on every call, so a daemon that waits on
/// this picks up what `crossfyre` writes while it waits.
pub async fn ensure_ready(database: &str) -> Result<PgPool, NotReady> {
    ready_at(&config_path()?, database).await
}

/// [`ensure_ready`] for the config.toml at `path`.
async fn ready_at(path: &Path, database: &str) -> Result<PgPool, NotReady> {
    let settings = Settings::read(path)?;
    let address = settings.address();
    // One connection first, because its error says why. A pool retries a refused
    // connection until its time is up and then says only that it timed out.
    let mut server = tokio::time::timeout(
        ANSWER_WITHIN,
        PgConnection::connect_with(&settings.options(MAINTENANCE_DB)),
    )
    .await
    .map_err(|_| {
        NotReady::new(
            format!(
                "the database on {address} did not answer within {} seconds",
                ANSWER_WITHIN.as_secs()
            ),
            None,
        )
    })?
    .map_err(|e| not_reached(&settings, path, e))?;
    let made = make_database(&mut server, database).await;
    let _ = server.close().await;
    made.map_err(|e| {
        NotReady::new(
            format!("could not make the {database} database on {address}: {e}"),
            None,
        )
    })?;
    PgPoolOptions::new()
        .connect_with(settings.options(database))
        .await
        .map_err(|e| not_reached(&settings, path, e))
}

/// Make the database called `name` on the server unless it is there.
async fn make_database(server: &mut PgConnection, name: &str) -> Result<(), sqlx::Error> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(name)
            .fetch_one(&mut *server)
            .await?;
    if !exists {
        // CREATE DATABASE takes no parameters, so the name goes in as a quoted identifier.
        let create = format!("CREATE DATABASE \"{}\"", name.replace('"', "\"\""));
        sqlx::query(&create).execute(&mut *server).await?;
    }
    Ok(())
}

/// Why the server `settings` names could not be used, from what connecting to it said.
/// The settings are the ones in the config.toml at `path`.
fn not_reached(settings: &Settings, path: &Path, e: sqlx::Error) -> NotReady {
    let at = settings.address();
    match &e {
        sqlx::Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => NotReady::new(
            format!(
                "nothing is listening on {at}, where {} puts the database",
                path.display()
            ),
            Some(DB_UP),
        ),
        sqlx::Error::Database(db) => match db.code().as_deref() {
            // invalid_password
            Some("28P01") => NotReady::new(
                format!(
                    "the database on {at} refused the password in {}",
                    path.display()
                ),
                Some(DB_UP),
            ),
            // invalid_authorization_specification: no such user, or a rule of the
            // server's that turns this one away
            Some("28000") => NotReady::new(
                format!(
                    "the database on {at} refused user {}: {}",
                    settings.user,
                    db.message()
                ),
                Some(DB_UP),
            ),
            _ => NotReady::new(
                format!(
                    "the database on {at} refused the connection: {}",
                    db.message()
                ),
                None,
            ),
        },
        _ => NotReady::new(format!("cannot reach the database on {at}: {e}"), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config_on(dir: &Path, port: u16) -> PathBuf {
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            format!(
                "[postgres]\nhost = \"127.0.0.1\"\nport = {port}\nuser = \"postgres\"\n\
                 password = \"pw\"\ndb_name = \"crossfyre\"\n"
            ),
        )
        .unwrap();
        path
    }

    /// A port nothing listens on: one the system just handed out, closed again.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    /// A server that turns every connection away as Postgres does a wrong password: with
    /// an ErrorResponse carrying SQLSTATE 28P01 in answer to the startup message. A
    /// request for TLS before it is declined.
    async fn refusing_server() -> u16 {
        const SSL_REQUEST: u32 = 80877103;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                loop {
                    let mut len = [0u8; 4];
                    if sock.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let mut body = vec![0u8; (u32::from_be_bytes(len) as usize).saturating_sub(4)];
                    if sock.read_exact(&mut body).await.is_err() {
                        break;
                    }
                    if body.starts_with(&SSL_REQUEST.to_be_bytes()) {
                        let _ = sock.write_all(b"N").await;
                        continue;
                    }
                    let mut fields = Vec::new();
                    for (kind, value) in [
                        (b'S', "FATAL"),
                        (b'V', "FATAL"),
                        (b'C', "28P01"),
                        (b'M', "password authentication failed for user \"postgres\""),
                    ] {
                        fields.push(kind);
                        fields.extend_from_slice(value.as_bytes());
                        fields.push(0);
                    }
                    fields.push(0);
                    let mut reply = vec![b'E'];
                    reply.extend_from_slice(&(fields.len() as u32 + 4).to_be_bytes());
                    reply.extend_from_slice(&fields);
                    let _ = sock.write_all(&reply).await;
                    break;
                }
            }
        });
        port
    }

    #[test]
    fn the_command_follows_what_is_wrong() {
        let with = NotReady::new("nothing is listening on h:1".to_string(), Some(DB_UP));
        assert_eq!(
            with.to_string(),
            "nothing is listening on h:1. Run `crossfyre db up`"
        );
        let without = NotReady::new("cannot read c".to_string(), None);
        assert_eq!(without.to_string(), "cannot read c");
    }

    #[tokio::test]
    async fn a_closed_port_says_nothing_listens_there_and_what_starts_it() {
        let dir = tempfile::tempdir().unwrap();
        let port = closed_port();
        let path = config_on(dir.path(), port);
        let e = ready_at(&path, "voyage").await.unwrap_err();
        assert_eq!(
            e.problem(),
            format!(
                "nothing is listening on 127.0.0.1:{port}, where {} puts the database",
                path.display()
            )
        );
        assert_eq!(e.fix(), Some("crossfyre db up"));
    }

    #[tokio::test]
    async fn a_refused_password_says_whose_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let port = refusing_server().await;
        let path = config_on(dir.path(), port);
        let e = ready_at(&path, "voyage").await.unwrap_err();
        assert_eq!(
            e.problem(),
            format!(
                "the database on 127.0.0.1:{port} refused the password in {}",
                path.display()
            )
        );
        assert_eq!(e.fix(), Some("crossfyre db up"));
    }

    #[tokio::test]
    async fn a_missing_config_is_said_before_anything_is_reached() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let e = ready_at(&path, "voyage").await.unwrap_err();
        assert_eq!(e.fix(), Some("crossfyre db up"));
        assert!(e.problem().contains("no toolchain config"), "{e}");
    }

    /// A Postgres server in Docker, removed with its data when dropped.
    struct Server {
        name: String,
        port: u16,
    }

    impl Server {
        fn start(password: &str) -> Self {
            let mut server = Self {
                name: format!("cfx-db-test-{}", std::process::id()),
                port: 0,
            };
            let run = std::process::Command::new("docker")
                .args(["run", "-d", "--rm", "--name", &server.name])
                .args(["-p", "127.0.0.1::5432", "-e"])
                .arg(format!("POSTGRES_PASSWORD={password}"))
                .arg("postgres:16-alpine")
                .output()
                .expect("docker runs");
            assert!(
                run.status.success(),
                "{}",
                String::from_utf8_lossy(&run.stderr)
            );
            let out = std::process::Command::new("docker")
                .args(["port", &server.name, "5432/tcp"])
                .output()
                .expect("docker port");
            server.port = String::from_utf8_lossy(&out.stdout)
                .lines()
                .find_map(|l| l.rsplit(':').next()?.trim().parse().ok())
                .expect("a published port");
            server
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", "-v", &self.name])
                .output();
        }
    }

    #[tokio::test]
    #[ignore = "needs Docker and the postgres:16-alpine image"]
    async fn a_missing_database_is_made_and_one_that_is_there_is_used() {
        let server = Server::start("pw");
        let dir = tempfile::tempdir().unwrap();
        let path = config_on(dir.path(), server.port);
        // The server takes a while to take connections, and says so while it does.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let pool = loop {
            match ready_at(&path, "cfx_db_test").await {
                Ok(pool) => break pool,
                Err(e) if std::time::Instant::now() < deadline => {
                    eprintln!("not yet: {e}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => panic!("{e}"),
            }
        };
        let name: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(name, "cfx_db_test");
        sqlx::query("CREATE TABLE kept (n int)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let again = ready_at(&path, "cfx_db_test").await.unwrap();
        let tables: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.tables WHERE table_name = 'kept'",
        )
        .fetch_one(&again)
        .await
        .unwrap();
        assert_eq!(tables, 1, "the database was made again, empty");
    }
}

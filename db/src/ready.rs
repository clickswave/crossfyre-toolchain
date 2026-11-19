//! Reaching the database, or saying why it cannot be reached.

use crate::account::ThisAccount;
use crate::settings::{Backend, CONFIG_FILE, Settings};
use crate::toolchain::Toolchain;
use sqlx::Connection;
use sqlx::postgres::{PgConnection, PgPool, PgPoolOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long the server has to answer a connection.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// The database every Postgres server has, which an engine's own is made from.
const MAINTENANCE_DB: &str = "postgres";

/// The command that makes the local database, or starts it.
pub(crate) const DB_UP: &str = "crossfyre db up";

/// Why the database cannot be used, and the one command that fixes it when one does.
///
/// It names where it looked, which "pool timed out while waiting for an open connection",
/// what sqlx says when nothing listens on the port, does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotReady {
    problem: String,
    fix: Option<String>,
    or: Option<String>,
}

impl NotReady {
    pub(crate) fn new(problem: String, fix: Option<&str>) -> Self {
        Self {
            problem,
            fix: fix.map(str::to_string),
            or: None,
        }
    }

    /// With `instead`, what else would do where the command is not wanted.
    pub(crate) fn or(mut self, instead: &str) -> Self {
        self.or = Some(instead.to_string());
        self
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
            if let Some(instead) = &self.or {
                write!(f, ", or {instead}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for NotReady {}

/// A pool on the database called `database`, made on the server first if it is missing.
///
/// The server is the one config.toml names, in the toolchain directory
/// (`dguard::toolchain_dir`). With the local backend this makes the cluster and
/// config.toml when they are missing, and starts the cluster when it is stopped, as the
/// user this process runs as. The file is read on every call, so a daemon that waits on
/// this picks up what `crossfyre` writes while it waits.
pub async fn ensure_ready(database: &str) -> Result<PgPool, NotReady> {
    let dir = dguard::toolchain_dir().ok_or_else(|| {
        NotReady::new(
            format!(
                "there is no home directory to find the toolchain config in. Set {} to the \
                 directory that holds {CONFIG_FILE}",
                dguard::TOOLCHAIN_DIR_ENV
            ),
            None,
        )
    })?;
    ready_in(dir, database).await
}

/// [`ensure_ready`] for the toolchain directory `dir`.
async fn ready_in(dir: PathBuf, database: &str) -> Result<PgPool, NotReady> {
    let path = dir.join(CONFIG_FILE);
    // Making and starting the cluster runs programs and waits on a lock, which the
    // daemon's other tasks should not wait behind.
    let settings = tokio::task::spawn_blocking(move || {
        let account = ThisAccount::new()?;
        Toolchain::new(dir, &account)
            .up()
            .map(|(settings, _)| settings)
    })
    .await
    .map_err(|e| NotReady::new(format!("getting the database ready failed: {e}"), None))??;
    let mut server = connect(&settings, Some(&path), MAINTENANCE_DB).await?;
    let made = make_database(&mut server, database).await;
    let _ = server.close().await;
    made.map_err(|e| {
        NotReady::new(
            format!(
                "could not make the {database} database on {}: {e}",
                settings.address()
            ),
            None,
        )
    })?;
    PgPoolOptions::new()
        .connect_with(settings.options(database))
        .await
        .map_err(|e| not_reached(&settings, Some(&path), e))
}

/// Whether the server `settings` names lets them in. `config` is the config.toml they
/// were read from, or None for settings given that are in no file yet.
pub async fn check(settings: &Settings, config: Option<&Path>) -> Result<(), NotReady> {
    let server = connect(settings, config, MAINTENANCE_DB).await?;
    let _ = server.close().await;
    Ok(())
}

/// One connection to `database`, because its error says why. A pool retries a refused
/// connection until its time is up and then says only that it timed out.
async fn connect(
    settings: &Settings,
    config: Option<&Path>,
    database: &str,
) -> Result<PgConnection, NotReady> {
    tokio::time::timeout(
        ANSWER_WITHIN,
        PgConnection::connect_with(&settings.options(database)),
    )
    .await
    .map_err(|_| {
        NotReady::new(
            format!(
                "the database on {} did not answer within {} seconds",
                settings.address(),
                ANSWER_WITHIN.as_secs()
            ),
            None,
        )
    })?
    .map_err(|e| not_reached(settings, config, e))
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
/// `config` is the config.toml the settings were read from, or None for settings given
/// that are in no file yet.
fn not_reached(settings: &Settings, config: Option<&Path>, e: sqlx::Error) -> NotReady {
    let at = settings.address();
    let Some(config) = config.map(Path::display) else {
        return not_reached_given(settings, e);
    };
    // A database the user runs is fixed by recording it again; the local one by
    // `crossfyre db up` where anything fixes it.
    let record = match &settings.backend {
        Backend::Local => None,
        Backend::External { host } => Some(format!(
            "crossfyre db external {host} {} {}",
            settings.port, settings.user
        )),
    };
    match &e {
        sqlx::Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => match record {
            None => NotReady::new(
                format!("nothing is listening on {at}, where the local database should be"),
                Some(DB_UP),
            ),
            Some(_) => NotReady::new(
                format!("nothing is listening on {at}, where {config} puts the database you run"),
                None,
            ),
        },
        sqlx::Error::Database(db) => match db.code().as_deref() {
            // invalid_password
            Some("28P01") => match &record {
                None => NotReady::new(
                    format!(
                        "the local database refused the password in {config}, which is not the \
                         one it was made with"
                    ),
                    None,
                ),
                Some(record) => NotReady::new(
                    format!("the database on {at} refused the password in {config}"),
                    Some(record),
                ),
            },
            // invalid_authorization_specification: no such user, or a rule of the
            // server's that turns this one away
            Some("28000") => NotReady::new(
                format!(
                    "the database on {at} refused user {}: {}",
                    settings.user,
                    db.message()
                ),
                record.as_deref(),
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

/// [`not_reached`] for settings given on the command line, which only other settings fix.
fn not_reached_given(settings: &Settings, e: sqlx::Error) -> NotReady {
    let at = settings.address();
    let problem = match &e {
        sqlx::Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
            format!("nothing is listening on {at}")
        }
        sqlx::Error::Database(db) => match db.code().as_deref() {
            Some("28P01") => format!(
                "the database on {at} refused the password given for {}",
                settings.user
            ),
            Some("28000") => format!(
                "the database on {at} refused user {}: {}",
                settings.user,
                db.message()
            ),
            _ => format!(
                "the database on {at} refused the connection: {}",
                db.message()
            ),
        },
        _ => format!("cannot reach the database on {at}: {e}"),
    };
    NotReady::new(problem, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::{Stop, Up};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn external_on(port: u16) -> Settings {
        Settings {
            backend: Backend::External {
                host: "127.0.0.1".to_string(),
            },
            port,
            password: Some("pw".to_string()),
            ..Settings::default()
        }
    }

    fn local_on(port: u16) -> Settings {
        Settings {
            port,
            password: Some("pw".to_string()),
            ..Settings::default()
        }
    }

    /// A toolchain directory whose config.toml holds `settings`.
    fn toolchain_with(settings: &Settings) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let toolchain = dir.path().join("crossfyre");
        std::fs::create_dir_all(&toolchain).unwrap();
        std::fs::write(toolchain.join(CONFIG_FILE), settings.to_file()).unwrap();
        (dir, toolchain)
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
        let either = NotReady::new("x is missing".to_string(), Some("get x")).or("use y");
        assert_eq!(either.to_string(), "x is missing. Run `get x`, or use y");
    }

    #[tokio::test]
    async fn a_closed_port_of_a_database_one_runs_says_where_config_puts_it() {
        let port = closed_port();
        let (_dir, toolchain) = toolchain_with(&external_on(port));
        let e = ready_in(toolchain.clone(), "voyage").await.unwrap_err();
        assert_eq!(
            e.problem(),
            format!(
                "nothing is listening on 127.0.0.1:{port}, where {} puts the database you run",
                toolchain.join(CONFIG_FILE).display()
            )
        );
        assert_eq!(e.fix(), None);
    }

    #[tokio::test]
    async fn a_password_a_database_one_runs_refuses_is_recorded_again() {
        let port = refusing_server().await;
        let (_dir, toolchain) = toolchain_with(&external_on(port));
        let e = ready_in(toolchain.clone(), "voyage").await.unwrap_err();
        assert_eq!(
            e.problem(),
            format!(
                "the database on 127.0.0.1:{port} refused the password in {}",
                toolchain.join(CONFIG_FILE).display()
            )
        );
        assert_eq!(
            e.fix().map(str::to_string),
            Some(format!("crossfyre db external 127.0.0.1 {port} postgres"))
        );
    }

    #[tokio::test]
    async fn a_password_given_that_is_refused_is_said_to_be_the_one_given() {
        let port = refusing_server().await;
        let e = check(&external_on(port), None).await.unwrap_err();
        assert_eq!(
            e.problem(),
            format!("the database on 127.0.0.1:{port} refused the password given for postgres")
        );
        assert_eq!(e.fix(), None);
    }

    #[tokio::test]
    async fn the_local_database_refusing_its_password_says_config_changed() {
        let port = refusing_server().await;
        let path = Path::new("/t/config.toml");
        let e = connect(&local_on(port), Some(path), MAINTENANCE_DB)
            .await
            .unwrap_err();
        assert_eq!(
            e.problem(),
            "the local database refused the password in /t/config.toml, which is not the one \
             it was made with"
        );
        assert_eq!(e.fix(), None);
    }

    #[tokio::test]
    async fn the_local_database_not_listening_says_what_starts_it() {
        let port = closed_port();
        let e = connect(&local_on(port), Some(Path::new("/t/c")), MAINTENANCE_DB)
            .await
            .unwrap_err();
        assert_eq!(
            e.problem(),
            format!("nothing is listening on 127.0.0.1:{port}, where the local database should be")
        );
        assert_eq!(e.fix(), Some("crossfyre db up"));
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

    /// `ready_in`, tried again while the server starts, which takes it a few seconds.
    async fn ready_soon(toolchain: &Path, database: &str) -> PgPool {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            match ready_in(toolchain.to_path_buf(), database).await {
                Ok(pool) => return pool,
                Err(e) if std::time::Instant::now() < deadline => {
                    eprintln!("not yet: {e}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[tokio::test]
    #[ignore = "needs Docker and the postgres:16-alpine image"]
    async fn a_missing_database_is_made_on_a_server_one_runs_and_one_there_is_used() {
        let server = Server::start("pw");
        let (_dir, toolchain) = toolchain_with(&external_on(server.port));
        let pool = ready_soon(&toolchain, "cfx_db_test").await;
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

        let again = ready_in(toolchain, "cfx_db_test").await.unwrap();
        let tables: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.tables WHERE table_name = 'kept'",
        )
        .fetch_one(&again)
        .await
        .unwrap();
        assert_eq!(tables, 1, "the database was made again, empty");
    }

    /// A free port for a local database of a test's own.
    fn free_port() -> u16 {
        closed_port()
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn the_local_database_is_made_started_stopped_and_kept() {
        let (_dir, toolchain) = toolchain_with(&local_on(free_port()));
        let account = ThisAccount::new().unwrap();
        let tc = Toolchain::new(toolchain.clone(), &account);

        let pool = ready_in(toolchain.clone(), "cfx_db_test").await.unwrap();
        sqlx::query("CREATE TABLE kept (n int)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kept VALUES (7)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let listens: String = {
            let mut c = connect(
                &tc.settings().unwrap(),
                Some(Path::new("c")),
                MAINTENANCE_DB,
            )
            .await
            .unwrap();
            sqlx::query_scalar("SHOW listen_addresses")
                .fetch_one(&mut c)
                .await
                .unwrap()
        };
        assert_eq!(listens, "127.0.0.1");
        assert_eq!(tc.up().unwrap().1, Up::Running);

        assert_eq!(tc.stop().unwrap(), Stop::Stopped);
        assert_eq!(tc.stop().unwrap(), Stop::NotRunning);
        assert!(!tc.status().unwrap().unwrap().running);

        let again = ready_in(toolchain.clone(), "cfx_db_test").await.unwrap();
        let n: i32 = sqlx::query_scalar("SELECT n FROM kept")
            .fetch_one(&again)
            .await
            .unwrap();
        assert_eq!(n, 7, "the data did not survive a stop and a start");
        again.close().await;
        assert!(tc.status().unwrap().unwrap().running);
        assert_eq!(tc.stop().unwrap(), Stop::Stopped);
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn engines_starting_at_once_make_one_database() {
        let (_dir, toolchain) = toolchain_with(&local_on(free_port()));
        let names = ["voyage", "doorward", "ambulo"];
        let pools = futures_join(names.map(|name| {
            let toolchain = toolchain.clone();
            tokio::spawn(async move { ready_in(toolchain, name).await })
        }))
        .await;
        for (name, pool) in names.iter().zip(pools) {
            let pool = pool.unwrap().unwrap_or_else(|e| panic!("{name}: {e}"));
            let here: String = sqlx::query_scalar("SELECT current_database()")
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(&here, name);
            pool.close().await;
        }
        let account = ThisAccount::new().unwrap();
        let tc = Toolchain::new(toolchain, &account);
        assert!(tc.cluster_dir().join("PG_VERSION").is_file());
        assert_eq!(tc.stop().unwrap(), Stop::Stopped);
    }

    /// Every handle's result, in order.
    async fn futures_join<T>(
        handles: [tokio::task::JoinHandle<T>; 3],
    ) -> Vec<Result<T, tokio::task::JoinError>> {
        let mut out = Vec::new();
        for h in handles {
            out.push(h.await);
        }
        out
    }
}

//! A database of a test's own: a local cluster in a temporary directory, made and started
//! for one test and stopped when it ends, with an engine's schema ready in it.
//!
//! cfx_db's own tests use it, and so can another crate's, by taking cfx_db as a
//! dev-dependency with the `testing` feature. Tests that start a database need
//! PostgreSQL's programs, so they are marked `#[ignore = "needs PostgreSQL's programs"]`
//! and run with `cargo test -- --ignored`, with XDG_RUNTIME_DIR unset so that nothing
//! goes to the user's service manager.

use crate::settings::CONFIG_FILE;
use crate::{Engine, Settings, Stop, ThisAccount, Toolchain};
use sqlx::PgPool;
use std::path::PathBuf;

/// Settings for the local database on `port`.
pub fn local_on(port: u16) -> Settings {
    Settings {
        port,
        password: Some("pw".to_string()),
        ..Settings::default()
    }
}

/// A toolchain directory whose config.toml holds `settings`.
pub fn toolchain_with(settings: &Settings) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let toolchain = dir.path().join("crossfyre");
    std::fs::create_dir_all(&toolchain).expect("the toolchain directory");
    std::fs::write(toolchain.join(CONFIG_FILE), settings.to_file()).expect("config.toml");
    (dir, toolchain)
}

/// A port nothing listens on, which stays this test's while what comes with it is held,
/// so no test running meanwhile is given it by the system and answers on it. That is a
/// socket bound to it and not listening, which refuses every connection. macOS drops a
/// connection to such a socket unanswered, so a connect there waits for its timeout
/// instead of being refused; on macOS the port is the local end of a connection to a
/// listener of its own, which refuses a new connection at once.
pub fn closed_port() -> (u16, impl Send) {
    #[cfg(not(target_os = "macos"))]
    {
        let socket = bound();
        (socket.local_addr().expect("its address").port(), socket)
    }
    #[cfg(target_os = "macos")]
    {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let near = std::net::TcpStream::connect(l.local_addr().expect("its address"))
            .expect("a connection");
        let (far, _) = l.accept().expect("the connection");
        (near.local_addr().expect("its address").port(), (near, far))
    }
}

/// A free port for a local database of a test's own, which its server binds.
pub fn free_port() -> u16 {
    bound().local_addr().expect("its address").port()
}

/// A socket bound to a port of the system's choosing on 127.0.0.1, not listening.
fn bound() -> tokio::net::TcpSocket {
    let socket = tokio::net::TcpSocket::new_v4().expect("a socket");
    socket
        .bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
        .expect("a port");
    socket
}

/// A local database of a test's own, with an engine's schema ready in it. [`Scratch::done`]
/// stops it; a test that fails before then leaves its server to stop with its directory.
pub struct Scratch {
    _dir: tempfile::TempDir,
    toolchain: PathBuf,
    /// A pool on the engine's schema.
    pub pool: PgPool,
}

impl Scratch {
    /// A local database made and started in a directory of its own, on a free port, with
    /// `engine`'s schema made in it.
    pub async fn new(engine: &Engine) -> Self {
        let (dir, toolchain) = toolchain_with(&local_on(free_port()));
        let pool = crate::ready::ready_in(toolchain.clone(), engine)
            .await
            .expect("a database of the test's own");
        Self {
            _dir: dir,
            toolchain,
            pool,
        }
    }

    /// The toolchain directory the database is in.
    pub fn toolchain(&self) -> &std::path::Path {
        &self.toolchain
    }

    /// Close the pool and stop the database.
    pub async fn done(self) {
        self.pool.close().await;
        let account = ThisAccount::new().expect("this account");
        assert_eq!(
            Toolchain::new(self.toolchain.clone(), &account)
                .stop()
                .expect("stopping the database"),
            Stop::Stopped
        );
    }
}

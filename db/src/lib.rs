//! The engines' Postgres: which database they use, making and running the local one,
//! reaching either, each engine's schema in it, and what to run when it cannot be
//! reached.
//!
//! The engines keep their state in one database on one Postgres server. Which server,
//! and how to log in to it, is the `[postgres]` section of the toolchain's `config.toml`,
//! which `crossfyre` writes and the engines read. [`Settings`] is that section for both
//! of them. Its backend is either the local database, a cluster crossfyre makes in the
//! toolchain directory and runs as the user that directory belongs to, or a server the
//! user runs themselves. In the database each engine has a schema of its own, named
//! after it, whose tables its numbered SQL files make: see [`Engine`].
//!
//! An engine daemon gets its schema from [`ensure_ready`], which makes and starts the
//! local database when it has to and brings the schema up to date. When it cannot, the
//! [`NotReady`] it gets instead says what is wrong and, where one command fixes it,
//! which. The tables every engine has are read and written through [`scans`].
//! `crossfyre db` works on the same [`Toolchain`].

mod account;
mod local;
mod migrate;
mod ready;
pub mod scans;
mod settings;
mod toolchain;

#[cfg(unix)]
pub use account::lock_file;
pub use account::{Account, ThisAccount};
pub use local::{Postgres, find_postgres};
pub use migrate::{Engine, Migrated};
pub use ready::{NotReady, check, ensure_ready};
pub use settings::{Backend, FROM_DOCKER_DAYS, Settings, config_unreadable, new_password};
pub use toolchain::{Status, Stop, Toolchain, Up};

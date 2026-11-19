//! The engines' Postgres: which database they use, making and running the local one,
//! reaching either, and what to run when it cannot be reached.
//!
//! ambulo, doorward and voyage keep their state in one Postgres server. Which one, and
//! how to log in to it, is the `[postgres]` section of the toolchain's `config.toml`,
//! which `crossfyre` writes and the engines read. [`Settings`] is that section for both
//! of them. Its backend is either the local database, a cluster crossfyre makes in the
//! toolchain directory and runs as the user that directory belongs to, or a server the
//! user runs themselves.
//!
//! An engine daemon gets its database from [`ensure_ready`], which makes and starts the
//! local one when it has to. When it cannot, the [`NotReady`] it gets instead says what
//! is wrong and, where one command fixes it, which. `crossfyre db` works on the same
//! [`Toolchain`].

mod account;
mod local;
mod ready;
mod settings;
mod toolchain;

#[cfg(unix)]
pub use account::lock_file;
pub use account::{Account, ThisAccount};
pub use local::{Postgres, find_postgres};
pub use ready::{NotReady, check, ensure_ready};
pub use settings::{Backend, Settings, new_password};
pub use toolchain::{Status, Stop, Toolchain, Up};

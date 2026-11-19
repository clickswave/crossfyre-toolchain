//! The engines' Postgres: where it is, how to reach it, and what to run when it cannot be
//! reached.
//!
//! ambulo, doorward and voyage keep their state in one Postgres server. Where it is and
//! how to log in to it is the `[postgres]` section of the toolchain's `config.toml`,
//! which `crossfyre` writes and the engines read. [`Settings`] is that section for both
//! of them.
//!
//! An engine daemon gets its database from [`ensure_ready`]. When it cannot, the
//! [`NotReady`] it gets instead says what is wrong and, where one command fixes it, which.

mod ready;
mod settings;

pub use ready::{NotReady, ensure_ready};
pub use settings::{Settings, new_password};

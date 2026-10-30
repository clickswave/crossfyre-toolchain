//! The Cloud backend: a workspace on the Crossfyre platform, reached with an MCP key.
//!
//! The key is read from a file only its owner can read, or from the environment when
//! there is no file, and goes nowhere but the `Authorization` header of a request to
//! the origin it was saved with. `crossfyre mcp cloud login` checks a key with the
//! platform before it writes the file.

pub(crate) mod client;
pub(crate) mod file;
pub(crate) mod login;

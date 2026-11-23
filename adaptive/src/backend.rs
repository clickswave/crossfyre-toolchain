//! Where an answer comes from: this crate's baseline, or a module installed at run time.
//!
//! A [`Backend`] is installed once per process, by the engine at start (the `cfx_pacing`
//! crate loads one when a verified module is present). With one installed, the functions
//! of this crate that have a module answer ask it first, through one call each, JSON in
//! and out, and keep the baseline's answer when the module gives none or an answer that
//! does not read. Whatever the module answers is held to the bounds the caller gave
//! before it is used, so a module can never take a scan past what this code allows.
//! Without one, the baseline answers, as it always has.

use serde::{Serialize, de::DeserializeOwned};
use std::sync::OnceLock;

/// The version of the interface between this crate and a module. A module states the
/// one it implements, and one of another version is not installed.
pub const INTERFACE: u32 = 1;

/// A module that answers this crate's calls.
pub trait Backend: Send + Sync {
    /// The module's own version, said where the engine says which pacing it runs.
    fn version(&self) -> &str;
    /// The answer to `op` for `input`, both JSON, or None when the module failed or
    /// has no answer for it.
    fn call(&self, op: &str, input: &[u8]) -> Option<Vec<u8>>;
}

static BACKEND: OnceLock<Box<dyn Backend>> = OnceLock::new();

/// Install `backend` for the rest of the process. False when one is installed already,
/// which is left in place.
pub fn install(backend: Box<dyn Backend>) -> bool {
    BACKEND.set(backend).is_ok()
}

/// Which pacing answers in this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pacing {
    /// This crate's own, with no module installed.
    Baseline,
    /// A module, by its version.
    Module(String),
}

impl Pacing {
    /// As an engine says it: `baseline`, or `module <version>`.
    pub fn label(&self) -> String {
        match self {
            Pacing::Baseline => "baseline".to_string(),
            Pacing::Module(v) => format!("module {v}"),
        }
    }
}

/// Which pacing answers in this process.
pub fn pacing() -> Pacing {
    match BACKEND.get() {
        Some(b) => Pacing::Module(b.version().to_string()),
        None => Pacing::Baseline,
    }
}

/// Whether a module is installed.
pub(crate) fn installed() -> bool {
    BACKEND.get().is_some()
}

/// The installed module's answer to `op` for `input`, read as `O`, or None.
pub(crate) fn ask<I: Serialize, O: DeserializeOwned>(op: &str, input: &I) -> Option<O> {
    let backend = BACKEND.get()?;
    let asked = serde_json::to_vec(input).ok()?;
    let answer = backend.call(op, &asked)?;
    serde_json::from_slice(&answer).ok()
}

/// The answer to a call whose answer cannot change within a process, as `held` keeps
/// it: asked once a module is installed, then kept, the refusal included. Without a
/// module nothing is asked or kept, so one installed later is still asked.
pub(crate) fn ask_once<I: Serialize, A: DeserializeOwned, O: Clone>(
    kept: &OnceLock<Option<O>>,
    op: &str,
    input: &I,
    held: impl FnOnce(A) -> Option<O>,
) -> Option<O> {
    if !installed() {
        return None;
    }
    kept.get_or_init(|| ask(op, input).and_then(held)).clone()
}

/// A header name a module may give: an HTTP token of at most 64 characters.
pub(crate) fn is_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A header value a module may give: printable ASCII, spaces and tabs, no line
/// breaks, at most 1024 bytes.
pub(crate) fn is_header_value(s: &str) -> bool {
    s.len() <= 1024 && s.bytes().all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
}

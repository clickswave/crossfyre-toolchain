//! What a template scan keeps between its steps, as the engine sees it: the templates it
//! runs, and where each one is. The daemon gives the engine a [`Ledger`] backed by its
//! database, so the engine never holds the database itself.

use serde_json::Value;
use std::collections::HashSet;
use std::future::Future;

/// Where a template of a scan is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not run yet. A scan taken up again runs these.
    Queued,
    /// Run, and nothing found.
    Sent,
    /// Run, and waiting on an out-of-band callback to confirm what it found. A scan
    /// stopped before the callback could come runs it again when taken up.
    Matched,
    /// Run, and what it found confirmed.
    Confirmed,
    /// Not run, because what it sends changes the target.
    HeldBack,
    /// Not run, for the reason given with it.
    Skipped,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Queued => "queued",
            State::Sent => "sent",
            State::Matched => "matched",
            State::Confirmed => "confirmed",
            State::HeldBack => "held_back",
            State::Skipped => "skipped",
        }
    }
}

/// A template of a scan's plan, with where it starts and why, when it is not run.
pub struct Planned {
    pub id: String,
    pub state: State,
    pub reason: Option<&'static str>,
}

/// What a scan's plan came to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Planning {
    /// The templates a scan taken up again had run to their end, which this run leaves
    /// out.
    pub done: HashSet<String>,
    /// What those templates found, reported again, so that a scan taken up again reports
    /// all it found.
    pub found: Vec<Value>,
    /// The scan was taken up again, but the templates it started with are gone, so its
    /// plan was made again and it starts over.
    pub replanned: bool,
}

/// Where a template scan's plan and the state of each of its templates are kept.
pub trait Ledger: Send + Sync + 'static {
    /// The scan's plan: its templates in order under `pack`, a digest of the templates
    /// there are to run.
    fn plan(&self, pack: &str, templates: &[Planned]) -> impl Future<Output = Planning> + Send;

    /// Where template `id` is now.
    fn state(&self, id: &str, state: State) -> impl Future<Output = ()> + Send;
}

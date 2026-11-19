//! What a scan keeps while it runs, as the scanner sees it: the names left to try, and
//! what trying each one found. The daemon hands the scanner a [`Store`] backed by its
//! database, so the scanner never holds the database itself.

use std::future::Future;

/// A name to try, taken by one worker so that no other worker tries it too.
pub struct Work {
    pub entry_id: i64,
    pub full_subdomain: String,
}

/// A name a passive source reported, and which source.
pub struct PassiveResult {
    pub full_subdomain: String,
    pub source: String,
}

/// Where a scan's names, and what was found about each, are kept. An error is the
/// store's own account of what failed, for the scan's log.
pub trait Store: Send + Sync + 'static {
    /// The names the passive sources reported for scan `scan`.
    fn passive_results(
        &self,
        scan: &str,
    ) -> impl Future<Output = Result<Vec<PassiveResult>, String>> + Send;

    /// The next name of `scan` to try, or None when every name has been taken.
    fn claim(&self, scan: &str) -> impl Future<Output = Result<Option<Work>, String>> + Send;

    /// Whether a name of `scan` is still being tried by some worker.
    fn trying(&self, scan: &str) -> impl Future<Output = Result<bool, String>> + Send;

    /// What trying the name of entry `entry` found: `found` or `not_found`, and the
    /// technique that found it.
    fn record(
        &self,
        entry: i64,
        status: &str,
        source: &str,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// Give back a name a worker took and could not finish, to be tried again.
    fn release(&self, entry: i64) -> impl Future<Output = Result<(), String>> + Send;

    /// How many names of `scan` were found, and how many were not.
    fn totals(&self, scan: &str) -> impl Future<Output = Result<(i64, i64), String>> + Send;
}

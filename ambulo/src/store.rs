//! What a scan keeps while it runs, as the scanner sees it: the requests left to send,
//! what each one got back, and the scan's log. The daemon hands the scanner a [`Store`]
//! for one scan, backed by its database, so the scanner never holds the database itself.

use crate::scanner::ScanResults;
use std::future::Future;

/// A request to send, taken by one worker so that no other worker sends it too.
pub struct Work {
    pub url: String,
    pub entry_id: i64,
    pub method: String,
}

/// What one request got back. The response itself is not kept: its status, its code and
/// how long it was are what a result says.
pub struct Outcome<'a> {
    /// `found`, `not_found` or `error`.
    pub status: &'a str,
    /// The HTTP status code, or what stands in for one when there was no response.
    pub code: &'a str,
    pub body_length: i64,
    pub headers_length: i64,
}

/// Where one scan's requests, what each got back, and its log are kept. An error is the
/// store's own account of what failed, for the scan's log.
pub trait Store: Send + Sync + 'static {
    /// The next request of the scan to send, or None when every one has been taken.
    fn claim(&self) -> impl Future<Output = Result<Option<Work>, String>> + Send;

    /// What sending the request of entry `entry` got back.
    fn record(
        &self,
        entry: i64,
        outcome: Outcome<'_>,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// Give back a request a worker took and could not finish, to be sent again.
    fn release(&self, entry: i64) -> impl Future<Output = Result<(), String>> + Send;

    /// What the scan has found so far.
    fn results(&self) -> impl Future<Output = Result<ScanResults, String>> + Send;

    /// A line for the scan's log, kept when it is at the scan's log level or above.
    fn log(&self, level: &str, message: &str) -> impl Future<Output = ()> + Send;
}

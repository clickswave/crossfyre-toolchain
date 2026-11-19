//! What a fingerprint saw, handed to whoever keeps it. The daemon keeps it in its
//! database; the fingerprint itself never holds one.

use std::future::Future;

/// A page a fingerprint fetched: the landing page, or a path a signature asked for.
pub struct Observation<'a> {
    pub url: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub scheme: &'a str,
    pub status: u16,
    /// Each header's name, in lower case, and value.
    pub headers: &'a [(String, String)],
    /// The body as read, which reading caps.
    pub body: &'a [u8],
}

/// Where what a fingerprint saw goes.
pub trait Observer: Send + Sync + 'static {
    fn observed(&self, observation: Observation<'_>) -> impl Future<Output = ()> + Send;
}

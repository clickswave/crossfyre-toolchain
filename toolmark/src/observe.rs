//! What a fingerprint saw, handed to whoever keeps it. The daemon keeps it in its
//! database; the fingerprint itself never holds one.

use std::future::Future;

/// What a page was fetched for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asked {
    /// The page the target is.
    Landing,
    /// One of the two random paths that learn the host's not-found page.
    NotFound,
    /// A path a signature asked for.
    Path,
    /// The landing page as a browser built it, at the rendered tier.
    Rendered,
}

impl Asked {
    /// As the observations table writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Asked::Landing => "landing",
            Asked::NotFound => "not_found",
            Asked::Path => "path",
            Asked::Rendered => "rendered",
        }
    }

    /// From what the observations table wrote.
    pub fn from_str(text: &str) -> Option<Self> {
        Some(match text {
            "landing" => Asked::Landing,
            "not_found" => Asked::NotFound,
            "path" => Asked::Path,
            "rendered" => Asked::Rendered,
            _ => return None,
        })
    }
}

/// A page a fingerprint saw: the landing page, a path a signature asked for, or the
/// landing page as a browser built it.
pub struct Observation<'a> {
    /// What it was fetched for.
    pub asked: Asked,
    pub url: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub scheme: &'a str,
    pub status: u16,
    /// Each header's name, in lower case, and value.
    pub headers: &'a [(String, String)],
    /// The body as read, which reading caps.
    pub body: &'a [u8],
    /// The request ended somewhere other than where it was sent, through a redirect.
    pub moved: bool,
    /// The certificate its server presented, DER encoded, for a landing page that came
    /// over TLS.
    pub certificate: Option<&'a [u8]>,
}

/// Where what a fingerprint saw goes.
pub trait Observer: Send + Sync + 'static {
    fn observed(&self, observation: Observation<'_>) -> impl Future<Output = ()> + Send;
}

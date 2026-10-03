//! The capture core's [`ExchangeSink`], writing into a [`Project`].
//!
//! This is the join that makes the proxy local-first: with one of these attached, a capture
//! session records to a file on the operator's machine and needs no control plane to
//! function. Without one, nothing is stored locally, which is the behaviour everything had
//! before.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cfx_capture::{ExchangeSink, RawExchange};

use crate::{Exchange, Project};

/// How many exchanges go in between cap checks, by default.
///
/// Not every one. Checking means two pragmas and a SUM over the blob table, which is
/// cheap on its own and silly to run on every request of a capture doing hundreds a
/// second. Overshooting the cap by a few dozen exchanges between checks is not a problem a
/// cap exists to solve.
pub const CHECK_CAP_EVERY: usize = 64;

pub struct ProjectSink {
    project: Arc<Project>,
    since_check: AtomicUsize,
    check_every: usize,
}

impl ProjectSink {
    pub fn new(project: Arc<Project>) -> Self {
        Self::with_check_interval(project, CHECK_CAP_EVERY)
    }

    /// Mostly for tests, which want the cap to act at a known point.
    pub fn with_check_interval(project: Arc<Project>, check_every: usize) -> Self {
        Self {
            project,
            since_check: AtomicUsize::new(0),
            check_every: check_every.max(1),
        }
    }

    pub fn project(&self) -> &Arc<Project> {
        &self.project
    }
}

impl std::fmt::Debug for ProjectSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectSink")
            .field("project", &self.project.path())
            .finish()
    }
}

impl ExchangeSink for ProjectSink {
    fn record<'a>(
        &'a self,
        ex: &'a RawExchange,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            // Logged, never propagated. The trait says so and the reason is worth keeping
            // in view: a store that cannot take a row has lost that row, which is bad, and
            // failing the request the operator is watching would be worse. A capture that
            // quietly stops recording is the failure mode this logging exists to make
            // visible, so it is an error line and not a debug one.
            if let Err(e) = self.project.insert(&from_raw(ex)).await {
                log::error!("project store: dropping {} {}: {e}", ex.method, ex.url);
                return;
            }

            if self.since_check.fetch_add(1, Ordering::Relaxed) + 1 >= self.check_every {
                self.since_check.store(0, Ordering::Relaxed);
                match self.project.enforce_cap().await {
                    Ok(ev) if ev.exchanges > 0 => {
                        log::info!(
                            "project store: evicted {} exchange(s) to stay under the cap",
                            ev.exchanges
                        );
                    }
                    Ok(ev) if ev.kept_pinned > 0 => {
                        // The cap cannot be met without breaking a promise, so say so
                        // rather than looping on it every time the interval comes round.
                        log::warn!(
                            "project store: over its cap and cannot shrink, because all {} \
                             remaining exchanges are pinned",
                            ev.kept_pinned
                        );
                    }
                    Ok(_) => {}
                    Err(e) => log::error!("project store: cap check failed: {e}"),
                }
            }
        })
    }
}

/// A captured exchange as the store wants it.
///
/// Bodies move across as bytes, which is the whole point of [`RawExchange`] existing
/// alongside the trace event.
fn from_raw(ex: &RawExchange) -> Exchange {
    Exchange {
        at_ms: ex.at_ms,
        method: ex.method.clone(),
        url: ex.url.clone(),
        host: ex.host.clone(),
        // Zero is not an HTTP status. It reaches here only if an upstream leg reported one
        // without having answered, and recording it as a status would put a `0` in a column
        // a reader will compare against 200 and 404.
        status: (ex.status > 0).then_some(ex.status),
        duration_ms: Some(ex.duration_ms as i64),
        req_headers: pairs(&ex.req_headers),
        resp_headers: pairs(&ex.resp_headers),
        req_body: ex.req_body.clone(),
        resp_body: ex.resp_body.clone(),
    }
}

fn pairs(h: &[(String, String)]) -> Vec<[String; 2]> {
    h.iter().map(|(k, v)| [k.clone(), v.clone()]).collect()
}

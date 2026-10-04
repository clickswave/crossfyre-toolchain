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
    /// Exchanges handed over and not yet written. Unbounded because dropping a capture to
    /// keep a queue short would defeat the point of having one.
    tx: tokio::sync::mpsc::UnboundedSender<RawExchange>,
    /// How many are still in flight, so `flush` knows when there is nothing left.
    pending: Arc<AtomicUsize>,
    drained: Arc<tokio::sync::Notify>,
}

impl ProjectSink {
    pub fn new(project: Arc<Project>) -> Self {
        Self::with_check_interval(project, CHECK_CAP_EVERY)
    }

    /// Mostly for tests, which want the cap to act at a known point.
    pub fn with_check_interval(project: Arc<Project>, check_every: usize) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<RawExchange>();
        let pending = Arc::new(AtomicUsize::new(0));
        let drained = Arc::new(tokio::sync::Notify::new());
        let check_every = check_every.max(1);

        // One writer, so exchanges land in the order they completed and two inserts never
        // race for the same connection.
        {
            let project = project.clone();
            let pending = pending.clone();
            let drained = drained.clone();
            tokio::spawn(async move {
                let mut since_check = 0usize;
                while let Some(ex) = rx.recv().await {
                    // Logged, never propagated. A store that cannot take a row has lost
                    // that row, which is bad, and there is nobody here to tell: the
                    // request it belonged to finished some time ago. A capture that
                    // quietly stops recording is the failure this logging exists to make
                    // visible, so it is an error line and not a debug one.
                    if let Err(e) = project.insert(&from_raw(&ex)).await {
                        log::error!("project store: dropping {} {}: {e}", ex.method, ex.url);
                    } else {
                        since_check += 1;
                        if since_check >= check_every {
                            since_check = 0;
                            check_cap(&project).await;
                        }
                    }
                    if pending.fetch_sub(1, Ordering::AcqRel) == 1 {
                        drained.notify_waiters();
                    }
                }
            });
        }

        Self {
            project,
            tx,
            pending,
            drained,
        }
    }

    pub fn project(&self) -> &Arc<Project> {
        &self.project
    }
}

async fn check_cap(project: &Project) {
    match project.enforce_cap().await {
        Ok(ev) if ev.exchanges > 0 => {
            log::info!(
                "project store: evicted {} exchange(s) to stay under the cap",
                ev.exchanges
            );
        }
        Ok(ev) if ev.kept_pinned > 0 => {
            // The cap cannot be met without breaking a promise, so say so rather than
            // looping on it every time the interval comes round.
            log::warn!(
                "project store: over its cap and cannot shrink, because all {} remaining \
                 exchanges are pinned",
                ev.kept_pinned
            );
        }
        Ok(_) => {}
        Err(e) => log::error!("project store: cap check failed: {e}"),
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
    fn record(&self, ex: RawExchange) {
        // Counted BEFORE it is sent, so a `flush` that arrives between the two cannot
        // conclude there is nothing left to wait for.
        self.pending.fetch_add(1, Ordering::AcqRel);
        if self.tx.send(ex).is_err() {
            // The writer is gone, which happens only after the runtime is shutting down.
            self.pending.fetch_sub(1, Ordering::AcqRel);
            log::error!("project store: the writer has stopped; an exchange was lost");
        }
    }

    fn flush<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            while self.pending.load(Ordering::Acquire) > 0 {
                // Registered before the re-check, so a writer finishing in between still
                // wakes this rather than leaving it parked on a queue that is already
                // empty.
                let waiter = self.drained.notified();
                if self.pending.load(Ordering::Acquire) == 0 {
                    break;
                }
                waiter.await;
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
        resp_len: ex.resp_len,
    }
}

fn pairs(h: &[(String, String)]) -> Vec<[String; 2]> {
    h.iter().map(|(k, v)| [k.clone(), v.clone()]).collect()
}

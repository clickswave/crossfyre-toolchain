//! An [`InterceptGate`] that parks requests in this process, for a host with a UI attached.
//!
//! The gates that existed before this one park a request with the control plane and poll
//! for a verdict (`intercept-hold`, `intercept-poll`), which costs a round trip and a
//! second of latency per decision and cannot work at all with no network. A local
//! workbench holds the request in memory, shows it to the operator, and resolves it the
//! moment they click.
//!
//! # Why this fails CLOSED
//!
//! The trait's own note says an implementation may return `Forward` on error to keep
//! traffic flowing, and the polling gates do exactly that after about two minutes. This
//! one does the opposite, deliberately.
//!
//! Interception is a promise: with it on, nothing reaches the target that the operator has
//! not seen. A gate that forwards whatever it could not ask about breaks that promise
//! quietly, and the operator's evidence then includes requests they never approved. A gate
//! that drops instead breaks a browser visibly, which is a complaint rather than a wrong
//! conclusion. For a remote gate over a flaky network, fail-open is the better trade and
//! that is why those keep it. For a gate whose decider is a window on the same machine,
//! an unanswered request means the UI is gone or wedged, and not sending is the safe half.
//!
//! [`LocalGate::with_timeout`] exists for a host that wants the other trade, and it has to
//! name the decision it wants on expiry rather than inheriting one.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, oneshot};

use crate::{InterceptDecision, InterceptGate};

/// A request being held for a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// Identifies this hold for [`LocalGate::resolve`]. Unique for the gate's lifetime.
    pub id: u64,
    pub method: String,
    /// The full URL, values included: this is what the operator is being asked about.
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

struct State {
    /// Oldest first, which is the order a queue should be worked and shown in.
    waiting: VecDeque<(Held, oneshot::Sender<InterceptDecision>)>,
    /// Set by [`LocalGate::shutdown`]. Everything already waiting is dropped and anything
    /// arriving afterwards is dropped on arrival rather than parked for a UI that has gone.
    closed: bool,
}

pub struct LocalGate {
    state: Mutex<State>,
    arrived: Notify,
    next_id: AtomicU64,
    /// `None` holds until somebody decides, which is what a local operator expects.
    timeout: Option<Duration>,
    on_timeout: InterceptDecision,
}

impl Default for LocalGate {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalGate {
    /// Hold each request until it is resolved, with no deadline.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                waiting: VecDeque::new(),
                closed: false,
            }),
            arrived: Notify::new(),
            next_id: AtomicU64::new(1),
            timeout: None,
            on_timeout: InterceptDecision::Drop,
        }
    }

    /// Give up on a request after `after`, resolving it as `then`.
    ///
    /// `then` is required rather than defaulted, because a host that wants a deadline is
    /// choosing between a browser that stalls and traffic the operator never saw, and that
    /// choice should appear at the call site.
    pub fn with_timeout(after: Duration, then: InterceptDecision) -> Self {
        Self {
            timeout: Some(after),
            on_timeout: then,
            ..Self::new()
        }
    }

    /// Everything waiting, oldest first.
    pub fn pending(&self) -> Vec<Held> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .waiting
            .iter()
            .map(|(h, _)| h.clone())
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .waiting
            .len()
    }

    /// Resolve one held request. False if that id is not waiting, which covers a UI acting
    /// on a stale list and a double click on the same row.
    pub fn resolve(&self, id: u64, decision: InterceptDecision) -> bool {
        let sender = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let Some(i) = st.waiting.iter().position(|(h, _)| h.id == id) else {
                return false;
            };
            st.waiting.remove(i).map(|(_, tx)| tx)
        };
        // Sent with the lock released: the receiving task may run immediately and ask the
        // gate something.
        match sender {
            Some(tx) => tx.send(decision).is_ok(),
            None => false,
        }
    }

    /// Resolve everything waiting the same way, for a "forward all" button.
    pub fn resolve_all(&self, decision: InterceptDecision) -> usize {
        let drained: Vec<_> = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.waiting.drain(..).collect()
        };
        let n = drained.len();
        for (_, tx) in drained {
            let _ = tx.send(decision.clone());
        }
        n
    }

    /// Wait until a request arrives. For a UI that would otherwise poll.
    ///
    /// Returns immediately if something is already waiting, so a caller cannot miss an
    /// arrival that happened between checking and awaiting.
    pub async fn arrival(&self) {
        if self.pending_count() > 0 {
            return;
        }
        self.arrived.notified().await;
    }

    /// Stop intercepting: drop what is held and drop what arrives next.
    ///
    /// Called when the operator closes the session or the window. Dropping rather than
    /// forwarding, because a request released by a UI that is going away is one nobody
    /// looked at, and the point of the gate was that somebody would.
    pub fn shutdown(&self) -> usize {
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.closed = true;
        }
        self.resolve_all(InterceptDecision::Drop)
    }

    pub fn is_shut_down(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed
    }

    /// Take a hold back out of the queue without answering it, for the timeout path.
    fn forget(&self, id: u64) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = st.waiting.iter().position(|(h, _)| h.id == id) {
            st.waiting.remove(i);
        }
    }
}

impl std::fmt::Debug for LocalGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalGate")
            .field("pending", &self.pending_count())
            .field("timeout", &self.timeout)
            .field("closed", &self.is_shut_down())
            .finish()
    }
}

impl InterceptGate for LocalGate {
    fn decide<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = InterceptDecision> + Send + 'a>> {
        Box::pin(async move {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let held = Held {
                id,
                method: method.to_string(),
                url: url.to_string(),
                headers: headers.to_vec(),
                body: body.to_vec(),
            };
            let rx = {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if st.closed {
                    return InterceptDecision::Drop;
                }
                let (tx, rx) = oneshot::channel();
                st.waiting.push_back((held, tx));
                rx
            };
            // Notified with the lock released, so a waiter that wakes immediately does not
            // find the queue locked by the task that just filled it.
            self.arrived.notify_waiters();

            match self.timeout {
                None => rx.await.unwrap_or(InterceptDecision::Drop),
                Some(d) => match tokio::time::timeout(d, rx).await {
                    Ok(Ok(decision)) => decision,
                    // Expired, or the sender went away. Either way this hold is still in
                    // the queue and has to come out, or a UI shows a row nobody is waiting
                    // on any more.
                    _ => {
                        self.forget(id);
                        log::warn!(
                            "intercept: no decision for {method} {} within {d:?}, applying \
                             the configured timeout action",
                            url.split('?').next().unwrap_or("")
                        );
                        self.on_timeout.clone()
                    }
                },
            }
        })
    }
}

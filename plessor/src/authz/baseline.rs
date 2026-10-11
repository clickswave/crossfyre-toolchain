//! Authorization-testing baseline (open build): no differential oracle.
//!
//! The full authorization engine (the differential identity matrix, privilege-aware
//! pairing, confirm-before-report, and the BOPLA data-exposure probe) is a platform
//! feature that ships in Crossfyre's distributed engine builds. This open build
//! validates the job and reports plainly that the oracle is not compiled in, rather
//! than silently returning no findings as if it had run - the same honesty the
//! isolated-egress baseline follows.

use super::AuthzParams;
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// Authorization-testing entry point (open build). Acks, then completes cleanly so
/// a workflow that includes an authz step does not hang or error - but performs no
/// authorization oracle. The full engine is a platform feature.
pub async fn run(params: AuthzParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({ "type": "ack", "target": params.target }));
    eprintln!(
        "[authz] the authorization oracle (BOLA/BFLA/BOPLA) is a Crossfyre platform \
         feature; this open build does not include it. Reporting no findings."
    );
    let _ = tx.send(json!({ "type": "done", "found": 0 }));
}

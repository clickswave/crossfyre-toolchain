//! Authorization-testing baseline (open build): no differential oracle.
//!
//! Authorization testing runs in plessor-authz, a component that comes with a Crossfyre
//! plan that includes it, rather than in the open plessor. A node sends `authz` there
//! when it is installed, and here when it is not, so this says what is needed, as a
//! note on the operation the platform shows, and completes with no findings rather
//! than silently returning none as if it had run.

use super::AuthzParams;
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// What a run here says: that the component is needed, and how to get it.
pub const NEEDS_THE_COMPONENT: &str = "Authorization testing needs plessor-authz, which comes \
     with a Crossfyre plan that includes it. Log in with `crossfyre login`, and it is \
     installed with `crossfyre update`. This run reported no findings.";

/// Authorization-testing entry point (open build). Acks, says what is needed, and
/// completes cleanly, so a workflow that includes an authz step does not hang or error.
pub async fn run(params: AuthzParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({ "type": "ack", "target": params.target }));
    eprintln!("[authz] {NEEDS_THE_COMPONENT}");
    let _ = tx.send(json!({ "type": "log", "message": NEEDS_THE_COMPONENT }));
    let _ = tx.send(json!({ "type": "done", "found": 0 }));
}

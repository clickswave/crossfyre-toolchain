//! Per-engine operation handlers, extracted from the run_operation()
//! dispatcher. Each handler owns an [`OpEnv`] for the lifetime of one
//! dispatched operation: it runs the engine, streams results/progress onto
//! NATS, and publishes the terminal `operation_completed`.
pub mod content_discovery;
pub mod network_scan;
pub mod origin_discovery;
pub mod service_enum;
pub mod subdomain_enum;
pub mod takeover;
pub mod vuln_scan;
pub mod web_crawl;

/// Shared context handed to each engine handler. Carries the operation
/// identifiers, the NATS publish handle + subjects the node reports on, and
/// the control-plane HTTP client used for claims and credential resolution.
pub struct OpEnv {
    pub op_id: String,
    pub workflow_id: String,
    pub data: serde_json::Value,
    pub node_id: String,
    pub pub_clone: async_nats::Client,
    pub status_subj: String,
    pub result_subj: String,
    pub http: reqwest::Client,
    pub api_url: String,
    pub api_key: String,
}

/// The NATS publish context the terminal helpers need, borrowed from the locals
/// each op already destructured out of [`OpEnv`]. Owns the two byte-identical
/// terminal sequences every single-daemon op repeats: the connect-failure
/// `completed{code:1}` and the success tail (`completed{code:0}` + optional final
/// `operation_progress` + `operation_completed`). The per-event relay (finding ->
/// `result`, throttled progress) stays in each op, since its event vocabulary and
/// payload shaping differ.
pub struct Relay<'a> {
    pub pubc: &'a async_nats::Client,
    pub status_subj: &'a str,
    pub result_subj: &'a str,
    pub op_id: &'a str,
    pub workflow_id: &'a str,
    pub node_id: &'a str,
}

impl Relay<'_> {
    fn job_id(&self) -> String {
        format!("{}-{}", self.workflow_id, self.op_id)
    }

    /// An engine said something an operator needs to know about COVERAGE.
    ///
    /// Engines emit `type:"log"` for the things that change what a result
    /// means: out-of-band callbacks unavailable, so blind classes could not be
    /// confirmed; an endpoint skipped because it stopped answering; a target
    /// refused because it is off-scope; a routing parameter found, so a
    /// dispatcher's pages entered the crawl.
    ///
    /// Every one of those used to be discarded here by a catch-all match arm.
    /// That is the expensive kind of silence: a scan that quietly stopped
    /// testing a whole class produces a report indistinguishable from a clean
    /// one, and the operator has no way to tell the difference. They are now
    /// carried to the control plane and stored on the operation.
    pub async fn publish_note(&self, message: &str) {
        let msg = serde_json::json!({
            "type": "operation_note",
            "operation_id": self.op_id,
            "workflow_id": self.workflow_id,
            "node_id": self.node_id,
            "message": message,
        });
        let _ = self
            .pubc
            .publish(self.status_subj.to_string(), msg.to_string().into())
            .await;
    }

    /// The engine daemon was unreachable: publish `completed{code:1}` on the
    /// result subject. The op logs its own engine-specific message and returns.
    pub async fn publish_failed(&self) {
        let msg = serde_json::json!({
            "type": "completed",
            "job_id": self.job_id(),
            "code": 1
        });
        let _ = self
            .pubc
            .publish(self.result_subj.to_string(), msg.to_string().into())
            .await;
    }

    /// Publish the success terminal sequence: `completed{code:0}` on the result
    /// subject, an optional final `operation_progress` (`Some((processed,total))`
    /// emits it; `None` skips it, matching origin_discovery), then mark the op
    /// done and publish `operation_completed` on the status subject.
    pub async fn finish(&self, found_count: i64, progress: Option<(i64, i64)>) {
        let done_msg = serde_json::json!({
            "type": "completed",
            "job_id": self.job_id(),
            "workflow_id": self.workflow_id,
            "code": 0
        });
        let _ = self
            .pubc
            .publish(self.result_subj.to_string(), done_msg.to_string().into())
            .await;

        if let Some((processed, total)) = progress {
            let final_prog = serde_json::json!({
                "type": "operation_progress",
                "operation_id": self.op_id,
                "workflow_id": self.workflow_id,
                "processed": processed,
                "total": total,
                "node_id": self.node_id,
            });
            let _ = self
                .pubc
                .publish(self.status_subj.to_string(), final_prog.to_string().into())
                .await;
        }

        crate::mark_op_done(self.op_id);
        let status_msg = serde_json::json!({
            "type": "operation_completed",
            "operation_id": self.op_id,
            "workflow_id": self.workflow_id,
            "found_count": found_count,
            "node_id": self.node_id,
        });
        let _ = self
            .pubc
            .publish(self.status_subj.to_string(), status_msg.to_string().into())
            .await;
    }
}

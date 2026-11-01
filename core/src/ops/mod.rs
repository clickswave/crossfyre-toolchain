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

use std::sync::Arc;

use crate::egress::gateway::Lease;

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
    /// The op's lease on the egress gateway when this node sends through a proxy.
    /// `None` on a direct node, where everything is sent as before.
    pub egress: Option<Arc<Lease>>,
}

/// Where engine `ext` listens. In tests, wherever the test put its fake engine, and
/// never an engine this machine runs.
pub(crate) fn engine_addr(ext: &str) -> String {
    #[cfg(test)]
    {
        test_engines::addr(ext)
    }
    #[cfg(not(test))]
    {
        crate::toolchain::config::engine_addr(ext)
    }
}

/// Why an op could not get its request to an engine.
pub(crate) enum EngineOpen {
    /// The engine is not listening, or the request could not be written. The op
    /// handles this as it always has.
    Unreachable(std::io::Error),
    /// The engine answered that it cannot run the op the way this node has to send it.
    /// The op fails with this note.
    Refused(String),
}

/// An engine's answer lines. A wrapped request's first line has already been read, to
/// see whether the engine took the wrapper; it is handed back first.
pub(crate) struct EngineLines {
    first: Option<String>,
    rest: tokio::io::Lines<tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>>,
}

impl EngineLines {
    pub async fn next_line(&mut self) -> std::io::Result<Option<String>> {
        if let Some(l) = self.first.take() {
            return Ok(Some(l));
        }
        self.rest.next_line().await
    }
}

/// Connect to engine `ext` and send it `req`, wrapped with the lease's egress when the
/// op has one.
///
/// The wrapper is what keeps a proxied op from going out directly: an engine that does
/// not know it answers `Unknown operation: egress` and sends nothing. That answer, read
/// here, fails the op with a note saying the engine needs updating.
pub(crate) async fn open_engine(
    ext: &str,
    req: &serde_json::Value,
    egress: Option<&Lease>,
) -> Result<(EngineLines, tokio::net::tcp::OwnedWriteHalf), EngineOpen> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::TcpStream::connect(engine_addr(ext))
        .await
        .map_err(EngineOpen::Unreachable)?;
    let (reader, mut writer) = stream.into_split();
    let mut line = crate::egress::state::encode_for_engine(req, egress);
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(EngineOpen::Unreachable)?;
    let mut rest = BufReader::new(reader).lines();
    let mut first = None;
    if egress.is_some() {
        first = rest.next_line().await.ok().flatten();
        if let Some(note) = first.as_deref().and_then(|l| {
            crate::egress::state::wrapper_refusal(crate::toolchain::public_name(ext), l)
        }) {
            return Err(EngineOpen::Refused(note));
        }
    }
    Ok((EngineLines { first, rest }, writer))
}

/// Publish the op's `operation_egress` when it has a lease and has not published it.
pub async fn publish_egress(
    pubc: &async_nats::Client,
    status_subj: &str,
    op_id: &str,
    workflow_id: &str,
    node_id: &str,
    egress: Option<&Lease>,
) {
    let Some(summary) = egress.and_then(Lease::take_summary) else {
        return;
    };
    let msg = serde_json::json!({
        "type": "operation_egress",
        "operation_id": op_id,
        "workflow_id": workflow_id,
        "node_id": node_id,
        "egress": summary,
    });
    let _ = pubc
        .publish(status_subj.to_string(), msg.to_string().into())
        .await;
}

/// End an op that did not run: a coverage note saying why, the egress summary when it
/// has one, then `operation_completed` with no findings and the reason as its error.
/// The op is not marked done, so a later dispatch runs it.
pub async fn publish_refused(
    pubc: &async_nats::Client,
    status_subj: &str,
    op_id: &str,
    workflow_id: &str,
    node_id: &str,
    egress: Option<&Lease>,
    why: &str,
) {
    let note = serde_json::json!({
        "type": "operation_note",
        "operation_id": op_id,
        "workflow_id": workflow_id,
        "node_id": node_id,
        "message": why,
    });
    let _ = pubc
        .publish(status_subj.to_string(), note.to_string().into())
        .await;
    publish_egress(pubc, status_subj, op_id, workflow_id, node_id, egress).await;
    let done = serde_json::json!({
        "type": "operation_completed",
        "operation_id": op_id,
        "workflow_id": workflow_id,
        "found_count": 0,
        "node_id": node_id,
        "error": why,
    });
    let _ = pubc
        .publish(status_subj.to_string(), done.to_string().into())
        .await;
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
    pub egress: Option<&'a Lease>,
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

    /// The op cannot run as this node has to send it. See [`publish_refused`].
    pub async fn refuse(&self, why: &str) {
        eprintln!("[op] {} not run: {why}", self.op_id);
        publish_refused(
            self.pubc,
            self.status_subj,
            self.op_id,
            self.workflow_id,
            self.node_id,
            self.egress,
            why,
        )
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
    /// emits it; `None` skips it, matching origin_discovery), the egress summary
    /// when the op has a lease, then mark the op done and publish
    /// `operation_completed` on the status subject.
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

        publish_egress(
            self.pubc,
            self.status_subj,
            self.op_id,
            self.workflow_id,
            self.node_id,
            self.egress,
        )
        .await;
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

#[cfg(test)]
pub(crate) mod test_engines {
    use std::collections::HashMap;

    tokio::task_local! {
        static PORTS: HashMap<String, u16>;
    }

    /// Run `f` with engine `ext` at 127.0.0.1:`port` for each pair.
    pub async fn with<F: std::future::Future>(ports: &[(&str, u16)], f: F) -> F::Output {
        let map = ports.iter().map(|(e, p)| (e.to_string(), *p)).collect();
        PORTS.scope(map, f).await
    }

    /// Port 0 for an engine the test did not place: nothing can be reached there.
    pub fn addr(ext: &str) -> String {
        let port = PORTS
            .try_with(|m| m.get(ext).copied())
            .ok()
            .flatten()
            .unwrap_or(0);
        format!("127.0.0.1:{port}")
    }
}

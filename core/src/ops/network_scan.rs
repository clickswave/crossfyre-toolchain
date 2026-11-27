//! Network-scan (port scan) op.
//!
//! Extracted verbatim from the run_operation() dispatcher in lib.rs.
use super::OpEnv;
use crate::*;

/// Why a proxied node does not run a port scan.
pub const PROXIED: &str = "Port scans cannot run on a node that sends through a proxy: each \
                           port is connected to directly, from this node's own address";

pub async fn handle(env: OpEnv) {
    let OpEnv {
        op_id,
        workflow_id,
        data,
        node_id,
        pub_clone,
        status_subj,
        result_subj,
        egress,
        ..
    } = env;

    // A port scan connects to each port itself, which no proxy can carry, so a node
    // that sends through one does not run it rather than run it from its own address.
    if egress.is_some() {
        super::publish_refused(
            &pub_clone,
            &status_subj,
            &op_id,
            &workflow_id,
            &node_id,
            egress.as_deref(),
            PROXIED,
        )
        .await;
        return;
    }

    // The ports of each target, as Crossfyre splits them across its nodes.
    let targets: Vec<String> = data["targets"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let ports_value = data["ports"].clone();
    let tasks = data["tasks"].as_i64().unwrap_or(100);
    let timeout = data["timeout"].as_i64().unwrap_or(2000);
    let delay = data["delay"].as_i64().unwrap_or(0).max(0);
    let service_detection = data["service_detection"].as_bool().unwrap_or(true);
    // Adaptive rate governor: default on. When on, doorward tunes
    // concurrency/timeout/retries live from loss+RTT (tasks is
    // just the seed); when off it uses the fixed tasks/timeout.
    let adaptive = data["adaptive"].as_bool().unwrap_or(true);
    let max_concurrency = data["max_concurrency"].as_i64();
    // Posture caps how aggressive the governor may get (stealth |
    // balanced | throughput). Passed straight through to doorward.
    let posture = data["posture"].as_str().unwrap_or("balanced").to_string();

    println!(
        "[op] doorward scan: {} targets, ports={}, {} tasks, delay={}ms, adaptive={} posture={}",
        targets.len(),
        ports_value,
        tasks,
        delay,
        adaptive,
        posture
    );

    let mut doorward_req = serde_json::json!({
        "operation": "scan",
        "response": "stream",
        "save": false,
        "targets": targets,
        "ports": ports_value,
        "tasks": tasks,
        "timeout": timeout,
        "delay": delay,
        "service_detection": service_detection,
        "adaptive": adaptive,
        "posture": posture,
    });
    if let Some(mc) = max_concurrency {
        doorward_req["max_concurrency"] = serde_json::json!(mc);
    }

    let conn = super::listener::connect(&super::engine_addr("doorward")).await;
    match conn {
        Ok(stream) => {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            // RST-close so this per-op connection to doorward doesn't pile
            // up TIME_WAIT sockets and exhaust ephemeral ports on a big scan.
            // SO_LINGER(0) is an RST close: it returns immediately and is what keeps a
            // full-range scan from exhausting the ephemeral-port pool via TIME_WAIT.
            // tokio deprecated set_linger because a NON-ZERO linger blocks the thread on
            // drop; that hazard does not apply here. Migrating means going through
            // socket2 on the raw fd, which is not worth the unsafe for the same syscall.
            #[allow(deprecated)]
            let _ = stream.set_linger(Some(std::time::Duration::ZERO));
            let (reader, mut writer) = stream.into_split();
            let mut req_str = crate::egress::state::encode_for_engine(&doorward_req, None);
            req_str.push('\n');
            let _ = writer.write_all(req_str.as_bytes()).await;

            let mut lines = BufReader::new(reader).lines();
            let mut found_count = 0;
            let mut total_events = 0;

            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                    total_events += 1;
                    let event_type = event["type"].as_str().unwrap_or("");

                    match event_type {
                        "result" => {
                            // Only an open port is a finding, as doorward keeps only
                            // those. A filtered one was sent too, and each counted as a
                            // finding beside an Open ports count of 0.
                            if event["status"].as_str() != Some("open") {
                                continue;
                            }
                            found_count += 1;
                            let result_msg = serde_json::json!({
                                "type": "result",
                                "job_id": format!("{}-{}", workflow_id, op_id),
                                "workflow_id": workflow_id,
                                "operation_id": op_id,
                                "data": {
                                    "host": event["host"],
                                    "port": event["port"],
                                    "status": event["status"],
                                    "service": event["service"],
                                    "banner": event["banner"],
                                    "latency_ms": event["latency_ms"],
                                }
                            });
                            let _ = pub_clone
                                .publish(result_subj.clone(), result_msg.to_string().into())
                                .await;
                        }
                        "progress" => {
                            // Probe-level progress from doorward: forward as
                            // operation_progress so the workflow bar can show
                            // "N / total_ports" instead of a coarse per-op count.
                            let processed = event["processed"].as_i64().unwrap_or(0);
                            let total = event["total"].as_i64().unwrap_or(0);
                            let prog_msg = serde_json::json!({
                                "type": "operation_progress",
                                "operation_id": op_id,
                                "workflow_id": workflow_id,
                                "processed": processed,
                                "total": total,
                                "node_id": node_id,
                            });
                            let _ = pub_clone
                                .publish(status_subj.clone(), prog_msg.to_string().into())
                                .await;
                        }
                        "done" => {
                            println!(
                                "[op] OK Scan complete: {found_count} open ports found ({total_events} events)"
                            );
                            break;
                        }
                        "error" => {
                            let msg = event["message"].as_str().unwrap_or("unknown");
                            eprintln!("[op] FAIL doorward error: {msg}");
                            break;
                        }
                        _ => {}
                    }
                }
            }

            let done_msg = serde_json::json!({
                "type": "completed",
                "job_id": format!("{}-{}", workflow_id, op_id),
                "workflow_id": workflow_id,
                "code": 0
            });
            let _ = pub_clone
                .publish(result_subj, done_msg.to_string().into())
                .await;

            mark_op_done(&op_id);
            let status_msg = serde_json::json!({
                "type": "operation_completed",
                "operation_id": op_id,
                "workflow_id": workflow_id,
                "found_count": found_count,
                "node_id": node_id,
            });
            let _ = pub_clone
                .publish(status_subj, status_msg.to_string().into())
                .await;
        }
        Err(e) => {
            use std::sync::atomic::{AtomicU64, Ordering};
            static LAST_LOG: AtomicU64 = AtomicU64::new(0);
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let why = super::unreachable("doorward", &e);
            if now_secs.saturating_sub(LAST_LOG.load(Ordering::Relaxed)) >= 60 {
                LAST_LOG.store(now_secs, Ordering::Relaxed);
                eprintln!("[op] FAIL {why} (suppressing further messages for 60s)");
            }
            super::publish_failed(
                &pub_clone,
                &result_subj,
                &op_id,
                &workflow_id,
                &node_id,
                &why,
            )
            .await;
        }
    }
}

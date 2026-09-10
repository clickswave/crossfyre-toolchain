//! Takeover op: dangling-CNAME detection via the voyage daemon.
//!
//! Sibling of `subdomain_enum` (same daemon, same port), split out because the
//! event vocabulary differs: voyage's takeover stream speaks cortex-shaped
//! `finding` events rather than the enum's `subdomain` events, so the relay
//! below matches the vuln-scan handler rather than the enum one.

use super::{OpEnv, Relay};
use crate::*;

pub async fn handle(env: OpEnv) {
    let OpEnv {
        op_id,
        workflow_id,
        data,
        node_id,
        pub_clone,
        status_subj,
        result_subj,
        ..
    } = env;

    // Either an explicit host list (the usual case when a subdomain enum ran
    // first and we are checking what it found) or a bare domain, which voyage
    // enumerates passively for us.
    let hosts = data["hosts"].as_array().cloned().unwrap_or_default();
    let domain = data["domain"]
        .as_str()
        .or_else(|| data["target"].as_str())
        .unwrap_or("")
        .to_string();

    let req = serde_json::json!({
        "operation": "takeover",
        "response": "stream",
        "hosts": hosts,
        "domain": domain,
        "max_hosts": data["max_hosts"].as_u64().unwrap_or(250),
        "tasks": data["tasks"].as_u64().unwrap_or(24),
        "timeout_ms": data["timeout_ms"].as_u64().unwrap_or(6000),
        // Identifying User-Agent, set by the caller. The public tools set one
        // that points at the scanning-policy page; a customer-authorised scan
        // can leave it empty and take voyage's default.
        "user_agent": data["user_agent"].as_str().unwrap_or(""),
        "dns_server": data["dns_server"].as_str().unwrap_or(""),
        // Refuse private / reserved destinations at connect time, and stop
        // following redirects. Absent = false, the behaviour a customer-
        // authorised run gets.
        "block_internal": data["block_internal"].as_bool().unwrap_or(false),
    });

    let relay = Relay {
        pubc: &pub_clone,
        status_subj: &status_subj,
        result_subj: &result_subj,
        op_id: &op_id,
        workflow_id: &workflow_id,
        node_id: &node_id,
    };

    let mut found_count: i64 = 0;
    let mut processed: i64 = 0;
    let mut total: i64 = 0;
    let mut last_prog = std::time::Instant::now();

    let conn =
        tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("voyage")).await;
    let Ok(stream) = conn else {
        eprintln!(
            "[op] FAIL voyage daemon unreachable on {}. Is `voyage --daemon` running?",
            crate::toolchain::config::engine_addr("voyage")
        );
        relay.publish_failed().await;
        return;
    };

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (reader, mut writer) = stream.into_split();
    let mut req_str = dguard::encode(&req);
    req_str.push('\n');
    let _ = writer.write_all(req_str.as_bytes()).await;

    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if !workflow_id.is_empty() && is_workflow_cancelled(&workflow_id) {
            drop(lines);
            drop(writer);
            return;
        }
        if line.trim().is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };

        match event["type"].as_str().unwrap_or("") {
            "finding" => {
                found_count += 1;
                let mut fdata = event["data"].clone();
                if let Some(obj) = fdata.as_object_mut() {
                    obj.insert("operation_id".to_string(), serde_json::json!(op_id));
                }
                let result_msg = serde_json::json!({
                    "type": "result",
                    "job_id": format!("{}-{}", workflow_id, op_id),
                    "workflow_id": workflow_id,
                    "data": fdata,
                });
                let _ = pub_clone
                    .publish(result_subj.clone(), result_msg.to_string().into())
                    .await;
            }
            "progress" => {
                if let Some(p) = event["processed"].as_i64() {
                    processed = p;
                }
                if let Some(t) = event["total"].as_i64()
                    && t > total
                {
                    total = t;
                }
            }
            // Coverage notes: what the engine could not test, and why.
            "log" => {
                if let Some(m) = event["message"].as_str() {
                    relay.publish_note(m).await;
                }
            }
            "done" => break,
            "error" => {
                eprintln!(
                    "[op] FAIL voyage takeover error: {}",
                    event["message"].as_str().unwrap_or("unknown")
                );
                break;
            }
            _ => {}
        }

        if last_prog.elapsed() >= std::time::Duration::from_millis(800) {
            let prog = serde_json::json!({
                "type": "operation_progress",
                "operation_id": op_id,
                "workflow_id": workflow_id,
                "processed": processed,
                "total": total.max(processed),
                "node_id": node_id,
            });
            let _ = pub_clone
                .publish(status_subj.clone(), prog.to_string().into())
                .await;
            last_prog = std::time::Instant::now();
        }
    }

    relay
        .finish(
            found_count,
            Some((processed.max(1), total.max(processed).max(1))),
        )
        .await;
}

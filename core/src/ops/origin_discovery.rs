//! Origin-discovery op: find a target's real origin IP behind a CDN/WAF.
//!
//! A single request/response against the voyage daemon (port 4442): voyage
//! gathers cert-transparency SANs, resolves them, drops CDN ranges, and validates
//! the survivors directly. Each confirmed/likely origin is published as a result.
use super::{OpEnv, Relay};
use crate::*;

/// Why a proxied node does not run origin discovery.
pub const PROXIED: &str =
    "Origin discovery connects to candidate addresses directly and cannot run through a proxy";

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

    let domain = data["domain"].as_str().unwrap_or("").to_string();
    // Origin probes present as a real browser unless the operation opts out.
    let evasive = data["evasive"].as_bool().unwrap_or(true);
    let timeout_ms = data["timeout_ms"].as_i64().unwrap_or(12000).max(1000);

    println!("[op] voyage origin discovery: {domain} evasive={evasive}");

    let voyage_req = serde_json::json!({
        "operation": "origin",
        "response": "instant",
        "domain": domain,
        "evasive": evasive,
        "timeout_ms": timeout_ms,
    });

    let relay = Relay {
        pubc: &pub_clone,
        status_subj: &status_subj,
        result_subj: &result_subj,
        op_id: &op_id,
        workflow_id: &workflow_id,
        node_id: &node_id,
        egress: egress.as_deref(),
    };

    // Origin discovery has to reach each candidate address itself to see whether it
    // is the origin, and a proxy would answer for it instead. voyage refuses it
    // through a proxy too; the node does not send it.
    if egress.is_some() {
        relay.refuse(PROXIED).await;
        return;
    }

    let mut found_count = 0;
    match tokio::net::TcpStream::connect(super::engine_addr("voyage")).await {
        Ok(stream) => {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = stream.into_split();
            let mut req_str = crate::egress::state::encode_for_engine(&voyage_req, None);
            req_str.push('\n');
            let _ = writer.write_all(req_str.as_bytes()).await;

            let mut lines = BufReader::new(reader).lines();
            if let Ok(Some(line)) = lines.next_line().await
                && let Ok(resp) = serde_json::from_str::<serde_json::Value>(&line)
            {
                match resp["status"].as_str() {
                    Some("completed") => {
                        if let Some(arr) = resp["results"].as_array() {
                            for f in arr {
                                found_count += 1;
                                let result_msg = serde_json::json!({
                                    "type": "result",
                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                    "workflow_id": workflow_id,
                                    "data": {
                                        "target": f["ip"].as_str().unwrap_or(""),
                                        "type": "origin",
                                        "confidence": f["confidence"].as_str().unwrap_or(""),
                                        "via_host": f["host"].as_str().unwrap_or(""),
                                        "note": f["note"].as_str().unwrap_or(""),
                                        "domain": domain.clone(),
                                        "operation_id": op_id,
                                    }
                                });
                                let _ = pub_clone
                                    .publish(result_subj.clone(), result_msg.to_string().into())
                                    .await;
                            }
                        }
                        println!("[op] OK origin discovery: {found_count} candidate(s)");
                    }
                    Some("error") => {
                        eprintln!(
                            "[op] FAIL voyage origin error: {}",
                            resp["message"].as_str().unwrap_or("unknown")
                        );
                    }
                    _ => {}
                }
            }
        }
        Err(e) => {
            relay.fail(&super::unreachable("voyage", &e)).await;
            return;
        }
    }

    relay.finish(found_count, None).await;
}

//! Web-crawl op: wordlist-free crawl via the mach daemon, streaming
//! discovered URLs into the shared asset graph.
//!
//! Extracted verbatim from the run_operation() dispatcher in lib.rs.
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
        http,
        api_url,
        api_key,
    } = env;

    // Wordlist-free crawl via the mach daemon (port 4441),
    // streaming discovered URLs into the shared asset graph.
    let seed = data["seed"]
        .as_str()
        .or_else(|| data["target"].as_str())
        .unwrap_or("")
        .to_string();

    let mut crawl_req = serde_json::json!({
        "operation": "crawl",
        "response": "stream",
        "seed": seed,
    });
    if let (Some(obj), Some(cr)) = (data.as_object(), crawl_req.as_object_mut()) {
        for k in [
            "same_host",
            "include_subdomains",
            "follow_external",
            "scope_hosts",
            "max_depth",
            "max_pages",
            "tasks",
            "delay",
            "timeout_ms",
            "parse_js",
            "exclude",
            "posture",
        ] {
            if let Some(v) = obj.get(k) {
                cr.insert(k.to_string(), v.clone());
            }
        }
    }

    // Authenticated crawl: resolve an attached credential into
    // request auth (headers/cookies) and hand it to mach.
    if let Some(cid) = data["credential_id"].as_str().filter(|s| !s.is_empty()) {
        let host = target_host(&seed);
        match creds::resolve_auth(&http, &api_url, &api_key, cid, &host).await {
            Ok(auth) => {
                if let Some(cr) = crawl_req.as_object_mut() {
                    cr.insert("auth".into(), auth);
                }
            }
            Err(e) => eprintln!("[op] web-crawl credential resolve failed ({cid}): {e}"),
        }
    }

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

    let conn = tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("mach")).await;
    match conn {
        Ok(stream) => {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = stream.into_split();
            let mut req_str = dguard::encode(&crawl_req);
            req_str.push('\n');
            let _ = writer.write_all(req_str.as_bytes()).await;

            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !workflow_id.is_empty() && is_workflow_cancelled(&workflow_id) {
                    println!(
                        "[op] web-crawl cancelled (workflow paused/deleted) - stopping mach stream"
                    );
                    drop(lines);
                    drop(writer);
                    return;
                }
                if line.trim().is_empty() {
                    continue;
                }
                let event = match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                match event["type"].as_str().unwrap_or("") {
                    "ack" => {
                        if let Some(t) = event["total"].as_i64()
                            && t > total
                        {
                            total = t;
                        }
                    }
                    "url" => {
                        let url = event["url"].as_str().unwrap_or("");
                        if url.is_empty() {
                            continue;
                        }
                        found_count += 1;
                        let result_msg = serde_json::json!({
                            "type": "result",
                            "job_id": format!("{}-{}", workflow_id, op_id),
                            "workflow_id": workflow_id,
                            "data": {
                                "target": url,
                                "url": url,
                                "type": "endpoint",
                                "source": "crawl",
                                "status_code": event["status_code"],
                                "method": event["method"],
                                "content_type": event["content_type"],
                                "params": event["params"],
                                // Body field names for a form/API endpoint (POST form inputs). The
                                // asset graph turns these into location=body params so the injection
                                // engine fuzzes the body, reaching SQLi/cmdi behind form submissions.
                                "body_params": event["body_params"],
                                "discovered_from": event["discovered_from"],
                                "depth": event["depth"],
                                "operation_id": op_id,
                            }
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
                            "[op] FAIL mach crawl error: {}",
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
        }
        Err(e) => {
            eprintln!(
                "[op] FAIL mach daemon unreachable on {} for crawl ({e}). Is `mach --daemon` running?",
                crate::toolchain::config::engine_addr("mach")
            );
            relay.publish_failed().await;
            return;
        }
    }

    relay
        .finish(
            found_count,
            Some((
                processed.max(found_count),
                total.max(processed).max(found_count),
            )),
        )
        .await;
}

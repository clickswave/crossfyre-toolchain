//! Subdomain-enum op: passive/active subdomain discovery.
//!
//! Extracted verbatim from the run_operation() dispatcher in lib.rs.
use super::OpEnv;
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

    // Subdomain enumeration via voyage daemon (port 4442)
    let domain = data["domain"].as_str().unwrap_or("").to_string();
    let threads = data["threads"].as_i64().unwrap_or(10);
    let delay = data["delay"].as_i64().unwrap_or(0).max(0);
    let disable_passive = data["disable_passive"].as_bool().unwrap_or(false);
    let disable_active = data["disable_active"].as_bool().unwrap_or(false);

    // Download wordlist for active enum if available
    let mut wordlist_path = String::new();
    if !disable_active {
        if let Some(wl_url) = data["wordlist_url"].as_str() {
            if !wl_url.is_empty() {
                let tmp = format!("/tmp/cfx-wl-sub-{op_id}.txt");
                if let Ok(resp) = reqwest::get(wl_url).await
                    && let Ok(body) = resp.text().await
                {
                    let _ = std::fs::write(&tmp, &body);
                    wordlist_path = tmp;
                }
            }
        } else if let Some(wls) = data["wordlists"].as_array()
            && let Some(first) = wls.first()
        {
            let dl_url = first["url"].as_str().unwrap_or("");
            if !dl_url.is_empty() {
                let tmp = format!(
                    "/tmp/cfx-wl-sub-{}.txt",
                    first["id"].as_str().unwrap_or("wl")
                );
                if let Ok(resp) = reqwest::get(dl_url).await
                    && let Ok(body) = resp.text().await
                {
                    let _ = std::fs::write(&tmp, &body);
                    wordlist_path = tmp;
                }
            }
        }
    }

    println!(
        "[op] voyage enum: {} passive={} active={} threads={} delay={}ms",
        domain, !disable_passive, !disable_active, threads, delay
    );

    // Recursive enumeration (wizard toggle): when a subdomain is
    // found, enumerate ITS subdomains too, up to recurse_depth levels.
    // Gated behind recurse=true, so recurse=false is the exact same
    // single-pass enum as before (frontier holds one domain).
    let recurse = data["recurse"].as_bool().unwrap_or(false);
    let recurse_depth = data["recurse_depth"].as_i64().unwrap_or(0).max(0) as usize;

    let mut frontier: std::collections::VecDeque<(String, usize)> =
        std::collections::VecDeque::new();
    frontier.push_back((domain.clone(), 0usize));
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    visited.insert(domain.clone());

    let mut found_count = 0;
    let mut cancelled = false;
    // Live word accounting across ALL recursion levels. Each level's
    // "ack" adds its candidate count to words_total, so the bar grows as
    // found subdomains are queued for their own enumeration - instead of
    // sitting at the initial wordlist size.
    let phase = data["phase"]
        .as_str()
        .or_else(|| data["mode"].as_str())
        .unwrap_or("active")
        .to_string();
    let mut words_done: i64 = 0;
    let mut words_total: i64 = 0;
    // Active candidates per domain (= wordlist size). Each subdomain we
    // queue for recursion adds this to the total the moment it's found,
    // so the bar climbs as discoveries come in (not only once the deeper
    // enumeration starts).
    let wl_lines: i64 = std::fs::read_to_string(&wordlist_path)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count() as i64)
        .unwrap_or(0);
    let mut last_prog = std::time::Instant::now();
    let emit_progress = |processed: i64, total: i64, found: i64| {
        let p = pub_clone.clone();
        let subj = status_subj.clone();
        let oid = op_id.clone();
        let wid = workflow_id.to_string();
        let ph = phase.clone();
        let nid = node_id.clone();
        async move {
            let msg = serde_json::json!({
                "type": "operation_progress", "operation_id": oid, "workflow_id": wid,
                "phase": ph, "processed": processed, "total": total,
                "found_count": found, "node_id": nid,
            });
            let _ = p.publish(subj, msg.to_string().into()).await;
        }
    };

    while let Some((cur_domain, depth)) = frontier.pop_front() {
        let voyage_req = serde_json::json!({
            "operation": "enum",
            "response": "stream",
            "domain": cur_domain.clone(),
            "wordlist": wordlist_path.clone(),
            "tasks": threads,
            "delay": delay,
            "fresh_start": true,
            "disable_passive": disable_passive,
            "disable_active": disable_active,
            "dns_server": data["dns_server"].as_str().unwrap_or(""),
            // Adaptive applies to the ACTIVE brute-force only.
            "adaptive_rate": data["adaptive_rate"].as_bool().unwrap_or(false),
            "adaptive_resilience": data["adaptive_resilience"].as_bool().unwrap_or(false),
            "posture": data["posture"].as_str().unwrap_or("balanced"),
            // Refuse private / reserved destinations when probing discovered
            // hosts. Absent = false, the behaviour a customer-authorised enum
            // gets: reaching your own internal network from your own node is
            // the product.
            "block_internal": data["block_internal"].as_bool().unwrap_or(false),
        });

        let conn =
            tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("voyage")).await;
        match conn {
            Ok(stream) => {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let (reader, mut writer) = stream.into_split();
                let mut req_str = dguard::encode(&voyage_req);
                req_str.push('\n');
                let _ = writer.write_all(req_str.as_bytes()).await;

                let mut lines = BufReader::new(reader).lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if !workflow_id.is_empty() && is_workflow_cancelled(&workflow_id) {
                        println!(
                            "[op] subdomain enum cancelled (workflow paused) - stopping stream"
                        );
                        cancelled = true;
                        break;
                    }
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                        let evt_type = event["type"].as_str().unwrap_or("");

                        match evt_type {
                            "ack" => {
                                // Level 0's real candidate count seeds the total.
                                // Deeper levels were already added to the total when
                                // their subdomain was discovered (see enqueue below),
                                // so we don't double-count them here.
                                if depth == 0 {
                                    words_total += event["total"].as_i64().unwrap_or(0);
                                }
                                emit_progress(words_done, words_total, found_count).await;
                            }
                            "result" => {
                                words_done += 1;
                                if event["status"].as_str() == Some("found") {
                                    found_count += 1;
                                    let subdomain =
                                        event["subdomain"].as_str().unwrap_or("").to_string();
                                    let source = event["source"].as_str().unwrap_or("unknown");
                                    let result_msg = serde_json::json!({
                                        "type": "result",
                                        "job_id": format!("{}-{}", workflow_id, op_id),
                                        "workflow_id": workflow_id,
                                        "data": {
                                            "target": subdomain.clone(),
                                            "type": "subdomain",
                                            "source": source,
                                            "domain": domain.clone(),
                                            "operation_id": op_id,
                                        }
                                    });
                                    let _ = pub_clone
                                        .publish(result_subj.clone(), result_msg.to_string().into())
                                        .await;

                                    // Enumerate found subdomains at the next level.
                                    if recurse
                                        && depth < recurse_depth
                                        && !subdomain.is_empty()
                                        && subdomain != cur_domain
                                        && visited.insert(subdomain.clone())
                                    {
                                        // Grow the total now, at discovery time, so the
                                        // bar climbs as subdomains are found.
                                        words_total += wl_lines;
                                        frontier.push_back((subdomain, depth + 1));
                                    }
                                }
                                if last_prog.elapsed() >= std::time::Duration::from_millis(1500) {
                                    emit_progress(words_done, words_total, found_count).await;
                                    last_prog = std::time::Instant::now();
                                }
                            }
                            "done" => {
                                println!(
                                    "[op] OK Enum level complete (depth {depth}): {found_count} found so far"
                                );
                                emit_progress(words_done, words_total, found_count).await;
                                break;
                            }
                            "error" => {
                                let msg = event["message"].as_str().unwrap_or("unknown");
                                eprintln!("[op] FAIL voyage error: {msg}");
                                break;
                            }
                            _ => {}
                        }
                    }
                }

                if cancelled {
                    drop(lines);
                    drop(writer);
                    return;
                }
            }
            Err(e) => {
                eprintln!("[op] FAIL Cannot connect to voyage daemon: {e}");
                let msg = serde_json::json!({
                    "type": "completed",
                    "job_id": format!("{}-{}", workflow_id, op_id),
                    "workflow_id": workflow_id,
                    "code": 1
                });
                let _ = pub_clone
                    .publish(result_subj.clone(), msg.to_string().into())
                    .await;
                return;
            }
        }
    }

    // Reconcile to 100%: every queued candidate has been tried.
    emit_progress(words_total, words_total, found_count).await;

    let done_msg = serde_json::json!({
        "type": "completed",
        "job_id": format!("{}-{}", workflow_id, op_id),
        "workflow_id": workflow_id,
        "code": 0
    });
    let _ = pub_clone
        .publish(result_subj.clone(), done_msg.to_string().into())
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
        .publish(status_subj.clone(), status_msg.to_string().into())
        .await;
}

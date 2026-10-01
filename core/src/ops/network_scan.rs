//! Network-scan (port scan) op.
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

    // Single-port probe mode: data has host+port
    if let Some(host) = data["host"].as_str().map(|s| s.to_string()) {
        let port = data["port"].as_u64().unwrap_or(0) as u16;
        let timeout_ms = data["timeout"].as_i64().unwrap_or(2000);
        let delay_ms = data["delay"].as_i64().unwrap_or(0).max(0) as u64;
        let service_detection = data["service_detection"].as_bool().unwrap_or(true);

        // Per-probe delay - sleeps WHILE holding the
        // semaphore permit, so it actually paces the
        // workflow's effective rate. e.g. tasks=10 +
        // delay=20ms => floor of ~500 probes/sec
        // (10 / 20ms = 500/s).
        if delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }

        // Use the same `scan` engine path the batch modes use, just
        // with a single-port array, so it shares the
        // exact same code in pulse that's been validated to
        // find every open port - the older `probe` mode had
        // a subtle reliability gap where some opens were
        // returned as the default-closed when run_connect_scan's
        // result event raced with the channel close.
        // Concurrency is already gated by `_ws_permit`.
        let pulse_req = serde_json::json!({
            "operation": "scan",
            "response": "instant",
            "save": false,
            "targets": [host],
            "ports": [port],
            "tasks": 1,
            "timeout": timeout_ms,
            "service_detection": service_detection,
        });

        let short_op = op_id.get(..8).unwrap_or(&op_id).to_string();
        // Log every probe response while we're debugging the
        // discrepancy between scan modes. Noisy but definitive: we'll
        // see exactly what pulse says about every port and
        // can grep for known-open ones (53, 80, 5432, etc).
        let log_sample = true;
        let mut found_count = 0;
        let conn =
            tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("pulse")).await;
        match conn {
            Ok(stream) => {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                // RST-close so this per-op connection to pulse doesn't pile
                // up TIME_WAIT sockets and exhaust ephemeral ports on a big scan.
                // SO_LINGER(0) is an RST close: it returns immediately and is what keeps a
                // full-range scan from exhausting the ephemeral-port pool via TIME_WAIT.
                // tokio deprecated set_linger because a NON-ZERO linger blocks the thread on
                // drop; that hazard does not apply here. Migrating means going through
                // socket2 on the raw fd, which is not worth the unsafe for the same syscall.
                #[allow(deprecated)]
                let _ = stream.set_linger(Some(std::time::Duration::ZERO));
                let (reader, mut writer) = stream.into_split();
                let mut req_str = dguard::encode(&pulse_req);
                req_str.push('\n');
                if log_sample {
                    println!(
                        "[ds {} {}:{}] -> probe sent ({} bytes)",
                        short_op,
                        host,
                        port,
                        req_str.len()
                    );
                }
                if let Err(e) = writer.write_all(req_str.as_bytes()).await {
                    eprintln!("[ds {short_op} {host}:{port}] write failed: {e}");
                }

                let mut lines = BufReader::new(reader).lines();
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        // Always log a snippet of the raw response on the
                        // sampled probes so we can see the actual shape.
                        if log_sample {
                            let snippet = &line[..line.len().min(250)];
                            println!("[ds {short_op} {host}:{port}] <- pulse: {snippet}");
                        }
                        if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&line) {
                            let results_arr =
                                resp["results"].as_array().cloned().unwrap_or_default();
                            if log_sample {
                                println!(
                                    "[ds {} {}:{}] parsed: results.len={}, top.status={:?}",
                                    short_op,
                                    host,
                                    port,
                                    results_arr.len(),
                                    resp["status"].as_str().unwrap_or("?")
                                );
                            }
                            if let Some(result) = results_arr.first() {
                                let status = result["status"].as_str().unwrap_or("");
                                if status == "open" || status == "filtered" {
                                    found_count = 1;
                                    let msg = serde_json::json!({
                                        "type": "result",
                                        "job_id": format!("{}-{}", workflow_id, op_id),
                                        "workflow_id": workflow_id,
                                        "operation_id": op_id,
                                        "data": {
                                            "host": host,
                                            "port": port,
                                            "status": status,
                                            "service": result["service"],
                                            "banner": result["banner"],
                                            "latency_ms": result["latency_ms"],
                                        }
                                    });
                                    match pub_clone
                                        .publish(result_subj.clone(), msg.to_string().into())
                                        .await
                                    {
                                        Err(e) => eprintln!(
                                            "[ds {short_op} {host}:{port}] result publish failed: {e}"
                                        ),
                                        Ok(_) => println!(
                                            "[ds {} {}:{}] OPEN service={} latency={}",
                                            short_op,
                                            host,
                                            port,
                                            result["service"].as_str().unwrap_or("?"),
                                            result["latency_ms"].as_u64().unwrap_or(0)
                                        ),
                                    }
                                }
                            }
                            // `dguard::is_error` rather than a local `status` check: the
                            // daemons spell the discriminator two ways, and the
                            // unauthorized reply uses `type`, so a local check on one
                            // of them logged a rejected request as a malformed one.
                            if resp.get("results").is_none() && !dguard::is_error(&line) {
                                eprintln!(
                                    "[ds {} {}:{}] WEIRD response (no results field): {}",
                                    short_op,
                                    host,
                                    port,
                                    &line[..line.len().min(300)]
                                );
                            }
                        } else {
                            eprintln!(
                                "[ds {} {}:{}] non-JSON response: {}",
                                short_op,
                                host,
                                port,
                                &line[..line.len().min(300)]
                            );
                        }
                    }
                    Ok(None) => {
                        eprintln!(
                            "[ds {short_op} {host}:{port}] pulse closed connection without response"
                        );
                    }
                    Err(e) => {
                        eprintln!("[ds {short_op} {host}:{port}] read error: {e}");
                    }
                }

                let done_msg = serde_json::json!({
                    "type": "completed",
                    "job_id": format!("{}-{}", workflow_id, op_id),
                    "workflow_id": workflow_id,
                    "code": 0
                });
                if let Err(e) = pub_clone
                    .publish(result_subj, done_msg.to_string().into())
                    .await
                {
                    eprintln!("[ds {short_op} {host}:{port}] completed publish failed: {e}");
                } else if log_sample {
                    println!(
                        "[ds {short_op} {host}:{port}] -> completed published (found={found_count})"
                    );
                }

                mark_op_done(&op_id);
                let status_msg = serde_json::json!({
                    "type": "operation_completed",
                    "operation_id": op_id,
                    "workflow_id": workflow_id,
                    "found_count": found_count,
                    "node_id": node_id,
                });
                if let Err(e) = pub_clone
                    .publish(status_subj, status_msg.to_string().into())
                    .await
                {
                    eprintln!(
                        "[ds {short_op} {host}:{port}] operation_completed publish failed: {e}"
                    );
                }
            }
            Err(e) => {
                // The workflow view already shows a "Fix" button
                // based on the heartbeat-reported extension_status,
                // so we don't spam node_logs here. Just rate-limited
                // local stderr for operator-side debugging.
                use std::sync::atomic::{AtomicU64, Ordering};
                static LAST_LOG: AtomicU64 = AtomicU64::new(0);
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now_secs.saturating_sub(LAST_LOG.load(Ordering::Relaxed)) >= 60 {
                    LAST_LOG.store(now_secs, Ordering::Relaxed);
                    eprintln!(
                        "[op] FAIL pulse daemon unreachable on {} ({e}). Is `pulse --daemon` running? (suppressing further messages for 60s)",
                        crate::toolchain::config::engine_addr("pulse")
                    );
                }
                let msg = serde_json::json!({
                    "type": "completed",
                    "job_id": format!("{}-{}", workflow_id, op_id),
                    "workflow_id": workflow_id,
                    "code": 1
                });
                let _ = pub_clone.publish(result_subj, msg.to_string().into()).await;
            }
        }
        return;
    }

    // Batch scan mode: data has targets+ports arrays
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
    // Adaptive rate governor: default on. When on, pulse tunes
    // concurrency/timeout/retries live from loss+RTT (tasks is
    // just the seed); when off it uses the fixed tasks/timeout.
    let adaptive = data["adaptive"].as_bool().unwrap_or(true);
    let max_concurrency = data["max_concurrency"].as_i64();
    // Posture caps how aggressive the governor may get (stealth |
    // balanced | throughput). Passed straight through to pulse.
    let posture = data["posture"].as_str().unwrap_or("balanced").to_string();

    println!(
        "[op] pulse scan: {} targets, ports={}, {} tasks, delay={}ms, adaptive={} posture={}",
        targets.len(),
        ports_value,
        tasks,
        delay,
        adaptive,
        posture
    );

    let mut pulse_req = serde_json::json!({
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
        pulse_req["max_concurrency"] = serde_json::json!(mc);
    }

    let conn = tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("pulse")).await;
    match conn {
        Ok(stream) => {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            // RST-close so this per-op connection to pulse doesn't pile
            // up TIME_WAIT sockets and exhaust ephemeral ports on a big scan.
            // SO_LINGER(0) is an RST close: it returns immediately and is what keeps a
            // full-range scan from exhausting the ephemeral-port pool via TIME_WAIT.
            // tokio deprecated set_linger because a NON-ZERO linger blocks the thread on
            // drop; that hazard does not apply here. Migrating means going through
            // socket2 on the raw fd, which is not worth the unsafe for the same syscall.
            #[allow(deprecated)]
            let _ = stream.set_linger(Some(std::time::Duration::ZERO));
            let (reader, mut writer) = stream.into_split();
            let mut req_str = dguard::encode(&pulse_req);
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
                            // Only report open/filtered ports as findings (skip closed to reduce noise)
                            if event["status"].as_str() == Some("closed") {
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
                            // Probe-level progress from pulse: forward as
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
                            eprintln!("[op] FAIL pulse error: {msg}");
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
            if now_secs.saturating_sub(LAST_LOG.load(Ordering::Relaxed)) >= 60 {
                LAST_LOG.store(now_secs, Ordering::Relaxed);
                eprintln!(
                    "[op] FAIL Cannot connect to pulse daemon: {e} (suppressing further messages for 60s)"
                );
            }
            let msg = serde_json::json!({
                "type": "completed",
                "job_id": format!("{}-{}", workflow_id, op_id),
                "workflow_id": workflow_id,
                "code": 1
            });
            let _ = pub_clone.publish(result_subj, msg.to_string().into()).await;
        }
    }
}

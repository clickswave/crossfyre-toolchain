//! Content-discovery op: wordlist-driven path fuzzing via the ambulo daemon
//! (probe + recursive batch modes), streaming found endpoints as results.
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

    let mode = data["mode"].as_str().unwrap_or("batch");

    // Single-URL probe mode: one target per op
    if mode == "probe" {
        let probe_url = data["probe_url"].as_str().unwrap_or("");
        let method = data["method"].as_str().unwrap_or("GET").to_lowercase();
        let success_codes_str = data["success_codes"]
            .as_str()
            .unwrap_or("200,201,301,302,403");
        let codes: Vec<u16> = success_codes_str
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect();

        // Per-slot pacing: sleep WHILE holding the semaphore
        // permit so the wizard's "delay" actually throttles
        // the rate. tasks=10 + delay=20ms => floor of ~500/sec.
        let delay_ms = data["delay"].as_i64().unwrap_or(0).max(0) as u64;
        if delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }

        let ambulo_req = serde_json::json!({
            "operation": "probe",
            "response": "instant",
            "url": probe_url,
            "method": method,
            "success_codes": codes,
            "volatility": 0,
            "operation_id": op_id,
            // Wizard "Follow Redirects" toggle (default off).
            "follow_redirects": data["follow_redirects"].as_bool().unwrap_or(false),
        });

        let conn =
            tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("mach")).await;
        match conn {
            Ok(stream) => {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let (reader, mut writer) = stream.into_split();
                let mut req_str = dguard::encode(&ambulo_req);
                req_str.push('\n');
                let _ = writer.write_all(req_str.as_bytes()).await;

                let mut lines = BufReader::new(reader).lines();
                // Bound the wait. If ambulo connects but never
                // answers (target stopped responding, or ambulo
                // wedged on this URL), don't deadlock the op
                // forever - time out and fall through to the
                // completion ack below so the scan advances.
                let read =
                    tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
                        .await;
                if let Ok(Ok(Some(line))) = read
                    && let Ok(resp) = serde_json::from_str::<serde_json::Value>(&line)
                {
                    let status = resp["status"].as_str().unwrap_or("");
                    let code = resp["code"].as_i64().unwrap_or(0);
                    let body_len = resp["body_length"].as_i64().unwrap_or(0);

                    if status == "found" {
                        let result_msg = serde_json::json!({
                            "type": "result",
                            "job_id": format!("{}-{}", workflow_id, op_id),
                            "workflow_id": workflow_id,
                            "data": {
                                "target": probe_url,
                                "type": "endpoint",
                                "status_code": code,
                                "body_length": body_len,
                                "source": "mach",
                                "operation_id": op_id,
                                "word": data["word"].as_str().unwrap_or(""),
                            }
                        });
                        let _ = pub_clone
                            .publish(result_subj.clone(), result_msg.to_string().into())
                            .await;
                        println!("[op] OK FOUND {probe_url} [{code}]");
                    } else {
                        // Not found - no result published
                    }
                }
            }
            Err(e) => {
                eprintln!("[op] FAIL Cannot connect to ambulo daemon: {e}");
            }
        }

        // Signal completion for this single probe
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
            "found_count": if data["probe_url"].is_string() { 1 } else { 0 },
            "node_id": node_id,
        });
        let _ = pub_clone
            .publish(status_subj, status_msg.to_string().into())
            .await;
        return;
    }

    // Batch/stream mode: full scan via ambulo
    let url = data["url"].as_str().unwrap_or("");
    let method = data["method"].as_str().unwrap_or("GET");
    let threads = data["threads"].as_i64().unwrap_or(10);
    // Wizard "Follow Redirects" toggle. api_switch puts it on the op, but the
    // streaming scan request below never forwarded it, so ambulo fell back to
    // its default (off) and a path that 301s was recorded as a 301 with an
    // empty body instead of following through to the real page.
    let follow_redirects = data["follow_redirects"].as_bool().unwrap_or(false);
    let success_codes_str = data["success_codes"]
        .as_str()
        .unwrap_or("200,201,301,302,403");

    // Download wordlist - supports both formats:
    // One input: "wordlist_url" (single presigned chunk URL)
    // Or: "wordlists" array with [{ id, url }]
    let mut wordlist_path = String::new();

    if let Some(wl_url) = data["wordlist_url"].as_str() {
        // single chunk URL
        if !wl_url.is_empty() {
            let tmp = crate::toolchain::config::handoff_path(&format!("cfx-wl-chunk-{op_id}.txt"));
            println!("[op] Downloading wordlist chunk...");
            if let Ok(resp) = reqwest::get(wl_url).await
                && let Ok(body) = resp.text().await
            {
                let _ = std::fs::write(&tmp, &body);
                wordlist_path = tmp;
                let lines = body.lines().count();
                println!(
                    "[op] OK Chunk downloaded ({} lines, {} bytes)",
                    lines,
                    body.len()
                );
            }
        }
    } else if let Some(wls) = data["wordlists"].as_array() {
        // array of wordlists
        if let Some(first) = wls.first() {
            let dl_url = first["url"].as_str().unwrap_or("");
            if !dl_url.is_empty() {
                let wl_id = first["id"].as_str().unwrap_or("wordlist");
                let tmp = crate::toolchain::config::handoff_path(&format!("cfx-wl-{wl_id}.txt"));
                println!("[op] Downloading wordlist: {wl_id}");
                if let Ok(resp) = reqwest::get(dl_url).await
                    && let Ok(body) = resp.text().await
                {
                    let _ = std::fs::write(&tmp, &body);
                    wordlist_path = tmp;
                    println!("[op] OK Wordlist downloaded ({} bytes)", body.len());
                }
            }
        }
    }

    if wordlist_path.is_empty() {
        // Fallback to local common.txt
        wordlist_path = "/opt/crossfyre/wordlists/common.txt".to_string();
        if !std::path::Path::new(&wordlist_path).exists() {
            eprintln!("[op] FAIL No wordlist available");
            let msg = serde_json::json!({
                "type": "completed", "job_id": op_id,
                "code": 1
            });
            let _ = pub_clone.publish(result_subj, msg.to_string().into()).await;
            return;
        }
    }

    // Build ambulo endpoint
    // Parse success codes + pacing (shared across recursion levels).
    let codes: Vec<u16> = success_codes_str
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();
    let delay = data["delay"].as_i64().unwrap_or(0).max(0);
    // Resume vs fresh: a re-dispatched paused op sets data.resume=true,
    // so ambulo RESUMES the chunk (fresh_start=false) instead of re-probing.
    let resume = data["resume"].as_bool().unwrap_or(false);

    // Recursive discovery (wizard toggle): when a directory is found,
    // re-run the same wordlist inside it, up to recurse_depth levels.
    // Gated behind recurse=true, so recurse=false is the exact same
    // single-pass scan as before (frontier holds one item, none added).
    let recurse = data["recurse"].as_bool().unwrap_or(false);
    let recurse_depth = data["recurse_depth"].as_i64().unwrap_or(0).max(0) as usize;
    // Adaptive engine flags (default off = current fixed pacing). ambulo
    // reads these and, when set, runs the controller-driven path.
    let adaptive_rate = data["adaptive_rate"].as_bool().unwrap_or(false);
    let adaptive_resilience = data["adaptive_resilience"].as_bool().unwrap_or(false);
    let posture = data["posture"].as_str().unwrap_or("balanced").to_string();
    // When adaptive rate is on, the pace is shared across every chunk
    // hitting this target host: it sets the engine's inter-probe delay
    // (rate self-adaptation off) while each chunk still adapts resilience.
    let cd_host = target_host(url);
    // Coverage-first, feedback-driven concurrency. A CD workflow runs many
    // chunks concurrently, each an ambulo scan, so an unbounded per-chunk
    // `tasks` would multiply the combined volume against one target well
    // past a healthy range and start dropping findings. The shared pace
    // starts from the posture seed and adapts toward safety as the engine
    // reports stress (probes that needed retries) that the final outcome
    // would otherwise hide; always-retry resilience recovers transients.
    let posture_cap = adaptive::coord::posture_cap(&posture) as i64;
    let pace = if adaptive_rate {
        Some(target_pace(
            &workflow_id,
            &cd_host,
            &posture,
            delay.max(0) as u64,
            threads.max(1).min(posture_cap) as u64,
        ))
    } else {
        None
    };
    let cd_tasks = pace.as_ref().map(|p| p.tasks() as i64).unwrap_or(threads);
    if let Some(ref p) = pace {
        println!(
            "[op] shared pace: target={} posture={} tasks={}",
            cd_host,
            posture,
            p.tasks()
        );
    }
    // Traversal order: "depth" dives into each find immediately (push to
    // front); anything else is breadth-first, finishing each level before
    // the next (push to back). Default breadth-first.
    let depth_first = data["recurse_order"].as_str() == Some("depth");
    // Probe-level progress denominator for the initial pass (level-0
    // chunk size, known up front). Recursion grows this live below.
    let chunk_total = data["wordlist_lines"].as_i64().unwrap_or(0);

    // Level 0 uses this node's assigned wordlist (a small chunk
    // of the full list). Recursion into a discovered directory must instead try the
    // FULL wordlist, or the chunk is far too small to find anything
    // deeper. The control plane passes the full list as
    // recurse_wordlist_url; download it once and use it for depth >= 1.
    // If absent (e.g. when the full list already ships), fall back to the
    // level-0 wordlist.
    let mut recurse_wordlist_path = wordlist_path.clone();
    let mut recurse_wl_lines: i64 = chunk_total; // per-directory probe count at deeper levels
    if recurse
        && let Some(rw_url) = data["recurse_wordlist_url"].as_str()
        && !rw_url.is_empty()
    {
        let tmp = crate::toolchain::config::handoff_path(&format!("cfx-wl-recurse-{op_id}.txt"));
        if let Ok(resp) = reqwest::get(rw_url).await
            && let Ok(body) = resp.text().await
        {
            let _ = std::fs::write(&tmp, &body);
            recurse_wordlist_path = tmp;
            recurse_wl_lines = body.lines().filter(|l| !l.trim().is_empty()).count() as i64;
            println!("[op] recursion wordlist downloaded ({recurse_wl_lines} lines)");
        }
    }

    // Live probe accounting. Recursion has no fixed total up front, so we
    // grow `probes_total` by one full recurse-wordlist each time a new
    // directory is queued, and count every probe in `probes_done`. This
    // makes the dashboard bar actually move during recursion instead of
    // sitting at a fixed 99%.
    let mut probes_done: i64 = 0;
    let mut probes_total: i64 = chunk_total.max(0);
    let mut probes_tested: i64 = 0; // requests sent incl. retries (reported by ambulo)
    let mut last_prog = std::time::Instant::now();

    // Frontier of (base_url, depth). Level 0 = the assigned target.
    let base0 = url.trim_end_matches('/').to_string();
    let mut frontier: std::collections::VecDeque<(String, usize)> =
        std::collections::VecDeque::new();
    frontier.push_back((base0.clone(), 0usize));
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    visited.insert(base0);

    // Authenticated content discovery: resolve the attached credential ONCE
    // (host is fixed for this op) into request auth ambulo applies to every
    // probe. Resolved here rather than per recursion level so the credential
    // is fetched a single time and every level of the crawl is authenticated
    // the same way. A resolve failure logs and falls through to an
    // unauthenticated scan rather than aborting the op.
    let cd_auth: Option<serde_json::Value> =
        match data["credential_id"].as_str().filter(|s| !s.is_empty()) {
            Some(cid) => {
                let host = target_host(url);
                match creds::resolve_auth(&http, &api_url, &api_key, cid, &host).await {
                    Ok(auth) => Some(auth),
                    Err(e) => {
                        eprintln!("[op] content-discovery credential resolve failed ({cid}): {e}");
                        None
                    }
                }
            }
            None => None,
        };

    let mut found_count = 0;
    let mut cancelled = false;

    while let Some((base, depth)) = frontier.pop_front() {
        // Build the ambulo endpoint for this level.
        let endpoint = if base.contains("::FUZZ::") {
            base.clone()
        } else {
            format!("{}/::FUZZ::", base.trim_end_matches('/'))
        };

        // Level 0 = assigned chunk; deeper levels = full wordlist.
        let level_wordlist = if depth == 0 {
            wordlist_path.clone()
        } else {
            recurse_wordlist_path.clone()
        };

        println!(
            "[op] ambulo scan (depth {depth}): {endpoint} method={method} threads={threads} delay={delay}ms wordlist={level_wordlist} mode={mode}"
        );

        let mut ambulo_req = serde_json::json!({
            "operation": "scan",
            "response": "stream",
            "endpoint": endpoint,
            "wordlist": level_wordlist.clone(),
            "method": method.to_lowercase(),
            // Shared concurrency + pace when adaptive rate is on, else the
            // fixed wizard values. Backing tasks off under stress keeps the
            // combined volume against a target in a healthy range so results
            // don't get dropped.
            "tasks": cd_tasks,
            "delay": pace.as_ref().map(|p| p.delay() as i64).unwrap_or(delay),
            "success_status_codes": codes.clone(),
            "fresh_start": !resume,
            "follow_redirects": follow_redirects,
            // The pace owns the rate now, so ambulo doesn't self-adapt it; it
            // still runs the adaptive path for resilience when enabled.
            "adaptive_rate": false,
            "adaptive_resilience": adaptive_resilience,
            "posture": posture,
        });

        // Attach the resolved credential (headers + cookies) when present, so
        // ambulo probes every path as the authenticated user.
        if let (Some(auth), Some(obj)) = (cd_auth.as_ref(), ambulo_req.as_object_mut()) {
            obj.insert("auth".into(), auth.clone());
        }

        let conn =
            tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("mach")).await;
        match conn {
            Ok(stream) => {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let (reader, mut writer) = stream.into_split();
                let mut req_str = dguard::encode(&ambulo_req);
                req_str.push('\n');
                let _ = writer.write_all(req_str.as_bytes()).await;

                let mut lines = BufReader::new(reader).lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    // Honor pause / halt / delete promptly (checked per probe event).
                    if !workflow_id.is_empty() && is_workflow_cancelled(&workflow_id) {
                        println!(
                            "[op] content-discovery cancelled (workflow paused/deleted) - stopping ambulo stream"
                        );
                        cancelled = true;
                        break;
                    }
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                        let evt_type = event["type"].as_str().unwrap_or("");
                        if evt_type == "result" {
                            probes_done += 1;
                        }
                        if let Some(t) = event["tested"].as_i64() {
                            probes_tested = t.max(probes_tested);
                        }
                        // ambulo's "ack" carries the real entry count it will probe.
                        // Seed the total from it when the op didn't pre-set
                        // wordlist_lines, so the progress
                        // bar shows real probes instead of a 0/1 op fallback.
                        if evt_type == "ack"
                            && let Some(t) = event["total"].as_i64()
                            && t > probes_total
                        {
                            probes_total = t;
                        }

                        // Feed the shared pace from each probe. A probe that
                        // needed retries hit raw stress even if it finally
                        // recovered - that's the signal the final status/code
                        // hides, and the one that must drive the backoff.
                        if let Some(ref p) = pace
                            && evt_type == "result"
                        {
                            let st = event["status"].as_str().unwrap_or("");
                            let cd = event["code"].as_i64().unwrap_or(0);
                            let retried = event["retries"].as_i64().unwrap_or(0) > 0;
                            let class = if retried {
                                adaptive::ProbeClass::RateLimited
                            } else {
                                classify_event(st, cd)
                            };
                            p.observe(class);
                        }

                        match evt_type {
                            "result" if event["status"].as_str() == Some("found") => {
                                found_count += 1;
                                let found_url = event["url"].as_str().unwrap_or(url).to_string();
                                let code = event["code"].as_i64().unwrap_or(0);
                                // Present only when ambulo followed a redirect
                                // to a different URL; carried through so the UI
                                // can show "requested -> final".
                                let final_url = event["final_url"].as_str();
                                let result_msg = serde_json::json!({
                                    "type": "result",
                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                    "workflow_id": workflow_id,
                                    "data": {
                                        "target": found_url.clone(),
                                        "type": "endpoint",
                                        "status_code": event["code"],
                                        "body_length": event["body_length"],
                                        "final_url": final_url,
                                        "source": "mach",
                                        "operation_id": op_id,
                                    }
                                });
                                let _ = pub_clone
                                    .publish(result_subj.clone(), result_msg.to_string().into())
                                    .await;

                                // Queue directory-like finds for the next level.
                                if recurse
                                    && depth < recurse_depth
                                    && looks_like_directory(&found_url, code)
                                {
                                    let next = found_url.trim_end_matches('/').to_string();
                                    if !next.is_empty()
                                        && !next.contains("::FUZZ::")
                                        && visited.insert(next.clone())
                                    {
                                        // This directory will be probed with the
                                        // full recurse wordlist, so grow the total.
                                        probes_total += recurse_wl_lines;
                                        if depth_first {
                                            frontier.push_front((next, depth + 1));
                                        } else {
                                            frontier.push_back((next, depth + 1));
                                        }
                                    }
                                }
                            }
                            "done" => {
                                println!(
                                    "[op] OK Scan level complete (depth {depth}): {found_count} found so far"
                                );
                                break;
                            }
                            "error" => {
                                let msg = event["message"].as_str().unwrap_or("unknown error");
                                eprintln!("[op] FAIL ambulo error: {msg}");
                                break;
                            }
                            _ => {} // ack, progress, not_found - skip
                        }

                        // Live probe progress. `probes_total` grows as new
                        // directories are queued, so the bar keeps moving
                        // through recursion instead of sitting at a fixed 99%.
                        if last_prog.elapsed() >= std::time::Duration::from_millis(800) {
                            let prog = serde_json::json!({
                                "type": "operation_progress",
                                "operation_id": op_id,
                                "workflow_id": workflow_id,
                                "processed": probes_done,
                                "total": probes_total,
                                "tested": probes_tested,
                                "node_id": node_id,
                            });
                            let _ = pub_clone
                                .publish(status_subj.clone(), prog.to_string().into())
                                .await;
                            last_prog = std::time::Instant::now();
                        }
                    }
                }

                if cancelled {
                    // Stop probing; do NOT mark done (resume re-dispatches it).
                    drop(lines);
                    drop(writer);
                    return;
                }

                // Push current cumulative progress at the end of each level
                // so finished levels are reflected promptly (the in-loop emit
                // is throttled and a short level may not have fired one).
                let prog = serde_json::json!({
                    "type": "operation_progress",
                    "operation_id": op_id,
                    "workflow_id": workflow_id,
                    "processed": probes_done,
                    "total": probes_total,
                    "tested": probes_tested,
                    "node_id": node_id,
                });
                let _ = pub_clone
                    .publish(status_subj.clone(), prog.to_string().into())
                    .await;
            }
            Err(e) => {
                eprintln!("[op] FAIL Cannot connect to ambulo daemon: {e}");
                let msg = serde_json::json!({
                    "type": "completed",
                    "job_id": format!("{}-{}", workflow_id, op_id),
                    "code": 1
                });
                let _ = pub_clone
                    .publish(result_subj.clone(), msg.to_string().into())
                    .await;
                return;
            }
        }
    }

    // All recursion levels drained: completion + final progress + status.
    let done_msg = serde_json::json!({
        "type": "completed",
        "job_id": format!("{}-{}", workflow_id, op_id),
        "workflow_id": workflow_id,
        "code": 0
    });
    let _ = pub_clone
        .publish(result_subj.clone(), done_msg.to_string().into())
        .await;

    // Reconcile to 100%: everything queued has now been probed.
    let final_prog = serde_json::json!({
        "type": "operation_progress",
        "operation_id": op_id,
        "workflow_id": workflow_id,
        "processed": probes_total,
        "total": probes_total,
        "tested": probes_tested,
        "node_id": node_id,
    });
    let _ = pub_clone
        .publish(status_subj.clone(), final_prog.to_string().into())
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

//! Vuln-scan op: cortex-driven template matching.
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

    // Vulnerability detection via the cortex daemon (port 4445).
    // Cortex streams already-confirmed `finding` events; the node
    // stamps operation_id and relays them into the asset graph.
    let target = data["target"]
        .as_str()
        .or_else(|| data["url"].as_str())
        .or_else(|| data["seed"].as_str())
        .unwrap_or("")
        .to_string();
    let sev_arr = data["severity"].as_array().cloned().unwrap_or_default();

    let host = target_host(&target);
    let mode = data["mode"].as_str().unwrap_or("scan");
    let mut cortex_req = if mode == "authz" {
        // Authorization testing (BOLA/BFLA): resolve the identity
        // matrix and hand cortex the endpoints + identities.
        let idents = data["identities"].as_array().cloned().unwrap_or_default();
        let resolved = creds::resolve_identities(&http, &api_url, &api_key, &idents, &host).await;
        serde_json::json!({
            "operation": "authz",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(10000),
            "endpoints": data["endpoints"].clone(),
            "identities": resolved,
        })
    } else if mode == "inject" {
        // Active parameter injection (SQLi/XSS/cmdi/LFI). The endpoints carry the
        // request shape (method, url, query params, typed body fields) built by
        // api_switch from the asset graph, so cortex fuzzes real body + query + path
        // sites - not just whatever it can parse off the URL.
        serde_json::json!({
            "operation": "inject",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(12000),
            "endpoints": data["endpoints"].clone(),
            "classes": data["classes"].clone(),
        })
    } else if mode == "fuzz" {
        // Structure / type fuzzing over the typed request shape (type confusion + mass assignment).
        serde_json::json!({
            "operation": "fuzz",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(12000),
            "endpoints": data["endpoints"].clone(),
            "classes": data["classes"].clone(),
        })
    } else if mode == "discover" {
        // Request-shape discovery: cortex probes each endpoint (error-mining +
        // calibrated field brute-force) and streams the body fields it learns as
        // `shape_field` findings, which the control plane ingests as inferred params.
        serde_json::json!({
            "operation": "discover",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(12000),
            "endpoints": data["endpoints"].clone(),
        })
    } else if mode == "graphql" {
        // GraphQL: cortex live-introspects the endpoint and runs GraphQL-native checks
        // (introspection exposure, suggestion leak, argument injection, alias DoS). No
        // per-endpoint request shapes needed - just the GraphQL route on the target.
        serde_json::json!({
            "operation": "graphql",
            "response": "stream",
            "target": target,
            "endpoint": data["graphql_endpoint"].as_str().unwrap_or("/graphql"),
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(12000),
        })
    } else {
        // Standard vuln scan (templates).
        serde_json::json!({
            "operation": "scan",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(10000),
            "follow_redirects": data["follow_redirects"].as_bool().unwrap_or(true),
            "severity": sev_arr,
            "templates_dir": data["templates_dir"].clone(),
            // Template-id allowlist. Empty/absent = every template the severity
            // filter admits, which is the behaviour every existing workflow got.
            // The public free tools set it so a checker that advertises one thing
            // cannot fire an unrelated probe at a stranger's host.
            // `as_array().unwrap_or_default()` rather than a bare clone: an absent
            // key clones to JSON null, and serde's `default` only fills a MISSING
            // field, so null would fail to deserialize into Vec<String>.
            "only": data["only"].as_array().cloned().unwrap_or_default(),
            // Passive header checks only, no template requests at all.
            "passive_only": data["passive_only"].as_bool().unwrap_or(false),
            // Announce ourselves under this exact User-Agent instead of
            // presenting as a browser, and drop emulation with it. Empty leaves
            // the engine's own posture, which is what every existing workflow
            // gets. The public free tools set it.
            "user_agent": data["user_agent"].as_str().unwrap_or(""),
            // Refuse private / reserved destinations at connect time. Absent =
            // false, which is the behaviour every existing workflow gets.
            "block_internal": data["block_internal"].as_bool().unwrap_or(false),
        })
    };

    // Both the template scan and the injection engine reach the target directly, so both may need
    // an attached credential (authed testing) and an OAST endpoint (blind/OOB confirmation). Authz
    // resolves its own per-identity credentials, so it is skipped here.
    if mode != "authz" {
        if let Some(cid) = data["credential_id"].as_str().filter(|s| !s.is_empty()) {
            match creds::resolve_auth(&http, &api_url, &api_key, cid, &host).await {
                Ok(auth) => {
                    if let Some(cr) = cortex_req.as_object_mut() {
                        cr.insert("auth".into(), auth);
                    }
                }
                Err(e) => eprintln!("[op] vuln-scan credential resolve failed ({cid}): {e}"),
            }
        }
        // OAST endpoint for out-of-band (blind) confirmation. Default ("" / "managed") resolves to
        // the managed pool; a UUID to a BYO endpoint; "off" disables OOB. The node hands cortex the
        // resolved { domains, api_url }; cortex registers/polls directly.
        let oast_ep = data["oast_endpoint_id"].as_str().unwrap_or("");
        match oast::resolve(&http, &api_url, &api_key, oast_ep).await {
            Ok(Some((domains, poll_url))) => {
                if let Some(cr) = cortex_req.as_object_mut() {
                    cr.insert(
                        "oast".into(),
                        serde_json::json!({ "domains": domains, "api_url": poll_url }),
                    );
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("[op] vuln-scan oast resolve failed ({oast_ep}): {e}"),
        }
    }

    // Forward the Evasiveness switch + attribution token when the workflow set them,
    // so the operator's posture reaches cortex (which otherwise defaults to
    // evasive=true / identify=none) for both the scan and authz operations.
    if let Some(ev) = data["evasive"].as_bool() {
        cortex_req["evasive"] = serde_json::json!(ev);
    }
    if let Some(tok) = data["identify"].as_str().filter(|s| !s.is_empty()) {
        cortex_req["identify"] = serde_json::json!(tok);
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
    let conn =
        tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("cortex")).await;
    match conn {
        Ok(stream) => {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = stream.into_split();
            let mut req_str = dguard::encode(&cortex_req);
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
                let event = match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(e) => e,
                    Err(_) => continue,
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
                            "[op] FAIL cortex error: {}",
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
                "[op] FAIL cortex daemon unreachable on {} ({e}). Is `cortex --daemon` running?",
                crate::toolchain::config::engine_addr("cortex")
            );
            relay.publish_failed().await;
            return;
        }
    }

    relay
        .finish(
            found_count,
            Some((processed.max(1), total.max(processed).max(1))),
        )
        .await;
}

//! Vuln-scan op: plessor-driven template matching.
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
        egress,
    } = env;
    let lease = egress.as_deref();

    // Vulnerability detection via the plessor daemon (port 4445).
    // Plessor streams already-confirmed `finding` events; the node
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
    // What the operator needs to know about a credential kept off part of the pass.
    let mut notes: Vec<String> = Vec::new();
    // The hosts of each credential the pass carries. The platform checked them
    // against the target only; anything else the engine is sent to is held to them.
    let mut cred_scopes: Vec<Vec<String>> = Vec::new();
    let mut plessor_req = if mode == "authz" {
        // Authorization testing (BOLA/BFLA): resolve the identity
        // matrix and hand plessor the endpoints + identities.
        let idents = data["identities"].as_array().cloned().unwrap_or_default();
        let (resolved, scopes) =
            creds::resolve_identities(&http, &api_url, &api_key, &idents, &host, lease).await;
        cred_scopes = scopes;
        serde_json::json!({
            "operation": "authz",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(10000),
            "endpoints": data["endpoints"].clone(),
            "identities": resolved,
            // Refuse private / reserved destinations at the resolver. The scan
            // mode has always forwarded this; the others silently dropped it.
            "block_internal": data["block_internal"].as_bool().unwrap_or(false),
            // Destinations beyond the target the OPERATOR authorised. Never
            // widened by anything a scan discovers.
            "scope": data["scope"].clone(),
        })
    } else if mode == "inject" {
        // Active parameter injection (SQLi/XSS/cmdi/LFI). The endpoints carry the
        // request shape (method, url, query params, typed body fields) built by
        // api_switch from the asset graph, so plessor fuzzes real body + query + path
        // sites - not just whatever it can parse off the URL.
        serde_json::json!({
            "operation": "inject",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(12000),
            "endpoints": data["endpoints"].clone(),
            "classes": data["classes"].clone(),
            // Refuse private / reserved destinations at the resolver. The scan
            // mode has always forwarded this; the others silently dropped it.
            "block_internal": data["block_internal"].as_bool().unwrap_or(false),
            // Destinations beyond the target the OPERATOR authorised. Never
            // widened by anything a scan discovers.
            "scope": data["scope"].clone(),
            // Addresses other engines observed on this estate, for a confirmed
            // SSRF to be re-tested against. The engine scope-checks every one.
            "internal_targets": data["internal_targets"].clone(),
        })
    } else if mode == "flow" {
        // Replay a recorded multi-step flow and test whether its order is real.
        // No credential: a recorded flow that begins with a login establishes
        // its own session, and handing one in would hide the thing being tested.
        serde_json::json!({
            "operation": "flow",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(15000),
            "name": data["flow_name"].clone(),
            "steps": data["steps"].clone(),
            // The same flow as a second user, when one was marked.
            "other_steps": data["other_steps"].clone(),
            "evasive": data["evasive"].clone(),
            "identify": data["identify"].clone(),
            "block_internal": data["block_internal"].as_bool().unwrap_or(false),
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
            // Refuse private / reserved destinations at the resolver. The scan
            // mode has always forwarded this; the others silently dropped it.
            "block_internal": data["block_internal"].as_bool().unwrap_or(false),
        })
    } else if mode == "discover" {
        // Request-shape discovery: plessor probes each endpoint (error-mining +
        // calibrated field brute-force) and streams the body fields it learns as
        // `shape_field` findings, which the control plane ingests as inferred params.
        serde_json::json!({
            "operation": "discover",
            "response": "stream",
            "target": target,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(12000),
            "endpoints": data["endpoints"].clone(),
            // Refuse private / reserved destinations at the resolver. The scan
            // mode has always forwarded this; the others silently dropped it.
            "block_internal": data["block_internal"].as_bool().unwrap_or(false),
        })
    } else if mode == "graphql" {
        // GraphQL: plessor live-introspects the endpoint and runs GraphQL-native checks
        // (introspection exposure, suggestion leak, argument injection, alias DoS). No
        // per-endpoint request shapes needed - just the GraphQL route on the target.
        serde_json::json!({
            "operation": "graphql",
            "response": "stream",
            "target": target,
            "endpoint": data["graphql_endpoint"].as_str().unwrap_or("/graphql"),
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(12000),
            // Refuse private / reserved destinations at the resolver. The scan
            // mode has always forwarded this; the others silently dropped it.
            "block_internal": data["block_internal"].as_bool().unwrap_or(false),
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
            // The template pack, crossfyre-templates' plessor folder as `crossfyre update`
            // last brought it or the release compiled it in, beside the built-in checks.
            // A workflow asks for it; absent is built-in checks only, as every workflow
            // before it got.
            "pack": data["pack"].as_bool().unwrap_or(false),
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
            // Several independent sessions for the injection pass, one per
            // worker. A single session is a bottleneck on any target that locks
            // it per request, and the resulting timeouts are reported as
            // "the endpoint did not answer" rather than as slowness.
            //
            // Only the injection mode benefits: template scanning is stateless
            // per request, so it takes one session like before.
            let want = if mode == "inject" { 4 } else { 1 };
            match creds::resolve_auth_pool(&http, &api_url, &api_key, cid, &host, want, lease).await
            {
                Ok((pool, hosts)) if !pool.is_empty() => {
                    if let Some(cr) = plessor_req.as_object_mut() {
                        cr.insert("auth".into(), pool[0].clone());
                        if pool.len() > 1 {
                            cr.insert("auth_pool".into(), serde_json::json!(pool));
                        }
                    }
                    if mode == "graphql" {
                        notes.extend(super::cred_scope::graphql(&mut plessor_req, &hosts));
                    } else {
                        cred_scopes.push(hosts);
                    }
                }
                Ok(_) => {}
                Err(e) => eprintln!("[op] vuln-scan credential resolve failed ({cid}): {e}"),
            }
        }
        // OAST endpoint for out-of-band (blind) confirmation. Default ("" / "managed") resolves to
        // the managed pool; a UUID to a BYO endpoint; "off" disables OOB. The node hands plessor the
        // resolved { domains, api_url }; plessor registers/polls directly.
        let oast_ep = data["oast_endpoint_id"].as_str().unwrap_or("");
        match oast::resolve(&http, &api_url, &api_key, oast_ep).await {
            Ok(Some((domains, poll_url))) => {
                if let Some(cr) = plessor_req.as_object_mut() {
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

    // An endpoint on a host the credential is not for is not handed to the engine,
    // which would send it the credential along with every other request.
    let scopes: Vec<&[String]> = cred_scopes.iter().map(Vec::as_slice).collect();
    notes.extend(super::cred_scope::keep_endpoints(
        &mut plessor_req,
        &target,
        &scopes,
    ));

    // Forward the Evasiveness switch + attribution token when the workflow set them,
    // so the operator's posture reaches plessor (which otherwise defaults to
    // evasive=true / identify=none) for both the scan and authz operations.
    if let Some(ev) = data["evasive"].as_bool() {
        plessor_req["evasive"] = serde_json::json!(ev);
    }
    if let Some(tok) = data["identify"].as_str().filter(|s| !s.is_empty()) {
        plessor_req["identify"] = serde_json::json!(tok);
    }

    // What toolmark saw on the target's host and port lately chooses the templates, unless
    // the workflow asks for all of them, and its CVE leads go to be answered either way.
    // The answers go back to toolmark for that host and port once the scan has run.
    let mut answer_back: Option<(String, u16)> = None;
    if mode == "scan" {
        if data["all_templates"].as_bool().unwrap_or(false) {
            plessor_req["all_templates"] = serde_json::json!(true);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        if let Some(inventory) = toolmark_inventory().await
            && let Some((host, port)) = cfx_cve::inventory::host_and_port(&target)
            && let Some(fresh) = cfx_cve::inventory::fresh(&inventory, &host, port, now)
        {
            plessor_req["products"] = serde_json::json!(fresh.products);
            plessor_req["leads"] = serde_json::json!(fresh.leads);
            plessor_req["products_from"] = serde_json::json!(fresh.from);
            if !fresh.leads.is_empty() {
                answer_back = Some((host, port));
            }
        }
    }

    let relay = Relay {
        pubc: &pub_clone,
        status_subj: &status_subj,
        result_subj: &result_subj,
        op_id: &op_id,
        workflow_id: &workflow_id,
        node_id: &node_id,
        egress: lease,
    };
    for note in &notes {
        eprintln!("[op] {op_id}: {note}");
        relay.publish_note(note).await;
    }

    let mut found_count: i64 = 0;
    let mut processed: i64 = 0;
    let mut total: i64 = 0;
    let mut last_prog = std::time::Instant::now();
    // The scan the ack names, and its answers to the leads.
    let mut scan_id: Option<String> = None;
    let mut answered: Option<serde_json::Value> = None;
    match super::open_engine("plessor", &plessor_req, lease).await {
        Ok((mut lines, writer)) => {
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
                match event["type"].as_str() {
                    Some("ack") => scan_id = event["scan"].as_str().map(str::to_string),
                    Some("lead_answers") => answered = Some(event.clone()),
                    _ => {}
                }
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
                    "done" => break,
                    "error" => {
                        eprintln!(
                            "[op] FAIL plessor error: {}",
                            event["message"].as_str().unwrap_or("unknown")
                        );
                        break;
                    }
                    _ => {
                        if let Some(m) = coverage_note(&event) {
                            relay.publish_note(m).await;
                        }
                    }
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
        Err(super::EngineOpen::Refused(why)) => {
            relay.refuse(&why).await;
            return;
        }
        Err(super::EngineOpen::Unreachable(e)) => {
            relay.fail(&super::unreachable("plessor", &e)).await;
            return;
        }
    }

    if let (Some((host, port)), Some(event)) = (answer_back, answered)
        && let Some(back) =
            cfx_cve::inventory::AnswersBack::from_event(&host, port, scan_id.as_deref(), &event)
    {
        tell_toolmark(&back).await;
    }

    relay
        .finish(
            found_count,
            Some((processed.max(1), total.max(processed).max(1))),
        )
        .await;
}

/// What a plessor event says the scan did not test, and why, as a note for the workflow:
/// a log line, the templates it held back, so that none is left out in silence, or what
/// its templates said of toolmark's CVE leads.
fn coverage_note(event: &serde_json::Value) -> Option<&str> {
    match event["type"].as_str()? {
        "log" | "templates_held_back" | "lead_answers" => event["message"].as_str(),
        _ => None,
    }
}

/// Hand toolmark what the scan's templates said of its leads, which it keeps with each lead
/// for its inventory to show. A toolmark that is not running, or refuses, is said in the
/// node's log, and the scan's own answers stand in the workflow's note.
async fn tell_toolmark(back: &cfx_cve::inventory::AnswersBack) {
    let said = match super::open_engine("toolmark", &back.request(), None).await {
        Ok((mut lines, _writer)) => match lines.next_line().await {
            Ok(Some(line)) => serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .filter(|a| a["status"] != "completed")
                .map(|a| a["message"].as_str().unwrap_or("refused").to_string()),
            _ => Some("no answer".to_string()),
        },
        Err(_) => Some("not running".to_string()),
    };
    if let Some(why) = said {
        eprintln!(
            "[op] toolmark did not keep the answers to the leads of {}:{}: {why}",
            back.host, back.port
        );
    }
}

/// What toolmark holds of the hosts it has fingerprinted, or none when it is not running
/// or does not answer, and the scan then runs every template.
async fn toolmark_inventory() -> Option<serde_json::Value> {
    let ask = serde_json::json!({"operation": "inventory", "response": "instant"});
    let (mut lines, _writer) = super::open_engine("toolmark", &ask, None).await.ok()?;
    let line = lines.next_line().await.ok()??;
    let answer: serde_json::Value = serde_json::from_str(&line).ok()?;
    (answer["status"] == "completed").then_some(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log line, the templates a scan held back and its answers to the leads reach the
    /// workflow as notes; a finding is not one.
    #[test]
    fn what_a_scan_did_not_test_becomes_a_note() {
        let log = serde_json::json!({"type": "log", "message": "no OAST"});
        assert_eq!(coverage_note(&log), Some("no OAST"));
        let held = serde_json::json!({
            "type": "templates_held_back", "count": 1, "templates": ["CVE-2021-41773"],
            "message": "1 product templates held back: toolmark's inventory of h:80 names none",
        });
        assert_eq!(
            coverage_note(&held),
            Some("1 product templates held back: toolmark's inventory of h:80 names none")
        );
        let answered = serde_json::json!({
            "type": "lead_answers", "answers": [],
            "message": "1 CVE leads from toolmark's inventory of h:80: 1 confirmed (CVE-2021-41773).",
        });
        assert_eq!(
            coverage_note(&answered),
            Some("1 CVE leads from toolmark's inventory of h:80: 1 confirmed (CVE-2021-41773).")
        );
        let finding = serde_json::json!({"type": "finding", "message": "x", "data": {}});
        assert_eq!(coverage_note(&finding), None);
    }
}

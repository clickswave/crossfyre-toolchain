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

    // A template scan runs the templates about a product only where toolmark saw that
    // product on the target, when what it saw there is fresh; otherwise every template
    // runs, as it always did.
    if mode == "scan" && !data["all_templates"].as_bool().unwrap_or(false) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        if let Some(inventory) = toolmark_inventory().await
            && let Some((products, from)) = fresh_products(&inventory, &target, now)
        {
            plessor_req["products"] = serde_json::json!(products);
            plessor_req["products_from"] = serde_json::json!(from);
        }
    } else if data["all_templates"].as_bool().unwrap_or(false) {
        plessor_req["all_templates"] = serde_json::json!(true);
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
                            "[op] FAIL plessor error: {}",
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
        Err(super::EngineOpen::Refused(why)) => {
            relay.refuse(&why).await;
            return;
        }
        Err(super::EngineOpen::Unreachable(e)) => {
            relay.fail(&super::unreachable("plessor", &e)).await;
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

/// How long what toolmark saw on a host is taken to be what still runs there, when a scan
/// chooses its templates by it. A host's software changes, and a template held back on a
/// fingerprint taken before the change would miss what it was written for; a week is as
/// old as a fingerprint is trusted for that, and an older one chooses nothing, so every
/// template runs. What toolmark found earlier in the same workflow run is always within it.
const FRESH_INVENTORY_SECS: i64 = 7 * 24 * 3600;

/// What toolmark holds of the hosts it has fingerprinted, or none when it is not running
/// or does not answer, and the scan then runs every template.
async fn toolmark_inventory() -> Option<serde_json::Value> {
    let ask = serde_json::json!({"operation": "inventory", "response": "instant"});
    let (mut lines, _writer) = super::open_engine("toolmark", &ask, None).await.ok()?;
    let line = lines.next_line().await.ok()??;
    let answer: serde_json::Value = serde_json::from_str(&line).ok()?;
    (answer["status"] == "completed").then_some(answer)
}

/// The products toolmark saw on `target`'s host and port, by its names for them, from the
/// rows of `inventory` last seen within [`FRESH_INVENTORY_SECS`] of `now`, and what the
/// scan says of where they came from. None when no row for that host and port is fresh.
fn fresh_products(
    inventory: &serde_json::Value,
    target: &str,
    now: i64,
) -> Option<(Vec<String>, String)> {
    let with_scheme = if target.contains("://") {
        target.to_string()
    } else {
        format!("http://{target}")
    };
    let url = reqwest::Url::parse(&with_scheme).ok()?;
    let (host, port) = (url.host_str()?.to_lowercase(), url.port_or_known_default()?);
    let mut products = std::collections::BTreeSet::new();
    let mut newest: Option<i64> = None;
    for row in inventory["inventory"].as_array()? {
        let same = row["host"]
            .as_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(&host))
            && row["port"].as_u64() == Some(u64::from(port));
        let seen = row["last_seen"]
            .as_str()
            .and_then(crate::toolchain::data_manifest::unix_time);
        let Some(seen) = seen.filter(|t| same && now - t <= FRESH_INVENTORY_SECS) else {
            continue;
        };
        newest = newest.max(Some(seen));
        for name in row["cpe_names"].as_array().into_iter().flatten() {
            if let Some(name) = name.as_str() {
                products.insert(name.to_string());
            }
        }
    }
    let newest = newest?;
    let hours = (now - newest).max(0) / 3600;
    let s = if hours == 1 { "" } else { "s" };
    let from =
        format!("toolmark's inventory of {host}:{port}, last seen {hours} hour{s} before the scan");
    Some((products.into_iter().collect(), from))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_795_273_200; // 2026-11-21T15:00:00Z

    fn inventory(rows: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"status": "completed", "inventory": rows})
    }

    /// The products of the target's host and port that toolmark saw within a week choose
    /// the templates, and the scan says which inventory and how old.
    #[test]
    fn a_fresh_fingerprint_of_the_target_chooses_the_templates() {
        let inv = inventory(serde_json::json!([
            {"host": "app.test", "port": 443, "cpe_names": ["a:f5:nginx"], "last_seen": "2026-11-21T13:00:00Z"},
            {"host": "APP.test", "port": 443, "cpe_names": ["a:metabase:metabase"], "last_seen": "2026-11-20T15:00:00Z"},
            {"host": "app.test", "port": 443, "cpe_names": [], "last_seen": "2026-11-21T14:00:00Z"},
            {"host": "app.test", "port": 8443, "cpe_names": ["a:apache:tomcat"], "last_seen": "2026-11-21T14:00:00Z"},
            {"host": "other.test", "port": 443, "cpe_names": ["a:grafana:grafana"], "last_seen": "2026-11-21T14:00:00Z"},
        ]));
        let (products, from) = fresh_products(&inv, "https://app.test", NOW).unwrap();
        assert_eq!(products, ["a:f5:nginx", "a:metabase:metabase"]);
        assert_eq!(
            from,
            "toolmark's inventory of app.test:443, last seen 1 hour before the scan"
        );
        let (products, _) = fresh_products(&inv, "app.test:8443", NOW).unwrap();
        assert_eq!(products, ["a:apache:tomcat"]);
    }

    /// What toolmark saw more than a week ago chooses nothing, so every template runs, and
    /// so does a host it never saw.
    #[test]
    fn a_stale_fingerprint_or_none_chooses_nothing() {
        let inv = inventory(serde_json::json!([
            {"host": "app.test", "port": 443, "cpe_names": ["a:f5:nginx"], "last_seen": "2026-11-14T14:59:59Z"},
            {"host": "app.test", "port": 443, "cpe_names": ["a:metabase:metabase"], "last_seen": "not a time"},
        ]));
        assert_eq!(fresh_products(&inv, "https://app.test", NOW), None);
        assert_eq!(fresh_products(&inv, "https://unseen.test", NOW), None);
        let week = inventory(serde_json::json!([
            {"host": "app.test", "port": 443, "cpe_names": ["a:f5:nginx"], "last_seen": "2026-11-14T15:00:00Z"},
        ]));
        assert!(
            fresh_products(&week, "https://app.test", NOW).is_some(),
            "a week is fresh"
        );
    }
}

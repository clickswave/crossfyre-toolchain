//! Service-enum op: scout-driven service/tech identification.
//!
//! Two shapes, because "what is on this port" has two answers depending on
//! whether the port speaks HTTP:
//!
//!   * a URL or host -> scout `fingerprint`, the web stack behind it.
//!   * `host:port` entries -> scout `services`, which speaks Redis, MongoDB,
//!     memcached, MySQL, Postgres, FTP, SMTP, SSH and LDAP, names the version,
//!     and says whether the service lets an anonymous caller in. A port scan
//!     produces exactly this shape, so a pipeline that has already run pulse
//!     can hand its open ports straight here.
//!
//! A single target on a port conventionally used by one of those services takes
//! the second path too: fingerprinting an HTTP client against Redis tells you
//! nothing, which is what used to happen.
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

    // Web/service fingerprinting via the scout daemon (port 4444).
    // Scout streams `finding` events whose `data` is the finding
    // verbatim; the node just stamps operation_id and relays them.
    let target = data["target"]
        .as_str()
        .or_else(|| data["seed"].as_str())
        .or_else(|| data["url"].as_str())
        .unwrap_or("")
        .to_string();

    // `targets` (plural) is the port-scan shape: a list of host:port.
    let listed: Vec<String> = data["targets"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let single_service_port = listed.is_empty() && is_service_port(&target);

    if !listed.is_empty() || single_service_port {
        let targets = if listed.is_empty() {
            vec![strip_scheme(&target)]
        } else {
            listed
        };
        let req = serde_json::json!({
            "operation": "services",
            "response": "stream",
            "targets": targets,
            "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(5000),
            "auth_checks": data["auth_checks"].as_bool().unwrap_or(true),
        });
        run_scout(
            req,
            &op_id,
            &workflow_id,
            &node_id,
            &pub_clone,
            &status_subj,
            &result_subj,
        )
        .await;
        return;
    }

    let mut scout_req = serde_json::json!({
        "operation": "fingerprint",
        "response": "stream",
        "target": target,
        "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(8000),
        "follow_redirects": data["follow_redirects"].as_bool().unwrap_or(true),
        "favicon": data["favicon"].as_bool().unwrap_or(true),
        "depth_tier": data["depth_tier"].as_i64().unwrap_or(2),
    });

    // Authenticated fingerprinting: resolve an attached credential
    // into request auth and hand it to scout.
    if let Some(cid) = data["credential_id"].as_str().filter(|s| !s.is_empty()) {
        let host = target_host(&target);
        match creds::resolve_auth(&http, &api_url, &api_key, cid, &host).await {
            Ok(auth) => {
                if let Some(cr) = scout_req.as_object_mut() {
                    cr.insert("auth".into(), auth);
                }
            }
            Err(e) => eprintln!("[op] service-enum credential resolve failed ({cid}): {e}"),
        }
    }

    run_scout(
        scout_req,
        &op_id,
        &workflow_id,
        &node_id,
        &pub_clone,
        &status_subj,
        &result_subj,
    )
    .await;
}

/// `host:port`, scheme stripped, path dropped: what scout's services pass takes.
fn strip_scheme(t: &str) -> String {
    let t = t.split_once("://").map(|(_, rest)| rest).unwrap_or(t);
    t.split('/').next().unwrap_or(t).to_string()
}

/// Ports where a non-HTTP service is the convention. Only used to choose which
/// scout pass to run; scout itself never trusts the port number for identity.
fn is_service_port(target: &str) -> bool {
    let hp = strip_scheme(target);
    let Some((_, p)) = hp.rsplit_once(':') else {
        return false;
    };
    matches!(
        p.parse::<u16>().unwrap_or(0),
        21 | 22
            | 25
            | 389
            | 465
            | 587
            | 636
            | 3268
            | 3306
            | 3307
            | 5432
            | 5433
            | 6379
            | 6380
            | 11211
            | 27017
            | 27018
            | 27019
    )
}

/// Send one request to the scout daemon and relay what it streams back.
#[allow(clippy::too_many_arguments)]
async fn run_scout(
    req: serde_json::Value,
    op_id: &str,
    workflow_id: &str,
    node_id: &str,
    pub_clone: &async_nats::Client,
    status_subj: &str,
    result_subj: &str,
) {
    let relay = Relay {
        pubc: pub_clone,
        status_subj,
        result_subj,
        op_id,
        workflow_id,
        node_id,
    };

    let mut found_count: i64 = 0;
    let conn = tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("scout")).await;
    match conn {
        Ok(stream) => {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = stream.into_split();
            let mut req_str = dguard::encode(&req);
            req_str.push('\n');
            let _ = writer.write_all(req_str.as_bytes()).await;

            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !workflow_id.is_empty() && is_workflow_cancelled(workflow_id) {
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
                    // A `service` event is inventory, not a vulnerability: what
                    // is listening, its version, and whether it wanted
                    // credentials. It goes into the asset graph beside the
                    // findings so the surface is recorded even when nothing is
                    // wrong with it.
                    "finding" | "service" => {
                        let mut fdata = if event["type"] == "service" {
                            let mut v = event.clone();
                            if let Some(o) = v.as_object_mut() {
                                o.remove("type");
                                o.insert("type".into(), serde_json::json!("service"));
                                o.insert("source".into(), serde_json::json!("scout-services"));
                            }
                            v
                        } else {
                            event["data"].clone()
                        };
                        if event["type"] == "finding" {
                            found_count += 1;
                        }
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
                            .publish(result_subj.to_string(), result_msg.to_string().into())
                            .await;
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
                            "[op] FAIL scout error: {}",
                            event["message"].as_str().unwrap_or("unknown")
                        );
                        break;
                    }
                    _ => {}
                }
            }
        }
        Err(e) => {
            eprintln!(
                "[op] FAIL scout daemon unreachable on {} ({e}). Is `scout --daemon` running?",
                crate::toolchain::config::engine_addr("scout")
            );
            relay.publish_failed().await;
            return;
        }
    }

    relay.finish(found_count, Some((1, 1))).await;
}

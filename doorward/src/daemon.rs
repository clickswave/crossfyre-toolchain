use crate::libs::doorward_db::DoorwardDb;
use crate::scanner::{self, ScanParams, StreamEvent};
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
    #[serde(default = "default_response")]
    response: String,
    #[serde(default)]
    save: bool,
    #[serde(flatten)]
    params: serde_json::Value,
}

fn default_response() -> String {
    "queue".to_string()
}

/// Why a port scan is not run through a proxy.
pub(crate) const NOT_THROUGH_A_PROXY: &str = "Port scans cannot run on a node that sends \
     through a proxy: a connect scan measures this machine's own path to each port, and \
     through a proxy every port would read as whatever the proxy answers";

/// One request line, unwrapped. A node wraps an op with the egress it chose; this
/// engine only ever connects directly, so it runs a wrapped op whose egress is
/// direct and refuses one that names a proxy, with the reason, rather than scan
/// from this machine's own address instead. An error is the message the client is
/// answered with, and nothing is sent anywhere.
fn parse_request(line: &str) -> Result<DaemonRequest, String> {
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("Invalid JSON: {e}"))?;
    let (inner, wire) = dguard::split_egress(v)?;
    if let Some(wire) = wire {
        let fields = wire
            .as_object()
            .ok_or("the egress instruction cannot be read")?;
        if let Some(k) = fields
            .keys()
            .find(|k| !["v", "proxy"].contains(&k.as_str()))
        {
            return Err(format!(
                "the egress instruction cannot be read: unknown field {k}"
            ));
        }
        match fields.get("v").and_then(|v| v.as_u64()) {
            Some(1) => {}
            Some(v) => {
                return Err(format!(
                    "egress version {v} is not one this engine reads (it reads 1)"
                ));
            }
            None => return Err("the egress instruction cannot be read: no version".into()),
        }
        if fields.get("proxy").is_some_and(|p| !p.is_null()) {
            return Err(NOT_THROUGH_A_PROXY.to_string());
        }
    }
    serde_json::from_value(inner).map_err(|e| format!("Invalid request: {e}"))
}

pub async fn run(port: u16, db: DoorwardDb) -> Result<(), Box<dyn std::error::Error>> {
    // Loopback unless an operator opts out: this channel has no per-request
    // credential of its own, so the bind address is the boundary.
    let addr = dguard::bind_addr(port);
    let gate = dguard::Gate::from_env();
    let listener = TcpListener::bind(addr).await?;
    gate.announce("Doorward", addr);

    let db = Arc::new(db);

    // Background: clean up expired probe results every 5 minutes
    {
        let db_c = Arc::clone(&db);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                if let Ok(n) = db_c.delete_expired_probe_results().await
                    && n > 0
                {
                    println!("Cleaned {n} expired probe result(s)");
                }
            }
        });
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let gate_clone = gate.clone();
        let db_clone = Arc::clone(&db);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, gate_clone, db_clone).await {
                eprintln!("Connection error from {addr}: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    gate: dguard::Gate,
    db: Arc<DoorwardDb>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        // The bind address is the primary boundary. This is the second one, for
        // deployments that used CFX_DAEMON_BIND to move the listener off loopback;
        // with no token configured it is a no-op.
        if !gate.allows(
            serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .as_ref()
                .and_then(|v| v.get("token"))
                .and_then(|t| t.as_str()),
        ) {
            // Same `type`/`message` envelope as every other reply: a client that
            // breaks on `type == "error"` has to recognise this one, or it waits
            // for a line that never comes. Then close, rather than leaving an
            // unauthenticated peer a socket to retry on.
            let _ = writer
                .write_all(b"{\"type\":\"error\",\"message\":\"unauthorized\"}\n")
                .await;
            break;
        }

        let req = match parse_request(&line) {
            Ok(r) => r,
            Err(message) => {
                let err = serde_json::json!({
                    "type": "error",
                    "operation_id": "",
                    "status": "error",
                    "message": message,
                });
                write_json(&mut writer, &err).await?;
                continue;
            }
        };

        // Streaming mode takes over the connection
        if req.response == "stream" {
            handle_stream_scan(req, writer, Arc::clone(&db)).await?;
            return Ok(());
        }

        // Non-streaming: dispatch and respond
        let response = dispatch(req, Arc::clone(&db)).await;
        write_json(&mut writer, &response).await?;
    }

    Ok(())
}

async fn handle_stream_scan(
    req: DaemonRequest,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    db: Arc<DoorwardDb>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let operation_id = uuid::Uuid::new_v4().to_string();

    let scan_params: ScanParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            write_json(
                &mut writer,
                &StreamEvent::error(&format!("Invalid scan params: {e}")),
            )
            .await?;
            return Ok(());
        }
    };

    if req.save {
        let params_str = serde_json::to_string(&req.params).unwrap_or_default();
        let _ = db
            .create_operation(&operation_id, "scan", &params_str)
            .await;
    }

    // Resolve hosts and compute total probes
    let hosts = scanner::resolve_targets(&scan_params.targets);
    let total = hosts.len() * scan_params.ports.len();

    // Send ack
    write_json(&mut writer, &StreamEvent::ack(&operation_id, total)).await?;

    // Run scan in background, forward events to writer
    let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();
    let oid = operation_id.clone();
    let db_c = Arc::clone(&db);

    tokio::spawn(async move {
        scanner::run_connect_scan(&scan_params, tx).await;
        let _ = db_c.update_operation_status(&oid, "completed", None).await;
    });

    while let Some(ev) = rx.recv().await {
        let done = ev.kind == "done";
        write_json(&mut writer, &ev).await?;
        if done {
            break;
        }
    }

    Ok(())
}

async fn dispatch(req: DaemonRequest, db: Arc<DoorwardDb>) -> serde_json::Value {
    let operation_id = uuid::Uuid::new_v4().to_string();

    match req.operation.as_str() {
        "scan" => {
            let scan_params: ScanParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return serde_json::json!({
                        "operation_id": operation_id,
                        "status": "error",
                        "message": format!("Invalid scan params: {}", e),
                    });
                }
            };

            if req.save {
                let params_str = serde_json::to_string(&req.params).unwrap_or_default();
                let _ = db
                    .create_operation(&operation_id, "scan", &params_str)
                    .await;
            }

            match req.response.as_str() {
                "instant" => {
                    let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();
                    scanner::run_connect_scan(&scan_params, tx).await;

                    let mut results = Vec::new();
                    while let Some(ev) = rx.recv().await {
                        if ev.kind == "result" {
                            results.push(serde_json::to_value(&ev).unwrap());
                        }
                        if ev.kind == "done" {
                            break;
                        }
                    }

                    let _ = db
                        .update_operation_status(&operation_id, "completed", None)
                        .await;

                    serde_json::json!({
                        "operation_id": operation_id,
                        "status": "completed",
                        "results": results,
                    })
                }
                _ => {
                    // Queue mode
                    let oid = operation_id.clone();
                    let db_c = Arc::clone(&db);
                    tokio::spawn(async move {
                        let (tx, mut _rx) = mpsc::unbounded_channel::<StreamEvent>();
                        scanner::run_connect_scan(&scan_params, tx).await;
                        let _ = db_c.update_operation_status(&oid, "completed", None).await;
                    });

                    serde_json::json!({
                        "operation_id": operation_id,
                        "status": "queued",
                    })
                }
            }
        }

        "probe" => {
            // Single port probe
            let host = req.params["host"].as_str().unwrap_or("").to_string();
            let port = req.params["port"].as_u64().unwrap_or(0) as u16;
            let timeout_ms = req.params["timeout"].as_u64().unwrap_or(2000);

            if host.is_empty() || port == 0 {
                return serde_json::json!({
                    "operation_id": operation_id,
                    "status": "error",
                    "message": "host and port are required",
                });
            }

            let params = ScanParams {
                targets: vec![host],
                ports: vec![port],
                technique: "connect".to_string(),
                tasks: 1,
                timeout: timeout_ms,
                delay: 0, // single-port probe path - no pacing needed; daemon-level handles it
                service_detection: req.params["service_detection"].as_bool().unwrap_or(true),
                adaptive: false, // one probe: nothing for the governor to tune
                max_concurrency: None,
                posture: None,
            };

            let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();
            scanner::run_connect_scan(&params, tx).await;

            let mut result = serde_json::json!({ "status": "closed" });
            while let Some(ev) = rx.recv().await {
                if ev.kind == "result" {
                    result = serde_json::to_value(&ev).unwrap();
                    break;
                }
                if ev.kind == "done" {
                    break;
                }
            }

            serde_json::json!({
                "operation_id": operation_id,
                "status": "completed",
                "results": result,
            })
        }

        "db_reset" => match db.truncate_tables().await {
            Ok(_) => serde_json::json!({
                "operation_id": operation_id,
                "status": "completed",
                "message": "All tables truncated.",
            }),
            Err(e) => serde_json::json!({
                "operation_id": operation_id,
                "status": "error",
                "message": format!("DB reset failed: {}", e),
            }),
        },

        unknown => serde_json::json!({
            "operation_id": operation_id,
            "status": "error",
            "message": format!("Unknown operation: {}", unknown),
        }),
    }
}

async fn write_json<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut json = serde_json::to_string(value)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod egress_tests {
    use super::*;
    use serde_json::json;

    fn line(v: serde_json::Value) -> String {
        v.to_string()
    }

    #[test]
    fn a_scan_wrapped_with_a_proxy_is_refused_with_the_reason() {
        let scan = json!({"operation": "scan", "response": "stream",
                          "targets": ["127.0.0.1"], "ports": [22]});
        let wrapped = dguard::wrap_egress(
            &scan,
            &json!({"v": 1, "proxy": "socks5h://u:p@127.0.0.1:1080"}),
        );
        let e = parse_request(&line(wrapped)).unwrap_err();
        assert_eq!(e, NOT_THROUGH_A_PROXY);
        assert!(!e.contains("u:p"), "{e}");
    }

    #[test]
    fn a_scan_wrapped_as_direct_runs_as_it_always_has() {
        let scan = json!({"operation": "scan", "response": "stream"});
        let wrapped = dguard::wrap_egress(&scan, &json!({"v": 1, "proxy": null}));
        let req = parse_request(&line(wrapped)).unwrap();
        assert_eq!(req.operation, "scan");
        assert_eq!(req.response, "stream");
        let unwrapped = parse_request(&line(scan)).unwrap();
        assert_eq!(unwrapped.operation, "scan");
    }

    #[test]
    fn an_egress_this_engine_cannot_read_is_refused() {
        let scan = json!({"operation": "scan"});
        for egress in [
            json!({"v": 2, "proxy": null}),
            json!({"v": 1, "proxy": null, "pace": 1}),
            json!({"proxy": null}),
            json!("direct"),
        ] {
            assert!(
                parse_request(&line(dguard::wrap_egress(&scan, &egress))).is_err(),
                "{egress}"
            );
        }
        // And an egress outside the wrapper is not quietly dropped.
        assert!(parse_request(&line(json!({"operation": "scan", "egress": {}}))).is_err());
    }
}

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
    dguard::exit_when_idle("doorward");
    eprintln!("[doorward] {}", cfx_pacing::load().say());

    let db = Arc::new(db);

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let gate_clone = gate.clone();
        let db_clone = Arc::clone(&db);
        dguard::spawn_busy(async move {
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

        // A line that is not a JSON object is not from a client (an HTTP request
        // from a web page starts that way), and a request without the configured
        // token is not from an authorised one. Either ends the connection, so
        // nothing written after that line is ever read as a request.
        if let Some(reply) = gate.refusal(&line) {
            let _ = writer.write_all(reply.as_bytes()).await;
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

        // What this daemon honours beyond the original protocol, and which process it
        // is, asked before an operation is sent and by a client waiting for the daemon
        // it started. It reads the egress wrapper only to refuse a proxy, so it names no
        // egress version, and a node sends it nothing through one. The connection stays
        // open for the operation that follows.
        if req.operation == "capabilities" {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "capabilities",
                    "scan": ["resolve", "block_internal"],
                    // Which pacing this daemon runs: `module <version>`, or `baseline (<why>)`.
                    "pacing": cfx_pacing::load().label(),
                    "pid": std::process::id(),
                }),
            )
            .await?;
            continue;
        }

        // The scans this daemon keeps, the latest first, one as it was kept, and what they
        // found, oldest first.
        if req.operation == "scans" {
            let answer = cfx_db::scans::answer_scans(&db.pool, cfx_db::scans::Listed::why_not);
            write_json(&mut writer, &answer.await).await?;
            continue;
        }
        if req.operation == "scan_info" {
            let id = req.params["id"].as_str().unwrap_or_default();
            write_json(&mut writer, &cfx_db::found::answer_scan(&db.pool, id).await).await?;
            continue;
        }
        if req.operation == "finding" {
            let id = req.params["id"].as_i64().unwrap_or(0);
            write_json(
                &mut writer,
                &cfx_db::found::answer_finding(&db.pool, id).await,
            )
            .await?;
            continue;
        }
        if req.operation == "findings" {
            let answer = cfx_db::found::answer_findings(
                &db.pool,
                req.params["scan"].as_str(),
                req.params["after"].as_i64(),
                req.params["limit"].as_i64().unwrap_or(200),
            );
            write_json(&mut writer, &answer.await).await?;
            continue;
        }

        // Every operation from here on sends: say which pacing it runs with.
        eprintln!("[doorward] {}: {}", req.operation, cfx_pacing::load().say());

        // Streaming mode takes over the connection. A stopped scan taken up again streams
        // as the scan did.
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

    // The scan as asked for, or a stopped one taken up again with the settings it was
    // kept with.
    let begun = match req.operation.as_str() {
        "resume" => taken_up(&req, &db)
            .await
            .map(|(params, running)| (params, Some(running))),
        _ => match serde_json::from_value::<ScanParams>(req.params.clone()) {
            Ok(params) => {
                let scan = db
                    .start_scan(&params.targets, &req.params, params.fresh_start)
                    .await;
                Ok((params, scan))
            }
            Err(e) => Err(format!("Invalid scan params: {e}")),
        },
    };
    let (scan_params, scan) = match begun {
        Ok(begun) => begun,
        Err(message) => {
            write_json(&mut writer, &StreamEvent::error(&message)).await?;
            return Ok(());
        }
    };
    if req.save {
        let _ = cfx_db::scans::record_operation(
            &db.pool,
            &operation_id,
            "scan",
            scan.as_ref().map(|s| s.id.as_str()),
            &req.params.to_string(),
        )
        .await;
    }

    // Resolve hosts and compute total probes
    let hosts = scanner::resolve_targets(&scan_params.targets);
    let total = hosts.len() * scan_params.ports.len();

    // Send ack, with the scan it is kept as
    let mut ack = serde_json::to_value(StreamEvent::ack(&operation_id, total))?;
    if let Some(running) = &scan {
        ack["scan"] = serde_json::json!(running.id);
    }
    write_json(&mut writer, &ack).await?;

    // Run scan in background, forward events to writer
    let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();
    let oid = operation_id.clone();
    let db_c = Arc::clone(&db);
    // What the scan found, said and how far it got, as every engine keeps it: an open port
    // is a finding, a filtered one is not.
    let mut keeper = cfx_db::found::Keeper::new(&db.pool, scan.as_ref().map(|s| s.id.as_str()));

    dguard::spawn_busy(async move {
        scanner::run_connect_scan(&scan_params, tx).await;
        db_c.finish_scan(scan).await;
        let _ = cfx_db::scans::finish_operation(
            &db_c.pool,
            &oid,
            cfx_db::scans::Status::Completed,
            None,
        )
        .await;
    });

    while let Some(ev) = rx.recv().await {
        let done = ev.kind == "done";
        if kept(&ev) {
            keeper.event(&serde_json::to_value(&ev)?).await;
        }
        write_json(&mut writer, &ev).await?;
        if done {
            break;
        }
    }
    let _ = keeper.flush().await;

    Ok(())
}

/// Whether `ev` is kept with its scan: an open port, and everything but a result.
fn kept(ev: &StreamEvent) -> bool {
    ev.kind != "result" || ev.status.as_deref() == Some("open")
}

/// The stopped scan a `resume` request names, taken up again with the settings it was kept
/// with: or why it cannot be. A port scan keeps nothing to carry on from, so it runs again
/// from the start, under its own record.
async fn taken_up(
    req: &DaemonRequest,
    db: &DoorwardDb,
) -> Result<(ScanParams, cfx_db::scans::Running), String> {
    let id = req.params["scan"]
        .as_str()
        .ok_or("a resume names the scan to take up again")?;
    let (running, settings) = cfx_db::scans::take_up(&db.pool, id, None)
        .await
        .map_err(|e| e.to_string())?;
    match serde_json::from_value(settings) {
        Ok(params) => Ok((params, running)),
        Err(e) => {
            let _ = cfx_db::scans::finish(running, cfx_db::scans::Status::Stopped).await;
            Err(format!(
                "scan {id} was kept with settings this doorward cannot read: {e}"
            ))
        }
    }
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

            let scan = db
                .start_scan(&scan_params.targets, &req.params, scan_params.fresh_start)
                .await;
            if req.save {
                let _ = cfx_db::scans::record_operation(
                    &db.pool,
                    &operation_id,
                    "scan",
                    scan.as_ref().map(|s| s.id.as_str()),
                    &req.params.to_string(),
                )
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

                    db.finish_scan(scan).await;
                    let _ = cfx_db::scans::finish_operation(
                        &db.pool,
                        &operation_id,
                        cfx_db::scans::Status::Completed,
                        None,
                    )
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
                    dguard::spawn_busy(async move {
                        let (tx, mut _rx) = mpsc::unbounded_channel::<StreamEvent>();
                        scanner::run_connect_scan(&scan_params, tx).await;
                        db_c.finish_scan(scan).await;
                        let _ = cfx_db::scans::finish_operation(
                            &db_c.pool,
                            &oid,
                            cfx_db::scans::Status::Completed,
                            None,
                        )
                        .await;
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
                tasks: 1,
                timeout: timeout_ms,
                delay: 0, // single-port probe path - no pacing needed; daemon-level handles it
                service_detection: req.params["service_detection"].as_bool().unwrap_or(true),
                adaptive: false, // one probe: nothing for the governor to tune
                max_concurrency: None,
                posture: None,
                fresh_start: false,
                resolve: Vec::new(),
                block_internal: false,
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

        "db_reset" => {
            match cfx_db::scans::reset(&db.pool, &super::libs::doorward_db::ENGINE).await {
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
            }
        }

        "purge" => match cfx_db::scans::purge_operation(&db.pool, &req.params).await {
            Ok(done) => serde_json::json!({
                "operation_id": operation_id,
                "status": "completed",
                "message": done,
            }),
            Err(why) => serde_json::json!({
                "operation_id": operation_id,
                "status": "error",
                "message": why,
            }),
        },

        unknown => serde_json::json!({
            "operation_id": operation_id,
            "status": "error",
            "message": format!("Unknown operation: {}", unknown),
        }),
    }
}

/// Send `value` to the client, made safe to leave the engine (see
/// [`cfx_db::scans::safe_stream`]): the node relays it to Cloud as it is.
async fn write_json<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut json =
        serde_json::to_string(&cfx_db::scans::safe_stream(&serde_json::to_value(value)?))?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod kept_tests {
    //! What a scan found, kept as every engine keeps it, and read back through the daemon.
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// What a daemon on `pool` answers `ask` with, or every line of a stream until done.
    async fn ask(port: u16, ask: &serde_json::Value) -> Vec<serde_json::Value> {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (r, mut w) = stream.into_split();
        w.write_all(format!("{ask}\n").as_bytes()).await.unwrap();
        let mut lines = BufReader::new(r).lines();
        let mut got = Vec::new();
        while let Ok(Ok(Some(line))) =
            tokio::time::timeout(std::time::Duration::from_secs(20), lines.next_line()).await
        {
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            let last = v["type"] == "done" || v.get("type").is_none();
            got.push(v);
            if last {
                break;
            }
        }
        got
    }

    /// The only open port of a scan is kept as its finding, a closed one is not, and the
    /// `findings` and `scan_info` answers give them back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs PostgreSQL's programs"]
    async fn an_open_port_is_kept_and_read_back() {
        let scratch = cfx_db::testing::Scratch::new(&crate::libs::doorward_db::ENGINE).await;
        let db = Arc::new(DoorwardDb::new(scratch.pool.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dport = listener.local_addr().unwrap().port();
        let serving = Arc::clone(&db);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(handle_connection(
                    stream,
                    dguard::Gate::default(),
                    Arc::clone(&serving),
                ));
            }
        });
        let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let oport = open.local_addr().unwrap().port();
        tokio::spawn(async move { while open.accept().await.is_ok() {} });
        let (closed, _held) = cfx_db::testing::closed_port();
        let events = ask(
            dport,
            &serde_json::json!({"operation": "scan", "response": "stream",
                "targets": ["127.0.0.1"], "ports": [oport, closed], "adaptive": false,
                "timeout": 2000}),
        )
        .await;
        assert!(events.iter().any(|e| e["type"] == "done"), "{events:?}");
        let found = &ask(dport, &serde_json::json!({"operation": "findings"})).await[0];
        let rows = found["findings"].as_array().expect("rows");
        assert_eq!(rows.len(), 1, "{found}");
        assert_eq!(rows[0]["data"]["port"], oport);
        assert_eq!(rows[0]["kind"], "result");
        let ack = events.iter().find(|e| e["type"] == "ack").expect("an ack");
        assert_eq!(
            ack["scan"], rows[0]["scan"],
            "the ack names the scan it is kept as"
        );
        let scan = &ask(
            dport,
            &serde_json::json!({"operation": "scan_info", "id": rows[0]["scan"]}),
        )
        .await[0];
        assert_eq!(scan["scan"]["findings"], 1, "{scan}");
        scratch.done().await;
    }

    /// Only an open port is a finding of a scan.
    #[test]
    fn only_an_open_port_is_kept() {
        let result = |status: &str| StreamEvent::result("127.0.0.1", 80, status, 1);
        assert!(kept(&result("open")));
        assert!(!kept(&result("filtered")));
        assert!(kept(&StreamEvent::ack("op", 1)));
    }
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

#[cfg(test)]
mod http_request_tests {
    //! A web page open in the operator's browser can POST to this port. The browser
    //! writes a request line and headers before the body the page chose, so the
    //! connection has to end at the request line, before the body is read.
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn daemon() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let db = Arc::new(DoorwardDb::unconnected());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(handle_connection(
                    stream,
                    dguard::Gate::default(),
                    Arc::clone(&db),
                ));
            }
        });
        port
    }

    /// Sends `raw` and returns the lines the daemon wrote back, and whether it
    /// closed the connection.
    async fn send(port: u16, raw: &str) -> (Vec<String>, bool) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(raw.as_bytes()).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        let closed = loop {
            match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break true,
                Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
                Err(_) => break false,
            }
        };
        let lines = String::from_utf8_lossy(&got)
            .lines()
            .map(str::to_string)
            .collect();
        (lines, closed)
    }

    /// A service's banner that names a URL with a credential in it and a session cookie
    /// comes out of a scan with neither.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_banner_goes_out_with_no_secret() {
        let service = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let sport = service.local_addr().expect("addr").port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = service.accept().await {
                let _ = sock
                    .write_all(
                        b"220 ready, see http://u:dw-secret-1@x.test/?token=dw-secret-2\r\n\
                          Set-Cookie: s=dw-secret-3\r\n",
                    )
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
        let port = daemon().await;
        let op = serde_json::json!({
            "operation": "scan", "response": "stream", "targets": ["127.0.0.1"],
            "ports": [sport], "service_detection": true, "adaptive": false, "timeout": 2000,
        });
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("{op}\n").as_bytes()).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(Ok(n)) =
            tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if String::from_utf8_lossy(&got).contains("\"done\"") {
                break;
            }
        }
        let out = String::from_utf8_lossy(&got).into_owned();
        assert!(out.contains("220 ready"), "no banner came out: {out}");
        for secret in ["dw-secret-1", "dw-secret-2", "dw-secret-3"] {
            assert!(!out.contains(secret), "{secret} went out: {out}");
        }
    }

    /// The events of the stream scan `op`, to its `done`.
    async fn scan_events(port: u16, op: &serde_json::Value) -> Vec<serde_json::Value> {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (r, mut w) = s.into_split();
        w.write_all(format!("{op}\n").as_bytes()).await.unwrap();
        let mut lines = BufReader::new(r).lines();
        let mut events = Vec::new();
        while let Ok(Ok(Some(line))) =
            tokio::time::timeout(Duration::from_secs(20), lines.next_line()).await
        {
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            let done = v["type"] == "done" || v["type"] == "error";
            events.push(v);
            if done {
                break;
            }
        }
        events
    }

    /// A listener on loopback that counts the connections it is given.
    async fn counted() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = l.local_addr().expect("addr").port();
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&n);
        tokio::spawn(async move {
            while let Ok((_sock, _)) = l.accept().await {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        (port, n)
    }

    fn open_ports(events: &[serde_json::Value]) -> Vec<u64> {
        let mut open: Vec<u64> = events
            .iter()
            .filter(|e| e["type"] == "result" && e["status"] == "open")
            .filter_map(|e| e["port"].as_u64())
            .collect();
        open.sort_unstable();
        open
    }

    /// A name pinned to an address is dialled there on every port the scan tries. The
    /// name is under `.invalid`, which never resolves, so a port found open was reached
    /// through the pin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pinned_name_is_dialled_at_its_address_on_every_port() {
        let (a, _) = counted().await;
        let (b, _) = counted().await;
        let port = daemon().await;
        let mut op = serde_json::json!({
            "operation": "scan", "response": "stream", "targets": ["pinned.invalid"],
            "ports": [a, b], "adaptive": false, "timeout": 2000,
        });
        assert!(open_ports(&scan_events(port, &op).await).is_empty());
        op["resolve"] = serde_json::json!([["pinned.invalid", "127.0.0.1:9"]]);
        let mut want = vec![u64::from(a), u64::from(b)];
        want.sort_unstable();
        assert_eq!(open_ports(&scan_events(port, &op).await), want);
    }

    /// With block_internal, a target at an internal address, its own or a pinned one, is
    /// not dialled at all, and the scan says why.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn block_internal_leaves_an_internal_target_unscanned() {
        let (a, seen) = counted().await;
        let port = daemon().await;
        for target in ["127.0.0.1", "pinned.invalid"] {
            let op = serde_json::json!({
                "operation": "scan", "response": "stream", "targets": [target],
                "ports": [a], "adaptive": false, "timeout": 2000, "block_internal": true,
                "resolve": [["pinned.invalid", "127.0.0.1:9"]],
            });
            let events = scan_events(port, &op).await;
            assert!(
                events.iter().any(|e| e["type"] == "log"
                    && e["message"]
                        .as_str()
                        .is_some_and(|m| m.contains("was not scanned"))),
                "{target}: {events:?}"
            );
            assert!(open_ports(&events).is_empty(), "{target}: {events:?}");
        }
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_http_post_is_closed_at_its_request_line() {
        let port = daemon().await;
        let body = "{\"operation\":\"capabilities\"}\n";
        let raw = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://page.test\r\n\
             Content-Type: text/plain;charset=UTF-8\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (lines, closed) = send(port, &raw).await;
        assert!(closed, "the connection stayed open: {lines:?}");
        assert!(
            lines.len() <= 1,
            "answered the HTTP lines one by one: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("capabilities")),
            "read the body as a request: {lines:?}"
        );
    }

    #[tokio::test]
    async fn capabilities_say_which_process_answers_and_name_no_egress_version() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let port = daemon().await;
        let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (r, mut w) = s.into_split();
        w.write_all(b"{\"operation\":\"capabilities\"}\n")
            .await
            .unwrap();
        let mut lines = BufReader::new(r).lines();
        let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .expect("an answer in time")
            .unwrap()
            .expect("a line");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["type"], "capabilities", "{v}");
        // Which pacing runs, as the engine said it when it started.
        assert_eq!(v["pacing"], cfx_pacing::load().label().as_str());
        assert_eq!(v["pid"], std::process::id(), "{v}");
        assert_eq!(
            v["scan"],
            serde_json::json!(["resolve", "block_internal"]),
            "{v}"
        );
        // A node that read an egress version here would send doorward ops through a
        // proxy, which it refuses.
        assert!(v.get("egress").is_none(), "{v}");
    }

    #[tokio::test]
    async fn a_line_that_is_json_but_not_an_object_closes_too() {
        let port = daemon().await;
        let (lines, closed) = send(port, "[1]\n{\"operation\":\"capabilities\"}\n").await;
        assert!(closed, "the connection stayed open: {lines:?}");
        assert!(
            !lines.iter().any(|l| l.contains("capabilities")),
            "read on past the first line: {lines:?}"
        );
    }
}

#[cfg(test)]
mod flag_tests {
    use crate::scanner::ScanParams;
    use clap::Parser;

    /// Every flag `doorward scan` takes reaches the daemon, from the command line through
    /// the request the client sends, into what the daemon reads: all but the dashboard's
    /// poll timeout, which is the client's own.
    #[test]
    fn every_scan_flag_reaches_the_daemon() {
        let cli = crate::libs::cli_args::Cli::try_parse_from([
            "doorward",
            "scan",
            "10.0.0.1",
            "-p",
            "80",
            "--tasks",
            "7",
            "--timeout",
            "900",
            "--delay",
            "30",
            "--service-detection",
            "--fresh-start",
        ])
        .unwrap();
        let Some(crate::libs::cli_args::Commands::Scan(args)) = cli.command else {
            panic!("not a scan");
        };
        let ports = crate::libs::cli_args::resolve_ports(&args.ports);
        let params: ScanParams =
            serde_json::from_value(crate::scan_request(&args, &ports)).unwrap();
        assert_eq!(params.targets, ["10.0.0.1"]);
        assert_eq!(params.ports, [80]);
        assert_eq!(params.tasks, 7);
        assert_eq!(params.timeout, 900);
        assert_eq!(params.delay, 30);
        assert!(params.service_detection);
        assert!(params.fresh_start);
    }
}

use crate::fingerprint::{self, FpParams};
use crate::libs::toolmark_db::ToolmarkDb;
use cfx_db::scans::Status;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::mpsc;

/// Top-level request over the TCP connection (newline-delimited JSON).
#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
    #[serde(flatten)]
    params: Value,
    /// From the egress wrapper, never from the request's own fields.
    #[serde(skip)]
    egress: transport::Egress,
}

/// One request line: the operation it asks for, unwrapped, with the egress its
/// wrapper names. An error is the message the client is answered with, and nothing
/// is sent anywhere.
fn parse_request(line: &str) -> Result<DaemonRequest, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("Invalid JSON: {e}"))?;
    let (inner, wire) = dguard::split_egress(v)?;
    let egress = transport::Egress::from_request(wire)?;
    let mut req: DaemonRequest =
        serde_json::from_value(inner).map_err(|e| format!("Invalid request: {e}"))?;
    req.egress = egress;
    Ok(req)
}

pub async fn run(
    port: u16,
    db: ToolmarkDb,
    cves: std::sync::Arc<crate::cve::Cves>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Loopback unless an operator opts out: this channel has no per-request
    // credential of its own, so the bind address is the boundary.
    let addr = dguard::bind_addr(port);
    let gate = dguard::Gate::from_env();
    let listener = TcpListener::bind(addr).await?;
    gate.announce("Toolmark", addr);
    dguard::exit_when_idle("toolmark");

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let gate_clone = gate.clone();
        let db = db.clone();
        let cves = cves.clone();
        dguard::spawn_busy(async move {
            if let Err(e) = handle_connection(stream, gate_clone, db, cves).await {
                eprintln!("Connection error from {addr}: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    gate: dguard::Gate,
    db: ToolmarkDb,
    cves: std::sync::Arc<crate::cve::Cves>,
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
                write_line(
                    &mut writer,
                    &serde_json::json!({"type": "error", "message": message}),
                )
                .await?;
                continue;
            }
        };

        match req.operation.as_str() {
            "fingerprint" => {
                handle_fingerprint(req.params, req.egress, &mut writer, &db, cves).await?;
                return Ok(());
            }
            // Non-HTTP service identification: what is really listening on a
            // port, and whether it lets anyone in.
            "services" => {
                handle_services(req.params, req.egress, &mut writer, &db, cves).await?;
                return Ok(());
            }
            // The scans this daemon keeps, the latest first.
            "scans" => write_line(&mut writer, &db.scans().await).await?,
            // What it knows runs where.
            "inventory" => write_line(&mut writer, &db.inventory().await).await?,
            // The signatures it has now, over the pages it kept, and nothing sent.
            "rematch" => {
                handle_rematch(&mut writer, &db).await?;
                return Ok(());
            }
            "resume" => {
                write_line(
                    &mut writer,
                    &serde_json::json!({
                        "type": "error",
                        "message": crate::libs::toolmark_db::NOTHING_TO_TAKE_UP,
                    }),
                )
                .await?;
            }
            "db_reset" | "purge" => {
                let done = match req.operation.as_str() {
                    "db_reset" => {
                        cfx_db::scans::reset(db.pool(), crate::libs::toolmark_db::ENGINE.name)
                            .await
                            .map(|()| "All tables truncated.".to_string())
                            .map_err(|e| format!("DB reset failed: {e}"))
                    }
                    _ => cfx_db::scans::purge_operation(db.pool(), &req.params).await,
                };
                let reply = match done {
                    Ok(message) => serde_json::json!({"status": "completed", "message": message}),
                    Err(message) => serde_json::json!({"status": "error", "message": message}),
                };
                write_line(&mut writer, &reply).await?;
            }
            // What this daemon honours beyond the original protocol. A caller that
            // must not run on a daemon that would ignore an option asks first, and an
            // older daemon answers `Unknown operation` before anything is sent. The
            // connection stays open for the operation that follows.
            "capabilities" => {
                write_line(
                    &mut writer,
                    &serde_json::json!({
                        "type": "capabilities",
                        "fingerprint": ["resolve", "block_internal"],
                        // The version of the egress wrapper this daemon reads.
                        "egress": transport::WIRE_VERSION,
                        // Which process answers, for the client that started it.
                        "pid": std::process::id(),
                    }),
                )
                .await?;
            }
            other => {
                write_line(
                    &mut writer,
                    &serde_json::json!({
                        "type": "error",
                        "message": format!("Unknown operation: {}", other),
                    }),
                )
                .await?;
            }
        }
    }

    Ok(())
}

async fn handle_fingerprint(
    params: Value,
    egress: transport::Egress,
    writer: &mut OwnedWriteHalf,
    db: &ToolmarkDb,
    cves: std::sync::Arc<crate::cve::Cves>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fp: FpParams = match serde_json::from_value(params.clone()) {
        Ok(p) => FpParams { egress, ..p },
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid fingerprint params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let scan = db.start("fingerprint", &fp.target, &params).await;
    let observer = std::sync::Arc::new(db.observer(scan.as_ref(), &params));
    let (tx, rx) = mpsc::unbounded_channel::<Value>();
    let op = dguard::spawn_busy(async move {
        fingerprint::run(fp, tx, observer, cves).await;
    });
    forward(op, rx, writer, db, scan).await
}

/// Run the signatures toolmark has now over the pages it kept, and keep what is new as
/// a fingerprint's findings are kept.
async fn handle_rematch(
    writer: &mut OwnedWriteHalf,
    db: &ToolmarkDb,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let scan = db
        .start("rematch", "the pages toolmark kept", &serde_json::json!({}))
        .await;
    let (tx, rx) = mpsc::unbounded_channel::<Value>();
    let kept = db.clone();
    let op = dguard::spawn_busy(async move {
        crate::rematch::run(&kept, crate::signatures::Signatures::shipped(), tx).await;
    });
    forward(op, rx, writer, db, scan).await
}

/// Write the events of scan `op` as they come, and keep what they found. The scan is
/// kept to its end, after a caller that went away too.
async fn forward(
    op: tokio::task::JoinHandle<()>,
    mut rx: mpsc::UnboundedReceiver<Value>,
    writer: &mut OwnedWriteHalf,
    db: &ToolmarkDb,
    scan: Option<cfx_db::scans::Running>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (out, mut written) = mpsc::unbounded_channel::<Value>();
    let keeping = db.clone();
    dguard::spawn_busy(async move {
        let id = scan.as_ref().map(|s| s.id.clone());
        while let Some(ev) = rx.recv().await {
            keeping.event(id.as_deref(), &ev).await;
            let _ = out.send(ev);
        }
        let ended = match op.await {
            Ok(()) => Status::Completed,
            Err(_) => Status::Failed,
        };
        keeping.finish(scan, ended).await;
    });
    while let Some(ev) = written.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn handle_services(
    params: Value,
    egress: transport::Egress,
    writer: &mut OwnedWriteHalf,
    db: &ToolmarkDb,
    cves: std::sync::Arc<crate::cve::Cves>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sp: crate::services::SvcParams = match serde_json::from_value(params.clone()) {
        Ok(p) => crate::services::SvcParams { egress, ..p },
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid services params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let scan = db.start("services", &sp.targets.join(", "), &params).await;
    let (tx, rx) = mpsc::unbounded_channel::<Value>();
    let op = dguard::spawn_busy(async move {
        crate::services::run(sp, tx, cves).await;
    });
    forward(op, rx, writer, db, scan).await
}

async fn write_line(
    writer: &mut OwnedWriteHalf,
    v: &Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut s = serde_json::to_string(v)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The options a caller that fences toolmark's traffic relies on, counted at a
    //! socket.
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, Lines};
    use tokio::net::tcp::OwnedReadHalf;

    /// A page that answers every request and counts them.
    async fn target() -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let seen = Arc::clone(&counter);
                tokio::spawn(async move {
                    let mut buf = [0u8; 16384];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        seen.fetch_add(1, Ordering::SeqCst);
                        let body = b"<html><head><title>pinned</title></head></html>";
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                             Content-Length: {}\r\n\r\n",
                            body.len()
                        );
                        if sock.write_all(head.as_bytes()).await.is_err()
                            || sock.write_all(body).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    async fn daemon() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(handle_connection(
                    stream,
                    dguard::Gate::default(),
                    ToolmarkDb::unconnected(),
                    crate::cve::snapshot_for_tests(),
                ));
            }
        });
        port
    }

    async fn next_event(lines: &mut Lines<BufReader<OwnedReadHalf>>) -> Option<Value> {
        loop {
            let l = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
                .await
                .ok()?
                .ok()??;
            if let Ok(v) = serde_json::from_str::<Value>(&l) {
                return Some(v);
            }
        }
    }

    /// Ask for the capabilities, then send `op` on the same connection, and read
    /// everything up to `done`.
    async fn ask_then_run(dport: u16, op: Value) -> (Value, Vec<Value>) {
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"{\"operation\":\"capabilities\"}\n")
            .await
            .unwrap();
        let caps = next_event(&mut lines).await.expect("an answer");
        let mut line = op.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();
        let mut events = Vec::new();
        while let Some(ev) = next_event(&mut lines).await {
            let done = ev["type"] == "done";
            events.push(ev);
            if done {
                break;
            }
        }
        (caps, events)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pinned_name_is_fetched_at_the_pinned_address() {
        let (tport, seen) = target().await;
        let dport = daemon().await;
        // `.invalid` never resolves, so a request that arrives came through the pin.
        let (caps, events) = ask_then_run(
            dport,
            serde_json::json!({
                "operation": "fingerprint",
                "target": format!("http://pinned.invalid:{tport}/"),
                "evasive": false,
                "follow_redirects": false,
                "block_internal": true,
                "resolve": [["pinned.invalid", format!("127.0.0.1:{tport}")]],
            }),
        )
        .await;
        assert_eq!(caps["type"], "capabilities", "{caps}");
        for want in ["resolve", "block_internal"] {
            assert!(
                caps["fingerprint"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|x| x == want)),
                "{caps}"
            );
        }
        assert!(seen.load(Ordering::SeqCst) > 0, "the pin was not used");
        let service = events
            .iter()
            .find(|e| e["data"]["type"] == "service")
            .unwrap_or_else(|| panic!("no service record: {events:?}"));
        assert_eq!(service["data"]["title"], "pinned");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn block_internal_refuses_a_name_that_resolves_to_loopback() {
        let (tport, seen) = target().await;
        let dport = daemon().await;
        let (_, events) = ask_then_run(
            dport,
            serde_json::json!({
                "operation": "fingerprint",
                "target": format!("http://localhost:{tport}/"),
                "evasive": false,
                "follow_redirects": false,
                "block_internal": true,
            }),
        )
        .await;
        assert_eq!(seen.load(Ordering::SeqCst), 0, "{events:?}");
        assert!(events.iter().any(|e| e["type"] == "error"), "{events:?}");
    }

    // -----------------------------------------------------------------------
    // The egress wrapper. The fixture sits behind a recording SOCKS5 proxy; every
    // connection it accepts has to be one the proxy opened, so a connection made
    // around the proxy shows up as the difference.

    use cfx_tunnel::recorder::{Fixture, Recorder, to_loopback};

    fn wrapped(inner: Value, egress: Value) -> Value {
        dguard::wrap_egress(&inner, &egress)
    }

    fn through(proxy: &Recorder) -> Value {
        serde_json::json!({"v": 1, "proxy": proxy.url()})
    }

    /// Send `op` and read everything up to `done`, an error, or the end.
    async fn run(dport: u16, op: Value) -> Vec<Value> {
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        let mut line = op.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();
        let mut events = Vec::new();
        while let Some(ev) = next_event(&mut lines).await {
            let last =
                ["done", "error", "capabilities"].contains(&ev["type"].as_str().unwrap_or(""));
            events.push(ev);
            if last {
                break;
            }
        }
        events
    }

    fn assert_all_through(fx: &Fixture, proxy: &Recorder, events: &[Value]) {
        assert!(
            fx.connections() > 0,
            "nothing reached the target: {events:?}"
        );
        assert_eq!(
            fx.connections(),
            proxy.joined(),
            "the target accepted connections the proxy did not open"
        );
        assert!(proxy.seen().iter().all(|t| t.port == fx.port));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrapped_fingerprint_reaches_the_target_only_through_the_proxy() {
        let fx = Fixture::http(
            "text/html",
            "<html><head><title>proxied</title></head></html>".into(),
        )
        .await;
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "fingerprint",
            "target": fx.base(),
            "evasive": false,
        });
        let events = run(dport, wrapped(op, through(&proxy))).await;
        let service = events
            .iter()
            .find(|e| e["data"]["type"] == "service")
            .unwrap_or_else(|| panic!("no service record: {events:?}"));
        assert_eq!(service["data"]["title"], "proxied");
        assert_all_through(&fx, &proxy, &events);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrapped_service_probes_reach_the_target_only_through_the_proxy() {
        let fx = Fixture::banner(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "services",
            "targets": [format!("127.0.0.1:{}", fx.port)],
            "timeout_ms": 2000,
        });
        let events = run(dport, wrapped(op, through(&proxy))).await;
        let service = events
            .iter()
            .find(|e| e["type"] == "service")
            .unwrap_or_else(|| panic!("no service record: {events:?}"));
        assert_eq!(service["service"], "ssh", "{service}");
        assert_all_through(&fx, &proxy, &events);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_proxy_fails_the_fingerprint_and_nothing_goes_direct() {
        let fx = Fixture::http("text/html", "ok".into()).await;
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "fingerprint",
            "target": fx.base(),
            "evasive": false,
            "favicon": false,
        });
        let egress =
            serde_json::json!({"v": 1, "proxy": format!("socks5h://u:p@127.0.0.1:{port}")});
        let events = run(dport, wrapped(op, egress)).await;
        assert!(
            !events.iter().any(|e| e["data"]["type"] == "service"),
            "{events:?}"
        );
        assert_eq!(
            fx.connections(),
            0,
            "the fingerprint went around a dead proxy"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrapped_op_with_an_unknown_egress_version_is_refused_unsent() {
        let fx = Fixture::http("text/html", "ok".into()).await;
        let dport = daemon().await;
        let op = serde_json::json!({"operation": "fingerprint", "target": fx.base()});
        let events = run(
            dport,
            wrapped(op, serde_json::json!({"v": 2, "proxy": null})),
        )
        .await;
        assert_eq!(events[0]["type"], "error", "{events:?}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fx.connections(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrapped_capabilities_name_the_egress_version() {
        let dport = daemon().await;
        let events = run(
            dport,
            wrapped(
                serde_json::json!({"operation": "capabilities"}),
                serde_json::json!({"v": 1, "proxy": null}),
            ),
        )
        .await;
        assert_eq!(events[0]["type"], "capabilities", "{events:?}");
        assert_eq!(events[0]["egress"], 1, "{events:?}");
        assert_eq!(events[0]["pid"], std::process::id(), "{events:?}");
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
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(handle_connection(
                    stream,
                    dguard::Gate::default(),
                    ToolmarkDb::unconnected(),
                    crate::cve::snapshot_for_tests(),
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

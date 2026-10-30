use crate::fingerprint::{self, FpParams};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::mpsc;

/// Top-level request over the TCP connection (newline-delimited JSON).
#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
    #[serde(default = "default_response")]
    #[allow(dead_code)]
    response: String,
    #[serde(flatten)]
    params: Value,
}
fn default_response() -> String {
    "stream".to_string()
}

pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Loopback unless an operator opts out: this channel has no per-request
    // credential of its own, so the bind address is the boundary.
    let addr = dguard::bind_addr(port);
    let gate = dguard::Gate::from_env();
    let listener = TcpListener::bind(addr).await?;
    gate.announce("Toolmark", addr);

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let gate_clone = gate.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, gate_clone).await {
                eprintln!("Connection error from {addr}: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    gate: dguard::Gate,
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

        let req: DaemonRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_line(
                    &mut writer,
                    &serde_json::json!({
                        "type": "error",
                        "message": format!("Invalid JSON: {}", e),
                    }),
                )
                .await?;
                continue;
            }
        };

        match req.operation.as_str() {
            "fingerprint" => {
                handle_fingerprint(req.params, &mut writer).await?;
                return Ok(());
            }
            // Non-HTTP service identification: what is really listening on a
            // port, and whether it lets anyone in.
            "services" => {
                handle_services(req.params, &mut writer).await?;
                return Ok(());
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
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fp: FpParams = match serde_json::from_value(params) {
        Ok(p) => p,
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

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        fingerprint::run(fp, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn handle_services(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sp: crate::services::SvcParams = match serde_json::from_value(params) {
        Ok(p) => p,
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

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        crate::services::run(sp, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
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
                tokio::spawn(handle_connection(stream, dguard::Gate::default()));
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
}

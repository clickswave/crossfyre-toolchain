use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::future::Future;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

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

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Loopback unless an operator opts out: this channel has no per-request
    // credential of its own, so the bind address is the boundary.
    let addr = dguard::bind_addr(port);
    let gate = dguard::Gate::from_env();
    let listener = TcpListener::bind(addr).await?;
    gate.announce("Plessor", addr);
    serve(listener, gate).await?;
    Ok(())
}

/// Accept connections on an already bound listener. Split from `run` so the tests can
/// serve on a port the system picked.
pub(crate) async fn serve(listener: TcpListener, gate: dguard::Gate) -> std::io::Result<()> {
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

async fn handle_connection(stream: TcpStream, gate: dguard::Gate) -> Result<(), BoxError> {
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

        let (w, l, g) = (&mut writer, &mut lines, &gate);
        match req.operation.as_str() {
            "scan" => run_op(req.params, "scan", crate::engine::run, w, l, g).await?,
            "authz" => run_op(req.params, "authz", crate::authz::run, w, l, g).await?,
            "inject" => run_op(req.params, "inject", crate::inject::run, w, l, g).await?,
            "discover" => run_op(req.params, "discover", crate::discover::run, w, l, g).await?,
            "fuzz" => run_op(req.params, "fuzz", crate::fuzz::run, w, l, g).await?,
            "graphql" => run_op(req.params, "graphql", crate::graphql::run, w, l, g).await?,
            // Replay a recorded multi-step flow and test its order. See `flow`.
            "flow" => run_op(req.params, "flow", crate::flow::run, w, l, g).await?,
            // What this daemon honours beyond the original protocol. A caller that
            // must not run on a daemon that would ignore an option asks first, and an
            // older daemon answers `Unknown operation` before anything is sent. The
            // connection stays open for the operation that follows.
            "capabilities" => {
                write_line(
                    w,
                    &serde_json::json!({
                        "type": "capabilities",
                        "cancel": true,
                        "inject": ["follow_redirects", "resolve"],
                    }),
                )
                .await?;
                continue;
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
                continue;
            }
        }
        return Ok(());
    }

    Ok(())
}

/// Is this line a request to stop the operation running on this connection?
fn is_cancel(line: &str, gate: &dguard::Gate) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
        return false;
    };
    v.get("operation").and_then(|o| o.as_str()) == Some("cancel")
        && gate.allows(v.get("token").and_then(|t| t.as_str()))
}

/// Run one operation and relay its events, until it ends or the client stops it.
///
/// Every operation used to run in a task of its own that nothing held on to, so a
/// client that went away left its scan running to the end: a scan whose caller has
/// gone is traffic at somebody's service that nobody will read. Two things now stop
/// it. A `{"operation":"cancel"}` line on the same connection stops it and is
/// answered with `{"type":"done","cancelled":true}`. A write that fails, because the
/// client closed the connection, stops it at the next event.
///
/// The end of the client's input does not. `echo '{...}' | ncat 127.0.0.1 4445` closes
/// its sending side as soon as the request is written, and treating that as a
/// cancellation would end every piped scan before its first request.
///
/// Aborting the task stops the traffic as long as no operation spawns anything
/// detached, which holds for every operation in this tree: the injection pass keeps
/// its endpoint workers in a `JoinSet`, which aborts them when it is dropped.
///
/// The `ack` says `"cancellable": true`, so a client can tell this daemon from one
/// that cannot be stopped and say so rather than claim it stopped.
async fn run_op<P, F, Fut>(
    params: Value,
    what: &str,
    run: F,
    writer: &mut OwnedWriteHalf,
    lines: &mut Lines<BufReader<OwnedReadHalf>>,
    gate: &dguard::Gate,
) -> Result<(), BoxError>
where
    P: DeserializeOwned + Send + 'static,
    F: FnOnce(P, mpsc::UnboundedSender<Value>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let p: P = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid {what} params: {e}"),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let op = tokio::spawn(run(p, tx));
    let mut reading = true;
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(mut ev) => {
                    if ev.get("type").and_then(|t| t.as_str()) == Some("ack")
                        && let Some(o) = ev.as_object_mut()
                    {
                        o.insert("cancellable".into(), Value::Bool(true));
                    }
                    if let Err(e) = write_line(writer, &ev).await {
                        op.abort();
                        return Err(e);
                    }
                }
                None => return Ok(()),
            },
            line = lines.next_line(), if reading => match line {
                Ok(Some(l)) => {
                    if is_cancel(&l, gate) {
                        op.abort();
                        let _ = op.await;
                        write_line(
                            writer,
                            &serde_json::json!({"type": "done", "cancelled": true}),
                        )
                        .await?;
                        return Ok(());
                    }
                }
                Ok(None) | Err(_) => reading = false,
            },
        }
    }
}

async fn write_line(writer: &mut OwnedWriteHalf, v: &Value) -> Result<(), BoxError> {
    let mut s = serde_json::to_string(v)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Cancellation, counted at the target's socket.
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    /// A target that answers every request after `delay` and counts them.
    async fn target(delay: Duration) -> (u16, Arc<AtomicUsize>) {
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
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                seen.fetch_add(1, Ordering::SeqCst);
                                tokio::time::sleep(delay).await;
                                let body = b"<html><body>ok</body></html>";
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
        tokio::spawn(serve(listener, dguard::Gate::default()));
        port
    }

    fn inject_op(tport: u16, n: usize) -> String {
        let endpoints: Vec<Value> = (0..n)
            .map(|i| serde_json::json!({"method": "GET", "url": format!("http://127.0.0.1:{tport}/p{i}?q=1")}))
            .collect();
        let mut s = serde_json::json!({
            "operation": "inject",
            "response": "stream",
            "target": format!("http://127.0.0.1:{tport}"),
            "endpoints": endpoints,
            "classes": ["xss"],
            "evasive": false,
        })
        .to_string();
        s.push('\n');
        s
    }

    async fn next_event(
        lines: &mut Lines<BufReader<OwnedReadHalf>>,
        wait: Duration,
    ) -> Option<Value> {
        loop {
            let l = tokio::time::timeout(wait, lines.next_line())
                .await
                .ok()?
                .ok()??;
            if let Ok(v) = serde_json::from_str::<Value>(&l) {
                return Some(v);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cancel_line_stops_the_operation_and_its_traffic() {
        let (tport, seen) = target(Duration::from_millis(200)).await;
        let dport = daemon().await;
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(inject_op(tport, 50).as_bytes()).await.unwrap();

        let ack = next_event(&mut lines, Duration::from_secs(10))
            .await
            .expect("ack");
        assert_eq!(ack["type"], "ack", "{ack}");
        assert_eq!(ack["cancellable"], true, "{ack}");

        // Wait for traffic to start, so there is something to stop.
        for _ in 0..200 {
            if seen.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            seen.load(Ordering::SeqCst) > 0,
            "the scan never reached the target"
        );

        w.write_all(b"{\"operation\":\"cancel\"}\n").await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let done = loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let ev = next_event(&mut lines, left)
                .await
                .expect("no done within 3 s of the cancel line");
            if ev["type"] == "done" {
                break ev;
            }
        };
        assert_eq!(done["cancelled"], true, "{done}");

        // Requests already on the wire may land; nothing new after that.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let settled = seen.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            seen.load(Ordering::SeqCst),
            settled,
            "requests kept arriving after the scan was cancelled"
        );
    }

    /// A target that answers every request with a redirect to `location`, and counts.
    async fn redirector(location: String) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        let reply =
            format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let (seen, reply) = (Arc::clone(&counter), reply.clone());
                tokio::spawn(async move {
                    let mut buf = [0u8; 16384];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        seen.fetch_add(1, Ordering::SeqCst);
                        if sock.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    /// Send one operation and read its events up to `done`.
    async fn run_to_done(dport: u16, op: &Value) -> Vec<Value> {
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        let mut line = op.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();
        let mut events = Vec::new();
        loop {
            let ev = next_event(&mut lines, Duration::from_secs(120))
                .await
                .expect("the operation ended without a done");
            let done = ev["type"] == "done";
            events.push(ev);
            if done {
                return events;
            }
        }
    }

    fn one_endpoint_op(url: &str) -> Value {
        serde_json::json!({
            "operation": "inject",
            "response": "stream",
            "target": url,
            "endpoints": [{"method": "GET", "url": url}],
            "classes": ["xss"],
            "evasive": false,
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn follow_redirects_false_keeps_every_request_on_the_target() {
        let (elsewhere, elsewhere_seen) = target(Duration::ZERO).await;
        let (rport, redirector_seen) =
            redirector(format!("http://127.0.0.1:{elsewhere}/admin")).await;
        let dport = daemon().await;
        let url = format!("http://127.0.0.1:{rport}/p?q=1");

        let mut op = one_endpoint_op(&url);
        op["follow_redirects"] = Value::Bool(false);
        run_to_done(dport, &op).await;
        assert!(
            redirector_seen.load(Ordering::SeqCst) > 0,
            "nothing was sent"
        );
        assert_eq!(
            elsewhere_seen.load(Ordering::SeqCst),
            0,
            "a redirect was followed with follow_redirects false"
        );

        // Left out, the old behaviour stands, so the fixture does redirect.
        run_to_done(dport, &one_endpoint_op(&url)).await;
        assert!(elsewhere_seen.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pinned_name_is_dialled_at_the_pinned_address() {
        let (tport, seen) = target(Duration::ZERO).await;
        let dport = daemon().await;
        // `.invalid` never resolves, so anything that arrives came through the pin.
        let url = format!("http://pinned.invalid:{tport}/p?q=1");
        let mut op = one_endpoint_op(&url);
        op["resolve"] = serde_json::json!([["pinned.invalid", format!("127.0.0.1:{tport}")]]);
        run_to_done(dport, &op).await;
        assert!(seen.load(Ordering::SeqCst) > 0, "the pin was not used");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn capabilities_are_answered_and_the_connection_stays_open() {
        let (tport, seen) = target(Duration::ZERO).await;
        let dport = daemon().await;
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"{\"operation\":\"capabilities\"}\n")
            .await
            .unwrap();
        let caps = next_event(&mut lines, Duration::from_secs(5))
            .await
            .expect("an answer");
        assert_eq!(caps["type"], "capabilities", "{caps}");
        for want in ["follow_redirects", "resolve"] {
            assert!(
                caps["inject"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|x| x == want)),
                "{caps}"
            );
        }
        assert_eq!(caps["cancel"], true, "{caps}");
        // The operation itself still goes on the same connection.
        w.write_all(inject_op(tport, 1).as_bytes()).await.unwrap();
        let ack = next_event(&mut lines, Duration::from_secs(10))
            .await
            .expect("ack");
        assert_eq!(ack["type"], "ack", "{ack}");
        for _ in 0..200 {
            if seen.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(seen.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_half_closed_client_still_gets_its_results() {
        let (tport, seen) = target(Duration::from_millis(0)).await;
        let dport = daemon().await;
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(inject_op(tport, 1).as_bytes()).await.unwrap();
        // What `echo '{...}' | ncat` does once the request is written.
        w.shutdown().await.unwrap();

        let done = loop {
            let ev = next_event(&mut lines, Duration::from_secs(120))
                .await
                .expect("the operation ended without a done");
            if ev["type"] == "done" {
                break ev;
            }
        };
        assert!(done.get("cancelled").is_none(), "{done}");
        assert!(
            seen.load(Ordering::SeqCst) > 0,
            "the scan never reached the target"
        );
    }
}

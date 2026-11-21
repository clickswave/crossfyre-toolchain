use crate::plessor_db::PlessorDb;
use crate::template::Packs;
use cfx_db::scans::Status;
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
    /// From the egress wrapper, never from the request's own fields.
    #[serde(skip)]
    egress: transport::Egress,
}
fn default_response() -> String {
    "stream".to_string()
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

/// An op's parameters, which carry the egress the daemon read off the request.
pub(crate) trait Routed {
    fn route(&mut self, egress: transport::Egress);
}

macro_rules! routed {
    ($($t:ty),* $(,)?) => {$(
        impl Routed for $t {
            fn route(&mut self, egress: transport::Egress) {
                self.egress = egress;
            }
        }
    )*};
}

routed!(
    crate::engine::ScanParams,
    crate::authz::AuthzParams,
    crate::inject::InjectParams,
    crate::discover::DiscoverParams,
    crate::fuzz::FuzzParams,
    crate::graphql::GraphqlParams,
    crate::flow::FlowParams,
);

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // The database being briefly unreachable is not a reason to exit: wait for it,
    // saying why each time, and start as soon as it answers.
    let db = dguard::wait_for(
        "the database",
        std::time::Duration::from_secs(3600),
        || async {
            let pool = cfx_db::ensure_ready(&crate::plessor_db::ENGINE)
                .await
                .map_err(|e| e.to_string())?;
            cfx_db::scans::stop_abandoned(&pool)
                .await
                .map_err(|e| e.to_string())?;
            Ok::<_, String>(PlessorDb::new(pool))
        },
    )
    .await?;
    // Loopback unless an operator opts out: this channel has no per-request
    // credential of its own, so the bind address is the boundary.
    let addr = dguard::bind_addr(port);
    let gate = dguard::Gate::from_env();
    let listener = TcpListener::bind(addr).await?;
    gate.announce("Plessor", addr);
    dguard::exit_when_idle("plessor");
    // What `crossfyre update` put in the toolchain directory, or what is compiled in.
    let packs = std::sync::Arc::new(Packs::load(dguard::toolchain_dir().as_deref()));
    eprintln!("[plessor] templates from {}", packs.now().from);
    serve(listener, gate, db, packs).await?;
    Ok(())
}

/// Accept connections on an already bound listener. Split from `run` so the tests can
/// serve on a port the system picked.
pub(crate) async fn serve(
    listener: TcpListener,
    gate: dguard::Gate,
    db: PlessorDb,
    packs: std::sync::Arc<Packs>,
) -> std::io::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let gate_clone = gate.clone();
        let db = db.clone();
        let packs = packs.clone();
        dguard::spawn_busy(async move {
            if let Err(e) = handle_connection(stream, gate_clone, db, packs).await {
                eprintln!("Connection error from {addr}: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    gate: dguard::Gate,
    db: PlessorDb,
    packs: std::sync::Arc<Packs>,
) -> Result<(), BoxError> {
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

        let (params, egress) = (req.params, req.egress);
        // The template scan keeps its plan; every operation keeps its record and findings.
        let scan =
            |p, tx, id| crate::engine::run(p, tx, std::sync::Arc::new(db.ledger(id)), packs.now());
        macro_rules! op {
            ($what:literal, $run:expr) => {
                run_op(
                    params,
                    egress,
                    $what,
                    $run,
                    &mut writer,
                    &mut lines,
                    &gate,
                    &db,
                    None,
                )
                .await?
            };
        }
        match req.operation.as_str() {
            "scan" => op!("scan", scan),
            // A stopped template scan, taken up again with the request it was kept with.
            "resume" => match db
                .taken_up(params["scan"].as_str().unwrap_or_default())
                .await
            {
                Ok((kept, taken)) => {
                    run_op(
                        kept,
                        egress,
                        "scan",
                        scan,
                        &mut writer,
                        &mut lines,
                        &gate,
                        &db,
                        Some(taken),
                    )
                    .await?
                }
                Err(message) => {
                    write_line(
                        &mut writer,
                        &serde_json::json!({"type": "error", "message": message}),
                    )
                    .await?;
                    continue;
                }
            },
            // The scans this daemon keeps, the latest first.
            "scans" => {
                write_line(&mut writer, &db.scans().await).await?;
                continue;
            }
            // Read the pack in the toolchain directory again, as `crossfyre update` asks
            // after it writes a new one. A scan running goes on with what it started with.
            "reload" => {
                let reply = match packs.reload().await {
                    Ok(said) => serde_json::json!({"status": "completed", "message": said}),
                    Err(why) => serde_json::json!({"status": "error", "message": why}),
                };
                write_line(&mut writer, &reply).await?;
                continue;
            }
            "authz" => op!("authz", plain(crate::authz::run)),
            "inject" => op!("inject", plain(crate::inject::run)),
            "discover" => op!("discover", plain(crate::discover::run)),
            "fuzz" => op!("fuzz", plain(crate::fuzz::run)),
            "graphql" => op!("graphql", plain(crate::graphql::run)),
            // Replay a recorded multi-step flow and test its order. See `flow`.
            "flow" => op!("flow", plain(crate::flow::run)),
            "db_reset" | "purge" => {
                let done = match req.operation.as_str() {
                    "db_reset" => cfx_db::scans::reset(db.pool(), crate::plessor_db::ENGINE.name)
                        .await
                        .map(|()| "All tables truncated.".to_string())
                        .map_err(|e| format!("DB reset failed: {e}")),
                    _ => cfx_db::scans::purge_operation(db.pool(), &params).await,
                };
                let reply = match done {
                    Ok(message) => serde_json::json!({"status": "completed", "message": message}),
                    Err(message) => serde_json::json!({"status": "error", "message": message}),
                };
                write_line(&mut writer, &reply).await?;
                continue;
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
                        "cancel": true,
                        "inject": ["follow_redirects", "resolve", "verify_certs"],
                        // The version of the egress wrapper this daemon reads.
                        "egress": transport::WIRE_VERSION,
                        // Which process answers, for the client that started it.
                        "pid": std::process::id(),
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
///
/// The operation is kept as a scan of its own, or as `taken`, a stopped one taken up
/// again, which it hands back as stopped when its settings no longer parse.
#[allow(clippy::too_many_arguments)]
async fn run_op<P, F, Fut>(
    params: Value,
    egress: transport::Egress,
    what: &str,
    run: F,
    writer: &mut OwnedWriteHalf,
    lines: &mut Lines<BufReader<OwnedReadHalf>>,
    gate: &dguard::Gate,
    db: &PlessorDb,
    taken: Option<cfx_db::scans::Running>,
) -> Result<(), BoxError>
where
    P: DeserializeOwned + Routed + Send + 'static,
    F: FnOnce(P, mpsc::UnboundedSender<Value>, Option<String>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let asked = params.clone();
    let p: P = match serde_json::from_value(params) {
        Ok(mut p) => {
            P::route(&mut p, egress);
            p
        }
        Err(e) => {
            db.finish(taken, Status::Stopped).await;
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

    let scan = match taken {
        Some(taken) => Some(taken),
        None => db.start(what, &asked).await,
    };
    let id = scan.as_ref().map(|s| s.id.clone());
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let op = dguard::spawn_busy(run(p, tx, id.clone()));
    let mut reading = true;
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(mut ev) => {
                    db.event(id.as_deref(), &ev).await;
                    acked(&mut ev, id.as_deref());
                    if let Err(e) = write_line(writer, &ev).await {
                        op.abort();
                        db.finish(scan, Status::Stopped).await;
                        return Err(e);
                    }
                }
                None => {
                    let ended = match op.await {
                        Ok(()) => Status::Completed,
                        Err(_) => Status::Failed,
                    };
                    db.finish(scan, ended).await;
                    return Ok(());
                }
            },
            line = lines.next_line(), if reading => match line {
                Ok(Some(l)) => {
                    if is_cancel(&l, gate) {
                        op.abort();
                        let _ = op.await;
                        db.finish(scan, Status::Stopped).await;
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

/// An `ack` says the operation can be cancelled, and which scan it is when the scan is
/// kept, so a client can name it, as one writing lead answers back to toolmark does.
fn acked(ev: &mut Value, scan: Option<&str>) {
    if ev.get("type").and_then(|t| t.as_str()) == Some("ack")
        && let Some(o) = ev.as_object_mut()
    {
        o.insert("cancellable".into(), Value::Bool(true));
        if let Some(scan) = scan {
            o.insert("scan".into(), Value::String(scan.to_string()));
        }
    }
}

/// An operation that keeps nothing of its own between runs, as [`run_op`] takes one.
fn plain<P, F, Fut>(run: F) -> impl FnOnce(P, mpsc::UnboundedSender<Value>, Option<String>) -> Fut
where
    F: FnOnce(P, mpsc::UnboundedSender<Value>) -> Fut,
{
    move |p, tx, _| run(p, tx)
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

    /// An ack names the scan when it is kept, and nothing else is touched.
    #[test]
    fn an_ack_names_the_scan_it_is() {
        let mut ack = serde_json::json!({"type": "ack", "target": "http://app.test"});
        acked(&mut ack, Some("s1"));
        assert_eq!(
            ack,
            serde_json::json!({"type": "ack", "target": "http://app.test", "cancellable": true,
                "scan": "s1"})
        );
        let mut unkept = serde_json::json!({"type": "ack"});
        acked(&mut unkept, None);
        assert!(unkept.get("scan").is_none());
        let mut finding = serde_json::json!({"type": "finding"});
        acked(&mut finding, Some("s1"));
        assert_eq!(finding, serde_json::json!({"type": "finding"}));
    }

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
        tokio::spawn(serve(
            listener,
            dguard::Gate::default(),
            PlessorDb::unconnected(),
            std::sync::Arc::new(Packs::load(None)),
        ));
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

    /// A target that sends `/p` to `/landing` on itself and answers that, counting
    /// the requests that reach `/landing`.
    async fn same_origin_redirector() -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let landed = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&landed);
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
                        let head = String::from_utf8_lossy(&buf[..n]);
                        let path = head.split_whitespace().nth(1).unwrap_or("");
                        let reply = if path.starts_with("/landing") {
                            seen.fetch_add(1, Ordering::SeqCst);
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                        } else {
                            "HTTP/1.1 302 Found\r\nLocation: /landing\r\nContent-Length: 0\r\n\r\n"
                        };
                        if sock.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, landed)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn follow_redirects_false_keeps_every_request_on_the_target() {
        let (sport, landed) = same_origin_redirector().await;
        let dport = daemon().await;
        let url = format!("http://127.0.0.1:{sport}/p?q=1");

        let mut op = one_endpoint_op(&url);
        op["follow_redirects"] = Value::Bool(false);
        run_to_done(dport, &op).await;
        assert_eq!(
            landed.load(Ordering::SeqCst),
            0,
            "a redirect was followed with follow_redirects false"
        );

        // Left out, the old behaviour stands, so the fixture does redirect.
        run_to_done(dport, &one_endpoint_op(&url)).await;
        assert!(landed.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_redirect_off_the_target_is_never_followed() {
        // With follow_redirects left on, a redirect is followed only on the
        // target's own origin. Another host, here one that answers everything, is
        // not sent the probes.
        let (elsewhere, elsewhere_seen) = target(Duration::ZERO).await;
        let (rport, redirector_seen) =
            redirector(format!("http://127.0.0.1:{elsewhere}/admin")).await;
        let dport = daemon().await;
        let url = format!("http://127.0.0.1:{rport}/p?q=1");

        run_to_done(dport, &one_endpoint_op(&url)).await;
        assert!(
            redirector_seen.load(Ordering::SeqCst) > 0,
            "nothing was sent"
        );
        assert_eq!(
            elsewhere_seen.load(Ordering::SeqCst),
            0,
            "a redirect off the target's origin was followed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_template_scan_does_not_follow_a_redirect_off_the_target() {
        let (elsewhere, elsewhere_seen) = target(Duration::ZERO).await;
        let (rport, redirector_seen) =
            redirector(format!("http://127.0.0.1:{elsewhere}/admin")).await;
        let dport = daemon().await;
        let dir = std::env::temp_dir().join(format!("plessor-redirect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("probe.yaml"),
            "id: redirect-probe\n\
             info:\n  name: redirect probe\n  severity: info\n\
             http:\n  - method: POST\n    path:\n\
             \x20     - \"{{BaseURL}}/form\"\n    body: \"q=probe\"\n    matchers:\n\
             \x20     - type: status\n        status:\n          - 200\n",
        )
        .unwrap();
        let op = serde_json::json!({
            "operation": "scan",
            "response": "stream",
            "target": format!("http://127.0.0.1:{rport}"),
            "templates_dir": dir.to_string_lossy(),
            "only": ["redirect-probe"],
            "evasive": false,
            "follow_redirects": true,
            "timeout_ms": 5000,
        });
        let events = run_to_done(dport, &op).await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            redirector_seen.load(Ordering::SeqCst) > 0,
            "nothing was sent: {events:?}"
        );
        assert_eq!(
            elsewhere_seen.load(Ordering::SeqCst),
            0,
            "a template request followed a redirect off the target"
        );
    }

    /// Given what toolmark saw, a scan runs the general templates and the ones about a
    /// product it saw, and says which it held back and from what; given nothing, it runs
    /// every template, as it always did.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_scan_holds_back_the_templates_for_products_toolmark_did_not_see() {
        let (tport, _) = target(Duration::ZERO).await;
        let dport = daemon().await;
        let dir = std::env::temp_dir().join(format!("plessor-choice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let probe = |id: &str, meta: &str| {
            format!(
                "id: {id}\ninfo:\n  name: {id}\n  severity: info\n  metadata:\n{meta}\
                 http:\n  - method: GET\n    path:\n      - \"{{{{BaseURL}}}}/{id}\"\n    \
                 matchers:\n      - type: word\n        words:\n          - ok\n"
            )
        };
        std::fs::write(
            dir.join("general.yaml"),
            probe("general-probe", "    category: misc\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("widget.yaml"),
            probe("widget-probe", "    vendor: acme\n    product: widget\n"),
        )
        .unwrap();
        // The pack's CVE-2021-41773 is asked for only where it is to be held back: run, it
        // waits out its raw requests' timeouts against this target.
        let scan = |products: Option<serde_json::Value>, with_pack_cve: bool| {
            let mut only = vec!["general-probe", "widget-probe"];
            if with_pack_cve {
                only.push("cve-2021-41773");
            }
            let mut op = serde_json::json!({
                "operation": "scan",
                "response": "stream",
                "target": format!("http://127.0.0.1:{tport}"),
                "templates_dir": dir.to_string_lossy(),
                "pack": true,
                "only": only,
                "evasive": false,
                "timeout_ms": 5000,
            });
            if let Some(p) = products {
                op["products"] = p;
                op["products_from"] = serde_json::json!("toolmark's inventory of the test");
            }
            op
        };
        let found = |events: &[Value]| {
            let mut ids: Vec<String> = events
                .iter()
                .filter(|e| e["type"] == "finding")
                .filter_map(|e| e["data"]["template"].as_str().map(str::to_string))
                .collect();
            ids.sort();
            ids.dedup();
            ids
        };
        let held = |events: &[Value]| {
            events
                .iter()
                .find(|e| e["type"] == "templates_held_back")
                .cloned()
        };

        let events = run_to_done(
            dport,
            &scan(Some(serde_json::json!(["a:acme:gadget"])), true),
        )
        .await;
        assert_eq!(found(&events), ["general-probe"]);
        let said = held(&events).expect("the held back templates are said");
        assert_eq!(said["count"], 2);
        assert_eq!(
            said["templates"],
            serde_json::json!(["CVE-2021-41773", "widget-probe"]),
            "the pack's and the folder's alike"
        );
        assert_eq!(said["from"], "toolmark's inventory of the test");
        assert_eq!(
            said["reason"],
            "toolmark's inventory of the test names none of its products"
        );

        let events = run_to_done(
            dport,
            &scan(Some(serde_json::json!(["a:acme:widget"])), false),
        )
        .await;
        assert_eq!(found(&events), ["general-probe", "widget-probe"]);
        assert!(held(&events).is_none(), "{:?}", held(&events));

        let events = run_to_done(dport, &scan(None, false)).await;
        assert_eq!(
            found(&events),
            ["general-probe", "widget-probe"],
            "as it always did"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The leads a scan is given come back answered: confirmed where the template for the
    /// CVE found it, checked and not found, with the line that this is no proof, where it
    /// ran and found nothing, and not checked where no template checks the CVE.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_scan_answers_the_leads_it_was_given() {
        let (tport, _) = target(Duration::ZERO).await;
        let dport = daemon().await;
        let dir = std::env::temp_dir().join(format!("plessor-leads-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cve = |id: &str, word: &str| {
            format!(
                "id: {id}\ninfo:\n  name: {id}\n  severity: high\n  classification:\n    \
                 cve-id: {id}\nhttp:\n  - method: GET\n    path:\n      - \"{{{{BaseURL}}}}/{id}\"\n    \
                 matchers:\n      - type: word\n        words:\n          - {word}\n"
            )
        };
        std::fs::write(dir.join("hit.yaml"), cve("CVE-2099-0001", "ok")).unwrap();
        std::fs::write(dir.join("miss.yaml"), cve("CVE-2099-0002", "absent-marker")).unwrap();
        let lead =
            |cve: &str| serde_json::json!({"cve": cve, "product": "Widget", "severity": "high"});
        let op = serde_json::json!({
            "operation": "scan",
            "response": "stream",
            "target": format!("http://127.0.0.1:{tport}"),
            "templates_dir": dir.to_string_lossy(),
            "only": ["CVE-2099-0001", "CVE-2099-0002"],
            "leads": [lead("CVE-2099-0001"), lead("CVE-2099-0002"), lead("CVE-2099-0003")],
            "products_from": "toolmark's inventory of the test",
            "evasive": false,
            "timeout_ms": 5000,
        });
        let events = run_to_done(dport, &op).await;
        let _ = std::fs::remove_dir_all(&dir);
        let given = events
            .iter()
            .find(|e| e["type"] == "leads")
            .expect("leads said");
        assert_eq!(given["leads"].as_array().unwrap().len(), 3);
        let answers = events
            .iter()
            .find(|e| e["type"] == "lead_answers")
            .unwrap_or_else(|| panic!("no lead_answers in {events:?}"));
        let said: Vec<(&str, &str)> = answers["answers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["cve"].as_str().unwrap(), a["answer"].as_str().unwrap()))
            .collect();
        assert_eq!(
            said,
            [
                ("CVE-2099-0001", "confirmed"),
                ("CVE-2099-0002", "checked, not found"),
                ("CVE-2099-0003", "not checked"),
            ]
        );
        assert_eq!(answers["answers"][2]["reason"], "no template checks it");
        assert_eq!(answers["not_proof"], cfx_cve::inventory::NOT_PROOF);
        assert_eq!(answers["from"], "toolmark's inventory of the test");
        let at = |kind: &str| events.iter().position(|e| e["type"] == kind).unwrap();
        assert!(at("lead_answers") < at("done"));
    }

    /// A template whose method changes the target is not run, and the scan says so in
    /// the same event as the templates it held back for their products, with why.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_template_that_changes_the_target_is_said_held_back() {
        let (tport, _) = target(Duration::ZERO).await;
        let dport = daemon().await;
        let dir = std::env::temp_dir().join(format!("plessor-writes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rewrite.yaml"),
            "id: rewrite-probe\ninfo:\n  name: rewrite probe\n  severity: high\n\
             http:\n  - method: PATCH\n    path:\n      - \"{{BaseURL}}/account\"\n    \
             body: \"{}\"\n    matchers:\n      - type: word\n        words:\n          - ok\n",
        )
        .unwrap();
        let op = serde_json::json!({
            "operation": "scan",
            "response": "stream",
            "target": format!("http://127.0.0.1:{tport}"),
            "templates_dir": dir.to_string_lossy(),
            "only": ["rewrite-probe"],
            "evasive": false,
            "timeout_ms": 5000,
        });
        let events = run_to_done(dport, &op).await;
        let _ = std::fs::remove_dir_all(&dir);
        let said = events
            .iter()
            .find(|e| e["type"] == "templates_held_back")
            .unwrap_or_else(|| panic!("no templates_held_back in {events:?}"));
        assert_eq!(said["templates"], serde_json::json!(["rewrite-probe"]));
        assert_eq!(said["count"], 1);
        assert_eq!(said["reason"], "what it sends changes the target");
        assert!(
            said["message"]
                .as_str()
                .unwrap()
                .contains("were NOT run: rewrite-probe"),
            "{said}"
        );
        assert!(!events.iter().any(|e| e["type"] == "finding"), "{events:?}");
    }

    /// A template in the --templates folder with a pack template's id runs in its place,
    /// once: the folder's is the one that finds, and the scan counts one template.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_folder_template_with_a_pack_templates_id_replaces_it() {
        let (tport, _) = target(Duration::ZERO).await;
        let dport = daemon().await;
        let dir = std::env::temp_dir().join(format!("plessor-replace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("mine.yaml"),
            "id: CVE-2021-41773\ninfo:\n  name: my own\n  severity: info\n\
             http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/mine\"\n    \
             matchers:\n      - type: word\n        words:\n          - ok\n",
        )
        .unwrap();
        let op = serde_json::json!({
            "operation": "scan",
            "response": "stream",
            "target": format!("http://127.0.0.1:{tport}"),
            "templates_dir": dir.to_string_lossy(),
            "pack": true,
            "only": ["cve-2021-41773"],
            "evasive": false,
            "timeout_ms": 5000,
        });
        let events = run_to_done(dport, &op).await;
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            events
                .iter()
                .any(|e| e["type"] == "finding" && e["data"]["template"] == "CVE-2021-41773"),
            "the folder's template found: {events:?}"
        );
        let totals: Vec<&Value> = events
            .iter()
            .filter(|e| e["type"] == "progress")
            .map(|e| &e["total"])
            .collect();
        assert!(
            !totals.is_empty() && totals.iter().all(|t| **t == 1),
            "{totals:?}"
        );
    }

    /// `reload`, as `crossfyre update` sends it after it writes a new pack, has the next
    /// scan run the pack's templates: one that was not there before runs after it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reload_has_the_next_scan_run_the_new_pack() {
        let (tport, _) = target(Duration::ZERO).await;
        let dir = std::env::temp_dir().join(format!("plessor-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let dport = listener.local_addr().expect("addr").port();
        tokio::spawn(serve(
            listener,
            dguard::Gate::default(),
            PlessorDb::unconnected(),
            Arc::new(Packs::load(Some(&dir))),
        ));
        let op = serde_json::json!({
            "operation": "scan",
            "response": "stream",
            "target": format!("http://127.0.0.1:{tport}"),
            "pack": true,
            "only": ["acme-probe"],
            "evasive": false,
            "timeout_ms": 5000,
        });
        let found = |events: &[Value]| {
            events
                .iter()
                .any(|e| e["type"] == "finding" && e["data"]["template"] == "acme-probe")
        };
        assert!(
            !found(&run_to_done(dport, &op).await),
            "not in the compiled pack"
        );
        crate::template::tests::install_pack(
            &dir,
            cfx_pack::COMPILED.sequence + 1,
            &[crate::template::tests::ACME_PROBE],
        );
        assert!(
            !found(&run_to_done(dport, &op).await),
            "not read until told"
        );
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"{\"operation\":\"reload\"}\n").await.unwrap();
        let answer = next_event(&mut lines, Duration::from_secs(30))
            .await
            .expect("an answer");
        assert_eq!(answer["status"], "completed", "{answer}");
        assert!(
            answer["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("templates from crossfyre-templates ")),
            "{answer}"
        );
        assert!(found(&run_to_done(dport, &op).await), "the new pack runs");
        std::fs::remove_dir_all(&dir).unwrap();
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
        for want in ["follow_redirects", "resolve", "verify_certs"] {
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

    // -----------------------------------------------------------------------
    // The egress wrapper. A fixture that counts its connections sits behind a
    // recording SOCKS5 proxy; every connection the fixture accepts has to be one
    // the proxy opened, so a connection made around the proxy shows up as the
    // difference.

    use cfx_tunnel::recorder::{Fixture, Recorder, name_of, to_loopback};

    /// A name only the proxy can be trusted with: a client that looked it up
    /// itself would fail rather than reach anything.
    const ONLY_THE_PROXY: &str = "only-the-proxy-knows.invalid";

    fn wrapped(inner: Value, egress: Value) -> Value {
        dguard::wrap_egress(&inner, &egress)
    }

    fn through(proxy: &Recorder) -> Value {
        serde_json::json!({"v": 1, "proxy": proxy.url()})
    }

    /// Send one line and read the first event that comes back.
    async fn first_answer(dport: u16, op: &Value) -> Value {
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        let mut line = op.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();
        next_event(&mut lines, Duration::from_secs(10))
            .await
            .expect("an answer")
    }

    /// Send one op and read its events until `done` or the connection closes.
    async fn run_to_end(dport: u16, op: &Value) -> Vec<Value> {
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        let mut line = op.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();
        let mut events = Vec::new();
        while let Some(ev) = next_event(&mut lines, Duration::from_secs(60)).await {
            let done = ev["type"] == "done";
            events.push(ev);
            if done {
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_wrapped_inject_op_reaches_the_target_only_through_the_proxy() {
        let fx = Fixture::http("text/html", "<html><body>ok</body></html>".into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let url = format!("{}/p?q=1", fx.base());
        let events = run_to_done(dport, &wrapped(one_endpoint_op(&url), through(&proxy))).await;
        assert_all_through(&fx, &proxy, &events);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_wrapped_template_scan_sends_its_raw_requests_through_the_proxy_too() {
        // An `unsafe` template goes out over a raw socket rather than the HTTP
        // client. The target is a name that resolves nowhere, so a raw send that
        // went around the proxy would never arrive.
        let fx = Fixture::http("text/html", "<html><body>ok</body></html>".into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let dir = std::env::temp_dir().join(format!("plessor-egress-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("raw.yaml"),
            "id: egress-raw-probe\n\
             info:\n  name: raw probe\n  severity: info\n\
             http:\n  - method: GET\n    unsafe: true\n    path:\n\
             \x20     - \"{{BaseURL}}/raw/.%2e/probe\"\n    matchers:\n\
             \x20     - type: status\n        status:\n          - 200\n",
        )
        .unwrap();
        let op = serde_json::json!({
            "operation": "scan",
            "response": "stream",
            "target": format!("http://{ONLY_THE_PROXY}:{}", fx.port),
            "templates_dir": dir.to_string_lossy(),
            "only": ["egress-raw-probe"],
            "evasive": false,
            "timeout_ms": 5000,
        });
        let events = run_to_done(dport, &wrapped(op, through(&proxy))).await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            fx.requests().iter().any(|l| l.contains("/raw/.%2e/probe")),
            "the raw request never arrived: {:?} {events:?}",
            fx.requests()
        );
        assert_all_through(&fx, &proxy, &events);
        assert!(
            proxy
                .seen()
                .iter()
                .all(|t| name_of(t) == Some(ONLY_THE_PROXY)),
            "the name went to the proxy unresolved: {:?}",
            proxy.seen()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_wrapped_op_with_an_unknown_egress_version_is_refused_unsent() {
        let fx = Fixture::http("text/html", "ok".into()).await;
        let dport = daemon().await;
        let url = format!("{}/p?q=1", fx.base());
        let answer = first_answer(
            dport,
            &wrapped(
                one_endpoint_op(&url),
                serde_json::json!({"v": 2, "proxy": null}),
            ),
        )
        .await;
        assert_eq!(answer["type"], "error", "{answer}");
        assert!(
            answer["message"]
                .as_str()
                .unwrap_or("")
                .contains("version 2"),
            "{answer}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fx.connections(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_egress_outside_the_wrapper_is_refused_unsent() {
        let fx = Fixture::http("text/html", "ok".into()).await;
        let dport = daemon().await;
        let mut op = one_endpoint_op(&format!("{}/p?q=1", fx.base()));
        op["egress"] = serde_json::json!({"v": 1, "proxy": null});
        let answer = first_answer(dport, &op).await;
        assert_eq!(answer["type"], "error", "{answer}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fx.connections(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wrapped_capabilities_name_the_egress_version() {
        let dport = daemon().await;
        let answer = first_answer(
            dport,
            &wrapped(
                serde_json::json!({"operation": "capabilities"}),
                serde_json::json!({"v": 1, "proxy": null}),
            ),
        )
        .await;
        assert_eq!(answer["type"], "capabilities", "{answer}");
        assert_eq!(answer["egress"], 1, "{answer}");
        assert_eq!(answer["pid"], std::process::id(), "{answer}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pinned_name_cannot_go_through_a_proxy_and_the_op_says_why() {
        // Pins are honoured only when this process dials. Through a proxy the op is
        // refused, with the reason, and nothing is sent.
        let fx = Fixture::http("text/html", "ok".into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let url = format!("http://pinned.invalid:{}/p?q=1", fx.port);
        let mut op = one_endpoint_op(&url);
        op["resolve"] = serde_json::json!([["pinned.invalid", format!("127.0.0.1:{}", fx.port)]]);
        let events = run_to_end(dport, &wrapped(op, through(&proxy))).await;
        assert!(
            events
                .iter()
                .any(|e| e["type"] == "error"
                    && e["message"].as_str().unwrap_or("").contains("pinned")),
            "{events:?}"
        );
        assert_eq!(fx.connections(), 0);
        assert_eq!(proxy.connections(), 0);
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
        tokio::spawn(serve(
            listener,
            dguard::Gate::default(),
            PlessorDb::unconnected(),
            std::sync::Arc::new(Packs::load(None)),
        ));
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

#[cfg(test)]
mod session_tls_tests {
    //! A session handed in as `auth` goes only where it can be trusted to go: past a
    //! certificate check when the caller asks for one, and never to the OAST API.
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const COOKIE: &str = "sid=SESSION-COOKIE-7f3a";
    const BEARER: &str = "Bearer SESSION-BEARER-91c2";

    async fn daemon() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(serve(
            listener,
            dguard::Gate::default(),
            PlessorDb::unconnected(),
            std::sync::Arc::new(Packs::load(None)),
        ));
        port
    }

    /// Every request a fixture read, as text.
    type Seen = Arc<Mutex<Vec<String>>>;

    async fn answer<S>(mut sock: S, seen: Seen, reply: &'static [u8])
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 16384];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase());
                    if sock.write_all(reply).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    const PAGE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nok";

    /// An HTTPS origin whose certificate nothing vouches for, which is what a machine
    /// in the middle presents.
    async fn self_signed_origin() -> (u16, Seen) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("mint");
        let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("key");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("tls protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen: Seen = Arc::default();
        let s = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, s) = (acceptor.clone(), Arc::clone(&s));
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        answer(tls, s, PAGE).await;
                    }
                });
            }
        });
        (port, seen)
    }

    /// A plain HTTP listener that answers every request with `reply`.
    async fn plain(reply: &'static [u8]) -> (u16, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen: Seen = Arc::default();
        let s = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(answer(sock, Arc::clone(&s), reply));
            }
        });
        (port, seen)
    }

    async fn run_to_done(dport: u16, op: &Value) -> Vec<Value> {
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        let mut line = op.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();
        let mut events = Vec::new();
        loop {
            let l = tokio::time::timeout(Duration::from_secs(120), lines.next_line())
                .await
                .expect("the operation ended without a done")
                .unwrap()
                .expect("the daemon closed before done");
            let Ok(ev) = serde_json::from_str::<Value>(&l) else {
                continue;
            };
            let done = ev["type"] == "done";
            events.push(ev);
            if done {
                return events;
            }
        }
    }

    fn with_session(url: &str) -> Value {
        serde_json::json!({
            "operation": "inject",
            "response": "stream",
            "target": url,
            "endpoints": [{"method": "GET", "url": url}],
            "classes": ["xss"],
            "evasive": false,
            "follow_redirects": false,
            "auth": {"cookies": COOKIE, "headers": {"authorization": BEARER}},
        })
    }

    fn carried_session(seen: &Seen) -> usize {
        let cookie = COOKIE.to_ascii_lowercase();
        let bearer = BEARER.to_ascii_lowercase();
        seen.lock()
            .unwrap()
            .iter()
            .filter(|r| r.contains(&cookie) || r.contains(&bearer))
            .count()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn verify_certs_keeps_a_session_from_an_origin_nothing_vouches_for() {
        let (port, seen) = self_signed_origin().await;
        let dport = daemon().await;
        let url = format!("https://localhost:{port}/p?q=1");
        let pin = serde_json::json!([["localhost", format!("127.0.0.1:{port}")]]);

        let mut op = with_session(&url);
        op["resolve"] = pin.clone();
        op["verify_certs"] = Value::Bool(true);
        run_to_done(dport, &op).await;
        assert_eq!(
            seen.lock().unwrap().len(),
            0,
            "requests were sent past a certificate that does not check out"
        );

        // Left out, the old behaviour stands for the callers that rely on it, which
        // also shows the fixture is reachable at all.
        let mut op = with_session(&url);
        op["resolve"] = pin;
        run_to_done(dport, &op).await;
        assert!(carried_session(&seen) > 0, "the fixture was never reached");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_oast_api_is_not_sent_the_session() {
        let (tport, target_seen) = plain(PAGE).await;
        let (oport, oast_seen) = plain(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"ok\":false}",
        )
        .await;
        let dport = daemon().await;
        let mut op = with_session(&format!("http://127.0.0.1:{tport}/p?q=1"));
        op["oast"] = serde_json::json!({
            "domains": ["oast.invalid"],
            "api_url": format!("http://127.0.0.1:{oport}"),
        });
        run_to_done(dport, &op).await;
        assert!(
            carried_session(&target_seen) > 0,
            "the target never got the session"
        );
        assert!(
            !oast_seen.lock().unwrap().is_empty(),
            "the OAST API was never asked to register"
        );
        assert_eq!(
            carried_session(&oast_seen),
            0,
            "the session went to the OAST API: {:?}",
            oast_seen.lock().unwrap()
        );
    }
}

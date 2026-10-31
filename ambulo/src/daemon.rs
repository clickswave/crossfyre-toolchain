use crate::libs::ambulo_db::AmbuloDb;
use crate::libs::cli_args::{Args, HttpMethod, LogLevel, OutputFormat};
use crate::scanner::{Scanner, StreamEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::mpsc;
use transport::Client;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Top-level request sent over the TCP connection (newline-delimited JSON).
#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
    /// "instant" - wait for completion and return results
    /// "queue"   - ack immediately with operation_id, run in background
    /// "stream"  - stream events as they occur (used by `ambulo fuzz`)
    #[serde(default = "default_response_mode")]
    response: String,
    #[serde(default)]
    save: bool,
    #[serde(flatten)]
    params: Value,
    /// From the egress wrapper, never from the request's own fields.
    #[serde(skip)]
    egress: transport::Egress,
}

fn default_response_mode() -> String {
    "queue".to_string()
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

#[derive(Debug, Serialize)]
struct DaemonResponse {
    operation_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Scan-specific parameters.
#[derive(Debug, Deserialize, Clone)]
struct ScanParams {
    endpoint: String,
    wordlist: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default = "default_tasks")]
    tasks: usize,
    /// Per-task wait between requests, in ms. Same semantic as doorward's
    /// `delay` and as ambulo's CLI `--interval`. cfx_node passes this from
    /// the wizard's "Delay between probes" setting.
    #[serde(default)]
    delay: u64,
    #[serde(default)]
    follow_redirects: bool,
    #[serde(default = "default_follow_redirects_depth")]
    follow_redirects_depth: u64,
    #[serde(default)]
    fresh_start: bool,
    #[serde(default = "default_fuzz_marker")]
    fuzz_marker: String,
    #[serde(default = "default_success_codes")]
    success_status_codes: Vec<u16>,
    /// Adaptive rate limiting: controller sets concurrency + delay from target
    /// health. When false, the fixed `tasks`/`delay` above are used (current
    /// behaviour, unchanged).
    #[serde(default)]
    adaptive_rate: bool,
    /// Adaptive resilience: retry policy follows the live health signal.
    #[serde(default)]
    adaptive_resilience: bool,
    /// Controller posture: stealth | balanced | throughput.
    #[serde(default = "default_posture")]
    posture: String,
    /// Optional request auth for an authenticated scan: custom headers plus a
    /// Cookie string, resolved from a credential by the node. Absent for an
    /// anonymous scan.
    /// Evasiveness posture: present as a real browser (default) vs neutral.
    #[serde(default = "default_evasive")]
    evasive: bool,
    /// Attribution token for authorized programs (sent as X-Bug-Bounty).
    #[serde(default)]
    identify: Option<String>,
    #[serde(default)]
    auth: ScanAuth,
    /// Set by the daemon from the egress wrapper. See `DaemonRequest::egress`.
    #[serde(skip)]
    egress: transport::Egress,
}

fn default_evasive() -> bool {
    true
}

/// Auth applied to every probe in an authenticated content-discovery scan. Same
/// shape the crawler receives (`AuthContext::to_json` on the node side).
#[derive(Debug, Deserialize, Clone, Default)]
struct ScanAuth {
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    cookies: String,
}

impl ScanAuth {
    /// Flatten into the `headers` list the prober consumes ("Key: Value"). The
    /// Cookie header carries the resolved cookie string verbatim rather than
    /// going through the prober's `cookies` list, which reparses `k:v` pairs and
    /// would mangle an already-formed Cookie value.
    fn to_header_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        if !self.cookies.is_empty() {
            lines.push(format!("Cookie: {}", self.cookies));
        }
        lines
    }
}

fn default_posture() -> String {
    "balanced".to_string()
}
fn default_method() -> String {
    "get".to_string()
}
fn default_tasks() -> usize {
    4
}
fn default_follow_redirects_depth() -> u64 {
    5
}
fn default_fuzz_marker() -> String {
    "::FUZZ::".to_string()
}
fn default_success_codes() -> Vec<u16> {
    vec![
        200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303, 304, 305, 306, 307,
        308,
    ]
}

/// Params for the lightweight single-URL probe operation.
#[derive(Debug, Deserialize)]
pub(crate) struct ProbeParams {
    operation_id: String,
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default = "default_success_codes")]
    success_codes: Vec<u16>,
    /// 0 = don't store; 1-8766 = store and delete after this many hours
    #[serde(default)]
    volatility: u32,
    /// Whether to follow HTTP redirects (wizard toggle). Defaults to true to
    /// preserve the daemon's historical behaviour for direct callers.
    #[serde(default = "default_follow_redirects")]
    follow_redirects: bool,
}

fn default_follow_redirects() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Serve on an already-bound listener.
///
/// The only entry point: `main` binds before opening the database so a database
/// problem does not present as "extension not running", which is
/// indistinguishable from a crashed engine and made every web_crawl fail with
/// nothing useful attached. It owns the bind because it answers on the socket
/// while it waits, so there is deliberately no variant here that binds for you.
/// Loopback unless an operator opts out: this channel carries no per-request
/// credential of its own, so the bind address is the boundary.
pub async fn run_on(listener: TcpListener, db: AmbuloDb) -> Result<(), Box<dyn std::error::Error>> {
    let addr = listener.local_addr()?;
    let gate = dguard::Gate::from_env();
    gate.announce("Ambulo", addr);

    let db = Arc::new(db);
    // Shared by every probe that comes without an egress wrapper. A wrapped probe
    // gets clients of its own, built with its egress.
    let probe_client = Arc::new(build_probe_client(true, &transport::Egress::Inherit)?);
    // Second client that does NOT follow redirects, for the wizard's
    // "Follow Redirects = off" probes (reqwest sets redirect policy per-client).
    let probe_client_noredirect = Arc::new(build_probe_client(false, &transport::Egress::Inherit)?);

    // Background task: delete expired probe_results + GC old scans every 5 min.
    {
        let db_cleanup = Arc::clone(&db);
        // Scans older than this are reclaimed (see AmbuloDb::gc_old_scans). Default
        // 7 days: comfortably longer than any real scan (so a running/paused scan
        // is never touched) while still bounding the table. Tunable per node.
        let retention_hours: i64 = dguard::env_renamed(
            "CROSSFYRE_AMBULO_SCAN_RETENTION_HOURS",
            "CROSSFYRE_MACH_SCAN_RETENTION_HOURS",
        )
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&h| h > 0)
        .unwrap_or(168);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(300);
            loop {
                tokio::time::sleep(interval).await;
                if let Ok(n) = db_cleanup.delete_expired_probe_results().await
                    && n > 0
                {
                    println!("Cleaned up {n} expired probe result(s)");
                }
                match db_cleanup.gc_old_scans(retention_hours).await {
                    Ok(n) if n > 0 => {
                        println!(
                            "GC: reclaimed {n} scan_entries from scans older than {retention_hours}h"
                        )
                    }
                    Err(e) => eprintln!("GC: scan sweep failed: {e}"),
                    _ => {}
                }
            }
        });
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let gate_clone = gate.clone();
        let db_clone = Arc::clone(&db);
        let client_clone = Arc::clone(&probe_client);
        let client_noredir_clone = Arc::clone(&probe_client_noredirect);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                gate_clone,
                db_clone,
                client_clone,
                client_noredir_clone,
            )
            .await
            {
                eprintln!("Connection error from {addr}: {e}");
            }
        });
    }
}

/// The client the single-URL probe sends with.
fn build_probe_client(
    follow_redirects: bool,
    egress: &transport::Egress,
) -> Result<Client, transport::BuildError> {
    transport::build_client(
        transport::ClientConfig {
            timeout: Some(std::time::Duration::from_secs(10)),
            redirect: if follow_redirects {
                transport::Redirect::Limited(10)
            } else {
                transport::Redirect::None
            },
            accept_invalid_certs: false,
            cookie_store: false,
            user_agent: Some(
                adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None).user_agent,
            ),
            browser_headers: transport::HeaderMap::new(),
            extra_headers: transport::HeaderMap::new(),
            emulate: true,
            resolve: Vec::new(),
            ..Default::default()
        },
        egress,
    )
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    stream: TcpStream,
    gate: dguard::Gate,
    db: Arc<AmbuloDb>,
    probe_client: Arc<Client>,
    probe_client_noredirect: Arc<Client>,
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
            Err(message) => {
                write_json(
                    &mut writer,
                    &serde_json::json!({
                        "type": "error",
                        "operation_id": Uuid::new_v4().to_string(),
                        "status": "error",
                        "message": message,
                    }),
                )
                .await?;
                continue;
            }
            Ok(r) => r,
        };

        // What this daemon honours beyond the original protocol, asked before an
        // operation is sent. The connection stays open for the one that follows.
        if req.operation == "capabilities" {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "capabilities",
                    // The version of the egress wrapper this daemon reads.
                    "egress": transport::WIRE_VERSION,
                }),
            )
            .await?;
            continue;
        }

        // Stream mode takes over the connection for the duration of the operation.
        if req.response == "stream" {
            match req.operation.as_str() {
                "crawl" => handle_stream_crawl(req, writer).await?,
                _ => handle_stream_scan(req, writer, Arc::clone(&db)).await?,
            }
            return Ok(());
        }

        let response = dispatch(
            req,
            Arc::clone(&db),
            Arc::clone(&probe_client),
            Arc::clone(&probe_client_noredirect),
        )
        .await;
        write_json(&mut writer, &response).await?;
    }

    Ok(())
}

async fn write_json<W, T>(
    writer: &mut W,
    value: &T,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Stream mode: owned writer, forward events as JSON lines
// ---------------------------------------------------------------------------

async fn handle_stream_scan(
    req: DaemonRequest,
    mut writer: OwnedWriteHalf,
    db: Arc<AmbuloDb>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let operation_id = Uuid::new_v4().to_string();

    let scan_params: ScanParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => ScanParams {
            egress: req.egress.clone(),
            ..p
        },
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": format!("Invalid scan params: {}", e),
                }),
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

    // Set up the scan (wordlist, DB entries, etc.). Pass operation_id so this
    // stream scan gets its OWN isolated scan record - concurrent scans of the
    // same target/wordlist no longer share a row and clobber each other.
    let (scanner, total, scan_id) = match prepare_scan(&scan_params, &db, Some(&operation_id)).await
    {
        Ok(v) => v,
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": e.to_string(),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    // Send "ack" with operation_id and total entry count
    write_json(
        &mut writer,
        &StreamEvent {
            kind: "ack".to_string(),
            operation_id: Some(operation_id.clone()),
            total: Some(total),
            tested: None,
            retries: None,
            url: None,
            status: None,
            code: None,
            body_length: None,
            headers_length: None,
            found: None,
            not_found: None,
            error: None,
            log_level: None,
            message: None,
            concurrency: None,
            delay_ms: None,
            posture: None,
            score: None,
            final_url: None,
        },
    )
    .await?;

    // Create event channel and run the scan
    let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();

    let oid = operation_id.clone();
    let save = req.save;
    let db_clone = Arc::clone(&db);

    tokio::spawn(async move {
        match scanner.run_headless_stream(tx).await {
            Ok(_) => {
                if save {
                    let _ = db_clone
                        .update_operation_status(&oid, "completed", None)
                        .await;
                }
            }
            Err(e) => {
                if save {
                    let _ = db_clone
                        .update_operation_status(&oid, "error", Some(&e.to_string()))
                        .await;
                }
            }
        }
        // Isolated per-connection scan: drop its now-unreferenced rows so the
        // isolation doesn't grow the ambulo DB unbounded. Runs after the scanner
        // finishes, even if the client disconnected mid-stream.
        let _ = db_clone.delete_scan(scan_id).await;
    });

    // Forward all events to the TCP stream
    while let Some(event) = rx.recv().await {
        write_json(&mut writer, &event).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Stream mode: web crawl. Forwards each CrawlEvent as a JSON line.
// ---------------------------------------------------------------------------

async fn handle_stream_crawl(
    req: DaemonRequest,
    mut writer: OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let params: crate::crawler::CrawlParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => crate::crawler::CrawlParams {
            egress: req.egress.clone(),
            ..p
        },
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid crawl params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<crate::crawler::CrawlEvent>();
    tokio::spawn(async move {
        crate::crawler::run_stream(params, tx).await;
    });

    while let Some(event) = rx.recv().await {
        write_json(&mut writer, &event).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Regular (non-stream) dispatch
// ---------------------------------------------------------------------------

async fn dispatch(
    req: DaemonRequest,
    db: Arc<AmbuloDb>,
    probe_client: Arc<Client>,
    probe_client_noredirect: Arc<Client>,
) -> DaemonResponse {
    let operation_id = Uuid::new_v4().to_string();

    match req.operation.as_str() {
        "scan" => {
            let scan_params: ScanParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => ScanParams {
                    egress: req.egress.clone(),
                    ..p
                },
                Err(e) => {
                    return DaemonResponse {
                        operation_id,
                        status: "error".to_string(),
                        results: None,
                        message: Some(format!("Invalid scan params: {e}")),
                    };
                }
            };

            if req.save {
                let params_str = serde_json::to_string(&req.params).unwrap_or_default();
                if let Err(e) = db
                    .create_operation(&operation_id, "scan", &params_str)
                    .await
                {
                    eprintln!("Failed to save operation: {e}");
                }
            }

            match req.response.as_str() {
                "instant" => run_scan_instant(operation_id, scan_params, db, req.save).await,
                _ => {
                    let oid = operation_id.clone();
                    tokio::spawn(async move {
                        run_scan_background(oid, scan_params, db).await;
                    });
                    DaemonResponse {
                        operation_id,
                        status: "queued".to_string(),
                        results: None,
                        message: None,
                    }
                }
            }
        }
        "probe" => {
            let probe_params: ProbeParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return DaemonResponse {
                        operation_id,
                        status: "error".to_string(),
                        results: None,
                        message: Some(format!("Invalid probe params: {e}")),
                    };
                }
            };
            // Pick the client whose redirect policy matches the request. The shared
            // clients send the way an unwrapped request always has; a wrapped one
            // gets its own, with its egress.
            let client = if req.egress != transport::Egress::Inherit {
                match build_probe_client(probe_params.follow_redirects, &req.egress) {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        return DaemonResponse {
                            operation_id: probe_params.operation_id,
                            status: "error".to_string(),
                            results: None,
                            message: Some(format!("client build failed: {e}")),
                        };
                    }
                }
            } else if probe_params.follow_redirects {
                probe_client
            } else {
                probe_client_noredirect
            };
            run_probe(probe_params, client, db).await
        }
        "db_reset" => match db.truncate_tables().await {
            Ok(_) => DaemonResponse {
                operation_id,
                status: "completed".to_string(),
                results: None,
                message: Some("All tables truncated.".to_string()),
            },
            Err(e) => DaemonResponse {
                operation_id,
                status: "error".to_string(),
                results: None,
                message: Some(format!("DB reset failed: {e}")),
            },
        },
        unknown => DaemonResponse {
            operation_id,
            status: "error".to_string(),
            results: None,
            message: Some(format!("Unknown operation: {unknown}")),
        },
    }
}

async fn run_scan_instant(
    operation_id: String,
    params: ScanParams,
    db: Arc<AmbuloDb>,
    save: bool,
) -> DaemonResponse {
    match run_scan(&params, &db).await {
        Ok(results) => {
            let result_json = serde_json::to_value(&results.found).unwrap_or(Value::Null);
            if save {
                let s = serde_json::to_string(&result_json).unwrap_or_default();
                let _ = db
                    .update_operation_status(&operation_id, "completed", Some(&s))
                    .await;
            }
            DaemonResponse {
                operation_id,
                status: "completed".to_string(),
                results: Some(result_json),
                message: None,
            }
        }
        Err(e) => {
            if save {
                let _ = db
                    .update_operation_status(&operation_id, "error", Some(&e.to_string()))
                    .await;
            }
            DaemonResponse {
                operation_id,
                status: "error".to_string(),
                results: None,
                message: Some(e.to_string()),
            }
        }
    }
}

async fn run_scan_background(operation_id: String, params: ScanParams, db: Arc<AmbuloDb>) {
    match run_scan(&params, &db).await {
        Ok(results) => {
            let s = serde_json::to_string(&results.found).unwrap_or_default();
            let _ = db
                .update_operation_status(&operation_id, "completed", Some(&s))
                .await;
        }
        Err(e) => {
            let _ = db
                .update_operation_status(&operation_id, "error", Some(&e.to_string()))
                .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Shared scan setup → returns (Scanner, total_entries)
// ---------------------------------------------------------------------------

/// `isolate`: when `Some(op_id)`, the op id is folded into the scan's config
/// hash so this scan gets its OWN scan record instead of being deduped onto a
/// shared one by (url, wordlist, method). Stream scans pass their per-connection
/// operation_id here: without it, two concurrent scans of the same target +
/// wordlist collapse onto one `scans` row and clobber each other's entries and
/// results (findings lost / delivered to the wrong connection). `None` keeps the
/// legacy shared/cached behaviour for one-off (non-stream) scans.
async fn prepare_scan(
    params: &ScanParams,
    db: &Arc<AmbuloDb>,
    isolate: Option<&str>,
) -> Result<(Scanner, usize, i64), Box<dyn std::error::Error + Send + Sync>> {
    // Every scan path reaches here, so this is the one place the wordlist has to
    // be contained. `wordlist` is a filesystem path from the request and the
    // scanner emits one request per line to a target the same request names,
    // which made an arbitrary file readable one line at a time by anyone who
    // could reach this daemon.
    dguard::resolve_wordlist(&params.wordlist)?;

    let http_method = parse_method(&params.method);

    let mut endpoint = params.endpoint.clone();
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        endpoint = format!("http://{endpoint}");
    }
    if !endpoint.contains(&params.fuzz_marker) {
        if endpoint.ends_with('/') {
            endpoint.push_str(&params.fuzz_marker);
        } else {
            endpoint.push_str(&format!("/{}", params.fuzz_marker));
        }
    }

    let config = build_args(params, endpoint, http_method);

    let wordlist_config = crate::libs::wordlist_config::WordlistConfig::new(&params.wordlist)
        .await
        .map_err(|e| format!("Wordlist error: {e}"))?;

    let wordlist = match db.find_wordlist(&wordlist_config.hash).await {
        Ok(w) => w,
        Err(sqlx::Error::RowNotFound) => db
            .create_wordlist(&wordlist_config)
            .await
            .map_err(|e| format!("DB: {e}"))?,
        Err(e) => return Err(format!("DB: {e}").into()),
    };

    let words = db
        .fetch_words(&wordlist.id)
        .await
        .map_err(|e| format!("DB: {e}"))?;

    let mut scan_config = serde_json::json!({
        "urls": &config.url,
        "wordlist_hash": &wordlist_config.hash,
        "method": &config.http_method.to_string(),
    });
    // Per-connection isolation (stream scans): make the hash unique so concurrent
    // scans never share a `scans` row. Omitted when None so one-off scans keep
    // the exact same hash and can still reuse a cached scan.
    if let Some(iso) = isolate {
        scan_config["isolate"] = serde_json::json!(iso);
    }
    let scan_config_json = serde_json::to_string(&scan_config)?;
    let scan_config_hash = crate::libs::sha::sha512_from_string(scan_config_json)
        .await
        .map_err(|e| format!("Hash: {e}"))?;

    let mut scan = match db.find_scan(&scan_config_hash).await {
        Ok(s) if params.fresh_start => db
            .fresh_start_scan(&s.id)
            .await
            .map_err(|e| format!("DB: {e}"))?,
        Ok(s) => s,
        Err(sqlx::Error::RowNotFound) => db
            .create_scan(
                &scan_config_hash,
                &wordlist.id,
                &config.http_method.to_string(),
            )
            .await
            .map_err(|e| format!("DB: {e}"))?,
        Err(e) => return Err(format!("DB: {e}").into()),
    };

    let logger = db
        .spawn_logger(&scan.id, &config.log_level.to_string())
        .await
        .map_err(|e| format!("DB: {e}"))?;

    let urls = match db.find_urls(&scan.id).await {
        Ok(u) => u,
        Err(sqlx::Error::RowNotFound) => db
            .create_urls(&scan.id, &config.url)
            .await
            .map_err(|e| format!("DB: {e}"))?,
        Err(e) => return Err(format!("DB: {e}").into()),
    };

    if scan.status == "created" {
        db.create_scan_entries(&urls, &scan, &words)
            .await
            .map_err(|e| format!("DB: {e}"))?;
        scan.status = db
            .set_scan_status(&scan.id, "populated")
            .await
            .map_err(|e| format!("DB: {e}"))?;
    }

    db.reset_halted_scan_entries(&scan.id)
        .await
        .map_err(|e| format!("DB: {e}"))?;

    let (_, _, _, total) = db
        .fetch_total_scan_entries(scan.id)
        .await
        .map_err(|e| format!("DB: {e}"))?;

    let scan_db = db.clone_with_config(config.clone());
    let scanner = Scanner::new(config, scan_db, logger, scan.id);

    Ok((scanner, total, scan.id))
}

async fn run_scan(
    params: &ScanParams,
    db: &Arc<AmbuloDb>,
) -> Result<crate::scanner::ScanResults, Box<dyn std::error::Error + Send + Sync>> {
    let (scanner, _, _) = prepare_scan(params, db, None).await?;
    scanner
        .run_headless()
        .await
        .map_err(|e| format!("Scan: {e}").into())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_method(method: &str) -> HttpMethod {
    match method.to_lowercase().as_str() {
        "post" => HttpMethod::Post,
        "put" => HttpMethod::Put,
        "delete" => HttpMethod::Delete,
        "head" => HttpMethod::Head,
        _ => HttpMethod::Get,
    }
}

fn build_args(params: &ScanParams, endpoint: String, http_method: HttpMethod) -> Args {
    Args {
        url: vec![endpoint],
        wordlist_path: params.wordlist.clone(),
        fuzz_marker: params.fuzz_marker.clone(),
        cookies: vec![],
        // Authenticated scan: the credential's headers + Cookie land here so the
        // prober sends every probe as the logged-in user. Empty for anonymous.
        headers: params.auth.to_header_lines(),
        basic_auth: String::new(),
        store_cookies: false,
        success_status_codes: params.success_status_codes.clone(),
        follow_redirects: params.follow_redirects,
        follow_redirects_depth: params.follow_redirects_depth,
        http_method,
        interval: params.delay,
        tasks: params.tasks,
        fresh_start: params.fresh_start,
        random_user_agent_scan: false,
        random_user_agent_request: false,
        append_slash: false,
        save_response_body: false,
        save_response_headers: true,
        user_agent: adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None)
            .user_agent,
        no_exit_banner: true,
        recreate_db: false,
        launch_delay: 0,
        log_level: LogLevel::Info,
        output_format: OutputFormat::Text,
        output_path: String::new(),
        event_poll_timeout: 1000,
        enable_offset_pagination: false,
        interactive: false,
        adaptive_rate: params.adaptive_rate,
        adaptive_resilience: params.adaptive_resilience,
        posture: params.posture.clone(),
        evasive: params.evasive,
        identify: params.identify.clone(),
        egress: params.egress.clone(),
    }
}

async fn run_probe(params: ProbeParams, client: Arc<Client>, db: Arc<AmbuloDb>) -> DaemonResponse {
    let builder = match params.method.to_lowercase().as_str() {
        "post" => client.post(&params.url),
        "put" => client.put(&params.url),
        "delete" => client.delete(&params.url),
        "head" => client.head(&params.url),
        _ => client.get(&params.url),
    };

    match builder.send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let status = if params.success_codes.is_empty() || params.success_codes.contains(&code)
            {
                "found"
            } else {
                "not_found"
            };
            let headers_length = resp.headers().len() as i64;
            let body_length = resp.content_length().unwrap_or(0) as i64;

            let volatility = params.volatility.min(8766);
            if volatility > 0 {
                let _ = db
                    .save_probe_result(
                        &params.operation_id,
                        &params.url,
                        status,
                        code as i32,
                        body_length,
                        headers_length,
                        volatility as i32,
                    )
                    .await;
            }

            DaemonResponse {
                operation_id: params.operation_id,
                status: status.to_string(),
                results: Some(serde_json::json!({
                    "code": code,
                    "body_length": body_length,
                    "headers_length": headers_length,
                })),
                message: None,
            }
        }
        Err(e) => DaemonResponse {
            operation_id: params.operation_id,
            status: "error".to_string(),
            results: None,
            message: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod egress_tests {
    //! The egress wrapper. A fixture that counts its connections sits behind a
    //! recording SOCKS5 proxy; every connection the fixture accepts has to be one
    //! the proxy opened, so a connection made around the proxy shows up as the
    //! difference.
    use super::*;
    use cfx_tunnel::recorder::{Fixture, Recorder, to_loopback};
    use std::time::Duration;
    use tokio::io::AsyncBufReadExt;

    const PAGE: &str = "<html><body><a href=\"/a\">a</a> <a href=\"/b\">b</a></body></html>";

    async fn daemon() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let db = Arc::new(AmbuloDb::unconnected(
            &crate::libs::cli_args::defaults_for_tests(),
        ));
        let follow = Arc::new(build_probe_client(true, &transport::Egress::Inherit).unwrap());
        let stay = Arc::new(build_probe_client(false, &transport::Egress::Inherit).unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(handle_connection(
                    stream,
                    dguard::Gate::default(),
                    Arc::clone(&db),
                    Arc::clone(&follow),
                    Arc::clone(&stay),
                ));
            }
        });
        port
    }

    /// Send one line and read until `done`, a reply that is not a stream event, or
    /// the connection closing.
    async fn exchange(dport: u16, op: &Value) -> Vec<Value> {
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        let mut line = op.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();
        let mut events = Vec::new();
        while let Ok(Ok(Some(l))) =
            tokio::time::timeout(Duration::from_secs(60), lines.next_line()).await
        {
            let Ok(ev) = serde_json::from_str::<Value>(&l) else {
                continue;
            };
            let last = ev.get("type").is_none()
                || ["done", "error", "capabilities"].contains(&ev["type"].as_str().unwrap_or(""));
            events.push(ev);
            if last {
                break;
            }
        }
        events
    }

    fn wrapped(inner: Value, proxy: &Recorder) -> Value {
        dguard::wrap_egress(&inner, &serde_json::json!({"v": 1, "proxy": proxy.url()}))
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
    async fn a_wrapped_probe_reaches_the_target_only_through_the_proxy() {
        let fx = Fixture::http("text/html", PAGE.into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        for follow in [true, false] {
            let op = serde_json::json!({
                "operation": "probe",
                "response": "instant",
                "operation_id": "op-1",
                "url": format!("{}/admin", fx.base()),
                "follow_redirects": follow,
            });
            let events = exchange(dport, &wrapped(op, &proxy)).await;
            assert_eq!(
                events.last().map(|e| &e["status"]),
                Some(&"found".into()),
                "{events:?}"
            );
        }
        assert_all_through(&fx, &proxy, &[]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrapped_crawl_reaches_the_target_only_through_the_proxy() {
        let fx = Fixture::http("text/html", PAGE.into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "crawl",
            "response": "stream",
            "seed": fx.base(),
            "max_pages": 5,
            "evasive": false,
        });
        let events = exchange(dport, &wrapped(op, &proxy)).await;
        assert!(
            fx.requests().iter().any(|l| l.starts_with("GET /a ")),
            "the crawl did not follow a link: {:?}",
            fx.requests()
        );
        assert_all_through(&fx, &proxy, &events);
    }

    /// A site whose every page links to ten pages nobody has asked for yet, so a crawl
    /// of it never runs out. Returns its port and how many requests it has had.
    async fn endless_site() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut lines = BufReader::new(r).lines();
                    let Ok(Some(first)) = lines.next_line().await else {
                        return;
                    };
                    while let Ok(Some(l)) = lines.next_line().await {
                        if l.is_empty() {
                            break;
                        }
                    }
                    seen.fetch_add(1, Ordering::SeqCst);
                    let path = first.split_whitespace().nth(1).unwrap_or("/");
                    let base = path.trim_end_matches('/');
                    let links: String = (0..10)
                        .map(|i| format!("<a href=\"{base}/p{i}\">p{i}</a> "))
                        .collect();
                    let body = format!("<html><body>{links}</body></html>");
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = w.write_all(reply.as_bytes()).await;
                });
            }
        });
        (port, count)
    }

    /// A crawl stops once the client that asked for it is gone: the node closes the
    /// connection when it stops an op, and a crawl nobody reads is only traffic at
    /// somebody's site, from wherever this engine sends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_crawl_stops_when_its_client_goes_away() {
        use std::sync::atomic::Ordering;
        let (port, count) = endless_site().await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "crawl",
            "response": "stream",
            "seed": format!("http://127.0.0.1:{port}/"),
            "max_pages": 100000,
            "max_depth": 20,
            "tasks": 2,
            "delay": 10,
            "evasive": false,
        });
        let stream = TcpStream::connect(("127.0.0.1", dport)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(format!("{op}\n").as_bytes()).await.unwrap();
        let mut fetched = 0;
        while fetched < 5 {
            let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
                .await
                .expect("the crawl went quiet")
                .unwrap()
                .expect("the crawl ended");
            // A fetched page is reported with the status it answered.
            if line.contains("\"status_code\"") {
                fetched += 1;
            }
        }
        drop(lines);
        drop(w);
        // Requests already in flight finish; after them, nothing more is asked for.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let settled = count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let later = count.load(Ordering::SeqCst);
        assert!(
            later <= settled + 2,
            "the crawl went on without its client: {settled} requests, then {later} a second later"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_proxied_crawl_skips_the_headless_tier_and_says_so() {
        let fx = Fixture::http("text/html", PAGE.into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "crawl",
            "response": "stream",
            "seed": fx.base(),
            "max_pages": 2,
            "evasive": false,
            "browser": true,
        });
        let events = exchange(dport, &wrapped(op, &proxy)).await;
        assert!(
            events.iter().any(|e| e["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("headless tier skipped"))),
            "{events:?}"
        );
        assert_all_through(&fx, &proxy, &events);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrapped_op_with_an_unknown_egress_version_is_refused_unsent() {
        let fx = Fixture::http("text/html", PAGE.into()).await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "crawl",
            "response": "stream",
            "seed": fx.base(),
        });
        let events = exchange(
            dport,
            &dguard::wrap_egress(&op, &serde_json::json!({"v": 2, "proxy": null})),
        )
        .await;
        assert!(dguard::is_error(&events[0].to_string()), "{events:?}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fx.connections(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrapped_capabilities_name_the_egress_version() {
        let dport = daemon().await;
        let events = exchange(
            dport,
            &dguard::wrap_egress(
                &serde_json::json!({"operation": "capabilities"}),
                &serde_json::json!({"v": 1, "proxy": null}),
            ),
        )
        .await;
        assert_eq!(events[0]["type"], "capabilities", "{events:?}");
        assert_eq!(events[0]["egress"], 1, "{events:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn content_discovery_probes_go_through_the_scan_egress() {
        // The content-discovery scan keeps its state in the database, so its
        // prober is driven here directly, built from the arguments a wrapped
        // scan gets.
        let fx = Fixture::http("text/html", PAGE.into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let params: ScanParams = serde_json::from_value(serde_json::json!({
            "endpoint": format!("{}/::FUZZ::", fx.base()),
            "wordlist": "/dev/null",
            "evasive": false,
        }))
        .unwrap();
        let params = ScanParams {
            egress: transport::Egress::Proxy(proxy.url()),
            ..params
        };
        let args = build_args(&params, params.endpoint.clone(), HttpMethod::Get);
        let prober = crate::prober::Prober::new(&args).await.unwrap();
        let work = crate::libs::ambulo_db::Work {
            url: format!("{}/admin", fx.base()),
            entry_id: 1,
            method: "get".into(),
        };
        let got = prober.probe_url(&work, false).await;
        assert!(got.is_ok(), "the probe did not arrive");
        assert_eq!(fx.requests(), ["GET /admin HTTP/1.1"]);
        assert_all_through(&fx, &proxy, &[]);
    }
}

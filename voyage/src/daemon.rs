use crate::libs::voyage_db::VoyageDb;
use crate::scanner::{EnumConfig, Scanner, StreamEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::mpsc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
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

#[derive(Debug, Deserialize, Clone)]
struct EnumParams {
    domain: String,
    /// Evasiveness posture: present as a real browser (default) vs neutral.
    #[serde(default = "default_true")]
    evasive: bool,
    /// Attribution token for authorized programs (sent as X-Bug-Bounty).
    #[serde(default)]
    identify: Option<String>,
    #[serde(default)]
    wordlist: String,
    #[serde(default = "default_tasks")]
    tasks: usize,
    /// Per-task wait between requests in ms. Same semantic as doorward's
    /// `delay` and as voyage's CLI `--interval`. cfx_node passes this from
    /// the wizard's "Delay between probes" setting.
    #[serde(default)]
    delay: u64,
    #[serde(default)]
    fresh_start: bool,
    #[serde(default)]
    disable_passive: bool,
    #[serde(default)]
    disable_active: bool,
    #[serde(default)]
    exclude_passive_sources: Vec<String>,
    #[serde(default)]
    exclude_active_techniques: Vec<String>,
    #[serde(default = "default_http_ports")]
    http_probing_ports: Vec<u16>,
    #[serde(default = "default_https_ports")]
    https_probing_ports: Vec<u16>,
    #[serde(default = "default_active_ua")]
    active_user_agent: String,
    #[serde(default = "default_passive_ua")]
    passive_user_agent: String,
    /// Explicit DNS server IP to resolve against. Empty = use the node's
    /// default resolver config.
    #[serde(default)]
    dns_server: String,
    /// Adaptive rate limiting for the active brute-force (default off).
    #[serde(default)]
    adaptive_rate: bool,
    /// Adaptive resilience: retry transient DNS failures (default off).
    #[serde(default)]
    adaptive_resilience: bool,
    /// Controller posture: stealth | balanced | throughput.
    #[serde(default = "default_posture")]
    posture: String,
    /// Refuse to connect to private / reserved addresses when probing. Set by
    /// the public free tools; absent = false, which is what a customer-
    /// authorised enum gets.
    #[serde(default)]
    block_internal: bool,
    /// Set by the daemon from the egress wrapper. See `DaemonRequest::egress`.
    #[serde(skip)]
    egress: transport::Egress,
}

fn default_posture() -> String {
    "balanced".to_string()
}

fn default_true() -> bool {
    true
}

fn default_tasks() -> usize {
    4
}
fn default_http_ports() -> Vec<u16> {
    vec![80]
}
fn default_https_ports() -> Vec<u16> {
    vec![443]
}
fn default_active_ua() -> String {
    format!("voyage/{}", env!("CARGO_PKG_VERSION"))
}
fn default_passive_ua() -> String {
    format!("voyage/{}", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Deserialize, Clone)]
struct OriginParams {
    domain: String,
    /// Present as a real browser for the origin probes (default on).
    #[serde(default = "default_true")]
    evasive: bool,
    /// Per-request timeout in ms.
    #[serde(default = "default_origin_timeout")]
    timeout_ms: u64,
}

fn default_origin_timeout() -> u64 {
    12000
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProbeParams {
    operation_id: String,
    domain: String,
    /// 0 = don't store; 1-8766 = store and delete after this many hours
    #[serde(default)]
    volatility: u32,
    #[serde(default)]
    dns_server: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(port: u16, db: VoyageDb) -> Result<(), Box<dyn std::error::Error>> {
    // Loopback unless an operator opts out: this channel has no per-request
    // credential of its own, so the bind address is the boundary.
    let addr = dguard::bind_addr(port);
    let gate = dguard::Gate::from_env();
    let listener = TcpListener::bind(addr).await?;
    gate.announce("Voyage", addr);

    let db = Arc::new(db);

    // Background task: delete expired probe_results every 5 minutes
    {
        let db_cleanup = Arc::clone(&db);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(300);
            loop {
                tokio::time::sleep(interval).await;
                if let Ok(n) = db_cleanup.delete_expired_probe_results().await
                    && n > 0
                {
                    println!("Cleaned up {n} expired probe result(s)");
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

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    stream: TcpStream,
    gate: dguard::Gate,
    db: Arc<VoyageDb>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
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

        // Stream mode takes over the connection for the duration of the scan.
        // Routed by operation first: each stream handler parses its own params,
        // so takeover requests must not reach the enum parser.
        if req.response == "stream" {
            match req.operation.as_str() {
                "takeover" => handle_stream_takeover(req, writer).await?,
                // Zone transfer: when a nameserver answers it, the zone lists
                // every name it holds and the brute-force phase is redundant.
                "axfr" => handle_stream_axfr(req, writer).await?,
                _ => handle_stream_enum(req, writer, Arc::clone(&db)).await?,
            }
            return Ok(());
        }

        let response = dispatch(req, Arc::clone(&db)).await;
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
// Stream mode: forward events as JSON lines
// ---------------------------------------------------------------------------

async fn handle_stream_enum(
    req: DaemonRequest,
    mut writer: OwnedWriteHalf,
    db: Arc<VoyageDb>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let operation_id = Uuid::new_v4().to_string();

    let params: EnumParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => EnumParams {
            egress: req.egress.clone(),
            ..p
        },
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": format!("Invalid enum params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    if req.save {
        let params_str = serde_json::to_string(&req.params).unwrap_or_default();
        let _ = db
            .create_operation(&operation_id, "enum", &params_str)
            .await;
    }

    let (scanner, total) = match prepare_enum(&params, &db).await {
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
            subdomain: None,
            status: None,
            source: None,
            found: None,
            not_found: None,
            log_level: None,
            message: None,
            error: None,
            ..Default::default()
        },
    )
    .await?;

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
    });

    // Forward all events to the TCP stream
    while let Some(event) = rx.recv().await {
        write_json(&mut writer, &event).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Regular (non-stream) dispatch
// ---------------------------------------------------------------------------

async fn dispatch(req: DaemonRequest, db: Arc<VoyageDb>) -> DaemonResponse {
    let operation_id = Uuid::new_v4().to_string();

    match req.operation.as_str() {
        "enum" => {
            let params: EnumParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => EnumParams {
                    egress: req.egress.clone(),
                    ..p
                },
                Err(e) => {
                    return DaemonResponse {
                        operation_id,
                        status: "error".to_string(),
                        results: None,
                        message: Some(format!("Invalid enum params: {e}")),
                    };
                }
            };

            if req.save {
                let params_str = serde_json::to_string(&req.params).unwrap_or_default();
                let _ = db
                    .create_operation(&operation_id, "enum", &params_str)
                    .await;
            }

            match req.response.as_str() {
                "instant" => match run_enum_instant(&params, &db).await {
                    Ok(found) => {
                        let result_json = serde_json::to_value(&found).unwrap_or(Value::Null);
                        if req.save {
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
                        if req.save {
                            let _ = db
                                .update_operation_status(
                                    &operation_id,
                                    "error",
                                    Some(&e.to_string()),
                                )
                                .await;
                        }
                        DaemonResponse {
                            operation_id,
                            status: "error".to_string(),
                            results: None,
                            message: Some(e.to_string()),
                        }
                    }
                },
                _ => {
                    let oid = operation_id.clone();
                    let db2 = Arc::clone(&db);
                    tokio::spawn(async move {
                        let _ = run_enum_instant(&params, &db2).await;
                        let _ = db2.update_operation_status(&oid, "completed", None).await;
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
            run_probe(probe_params, db).await
        }
        "origin" => {
            let params: OriginParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return DaemonResponse {
                        operation_id,
                        status: "error".to_string(),
                        results: None,
                        message: Some(format!("Invalid origin params: {e}")),
                    };
                }
            };
            if let Some(why) = crate::scanners::origin::refused(&req.egress) {
                return DaemonResponse {
                    operation_id,
                    status: "error".to_string(),
                    results: None,
                    message: Some(why.to_string()),
                };
            }
            let noop = |_: String| {};
            let findings = crate::scanners::origin::discover(
                &params.domain,
                params.timeout_ms,
                params.evasive,
                &req.egress,
                &noop,
            )
            .await;
            let results: Vec<Value> = findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "ip": f.ip.to_string(),
                        "host": f.host,
                        "confidence": f.confidence,
                        "note": f.note,
                    })
                })
                .collect();
            DaemonResponse {
                operation_id,
                status: "completed".to_string(),
                results: Some(Value::Array(results)),
                message: None,
            }
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

// ---------------------------------------------------------------------------
// Shared enum setup → returns (Scanner, total_entries)
// ---------------------------------------------------------------------------

/// The wordlist an enum reads, if it reads one, contained as ambulo contains its own.
/// `wordlist` is a path from the request, and the enum sends one DNS query per line for
/// a domain the same request names, so without the check any file the daemon can read
/// went out a line at a time to whoever answers for that domain.
fn active_wordlist(params: &EnumParams) -> Result<Option<std::path::PathBuf>, String> {
    if params.disable_active || params.wordlist.is_empty() {
        return Ok(None);
    }
    dguard::resolve_wordlist(&params.wordlist).map(Some)
}

async fn prepare_enum(
    params: &EnumParams,
    db: &Arc<VoyageDb>,
) -> Result<(Scanner, usize), Box<dyn std::error::Error + Send + Sync>> {
    let wordlist = active_wordlist(params)?;
    // Compute config hash from domain + wordlist path
    let config_str = serde_json::json!({
        "domain": &params.domain,
        "wordlist": &params.wordlist,
    })
    .to_string();
    let config_hash = crate::libs::sha::sha512(config_str)
        .await
        .map_err(|e| format!("Hash error: {e}"))?;

    let scan_id = db
        .get_or_create_scan(&config_hash, &params.domain, &params.wordlist)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    if params.fresh_start {
        db.fresh_start_scan(&scan_id)
            .await
            .map_err(|e| format!("DB error: {e}"))?;
    }

    // Passive scan - insert results with status="found"
    if !params.disable_passive {
        match crate::scanners::passive_scan::execute(
            &params.domain,
            &params.passive_user_agent,
            &params.exclude_passive_sources,
            &params.egress,
        )
        .await
        {
            Ok(results) => {
                let entries: Vec<(String, String, String, String)> = results
                    .iter()
                    .map(|(subdomain, source)| {
                        (
                            subdomain.clone(),
                            "passive".to_string(),
                            source.clone(),
                            "found".to_string(),
                        )
                    })
                    .collect();
                let _ = db.insert_entries_batch(&scan_id, &entries).await;
            }
            Err(e) => eprintln!("[WARN] Passive scan error: {e}"),
        }
    }

    // Active wordlist - insert entries with status="queued"
    if let Some(wordlist) = &wordlist {
        let words = crate::libs::wordlist::read_lines(&wordlist.to_string_lossy())
            .await
            .map_err(|e| format!("Wordlist error: {e}"))?;

        let entries: Vec<(String, String, String, String)> = words
            .iter()
            .filter(|w| !w.trim().is_empty())
            .map(|word| {
                (
                    format!("{}.{}", word.trim(), params.domain),
                    "active".to_string(),
                    String::new(),
                    "queued".to_string(),
                )
            })
            .collect();

        db.insert_entries_batch(&scan_id, &entries)
            .await
            .map_err(|e| format!("DB error: {e}"))?;
    }

    db.set_scan_status(&scan_id, "populated")
        .await
        .map_err(|e| format!("DB error: {e}"))?;
    db.reset_halted_entries(&scan_id)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    let total = db
        .get_scan_entry_total(&scan_id)
        .await
        .map_err(|e| format!("DB error: {e}"))? as usize;

    let config = EnumConfig {
        scan_id,
        domain: params.domain.clone(),
        tasks: params.tasks,
        interval_ms: params.delay,
        exclude_passive_sources: params.exclude_passive_sources.clone(),
        exclude_active_techniques: params.exclude_active_techniques.clone(),
        block_internal: params.block_internal,
        http_probing_ports: params.http_probing_ports.clone(),
        https_probing_ports: params.https_probing_ports.clone(),
        active_user_agent: params.active_user_agent.clone(),
        passive_user_agent: params.passive_user_agent.clone(),
        active_random_user_agent: false,
        dns_server: params.dns_server.clone(),
        adaptive_rate: params.adaptive_rate,
        adaptive_resilience: params.adaptive_resilience,
        posture: params.posture.clone(),
        evasive: params.evasive,
        identify: params.identify.clone(),
        egress: params.egress.clone(),
    };

    let scanner = Scanner::new(config, Arc::clone(db));
    Ok((scanner, total))
}

async fn run_enum_instant(
    params: &EnumParams,
    db: &Arc<VoyageDb>,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let (scanner, _) = prepare_enum(params, db).await?;
    let scan_id = scanner.config.scan_id.clone();
    let db2 = Arc::clone(&scanner.db);

    let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();

    tokio::spawn(async move {
        let _ = scanner.run_headless_stream(tx).await;
    });

    // Drain until channel closes (after "done" is sent)
    while rx.recv().await.is_some() {}

    db2.get_found_subdomains(&scan_id)
        .await
        .map_err(|e| format!("{e}").into())
}

// ---------------------------------------------------------------------------
// Probe: single subdomain DNS lookup
// ---------------------------------------------------------------------------

async fn run_probe(params: ProbeParams, db: Arc<VoyageDb>) -> DaemonResponse {
    let resolver = match crate::libs::dns::create_resolver(Some(params.dns_server.as_str())) {
        Ok(r) => r,
        Err(e) => {
            return DaemonResponse {
                operation_id: params.operation_id,
                status: "error".to_string(),
                results: None,
                message: Some(format!("DNS resolver error: {e}")),
            };
        }
    };

    // ipv4 lookup is the fastest check for subdomain existence
    let found = resolver.ipv4_lookup(&params.domain).await.is_ok();

    let volatility = params.volatility.min(8766);
    if volatility > 0 {
        let _ = db
            .save_probe_result(
                &params.operation_id,
                &params.domain,
                found,
                "ipv4_lookup",
                volatility as i32,
            )
            .await;
    }

    DaemonResponse {
        operation_id: params.operation_id,
        status: if found { "found" } else { "not_found" }.to_string(),
        results: Some(serde_json::json!({ "found": found })),
        message: None,
    }
}

// ---------------------------------------------------------------------------
// Stream mode: subdomain takeover
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TakeoverParams {
    /// Hosts to check. Takes precedence over `domain`.
    #[serde(default)]
    hosts: Vec<String>,
    /// Enumerate this domain passively first, then check what it finds. Ignored
    /// when `hosts` is non-empty.
    #[serde(default)]
    domain: String,
    /// Ceiling on hosts checked in one run. A takeover check is a DNS lookup
    /// plus at most one GET, but a domain with 40k names in CT is a real thing,
    /// and an unbounded run behind an interactive request is a hang.
    #[serde(default = "default_max_hosts")]
    max_hosts: usize,
    #[serde(default = "default_takeover_tasks")]
    tasks: usize,
    #[serde(default = "default_takeover_timeout")]
    timeout_ms: u64,
    /// Outbound User-Agent. The public tools set an identifying string that
    /// points at the scanning-policy page, so an admin reading their logs can
    /// find out who we are.
    #[serde(default)]
    user_agent: String,
    /// DNS server to query. Empty uses the host's resolver.
    #[serde(default)]
    dns_server: String,
    /// Refuse to connect to private / reserved addresses.
    ///
    /// Set by the public free tools. A takeover check follows a CNAME chain
    /// chosen by whoever typed the domain, so without this an anonymous caller
    /// can aim the confirmation fetch at our own network by pointing a record
    /// inward.
    #[serde(default)]
    block_internal: bool,
}

fn default_max_hosts() -> usize {
    250
}
fn default_takeover_tasks() -> usize {
    24
}
fn default_takeover_timeout() -> u64 {
    6000
}

/// Largest response body we will read when confirming a fingerprint.
///
/// The match strings all appear in a provider's small error page. Reading more
/// than this buys nothing and hands a hostile target a cheap way to tie up the
/// engine, which is the same reason the raw HTTP sender caps its reads.
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, serde::Deserialize)]
struct AxfrParams {
    /// The zone to ask for.
    domain: String,
    /// `ip` or `ip:port`. Empty asks the zone's own authoritative servers,
    /// which is the usual case; naming one is how you reach an internal
    /// resolver or a lab.
    #[serde(default)]
    dns_server: String,
    #[serde(default = "default_axfr_timeout")]
    timeout_ms: u64,
}
fn default_axfr_timeout() -> u64 {
    8000
}

async fn handle_stream_axfr(
    req: DaemonRequest,
    mut writer: OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let operation_id = Uuid::new_v4().to_string();
    let params: AxfrParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": format!("Invalid axfr params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let zone = params.domain.trim().trim_end_matches('.').to_string();
    let timeout = std::time::Duration::from_millis(params.timeout_ms.clamp(500, 60_000));
    // `map_err` to a String BEFORE any await: create_resolver's error is a bare
    // `Box<dyn Error>`, which is not Send, and holding one across an await stops
    // the whole connection future being spawnable.
    let built = crate::libs::dns::create_resolver(if params.dns_server.trim().is_empty() {
        None
    } else {
        Some(params.dns_server.as_str())
    })
    .map_err(|e| format!("DNS resolver error: {e}"));
    let resolver = match built {
        Ok(r) => r,
        Err(msg) => {
            write_json(
                &mut writer,
                &serde_json::json!({"type":"error","operation_id":operation_id,
                                    "message": msg}),
            )
            .await?;
            return Ok(());
        }
    };

    write_json(
        &mut writer,
        &serde_json::json!({"type":"ack","operation_id":operation_id,"domain":zone}),
    )
    .await?;

    // An explicitly named server is asked directly; otherwise ask the zone's
    // own authoritative servers, which is what a transfer is normally against.
    let port = crate::libs::dns::server_addr(&params.dns_server)
        .map(|a| a.port())
        .unwrap_or(53);
    let mut servers: Vec<(String, std::net::SocketAddr)> = Vec::new();
    if let Some(explicit) = crate::libs::dns::server_addr(&params.dns_server) {
        servers.push((params.dns_server.trim().to_string(), explicit));
    }
    for (host, addr) in crate::axfr::authoritative(&resolver, &zone, port).await {
        if !servers.iter().any(|(_, a)| *a == addr) {
            servers.push((host, addr));
        }
    }
    if servers.is_empty() {
        write_json(
            &mut writer,
            &serde_json::json!({"type":"error","operation_id":operation_id,
                                "message": format!("no nameservers found for {zone}")}),
        )
        .await?;
        return Ok(());
    }

    let mut total = 0usize;
    for (label, addr) in servers {
        let t = crate::axfr::transfer(&zone, addr, timeout, &req.egress).await;
        if let Some(why) = &t.refused {
            write_json(
                &mut writer,
                &serde_json::json!({"type":"log","operation_id":operation_id,
                                    "message": format!("{label} ({addr}): {why}")}),
            )
            .await?;
            continue;
        }
        total += t.names.len();
        // The transfer itself is the finding: a zone anyone can copy.
        write_json(
            &mut writer,
            &serde_json::json!({"type":"finding","data": {
                "type": "vulnerability",
                "vuln_class": "misconfig",
                "name": "DNS zone transfer (AXFR) allowed",
                "severity": "medium",
                "confidence": "confirmed",
                "source": "voyage-axfr",
                "target": format!("{addr}"),
                "url": format!("{addr}"),
                "matched_at": format!("{addr}"),
                "location": "service",
                "description": format!(
                    "The nameserver at {addr} transferred the whole `{zone}` zone to an \
                     unauthenticated request: {} records, {} distinct names. That is the \
                     complete internal inventory - hosts nobody links to, staging and admin \
                     names, mail and VPN endpoints - handed over without a wordlist. Restrict \
                     allow-transfer to the secondaries that need it.",
                    t.names.len(), t.names.len()
                ),
            }}),
        )
        .await?;
        for name in &t.names {
            write_json(
                &mut writer,
                &serde_json::json!({"type":"result","operation_id":operation_id,
                                    "subdomain": name, "source": "axfr",
                                    "server": label}),
            )
            .await?;
        }
        // One successful transfer is the whole zone; asking the secondaries too
        // would just repeat it.
        break;
    }

    write_json(
        &mut writer,
        &serde_json::json!({"type":"done","operation_id":operation_id,"found":total}),
    )
    .await?;
    Ok(())
}

/// The confirmation fetch's client.
///
/// An explicit User-Agent and no browser emulation, deliberately. This path serves
/// the public free tools, which reach hosts whose owners have not asked us to scan
/// them; the only defensible posture there is to say who we are. Evasion belongs to
/// scans a customer authorised on their own property.
///
/// It goes out the way the op's egress says, like every other client: a takeover
/// check is an op a node runs too, and a proxied node's must not go out from its own
/// address. Without a wrapper it inherits, which with `block_internal` uses no proxy
/// from the environment.
fn takeover_client(
    params: &TakeoverParams,
    ua: &str,
    egress: &transport::Egress,
) -> Result<transport::Client, transport::BuildError> {
    transport::build_client(
        transport::ClientConfig {
            timeout: Some(std::time::Duration::from_millis(params.timeout_ms)),
            // No redirects on the guarded path: a followed redirect is a second
            // destination the caller chose and we did not check. The confirmation
            // fetch only needs the provider's own not-configured page, which is
            // served directly, so nothing legitimate is lost.
            redirect: if params.block_internal {
                transport::Redirect::None
            } else {
                transport::Redirect::Limited(3)
            },
            user_agent: Some(ua.to_string()),
            emulate: false,
            block_internal: params.block_internal,
            ..Default::default()
        },
        egress,
    )
}

async fn handle_stream_takeover(
    req: DaemonRequest,
    mut writer: OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let operation_id = Uuid::new_v4().to_string();

    let params: TakeoverParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": format!("Invalid takeover params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let ua = if params.user_agent.trim().is_empty() {
        "Mozilla/5.0 (compatible; crossfyre)".to_string()
    } else {
        params.user_agent.trim().to_string()
    };

    let client = match takeover_client(&params, &ua, &req.egress) {
        Ok(c) => c,
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": format!("client build failed: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    // Resolve the host list. An explicit list wins; otherwise enumerate the
    // domain passively, which is what makes "check my whole domain" one call.
    let mut hosts: Vec<String> = if !params.hosts.is_empty() {
        params.hosts.clone()
    } else if !params.domain.trim().is_empty() {
        let domain = params.domain.trim().to_lowercase();
        let mut found: Vec<String> =
            match crate::scanners::passive_scan::execute(&domain, &ua, &[], &req.egress).await {
                Ok(map) => map.into_keys().collect(),
                Err(e) => {
                    eprintln!("[takeover] passive enum failed for {domain}: {e}");
                    vec![]
                }
            };
        // The apex is checked too: a dangling CNAME on the apex is rarer but
        // strictly worse than one on a subdomain.
        found.push(domain);
        found
    } else {
        write_json(
            &mut writer,
            &serde_json::json!({
                "type": "error",
                "operation_id": operation_id,
                "message": "takeover needs either `hosts` or `domain`",
            }),
        )
        .await?;
        return Ok(());
    };

    hosts.sort();
    hosts.dedup();
    let truncated = hosts.len().saturating_sub(params.max_hosts);
    hosts.truncate(params.max_hosts);

    let total = hosts.len();
    write_json(
        &mut writer,
        &serde_json::json!({
            "type": "progress",
            "operation_id": operation_id,
            "processed": 0,
            "total": total,
            // Reported, never silent: a run that checked 250 of 900 names must
            // not read as "your domain is clean".
            "truncated": truncated,
        }),
    )
    .await?;

    // `map_err` to a String before any await: create_resolver's error is a bare
    // `Box<dyn Error>`, which is not Send, and holding one across the write below
    // makes the whole connection future non-Send.
    let built = crate::libs::dns::create_resolver(if params.dns_server.trim().is_empty() {
        None
    } else {
        Some(params.dns_server.trim())
    })
    .map_err(|e| e.to_string());
    let resolver = match built {
        Ok(r) => Arc::new(r),
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": format!("resolver build failed: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let mut processed = 0usize;
    let mut found_count = 0usize;

    // Bounded concurrency: `tasks` in flight at a time. DNS dominates the wall
    // clock here and it parallelises well, which is what keeps a 250-host run
    // inside an interactive request.
    for chunk in hosts.chunks(params.tasks.clamp(1, 64)) {
        let mut set = tokio::task::JoinSet::new();
        for host in chunk {
            let host = host.clone();
            let resolver = Arc::clone(&resolver);
            let client = client.clone();
            set.spawn(async move {
                crate::takeover::check(&resolver, &host, |h| async move {
                    // https first, then http: a host whose TLS is broken is
                    // exactly the kind that has been abandoned, so falling back
                    // is the difference between finding it and missing it.
                    for scheme in ["https", "http"] {
                        let Ok(resp) = client.get(format!("{scheme}://{h}/")).send().await else {
                            continue;
                        };
                        let Ok(body) = resp.text().await else {
                            continue;
                        };
                        let mut body = body;
                        body.truncate(
                            body.char_indices()
                                .map(|(i, _)| i)
                                .take_while(|i| *i < MAX_BODY_BYTES)
                                .last()
                                .map_or(0, |i| i + 1),
                        );
                        return Some(body);
                    }
                    None
                })
                .await
            });
        }

        while let Some(joined) = set.join_next().await {
            processed += 1;
            let Ok(report) = joined else { continue };

            if report.is_finding() {
                found_count += 1;
                write_json(
                    &mut writer,
                    &serde_json::json!({
                        "type": "finding",
                        "operation_id": operation_id,
                        "data": {
                            "target": report.host,
                            "type": "takeover",
                            "source": "voyage",
                            "severity": report.severity(),
                            "name": match report.service {
                                Some(s) => format!("Dangling CNAME to {s}"),
                                None => "Dangling CNAME".to_string(),
                            },
                            "matched_at": report.host,
                            "description": report.detail,
                            "confidence": "confirmed",
                            "verdict": report.verdict.as_str(),
                            "service": report.service,
                            "claimability": report.status.map(|s| s.as_str()),
                            "cname_chain": report.chain,
                        }
                    }),
                )
                .await?;
            }

            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "progress",
                    "operation_id": operation_id,
                    "processed": processed,
                    "total": total,
                }),
            )
            .await?;
        }
    }

    write_json(
        &mut writer,
        &serde_json::json!({
            "type": "done",
            "operation_id": operation_id,
            "found": found_count,
            "processed": processed,
            "total": total,
            "truncated": truncated,
        }),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod wordlist_tests {
    use super::*;

    fn enum_params(wordlist: &str, disable_active: bool) -> EnumParams {
        serde_json::from_value(serde_json::json!({
            "domain": "example.com",
            "wordlist": wordlist,
            "disable_active": disable_active,
        }))
        .expect("enum params")
    }

    #[test]
    fn a_wordlist_outside_the_permitted_directories_is_refused() {
        // This crate's own manifest: a readable file that is in none of the roots.
        let outside = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let err = active_wordlist(&enum_params(outside, false)).expect_err("refused");
        assert!(err.contains(dguard::WORDLIST_ROOTS_ENV), "{err}");
    }

    #[test]
    fn a_wordlist_in_the_temp_dir_is_read_and_none_is_needed_without_active_enum() {
        let inside = std::env::temp_dir().join(format!("voyage-wl-{}.txt", std::process::id()));
        std::fs::write(&inside, "www\n").expect("write");
        let got = active_wordlist(&enum_params(&inside.to_string_lossy(), false));
        let _ = std::fs::remove_file(&inside);
        assert!(matches!(got, Ok(Some(_))), "{got:?}");
        let outside = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        assert!(matches!(
            active_wordlist(&enum_params(outside, true)),
            Ok(None)
        ));
        assert!(matches!(active_wordlist(&enum_params("", false)), Ok(None)));
    }
}

#[cfg(test)]
mod egress_tests {
    //! The egress wrapper. Fixtures that count their connections sit behind a
    //! recording SOCKS5 proxy; every connection a fixture accepts has to be one the
    //! proxy opened, so a connection made around the proxy shows up as the
    //! difference. DNS goes to a server on loopback that knows no names, so nothing
    //! here leaves the machine.
    use super::*;
    use cfx_tunnel::recorder::{Fixture, Recorder, name_of, to_loopback};
    use std::time::Duration;
    use tokio::io::AsyncBufReadExt;

    const ONLY_THE_PROXY: &str = "only-the-proxy-knows.invalid";

    async fn daemon() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let db = Arc::new(VoyageDb::unconnected());
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

    /// A DNS server on loopback that answers every query "no such name", so a
    /// lookup ends at once and none goes anywhere else.
    async fn local_dns() -> String {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("127.0.0.1:{}", s.local_addr().unwrap().port());
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                if n < 12 {
                    continue;
                }
                // A response (QR), recursion available, NXDOMAIN.
                buf[2] |= 0x80;
                buf[3] = 0x80 | 3;
                let _ = s.send_to(&buf[..n], from).await;
            }
        });
        addr
    }

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

    fn proxied(proxy: &Recorder) -> transport::Egress {
        transport::Egress::Proxy(proxy.url())
    }

    fn wrapped(inner: Value, proxy: &Recorder) -> Value {
        dguard::wrap_egress(&inner, &serde_json::json!({"v": 1, "proxy": proxy.url()}))
    }

    fn assert_all_through(fx: &Fixture, proxy: &Recorder) {
        assert!(fx.connections() > 0, "nothing reached the target");
        assert_eq!(
            fx.connections(),
            proxy.joined(),
            "the target accepted connections the proxy did not open"
        );
    }

    /// The passive providers, as the sources name their hosts.
    fn providers(proxy: &Recorder) -> Vec<String> {
        let mut v: Vec<String> = proxy
            .seen()
            .iter()
            .filter_map(|t| name_of(t).map(str::to_string))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrapped_takeover_asks_its_passive_sources_through_the_proxy() {
        // Every provider is joined to a listener that hangs up, so each source
        // fails fast and nothing is fetched from anywhere real.
        let fx = Fixture::banner(b"").await;
        let to = fx.port;
        let proxy = Recorder::start(move |_| Some(([127, 0, 0, 1], to).into())).await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "takeover",
            "response": "stream",
            "domain": "example.test",
            "dns_server": local_dns().await,
            "timeout_ms": 3000,
        });
        let events = exchange(dport, &wrapped(op, &proxy)).await;
        assert!(
            events.iter().any(|e| e["type"] == "done"),
            "the check did not finish: {events:?}"
        );
        let asked = providers(&proxy);
        assert!(asked.iter().any(|h| h == "crt.sh"), "{asked:?}");
        assert!(asked.len() >= 5, "{asked:?}");
        assert_all_through(&fx, &proxy);
    }

    #[tokio::test]
    async fn the_passive_sources_go_through_the_egress_they_are_given() {
        let fx = Fixture::banner(b"").await;
        let to = fx.port;
        let proxy = Recorder::start(move |_| Some(([127, 0, 0, 1], to).into())).await;
        let found = crate::scanners::passive_scan::execute(
            "example.test",
            "voyage-test",
            &[],
            &proxied(&proxy),
        )
        .await
        .unwrap();
        assert!(found.is_empty());
        assert!(providers(&proxy).iter().any(|h| h == "crt.sh"));
        assert_all_through(&fx, &proxy);
    }

    #[tokio::test]
    async fn enum_http_probing_goes_through_the_egress() {
        let fx = Fixture::http("text/html", "ok".into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let config = EnumConfig {
            scan_id: "s".into(),
            domain: "example.test".into(),
            tasks: 1,
            interval_ms: 0,
            exclude_passive_sources: vec![],
            exclude_active_techniques: vec![],
            http_probing_ports: vec![fx.port],
            https_probing_ports: vec![],
            active_user_agent: "voyage-test".into(),
            passive_user_agent: "voyage-test".into(),
            active_random_user_agent: false,
            dns_server: local_dns().await,
            adaptive_rate: false,
            adaptive_resilience: false,
            posture: "balanced".into(),
            evasive: false,
            identify: None,
            block_internal: false,
            egress: proxied(&proxy),
        };
        let client = crate::scanner::probe_client(&config, "voyage-test").unwrap();
        let got = crate::scanners::techniques::http_probing::execute(
            &client,
            &ONLY_THE_PROXY.to_string(),
            &[fx.port],
        )
        .await;
        assert!(got.is_ok(), "the probe did not arrive");
        assert_eq!(fx.requests().len(), 1);
        assert_eq!(
            proxy.seen().iter().filter_map(name_of).collect::<Vec<_>>(),
            [ONLY_THE_PROXY]
        );
        assert_all_through(&fx, &proxy);
    }

    #[tokio::test]
    async fn the_takeover_fetch_goes_through_the_egress() {
        let fx = Fixture::http("text/html", "ok".into()).await;
        let proxy = Recorder::start(to_loopback).await;
        let params: TakeoverParams = serde_json::from_value(serde_json::json!({
            "hosts": [ONLY_THE_PROXY],
            "block_internal": true,
        }))
        .unwrap();
        let client = takeover_client(&params, "voyage-test", &proxied(&proxy)).unwrap();
        let r = client
            .get(format!("http://{ONLY_THE_PROXY}:{}/", fx.port))
            .send()
            .await
            .expect("through the proxy");
        assert_eq!(r.status().as_u16(), 200);
        assert_all_through(&fx, &proxy);
    }

    #[tokio::test]
    async fn a_zone_transfer_dials_the_nameserver_through_the_egress() {
        let fx = Fixture::banner(b"").await;
        let proxy = Recorder::start(to_loopback).await;
        let ns: std::net::SocketAddr = ([127, 0, 0, 1], fx.port).into();
        let t = crate::axfr::transfer("example.test", ns, Duration::from_secs(2), &proxied(&proxy))
            .await;
        assert!(t.refused.is_some());
        assert_eq!(proxy.seen().len(), 1);
        assert_eq!(proxy.seen()[0].port, fx.port);
        assert_all_through(&fx, &proxy);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_proxied_origin_op_is_refused_with_a_note() {
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "origin",
            "response": "instant",
            "domain": "example.test",
        });
        let events = exchange(dport, &wrapped(op, &proxy)).await;
        assert_eq!(events[0]["status"], "error", "{events:?}");
        assert!(
            events[0]["message"]
                .as_str()
                .unwrap_or("")
                .contains("cannot run through a proxy"),
            "{events:?}"
        );
        assert_eq!(proxy.connections(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrapped_op_with_an_unknown_egress_version_is_refused_unsent() {
        let proxy = Recorder::start(to_loopback).await;
        let dport = daemon().await;
        let op = serde_json::json!({
            "operation": "takeover",
            "response": "stream",
            "hosts": ["example.test"],
            "dns_server": local_dns().await,
        });
        let events = exchange(
            dport,
            &dguard::wrap_egress(&op, &serde_json::json!({"v": 2, "proxy": proxy.url()})),
        )
        .await;
        assert!(dguard::is_error(&events[0].to_string()), "{events:?}");
        assert_eq!(proxy.connections(), 0);
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
}

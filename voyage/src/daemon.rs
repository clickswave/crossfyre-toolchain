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
}

fn default_response_mode() -> String {
    "queue".to_string()
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
    /// Per-task wait between requests in ms. Same semantic as pulse's
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
struct ProbeParams {
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
            let _ = writer
                .write_all(b"{\"status\":\"error\",\"error\":\"unauthorized\"}\n")
                .await;
            continue;
        }

        let req = match serde_json::from_str::<DaemonRequest>(&line) {
            Err(e) => {
                write_json(
                    &mut writer,
                    &serde_json::json!({
                        "operation_id": Uuid::new_v4().to_string(),
                        "status": "error",
                        "message": format!("Invalid JSON: {}", e),
                    }),
                )
                .await?;
                continue;
            }
            Ok(r) => r,
        };

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
        Ok(p) => p,
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
                Ok(p) => p,
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
            let noop = |_: String| {};
            let findings = crate::scanners::origin::discover(
                &params.domain,
                params.timeout_ms,
                params.evasive,
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

async fn prepare_enum(
    params: &EnumParams,
    db: &Arc<VoyageDb>,
) -> Result<(Scanner, usize), Box<dyn std::error::Error + Send + Sync>> {
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
    if !params.disable_active && !params.wordlist.is_empty() {
        let words = crate::libs::wordlist::read_lines(&params.wordlist)
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
        let t = crate::axfr::transfer(&zone, addr, timeout).await;
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

    // Plain reqwest with an explicit User-Agent, deliberately NOT the transport
    // layer's browser-emulating identity. This path serves the public free
    // tools, which reach hosts whose owners have not asked us to scan them; the
    // only defensible posture there is to say who we are. Evasion belongs to
    // scans a customer authorised on their own property.
    let mut builder = reqwest::Client::builder()
        .user_agent(&ua)
        .timeout(std::time::Duration::from_millis(params.timeout_ms))
        // No redirects on the guarded path: a followed redirect is a second
        // destination the caller chose and we did not check. The confirmation
        // fetch only needs the provider's own not-configured page, which is
        // served directly, so nothing legitimate is lost.
        .redirect(if params.block_internal {
            reqwest::redirect::Policy::none()
        } else {
            reqwest::redirect::Policy::limited(3)
        });
    if params.block_internal {
        builder = builder.dns_resolver(std::sync::Arc::new(transport::guard::PublicOnlyResolver));
    }
    let client = match builder.build() {
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
            match crate::scanners::passive_scan::execute(&domain, &ua, &[]).await {
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

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Events streamed to the client during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    #[serde(rename = "type")]
    pub kind: String, // "ack", "result", "log", "done"

    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,

    // Result fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>, // "open", "closed", "filtered"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,

    // Cumulative probes finished so far (sent with "progress").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed: Option<usize>,

    // Counters (sent with "done")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filtered: Option<usize>,

    // Logging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    // Governor telemetry (kind == "governor"): live adaptive-rate state so a
    // consumer (node -> api_switch -> UI, or a stream client) can chart how the
    // scan is riding the network. Absent on every other event kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srtt_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rtt_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_pct: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goodput: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

impl StreamEvent {
    /// All-`None` event of a given kind; constructors set only what they need.
    fn base(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            operation_id: None,
            total: None,
            host: None,
            port: None,
            status: None,
            service: None,
            banner: None,
            latency_ms: None,
            processed: None,
            open: None,
            closed: None,
            filtered: None,
            log_level: None,
            message: None,
            concurrency: None,
            timeout_ms: None,
            retries: None,
            srtt_ms: None,
            min_rtt_ms: None,
            loss_pct: None,
            goodput: None,
            phase: None,
        }
    }

    /// Cumulative progress during a scan: `processed` of `total` probes finished.
    pub fn progress(processed: usize, total: usize) -> Self {
        let mut ev = Self::base("progress");
        ev.processed = Some(processed);
        ev.total = Some(total);
        ev
    }

    pub fn ack(operation_id: &str, total: usize) -> Self {
        let mut ev = Self::base("ack");
        ev.operation_id = Some(operation_id.to_string());
        ev.total = Some(total);
        ev
    }

    pub fn result(host: &str, port: u16, status: &str, latency_ms: u64) -> Self {
        let mut ev = Self::base("result");
        ev.host = Some(host.to_string());
        ev.port = Some(port);
        ev.status = Some(status.to_string());
        ev.latency_ms = Some(latency_ms);
        ev
    }

    pub fn result_with_service(
        host: &str,
        port: u16,
        status: &str,
        latency_ms: u64,
        service: &str,
        banner: Option<String>,
    ) -> Self {
        let mut ev = Self::result(host, port, status, latency_ms);
        ev.service = Some(service.to_string());
        ev.banner = banner;
        ev
    }

    pub fn done(open: usize, closed: usize, filtered: usize) -> Self {
        let mut ev = Self::base("done");
        ev.open = Some(open);
        ev.closed = Some(closed);
        ev.filtered = Some(filtered);
        ev
    }

    pub fn log(level: &str, message: &str) -> Self {
        let mut ev = Self::base("log");
        ev.log_level = Some(level.to_string());
        ev.message = Some(message.to_string());
        ev
    }

    pub fn error(message: &str) -> Self {
        let mut ev = Self::base("error");
        ev.message = Some(message.to_string());
        ev
    }

    /// Adaptive-rate governor snapshot (see `governor::Telemetry`).
    pub fn governor(t: &crate::governor::Telemetry) -> Self {
        let mut ev = Self::base("governor");
        ev.concurrency = Some(t.concurrency);
        ev.timeout_ms = Some(t.timeout_ms);
        ev.retries = Some(t.retries);
        ev.srtt_ms = Some(t.srtt_ms);
        ev.min_rtt_ms = Some(t.min_rtt_ms);
        ev.loss_pct = Some(t.loss_pct);
        ev.goodput = Some(t.goodput);
        ev.phase = Some(t.phase.to_string());
        ev
    }
}

/// Scan parameters parsed from a daemon request.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanParams {
    pub targets: Vec<String>,
    /// Ports can be an array of numbers [80, 443] or a string spec "top-1000", "22,80,443"
    #[serde(deserialize_with = "deserialize_ports")]
    pub ports: Vec<u16>,
    #[serde(default = "default_technique")]
    // populated but not read yet; kept so the struct still mirrors its config
    #[allow(dead_code)]
    pub technique: String,
    #[serde(default = "default_tasks")]
    pub tasks: u32,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Per-slot delay in milliseconds. Each concurrent slot waits this long
    /// after acquiring the semaphore before issuing its probe, so the
    /// effective rate is roughly `tasks / (delay + probe_time)`.
    #[serde(default)]
    pub delay: u64,
    #[serde(default)]
    pub service_detection: bool,
    /// Adaptive rate governor (default on): treat `tasks`/`timeout` as seeds and
    /// let the congestion-control loop tune concurrency/timeout/retries live.
    /// Set false to pin the old fixed-rate behaviour.
    #[serde(default = "default_adaptive")]
    pub adaptive: bool,
    /// Hard ceiling on adaptive concurrency (defaults to the governor envelope).
    #[serde(default)]
    pub max_concurrency: Option<usize>,
    /// Adaptive posture: gentle | balanced | throughput (stealth is the same as
    /// gentle). Picks how aggressive the governor may get (its concurrency ceiling
    /// + retry budget).
    #[serde(default)]
    pub posture: Option<String>,
}

fn default_technique() -> String {
    "connect".to_string()
}
fn default_tasks() -> u32 {
    100
}
fn default_timeout() -> u64 {
    2000
}
fn default_adaptive() -> bool {
    true
}

fn deserialize_ports<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct PortsVisitor;
    impl<'de> de::Visitor<'de> for PortsVisitor {
        type Value = Vec<u16>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a port array or a port spec string")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u16>, E> {
            Ok(crate::libs::cli_args::resolve_ports(v))
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u16>, A::Error> {
            let mut ports = Vec::new();
            while let Some(val) = seq.next_element::<u16>()? {
                ports.push(val);
            }
            Ok(ports)
        }
    }

    deserializer.deserialize_any(PortsVisitor)
}

/// Resolves target strings (hostnames, IPs, CIDRs) into a list of IPs.
/// For now, supports single IPs and hostnames. CIDR expansion can be added later.
pub fn resolve_targets(targets: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    for target in targets {
        let t = target.trim();
        if t.contains('/') {
            // Basic CIDR: e.g. 192.168.1.0/24
            if let Some(expanded) = expand_cidr(t) {
                hosts.extend(expanded);
            } else {
                hosts.push(t.to_string());
            }
        } else {
            hosts.push(t.to_string());
        }
    }
    hosts
}

fn expand_cidr(cidr: &str) -> Option<Vec<String>> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }

    let octets: Vec<u32> = ip_str.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return None;
    }

    let ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    let mask = if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let network = ip_num & mask;
    let broadcast = network | !mask;

    // Skip network and broadcast addresses for /24 and larger
    let (start, end) = if prefix <= 30 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    };

    let mut ips = Vec::new();
    for i in start..=end {
        ips.push(format!(
            "{}.{}.{}.{}",
            (i >> 24) & 0xFF,
            (i >> 16) & 0xFF,
            (i >> 8) & 0xFF,
            i & 0xFF
        ));
    }
    Some(ips)
}

/// Below this many probes the adaptive control loop has no room to converge, so
/// we run the simple fixed-rate path (also the DS-per-port and single-probe case).
const ADAPTIVE_MIN: usize = 16;

/// Run a TCP connect scan, streaming results to the channel. Uses the adaptive
/// rate governor when the batch is large enough (and `params.adaptive`), else a
/// fixed-rate pass.
pub async fn run_connect_scan(params: &ScanParams, tx: mpsc::UnboundedSender<StreamEvent>) {
    let hosts = resolve_targets(&params.targets);
    let total = hosts.len().saturating_mul(params.ports.len());
    if params.adaptive && total >= ADAPTIVE_MIN {
        run_adaptive_scan(params, hosts, tx).await;
    } else {
        run_fixed_scan(params, hosts, tx).await;
    }
}

/// One completed probe: the streamed event plus its control-loop sample.
struct ProbeReport {
    event: StreamEvent,
    sample: crate::governor::Sample,
}

/// Fixed-rate scan: constant concurrency/timeout, 3-attempt retry. Kept for
/// small batches, single-port probes, and `adaptive = false`.
async fn run_fixed_scan(
    params: &ScanParams,
    hosts: Vec<String>,
    tx: mpsc::UnboundedSender<StreamEvent>,
) {
    let timeout_dur = Duration::from_millis(params.timeout);
    let semaphore =
        std::sync::Arc::new(tokio::sync::Semaphore::new((params.tasks.max(1)) as usize));

    let (result_tx, mut result_rx) = mpsc::unbounded_channel::<StreamEvent>();
    let delay = params.delay;
    let mut total_spawned = 0usize;
    for host in &hosts {
        for &port in &params.ports {
            let sem = semaphore.clone();
            let host = host.clone();
            let rtx = result_tx.clone();
            let detect_service = params.service_detection;
            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let rep = probe_port(&host, port, timeout_dur, 3, detect_service).await;
                let _ = rtx.send(rep.event);
            });
            total_spawned += 1;
        }
    }
    drop(result_tx);

    let (mut open, mut closed, mut filtered, mut received) = (0usize, 0usize, 0usize, 0usize);
    let mut last_progress = Instant::now();
    while let Some(ev) = result_rx.recv().await {
        match ev.status.as_deref() {
            Some("open") => open += 1,
            Some("filtered") => filtered += 1,
            _ => closed += 1,
        }
        received += 1;
        if ev.status.as_deref() != Some("closed") {
            let _ = tx.send(ev);
        }
        // Structured probe-level progress, time-throttled so a fast batch
        // doesn't flood the consumer (the node forwards this ~as-is).
        if last_progress.elapsed() >= Duration::from_millis(500) {
            last_progress = Instant::now();
            let _ = tx.send(StreamEvent::progress(received, total_spawned));
        }
    }
    let _ = tx.send(StreamEvent::progress(received, total_spawned));
    let _ = tx.send(StreamEvent::done(open, closed, filtered));
}

/// Adaptive scan: an `AdaptiveGovernor` drives concurrency, timeout and retries
/// from live loss/RTT so the scan rides the egress knee (fast) without
/// overrunning a thin tunnel into false negatives (reliable).
async fn run_adaptive_scan(
    params: &ScanParams,
    hosts: Vec<String>,
    tx: mpsc::UnboundedSender<StreamEvent>,
) {
    use crate::governor::{Governor, Limits};

    let mut limits = Limits::default();
    // Posture caps how hard the governor may push: Stealth stays quiet, Balanced
    // is the middle, Throughput lets it fully open up on a healthy path. It sets
    // the concurrency ceiling and retry budget; the governor still adapts within.
    match params.posture.as_deref() {
        Some("gentle" | "stealth") => {
            limits.conc_ceil = 64;
            limits.retry_ceil = 4;
        }
        Some("throughput") => {
            limits.conc_ceil = 512;
            limits.retry_ceil = 3;
        }
        // balanced (and anything unrecognised)
        _ => {
            limits.conc_ceil = 256;
            limits.retry_ceil = 4;
        }
    }
    if let Some(mc) = params.max_concurrency {
        limits.conc_ceil = mc.max(limits.conc_floor);
    }
    let initial_conc = (params.tasks as usize).clamp(limits.conc_floor, limits.conc_ceil);
    let gov = Governor::new(initial_conc, params.timeout, limits);

    // Control loop: emit a structured telemetry event + a human log line each tick.
    let gov_task = {
        let gov_c = gov.clone();
        let tx_c = tx.clone();
        tokio::spawn(async move {
            gov_c
                .run(|t| {
                    let _ = tx_c.send(StreamEvent::governor(&t));
                    let _ = tx_c.send(StreamEvent::log(
                        "info",
                        &format!(
                            "[adaptive:{}] conc={} timeout={}ms retries={} srtt={}ms min_rtt={}ms loss={}% recovered={} ~{}/s",
                            t.phase, t.concurrency, t.timeout_ms, t.retries,
                            t.srtt_ms, t.min_rtt_ms, t.loss_pct, t.recovered, t.goodput
                        ),
                    ));
                })
                .await;
        })
    };

    let (result_tx, mut result_rx) = mpsc::unbounded_channel::<StreamEvent>();
    for host in &hosts {
        for &port in &params.ports {
            let gov = gov.clone();
            let host = host.clone();
            let rtx = result_tx.clone();
            let detect_service = params.service_detection;
            tokio::spawn(async move {
                let _permit = gov.slot().await;
                let (timeout_dur, retries) = gov.probe_params();
                let rep = probe_port(&host, port, timeout_dur, retries, detect_service).await;
                gov.record(&rep.sample);
                let _ = rtx.send(rep.event);
            });
        }
    }
    drop(result_tx);

    let (mut open, mut closed, mut filtered, mut received) = (0usize, 0usize, 0usize, 0usize);
    let total = hosts.len().saturating_mul(params.ports.len());
    let mut last_progress = Instant::now();
    while let Some(ev) = result_rx.recv().await {
        match ev.status.as_deref() {
            Some("open") => open += 1,
            Some("filtered") => filtered += 1,
            _ => closed += 1,
        }
        received += 1;
        if ev.status.as_deref() != Some("closed") {
            let _ = tx.send(ev);
        }
        if last_progress.elapsed() >= Duration::from_millis(500) {
            last_progress = Instant::now();
            let _ = tx.send(StreamEvent::progress(received, total));
        }
    }

    gov.finish();
    let _ = gov_task.await;
    let _ = tx.send(StreamEvent::progress(received, total));
    let _ = tx.send(StreamEvent::done(open, closed, filtered));
}

/// Probe a single host:port via TCP connect.
///
/// For hostnames that resolve to multiple addresses (e.g. "localhost" →
/// 127.0.0.1 *and* ::1) we try every one before declaring the port closed.
/// Most local services bind to only IPv4 OR only IPv6, so picking just the
/// first address from the resolver was making the same port look open or
/// closed depending on which family came back first - that's why DS and
/// SB scans of the same `localhost:5432` could disagree.
async fn probe_port(
    host: &str,
    port: u16,
    timeout_dur: Duration,
    max_attempts: u32,
    detect_service: bool,
) -> ProbeReport {
    use crate::governor::{Outcome, Sample};
    let addr_str = format!("{host}:{port}");

    // Build the list of addresses to try.
    let addrs: Vec<SocketAddr> = if let Ok(parsed) = addr_str.parse::<SocketAddr>() {
        vec![parsed]
    } else {
        match tokio::net::lookup_host(&addr_str).await {
            Ok(iter) => iter.collect(),
            // DNS failure isn't network loss on the probe path; report as
            // delivered-fast so it doesn't drag the governor's loss signal.
            Err(_) => {
                return ProbeReport {
                    event: StreamEvent::result(host, port, "filtered", 0),
                    sample: Sample {
                        outcome: Outcome::Delivered { rtt_ms: 0 },
                        attempts: 1,
                    },
                };
            }
        }
    };
    if addrs.is_empty() {
        return ProbeReport {
            event: StreamEvent::result(host, port, "filtered", 0),
            sample: Sample {
                outcome: Outcome::Delivered { rtt_ms: 0 },
                attempts: 1,
            },
        };
    }

    let start = Instant::now();
    let max_attempts = max_attempts.max(1);

    // Retry timed-out probes. A single dropped SYN over a lossy link (a lab
    // VPN, a rate-limiting target) would otherwise turn an open port into a
    // false "filtered" - that's how a full HTB scan "found" only 1 of 3 open
    // ports. A successful connect ("open") or a definitive RST ("closed")
    // returns immediately; only an all-timeout result is retried. The attempt
    // budget is set by the adaptive governor from live loss.
    let mut saw_refused = false;
    let mut attempts_used = 0u32;
    for attempt in 0..max_attempts {
        saw_refused = false;
        attempts_used = attempt + 1;
        for addr in &addrs {
            match timeout(timeout_dur, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    let latency = start.elapsed().as_millis() as u64;
                    // RST-close instead of a graceful FIN so the socket doesn't
                    // sit in TIME_WAIT. A full-range scan opens tens of
                    // thousands of connections; without this the local
                    // ephemeral-port pool is exhausted partway through and
                    // connect() stalls (slow tail).
                    // SO_LINGER(0) is an RST close: it returns immediately and is what keeps a
                    // full-range scan from exhausting the ephemeral-port pool via TIME_WAIT.
                    // tokio deprecated set_linger because a NON-ZERO linger blocks the thread on
                    // drop; that hazard does not apply here. Migrating means going through
                    // socket2 on the raw fd, which is not worth the unsafe for the same syscall.
                    #[allow(deprecated)]
                    let _ = stream.set_linger(Some(std::time::Duration::ZERO));
                    let event = if detect_service {
                        let service = identify_service(port);
                        let banner = grab_banner(&stream, timeout_dur).await;
                        StreamEvent::result_with_service(
                            host, port, "open", latency, service, banner,
                        )
                    } else {
                        StreamEvent::result(host, port, "open", latency)
                    };
                    return ProbeReport {
                        event,
                        sample: Sample {
                            outcome: Outcome::Delivered { rtt_ms: latency },
                            attempts: attempt + 1,
                        },
                    };
                }
                Ok(Err(_)) => {
                    saw_refused = true;
                } // RST -> closed (this address)
                Err(_) => {} // timeout -> retry below
            }
        }
        // A definitive RST is a real answer - don't waste retries on it.
        if saw_refused {
            break;
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }

    // No address opened across all attempts. Distinguish "closed" (we got RST)
    // from "filtered" (everything timed out, even after retries). A closed port
    // is a delivered answer (RST arrived); an all-timeout is loss for the loop.
    if saw_refused {
        let rtt = start.elapsed().as_millis() as u64;
        ProbeReport {
            event: StreamEvent::result(host, port, "closed", rtt),
            sample: Sample {
                outcome: Outcome::Delivered { rtt_ms: rtt },
                attempts: attempts_used,
            },
        }
    } else {
        ProbeReport {
            event: StreamEvent::result(host, port, "filtered", timeout_dur.as_millis() as u64),
            sample: Sample {
                outcome: Outcome::Lost,
                attempts: max_attempts,
            },
        }
    }
}

/// Basic service identification by well-known port.
fn identify_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        587 => "submission",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        6443 => "k8s-api",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    }
}

/// Attempt to grab a service banner (first bytes sent by the server).
async fn grab_banner(stream: &TcpStream, timeout_dur: Duration) -> Option<String> {
    let mut buf = [0u8; 512];
    match timeout(
        Duration::from_millis(timeout_dur.as_millis() as u64 / 2),
        stream.readable(),
    )
    .await
    {
        Ok(Ok(())) => match stream.try_read(&mut buf) {
            Ok(n) if n > 0 => {
                let banner = String::from_utf8_lossy(&buf[..n])
                    .trim()
                    .chars()
                    .take(200)
                    .collect::<String>();
                if banner.is_empty() {
                    None
                } else {
                    Some(banner)
                }
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end liveness of the adaptive path: probes spawn, the governor loop
    /// ticks and emits telemetry, and the scan shuts down cleanly with a `done`.
    /// Scans a block of almost-certainly-closed localhost ports (RST => fast
    /// "delivered" samples) so it runs in well under a second without depending
    /// on any listening service.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn adaptive_scan_completes_and_emits_telemetry() {
        let ports: Vec<u16> = (52000..52080).collect(); // 80 ports => adaptive path
        let params = ScanParams {
            targets: vec!["127.0.0.1".to_string()],
            ports,
            technique: "connect".to_string(),
            tasks: 32,
            timeout: 300,
            delay: 0,
            service_detection: false,
            adaptive: true,
            max_concurrency: Some(128),
            posture: None,
        };

        let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();
        let scan = tokio::spawn(async move { run_connect_scan(&params, tx).await });

        let mut saw_done = false;
        let mut saw_governor = false;
        // hard ceiling so a hang fails the test instead of blocking forever
        let collect = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(ev) = rx.recv().await {
                match ev.kind.as_str() {
                    "governor" => saw_governor = true,
                    "done" => {
                        saw_done = true;
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await;

        assert!(collect.is_ok(), "adaptive scan hung (no done within 10s)");
        assert!(saw_done, "scan must emit a done event");
        assert!(
            saw_governor,
            "adaptive scan must emit at least one governor telemetry tick"
        );
        let _ = scan.await;
    }
}

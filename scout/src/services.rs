//! Non-HTTP service identification, and whether the service is wide open.
//!
//! Everything else in the toolchain speaks HTTP. pulse can tell you port 6379
//! is open and guess "redis" from the port number, and there it stopped: no
//! engine ever spoke the protocol, so "an open Redis with no password" - one of
//! the most valuable things you can find on an estate - was invisible to us. A
//! port number is a guess anyway; services move, and a guess is not a finding.
//!
//! So this speaks the protocols. For each service it answers two questions:
//! what is actually listening (with a version where the protocol offers one),
//! and does it let an anonymous caller in.
//!
//! Rules this module holds to:
//!
//!   * Read-only. Nothing here writes a key, creates a database, uploads a
//!     file, or changes server state. The Redis probe is PING and INFO; the
//!     Mongo probe is hello and listDatabases; the SMTP probe stops at EHLO.
//!   * One attempt per credential, never a list. Checking whether Postgres
//!     trusts everyone, MySQL's root has no password, or FTP allows anonymous
//!     is a single well-known account each. That is a configuration check, not
//!     a brute force, and `auth_checks: false` turns even that off.
//!   * A fresh connection per protocol attempt, because a probe for the wrong
//!     protocol leaves the stream in a state the next probe would misread.
//!   * The port is a hint for ordering, never the answer.

use cfx_finding::Finding;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Debug, Deserialize)]
pub struct SvcParams {
    /// `host:port` entries, as pulse reports them.
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    /// Try the one well-known anonymous/default account per service (anonymous
    /// FTP, Postgres trust, MySQL root with an empty password, anonymous LDAP
    /// bind). Single attempt each; never a list.
    #[serde(default = "d_true")]
    pub auth_checks: bool,
    /// Targets probed concurrently.
    #[serde(default = "d_tasks")]
    pub tasks: usize,
}
fn d_timeout() -> u64 {
    5000
}
fn d_true() -> bool {
    true
}
fn d_tasks() -> usize {
    16
}

/// What one probe concluded about one service.
#[derive(Default)]
struct Svc {
    service: String,
    version: String,
    banner: String,
    /// "none" (anyone gets in), "required", or "" (not established).
    auth: String,
    findings: Vec<Value>,
}

impl Svc {
    fn named(service: &str) -> Self {
        Self {
            service: service.into(),
            ..Default::default()
        }
    }
}

pub async fn run(params: SvcParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({"type":"ack","targets": params.targets.len()}));
    let to = Duration::from_millis(params.timeout_ms.clamp(500, 30_000));
    let tasks = params.tasks.clamp(1, 64);
    let auth_checks = params.auth_checks;

    let mut queue = params.targets.clone().into_iter();
    let mut inflight = tokio::task::JoinSet::new();
    let mut done = 0usize;
    let total = params.targets.len();

    loop {
        while inflight.len() < tasks {
            match queue.next() {
                Some(t) => {
                    inflight.spawn(async move {
                        let svc = identify(&t, to, auth_checks).await;
                        (t, svc)
                    });
                }
                None => break,
            }
        }
        let Some(joined) = inflight.join_next().await else {
            break;
        };
        let Ok((target, svc)) = joined else {
            continue;
        };
        done += 1;
        if let Some(svc) = svc {
            let (host, port) = split_host_port(&target);
            let _ = tx.send(json!({
                "type": "service",
                "target": target,
                "host": host,
                "port": port,
                "service": svc.service,
                "version": svc.version,
                "banner": svc.banner,
                "auth": svc.auth,
            }));
            for f in svc.findings {
                let _ = tx.send(json!({"type":"finding","data": f}));
            }
        }
        let _ = tx.send(json!({"type":"progress","processed":done,"total":total}));
    }

    let _ = tx.send(json!({"type":"done","processed":done}));
}

fn split_host_port(t: &str) -> (String, u16) {
    match t.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(0)),
        None => (t.to_string(), 0),
    }
}

/// Probe order for a port. The port-conventional protocol goes first because it
/// is usually right and costs one connection; the rest follow so a service on a
/// non-standard port is still identified.
fn order_for(port: u16) -> Vec<&'static str> {
    let first: &[&str] = match port {
        6379 | 6380 => &["redis"],
        11211 => &["memcached"],
        27017..=27019 => &["mongodb"],
        3306 | 3307 => &["mysql"],
        5432 | 5433 => &["postgres"],
        21 => &["ftp"],
        22 => &["ssh"],
        25 | 465 | 587 => &["smtp"],
        389 | 636 | 3268 => &["ldap"],
        _ => &[],
    };
    let mut v: Vec<&'static str> = first.to_vec();
    // Banner-first for the rest: services that speak on connect identify
    // themselves in one round trip.
    for p in [
        "banner",
        "redis",
        "memcached",
        "mongodb",
        "postgres",
        "ldap",
        "mysql",
        "http",
    ] {
        if !v.contains(&p) {
            v.push(p);
        }
    }
    v
}

async fn identify(target: &str, to: Duration, auth_checks: bool) -> Option<Svc> {
    let (_, port) = split_host_port(target);
    for proto in order_for(port) {
        let got = match proto {
            "redis" => redis(target, to).await,
            "memcached" => memcached(target, to).await,
            "mongodb" => mongodb(target, to).await,
            "mysql" => mysql(target, to, auth_checks).await,
            "postgres" => postgres(target, to, auth_checks).await,
            "ftp" => ftp(target, to, auth_checks).await,
            "ssh" => banner_service(target, to).await,
            "smtp" => smtp(target, to).await,
            "ldap" => ldap(target, to, auth_checks).await,
            "banner" => banner_service(target, to).await,
            "http" => http_service(target, to).await,
            _ => None,
        };
        if let Some(mut svc) = got {
            // A banner probe that lands on FTP/SMTP should still get their
            // protocol-specific follow-up.
            if proto == "banner" {
                match svc.service.as_str() {
                    "ftp" => {
                        if let Some(s) = ftp(target, to, auth_checks).await {
                            svc = s;
                        }
                    }
                    "smtp" => {
                        if let Some(s) = smtp(target, to).await {
                            svc = s;
                        }
                    }
                    "mysql" => {
                        if let Some(s) = mysql(target, to, auth_checks).await {
                            svc = s;
                        }
                    }
                    _ => {}
                }
            }
            return Some(svc);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Transport helpers
// ---------------------------------------------------------------------------

async fn connect(target: &str, to: Duration) -> Option<TcpStream> {
    let s = timeout(to, TcpStream::connect(target)).await.ok()?.ok()?;
    let _ = s.set_nodelay(true);
    Some(s)
}

/// Read whatever arrives within the window, up to `cap` bytes. Absence of data
/// is not an error: plenty of protocols wait for the client to speak first.
async fn read_some(s: &mut TcpStream, to: Duration, cap: usize) -> Vec<u8> {
    let mut buf = vec![0u8; cap];
    match timeout(to, s.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            buf
        }
        _ => Vec::new(),
    }
}

async fn write_all(s: &mut TcpStream, data: &[u8], to: Duration) -> bool {
    matches!(timeout(to, s.write_all(data)).await, Ok(Ok(())))
}

/// Trim a version string to the version: protocols pad their replies with
/// CRLF and follow-on fields, and `printable` renders those as dots.
fn tidy_version(v: &str) -> String {
    v.trim()
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_string()
}

/// The whole buffer as text, for PARSING. `printable` truncates to a banner
/// length, which silently hid Postgres' server_version 200 bytes into its
/// parameter block.
fn full_text(b: &[u8]) -> String {
    b.iter()
        .map(|c| {
            if c.is_ascii_graphic() || *c == b' ' {
                *c as char
            } else {
                '.'
            }
        })
        .collect()
}

fn printable(b: &[u8]) -> String {
    b.iter()
        .take(200)
        .map(|c| {
            if c.is_ascii_graphic() || *c == b' ' {
                *c as char
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn open_finding(service: &str, target: &str, severity: &str, name: &str, detail: String) -> Value {
    Finding::new("scout-services", "misconfig", name, severity, target)
        .location("service")
        .describe(detail)
        .with("service", json!(service))
        .build()
}

fn creds_finding(service: &str, target: &str, name: &str, detail: String) -> Value {
    Finding::new("scout-services", "default_creds", name, "critical", target)
        .location("service")
        .describe(detail)
        .with("service", json!(service))
        .build()
}

// ---------------------------------------------------------------------------
// Protocols
// ---------------------------------------------------------------------------

/// Services that greet on connect: SSH, FTP, SMTP, MySQL, and anything else
/// whose first bytes name it.
async fn banner_service(target: &str, to: Duration) -> Option<Svc> {
    let mut s = connect(target, to).await?;
    let b = read_some(&mut s, to, 1024).await;
    if b.is_empty() {
        return None;
    }
    let text = printable(&b);
    let low = text.to_lowercase();
    let mut svc = Svc {
        banner: text.clone(),
        ..Default::default()
    };

    if low.starts_with("ssh-") {
        svc.service = "ssh".into();
        svc.version = text.trim_start_matches("SSH-").to_string();
    } else if low.starts_with("220") && low.contains("ftp") {
        svc.service = "ftp".into();
        svc.version = text.clone();
    } else if low.starts_with("220") {
        svc.service = "smtp".into();
        svc.version = text.clone();
    } else if b.len() > 5 && b[4] == 10 {
        // MySQL: [3-byte length][sequence][protocol version 10][version\0]
        svc.service = "mysql".into();
        svc.version = b[5..]
            .split(|c| *c == 0)
            .next()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .unwrap_or_default();
    } else if low.starts_with("http/") {
        svc.service = "http".into();
    } else {
        svc.service = "unknown".into();
    }
    Some(svc)
}

/// Last resort: does it speak HTTP? No finding here - the web engines own that
/// surface - but an identified port is better than an unknown one, and a
/// service on a port nobody expects HTTP on is worth seeing.
async fn http_service(target: &str, to: Duration) -> Option<Svc> {
    let (host, _) = split_host_port(target);
    let mut s = connect(target, to).await?;
    let req = format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if !write_all(&mut s, req.as_bytes(), to).await {
        return None;
    }
    let r = read_some(&mut s, to, 1024).await;
    let text = printable(&r);
    if !text.starts_with("HTTP/") {
        return None;
    }
    let mut svc = Svc::named("http");
    svc.banner = text.lines().next().unwrap_or("").to_string();
    if let Some(i) = text.to_lowercase().find("server:") {
        svc.version = tidy_version(text[i + 7..].lines().next().unwrap_or(""));
    }
    Some(svc)
}

/// Redis. PING is read-only and answers before AUTH on an open instance.
async fn redis(target: &str, to: Duration) -> Option<Svc> {
    let mut s = connect(target, to).await?;
    if !write_all(&mut s, b"*1\r\n$4\r\nPING\r\n", to).await {
        return None;
    }
    let r = read_some(&mut s, to, 512).await;
    if r.is_empty() {
        return None;
    }
    let text = printable(&r);
    let mut svc = Svc::named("redis");
    svc.banner = text.clone();

    if text.starts_with("+PONG") {
        svc.auth = "none".into();
        // INFO is a read: it reports the version and nothing is modified.
        if write_all(&mut s, b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n", to).await {
            let info = full_text(&read_some(&mut s, to, 4096).await);
            if let Some(v) = info
                .split("redis_version:")
                .nth(1)
                .and_then(|t| t.split('.').next().map(|_| t))
            {
                svc.version = tidy_version(
                    &v.chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect::<String>(),
                );
            }
        }
        svc.findings.push(open_finding(
            "redis",
            target,
            "critical",
            "Redis reachable with no authentication",
            format!(
                "The Redis instance answered PING from an unauthenticated connection{}. Anyone \
                 who can reach this port can read and delete every key, and Redis has well known \
                 paths from there to remote code execution on the host (writing an SSH key or a \
                 cron entry through CONFIG SET, or loading a module). Require a password with \
                 `requirepass`, keep it off any interface that is not the application's, and \
                 leave protected-mode on.",
                if svc.version.is_empty() {
                    String::new()
                } else {
                    format!(" (version {})", svc.version)
                }
            ),
        ));
    } else if text.contains("NOAUTH") || text.contains("operation not permitted") {
        svc.auth = "required".into();
    } else if text.contains("DENIED") {
        // protected-mode: it is Redis, and it is refusing us, which is correct.
        svc.auth = "required".into();
    } else {
        return None;
    }
    Some(svc)
}

/// memcached. `version` is read-only; the protocol has no authentication at all
/// in its default configuration, so reachability IS the finding.
async fn memcached(target: &str, to: Duration) -> Option<Svc> {
    let mut s = connect(target, to).await?;
    if !write_all(&mut s, b"version\r\n", to).await {
        return None;
    }
    let r = printable(&read_some(&mut s, to, 256).await);
    if !r.starts_with("VERSION") {
        return None;
    }
    let mut svc = Svc::named("memcached");
    svc.version = tidy_version(r.trim_start_matches("VERSION"));
    svc.banner = r;
    svc.auth = "none".into();
    svc.findings.push(open_finding(
        "memcached",
        target,
        "high",
        "memcached reachable with no authentication",
        format!(
            "The memcached instance answered `version` ({}) from an unauthenticated connection. \
             The text protocol has no authentication by default, so anyone who can reach the port \
             can read every cached item - sessions, tokens, personal data - and flush the cache. \
             It is also a well known UDP amplification reflector. Bind it to the application's \
             interface only.",
            svc.version
        ),
    ));
    Some(svc)
}

/// MongoDB over OP_MSG (wire protocol 3.6+). `hello` identifies the server;
/// `listDatabases` establishes whether authentication is enforced. Both are
/// reads.
async fn mongodb(target: &str, to: Duration) -> Option<Svc> {
    let mut s = connect(target, to).await?;
    let hello = bson_doc(&[("hello", BsonVal::I32(1)), ("$db", BsonVal::Str("admin"))]);
    if !write_all(&mut s, &op_msg(&hello, 1), to).await {
        return None;
    }
    let r = read_some(&mut s, to, 8192).await;
    let text = full_text(&r);
    if !(text.contains("ismaster")
        || text.contains("isWritablePrimary")
        || text.contains("maxWireVersion"))
    {
        return None;
    }
    let mut svc = Svc::named("mongodb");
    if let Some(i) = text.find("version") {
        svc.version = text[i + 7..]
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
    }
    svc.banner = text.chars().take(120).collect();

    // hello does not carry the server version; buildInfo does, and it is a read.
    let build = bson_doc(&[
        ("buildInfo", BsonVal::I32(1)),
        ("$db", BsonVal::Str("admin")),
    ]);
    if svc.version.is_empty() && write_all(&mut s, &op_msg(&build, 2), to).await {
        let b = full_text(&read_some(&mut s, to, 8192).await);
        if let Some(i) = b.find("version") {
            svc.version = tidy_version(
                &b[i + 7..]
                    .chars()
                    .skip_while(|c| !c.is_ascii_digit())
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect::<String>(),
            );
        }
    }

    let list = bson_doc(&[
        ("listDatabases", BsonVal::I32(1)),
        ("nameOnly", BsonVal::I32(1)),
        ("$db", BsonVal::Str("admin")),
    ]);
    if write_all(&mut s, &op_msg(&list, 3), to).await {
        let r2 = full_text(&read_some(&mut s, to, 8192).await);
        if r2.contains("requires authentication") || r2.contains("Unauthorized") {
            svc.auth = "required".into();
        } else if r2.contains("databases") || r2.contains("totalSize") {
            svc.auth = "none".into();
            svc.findings.push(open_finding(
                "mongodb",
                target,
                "critical",
                "MongoDB reachable with no authentication",
                "An unauthenticated connection was able to list the databases on this instance, so \
                 authorization is not enabled. Every collection is readable and writable by anyone \
                 who can reach the port, which in practice means the whole dataset. Enable \
                 authorization, create a user, and bind the server to the application's network."
                    .to_string(),
            ));
        }
    }
    Some(svc)
}

/// PostgreSQL. The startup message is enough: the server's answer says which
/// authentication method it will demand, and `trust` answers "none at all".
async fn postgres(target: &str, to: Duration, auth_checks: bool) -> Option<Svc> {
    let mut s = connect(target, to).await?;
    // StartupMessage: length, protocol 3.0, then null-terminated key/value pairs.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    for (k, v) in [("user", "postgres"), ("database", "postgres")] {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut msg = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(&body);
    if !write_all(&mut s, &msg, to).await {
        return None;
    }
    let r = read_some(&mut s, to, 2048).await;
    if r.is_empty() {
        return None;
    }
    // On trust auth the server follows AuthenticationOk with its parameters,
    // one of which is the version.
    let params_text = full_text(&r);
    let pg_version = params_text
        .split("server_version")
        .nth(1)
        .map(|t| {
            t.chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect::<String>()
        })
        .unwrap_or_default();

    let mut svc = Svc::named("postgres");
    svc.version = tidy_version(&pg_version);
    match r[0] {
        b'R' if r.len() >= 9 => {
            let code = u32::from_be_bytes([r[5], r[6], r[7], r[8]]);
            svc.banner = format!("authentication request {code}");
            match code {
                0 => {
                    svc.auth = "none".into();
                    if svc.version.is_empty() {
                        // The parameters usually arrive in a second segment.
                        let more = full_text(&read_some(&mut s, to, 2048).await);
                        if let Some(t) = more.split("server_version").nth(1) {
                            svc.version = tidy_version(
                                &t.chars()
                                    .skip_while(|c| !c.is_ascii_digit())
                                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                                    .collect::<String>(),
                            );
                        }
                    }
                    if auth_checks {
                        svc.findings.push(creds_finding(
                            "postgres",
                            target,
                            "PostgreSQL accepts connections with no password (trust auth)",
                            "The server answered AuthenticationOk to a startup message for the \
                             `postgres` superuser with no password offered, which is `trust` in \
                             pg_hba.conf. Anyone who can reach the port is a superuser: they can \
                             read and modify every database, and reach the filesystem through \
                             COPY ... PROGRAM. Change the host rules to scram-sha-256 and restrict \
                             the listen address."
                                .to_string(),
                        ));
                    }
                }
                3 => svc.auth = "required".into(),
                5 => svc.auth = "required".into(),
                10 => svc.auth = "required".into(),
                _ => svc.auth = "required".into(),
            }
        }
        b'E' => {
            // An error still proves it is Postgres (and often names the version
            // or the missing role).
            svc.banner = printable(&r);
            svc.auth = "required".into();
        }
        _ => return None,
    }
    let _ = write_all(&mut s, b"X\x00\x00\x00\x04", to).await;
    Some(svc)
}

/// MySQL / MariaDB. The greeting identifies it; with `auth_checks` on, one
/// handshake as root with an empty password says whether the classic
/// misconfiguration is present. An empty password needs no scramble, so this
/// stays a single well-formed packet.
async fn mysql(target: &str, to: Duration, auth_checks: bool) -> Option<Svc> {
    let mut s = connect(target, to).await?;
    let greet = read_some(&mut s, to, 1024).await;
    if greet.len() < 6 || greet[4] != 10 {
        return None;
    }
    let mut svc = Svc::named("mysql");
    svc.version = greet[5..]
        .split(|c| *c == 0)
        .next()
        .map(|v| String::from_utf8_lossy(v).to_string())
        .unwrap_or_default();
    svc.banner = printable(&greet);
    if svc.version.to_lowercase().contains("mariadb") {
        svc.service = "mariadb".into();
    }

    if auth_checks {
        // HandshakeResponse41: capabilities, max packet, charset, filler, user,
        // zero-length auth response (an empty password), plugin name.
        let caps: u32 = 0x0000_0200 | 0x0000_8000 | 0x0008_0000 | 0x0000_0001;
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&caps.to_le_bytes());
        body.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes());
        body.push(33); // utf8_general_ci
        body.extend_from_slice(&[0u8; 23]);
        body.extend_from_slice(b"root");
        body.push(0);
        body.push(0); // auth response length 0 = no password
        body.extend_from_slice(b"mysql_native_password");
        body.push(0);
        let mut pkt = (body.len() as u32).to_le_bytes()[..3].to_vec();
        pkt.push(1); // sequence 1, replying to the greeting
        pkt.extend_from_slice(&body);
        if write_all(&mut s, &pkt, to).await {
            // The server may answer with an auth-switch (0xFE) or more-data
            // (0x01) packet before it decides. With an empty password the
            // correct answer to both is an empty auth response, whichever
            // plugin it asks for, so follow the exchange rather than reading
            // one packet and giving up - which is what made a caching_sha2
            // server (the default since 8.0) look inconclusive.
            let mut r = read_some(&mut s, to, 1024).await;
            let mut seq = 3u8;
            for _ in 0..3 {
                if r.len() <= 4 || (r[4] != 0xFE && r[4] != 0x01) {
                    break;
                }
                let empty = [0u8, 0, 0, seq];
                if !write_all(&mut s, &empty, to).await {
                    break;
                }
                seq += 2;
                r = read_some(&mut s, to, 1024).await;
            }
            if r.len() > 4 {
                match r[4] {
                    0x00 => {
                        svc.auth = "none".into();
                        svc.findings.push(creds_finding(
                            "mysql",
                            target,
                            "MySQL root account has no password",
                            format!(
                                "The server ({}) completed a handshake for `root` with an empty \
                                 password. Anyone who can reach the port has full control of every \
                                 database, and of the filesystem wherever FILE privileges and \
                                 secure_file_priv allow. Set a password for root and bind the \
                                 server to the application's network.",
                                svc.version
                            ),
                        ));
                    }
                    0xFF => svc.auth = "required".into(),
                    _ => {}
                }
            }
        }
    }
    Some(svc)
}

/// FTP. The banner identifies it; anonymous login is one exchange.
async fn ftp(target: &str, to: Duration, auth_checks: bool) -> Option<Svc> {
    let mut s = connect(target, to).await?;
    let hello = printable(&read_some(&mut s, to, 512).await);
    if !hello.starts_with("220") {
        return None;
    }
    let mut svc = Svc::named("ftp");
    svc.banner = hello.clone();
    svc.version = tidy_version(hello.trim_start_matches("220"));

    if auth_checks {
        if write_all(&mut s, b"USER anonymous\r\n", to).await {
            let r1 = printable(&read_some(&mut s, to, 512).await);
            if r1.starts_with("331") || r1.starts_with("230") {
                let mut ok = r1.starts_with("230");
                if !ok && write_all(&mut s, b"PASS anonymous@example.com\r\n", to).await {
                    ok = printable(&read_some(&mut s, to, 512).await).starts_with("230");
                }
                if ok {
                    svc.auth = "none".into();
                    svc.findings.push(open_finding(
                        "ftp",
                        target,
                        "medium",
                        "FTP allows anonymous login",
                        "The server accepted an anonymous login. Whatever the anonymous account \
                         can see is public, and if the directory is writable it is a free file \
                         drop and often a path onto the web root. Disable anonymous access unless \
                         the content is deliberately public, and never leave it writable."
                            .to_string(),
                    ));
                } else {
                    svc.auth = "required".into();
                }
            } else {
                svc.auth = "required".into();
            }
        }
        let _ = write_all(&mut s, b"QUIT\r\n", to).await;
    }
    Some(svc)
}

/// SMTP: identify and read the advertised capabilities. Deliberately stops
/// before anything that would test relaying, which is not a read.
async fn smtp(target: &str, to: Duration) -> Option<Svc> {
    let mut s = connect(target, to).await?;
    let hello = printable(&read_some(&mut s, to, 512).await);
    if !hello.starts_with("220") {
        return None;
    }
    let mut svc = Svc::named("smtp");
    svc.banner = hello.clone();
    svc.version = tidy_version(hello.trim_start_matches("220"));
    if write_all(&mut s, b"EHLO crossfyre.invalid\r\n", to).await {
        let caps = full_text(&read_some(&mut s, to, 2048).await);
        if caps.to_uppercase().contains("AUTH") && !caps.to_uppercase().contains("STARTTLS") {
            svc.findings.push(open_finding(
                "smtp",
                target,
                "medium",
                "SMTP offers authentication without STARTTLS",
                "The server advertises AUTH but not STARTTLS, so credentials would cross the \
                 network in the clear on this listener. Offer STARTTLS, and refuse AUTH until the \
                 session is encrypted."
                    .to_string(),
            ));
        }
    }
    let _ = write_all(&mut s, b"QUIT\r\n", to).await;
    Some(svc)
}

/// LDAP. An anonymous simple bind is one BER-encoded request, and its result
/// code is the whole answer.
async fn ldap(target: &str, to: Duration, auth_checks: bool) -> Option<Svc> {
    if !auth_checks {
        return None;
    }
    let mut s = connect(target, to).await?;
    // SEQUENCE { messageID 1, [APPLICATION 0] { version 3, name "", [0] "" } }
    let req: [u8; 14] = [
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
    ];
    if !write_all(&mut s, &req, to).await {
        return None;
    }
    let r = read_some(&mut s, to, 512).await;
    // BindResponse: 0x30 .. 0x61 (APPLICATION 1) len 0x0a 0x01 <resultCode>
    let idx = r.windows(3).position(|w| w[0] == 0x0a && w[1] == 0x01)?;
    let code = r.get(idx + 2).copied()?;
    let mut svc = Svc::named("ldap");
    svc.banner = format!("bind result {code}");
    if code == 0 {
        svc.auth = "none".into();
        svc.findings.push(open_finding(
            "ldap",
            target,
            "medium",
            "LDAP accepts anonymous binds",
            "The directory accepted an anonymous simple bind. Depending on its ACLs that exposes \
             the directory tree - users, groups, mail addresses, and sometimes password hashes or \
             attributes used for authentication - to anyone who can reach the port. Require \
             authentication, or restrict what an anonymous bind may read."
                .to_string(),
        ));
    } else {
        svc.auth = "required".into();
    }
    Some(svc)
}

// ---------------------------------------------------------------------------
// Just enough BSON / wire protocol for the two Mongo commands above
// ---------------------------------------------------------------------------

enum BsonVal {
    I32(i32),
    Str(&'static str),
}

fn bson_doc(fields: &[(&str, BsonVal)]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    for (k, v) in fields {
        match v {
            BsonVal::I32(n) => {
                body.push(0x10);
                body.extend_from_slice(k.as_bytes());
                body.push(0);
                body.extend_from_slice(&n.to_le_bytes());
            }
            BsonVal::Str(sv) => {
                body.push(0x02);
                body.extend_from_slice(k.as_bytes());
                body.push(0);
                body.extend_from_slice(&((sv.len() + 1) as i32).to_le_bytes());
                body.extend_from_slice(sv.as_bytes());
                body.push(0);
            }
        }
    }
    body.push(0);
    let mut out = ((body.len() + 4) as i32).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

/// OP_MSG (opcode 2013): header, flag bits, one kind-0 section holding the
/// command document.
fn op_msg(doc: &[u8], request_id: i32) -> Vec<u8> {
    let len = 16 + 4 + 1 + doc.len();
    let mut out = (len as i32).to_le_bytes().to_vec();
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    out.extend_from_slice(&2013i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    out.push(0); // section kind 0
    out.extend_from_slice(doc);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_port_orders_probes_but_never_limits_them() {
        let redis_first = order_for(6379);
        assert_eq!(redis_first[0], "redis");
        // Everything else still gets a turn, so a service on an odd port is found.
        assert!(redis_first.contains(&"postgres"));
        let unknown = order_for(48211);
        assert_eq!(unknown[0], "banner");
        assert!(unknown.contains(&"redis"));
    }

    #[test]
    fn bson_lengths_are_self_consistent() {
        let d = bson_doc(&[("hello", BsonVal::I32(1)), ("$db", BsonVal::Str("admin"))]);
        let len = i32::from_le_bytes([d[0], d[1], d[2], d[3]]) as usize;
        assert_eq!(len, d.len());
        assert_eq!(*d.last().unwrap(), 0);
    }

    #[test]
    fn op_msg_header_declares_its_own_length() {
        let d = bson_doc(&[("hello", BsonVal::I32(1))]);
        let m = op_msg(&d, 7);
        let len = i32::from_le_bytes([m[0], m[1], m[2], m[3]]) as usize;
        assert_eq!(len, m.len());
        assert_eq!(i32::from_le_bytes([m[12], m[13], m[14], m[15]]), 2013);
    }

    #[test]
    fn host_and_port_split_from_the_right() {
        assert_eq!(split_host_port("10.0.0.1:6379"), ("10.0.0.1".into(), 6379));
        assert_eq!(
            split_host_port("db.internal:5432"),
            ("db.internal".into(), 5432)
        );
    }
}

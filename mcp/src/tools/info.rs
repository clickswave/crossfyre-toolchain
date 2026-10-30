//! `status`, `get_scope` and `check_scope`: questions about the server and its scope.
//! None of them sends anything to a target.

use super::{NoArgs, parse_args};
use crate::core::{Done, Mcp, Refusal};
use crate::scope_file::{EXAMPLE, ScopeState};
use crate::{guard, untrusted};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;

/// The engines this server drives.
pub(crate) const MCP_ENGINES: [&str; 2] = ["toolmark", "plessor"];

async fn listening(port: u16) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(300),
            tokio::net::TcpStream::connect(("127.0.0.1", port))
        )
        .await,
        Ok(Ok(_))
    )
}

fn env_set(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.trim().is_empty())
}

fn scope_summary(mcp: &Mcp) -> Value {
    let s = &mcp.scope;
    let changed = s.current_sha256() != s.sha256;
    json!({
        "state": s.state.as_str(),
        "path": s.path.display().to_string(),
        "sha256": s.sha256,
        "entries": s.entries,
        "allow_writes": s.allow_writes,
        "allow_private": s.allow_private,
        "changed_on_disk": changed,
    })
}

pub(crate) async fn status(mcp: &Mcp, args: &Value) -> Result<Done, Refusal> {
    let _: NoArgs = parse_args(args)?;
    let mut checks = Vec::new();
    for e in &mcp.settings.engines {
        let port = e.port;
        checks.push(tokio::spawn(listening(port)));
    }
    let pg = mcp
        .settings
        .postgres_port
        .map(|p| tokio::spawn(listening(p)));

    let mut engines = Vec::new();
    let mut hints = Vec::new();
    for (e, check) in mcp.settings.engines.iter().zip(checks) {
        let up = check.await.unwrap_or(false);
        let used = MCP_ENGINES.contains(&e.name.as_str());
        if used && !up {
            hints.push(if e.installed {
                format!(
                    "{} is not listening on 127.0.0.1:{}: run `crossfyre extension start {}`",
                    e.name, e.port, e.name
                )
            } else {
                format!(
                    "{} is not installed: run `crossfyre extension install {}`",
                    e.name, e.name
                )
            });
        }
        engines.push(json!({
            "name": e.name,
            "port": e.port,
            "installed": e.installed,
            "listening": up,
            "used_by_mcp": used,
        }));
    }
    let pg_up = match pg {
        Some(h) => h.await.unwrap_or(false),
        None => false,
    };

    let scope = scope_summary(mcp);
    if !mcp.scope.has_entries() {
        hints.push(format!(
            "no scope: traffic tools refuse until a person writes {} and the server is restarted \
             (get_scope shows an example)",
            mcp.scope.path.display()
        ));
    }
    if scope["changed_on_disk"] == json!(true) {
        hints.push(
            "the scope file changed on disk since the server started; restart the MCP server \
             to load it"
                .into(),
        );
    }
    if !mcp.audit.healthy() {
        hints.push(
            "the audit log could not be written, so traffic tools refuse; check the file and \
             restart the MCP server"
                .into(),
        );
    }
    let proxy = [
        "CROSSFYRE_EGRESS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ]
    .iter()
    .any(|v| env_set(v));
    if proxy {
        hints.push(
            "an egress proxy is set, so names are resolved by the proxy and the address check \
             is best effort"
                .into(),
        );
    }
    let recent: Vec<Value> = mcp
        .guard
        .recent(10)
        .into_iter()
        .map(|r| {
            json!({
                "at_ms": r.at_ms,
                "host": untrusted::clean(&r.host, 200),
                "port": r.port,
                "point": r.point.as_str(),
            })
        })
        .collect();
    let value = json!({
        "version": mcp.settings.version,
        "mcp_dir": mcp.dir.display().to_string(),
        "scope": scope,
        "engines": engines,
        "postgres": {"port": mcp.settings.postgres_port, "listening": pg_up},
        "daemon_token_set": env_set(dguard::TOKEN_ENV),
        "egress_proxy": proxy,
        "redaction": mcp.settings.redact,
        "limits": {
            "calls_per_minute": mcp.settings.calls_per_minute,
            "call_burst": mcp.settings.call_burst,
            "max_concurrent_scans": mcp.scope.max_concurrent_scans,
            "max_scan_starts_per_hour": mcp.scope.max_scan_starts_per_hour,
            "requests_per_second_per_host": mcp.scope.requests_per_second_per_host,
            "scan_time_limit_minutes": crate::core::SCAN_TIME_LIMIT.as_secs() / 60,
        },
        "refusals": {"total": mcp.guard.refused_total(), "recent": recent},
        "audit": {"path": mcp.audit.path().display().to_string(), "healthy": mcp.audit.healthy()},
        "hints": hints,
    });
    let summary = format!(
        "crossfyre mcp {}: scope {} ({} entries), {} hint(s).",
        mcp.settings.version,
        mcp.scope.state.as_str(),
        mcp.scope.entries.len(),
        value["hints"].as_array().map(|h| h.len()).unwrap_or(0)
    );
    Ok(Done { value, summary })
}

pub(crate) fn get_scope(mcp: &Mcp, args: &Value) -> Result<Done, Refusal> {
    let _: NoArgs = parse_args(args)?;
    let s = &mcp.scope;
    let mut value = json!({
        "state": s.state.as_str(),
        "path": s.path.display().to_string(),
        "sha256": s.sha256,
        "entries": s.entries,
        "allow_writes": s.allow_writes,
        "allow_private": s.allow_private,
        "max_concurrent_scans": s.max_concurrent_scans,
        "max_scan_starts_per_hour": s.max_scan_starts_per_hour,
        "requests_per_second_per_host": s.requests_per_second_per_host,
        "loaded_at": s.loaded_at,
    });
    if s.state != ScopeState::Loaded {
        value["how_to"] = json!(format!(
            "Traffic tools refuse until {} lists the destinations to test. Only the person \
             authorised to test them should write it, by hand, and then restart the MCP server. \
             This server never writes it. Example:\n{}",
            s.path.display(),
            EXAMPLE
        ));
    }
    let summary = format!(
        "Scope {}: {} entries from {}.",
        s.state.as_str(),
        s.entries.len(),
        s.path.display()
    );
    Ok(Done { value, summary })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckArgs {
    targets: Vec<String>,
}

/// A CIDR range, if the text is one.
fn parse_cidr(t: &str) -> Option<(IpAddr, u8)> {
    let (a, b) = t.split_once('/')?;
    let ip: IpAddr = a.trim().parse().ok()?;
    let bits: u8 = b.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((ip, bits))
}

fn range_ends(ip: IpAddr, bits: u8) -> (IpAddr, IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            let a = u32::from(v4);
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (
                IpAddr::V4((a & mask).into()),
                IpAddr::V4((a | !mask).into()),
            )
        }
        IpAddr::V6(v6) => {
            let a = u128::from(v6);
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (
                IpAddr::V6((a & mask).into()),
                IpAddr::V6((a | !mask).into()),
            )
        }
    }
}

/// The port named in a scope entry, if it names one.
fn entry_port(entry: &str) -> Option<u16> {
    let e = entry.trim();
    if let Some(rest) = e.strip_prefix('[') {
        return rest.split_once("]:")?.1.parse().ok();
    }
    if e.parse::<IpAddr>().is_ok() || e.contains('/') {
        return None;
    }
    e.rsplit_once(':')?.1.parse().ok()
}

/// `host`, `host:port` or `[v6]:port`, the way a scope entry is written.
fn parse_host_port(t: &str) -> Option<(String, Option<u16>)> {
    if t.contains('/') || t.contains('@') || t.contains(char::is_whitespace) {
        return None;
    }
    if let Some(rest) = t.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let ip: std::net::Ipv6Addr = addr.parse().ok()?;
        let port = match tail {
            "" => None,
            p => Some(p.strip_prefix(':')?.parse().ok()?),
        };
        return Some((ip.to_string(), port));
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Some((ip.to_string(), None));
    }
    match t.rsplit_once(':') {
        Some((h, p)) => Some((h.to_ascii_lowercase(), Some(p.parse().ok()?))),
        None => Some((t.to_ascii_lowercase(), None)),
    }
}

pub(crate) fn check_scope(mcp: &Mcp, args: &Value) -> Result<Done, Refusal> {
    let a: CheckArgs = parse_args(args)?;
    if a.targets.is_empty() || a.targets.len() > 100 {
        return Err(Refusal::invalid(
            "targets must hold between 1 and 100 entries",
        ));
    }
    let idx = &mcp.scope.per_entry;
    let mut results = Vec::new();
    for raw in &a.targets {
        if raw.len() > guard::MAX_URL {
            return Err(Refusal::invalid(format!(
                "a target is longer than {} bytes",
                guard::MAX_URL
            )));
        }
        let t = raw.trim();
        let input = untrusted::clean(t, 200);
        // A question, not egress: Scope::admits answers it without counting a refusal
        // against the guard.
        let (kind, host, port, rule, port_rules) = if let Some((ip, bits)) = parse_cidr(t) {
            let (first, last) = range_ends(ip, bits);
            let rule = idx
                .iter()
                .find(|(_, s)| {
                    s.admits(&first.to_string(), None) && s.admits(&last.to_string(), None)
                })
                .map(|(e, _)| e.clone());
            ("cidr", format!("{first}/{bits}"), None, rule, Vec::new())
        } else if t.contains("://") {
            match guard::parse_target(t) {
                Ok(d) => {
                    let rule = idx
                        .iter()
                        .find(|(_, s)| s.admits(&d.host, Some(d.port)))
                        .map(|(e, _)| e.clone());
                    ("url", d.host, Some(d.port), rule, Vec::new())
                }
                Err(e) => {
                    results.push(json!({
                        "input": input, "kind": "invalid", "host": null, "port": null,
                        "admitted": false, "rule": null, "port_rules": [],
                        "error": untrusted::clean(&e, 200),
                    }));
                    continue;
                }
            }
        } else {
            match parse_host_port(t) {
                Some((h, p)) => {
                    let rule = idx
                        .iter()
                        .find(|(_, s)| s.admits(&h, p))
                        .map(|(e, _)| e.clone());
                    // A bare host is checked with no port, so a host:port rule does not
                    // match it; those rules are listed so the answer is not misleading.
                    let port_rules: Vec<String> = if p.is_none() {
                        idx.iter()
                            .filter(|(e, s)| entry_port(e).is_some_and(|ep| s.admits(&h, Some(ep))))
                            .map(|(e, _)| e.clone())
                            .collect()
                    } else {
                        Vec::new()
                    };
                    (
                        if p.is_some() { "host_port" } else { "host" },
                        h,
                        p,
                        rule,
                        port_rules,
                    )
                }
                None => {
                    results.push(json!({
                        "input": input, "kind": "invalid", "host": null, "port": null,
                        "admitted": false, "rule": null, "port_rules": [],
                        "error": "not a URL, host, host:port or address range",
                    }));
                    continue;
                }
            }
        };
        results.push(json!({
            "input": input,
            "kind": kind,
            "host": untrusted::clean(&host, 200),
            "port": port,
            "admitted": rule.is_some(),
            "rule": rule,
            "port_rules": port_rules,
        }));
    }
    let admitted = results
        .iter()
        .filter(|r| r["admitted"] == json!(true))
        .count();
    let summary = format!(
        "{admitted} of {} target(s) are in the scope file (state {}). Nothing was sent.",
        results.len(),
        mcp.scope.state.as_str()
    );
    Ok(Done {
        value: json!({"scope_state": mcp.scope.state.as_str(), "results": results}),
        summary,
    })
}

//! Origin discovery: find a target's real origin IP behind a CDN/WAF.
//!
//! The highest-ROI evasion move. If we can reach the origin directly the WAF is
//! bypassed outright, and the exposure is itself a reportable finding. This is a
//! collector + validator, not a hosted browser:
//!   1. gather candidate hostnames (cert-transparency SANs + the apex + common
//!      non-proxied prefixes),
//!   2. resolve them to IPs,
//!   3. drop IPs inside known CDN/WAF ranges (Cloudflare, fetched live, plus a
//!      static fallback set),
//!   4. validate each remaining IP by requesting it directly with the target's
//!      real SNI + Host and comparing the response to the CDN-fronted baseline.
//!
//! A direct response that is byte-identical to the fronted one is a confirmed
//! origin; one that serves the same app on the same status is a likely origin.

use crate::libs::dns::create_resolver;
use ipnet::IpNet;
use serde::Deserialize;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Cap on hostnames resolved and IPs validated, so a target with thousands of
/// certs cannot turn discovery into an unbounded sweep. Excess is logged, never
/// silently dropped.
const MAX_HOSTS: usize = 600;
const MAX_CANDIDATE_IPS: usize = 120;

#[derive(Debug, Clone)]
pub struct OriginFinding {
    pub ip: IpAddr,
    /// The hostname that resolved to this IP.
    pub host: String,
    /// "confirmed" (byte-identical), "likely" (same app + status), or "reachable".
    pub confidence: &'static str,
    pub note: String,
}

#[derive(Deserialize)]
struct CrtEntry {
    name_value: String,
}

fn hash_body(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// Why origin discovery does not run with this egress, or `None` when it does.
///
/// Validating a candidate means connecting to that address and nowhere else, with
/// the target's name pinned to it. Through a proxy the proxy would look the name up
/// again and reach the CDN, so every candidate would be measured against the very
/// thing it is meant to get around. Refused rather than run from this machine's
/// own address instead.
pub fn refused(egress: &transport::Egress) -> Option<&'static str> {
    egress.is_proxied().then_some(
        "Origin discovery connects to candidate addresses directly and cannot run through \
         a proxy",
    )
}

/// A transport client for one origin probe. `resolve` pins the target host to a
/// candidate IP so the request keeps the real SNI + Host while hitting that IP.
fn client(
    evasive: bool,
    timeout_ms: u64,
    resolve: Vec<(String, SocketAddr)>,
    egress: &transport::Egress,
) -> Option<transport::Client> {
    transport::build_client(
        transport::ClientConfig {
            timeout: Some(Duration::from_millis(timeout_ms)),
            accept_invalid_certs: true,
            user_agent: Some(
                adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None).user_agent,
            ),
            emulate: evasive,
            resolve,
            ..Default::default()
        },
        egress,
    )
    .ok()
}

/// Cert-transparency SAN hostnames for the domain, via crt.sh.
async fn crt_sh_hosts(c: &transport::Client, domain: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    if let Ok(resp) = c.get(&url).send().await
        && let Ok(entries) = resp.json::<Vec<CrtEntry>>().await
    {
        let dot = format!(".{domain}");
        for e in entries {
            for raw in e.name_value.split(['\n', '\r']) {
                let h = raw.trim().trim_start_matches("*.").to_lowercase();
                if !h.is_empty() && (h == domain || h.ends_with(&dot)) {
                    out.insert(h);
                }
            }
        }
    }
    out
}

/// Cloudflare's published ranges (fetched live) plus a static fallback set, so we
/// skip IPs that are just another edge rather than the origin.
async fn cdn_ranges(c: &transport::Client) -> Vec<IpNet> {
    let mut nets: Vec<IpNet> = Vec::new();
    for url in [
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ] {
        if let Ok(resp) = c.get(url).send().await
            && let Ok(txt) = resp.text().await
        {
            for line in txt.lines() {
                if let Ok(n) = line.trim().parse::<IpNet>() {
                    nets.push(n);
                }
            }
        }
    }
    for s in STATIC_CDN_CIDRS {
        if let Ok(n) = s.parse::<IpNet>() {
            nets.push(n);
        }
    }
    nets
}

/// Cloudflare ranges as a hard fallback when the live fetch is blocked, so a
/// broken fetch never causes us to treat edge IPs as origins.
const STATIC_CDN_CIDRS: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Fetch `https://{domain}/` through `c` and return a (status, body-hash, len)
/// marker for comparison.
async fn fetch_marker(c: &transport::Client, domain: &str) -> Option<(u16, u64, usize)> {
    let resp = c.get(format!("https://{domain}/")).send().await.ok()?;
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.ok()?;
    Some((status, hash_body(bytes.as_ref()), bytes.len()))
}

/// Run origin discovery for `domain`. `log` receives progress lines; the return
/// value is the confirmed / likely / reachable origins, most-confident first.
pub async fn discover(
    domain: &str,
    timeout_ms: u64,
    evasive: bool,
    egress: &transport::Egress,
    log: &(dyn Fn(String) + Send + Sync),
) -> Vec<OriginFinding> {
    if let Some(why) = refused(egress) {
        log(why.to_string());
        return vec![];
    }
    let domain = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_lowercase();
    let tmo = timeout_ms.max(8000);
    let base = match client(evasive, tmo, vec![], egress) {
        Some(c) => c,
        None => return vec![],
    };

    // 1. Candidate hostnames: cert SANs + apex + common non-proxied prefixes.
    let mut hosts: HashSet<String> = crt_sh_hosts(&base, &domain).await;
    hosts.insert(domain.clone());
    for p in [
        "www",
        "mail",
        "direct",
        "origin",
        "origin-www",
        "dev",
        "staging",
        "test",
        "cpanel",
        "ftp",
        "webmail",
        "admin",
        "api",
        "vpn",
        "remote",
        "server",
        "host",
        "portal",
    ] {
        hosts.insert(format!("{p}.{domain}"));
    }
    let mut hosts: Vec<String> = hosts.into_iter().collect();
    if hosts.len() > MAX_HOSTS {
        log(format!(
            "capping candidate hostnames {} -> {} (rest skipped)",
            hosts.len(),
            MAX_HOSTS
        ));
        hosts.truncate(MAX_HOSTS);
    }
    log(format!("candidate hostnames: {}", hosts.len()));

    // 2. Resolve to IPs. Use an explicit public resolver rather than the host's
    // resolv.conf so discovery behaves identically on any node image.
    let resolver = match create_resolver(Some("1.1.1.1")) {
        Ok(r) => r,
        Err(e) => {
            log(format!("resolver init failed: {e}"));
            return vec![];
        }
    };
    let mut ip_hosts: Vec<(IpAddr, String)> = Vec::new();
    for h in &hosts {
        if let Ok(lookup) = resolver.lookup_ip(h.as_str()).await {
            for ip in lookup.iter() {
                ip_hosts.push((ip, h.clone()));
            }
        }
    }
    // Fallback: if public-resolver DNS returned nothing at all (raw DNS blocked,
    // e.g. an egress that only allows 443), resolve via the OS resolver instead so
    // discovery still works wherever the HTTP client can reach the network.
    if ip_hosts.is_empty() {
        log("public DNS returned nothing; falling back to the OS resolver".to_string());
        for h in &hosts {
            if let Ok(addrs) = tokio::net::lookup_host(format!("{h}:443")).await {
                for a in addrs {
                    ip_hosts.push((a.ip(), h.clone()));
                }
            }
        }
    }

    // 3. Exclude CDN/WAF ranges, dedupe by IP.
    let cdn = cdn_ranges(&base).await;
    let mut seen = HashSet::new();
    let mut candidates: Vec<(IpAddr, String)> = ip_hosts
        .into_iter()
        .filter(|(ip, _)| !cdn.iter().any(|n| n.contains(ip)) && seen.insert(*ip))
        .collect();
    if candidates.len() > MAX_CANDIDATE_IPS {
        log(format!(
            "capping candidate IPs {} -> {} (rest skipped)",
            candidates.len(),
            MAX_CANDIDATE_IPS
        ));
        candidates.truncate(MAX_CANDIDATE_IPS);
    }
    log(format!("non-CDN candidate IPs: {}", candidates.len()));

    // 4. Baseline: the CDN-fronted response for the apex.
    let baseline = fetch_marker(&base, &domain).await;

    // 5. Validate each candidate directly, keeping real SNI + Host.
    let mut findings: Vec<OriginFinding> = Vec::new();
    for (ip, host) in candidates {
        let c = match client(
            evasive,
            tmo,
            vec![(domain.clone(), SocketAddr::new(ip, 443))],
            egress,
        ) {
            Some(c) => c,
            None => continue,
        };
        let Some((status, hash, len)) = fetch_marker(&c, &domain).await else {
            continue;
        };
        let (confidence, note) = match &baseline {
            Some((_, bh, _)) if *bh == hash && hash != 0 => (
                "confirmed",
                format!("direct response byte-identical to the fronted site (HTTP {status})"),
            ),
            Some((bs, _, _)) if *bs == status && status < 400 => (
                "likely",
                format!("serves the app directly (HTTP {status}, {len} bytes)"),
            ),
            _ if status < 400 => (
                "reachable",
                format!("responds directly (HTTP {status}, {len} bytes)"),
            ),
            _ => continue,
        };
        log(format!("[{confidence}] {ip} via {host} - {note}"));
        findings.push(OriginFinding {
            ip,
            host,
            confidence,
            note,
        });
    }

    // Most confident first.
    let rank = |c: &str| match c {
        "confirmed" => 0,
        "likely" => 1,
        _ => 2,
    };
    findings.sort_by_key(|f| rank(f.confidence));
    findings
}

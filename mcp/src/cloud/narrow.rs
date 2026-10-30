//! The scope file as a fence on Cloud launches.
//!
//! When the file has entries, a Cloud launch must be admitted by it as well as by the
//! scope the key's owner confirmed on the platform, judged the way the platform judges
//! that scope: a URL by its host and port, a host or address for a port scan by an
//! entry that covers every port on it, a range by one entry that contains all of it,
//! and a recon domain by an entry for the domain (passive) or a `*.` entry over it
//! (active). It can only take away from what the platform would allow. Nothing is
//! looked up here: the workspace's nodes resolve the names, not this machine.

use crate::guard;
use cfx_cloud_wire::{LaunchType, TargetKind};
use cfx_scope::Scope;
use std::net::IpAddr;

/// One target as the scope file sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub kind: TargetKind,
    /// The host, address or range the entry has to cover, when the target parsed.
    pub host: Option<String>,
    pub port: Option<u16>,
    /// The entry that admits it.
    pub entry: Option<String>,
    /// Why it could not be read as this kind of target.
    pub error: Option<String>,
}

impl Verdict {
    pub(crate) fn admitted(&self) -> bool {
        self.entry.is_some()
    }

    fn bad(kind: TargetKind, why: impl Into<String>) -> Self {
        Verdict {
            kind,
            host: None,
            port: None,
            entry: None,
            error: Some(why.into()),
        }
    }
}

pub(crate) fn kind_str(k: TargetKind) -> &'static str {
    match k {
        TargetKind::Url => "url",
        TargetKind::Host => "host",
        TargetKind::Range => "range",
        TargetKind::Zone => "zone",
    }
}

/// How a target is read when nothing says: a URL, a range, or else a host.
pub(crate) fn kind_of(raw: &str) -> TargetKind {
    let t = raw.trim();
    if t.contains("://") {
        TargetKind::Url
    } else if t.contains('/') {
        TargetKind::Range
    } else {
        TargetKind::Host
    }
}

/// How a launch of this type reads one of its targets.
pub(crate) fn launch_kind(t: LaunchType, raw: &str) -> TargetKind {
    match t {
        LaunchType::PortScan if raw.contains('/') => TargetKind::Range,
        other => other.target_kind(),
    }
}

fn parse_range(t: &str) -> Option<(IpAddr, u8)> {
    let (a, b) = t.split_once('/')?;
    let ip: IpAddr = a.trim().parse().ok()?;
    let bits: u8 = b.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((ip, bits))
}

/// A bare host or address: no scheme, no path, no port.
fn parse_host(t: &str) -> Option<String> {
    if t.is_empty() || t.contains(['/', '@', '?', '#']) || t.contains(char::is_whitespace) {
        return None;
    }
    if let Some(inner) = t.strip_prefix('[') {
        let ip: std::net::Ipv6Addr = inner.strip_suffix(']')?.parse().ok()?;
        return Some(ip.to_string());
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    if t.contains(':') {
        return None;
    }
    Some(t.trim_end_matches('.').to_ascii_lowercase())
}

/// Judge one target of `kind` against the scope file's entries. `active` matters only
/// for a zone.
pub(crate) fn judge(scope: &Scope, kind: TargetKind, raw: &str, active: bool) -> Verdict {
    let t = raw.trim();
    if t.len() > guard::MAX_URL {
        return Verdict::bad(kind, format!("longer than {} bytes", guard::MAX_URL));
    }
    match kind {
        TargetKind::Url => {
            if !t.contains("://") {
                return Verdict::bad(kind, "not a URL: give it as https://host/");
            }
            match guard::parse_target(t) {
                Ok(d) => Verdict {
                    kind,
                    entry: scope.matching(&d.host, Some(d.port)),
                    host: Some(d.host),
                    port: Some(d.port),
                    error: None,
                },
                Err(e) => Verdict::bad(kind, e),
            }
        }
        TargetKind::Host => match parse_host(t) {
            Some(h) => Verdict {
                kind,
                entry: scope.matching(&h, None),
                host: Some(h),
                port: None,
                error: None,
            },
            None => Verdict::bad(
                kind,
                "not a host or address (a port scan's ports go in ports, not the target)",
            ),
        },
        TargetKind::Range => match parse_range(t) {
            Some((ip, bits)) => Verdict {
                kind,
                entry: scope.matching_range(ip, bits),
                host: Some(format!("{ip}/{bits}")),
                port: None,
                error: None,
            },
            None => Verdict::bad(kind, "not an address range such as 10.0.0.0/24"),
        },
        TargetKind::Zone => match parse_host(t) {
            Some(d) if d.parse::<IpAddr>().is_err() => Verdict {
                kind,
                entry: scope.matching_zone(&d, active),
                host: Some(d),
                port: None,
                error: None,
            },
            _ => Verdict::bad(kind, "not a domain name"),
        },
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    fn scope(entries: &[&str]) -> Scope {
        let list: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
        let (s, bad) = cfx_scope::parse(&list);
        assert!(bad.is_empty(), "{bad:?}");
        s
    }

    #[test]
    fn each_kind_is_judged_as_the_platform_judges_it() {
        let s = scope(&[
            "app.example.com",
            "api.example.com:8443",
            "*.staging.example.com",
            "10.20.0.0/24",
            "example.org",
        ]);
        let ok = |k, t: &str, active| judge(&s, k, t, active).admitted();
        assert!(ok(TargetKind::Url, "https://app.example.com/login", false));
        assert!(ok(TargetKind::Url, "https://api.example.com:8443/", false));
        assert!(!ok(TargetKind::Url, "https://api.example.com/", false));
        assert!(!ok(TargetKind::Url, "app.example.com", false));
        // A port scan needs an entry for every port: host:port is not one.
        assert!(ok(TargetKind::Host, "app.example.com", false));
        assert!(!ok(TargetKind::Host, "api.example.com", false));
        assert!(!ok(TargetKind::Host, "api.example.com:8443", false));
        assert!(ok(TargetKind::Host, "10.20.0.7", false));
        assert!(ok(TargetKind::Range, "10.20.0.0/25", false));
        assert!(!ok(TargetKind::Range, "10.20.0.0/23", false));
        // Passive recon needs the domain; active needs a *. entry over it.
        assert!(ok(TargetKind::Zone, "example.org", false));
        assert!(!ok(TargetKind::Zone, "example.org", true));
        assert!(ok(TargetKind::Zone, "staging.example.com", true));
        assert!(!ok(TargetKind::Zone, "evil-staging.example.com", true));
        assert!(!ok(TargetKind::Zone, "10.20.0.1", false));
    }

    #[test]
    fn a_launch_reads_its_targets_by_type() {
        assert_eq!(
            launch_kind(LaunchType::PortScan, "10.0.0.0/24"),
            TargetKind::Range
        );
        assert_eq!(
            launch_kind(LaunchType::PortScan, "app.example.com"),
            TargetKind::Host
        );
        assert_eq!(
            launch_kind(LaunchType::Recon, "example.com"),
            TargetKind::Zone
        );
        assert_eq!(
            launch_kind(LaunchType::VulnScan, "https://a.example/"),
            TargetKind::Url
        );
        assert_eq!(kind_of("https://a.example/"), TargetKind::Url);
        assert_eq!(kind_of("10.0.0.0/8"), TargetKind::Range);
        assert_eq!(kind_of("a.example:443"), TargetKind::Host);
    }
}

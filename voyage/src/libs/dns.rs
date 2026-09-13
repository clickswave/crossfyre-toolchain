use hickory_resolver::{Resolver, TokioResolver};

/// Build a DNS resolver. With `dns_server = Some("1.1.1.1")` (a non-empty IP) it
/// queries that server explicitly; otherwise it falls back to the node host's
/// own resolver config (its default nameservers).
///
/// hickory-resolver 0.26 reshaped this API: `NameServerConfigGroup` is gone in
/// favour of building `NameServerConfig` values directly, and the Tokio
/// connection provider moved to `net::runtime::TokioRuntimeProvider`. The bump
/// was needed for two advisories that matter here, because this resolver parses
/// DNS responses from scan targets we do not control:
///   RUSTSEC-2026-0118  unbounded loop in NSEC3 closest-encloser validation
///   RUSTSEC-2026-0119  O(n^2) CPU exhaustion in message encoding
/// `ip` or `ip:port`. A resolver on a non-standard port is normal on a split
/// horizon, an internal lab, or anywhere the interesting zone is not served by
/// the box's default nameserver, and refusing the port made those zones
/// unreachable rather than merely awkward.
fn parse_server(spec: &str) -> Result<(std::net::IpAddr, u16), String> {
    let spec = spec.trim();
    if let Ok(sa) = spec.parse::<std::net::SocketAddr>() {
        return Ok((sa.ip(), sa.port()));
    }
    if let Ok(ip) = spec.parse::<std::net::IpAddr>() {
        return Ok((ip, 53));
    }
    // ipv4:port, which does not parse as a SocketAddr when the port is absent
    // above but does have a single colon here.
    if let Some((host, port)) = spec.rsplit_once(':')
        && let (Ok(ip), Ok(port)) = (host.parse::<std::net::IpAddr>(), port.parse::<u16>())
    {
        return Ok((ip, port));
    }
    Err(format!(
        "invalid DNS server '{spec}' (expected ip or ip:port)"
    ))
}

pub fn create_resolver(
    dns_server: Option<&str>,
) -> Result<TokioResolver, Box<dyn std::error::Error>> {
    match dns_server {
        Some(spec) if !spec.trim().is_empty() => {
            let (addr, port) = parse_server(spec)?;
            // udp_and_tcp keeps the previous behaviour: UDP first, TCP fallback
            // for responses that do not fit.
            let mut ns = hickory_resolver::config::NameServerConfig::udp_and_tcp(addr);
            for c in ns.connections.iter_mut() {
                c.port = port;
            }
            let cfg = hickory_resolver::config::ResolverConfig::from_parts(None, vec![], vec![ns]);
            // 0.26: `build()` is fallible (it can fail to set up transports).
            Ok(Resolver::builder_with_config(
                cfg,
                hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
            )
            .build()?)
        }
        _ => Ok(Resolver::builder_tokio()?.build()?),
    }
}

/// The address a zone transfer should be attempted against.
pub fn server_addr(spec: &str) -> Option<std::net::SocketAddr> {
    parse_server(spec).ok().map(|(ip, p)| (ip, p).into())
}

#[cfg(test)]
mod tests {
    use super::parse_server;

    #[test]
    fn a_bare_ip_means_port_53() {
        assert_eq!(parse_server("1.1.1.1").unwrap().1, 53);
    }

    #[test]
    fn an_explicit_port_is_kept() {
        let (ip, port) = parse_server("127.0.0.1:5353").unwrap();
        assert_eq!(port, 5353);
        assert_eq!(ip.to_string(), "127.0.0.1");
        assert_eq!(parse_server("[::1]:5353").unwrap().1, 5353);
    }

    #[test]
    fn nonsense_is_an_error_not_a_silent_default() {
        assert!(parse_server("not-a-server").is_err());
    }
}

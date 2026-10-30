//! Turning what a model typed into a destination, and deciding which addresses of it
//! may be dialled.
//!
//! The host and port always come from the parsed URL, never from the string. The
//! WHATWG parser the engines' client uses reads `0x7f.1` and `2130706433` as
//! `127.0.0.1`, so a check on the raw text and a connection to the parsed form would
//! be two different destinations. Here both are the parsed form.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

pub(crate) type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Longest URL accepted anywhere. Matches the engines' own target limit.
pub(crate) const MAX_URL: usize = 2048;

/// One place traffic would go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dest {
    pub scheme: String,
    /// Bare host: a lowercase name, or an address without brackets.
    pub host: String,
    pub port: u16,
    /// Set when the host is an address literal.
    pub ip: Option<IpAddr>,
    /// The normalised URL, as the engines will see it.
    pub url: String,
}

impl Dest {
    pub(crate) fn key(&self) -> String {
        match self.ip {
            Some(IpAddr::V6(_)) => format!("[{}]:{}", self.host, self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
    }

    pub(crate) fn origin(&self) -> String {
        match self.ip {
            Some(IpAddr::V6(_)) => format!("{}://[{}]:{}", self.scheme, self.host, self.port),
            _ => format!("{}://{}:{}", self.scheme, self.host, self.port),
        }
    }
}

/// A URL, or a bare `host[:port]` with the scheme inferred the way toolmark and
/// plessor infer it.
pub(crate) fn parse_target(raw: &str) -> Result<Dest, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("the target is empty".into());
    }
    if t.len() > MAX_URL {
        return Err(format!("the target is longer than {MAX_URL} bytes"));
    }
    let lower = t.to_ascii_lowercase();
    let url = if lower.starts_with("http://") || lower.starts_with("https://") {
        transport::Url::parse(t).map_err(|e| format!("not a valid URL: {e}"))?
    } else if t.contains("://") {
        return Err("only http and https URLs are accepted".into());
    } else {
        let n = transport::url::normalize_target(t).ok_or("not a host, host:port or URL")?;
        transport::Url::parse(&n.url).map_err(|e| format!("not a valid URL: {e}"))?
    };
    dest_from_url(&url)
}

pub(crate) fn dest_from_url(url: &transport::Url) -> Result<Dest, String> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("only http and https URLs are accepted".into());
    }
    // `user@host` reads as one destination to a person and as another to a parser,
    // which is the whole trick, so it is refused rather than interpreted.
    if !url.username().is_empty() || url.password().is_some() {
        return Err("a URL with a user name or password in it is not accepted".into());
    }
    if url.as_str().len() > MAX_URL {
        return Err(format!("the URL is longer than {MAX_URL} bytes"));
    }
    let host_str = url.host_str().ok_or("the URL has no host")?;
    let (host, ip) =
        if let Some(inner) = host_str.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            let v6: Ipv6Addr = inner.parse().map_err(|_| "not a valid IPv6 address")?;
            (v6.to_string(), Some(IpAddr::V6(v6)))
        } else if let Ok(v4) = host_str.parse::<Ipv4Addr>() {
            (v4.to_string(), Some(IpAddr::V4(v4)))
        } else {
            (host_str.to_ascii_lowercase(), None)
        };
    let port = url
        .port_or_known_default()
        .ok_or("the URL has no port and its scheme has no default")?;
    Ok(Dest {
        scheme: scheme.to_string(),
        host,
        port,
        ip,
        url: url.to_string(),
    })
}

/// Name lookup, injectable so the tests can say what a name resolves to without DNS.
pub(crate) trait Resolver: Send + Sync {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFut<'a, std::io::Result<Vec<IpAddr>>>;
}

pub(crate) struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFut<'a, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let mut out: Vec<IpAddr> = Vec::new();
            for a in tokio::net::lookup_host((host, 0)).await? {
                if !out.contains(&a.ip()) {
                    out.push(a.ip());
                }
            }
            Ok(out)
        })
    }
}

/// Cloud instance metadata. Refused even with `allow_private`, because reaching one
/// through a name is how a scan of a web app turns into credentials for the account
/// it runs in. Listing the address explicitly still works.
pub(crate) fn is_metadata(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            *v4 == Ipv4Addr::new(169, 254, 169, 254) || *v4 == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(v6) => {
            *v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|m| is_metadata(&IpAddr::V4(m)))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddrRefusal {
    Private,
    Metadata,
    Unresolvable(String),
}

/// The addresses of `dest` that may be dialled.
///
/// An address the scope lists, as itself or inside a listed range, is always kept:
/// an explicit address entry is its own permission. Otherwise metadata addresses are
/// dropped, and private, loopback and link-local ones are dropped unless the file
/// sets `allow_private`. A name with a public and a private address keeps the public
/// one, so the connection is pinned to something the person could have meant.
pub(crate) async fn resolve_checked(
    resolver: &dyn Resolver,
    dest: &Dest,
    scope: &cfx_scope::Scope,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, AddrRefusal> {
    let ips = match dest.ip {
        Some(ip) => vec![ip],
        None => resolver
            .lookup(&dest.host)
            .await
            .map_err(|e| AddrRefusal::Unresolvable(e.to_string()))?,
    };
    if ips.is_empty() {
        return Err(AddrRefusal::Unresolvable("no addresses".into()));
    }
    let mut kept = Vec::new();
    let mut metadata = false;
    for ip in ips {
        let listed = scope.admits(&ip.to_string(), Some(dest.port));
        if listed {
            kept.push(ip);
        } else if is_metadata(&ip) {
            metadata = true;
        } else if transport::guard::is_internal(&ip) && !allow_private {
            continue;
        } else {
            kept.push(ip);
        }
    }
    if kept.is_empty() {
        return Err(if metadata {
            AddrRefusal::Metadata
        } else {
            AddrRefusal::Private
        });
    }
    Ok(kept
        .into_iter()
        .map(|ip| SocketAddr::new(ip, dest.port))
        .collect())
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn host_and_port_come_from_the_parsed_url() {
        let d = parse_target("http://0x7f.1:8080/x").unwrap();
        assert_eq!((d.host.as_str(), d.port), ("127.0.0.1", 8080));
        assert_eq!(d.ip, Some("127.0.0.1".parse().unwrap()));
        let d = parse_target("http://2130706433/").unwrap();
        assert_eq!(d.host, "127.0.0.1");
        let d = parse_target("HTTPS://App.Example.TEST").unwrap();
        assert_eq!((d.host.as_str(), d.port), ("app.example.test", 443));
    }

    #[test]
    fn bare_targets_infer_like_the_engines() {
        let d = parse_target("api.example.test:8443").unwrap();
        assert_eq!((d.scheme.as_str(), d.port), ("https", 8443));
        let d = parse_target("api.example.test").unwrap();
        assert_eq!((d.scheme.as_str(), d.port), ("http", 80));
        let d = parse_target("[fd00::1]:8080").unwrap();
        assert_eq!((d.host.as_str(), d.port), ("fd00::1", 8080));
        assert_eq!(d.key(), "[fd00::1]:8080");
    }

    #[test]
    fn userinfo_other_schemes_zone_ids_and_long_urls_are_refused() {
        assert!(parse_target("http://in.test@evil.test/").is_err());
        assert!(parse_target("in.test@evil.test").is_err());
        assert!(parse_target("http://a:b@evil.test/").is_err());
        assert!(parse_target("ftp://a.test/").is_err());
        assert!(parse_target("file:///etc/passwd").is_err());
        assert!(parse_target("http://[fe80::1%25eth0]/").is_err());
        assert!(parse_target(&format!("http://a.test/{}", "a".repeat(2100))).is_err());
    }

    #[test]
    fn metadata_addresses() {
        for a in [
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_metadata(&a.parse().unwrap()), "{a}");
        }
        assert!(!is_metadata(&"169.254.1.1".parse().unwrap()));
    }
}

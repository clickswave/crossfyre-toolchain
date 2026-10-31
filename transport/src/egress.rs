//! Where a client's connections go.
//!
//! Every client [`build_client`](crate::build_client) makes and every connection
//! [`dial`] opens names an [`Egress`]. It is an argument with no default, so a call
//! site cannot leave it out. A flag with a default is how `block_internal` was once
//! dropped at every plessor call site but one.
//!
//! ## Failing closed
//!
//! A proxy that was asked for and cannot be used is an error, never a quiet fall
//! back to sending from this machine's own address. A `CROSSFYRE_EGRESS_PROXY`
//! value that does not parse is such an error. So is a client the proxy would
//! undermine: one that pins names to addresses, or refuses private addresses,
//! cannot send through a proxy, because the proxy looks the name up itself and
//! neither check would ever be asked. Both HTTP backends speak SOCKS, so a SOCKS
//! URL is used, not ignored.
//!
//! ## Names go to the proxy
//!
//! A destination name is always handed to the proxy unresolved. `socks5://` is sent
//! as `socks5h://` and `socks4://` as `socks4a://`, so no backend resolves a name
//! locally behind the private-address filter's back, and a proxy with its own view
//! of DNS gets the answer it would give.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use cfx_tunnel::{Host, Target, Timeouts, Upstream};
use tokio::net::TcpStream;

pub use cfx_tunnel::{Io, Tunnel, TunnelError};

use crate::guard;

/// The variable an engine run on its own reads its proxy from, under
/// [`Egress::Inherit`].
pub const EGRESS_PROXY_VAR: &str = "CROSSFYRE_EGRESS_PROXY";

/// The version of [`EgressWire`] this build reads.
pub const WIRE_VERSION: u32 = 1;

/// Where a client's connections go.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Egress {
    /// No instruction from a node, as when an engine runs on its own or an older node
    /// sends the op. `CROSSFYRE_EGRESS_PROXY` is used when it is set. Otherwise the
    /// client goes direct, or through `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` when
    /// one is set and the client neither pins names nor refuses private addresses.
    #[default]
    Inherit,
    /// Direct, whatever the environment says.
    Direct,
    /// Through this proxy URL. From a node it is always the node's own gateway on
    /// loopback.
    Proxy(String),
}

/// The proxy is shown by its label, never by the URL, which may hold credentials.
impl fmt::Debug for Egress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Egress::Inherit => f.write_str("Inherit"),
            Egress::Direct => f.write_str("Direct"),
            Egress::Proxy(url) => match Upstream::parse(url) {
                Ok(up) => write!(f, "Proxy({})", up.label()),
                Err(_) => f.write_str("Proxy(<not a usable proxy URL>)"),
            },
        }
    }
}

/// The `egress` object a node puts on an engine request.
///
/// Unknown fields are refused rather than ignored: an engine that does not
/// understand an instruction about where its traffic goes must not send any.
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressWire {
    pub v: u32,
    /// A proxy URL, or `null` for direct.
    #[serde(default)]
    pub proxy: Option<String>,
}

impl Egress {
    /// The egress a node's request asks for. An unknown version or an unusable proxy
    /// URL is an error, and the op is refused with it.
    pub fn from_wire(w: &EgressWire) -> Result<Egress, String> {
        if w.v != WIRE_VERSION {
            return Err(format!(
                "egress version {} is not one this engine reads (it reads {WIRE_VERSION})",
                w.v
            ));
        }
        match &w.proxy {
            None => Ok(Egress::Direct),
            Some(url) => {
                Upstream::parse(url).map_err(|e| format!("the egress proxy is not usable: {e}"))?;
                Ok(Egress::Proxy(url.clone()))
            }
        }
    }

    /// Whether connections go through a proxy: [`Egress::Proxy`], or
    /// [`Egress::Inherit`] with `CROSSFYRE_EGRESS_PROXY` set.
    pub fn is_proxied(&self) -> bool {
        match self {
            Egress::Direct => false,
            Egress::Proxy(_) => true,
            // A value that cannot be read is still a proxy someone asked for.
            Egress::Inherit => !matches!(env_value(), Ok(None)),
        }
    }
}

/// Why a client could not be built.
#[derive(Debug)]
pub enum BuildError {
    /// The HTTP backend refused the configuration.
    Backend(crate::Error),
    /// The egress cannot be used for this client. The message says why and never
    /// quotes a proxy URL.
    Egress(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Backend(e) => e.fmt(f),
            BuildError::Egress(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BuildError::Backend(e) => Some(e),
            BuildError::Egress(_) => None,
        }
    }
}

impl From<crate::Error> for BuildError {
    fn from(e: crate::Error) -> BuildError {
        BuildError::Backend(e)
    }
}

/// What a client's egress comes to once the environment has been read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// The HTTP backend's default, which reads `HTTP_PROXY`, `HTTPS_PROXY` and
    /// `ALL_PROXY`. A raw [`dial`] reads none of them, so it goes direct.
    System,
    /// No proxy at all.
    Direct,
    /// Through this proxy. `url` is what the HTTP backends are given, with a scheme
    /// that sends names to the proxy unresolved.
    Proxy { url: String, upstream: Upstream },
}

/// What a client checks about the addresses it connects to.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Checks {
    /// Private and reserved addresses are refused.
    pub block_internal: bool,
    /// Names are pinned to addresses the caller chose.
    pub pinned: bool,
}

/// The route for `egress`, reading `CROSSFYRE_EGRESS_PROXY` only for
/// [`Egress::Inherit`].
pub(crate) fn route(egress: &Egress, checks: Checks) -> Result<Route, String> {
    match egress {
        Egress::Direct => Ok(Route::Direct),
        Egress::Proxy(url) => {
            if checks.pinned {
                return Err(
                    "a pinned address cannot be honoured through a proxy, which \
                            looks the name up itself"
                        .into(),
                );
            }
            // The private-address filter is the proxy's to apply here: a node's
            // gateway resolves and vets each name for an op that asks for it.
            proxy_route(url).map_err(|e| format!("the egress proxy is not usable: {e}"))
        }
        Egress::Inherit => inherit_route(env_value()?.as_deref(), checks),
    }
}

/// [`route`] for [`Egress::Inherit`], given the value of `CROSSFYRE_EGRESS_PROXY`
/// (`None` when it is unset or blank).
pub(crate) fn inherit_route(env: Option<&str>, checks: Checks) -> Result<Route, String> {
    let Some(value) = env else {
        // A proxy from HTTP_PROXY and the like would look names up where neither
        // check can see them, so a client with either check uses none.
        return Ok(if checks.block_internal || checks.pinned {
            Route::Direct
        } else {
            Route::System
        });
    };
    let route = proxy_route(value)
        .map_err(|e| format!("{EGRESS_PROXY_VAR} is not a usable proxy URL: {e}"))?;
    if checks.block_internal {
        return Err(format!(
            "{EGRESS_PROXY_VAR} is set, and private addresses cannot be refused through a \
             proxy, which looks names up itself"
        ));
    }
    if checks.pinned {
        return Err(format!(
            "{EGRESS_PROXY_VAR} is set, and a pinned address cannot be honoured through a \
             proxy, which looks the name up itself"
        ));
    }
    Ok(route)
}

/// `CROSSFYRE_EGRESS_PROXY`, trimmed, or `None` when it is unset or blank. A value
/// that is not UTF-8 is an error rather than unset.
fn env_value() -> Result<Option<String>, String> {
    match std::env::var(EGRESS_PROXY_VAR) {
        Ok(v) => {
            let v = v.trim();
            Ok((!v.is_empty()).then(|| v.to_string()))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{EGRESS_PROXY_VAR} is not a usable proxy URL: it is not UTF-8"
        )),
    }
}

fn proxy_route(url: &str) -> Result<Route, String> {
    let upstream = Upstream::parse(url)?;
    Ok(Route::Proxy {
        url: remote_dns(url),
        upstream,
    })
}

/// `url` with a scheme that hands destination names to the proxy unresolved.
/// [`Upstream::parse`] has already accepted it, so it has a known scheme.
fn remote_dns(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "socks5" | "socks5h" => "socks5h".to_string(),
        "socks4" | "socks4a" => "socks4a".to_string(),
        other => other.to_string(),
    };
    format!("{scheme}://{rest}")
}

/// Open a TCP connection to `host:port` the way `egress` says.
///
/// - Direct (and [`Egress::Inherit`] without `CROSSFYRE_EGRESS_PROXY`): connects to
///   `pin` when it is given, otherwise to `host`. `HTTP_PROXY` and the like are not
///   read, as no raw connection ever read them. With `block_internal`, a private or
///   reserved address is refused, whether it is `host` itself, the pin, or every
///   address `host` resolves to; addresses that pass are the only ones dialled.
/// - Through a proxy: `host` goes to the proxy as given, a name unresolved. A pin is
///   an error, since the proxy would look the name up again. With
///   `block_internal`, an address literal in a private range is refused here, and
///   names are left to the proxy, which on a node is the gateway that vets them.
///   Under `Inherit`, `block_internal` with `CROSSFYRE_EGRESS_PROXY` set is an error,
///   as it is for an HTTP client.
///
/// `pin` must be on `port`; one on another port is refused without dialling, since
/// it would reach a service nobody looked at. `timeout` bounds the whole of it,
/// including a proxy's handshake.
///
/// A proxy's failure comes back with its [`TunnelError`] inside the `io::Error`.
pub async fn dial(
    egress: &Egress,
    host: &str,
    port: u16,
    block_internal: bool,
    timeout: Duration,
    pin: Option<SocketAddr>,
) -> io::Result<Tunnel> {
    let route = route(
        egress,
        Checks {
            block_internal,
            pinned: pin.is_some(),
        },
    )
    .map_err(|m| io::Error::new(io::ErrorKind::InvalidInput, m))?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the destination port is 0",
        ));
    }
    if let Some(addr) = pin
        && addr.port() != port
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the address {addr} given for {host} is not on port {port}"),
        ));
    }
    let target = Target::new(host, port);
    if block_internal {
        let literal = match &target.host {
            Host::Ip(ip) => Some(*ip),
            Host::Name(_) => None,
        };
        if literal
            .into_iter()
            .chain(pin.map(|a| a.ip()))
            .any(|ip| guard::is_internal(&ip))
        {
            return Err(not_permitted());
        }
    }

    let open = async {
        match route {
            Route::Proxy { upstream, .. } => {
                let t = Timeouts {
                    connect: timeout,
                    handshake: timeout,
                };
                cfx_tunnel::connect(&upstream, &target, t)
                    .await
                    .map_err(tunnel_error)
            }
            Route::Direct | Route::System => direct(&target, block_internal, pin).await,
        }
    };
    match tokio::time::timeout(timeout, open).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("no connection within {} ms", timeout.as_millis()),
        )),
    }
}

async fn direct(
    target: &Target,
    block_internal: bool,
    pin: Option<SocketAddr>,
) -> io::Result<Tunnel> {
    let port = target.port;
    let stream = match (pin, &target.host) {
        (Some(addr), _) => TcpStream::connect(addr).await?,
        (None, Host::Ip(ip)) => TcpStream::connect((*ip, port)).await?,
        (None, Host::Name(name)) if block_internal => {
            let addrs: Vec<SocketAddr> = guard::resolve_public(name)
                .await?
                .into_iter()
                .map(|a| SocketAddr::new(a.ip(), port))
                .collect();
            TcpStream::connect(&addrs[..]).await?
        }
        (None, Host::Name(name)) => TcpStream::connect((name.as_str(), port)).await?,
    };
    Ok(Box::new(stream))
}

fn not_permitted() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, guard::NOT_PERMITTED)
}

/// A proxy's failure as an `io::Error` of the nearest kind, with the
/// [`TunnelError`] inside for a caller that wants the detail.
fn tunnel_error(e: TunnelError) -> io::Error {
    let kind = match &e {
        TunnelError::Invalid(_) => io::ErrorKind::InvalidInput,
        TunnelError::Connect(_) | TunnelError::Refused(_) => io::ErrorKind::ConnectionRefused,
        TunnelError::Auth => io::ErrorKind::PermissionDenied,
        TunnelError::Protocol(_) => io::ErrorKind::InvalidData,
        TunnelError::Timeout => io::ErrorKind::TimedOut,
        TunnelError::Http(_) => io::ErrorKind::Other,
    };
    io::Error::new(kind, e)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUARDED: Checks = Checks {
        block_internal: true,
        pinned: false,
    };
    const PINNED: Checks = Checks {
        block_internal: false,
        pinned: true,
    };
    const PLAIN: Checks = Checks {
        block_internal: false,
        pinned: false,
    };

    fn proxy_url(r: Result<Route, String>) -> String {
        match r {
            Ok(Route::Proxy { url, .. }) => url,
            other => panic!("not a proxy route: {other:?}"),
        }
    }

    #[test]
    fn inherit_with_bad_env_value_fails_closed() {
        for bad in [
            "bogus://x",
            "proxy.example:3128",
            "socks5://",
            "http://proxy.example:0",
            "http://proxy.example:3128/some/path",
        ] {
            let e = inherit_route(Some(bad), PLAIN).unwrap_err();
            assert!(
                e.starts_with("CROSSFYRE_EGRESS_PROXY is not a usable"),
                "{bad}: {e}"
            );
        }
    }

    #[test]
    fn a_bad_value_is_never_quoted() {
        let e = inherit_route(Some("bogus://user:hunter2@x"), PLAIN).unwrap_err();
        assert!(!e.contains("hunter2"), "{e}");
        let e = route(&Egress::Proxy("bogus://user:hunter2@x".into()), PLAIN).unwrap_err();
        assert!(!e.contains("hunter2"), "{e}");
    }

    #[test]
    fn inherit_with_no_env_value_is_todays_behaviour() {
        assert_eq!(inherit_route(None, PLAIN), Ok(Route::System));
        // A proxy from the environment would look names up where neither check sees.
        assert_eq!(inherit_route(None, GUARDED), Ok(Route::Direct));
        assert_eq!(inherit_route(None, PINNED), Ok(Route::Direct));
    }

    #[test]
    fn inherit_env_with_block_internal_is_refused() {
        let e = inherit_route(Some("http://proxy.example:3128"), GUARDED).unwrap_err();
        assert!(e.contains("private addresses"), "{e}");
        let both = Checks {
            block_internal: true,
            pinned: true,
        };
        assert!(inherit_route(Some("http://proxy.example:3128"), both).is_err());
    }

    #[test]
    fn inherit_env_with_pins_is_refused() {
        let e = inherit_route(Some("socks5h://127.0.0.1:1080"), PINNED).unwrap_err();
        assert!(e.contains("pinned address"), "{e}");
    }

    #[test]
    fn proxy_with_pins_is_refused() {
        let e = route(&Egress::Proxy("socks5h://127.0.0.1:1080".into()), PINNED).unwrap_err();
        assert!(e.contains("pinned address"), "{e}");
    }

    #[test]
    fn proxy_with_block_internal_leaves_the_check_to_the_proxy() {
        let r = route(
            &Egress::Proxy("socks5h://u:p@127.0.0.1:1080".into()),
            GUARDED,
        );
        assert_eq!(proxy_url(r), "socks5h://u:p@127.0.0.1:1080");
    }

    #[test]
    fn direct_reads_nothing() {
        for checks in [PLAIN, GUARDED, PINNED] {
            assert_eq!(route(&Egress::Direct, checks), Ok(Route::Direct));
        }
    }

    #[test]
    fn a_name_always_goes_to_the_proxy_unresolved() {
        for (given, sent) in [
            ("socks5://127.0.0.1:1080", "socks5h://127.0.0.1:1080"),
            (
                "SOCKS5://u:p@127.0.0.1:1080",
                "socks5h://u:p@127.0.0.1:1080",
            ),
            ("socks5h://127.0.0.1:1080", "socks5h://127.0.0.1:1080"),
            ("socks4://127.0.0.1:1080", "socks4a://127.0.0.1:1080"),
            ("socks4a://127.0.0.1:1080", "socks4a://127.0.0.1:1080"),
            (
                "http://u:p@proxy.example:3128",
                "http://u:p@proxy.example:3128",
            ),
            ("HTTPS://proxy.example", "https://proxy.example"),
        ] {
            assert_eq!(proxy_url(inherit_route(Some(given), PLAIN)), sent);
            assert_eq!(proxy_url(route(&Egress::Proxy(given.into()), PLAIN)), sent);
        }
    }

    #[test]
    fn wire_versions_and_values() {
        let wire = |s: &str| serde_json::from_str::<EgressWire>(s);
        let w = wire(r#"{"v":1,"proxy":null}"#).unwrap();
        assert_eq!(Egress::from_wire(&w), Ok(Egress::Direct));
        let w = wire(r#"{"v":1}"#).unwrap();
        assert_eq!(Egress::from_wire(&w), Ok(Egress::Direct));
        let w = wire(r#"{"v":1,"proxy":"socks5h://a:b@127.0.0.1:4000"}"#).unwrap();
        assert_eq!(
            Egress::from_wire(&w),
            Ok(Egress::Proxy("socks5h://a:b@127.0.0.1:4000".into()))
        );
        let w = wire(r#"{"v":2,"proxy":null}"#).unwrap();
        assert!(Egress::from_wire(&w).unwrap_err().contains("version 2"));
        let w = wire(r#"{"v":1,"proxy":"ftp://x"}"#).unwrap();
        assert!(Egress::from_wire(&w).is_err());
        assert!(wire(r#"{"v":1,"proxy":null,"scope":"x"}"#).is_err());
        assert!(wire(r#"{"proxy":null}"#).is_err());
    }

    #[test]
    fn debug_never_shows_credentials() {
        let e = Egress::Proxy("socks5h://3f9c0a7b1e2d4c56:deadbeef@127.0.0.1:43117".into());
        let shown = format!("{e:?}");
        assert_eq!(shown, "Proxy(socks5://127.0.0.1:43117)");
        let shown = format!("{:?}", Egress::Proxy("bogus://u:hunter2@x".into()));
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    #[test]
    fn is_proxied_follows_the_variant() {
        assert!(!Egress::Direct.is_proxied());
        assert!(Egress::Proxy("socks5h://127.0.0.1:1".into()).is_proxied());
    }
}

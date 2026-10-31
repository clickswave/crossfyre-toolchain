//! TCP tunnels through a proxy, and the server side of SOCKS5.
//!
//! [`connect`] opens a connection to a destination through one proxy and returns it
//! once the proxy has agreed, so the caller speaks the destination's protocol
//! straight into it. Four kinds of proxy are spoken to: SOCKS5 (RFC 1928, with the
//! user name and password of RFC 1929), SOCKS4 and 4a, HTTP `CONNECT`, and HTTP
//! `CONNECT` inside TLS.
//!
//! A destination name is never resolved here. It goes to the proxy as a name (SOCKS5
//! address type 3, SOCKS4a, `CONNECT name:port`), so the proxy's resolver answers
//! and this machine's is never asked. A caller that has to vet the address first
//! resolves the name itself and passes [`Host::Ip`]. That is why `socks5://` and
//! `socks4://` behave here exactly as `socks5h://` and `socks4a://` do.
//!
//! [`socks5_server`] is the other end. The node's gateway accepts the engines'
//! connections with it and opens each one onward with [`connect`].
//!
//! Every field that goes on the wire is checked before the proxy is dialled, so a
//! name or credential a protocol cannot carry ends in [`TunnelError::Invalid`] with
//! no connection made. The whole exchange with a proxy runs under one deadline, so
//! a proxy that never answers, or answers a byte at a time, ends in
//! [`TunnelError::Timeout`].

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

mod http;
mod socks4;
mod socks5;
pub mod socks5_server;

#[cfg(feature = "recorder")]
pub mod recorder;

/// The longest destination name sent to any proxy. SOCKS5 gives a name one length
/// byte, and no DNS name is longer.
pub const MAX_NAME: usize = 255;

/// The longest user name or password sent to an HTTP proxy. SOCKS5 carries at most
/// 255 bytes of each; HTTP has no such limit, and some providers hand out tokens
/// longer than that as passwords.
pub const MAX_HTTP_CREDENTIAL: usize = 1024;

/// Where a tunnel goes: a name for the proxy to resolve, or an address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

impl Host {
    /// An address literal becomes [`Host::Ip`], with or without the brackets an IPv6
    /// address has in a URL. Anything else is a name, checked when it is sent.
    pub fn parse(s: &str) -> Host {
        let bare = s
            .strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .unwrap_or(s);
        match bare.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Name(s.to_string()),
        }
    }
}

/// A destination: host and port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    pub fn new(host: &str, port: u16) -> Target {
        Target {
            host: Host::parse(host),
            port,
        }
    }

    /// Whether this can be sent to a proxy: a port other than 0, and a name of 1 to
    /// 255 bytes made of ASCII letters, digits, `.`, `-` and `_`. An international
    /// name goes in its ASCII (punycode) form, as a URL parser already gives it.
    ///
    /// The character set is what keeps a name from rewriting an HTTP `CONNECT` line
    /// or ending a SOCKS4a field early.
    pub fn check(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("the destination port is 0".into());
        }
        match &self.host {
            Host::Ip(_) => Ok(()),
            Host::Name(n) => check_name(n, "destination name"),
        }
    }
}

/// `host:port`, with an IPv6 address in brackets.
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Name(n) => write!(f, "{n}:{}", self.port),
            Host::Ip(IpAddr::V6(a)) => write!(f, "[{a}]:{}", self.port),
            Host::Ip(a) => write!(f, "{a}:{}", self.port),
        }
    }
}

fn check_name(n: &str, what: &str) -> Result<(), String> {
    if n.is_empty() {
        return Err(format!("the {what} is empty"));
    }
    if n.len() > MAX_NAME {
        return Err(format!(
            "the {what} is {} bytes long, and a proxy takes at most {MAX_NAME}",
            n.len()
        ));
    }
    if let Some(b) = n
        .bytes()
        .find(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
    {
        return Err(format!(
            "the {what} has a byte a host name cannot have ({b:#04x})"
        ));
    }
    Ok(())
}

/// The protocol spoken to a proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Http,
    Https,
    Socks4,
    Socks5,
}

impl Kind {
    /// The scheme [`Upstream::label`] shows.
    pub fn scheme(self) -> &'static str {
        match self {
            Kind::Http => "http",
            Kind::Https => "https",
            Kind::Socks4 => "socks4",
            Kind::Socks5 => "socks5",
        }
    }

    /// A proxy URL without a port means this one, as it does to the engines' HTTP
    /// clients.
    fn default_port(self) -> u16 {
        match self {
            Kind::Http => 80,
            Kind::Https => 443,
            Kind::Socks4 | Kind::Socks5 => 1080,
        }
    }
}

/// A proxy and the credentials it takes.
///
/// `Debug` hides the credentials and [`label`](Upstream::label) leaves them out, so
/// neither can put them in a log.
#[derive(Clone, PartialEq, Eq)]
pub struct Upstream {
    pub kind: Kind,
    /// A name or an address, an IPv6 address without brackets.
    pub host: String,
    pub port: u16,
    /// User name and password. SOCKS4 takes the user name as its user id and has no
    /// password.
    pub auth: Option<(String, String)>,
}

impl fmt::Debug for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upstream")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth", &self.auth.as_ref().map(|_| "<hidden>"))
            .finish()
    }
}

impl Upstream {
    /// Reads `http://`, `https://`, `socks4://`, `socks4a://`, `socks5://` or
    /// `socks5h://`, then an optional `user:password@` (percent-decoded), a host
    /// (an IPv6 address in brackets) and an optional port. A trailing `/` is allowed
    /// and nothing else after the port is.
    ///
    /// An error never quotes the URL, since the URL may hold a password.
    pub fn parse(url: &str) -> Result<Upstream, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or("a proxy URL starts with its type, such as socks5://")?;
        let kind = match scheme.to_ascii_lowercase().as_str() {
            "http" => Kind::Http,
            "https" => Kind::Https,
            "socks4" | "socks4a" => Kind::Socks4,
            "socks5" | "socks5h" => Kind::Socks5,
            _ => {
                return Err(
                    "the proxy type must be http, https, socks4, socks4a, socks5 or socks5h".into(),
                );
            }
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.contains(['/', '?', '#']) {
            return Err(
                "a proxy URL has a host and port only, with no path, query or fragment".into(),
            );
        }
        // The last `@`, so a password with an unescaped `@` in it still reads whole.
        let (userinfo, hostport) = match authority.rfind('@') {
            Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
            None => (None, authority),
        };
        let (host, port) = split_host_port(hostport, kind.default_port())?;
        let auth = match userinfo {
            None => None,
            Some(ui) => {
                let (user, pass) = ui.split_once(':').unwrap_or((ui, ""));
                Some((
                    percent_decode(user, "user name")?,
                    percent_decode(pass, "password")?,
                ))
            }
        };
        let up = Upstream {
            kind,
            host,
            port,
            auth,
        };
        up.check()?;
        Ok(up)
    }

    /// `type://host:port`, for logs and the dashboard. Never includes credentials.
    pub fn label(&self) -> String {
        if self.host.contains(':') {
            format!("{}://[{}]:{}", self.kind.scheme(), self.host, self.port)
        } else {
            format!("{}://{}:{}", self.kind.scheme(), self.host, self.port)
        }
    }

    /// Whether this can be spoken to: a valid host, a port other than 0, and
    /// credentials the protocol can carry. [`parse`](Upstream::parse) runs it, and
    /// [`connect`] runs it again for an `Upstream` built field by field.
    pub fn check(&self) -> Result<(), String> {
        if self.host.parse::<IpAddr>().is_err() {
            check_name(&self.host, "proxy host")?;
        }
        if self.port == 0 {
            return Err("the proxy port must be 1 to 65535".into());
        }
        let Some((user, pass)) = &self.auth else {
            return Ok(());
        };
        if user.is_empty() {
            return Err("the proxy user name is empty".into());
        }
        match self.kind {
            Kind::Socks5 => {
                for (what, v) in [("user name", user), ("password", pass)] {
                    if v.len() > 255 {
                        return Err(format!(
                            "the proxy {what} is {} bytes long, and SOCKS5 carries at most 255",
                            v.len()
                        ));
                    }
                }
            }
            Kind::Socks4 => {
                if !pass.is_empty() {
                    return Err("a SOCKS4 proxy takes a user id and no password".into());
                }
                if user.len() > 255 {
                    return Err(format!(
                        "the SOCKS4 user id is {} bytes long, and at most 255 are sent",
                        user.len()
                    ));
                }
                if user.contains('\0') {
                    return Err("the SOCKS4 user id has a NUL byte in it".into());
                }
            }
            Kind::Http | Kind::Https => {
                if user.contains(':') {
                    return Err("an HTTP proxy's user name cannot contain ':'".into());
                }
                for (what, v) in [("user name", user), ("password", pass)] {
                    if v.len() > MAX_HTTP_CREDENTIAL {
                        return Err(format!(
                            "the proxy {what} is {} bytes long, and at most {MAX_HTTP_CREDENTIAL} are sent",
                            v.len()
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn split_host_port(s: &str, default: u16) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or("an IPv6 proxy address is missing its closing ]")?;
        if h.parse::<Ipv6Addr>().is_err() {
            return Err("the proxy address in brackets is not an IPv6 address".into());
        }
        let port = match after {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .ok_or("unexpected text after the proxy's IPv6 address")?,
            ),
        };
        (h, port)
    } else {
        match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    let port = match port {
        None => default,
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("the proxy port is not a number".into());
            }
            p.parse::<u16>()
                .ok()
                .filter(|&n| n != 0)
                .ok_or("the proxy port must be 1 to 65535")?
        }
    };
    Ok((host.to_string(), port))
}

fn percent_decode(s: &str, what: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            match (
                b.get(i + 1).and_then(|&c| hex(c)),
                b.get(i + 2).and_then(|&c| hex(c)),
            ) {
                (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
                _ => {
                    return Err(format!(
                        "the proxy {what} has a % not followed by two hex digits"
                    ));
                }
            }
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("the proxy {what} is not UTF-8 once decoded"))
}

/// A tunnel's stream.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// An open tunnel: bytes written go to the destination, bytes read came from it.
pub type Tunnel = Box<dyn Io>;

/// How long each step may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Resolving the proxy's own name and the TCP connection to it.
    pub connect: Duration,
    /// Everything after that, as one deadline: TLS with an HTTPS proxy, then the
    /// proxy's handshake up to its answer about the destination.
    pub handshake: Duration,
}

impl Default for Timeouts {
    fn default() -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(10),
            handshake: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelError {
    /// The proxy or destination cannot be spoken: a field too long for the protocol,
    /// a name with a byte no host name has, an IPv6 address for SOCKS4. Nothing was
    /// dialled.
    Invalid(String),
    /// The proxy could not be reached, or TLS with it failed.
    Connect(String),
    /// The proxy refused the credentials, or wants some and none were given.
    Auth,
    /// The proxy refused the destination, with this reply code: any code other than
    /// 0 from SOCKS5 (0x01 to 0x08 are the assigned ones), 0x5B to 0x5D from SOCKS4.
    Refused(u8),
    /// An HTTP proxy answered `CONNECT` with this status, other than 2xx and 407.
    Http(u16),
    /// The proxy's answer was not the protocol it was asked to speak.
    Protocol(String),
    /// The proxy did not finish the handshake within [`Timeouts::handshake`].
    Timeout,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelError::Invalid(m) => f.write_str(m),
            TunnelError::Connect(m) => write!(f, "could not connect to the proxy: {m}"),
            TunnelError::Auth => f.write_str("the proxy refused the credentials"),
            TunnelError::Refused(c) => write!(
                f,
                "the proxy refused the destination ({}, reply {c:#04x})",
                refusal_meaning(*c)
            ),
            TunnelError::Http(c) => write!(f, "the proxy answered CONNECT with HTTP {c}"),
            TunnelError::Protocol(m) => write!(f, "the proxy's answer was malformed: {m}"),
            TunnelError::Timeout => f.write_str("the proxy did not answer in time"),
        }
    }
}

impl std::error::Error for TunnelError {}

fn refusal_meaning(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "not allowed by its rules",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        0x5B => "rejected or failed",
        0x5C => "no identd on the client",
        0x5D => "identd user id mismatch",
        _ => "unassigned code",
    }
}

impl TunnelError {
    /// The SOCKS5 reply a server sends its own client when the onward tunnel fails
    /// this way.
    pub fn reply_code(&self) -> u8 {
        use socks5_server::{CONNECTION_REFUSED, GENERAL_FAILURE, HOST_UNREACHABLE, NOT_ALLOWED};
        match self {
            TunnelError::Refused(c @ 0x01..=0x08) => *c,
            TunnelError::Refused(_) => CONNECTION_REFUSED,
            TunnelError::Http(403) => NOT_ALLOWED,
            TunnelError::Http(502 | 504) | TunnelError::Timeout => HOST_UNREACHABLE,
            _ => GENERAL_FAILURE,
        }
    }
}

/// An I/O error during a handshake. The proxy hanging up is a protocol failure: it
/// owed an answer and did not give one.
fn io_err(e: io::Error) -> TunnelError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        TunnelError::Protocol("the proxy closed the connection before answering".into())
    } else {
        TunnelError::Connect(e.to_string())
    }
}

async fn read_exact<S: AsyncRead + Unpin>(s: &mut S, buf: &mut [u8]) -> Result<(), TunnelError> {
    s.read_exact(buf).await.map(|_| ()).map_err(io_err)
}

/// Opens a tunnel to `target` through `up`.
///
/// A [`Host::Name`] target is sent unresolved (SOCKS5 address type 3, SOCKS4a,
/// `CONNECT name:port`) and a [`Host::Ip`] one as an address. Only the proxy's own
/// name is resolved here.
pub async fn connect(up: &Upstream, target: &Target, t: Timeouts) -> Result<Tunnel, TunnelError> {
    connect_with(up, target, t, &tls_config()).await
}

async fn connect_with(
    up: &Upstream,
    target: &Target,
    t: Timeouts,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<Tunnel, TunnelError> {
    up.check().map_err(TunnelError::Invalid)?;
    target.check().map_err(TunnelError::Invalid)?;
    let auth = up.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
    // Every byte the handshake sends is settled before the proxy is dialled, so
    // anything the protocol cannot carry stops here.
    let opening = match up.kind {
        Kind::Socks5 => Opening::Socks5(socks5::Opening::new(auth, target)?),
        Kind::Socks4 => Opening::Socks4(socks4::request(auth.map(|(u, _)| u), target)?),
        Kind::Http => Opening::Http(http::request(auth, target)?),
        Kind::Https => Opening::Https(
            http::request(auth, target)?,
            ServerName::try_from(up.host.clone()).map_err(|_| {
                TunnelError::Invalid("the proxy host is not a name TLS can check".into())
            })?,
        ),
    };

    let tcp = match tokio::time::timeout(t.connect, TcpStream::connect((up.host.as_str(), up.port)))
        .await
    {
        Err(_) => {
            return Err(TunnelError::Connect(format!(
                "no connection within {} ms",
                t.connect.as_millis()
            )));
        }
        Ok(Err(e)) => return Err(TunnelError::Connect(e.to_string())),
        Ok(Ok(s)) => s,
    };
    let _ = tcp.set_nodelay(true);

    let exchange = async move {
        match opening {
            Opening::Socks5(o) => {
                let mut s = tcp;
                socks5::handshake(&mut s, &o).await?;
                Ok(Box::new(s) as Tunnel)
            }
            Opening::Socks4(req) => {
                let mut s = tcp;
                socks4::handshake(&mut s, &req).await?;
                Ok(Box::new(s) as Tunnel)
            }
            Opening::Http(req) => http::handshake(tcp, &req).await,
            Opening::Https(req, name) => {
                let s = tokio_rustls::TlsConnector::from(Arc::clone(tls))
                    .connect(name, tcp)
                    .await
                    .map_err(|e| TunnelError::Connect(format!("TLS with the proxy failed: {e}")))?;
                http::handshake(s, &req).await
            }
        }
    };
    tokio::time::timeout(t.handshake, exchange)
        .await
        .map_err(|_| TunnelError::Timeout)?
}

/// What a handshake sends, built before the proxy is dialled.
enum Opening {
    Socks5(socks5::Opening),
    Socks4(Vec<u8>),
    Http(Vec<u8>),
    Https(Vec<u8>, ServerName<'static>),
}

/// TLS for an HTTPS proxy: the public web roots, TLS 1.2 and 1.3, and HTTP/1.1,
/// because `CONNECT` is spoken in it.
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(client_config(roots))
    }))
}

fn client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports TLS 1.2 and 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    c
}

/// A stream that first gives back bytes already read from it.
///
/// A proxy may send the destination's first bytes in the same segment as its
/// `200`, as it does for a server that speaks first. Those were read with the
/// answer and belong to the caller.
struct Rewind<S> {
    pre: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = (self.pre.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.pre[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests;

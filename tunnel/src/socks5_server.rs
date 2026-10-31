//! The server side of SOCKS5 (RFC 1928) with user name and password (RFC 1929),
//! for the node's gateway.
//!
//! The only method accepted is user name and password, and the only command is
//! `CONNECT`. [`accept`] runs the exchange up to the client's request and hands back
//! the destination; the caller decides, opens the onward connection, and answers
//! with [`reply`].

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::socks5::{ATYP_NAME, ATYP_V4, ATYP_V6, CMD_CONNECT, NO_ACCEPTABLE, USER_PASS, VERSION};
use crate::{Host, Target};

pub const SUCCEEDED: u8 = 0x00;
pub const GENERAL_FAILURE: u8 = 0x01;
pub const NOT_ALLOWED: u8 = 0x02;
pub const NETWORK_UNREACHABLE: u8 = 0x03;
pub const HOST_UNREACHABLE: u8 = 0x04;
pub const CONNECTION_REFUSED: u8 = 0x05;
pub const TTL_EXPIRED: u8 = 0x06;
pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Why [`accept`] gave up. Where the protocol has an answer for it, the client has
/// already been sent that answer; either way the caller only closes the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The client did not offer user name and password. Answered 0xFF.
    NoUserPass,
    /// The credentials were refused, or were not UTF-8, or the user name was empty.
    /// Answered with status 0x01.
    Auth,
    /// BIND, UDP ASSOCIATE or an unknown command. Answered 0x07.
    Command(u8),
    /// An address type other than IPv4, IPv6 and a name. Answered 0x08.
    AddressType(u8),
    /// A destination no proxy is asked for: port 0, or a name that is empty, not
    /// UTF-8, or has a byte no host name has. Answered 0x01.
    Target(String),
    /// Not SOCKS5, or cut short. Nothing is answered.
    Malformed(String),
    /// The client did not get as far as its request in time. Nothing is answered.
    Timeout,
    /// The connection failed under the exchange.
    Io(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NoUserPass => f.write_str("the client did not offer a user name and password"),
            Refusal::Auth => f.write_str("the client's credentials were refused"),
            Refusal::Command(c) => write!(f, "command {c:#04x} is not supported, only CONNECT"),
            Refusal::AddressType(a) => write!(f, "address type {a:#04x} is not supported"),
            Refusal::Target(m) => f.write_str(m),
            Refusal::Malformed(m) => write!(f, "malformed SOCKS5 from the client: {m}"),
            Refusal::Timeout => f.write_str("the client did not finish its request in time"),
            Refusal::Io(m) => write!(f, "the client connection failed: {m}"),
        }
    }
}

impl std::error::Error for Refusal {}

fn io_err(e: io::Error) -> Refusal {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        Refusal::Malformed("the client closed the connection mid-message".into())
    } else {
        Refusal::Io(e.to_string())
    }
}

async fn read<S: AsyncRead + Unpin>(s: &mut S, buf: &mut [u8]) -> Result<(), Refusal> {
    s.read_exact(buf).await.map(|_| ()).map_err(io_err)
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, bytes: &[u8]) -> Result<(), Refusal> {
    s.write_all(bytes).await.map_err(io_err)?;
    s.flush().await.map_err(io_err)
}

/// Runs a client's greeting, credentials and request, all within `deadline`.
///
/// `check(user, password)` is called once, with UTF-8 credentials and a non-empty
/// user name, and returns what the caller wants back for an accepted client, or
/// `None` to refuse it. On `Ok` the client is waiting for [`reply`].
///
/// A name that is an address literal comes back as [`Host::Ip`], so the caller's
/// address policy sees it as one.
pub async fn accept<S, C, F>(
    s: &mut S,
    deadline: Duration,
    check: F,
) -> Result<(C, Target), Refusal>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str, &str) -> Option<C>,
{
    match tokio::time::timeout(deadline, exchange(s, check)).await {
        Ok(r) => r,
        Err(_) => Err(Refusal::Timeout),
    }
}

async fn exchange<S, C, F>(s: &mut S, check: F) -> Result<(C, Target), Refusal>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str, &str) -> Option<C>,
{
    // VER NMETHODS METHODS
    let mut head = [0u8; 2];
    read(s, &mut head).await?;
    if head[0] != VERSION {
        return Err(Refusal::Malformed(format!(
            "greeting version {:#04x}, not 5",
            head[0]
        )));
    }
    let mut methods = vec![0u8; head[1] as usize];
    read(s, &mut methods).await?;
    if !methods.contains(&USER_PASS) {
        send(s, &[VERSION, NO_ACCEPTABLE]).await?;
        return Err(Refusal::NoUserPass);
    }
    send(s, &[VERSION, USER_PASS]).await?;

    // VER ULEN UNAME PLEN PASSWD
    let mut ver_ulen = [0u8; 2];
    read(s, &mut ver_ulen).await?;
    if ver_ulen[0] != 0x01 {
        return Err(Refusal::Malformed(format!(
            "credentials version {:#04x}, not 1",
            ver_ulen[0]
        )));
    }
    let mut user = vec![0u8; ver_ulen[1] as usize];
    read(s, &mut user).await?;
    let mut plen = [0u8; 1];
    read(s, &mut plen).await?;
    let mut pass = vec![0u8; plen[0] as usize];
    read(s, &mut pass).await?;
    let accepted = match (std::str::from_utf8(&user), std::str::from_utf8(&pass)) {
        (Ok(u), Ok(p)) if !u.is_empty() => check(u, p),
        _ => None,
    };
    let Some(ctx) = accepted else {
        // The client learns it was refused; the connection closes either way.
        let _ = send(s, &[0x01, 0x01]).await;
        return Err(Refusal::Auth);
    };
    send(s, &[0x01, 0x00]).await?;

    // VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    read(s, &mut req).await?;
    if req[0] != VERSION {
        return Err(Refusal::Malformed(format!(
            "request version {:#04x}, not 5",
            req[0]
        )));
    }
    if req[1] != CMD_CONNECT {
        let _ = reply(s, COMMAND_NOT_SUPPORTED).await;
        return Err(Refusal::Command(req[1]));
    }
    let host = match req[3] {
        ATYP_V4 => {
            let mut a = [0u8; 4];
            read(s, &mut a).await?;
            Host::Ip(IpAddr::from(a))
        }
        ATYP_V6 => {
            let mut a = [0u8; 16];
            read(s, &mut a).await?;
            Host::Ip(IpAddr::from(a))
        }
        ATYP_NAME => {
            let mut len = [0u8; 1];
            read(s, &mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            read(s, &mut name).await?;
            match String::from_utf8(name) {
                Ok(n) => Host::parse(&n),
                Err(_) => {
                    let _ = reply(s, GENERAL_FAILURE).await;
                    return Err(Refusal::Target("the destination name is not UTF-8".into()));
                }
            }
        }
        a => {
            let _ = reply(s, ADDRESS_TYPE_NOT_SUPPORTED).await;
            return Err(Refusal::AddressType(a));
        }
    };
    let mut port = [0u8; 2];
    read(s, &mut port).await?;
    let target = Target {
        host,
        port: u16::from_be_bytes(port),
    };
    if let Err(why) = target.check() {
        let _ = reply(s, GENERAL_FAILURE).await;
        return Err(Refusal::Target(why));
    }
    Ok((ctx, target))
}

/// Answers the request [`accept`] returned: [`SUCCEEDED`] once the onward tunnel is
/// open, or a failure code before closing. The bound address sent is 0.0.0.0:0;
/// clients do not use it for `CONNECT`.
pub async fn reply<S: AsyncWrite + Unpin>(s: &mut S, code: u8) -> io::Result<()> {
    s.write_all(&[VERSION, code, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
        .await?;
    s.flush().await
}

/// Compares a presented secret with the expected one in time that depends only on
/// their lengths, for a `check` that holds per-client secrets.
pub fn secret_eq(presented: &[u8], expected: &[u8]) -> bool {
    if presented.len() != expected.len() {
        return false;
    }
    let diff = presented
        .iter()
        .zip(expected)
        .fold(0u8, |d, (a, b)| d | (a ^ b));
    std::hint::black_box(diff) == 0
}

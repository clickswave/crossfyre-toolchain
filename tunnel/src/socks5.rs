//! The client side of SOCKS5 (RFC 1928), with user name and password (RFC 1929).

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{Host, Target, TunnelError, io_err, read_exact};

pub(crate) const VERSION: u8 = 0x05;
pub(crate) const NO_AUTH: u8 = 0x00;
pub(crate) const USER_PASS: u8 = 0x02;
pub(crate) const NO_ACCEPTABLE: u8 = 0xFF;
pub(crate) const CMD_CONNECT: u8 = 0x01;
pub(crate) const ATYP_V4: u8 = 0x01;
pub(crate) const ATYP_NAME: u8 = 0x03;
pub(crate) const ATYP_V6: u8 = 0x04;

/// The three messages a client sends, in order.
pub(crate) struct Opening {
    greeting: Vec<u8>,
    auth: Option<Vec<u8>>,
    request: Vec<u8>,
}

impl Opening {
    pub(crate) fn new(auth: Option<(&str, &str)>, target: &Target) -> Result<Opening, TunnelError> {
        // With credentials, no-auth is offered too: a proxy that needs none may pick
        // it, and nothing is lost when it does.
        let greeting = match auth {
            Some(_) => vec![VERSION, 2, NO_AUTH, USER_PASS],
            None => vec![VERSION, 1, NO_AUTH],
        };
        let auth = match auth {
            None => None,
            Some((user, pass)) => {
                let mut a = vec![0x01];
                for v in [user, pass] {
                    a.push(len_byte(v, "a SOCKS5 user name or password")?);
                    a.extend_from_slice(v.as_bytes());
                }
                Some(a)
            }
        };
        let mut request = vec![VERSION, CMD_CONNECT, 0x00];
        match &target.host {
            Host::Ip(IpAddr::V4(a)) => {
                request.push(ATYP_V4);
                request.extend_from_slice(&a.octets());
            }
            Host::Ip(IpAddr::V6(a)) => {
                request.push(ATYP_V6);
                request.extend_from_slice(&a.octets());
            }
            Host::Name(n) => {
                request.push(ATYP_NAME);
                request.push(len_byte(n, "a SOCKS5 destination name")?);
                request.extend_from_slice(n.as_bytes());
            }
        }
        request.extend_from_slice(&target.port.to_be_bytes());
        Ok(Opening {
            greeting,
            auth,
            request,
        })
    }
}

/// One length byte, so 255 at most.
fn len_byte(v: &str, what: &str) -> Result<u8, TunnelError> {
    u8::try_from(v.len()).map_err(|_| {
        TunnelError::Invalid(format!(
            "{what} is {} bytes long, and SOCKS5 carries at most 255",
            v.len()
        ))
    })
}

pub(crate) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    o: &Opening,
) -> Result<(), TunnelError> {
    s.write_all(&o.greeting).await.map_err(io_err)?;
    let mut chosen = [0u8; 2];
    read_exact(s, &mut chosen).await?;
    if chosen[0] != VERSION {
        return Err(TunnelError::Protocol(format!(
            "not a SOCKS5 proxy: it answered with version {:#04x}",
            chosen[0]
        )));
    }
    match (chosen[1], &o.auth) {
        (NO_AUTH, _) => {}
        (USER_PASS, Some(auth)) => {
            s.write_all(auth).await.map_err(io_err)?;
            let mut status = [0u8; 2];
            read_exact(s, &mut status).await?;
            // RFC 1929 says version 1; some servers answer with 5.
            if !matches!(status[0], 0x01 | VERSION) {
                return Err(TunnelError::Protocol(format!(
                    "the answer to the credentials has version {:#04x}",
                    status[0]
                )));
            }
            if status[1] != 0x00 {
                return Err(TunnelError::Auth);
            }
        }
        (NO_ACCEPTABLE, _) => return Err(TunnelError::Auth),
        (m, _) => {
            return Err(TunnelError::Protocol(format!(
                "the proxy chose authentication method {m:#04x}, which was not offered"
            )));
        }
    }

    s.write_all(&o.request).await.map_err(io_err)?;
    let mut head = [0u8; 2];
    read_exact(s, &mut head).await?;
    if head[0] != VERSION {
        return Err(TunnelError::Protocol(format!(
            "the reply to CONNECT has version {:#04x}",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(TunnelError::Refused(head[1]));
    }
    // The bound address is read to its end so the tunnel starts at the
    // destination's first byte. Its value is of no use here.
    let mut rsv_atyp = [0u8; 2];
    read_exact(s, &mut rsv_atyp).await?;
    let rest = match rsv_atyp[1] {
        ATYP_V4 => 4 + 2,
        ATYP_V6 => 16 + 2,
        ATYP_NAME => {
            let mut len = [0u8; 1];
            read_exact(s, &mut len).await?;
            len[0] as usize + 2
        }
        a => {
            return Err(TunnelError::Protocol(format!(
                "the reply to CONNECT has address type {a:#04x}"
            )));
        }
    };
    let mut bound = vec![0u8; rest];
    read_exact(s, &mut bound).await
}

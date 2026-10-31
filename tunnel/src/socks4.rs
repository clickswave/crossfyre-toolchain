//! The client side of SOCKS4, and SOCKS4a for a name.

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{Host, Target, TunnelError, io_err, read_exact};

const GRANTED: u8 = 0x5A;

/// `VN CD DSTPORT DSTIP USERID NUL`, then for SOCKS4a the name and a NUL. A name
/// goes with the address 0.0.0.1, which tells the server a name follows.
pub(crate) fn request(user: Option<&str>, target: &Target) -> Result<Vec<u8>, TunnelError> {
    let mut r = vec![0x04, 0x01];
    r.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddr::V4(a)) => r.extend_from_slice(&a.octets()),
        Host::Ip(IpAddr::V6(_)) => {
            return Err(TunnelError::Invalid(
                "SOCKS4 cannot carry an IPv6 address; use SOCKS5, or send the name".into(),
            ));
        }
        Host::Name(_) => r.extend_from_slice(&[0, 0, 0, 1]),
    }
    let user = user.unwrap_or("");
    // Upstream::check refuses these too; the NUL that ends each field is what a
    // stray one would forge.
    if user.contains('\0') {
        return Err(TunnelError::Invalid(
            "the SOCKS4 user id has a NUL byte in it".into(),
        ));
    }
    r.extend_from_slice(user.as_bytes());
    r.push(0);
    if let Host::Name(n) = &target.host {
        if n.contains('\0') {
            return Err(TunnelError::Invalid(
                "the destination name has a NUL byte in it".into(),
            ));
        }
        r.extend_from_slice(n.as_bytes());
        r.push(0);
    }
    Ok(r)
}

pub(crate) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    request: &[u8],
) -> Result<(), TunnelError> {
    s.write_all(request).await.map_err(io_err)?;
    let mut reply = [0u8; 8];
    read_exact(s, &mut reply).await?;
    if reply[0] != 0x00 {
        return Err(TunnelError::Protocol(format!(
            "not a SOCKS4 proxy: its reply starts with {:#04x}",
            reply[0]
        )));
    }
    match reply[1] {
        GRANTED => Ok(()),
        c @ 0x5B..=0x5D => Err(TunnelError::Refused(c)),
        c => Err(TunnelError::Protocol(format!(
            "unknown SOCKS4 reply code {c:#04x}"
        ))),
    }
}

//! The client side of HTTP `CONNECT` (RFC 9110 9.3.6), over TCP or inside TLS.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Rewind, Target, Tunnel, TunnelError, io_err};

/// The most of a proxy's answer read while looking for the end of its headers.
pub(crate) const MAX_HEAD: usize = 8 * 1024;

/// `CONNECT host:port HTTP/1.1`, `Host:` and, with credentials, Basic
/// `Proxy-Authorization`. The target was checked, so its name cannot carry a line
/// break or a space into the request.
pub(crate) fn request(auth: Option<(&str, &str)>, target: &Target) -> Result<Vec<u8>, TunnelError> {
    target.check().map_err(TunnelError::Invalid)?;
    let authority = target.to_string();
    let mut r = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, pass)) = auth {
        if user.contains(':') {
            return Err(TunnelError::Invalid(
                "an HTTP proxy's user name cannot contain ':'".into(),
            ));
        }
        r.push_str("Proxy-Authorization: Basic ");
        r.push_str(&base64(format!("{user}:{pass}").as_bytes()));
        r.push_str("\r\n");
    }
    r.push_str("\r\n");
    Ok(r.into_bytes())
}

pub(crate) async fn handshake<S>(mut s: S, request: &[u8]) -> Result<Tunnel, TunnelError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    s.write_all(request).await.map_err(io_err)?;
    // Inside TLS the request sits in the session's buffer until flushed.
    s.flush().await.map_err(io_err)?;

    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if head.len() >= MAX_HEAD {
            return Err(TunnelError::Protocol(format!(
                "the answer to CONNECT has no end to its headers within {MAX_HEAD} bytes"
            )));
        }
        let want = (MAX_HEAD - head.len()).min(chunk.len());
        let n = s.read(&mut chunk[..want]).await.map_err(io_err)?;
        if n == 0 {
            return Err(TunnelError::Protocol(
                "the proxy closed the connection before answering CONNECT".into(),
            ));
        }
        let from = head.len().saturating_sub(3);
        head.extend_from_slice(&chunk[..n]);
        if let Some(i) = find(&head[from..], b"\r\n\r\n") {
            break from + i + 4;
        }
    };

    match status(&head[..end])? {
        200..=299 => {}
        407 => return Err(TunnelError::Auth),
        code => return Err(TunnelError::Http(code)),
    }
    let early = head.split_off(end);
    if early.is_empty() {
        Ok(Box::new(s))
    } else {
        Ok(Box::new(Rewind {
            pre: early,
            pos: 0,
            inner: s,
        }))
    }
}

/// The status code from `HTTP/1.x NNN reason`.
fn status(head: &[u8]) -> Result<u16, TunnelError> {
    let line = &head[..find(head, b"\r\n").unwrap_or(head.len())];
    let bad = || {
        TunnelError::Protocol("the proxy did not answer CONNECT with an HTTP/1 status line".into())
    };
    match line.strip_prefix(b"HTTP/1.").ok_or_else(bad)? {
        [v, b' ', a, b, c, rest @ ..]
            if v.is_ascii_digit()
                && [a, b, c].iter().all(|d| d.is_ascii_digit())
                && rest.first().is_none_or(|&x| x == b' ') =>
        {
            Ok(u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0'))
        }
        _ => Err(bad()),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Standard base64 with padding (RFC 4648 section 4), for Basic credentials.
pub(crate) fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let sextet = |shift: u32| ALPHABET[(n >> shift) as usize & 63] as char;
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

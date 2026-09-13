//! Minimal raw HTTP/1.1 client that sends the request-target verbatim.
//!
//! reqwest (through the `url` crate) resolves `.` / `%2e` dot-segments in the
//! path before the request leaves the process, so a probe like
//! `/cgi-bin/.%2e/.%2e/etc/passwd` is flattened to `/etc/passwd`. That defeats
//! path-traversal templates (CVE-2021-41773 and friends) whose whole point is to
//! make the *server*, not the client, do the normalisation. A template marked
//! `unsafe: true` is sent through this path so the bytes reach the target
//! unchanged. TLS uses the same accept-any-cert posture as the reqwest client
//! (cortex scans hosts with self-signed / mismatched certs).

#[cfg(not(feature = "impersonate"))]
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct RawResp {
    pub status: u16,
    /// "name: value\n" per header, name lowercased (mirrors template::Resp).
    pub headers: String,
    pub body: String,
}

pub struct RawReq<'a> {
    pub method: &'a str,
    /// Unnormalised URL, e.g. "http://h/cgi-bin/.%2e/.%2e/etc/passwd".
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Option<String>,
    pub timeout: Duration,
}

/// Cap on how much of a response we read. Without it a hostile (or broken) target
/// could stream unbounded data and exhaust memory. 8 MiB is far more than any
/// finding-bearing response and matches the buffered-body limit used elsewhere.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

pub async fn send(req: RawReq<'_>) -> Option<RawResp> {
    let (https, host, port, target) = split(req.url)?;
    let request = build_request(&req, &host, port, https, &target);
    let raw = tokio::time::timeout(req.timeout, async {
        if https {
            send_tls(&host, port, request.as_bytes()).await
        } else {
            send_plain(&host, port, request.as_bytes()).await
        }
    })
    .await
    .ok()??;
    parse_response(&raw)
}

/// Split an (unnormalised) URL into (is_https, host, port, request-target).
/// Deliberately does NOT use url::Url, which would resolve the dot-segments we
/// are trying to preserve.
fn split(url: &str) -> Option<(bool, String, u16, String)> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return None;
    };
    let (authority, target) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().ok()?)
        }
        _ => (authority.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        return None;
    }
    let target = if target.is_empty() {
        "/".to_string()
    } else {
        target.to_string()
    };
    Some((https, host, port, target))
}

fn build_request(req: &RawReq, host: &str, port: u16, https: bool, target: &str) -> String {
    let mut s = format!("{} {} HTTP/1.1\r\n", req.method.to_uppercase(), target);
    let host_hdr = if (https && port == 443) || (!https && port == 80) {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    s.push_str(&format!("Host: {host_hdr}\r\n"));
    let have = |name: &str| {
        req.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(name))
    };
    if !have("user-agent") {
        s.push_str(&format!(
            "User-Agent: {}\r\n",
            adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, Some(host)).user_agent
        ));
    }
    if !have("accept") {
        s.push_str("Accept: */*\r\n");
    }
    for (k, v) in req.headers {
        // Host / Connection / Content-Length are managed here, not copied.
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = &req.body {
        s.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    s.push_str("Connection: close\r\n\r\n");
    if let Some(b) = &req.body {
        s.push_str(b);
    }
    s
}

/// Send bytes exactly as given and time the answer.
///
/// `send` builds a well-formed request and manages Content-Length itself, which
/// is right for everything that wants to be understood. Request smuggling is
/// the opposite: the payload IS a request two parsers frame differently, so
/// nothing may normalise it. This hands the caller the socket.
///
/// Returns (raw response bytes, elapsed). A timeout returns None with the
/// elapsed time, because on this probe a hang IS the signal rather than a
/// failure.
pub async fn send_exact(
    host: &str,
    port: u16,
    https: bool,
    data: &[u8],
    timeout: Duration,
) -> (Option<Vec<u8>>, Duration) {
    let start = std::time::Instant::now();
    let out = tokio::time::timeout(timeout, async {
        if https {
            send_tls(host, port, data).await
        } else {
            send_plain(host, port, data).await
        }
    })
    .await
    .ok()
    .flatten();
    (out, start.elapsed())
}

/// Split a URL for the raw senders: (https, host, port, request-target).
pub fn split_url(url: &str) -> Option<(bool, String, u16, String)> {
    split(url)
}

async fn send_plain(host: &str, port: u16, data: &[u8]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect((host, port)).await.ok()?;
    stream.write_all(data).await.ok()?;
    stream.flush().await.ok()?;
    let mut buf = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .await
        .ok()?;
    Some(buf)
}

// Open build: rustls handshake (accept-any-cert). Its ClientHello is the
// fingerprint a WAF flags, but the open toolchain ships no browser emulation.
#[cfg(not(feature = "impersonate"))]
async fn send_tls(host: &str, port: u16, data: &[u8]) -> Option<Vec<u8>> {
    let connector = tokio_rustls::TlsConnector::from(tls_config());
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
    let stream = TcpStream::connect((host, port)).await.ok()?;
    let mut tls = connector.connect(server_name, stream).await.ok()?;
    tls.write_all(data).await.ok()?;
    tls.flush().await.ok()?;
    let mut buf = Vec::new();
    tls.take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .await
        .ok()?;
    Some(buf)
}

// First-party build: BoringSSL handshake with GREASE and a browser cipher/curve
// profile, so even the verbatim-path (`unsafe`) probes present a browser-family
// ClientHello rather than the flagged rustls one. Not byte-identical to the wreq
// scan-client profile - the raw sender is HTTP/1.1, so ALPN is `http/1.1` only -
// but a genuine BoringSSL browser-shaped handshake. Cert verification is off, to
// match the rest of cortex (it scans hosts with self-signed / mismatched certs).
#[cfg(feature = "impersonate")]
async fn send_tls(host: &str, port: u16, data: &[u8]) -> Option<Vec<u8>> {
    use boring2::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut b = SslConnector::builder(SslMethod::tls_client()).ok()?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_grease_enabled(true);
    let _ = b.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
         ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:\
         AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
    );
    let _ = b.set_curves_list("X25519:P-256:P-384");
    let _ = b.set_alpn_protos(b"\x08http/1.1");
    let connector = b.build();
    let mut cfg = connector.configure().ok()?;
    cfg.set_verify_hostname(false);
    let stream = TcpStream::connect((host, port)).await.ok()?;
    let mut tls = tokio_boring2::connect(cfg, host, stream).await.ok()?;
    tls.write_all(data).await.ok()?;
    tls.flush().await.ok()?;
    let mut buf = Vec::new();
    tls.take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .await
        .ok()?;
    Some(buf)
}

#[cfg(not(feature = "impersonate"))]
fn tls_config() -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("tls protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

/// Accept any certificate: cortex deliberately scans hosts with invalid certs,
/// matching the reqwest client's danger_accept_invalid_certs.
#[cfg(not(feature = "impersonate"))]
#[derive(Debug)]
struct NoVerify;

#[cfg(not(feature = "impersonate"))]
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

fn parse_response(raw: &[u8]) -> Option<RawResp> {
    let (head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let status = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;

    let mut headers = String::new();
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let name = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if name == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
            headers.push_str(&name);
            headers.push_str(": ");
            headers.push_str(val);
            headers.push('\n');
        }
    }
    let body_bytes = if chunked {
        dechunk(body)
    } else {
        body.to_vec()
    };
    Some(RawResp {
        status,
        headers,
        body: String::from_utf8_lossy(&body_bytes).into_owned(),
    })
}

fn split_head_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = find(raw, b"\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = find(raw, b"\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, &[])
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(i) = find(data, b"\r\n") {
        let size_line = String::from_utf8_lossy(&data[..i]);
        let size =
            usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("").trim(), 16)
                .unwrap_or(0);
        data = &data[i + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            out.extend_from_slice(data);
            break;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_preserves_dot_segments() {
        let (https, host, port, target) =
            split("http://example.com/cgi-bin/.%2e/.%2e/etc/passwd").unwrap();
        assert!(!https);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        // the traversal is untouched (url::Url would have flattened it)
        assert_eq!(target, "/cgi-bin/.%2e/.%2e/etc/passwd");
    }

    #[test]
    fn split_explicit_port_and_https() {
        let (https, host, port, target) = split("https://h.test:8443/a?b=1").unwrap();
        assert!(https);
        assert_eq!(host, "h.test");
        assert_eq!(port, 8443);
        assert_eq!(target, "/a?b=1");
    }

    #[test]
    fn dechunk_reassembles() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(body), b"Wikipedia");
    }
}

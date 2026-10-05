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
    // A template probe, so Verify::Any: cortex scans hosts whose certificates are
    // expired, self-signed or for another name, and refusing to look at them would
    // remove most internal applications from what it can test.
    let raw = tokio::time::timeout(req.timeout, async {
        if https {
            send_tls(
                &host,
                port,
                request.as_bytes(),
                ReadUntil::Closed,
                Verify::Any,
            )
            .await
        } else {
            send_plain(&host, port, request.as_bytes(), ReadUntil::Closed).await
        }
    })
    .await
    .ok()?
    .ok()?;
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
/// Where to stop reading a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadUntil {
    /// The connection closes.
    ///
    /// What a scanner wants, and deliberately so: bytes arriving after a response is
    /// framed-complete are the signal for request smuggling, and a reader that stopped at
    /// the declared length would throw the finding away. The cost is that a server
    /// keeping the connection alive, which is nearly all of them, is only finished with
    /// when the timeout expires.
    Closed,
    /// The response is complete by its own framing, plus a short grace period.
    ///
    /// What an interactive tool wants, because thirty seconds of "Sending" against a
    /// perfectly healthy keep-alive server is indistinguishable from a hung tool. The
    /// grace read is there so the smuggling signal is not lost either: anything that
    /// arrives after the framed response is still returned, it is simply not waited for
    /// indefinitely.
    Framed,
}

/// Whether the origin has to prove who it is.
///
/// cortex scans hosts with self-signed, expired and mismatched certificates on purpose,
/// so the scanners want [`Verify::Any`] and always have. An interactive send is a
/// different thing: it carries whatever the operator put in the request, which for a
/// replay is a stored credential for somebody else's account. Sending that to whatever
/// answers on the host, over a connection that accepts any certificate, is a
/// machine-in-the-middle's whole job done for it.
///
/// So the choice belongs to the caller rather than to this module. The capture proxy has
/// had exactly this setting per project since it existed; this is the same decision
/// reaching the paths that egress without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    /// Accept whatever the origin presents. Signature checking is still real; only the
    /// question of who the certificate belongs to is skipped.
    Any,
    /// The Mozilla webpki roots, and the hostname.
    WebPki,
}

/// Why a send produced no response.
///
/// An enum rather than a string because the caller is the one that knows what to suggest:
/// a TLS failure means something different to a scanner sweeping a range than it does to
/// an operator who just turned certificate checking on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendFail {
    /// No TCP connection.
    Connect(String),
    /// The TLS handshake failed. Under [`Verify::WebPki`] this is usually the
    /// certificate, and usually the point.
    Tls(String),
    /// Connected and sent, and nothing complete came back in time.
    Timeout,
    /// The exchange failed part way through.
    Io(String),
}

impl std::fmt::Display for SendFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendFail::Connect(e) => write!(f, "could not connect: {e}"),
            SendFail::Tls(e) => write!(f, "TLS handshake failed: {e}"),
            SendFail::Timeout => write!(f, "no response before the deadline"),
            SendFail::Io(e) => write!(f, "the connection failed mid-exchange: {e}"),
        }
    }
}

/// How long to keep listening after a response is framed-complete, for bytes that should
/// not be there.
const GRACE: Duration = Duration::from_millis(250);

/// Read one response, stopping where its own framing says it ends.
async fn read_framed<S>(s: &mut S) -> Option<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 16 * 1024];

    // Headers first, because nothing about the body is knowable until they are in.
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            // Closed before the headers finished. Return what there is: a truncated
            // response is a result, and often the interesting one.
            return Some(buf);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() as u64 > MAX_RESPONSE_BYTES {
            return Some(buf);
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);

    // These have no body whatever their headers claim, and waiting for one is how a
    // 304 hangs a tool for thirty seconds.
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return Some(buf);
    }

    if head.contains("transfer-encoding:") && head.contains("chunked") {
        // The terminal chunk. Not a perfect chunked parser: this is looking for the end
        // of a stream, not decoding it, and the decoded body is somebody else's job.
        loop {
            if buf[head_end..].windows(5).any(|w| w == b"0\r\n\r\n") {
                break;
            }
            let n = s.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() as u64 > MAX_RESPONSE_BYTES {
                break;
            }
        }
    } else if let Some(len) = head
        .split("content-length:")
        .nth(1)
        .and_then(|rest| rest.split(['\r', '\n']).next())
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        let want = head_end.saturating_add(len);
        while buf.len() < want {
            let n = s.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() as u64 > MAX_RESPONSE_BYTES {
                break;
            }
        }
    } else {
        // Neither length nor chunking, which means the body ends when the connection
        // does. This is the HTTP/1.0 shape and the one case where waiting is correct.
        loop {
            let n = s.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() as u64 > MAX_RESPONSE_BYTES {
                break;
            }
        }
        return Some(buf);
    }

    // A grace read for bytes that should not be there. A second response queued behind
    // the first is what a successful desync looks like, and dropping it because the
    // first one was complete would throw away the finding.
    let before = buf.len();
    let _ = tokio::time::timeout(GRACE, async {
        loop {
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() as u64 > MAX_RESPONSE_BYTES {
                        break;
                    }
                }
            }
        }
    })
    .await;
    if buf.len() > before {
        eprintln!(
            "rawhttp: {} byte(s) arrived after the response was complete",
            buf.len() - before
        );
    }
    Some(buf)
}

/// The scanners' sender: read to close, and accept any certificate.
///
/// Both of those are deliberate and neither is a default worth changing here. See
/// [`ReadUntil::Closed`] and [`Verify::Any`].
pub async fn send_exact(
    host: &str,
    port: u16,
    https: bool,
    data: &[u8],
    timeout: Duration,
) -> (Option<Vec<u8>>, Duration) {
    let (out, took) = send_until(
        host,
        port,
        https,
        data,
        timeout,
        ReadUntil::Closed,
        Verify::Any,
    )
    .await;
    (out.ok(), took)
}

/// Send these bytes and stop reading where the caller says to.
///
/// Returns why rather than nothing. A caller that puts the result in front of a person
/// has to be able to tell "nothing is listening there" from "the certificate did not
/// check out", because those send them to completely different places, and under
/// [`Verify::WebPki`] the second one is newly possible.
pub async fn send_until(
    host: &str,
    port: u16,
    https: bool,
    data: &[u8],
    timeout: Duration,
    until: ReadUntil,
    verify: Verify,
) -> (Result<Vec<u8>, SendFail>, Duration) {
    let start = std::time::Instant::now();
    let out = match tokio::time::timeout(timeout, async {
        if https {
            send_tls(host, port, data, until, verify).await
        } else {
            send_plain(host, port, data, until).await
        }
    })
    .await
    {
        Ok(r) => r,
        Err(_) => Err(SendFail::Timeout),
    };
    (out, start.elapsed())
}

/// Split a URL for the raw senders: (https, host, port, request-target).
pub fn split_url(url: &str) -> Option<(bool, String, u16, String)> {
    split(url)
}

async fn send_plain(
    host: &str,
    port: u16,
    data: &[u8],
    until: ReadUntil,
) -> Result<Vec<u8>, SendFail> {
    let mut stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| SendFail::Connect(e.to_string()))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| SendFail::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| SendFail::Io(e.to_string()))?;
    if until == ReadUntil::Framed {
        return read_framed(&mut stream)
            .await
            .ok_or_else(|| SendFail::Io("the response could not be read".into()));
    }
    let mut buf = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .await
        .map_err(|e| SendFail::Io(e.to_string()))?;
    Ok(buf)
}

// Open build: rustls handshake (accept-any-cert). Its ClientHello is the
// fingerprint a WAF flags, but the open toolchain ships no browser emulation.
#[cfg(not(feature = "impersonate"))]
async fn send_tls(
    host: &str,
    port: u16,
    data: &[u8],
    until: ReadUntil,
    verify: Verify,
) -> Result<Vec<u8>, SendFail> {
    let connector = tokio_rustls::TlsConnector::from(tls_config(verify));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| SendFail::Tls(format!("{host} is not a usable server name: {e}")))?;
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| SendFail::Connect(e.to_string()))?;
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| SendFail::Tls(e.to_string()))?;
    tls.write_all(data)
        .await
        .map_err(|e| SendFail::Io(e.to_string()))?;
    tls.flush().await.map_err(|e| SendFail::Io(e.to_string()))?;
    if until == ReadUntil::Framed {
        return read_framed(&mut tls)
            .await
            .ok_or_else(|| SendFail::Io("the response could not be read".into()));
    }
    let mut buf = Vec::new();
    tls.take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .await
        .map_err(|e| SendFail::Io(e.to_string()))?;
    Ok(buf)
}

// First-party build: BoringSSL handshake with GREASE and a browser cipher/curve
// profile, so even the verbatim-path (`unsafe`) probes present a browser-family
// ClientHello rather than the flagged rustls one. Not byte-identical to the wreq
// scan-client profile - the raw sender is HTTP/1.1, so ALPN is `http/1.1` only -
// but a genuine BoringSSL browser-shaped handshake. Cert verification is off, to
// match the rest of cortex (it scans hosts with self-signed / mismatched certs).
#[cfg(feature = "impersonate")]
async fn send_tls(
    host: &str,
    port: u16,
    data: &[u8],
    until: ReadUntil,
    verify: Verify,
) -> Result<Vec<u8>, SendFail> {
    use boring2::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut b =
        SslConnector::builder(SslMethod::tls_client()).map_err(|e| SendFail::Tls(e.to_string()))?;
    // The builder already loads the platform's trust store, so WebPki here means
    // leaving its verification alone rather than configuring anything.
    if verify == Verify::Any {
        b.set_verify(SslVerifyMode::NONE);
    }
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
    let mut cfg = connector
        .configure()
        .map_err(|e| SendFail::Tls(e.to_string()))?;
    if verify == Verify::Any {
        cfg.set_verify_hostname(false);
    }
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| SendFail::Connect(e.to_string()))?;
    let mut tls = tokio_boring2::connect(cfg, host, stream)
        .await
        .map_err(|e| SendFail::Tls(e.to_string()))?;
    tls.write_all(data)
        .await
        .map_err(|e| SendFail::Io(e.to_string()))?;
    tls.flush().await.map_err(|e| SendFail::Io(e.to_string()))?;
    if until == ReadUntil::Framed {
        return read_framed(&mut tls)
            .await
            .ok_or_else(|| SendFail::Io("the response could not be read".into()));
    }
    let mut buf = Vec::new();
    tls.take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .await
        .map_err(|e| SendFail::Io(e.to_string()))?;
    Ok(buf)
}

#[cfg(not(feature = "impersonate"))]
fn tls_config(verify: Verify) -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    // One cache per policy. Built once each, because a handshake config is expensive to
    // assemble and neither of these ever changes after the first call.
    static ANY: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static WEBPKI: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    match verify {
        Verify::Any => ANY.get_or_init(|| {
            let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("tls protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
            Arc::new(cfg)
        }),
        Verify::WebPki => WEBPKI.get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("tls protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(cfg)
        }),
    }
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

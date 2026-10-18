//! A local TLS origin that records what a client sends on its first
//! connection, and the fingerprints computed from it: JA3 and JA4 over the
//! ClientHello, and the Akamai HTTP/2 fingerprint over the connection preface.

pub mod hpack;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// The name the client is pointed at. It resolves to the listener through
/// `ClientConfig::resolve`, so the ClientHello carries it as the SNI.
pub const HOST: &str = "fingerprint.test";

pub const BODY: &str = "<!doctype html><title>ok</title><p>captured";

/// How the origin encodes the body it answers with.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Identity,
    Brotli,
}

/// What the client sent on the connection.
pub struct Capture {
    /// The ClientHello handshake message: type, length, body.
    pub client_hello: Vec<u8>,
    /// The protocol ALPN settled on.
    pub alpn: Option<Vec<u8>>,
    /// For HTTP/2, the preface and every frame up to the end of the first
    /// request's header block. For HTTP/1.1, the request head.
    pub request: Vec<u8>,
}

pub struct Origin {
    pub addr: SocketAddr,
    worker: JoinHandle<Capture>,
}

impl Origin {
    /// Listen on a loopback port, offering `alpn` in that order, and answer the
    /// first request with 200 and [`BODY`].
    pub fn start(alpn: &[&[u8]], encoding: Encoding) -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let config = server_config(alpn);
        let worker = std::thread::spawn(move || serve(listener, config, encoding));
        Origin { addr, worker }
    }

    pub fn url(&self) -> String {
        format!("https://{HOST}:{}/", self.addr.port())
    }

    /// Wait for the connection to finish and hand back what was recorded.
    pub fn finish(self) -> Capture {
        self.worker.join().expect("origin thread panicked")
    }
}

fn server_config(alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![HOST.to_string()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

fn serve(listener: TcpListener, config: Arc<rustls::ServerConfig>, encoding: Encoding) -> Capture {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut tcp = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("no client connected: {e}"),
        }
    };
    tcp.set_nonblocking(false).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let client_hello = peek_client_hello(&tcp);

    let mut conn = rustls::ServerConnection::new(config).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).expect("TLS handshake");
    }
    let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let body = match encoding {
        Encoding::Identity => BODY.as_bytes().to_vec(),
        Encoding::Brotli => brotli_compress(BODY.as_bytes()),
    };
    let request = if alpn.as_deref() == Some(b"h2") {
        let request = read_h2_request(&mut tls);
        let stream_id = H2Preface::parse(&request).headers_stream;
        tls.write_all(&h2_response(stream_id, encoding, &body))
            .unwrap();
        request
    } else {
        let request = read_http1_head(&mut tls);
        let mut head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n", body.len());
        if encoding == Encoding::Brotli {
            head.push_str("content-encoding: br\r\n");
        }
        head.push_str("connection: close\r\n\r\n");
        tls.write_all(head.as_bytes()).unwrap();
        tls.write_all(&body).unwrap();
        request
    };
    tls.flush().unwrap();

    // Let the client read the answer before the socket goes away: keep reading
    // until it closes, or for a moment.
    tls.sock
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut sink = [0u8; 4096];
    while matches!(tls.read(&mut sink), Ok(n) if n > 0) {}

    Capture {
        client_hello,
        alpn,
        request,
    }
}

/// The ClientHello, read without consuming it so the TLS server sees it too.
fn peek_client_hello(tcp: &TcpStream) -> Vec<u8> {
    let mut buf = vec![0u8; 1 << 16];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let n = tcp.peek(&mut buf).expect("peek");
        if let Some(hello) = handshake_message(&buf[..n]) {
            return hello;
        }
        assert!(Instant::now() < deadline, "no complete ClientHello");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The first handshake message from a run of TLS records, once all of it is
/// there.
fn handshake_message(records: &[u8]) -> Option<Vec<u8>> {
    let mut message = Vec::new();
    let mut p = 0;
    while p + 5 <= records.len() {
        assert_eq!(records[p], 22, "not a handshake record");
        let len = u16::from_be_bytes([records[p + 3], records[p + 4]]) as usize;
        if p + 5 + len > records.len() {
            return None;
        }
        message.extend_from_slice(&records[p + 5..p + 5 + len]);
        p += 5 + len;
        if message.len() >= 4 {
            let want = 4 + u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
            if message.len() >= want {
                message.truncate(want);
                return Some(message);
            }
        }
    }
    None
}

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn read_h2_request(tls: &mut impl Read) -> Vec<u8> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 16384];
    while !h2_headers_complete(&data) {
        let n = tls.read(&mut chunk).expect("read HTTP/2 request");
        assert!(n > 0, "client closed before its request");
        data.extend_from_slice(&chunk[..n]);
    }
    data
}

fn h2_headers_complete(data: &[u8]) -> bool {
    if data.len() < H2_PREFACE.len() {
        return false;
    }
    frames(&data[H2_PREFACE.len()..])
        .iter()
        .any(|f| (f.kind == 1 || f.kind == 9) && f.flags & 0x4 != 0)
}

fn read_http1_head(tls: &mut impl Read) -> Vec<u8> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tls.read(&mut chunk).expect("read HTTP/1.1 request");
        assert!(n > 0, "client closed before its request");
        data.extend_from_slice(&chunk[..n]);
    }
    data
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    f.push(kind);
    f.push(flags);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A literal header field without indexing, with a literal name (RFC 7541
/// section 6.2.2), so the answer needs no encoder state.
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![0x00, name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    out
}

fn h2_response(stream: u32, encoding: Encoding, body: &[u8]) -> Vec<u8> {
    // :status 200 is entry 8 of the static table.
    let mut block = vec![0x88];
    block.extend(literal("content-type", "text/html"));
    block.extend(literal("content-length", &body.len().to_string()));
    if encoding == Encoding::Brotli {
        block.extend(literal("content-encoding", "br"));
    }
    let mut out = h2_frame(4, 0, 0, &[]); // our SETTINGS, all defaults
    out.extend(h2_frame(4, 0x1, 0, &[])); // ACK of the client's
    out.extend(h2_frame(1, 0x4, stream, &block)); // HEADERS, END_HEADERS
    out.extend(h2_frame(0, 0x1, stream, body)); // DATA, END_STREAM
    out
}

fn brotli_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        w.write_all(data).unwrap();
    }
    out
}

// ---------------------------------------------------------------------------
// ClientHello
// ---------------------------------------------------------------------------

/// RFC 8701: GREASE values are 0x?A?A with both bytes equal.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

pub struct ClientHello {
    pub legacy_version: u16,
    pub session_id_len: usize,
    pub ciphers: Vec<u16>,
    /// (type, data) in the order sent.
    pub extensions: Vec<(u16, Vec<u8>)>,
}

impl ClientHello {
    pub fn parse(message: &[u8]) -> ClientHello {
        assert_eq!(message[0], 1, "not a ClientHello");
        let body = &message[4..];
        let mut p = 0;
        let legacy_version = u16::from_be_bytes([body[0], body[1]]);
        p += 2 + 32;
        let session_id_len = body[p] as usize;
        p += 1 + session_id_len;
        let cs_len = u16_at(body, p) as usize;
        p += 2;
        let ciphers = (0..cs_len / 2).map(|i| u16_at(body, p + 2 * i)).collect();
        p += cs_len;
        p += 1 + body[p] as usize;
        let ext_end = p + 2 + u16_at(body, p) as usize;
        p += 2;
        let mut extensions = Vec::new();
        while p < ext_end {
            let kind = u16_at(body, p);
            let len = u16_at(body, p + 2) as usize;
            extensions.push((kind, body[p + 4..p + 4 + len].to_vec()));
            p += 4 + len;
        }
        ClientHello {
            legacy_version,
            session_id_len,
            ciphers,
            extensions,
        }
    }

    pub fn extension(&self, kind: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, d)| d.as_slice())
    }

    pub fn extension_types(&self) -> Vec<u16> {
        self.extensions.iter().map(|(k, _)| *k).collect()
    }

    /// A list of u16s behind a two-byte length (supported_groups,
    /// signature_algorithms, delegated_credentials).
    pub fn u16_list(&self, kind: u16) -> Vec<u16> {
        let d = self.extension(kind).unwrap_or(&[0, 0]);
        let len = u16_at(d, 0) as usize;
        (0..len / 2).map(|i| u16_at(d, 2 + 2 * i)).collect()
    }

    /// supported_versions, behind a one-byte length.
    pub fn versions(&self) -> Vec<u16> {
        let d = self.extension(43).unwrap_or(&[0]);
        (0..d[0] as usize / 2)
            .map(|i| u16_at(d, 1 + 2 * i))
            .collect()
    }

    /// The groups key_share carries entries for, in order.
    pub fn key_shares(&self) -> Vec<u16> {
        let d = self.extension(51).unwrap_or(&[0, 0]);
        let end = 2 + u16_at(d, 0) as usize;
        let mut p = 2;
        let mut groups = Vec::new();
        while p < end {
            groups.push(u16_at(d, p));
            p += 4 + u16_at(d, p + 2) as usize;
        }
        groups
    }

    /// The protocols in an ALPN-shaped list (ALPN itself, and ALPS).
    pub fn protocol_list(&self, kind: u16) -> Vec<String> {
        let d = self.extension(kind).unwrap_or(&[0, 0]);
        let end = 2 + u16_at(d, 0) as usize;
        let mut p = 2;
        let mut out = Vec::new();
        while p < end {
            let len = d[p] as usize;
            out.push(String::from_utf8(d[p + 1..p + 1 + len].to_vec()).unwrap());
            p += 1 + len;
        }
        out
    }

    /// compress_certificate, behind a one-byte length.
    pub fn cert_compression(&self) -> Vec<u16> {
        let d = self.extension(27).unwrap_or(&[0]);
        (0..d[0] as usize / 2)
            .map(|i| u16_at(d, 1 + 2 * i))
            .collect()
    }

    /// JA3 before hashing: version, ciphers, extensions, groups, point formats,
    /// GREASE left out.
    pub fn ja3_text(&self) -> String {
        let join = |v: Vec<u16>| {
            v.into_iter()
                .filter(|x| !is_grease(*x))
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        let formats = self
            .extension(11)
            .map(|d| {
                d[1..=d[0] as usize]
                    .iter()
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>()
                    .join("-")
            })
            .unwrap_or_default();
        format!(
            "{},{},{},{},{}",
            self.legacy_version,
            join(self.ciphers.clone()),
            join(self.extension_types()),
            join(self.u16_list(10)),
            formats
        )
    }

    pub fn ja4(&self) -> String {
        let version = self
            .versions()
            .into_iter()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version);
        let alpn = self.protocol_list(16).into_iter().next();
        ja4(
            version,
            self.extension(0).is_some(),
            alpn.as_deref(),
            &self.ciphers,
            &self.extension_types(),
            &self.u16_list(13),
        )
    }
}

fn u16_at(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}

/// JA4 for TLS over TCP, as the FoxIO specification defines it
/// (github.com/FoxIO-LLC/ja4, technical_details/JA4.md).
pub fn ja4(
    version: u16,
    sni: bool,
    first_alpn: Option<&str>,
    ciphers: &[u16],
    extensions: &[u16],
    sigalgs: &[u16],
) -> String {
    let hash = |s: &str| -> String {
        Sha256::digest(s.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()[..12]
            .to_string()
    };
    let hex = |v: &[u16]| v.iter().map(|x| format!("{x:04x}")).collect::<Vec<_>>();
    let ciphers: Vec<u16> = ciphers.iter().copied().filter(|c| !is_grease(*c)).collect();
    let extensions: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let sigalgs: Vec<u16> = sigalgs.iter().copied().filter(|s| !is_grease(*s)).collect();

    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let alpn = match first_alpn {
        Some(a) if !a.is_empty() => {
            let (f, l) = (a.chars().next().unwrap(), a.chars().last().unwrap());
            if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
                format!("{f}{l}")
            } else {
                let h = a.bytes().map(|b| format!("{b:02x}")).collect::<String>();
                format!("{}{}", &h[..1], &h[h.len() - 1..])
            }
        }
        _ => "00".to_string(),
    };
    let a = format!(
        "t{version}{}{:02}{:02}{alpn}",
        if sni { "d" } else { "i" },
        ciphers.len().min(99),
        extensions.len().min(99)
    );

    let mut sorted_ciphers = hex(&ciphers);
    sorted_ciphers.sort();
    let b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        hash(&sorted_ciphers.join(","))
    };

    let mut sorted_exts = hex(&extensions
        .into_iter()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect::<Vec<_>>());
    sorted_exts.sort();
    let mut c_input = sorted_exts.join(",");
    if !sigalgs.is_empty() {
        c_input.push('_');
        c_input.push_str(&hex(&sigalgs).join(","));
    }
    let c = if sorted_exts.is_empty() {
        "000000000000".to_string()
    } else {
        hash(&c_input)
    };
    format!("{a}_{b}_{c}")
}

// ---------------------------------------------------------------------------
// HTTP/2
// ---------------------------------------------------------------------------

pub struct Frame {
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}

/// Every complete frame in `data`.
pub fn frames(data: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    let mut p = 0;
    while p + 9 <= data.len() {
        let len = u32::from_be_bytes([0, data[p], data[p + 1], data[p + 2]]) as usize;
        if p + 9 + len > data.len() {
            break;
        }
        out.push(Frame {
            kind: data[p + 3],
            flags: data[p + 4],
            stream: u32::from_be_bytes([data[p + 5], data[p + 6], data[p + 7], data[p + 8]])
                & 0x7fff_ffff,
            payload: data[p + 9..p + 9 + len].to_vec(),
        });
        p += 9 + len;
    }
    out
}

/// The priority a HEADERS frame carries: (exclusive, depends on, weight byte).
pub type HeadersPriority = (bool, u32, u8);

pub struct H2Preface {
    /// SETTINGS (id, value) in the order sent.
    pub settings: Vec<(u16, u32)>,
    /// The increment of the first WINDOW_UPDATE on stream 0.
    pub window_update: Option<u32>,
    /// PRIORITY frames as stream:exclusive:dependency:weight.
    pub priority_frames: Vec<String>,
    pub headers_stream: u32,
    pub headers_priority: Option<HeadersPriority>,
    /// The first request's header fields, pseudo-headers included, in order.
    pub headers: Vec<(String, String)>,
}

impl H2Preface {
    pub fn parse(data: &[u8]) -> H2Preface {
        assert!(data.starts_with(H2_PREFACE), "no HTTP/2 connection preface");
        let mut settings = Vec::new();
        let mut window_update = None;
        let mut priority_frames = Vec::new();
        let mut headers_stream = 0;
        let mut headers_priority = None;
        let mut block = Vec::new();
        let mut in_headers = false;
        for f in frames(&data[H2_PREFACE.len()..]) {
            match f.kind {
                4 if f.flags & 0x1 == 0 => {
                    for c in f.payload.chunks(6) {
                        settings.push((
                            u16::from_be_bytes([c[0], c[1]]),
                            u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                        ));
                    }
                }
                8 if f.stream == 0 && window_update.is_none() => {
                    window_update = Some(
                        u32::from_be_bytes([
                            f.payload[0],
                            f.payload[1],
                            f.payload[2],
                            f.payload[3],
                        ]) & 0x7fff_ffff,
                    );
                }
                2 => {
                    let dep = u32::from_be_bytes([
                        f.payload[0],
                        f.payload[1],
                        f.payload[2],
                        f.payload[3],
                    ]);
                    priority_frames.push(format!(
                        "{}:{}:{}:{}",
                        f.stream,
                        dep >> 31,
                        dep & 0x7fff_ffff,
                        f.payload[4]
                    ));
                }
                1 if headers_stream == 0 => {
                    headers_stream = f.stream;
                    let mut p = 0;
                    let mut end = f.payload.len();
                    if f.flags & 0x8 != 0 {
                        end -= f.payload[0] as usize;
                        p += 1;
                    }
                    if f.flags & 0x20 != 0 {
                        let dep = u32::from_be_bytes([
                            f.payload[p],
                            f.payload[p + 1],
                            f.payload[p + 2],
                            f.payload[p + 3],
                        ]);
                        headers_priority =
                            Some((dep >> 31 == 1, dep & 0x7fff_ffff, f.payload[p + 4]));
                        p += 5;
                    }
                    block.extend_from_slice(&f.payload[p..end]);
                    in_headers = f.flags & 0x4 == 0;
                }
                9 if in_headers => {
                    block.extend_from_slice(&f.payload);
                    in_headers = f.flags & 0x4 == 0;
                }
                _ => {}
            }
        }
        H2Preface {
            settings,
            window_update,
            priority_frames,
            headers_stream,
            headers_priority,
            headers: hpack::decode(&block),
        }
    }

    /// The Akamai fingerprint: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header
    /// order, as the 2017 Akamai white paper "Passive Fingerprinting of HTTP/2
    /// Clients" lays it out.
    pub fn akamai(&self) -> String {
        let settings = self
            .settings
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(";");
        let window = self
            .window_update
            .map_or("00".to_string(), |w| w.to_string());
        let priority = if self.priority_frames.is_empty() {
            "0".to_string()
        } else {
            self.priority_frames.join(",")
        };
        let pseudo = self
            .headers
            .iter()
            .filter_map(|(n, _)| n.strip_prefix(':').map(|p| &p[..1]))
            .collect::<Vec<_>>()
            .join(",");
        format!("{settings}|{window}|{priority}|{pseudo}")
    }

    /// The regular header names, in order.
    pub fn header_names(&self) -> Vec<&str> {
        self.headers
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| !n.starts_with(':'))
            .collect()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

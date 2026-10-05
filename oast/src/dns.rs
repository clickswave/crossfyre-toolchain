//! Minimal authoritative DNS responder. DNS out-of-band is the gold standard for
//! blind detection: many payloads can trigger a DNS lookup even when outbound HTTP
//! is filtered. We only need to (1) log the queried name (which carries the token)
//! and (2) return a valid A answer so the resolver is satisfied.
//!
//! The parser is deliberately small and bounds-checked; any malformed packet is
//! dropped without a response rather than trusted.

use crate::Config;
use crate::store::{Interaction, Store, now_unix};
use std::sync::Arc;
use tokio::net::UdpSocket;

pub async fn serve(
    cfg: Config,
    store: Arc<Store>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sock = UdpSocket::bind(&cfg.dns_addr).await?;
    tracing::info!("oast dns responder on {}", cfg.dns_addr);
    let mut buf = [0u8; 512];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let Some((qname, resp)) = handle_query(&buf[..n], &cfg) else {
            continue;
        };
        let ql = qname.to_ascii_lowercase();
        if let Some(corr) = crate::store::corr_from_any(&ql, &cfg.domains) {
            store.capture(
                &corr,
                &Interaction {
                    protocol: "dns".to_string(),
                    full_host: ql,
                    remote_addr: peer.ip().to_string(),
                    at_unix: now_unix(),
                    detail: format!("DNS {qname}"),
                    raw: String::new(),
                },
            );
        }
        let _ = sock.send_to(&resp, peer).await;
    }
}

/// Parse a DNS query and build a response, returning (qname, response_bytes).
fn handle_query(q: &[u8], cfg: &Config) -> Option<(String, Vec<u8>)> {
    if q.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([q[4], q[5]]);
    if qdcount < 1 {
        return None;
    }
    let (qname, after_name) = read_name(q, 12)?;
    if after_name + 4 > q.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([q[after_name], q[after_name + 1]]);
    let q_end = after_name + 4; // QTYPE(2) + QCLASS(2)

    // ACME DNS-01: since we are authoritative for the delegated zone, we answer the
    // wildcard cert's `_acme-challenge` TXT ourselves, from a value lego writes.
    let is_acme = qname.to_ascii_lowercase().starts_with("_acme-challenge");
    let acme_txt: Option<String> = if qtype == 16 && is_acme {
        cfg.acme_txt_file
            .as_ref()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty() && v.len() <= 255)
    } else {
        None
    };
    let answer_a = qtype == 1 && !is_acme;
    let ancount: u16 = if answer_a || acme_txt.is_some() { 1 } else { 0 };

    let mut resp = Vec::with_capacity(q_end + 32);
    resp.extend_from_slice(&q[0..2]); // ID (echo)
    let rd = q[2] & 0x01; // preserve RD bit
    resp.push(0x84 | rd); // QR=1, AA=1, (+RD)
    resp.push(0x00); // RA=0, RCODE=0
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    resp.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    resp.extend_from_slice(&q[12..q_end]); // echo the question

    if let Some(txt) = acme_txt {
        let vb = txt.as_bytes();
        resp.extend_from_slice(&[0xC0, 0x0C]); // NAME -> pointer to offset 12
        resp.extend_from_slice(&[0x00, 0x10]); // TYPE TXT (16)
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x1E]); // TTL 30s
        resp.extend_from_slice(&((vb.len() + 1) as u16).to_be_bytes()); // RDLENGTH
        resp.push(vb.len() as u8); // TXT string length
        resp.extend_from_slice(vb);
    } else if answer_a {
        resp.extend_from_slice(&[0xC0, 0x0C]); // NAME -> pointer to offset 12
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x1E]); // TTL 30s
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        resp.extend_from_slice(&cfg.public_ip);
    }

    Some((qname, resp))
}

/// Read an uncompressed DNS name starting at `start`, returning (name, index just
/// past the terminating zero byte). Rejects compression pointers (not valid in a
/// question) and bounds-checks every label.
fn read_name(q: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut i = start;
    let mut labels = 0;
    loop {
        if i >= q.len() {
            return None;
        }
        let len = q[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer not allowed here
        }
        labels += 1;
        if labels > 127 {
            return None;
        }
        i += 1;
        if i + len > q.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &q[i..i + len] {
            // Keep it to a safe, log-friendly charset.
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                name.push(b as char);
            } else {
                name.push('.');
            }
        }
        i += len;
    }
    Some((name, i))
}

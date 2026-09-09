//! Zone transfer (AXFR): ask a nameserver for the whole zone.
//!
//! A nameserver that answers AXFR to anyone hands over every record it holds -
//! the internal hostnames, the staging and admin names nobody links to, the
//! mail and VPN endpoints, often the internal addressing scheme. It is one of
//! the oldest misconfigurations there is and it still turns up, and when it
//! does it replaces the whole brute-force phase: no wordlist finds what the
//! zone will simply tell you.
//!
//! Passive sources cannot see a zone that was never published, and active
//! brute force only finds names a wordlist happens to contain, so without this
//! an internal or split-horizon zone was out of reach entirely.
//!
//! The transfer is a read. It asks each of the zone's authoritative servers in
//! turn, over TCP as the protocol requires, and stops at the closing SOA.

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::TokioResolver;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// One server's answer to an AXFR request.
pub struct Transfer {
    /// Names the zone gave up, deduplicated and sorted.
    pub names: Vec<String>,
    /// Why it did not work, when it did not.
    pub refused: Option<String>,
}

/// The zone's authoritative nameservers, resolved to addresses. `port` is the
/// port to talk to them on (53 everywhere except a lab or a split horizon).
pub async fn authoritative(
    resolver: &TokioResolver,
    zone: &str,
    port: u16,
) -> Vec<(String, SocketAddr)> {
    let mut out: Vec<(String, SocketAddr)> = Vec::new();
    let Ok(name) = Name::from_utf8(zone) else {
        return out;
    };
    let Ok(ns) = resolver.lookup(name, RecordType::NS).await else {
        return out;
    };
    for rec in ns.answers() {
        let hickory_proto::rr::RData::NS(target) = &rec.data else {
            continue;
        };
        let host = target.0.to_utf8().trim_end_matches('.').to_string();
        if let Ok(ips) = resolver.lookup_ip(host.clone()).await {
            for ip in ips.iter() {
                out.push((host.clone(), SocketAddr::new(ip, port)));
            }
        }
    }
    out
}

/// Attempt a transfer of `zone` from one server.
pub async fn transfer(zone: &str, server: SocketAddr, timeout: Duration) -> Transfer {
    let fail = |why: String| Transfer {
        names: Vec::new(),
        refused: Some(why),
    };

    let Ok(name) = Name::from_utf8(zone) else {
        return fail(format!("invalid zone name '{zone}'"));
    };
    let mut msg = Message::query();
    msg.add_query(Query::query(name.clone(), RecordType::AXFR));
    let Ok(bytes) = msg.to_vec() else {
        return fail("could not encode the AXFR query".into());
    };

    let conn = match tokio::time::timeout(timeout, TcpStream::connect(server)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return fail(format!("connect failed: {e}")),
        Err(_) => return fail("connect timed out".into()),
    };
    let mut conn = conn;
    // DNS over TCP frames each message with a two-byte length.
    let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&bytes);
    if tokio::time::timeout(timeout, conn.write_all(&framed))
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        return fail("write failed".into());
    }

    let mut names: Vec<String> = Vec::new();
    let mut soa_seen = 0usize;
    let mut refused = None;
    // A transfer arrives as a sequence of messages that opens and closes with
    // the zone's SOA. Read until the closing one, or until the server stops.
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(timeout, conn.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let n = u16::from_be_bytes(len) as usize;
        if n == 0 || n > 65535 {
            break;
        }
        let mut buf = vec![0u8; n];
        match tokio::time::timeout(timeout, conn.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let Ok(reply) = Message::from_vec(&buf) else {
            break;
        };
        let code = reply.metadata.response_code;
        if code != hickory_proto::op::ResponseCode::NoError {
            refused = Some(format!("server answered {code}"));
            break;
        }
        for rec in reply.answers.iter() {
            if rec.record_type() == RecordType::SOA {
                soa_seen += 1;
            }
            let n = rec.name.to_utf8().trim_end_matches('.').to_string();
            if !n.is_empty() {
                names.push(n);
            }
        }
        if soa_seen >= 2 {
            break;
        }
    }

    names.sort();
    names.dedup();
    if names.is_empty() && refused.is_none() {
        refused = Some("no records returned (transfer refused or empty)".into());
    }
    Transfer { names, refused }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unreachable_server_is_reported_not_swallowed() {
        // Port 1 on loopback: nothing listens, so this must come back refused
        // with a reason rather than as an empty success.
        let t = transfer(
            "example.test",
            "127.0.0.1:1".parse().unwrap(),
            Duration::from_millis(500),
        )
        .await;
        assert!(t.names.is_empty());
        assert!(t.refused.is_some());
    }

    #[tokio::test]
    async fn an_invalid_zone_name_fails_fast() {
        let t = transfer(
            "not a name",
            "127.0.0.1:1".parse().unwrap(),
            Duration::from_millis(500),
        )
        .await;
        assert!(t.refused.unwrap().contains("invalid zone"));
    }
}

//! Read the server name out of a TLS ClientHello without terminating the connection.
//!
//! Interception is not always the right answer. An app that pins its API refuses
//! the certificate and the request fails, so capture does not merely miss that
//! traffic, it BREAKS the app: the feature under test stops working and the
//! operator is left comparing a broken app against a blank Requests tab. The
//! only honest options are to intercept a host or to carry it through untouched,
//! and choosing between them needs the hostname.
//!
//! The destination IP cannot make that choice. One address serves thousands of
//! names behind a CDN, and the two hosts an operator wants to treat differently
//! routinely share one. The name is in the ClientHello, in the clear, before any
//! decision has to be made, so it is read here and the bytes are replayed
//! verbatim to whichever path wins.
//!
//! Deliberately tolerant: this parses attacker-controlled bytes off a hostile
//! network, so every read is bounds-checked and any malformed record yields
//! `None` (meaning "no name, intercept as usual") rather than an error or a
//! panic.

/// Extract the SNI host from a buffer that begins with a TLS ClientHello.
///
/// `None` when the buffer is not a ClientHello, is truncated, or carries no
/// server_name extension. Callers treat that as "no opinion".
pub fn server_name(buf: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2), then the handshake message.
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let body = buf.get(5..5 + rec_len.min(buf.len().saturating_sub(5)))?;

    // Handshake: type(1) length(3) version(2) random(32) ...
    if body.first()? != &0x01 {
        return None;
    }
    let mut p = 4 + 2 + 32;
    // session_id
    let sid = *body.get(p)? as usize;
    p += 1 + sid;
    // cipher_suites
    let cs = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2 + cs;
    // compression_methods
    let cm = *body.get(p)? as usize;
    p += 1 + cm;
    // extensions
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + ext_total).min(body.len());

    while p + 4 <= end {
        let etype = u16::from_be_bytes([body[p], body[p + 1]]);
        let elen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if etype == 0x0000 {
            // server_name: list_len(2), then entries of type(1) len(2) bytes.
            let e = body.get(p..p + elen)?;
            if e.len() < 5 {
                return None;
            }
            let name_len = u16::from_be_bytes([e[3], e[4]]) as usize;
            let name = e.get(5..5 + name_len)?;
            return std::str::from_utf8(name)
                .ok()
                .map(|s| s.to_ascii_lowercase());
        }
        p += elen;
    }
    None
}

/// Whether `host` is covered by a bypass entry.
///
/// An entry matches the exact host, or any subdomain when written as a bare
/// domain: `example.com` covers `api.example.com`. Operators think in sites, not
/// in individual certificate names, and a pinned API is rarely on the apex.
pub fn is_bypassed(host: &str, bypass: &[String]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    bypass.iter().any(|raw| {
        let b = raw.trim().trim_start_matches('.').to_ascii_lowercase();
        !b.is_empty() && (h == b || h.ends_with(&format!(".{b}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally real ClientHello carrying `name`.
    fn hello(name: &str) -> Vec<u8> {
        let mut ext = vec![0x00, 0x00]; // server_name
        let mut sni = vec![0x00]; // host_name type
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name.as_bytes());
        let mut list = (sni.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&sni);
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn reads_the_name_out_of_a_client_hello() {
        assert_eq!(
            server_name(&hello("api.example.com")).as_deref(),
            Some("api.example.com")
        );
    }

    #[test]
    fn a_truncated_hello_yields_no_opinion() {
        // A short read must not panic and must not claim a name it never saw.
        let full = hello("api.example.com");
        for cut in [0, 1, 5, 20, full.len() - 3] {
            assert_eq!(server_name(&full[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn plaintext_http_is_not_a_client_hello() {
        assert_eq!(server_name(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None);
    }

    #[test]
    fn bypass_matches_the_host_and_its_subdomains() {
        let b = vec!["example.com".to_string()];
        assert!(is_bypassed("example.com", &b));
        assert!(is_bypassed("api.example.com", &b));
        assert!(is_bypassed("API.Example.Com.", &b));
        // Not a suffix match on the raw string: this is the classic bug that
        // would carry notexample.com through untouched.
        assert!(!is_bypassed("notexample.com", &b));
        assert!(!is_bypassed("example.com.evil.test", &b));
    }

    #[test]
    fn an_empty_bypass_list_bypasses_nothing() {
        assert!(!is_bypassed("api.example.com", &[]));
        assert!(!is_bypassed(
            "api.example.com",
            &["".to_string(), "   ".to_string()]
        ));
    }
}

//! Decoding captured bodies into something a human can read.
//!
//! A MITM proxy sees exactly what went over the wire, and what goes over the
//! wire is compressed. Firebase, most JSON APIs and effectively every modern
//! site answer with `content-encoding: gzip` (or `br`, increasingly `zstd`), so
//! the raw bytes are a deflate stream. Handing those to `from_utf8_lossy`
//! produces the mojibake that made the Requests tab useless even once rows
//! started being stored.
//!
//! This has to happen HERE, on the capture side, and not at ingest. The lossy
//! UTF-8 conversion is destructive: once a gzip stream has been through it the
//! original bytes are gone and no amount of server-side cleverness gets them
//! back. The server only ever receives a String.
//!
//! Decoding is best-effort by design. A body that is truncated, mislabelled, or
//! genuinely binary is kept exactly as captured rather than dropped, because a
//! recognisable blob is worth more to someone reading a trace than a blank
//! field. The one thing not negotiable is the output ceiling: this is a
//! security tool pointed at hostile servers, and a few hundred bytes of gzip
//! expands to gigabytes if you let it.

/// Ceiling on decoded output. A compression bomb is a real answer for a target
/// to give a scanner, and the decoded body is held in memory on a phone. Bodies
/// beyond this keep their original bytes.
const MAX_DECODED: usize = 8 * 1024 * 1024;

/// Read a header value case-insensitively out of captured `[name, value]` pairs.
fn header<'a>(headers: &'a [[String; 2]], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|kv| kv[0].eq_ignore_ascii_case(name))
        .map(|kv| kv[1].as_str())
}

fn read_capped<R: std::io::Read>(mut r: R) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut out = Vec::new();
    // One byte past the ceiling tells "exactly at the limit" from "ran over".
    match std::io::Read::take(&mut r, (MAX_DECODED + 1) as u64).read_to_end(&mut out) {
        Ok(_) if out.len() <= MAX_DECODED => Some(out),
        _ => None,
    }
}

fn gunzip(b: &[u8]) -> Option<Vec<u8>> {
    read_capped(flate2::read::GzDecoder::new(b))
}

fn inflate(b: &[u8]) -> Option<Vec<u8>> {
    // `deflate` is ambiguous in the wild: the RFC says zlib-wrapped, plenty of
    // servers send it raw. Try the spec first, then the common violation.
    read_capped(flate2::read::ZlibDecoder::new(b))
        .or_else(|| read_capped(flate2::read::DeflateDecoder::new(b)))
}

fn unbrotli(b: &[u8]) -> Option<Vec<u8>> {
    read_capped(brotli::Decompressor::new(b, 8192))
}

fn unzstd(b: &[u8]) -> Option<Vec<u8>> {
    read_capped(zstd::stream::read::Decoder::new(b).ok()?)
}

/// Decode one coding. `None` means "could not", never "empty".
fn decode_one(coding: &str, body: &[u8]) -> Option<Vec<u8>> {
    match coding {
        "gzip" | "x-gzip" => gunzip(body),
        "deflate" => inflate(body),
        "br" => unbrotli(body),
        "zstd" => unzstd(body),
        // `identity` is a no-op, and anything unrecognised is left alone.
        "identity" | "" => Some(body.to_vec()),
        _ => None,
    }
}

/// Decode a captured body according to its own `content-encoding`.
///
/// Returns the decoded bytes and whether anything actually changed. Encodings
/// are listed in the order they were applied, so they come off in reverse. If
/// any step fails the ORIGINAL body is returned untouched: a half-decoded body
/// is worse than a compressed one, because it looks like corruption rather than
/// like something that needs a decoder.
pub fn decode(body: &[u8], headers: &[[String; 2]]) -> (Vec<u8>, bool) {
    let Some(raw) = header(headers, "content-encoding") else {
        return (body.to_vec(), false);
    };
    let codings: Vec<String> = raw
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty() && c != "identity")
        .collect();
    if codings.is_empty() {
        return (body.to_vec(), false);
    }
    let mut cur = body.to_vec();
    for coding in codings.iter().rev() {
        match decode_one(coding, &cur) {
            Some(next) => cur = next,
            None => {
                log::debug!("capture: leaving body as captured, {coding} decode failed");
                return (body.to_vec(), false);
            }
        }
    }
    (cur, true)
}

/// Drop `content-encoding` and restate `content-length` on a header set whose
/// body we decoded.
///
/// Without this the stored exchange contradicts itself: headers claiming gzip
/// over a body that is now plain JSON. That is not just untidy, it breaks the
/// Repeater, which replays the stored request as-is and would tell the origin
/// to gunzip something that was never gzipped.
pub fn strip_encoding_headers(headers: &mut Vec<[String; 2]>, decoded_len: usize) {
    headers.retain(|kv| !kv[0].eq_ignore_ascii_case("content-encoding"));
    for kv in headers.iter_mut() {
        if kv[0].eq_ignore_ascii_case("content-length") {
            kv[1] = decoded_len.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn hdrs(enc: &str) -> Vec<[String; 2]> {
        vec![
            ["content-type".into(), "application/json".into()],
            ["Content-Encoding".into(), enc.into()],
            ["content-length".into(), "999".into()],
        ]
    }

    fn gz(s: &str) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(s.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_body_comes_back_as_text() {
        // The exact shape that made the Requests tab unreadable: a JSON API
        // answering with content-encoding: gzip.
        let want = r#"{"name":"projects/aculogic-405f8/installations/abc"}"#;
        let (out, decoded) = decode(&gz(want), &hdrs("gzip"));
        assert!(decoded);
        assert_eq!(String::from_utf8(out).unwrap(), want);
    }

    #[test]
    fn header_name_case_does_not_matter() {
        // Captured headers keep the server's casing, and HTTP/1 servers send
        // `Content-Encoding`. Matching case-sensitively would silently skip
        // decoding for most of the web.
        let (_, decoded) = decode(&gz("hi"), &hdrs("GZIP"));
        assert!(decoded);
    }

    #[test]
    fn brotli_and_zstd_round_trip() {
        let want = "hello brotli";
        let mut enc = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut enc, 4096, 5, 22);
            w.write_all(want.as_bytes()).unwrap();
        }
        let (out, decoded) = decode(&enc, &hdrs("br"));
        assert!(decoded);
        assert_eq!(String::from_utf8(out).unwrap(), want);

        let want = "hello zstd";
        let enc = zstd::stream::encode_all(want.as_bytes(), 3).unwrap();
        let (out, decoded) = decode(&enc, &hdrs("zstd"));
        assert!(decoded);
        assert_eq!(String::from_utf8(out).unwrap(), want);
    }

    #[test]
    fn an_uncompressed_body_is_untouched() {
        let body = b"{\"plain\":true}";
        let (out, decoded) = decode(body, &[["content-type".into(), "application/json".into()]]);
        assert!(!decoded);
        assert_eq!(out, body);
    }

    #[test]
    fn a_body_that_lies_about_its_encoding_is_kept_as_captured() {
        // Mislabelled or truncated bodies are common on a proxy. Keeping the
        // original beats storing nothing, and beats storing half a stream.
        let body = b"this is not gzip at all";
        let (out, decoded) = decode(body, &hdrs("gzip"));
        assert!(!decoded);
        assert_eq!(out, body);
    }

    #[test]
    fn a_decompression_bomb_is_refused() {
        // 100 MB of zeroes compresses to a few KB. The scanner must not try to
        // hold the expansion, least of all on a phone.
        let bomb = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            e.write_all(&vec![0u8; 100 * 1024 * 1024]).unwrap();
            e.finish().unwrap()
        };
        assert!(bomb.len() < 200_000, "bomb should be small: {}", bomb.len());
        let (out, decoded) = decode(&bomb, &hdrs("gzip"));
        assert!(!decoded, "an over-sized body must not be expanded");
        assert_eq!(out, bomb);
    }

    #[test]
    fn decoding_restates_the_headers_it_invalidated() {
        let mut h = hdrs("gzip");
        strip_encoding_headers(&mut h, 42);
        assert!(
            !h.iter()
                .any(|kv| kv[0].eq_ignore_ascii_case("content-encoding"))
        );
        assert_eq!(header(&h, "content-length"), Some("42"));
        assert_eq!(header(&h, "content-type"), Some("application/json"));
    }
}

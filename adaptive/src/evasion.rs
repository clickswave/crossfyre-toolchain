//! Payload-level WAF evasion.
//!
//! Given a concrete request-target (and optional body) that a signature WAF just
//! blocked, produce alternative encodings of it that preserve the payload's effect
//! on the origin while changing what the WAF sees. The caller sends the original
//! first and only reaches for these when the original looks blocked; the engine's
//! confirm-then-report pipeline then validates which (if any) variant actually
//! reproduced the finding, so a broken encoding is simply a wasted request, never
//! a false positive.
//!
//! This is the PUBLIC baseline: a few standard, transparent transforms. The tuned
//! ordering and the richer set (keyword case folding, comment injection, unicode
//! and mixed encodings, parameter pollution) live in the private drop-in, because
//! the exact mutation policy is what a WAF vendor would want to fingerprint.

/// Split a URL into (scheme://authority, path+query). Mutations only touch the
/// second half so the host is never mangled.
fn split_authority(url: &str) -> (&str, &str) {
    if let Some(after_scheme) = url.find("://").map(|i| i + 3) {
        if let Some(slash) = url[after_scheme..].find('/') {
            let idx = after_scheme + slash;
            return (&url[..idx], &url[idx..]);
        }
        return (url, "");
    }
    ("", url)
}

/// Percent-encode the characters a signature WAF keys on for XSS/SQLi/command
/// injection, leaving URL structure (`/?=&`) intact so the request still routes.
fn percent_encode_specials(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' | '>' | '\'' | '"' | '(' | ')' | ';' | ' ' | '`' | '|' | '{' | '}' => {
                for b in c.to_string().as_bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Encode path-traversal separators the way that slips past a `../` signature but
/// is still normalised by the origin (Apache CVE-2021-41773 and friends).
fn encode_traversal(s: &str) -> String {
    s.replace("../", "..%2f").replace("..\\", "..%5c")
}

/// Double-encode traversal so a WAF that decodes once still sees a literal, while
/// an origin that decodes twice resolves the path.
fn double_encode_traversal(s: &str) -> String {
    s.replace("../", "%252e%252e%252f")
        .replace("..\\", "%252e%252e%255c")
}

/// Produce up to `max` alternative encodings of the request. Returns `(url, body)`
/// pairs that differ from the input; the original is never included.
pub fn variants(url: &str, body: Option<&str>, max: usize) -> Vec<(String, Option<String>)> {
    if let Some(v) = from_module(url, body, max) {
        return v;
    }
    let (authority, tail) = split_authority(url);
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut push = |new_tail: String| {
        if new_tail != tail {
            out.push((
                format!("{authority}{new_tail}"),
                body.map(|b| b.to_string()),
            ));
        }
    };

    push(percent_encode_specials(tail));
    push(encode_traversal(tail));
    push(double_encode_traversal(tail));
    // Combined: encode specials on top of single-encoded traversal.
    push(percent_encode_specials(&encode_traversal(tail)));

    // If there is a form-style body, offer a specials-encoded body variant too
    // (harmless on non-form bodies: a mismatch just fails the matcher).
    if let Some(b) = body {
        let enc = percent_encode_specials(b);
        if enc != b {
            out.push((url.to_string(), Some(enc)));
        }
    }

    out.dedup();
    out.truncate(max);
    out
}

/// The installed module's variants, held to the request: at most `max`, none equal
/// to it, each to the same scheme, host and port, each no longer than four times its
/// part of the original and a little more, and none carrying a control character.
/// None without a module or a readable answer, or for a URL without an authority.
fn from_module(url: &str, body: Option<&str>, max: usize) -> Option<Vec<(String, Option<String>)>> {
    #[derive(serde::Serialize)]
    struct Ask<'a> {
        url: &'a str,
        body: Option<&'a str>,
        max: usize,
    }
    let (authority, _) = split_authority(url);
    if authority.is_empty() || !crate::backend::installed() {
        return None;
    }
    let asked: Vec<(String, Option<String>)> =
        crate::backend::ask("evasion.variants", &Ask { url, body, max })?;
    let room = |original: usize| original.saturating_mul(4).saturating_add(64);
    let clean = |s: &str| !s.chars().any(char::is_control);
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for (u, b) in asked {
        let same_place = split_authority(&u).0 == authority;
        let fits = u.len() <= room(url.len())
            && b.as_ref()
                .is_none_or(|b| b.len() <= room(body.map_or(0, str::len)));
        let changed = u != url || b.as_deref() != body;
        if same_place && fits && changed && clean(&u) && !out.contains(&(u.clone(), b.clone())) {
            out.push((u, b));
        }
        if out.len() >= max {
            break;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_authority() {
        let v = variants("https://h.example/a?x=<script>", None, 8);
        assert!(v.iter().all(|(u, _)| u.starts_with("https://h.example/")));
    }

    #[test]
    fn encodes_specials() {
        let v = variants("https://h.example/a?x=<script>", None, 8);
        assert!(
            v.iter()
                .any(|(u, _)| u.contains("%3C") && u.contains("%3E"))
        );
    }

    #[test]
    fn encodes_traversal() {
        let v = variants("https://h.example/../../etc/passwd", None, 8);
        assert!(v.iter().any(|(u, _)| u.contains("..%2f")));
        assert!(v.iter().any(|(u, _)| u.contains("%252e%252e%252f")));
    }

    #[test]
    fn respects_cap() {
        let v = variants("https://h.example/../a?x=<script>", None, 2);
        assert!(v.len() <= 2);
    }

    #[test]
    fn no_variant_equals_original_tail() {
        let orig = "/plain/path";
        let v = variants(&format!("https://h.example{orig}"), None, 8);
        assert!(
            v.iter()
                .all(|(u, _)| u != &format!("https://h.example{orig}"))
        );
    }
}

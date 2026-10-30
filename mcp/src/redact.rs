//! Masking secrets before they leave the machine in a result, or land in the audit.
//!
//! A response from a target is full of credentials that belong to somebody: session
//! cookies, bearer tokens, keys pasted into a config page. Results go to whatever
//! model the client uses, so they are masked by default, and `--no-redact` is the
//! person's call to make in their client config. The audit log is always masked,
//! because it outlives the session and is the file most likely to be copied
//! somewhere.
//!
//! This matches names and known formats, not meaning. It misses a secret with an
//! unremarkable name in an unremarkable format, and that limit is stated in the docs
//! rather than papered over.

use regex::Regex;
use std::sync::LazyLock;

pub(crate) const MASK: &str = "[redacted]";

/// A header, query parameter or form field whose value should not be shown.
pub(crate) fn sensitive_name(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    // `code` is the OAuth authorization code a login redirect carries.
    matches!(
        n.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" | "code"
    ) || ["token", "secret", "session", "auth", "key", "passw"]
        .iter()
        .any(|k| n.contains(k))
}

struct Pattern {
    re: Regex,
    with: &'static str,
}

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let p = |re: &str, with: &'static str| Pattern {
        re: Regex::new(re).expect("redaction pattern"),
        with,
    };
    vec![
        // A raw request or response pasted as evidence keeps its header names.
        p(
            r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:).*$",
            "$1 [redacted]",
        ),
        p(
            r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)",
            "[redacted private key]",
        ),
        p(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer [redacted]"),
        p(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*", MASK),
        p(r"AKIA[0-9A-Z]{16}", MASK),
        p(r"gh[pousr]_[A-Za-z0-9]{36,}", MASK),
        p(r"xox[baprs]-[\w-]+", MASK),
        p(r"AIza[\w-]{35}", MASK),
        p(r"sk_live_\w+", MASK),
        // `name=value` where the name carries one of the words `sensitive_name` looks
        // for, prefixed or not: `access_token=`, `client_secret=`, `session_id=`. No
        // word boundary in front, because `_` is a word character and `\b` would
        // miss every prefixed name.
        p(
            r#"(?i)([A-Za-z0-9_.-]*(?:passw|secret|token|api[_-]?key|session|auth)[A-Za-z0-9_.-]*)=[^&\s#"']+"#,
            "$1=[redacted]",
        ),
    ]
});

/// Mask secrets recognised by format anywhere in free text.
pub(crate) fn redact_text(s: &str) -> String {
    let mut out = s.to_string();
    for p in PATTERNS.iter() {
        if p.re.is_match(&out) {
            out = p.re.replace_all(&out, p.with).into_owned();
        }
    }
    out
}

/// Mask the values of query and fragment parameters with sensitive names, and any
/// password in the authority. Text that does not parse as a URL is masked as free
/// text.
pub(crate) fn redact_url(s: &str) -> String {
    let Ok(mut url) = transport::Url::parse(s) else {
        return redact_text(s);
    };
    if url.password().is_some() {
        let _ = url.set_password(Some(MASK));
    }
    if url.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| {
                let v = if sensitive_name(&k) {
                    MASK.to_string()
                } else {
                    redact_text(&v)
                };
                (k.into_owned(), v)
            })
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    // A fragment is never sent, but an OAuth implicit flow puts its tokens there, and
    // a URL copied from a browser keeps them.
    if let Some(fragment) = url.fragment().map(str::to_string) {
        let masked: Vec<String> = fragment
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, _)) if sensitive_name(k) => format!("{k}={MASK}"),
                _ => redact_text(pair),
            })
            .collect();
        url.set_fragment(Some(&masked.join("&")));
    }
    url.to_string()
}

/// One header value, masked by its name and then by format. A URL in a header is
/// masked as a URL, by parameter name.
pub(crate) fn redact_header(name: &str, value: &str) -> String {
    if sensitive_name(name) {
        MASK.to_string()
    } else if name.eq_ignore_ascii_case("location") || name.eq_ignore_ascii_case("content-location")
    {
        redact_url(value)
    } else {
        redact_text(value)
    }
}

/// Arguments as they are written to the audit log: URLs, headers and body fields
/// masked, a request body reduced to its size and hash, and the whole thing capped.
pub(crate) fn audit_args(tool: &str, args: &serde_json::Value) -> serde_json::Value {
    use serde_json::{Value, json};
    const ARGS_MAX: usize = 8 * 1024;

    fn url_in(v: &mut Value, key: &str) {
        if let Some(u) = v.get(key).and_then(|u| u.as_str()) {
            let r = redact_url(u);
            v[key] = json!(r);
        }
    }
    fn walk(v: &mut Value) {
        match v {
            Value::String(s) => *s = redact_text(s),
            Value::Array(a) => a.iter_mut().for_each(walk),
            Value::Object(o) => o.values_mut().for_each(walk),
            _ => {}
        }
    }

    let mut v = args.clone();
    match tool {
        "send_http_request" => {
            url_in(&mut v, "url");
            if let Some(h) = v.get_mut("headers").and_then(|h| h.as_object_mut()) {
                for (k, x) in h.iter_mut() {
                    let shown = match x.as_str() {
                        Some(s) => redact_header(k, s),
                        None => MASK.to_string(),
                    };
                    *x = json!(shown);
                }
            }
            if let Some(b) = v.get("body").filter(|b| !b.is_null()) {
                let text = b
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| b.to_string());
                v["body"] = json!({
                    "body_bytes": text.len(),
                    "body_sha256": crate::scope_file::sha256_hex(text.as_bytes()),
                });
            }
        }
        "test_injection" | "fingerprint" => {
            url_in(&mut v, "url");
            if let Some(eps) = v.get_mut("endpoints").and_then(|e| e.as_array_mut()) {
                for ep in eps.iter_mut() {
                    url_in(ep, "url");
                    if let Some(fields) = ep.get_mut("body").and_then(|b| b.as_array_mut()) {
                        for f in fields.iter_mut() {
                            let masked = f
                                .get("name")
                                .and_then(|n| n.as_str())
                                .is_some_and(sensitive_name);
                            if masked && f.get("value").is_some() {
                                f["value"] = json!(MASK);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    walk(&mut v);
    let size = v.to_string().len();
    if size > ARGS_MAX {
        return json!({"omitted": "arguments over 8 KB", "bytes": size});
    }
    v
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn names_that_carry_secrets() {
        for n in [
            "Authorization",
            "cookie",
            "Set-Cookie",
            "X-API-Key",
            "x-auth-token",
            "session_id",
            "client_secret",
            "password",
        ] {
            assert!(sensitive_name(n), "{n}");
        }
        for n in ["accept", "content-type", "q", "page"] {
            assert!(!sensitive_name(n), "{n}");
        }
    }

    #[test]
    fn formats_are_masked_in_free_text() {
        let t = "Authorization: Bearer sk-test-SECRET123\nok\ntoken=abc123&x=1 \
                 AKIAABCDEFGHIJKLMNOP eyJhbGciOi.eyJzdWIiOi.sig";
        let r = redact_text(t);
        for secret in [
            "sk-test-SECRET123",
            "abc123",
            "AKIAABCDEFGHIJKLMNOP",
            "eyJzdWIiOi",
        ] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        assert!(r.contains("x=1"));
    }

    #[test]
    fn a_bearer_token_outside_a_header_line_is_masked() {
        let r = redact_text("the value was Bearer abc.def-ghi and more");
        assert_eq!(r, "the value was Bearer [redacted] and more");
    }

    #[test]
    fn query_values_are_masked_by_name() {
        let r = redact_url("http://h.test/p?token=abc123&q=shoes");
        assert!(!r.contains("abc123"), "{r}");
        assert!(r.contains("q=shoes"));
    }

    #[test]
    fn names_with_a_prefix_are_masked_in_free_text() {
        let r = redact_text(
            "error for url (http://h.test/?access_token=AAA1&refresh_token=AAA2&q=1) \
             id_token=AAA3 client_secret=AAA4 session_id=AAA5",
        );
        for secret in ["AAA1", "AAA2", "AAA3", "AAA4", "AAA5"] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        assert!(r.contains("q=1"), "{r}");
    }

    #[test]
    fn fragment_values_are_masked_by_name_too() {
        let r = redact_url("http://h.test/cb?state=s1#access_token=BBB1&id_token=BBB2&x=keep");
        for secret in ["BBB1", "BBB2"] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        assert!(r.contains("x=keep") && r.contains("state=s1"), "{r}");
        let r = redact_url("http://h.test/cb?code=CCC1&next=%2Fhome");
        assert!(!r.contains("CCC1"), "{r}");
        assert!(r.contains("next="), "{r}");
    }

    #[test]
    fn a_location_header_is_masked_as_a_url() {
        let r = redact_header("Location", "https://h.test/cb?code=DDD1&token=DDD2");
        assert!(!r.contains("DDD1") && !r.contains("DDD2"), "{r}");
    }

    #[test]
    fn a_private_key_block_is_masked_whole() {
        let r = redact_text(
            "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\nabc\n-----END RSA PRIVATE KEY-----\nb",
        );
        assert!(!r.contains("MIIE"), "{r}");
        assert!(r.starts_with("a\n") && r.ends_with("\nb"));
    }
}

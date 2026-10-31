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

/// Names masked wherever they appear in them: `x-auth-token`, `client_secret`,
/// `session_id`, `api_key`.
const NAME_WORDS: [&str; 6] = ["token", "secret", "session", "auth", "key", "passw"];
/// Names masked only when they are the whole name. `code` is the OAuth authorization
/// code a login redirect carries.
const NAMES: [&str; 6] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "code",
];

/// A header, query parameter or form field whose value should not be shown.
pub(crate) fn sensitive_name(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    NAMES.contains(&n.as_str()) || NAME_WORDS.iter().any(|k| n.contains(k))
}

/// A regex alternative matching the names [`sensitive_name`] passes, where a name is a
/// run of `chars` (a character class body), ignoring case.
fn sensitive_names(chars: &str) -> String {
    let words = NAME_WORDS.join("|");
    let exact: Vec<String> = NAMES.iter().map(|n| regex::escape(n)).collect();
    format!("(?:[{chars}]*(?:{words})[{chars}]*|{})", exact.join("|"))
}

struct Pattern {
    re: Regex,
    with: &'static str,
    /// Replace only when the `name` group passes [`sensitive_name`].
    named: bool,
}

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let p = |re: &str, with: &'static str| Pattern {
        re: Regex::new(re).expect("redaction pattern"),
        with,
        named: false,
    };
    // Header field name characters (RFC 9110 `tchar`).
    let header = sensitive_names(r"!#$%&'*+.^_`|~0-9A-Za-z-");
    let member = sensitive_names(r#"^"\\"#);
    let field = sensitive_names("A-Za-z0-9_.-");
    vec![
        // A raw request or response pasted as evidence keeps its header names. Every
        // header `sensitive_name` would mask is masked here too: `X-Auth-Token:` and
        // `Api-Key:` as well as `Authorization:`.
        p(
            &format!(r"(?im)^(?P<head>[ \t]*{header}[ \t]*:)[^\r\n]*"),
            "${head} [redacted]",
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
        // A JSON member with one of those names and a string value: `"password":"x"`,
        // `"access_token": "..."`. Escapes inside the value are stepped over, so `\"`
        // does not end it early.
        p(
            &format!(r#"(?i)"(?P<name>{member})"\s*:\s*"(?:[^"\\]|\\.)*""#),
            r#""$name":"[redacted]""#,
        ),
        // A multipart/form-data part with one of those names: its headers are kept and
        // its body, up to the next boundary or the end of what was captured, is masked.
        // `\bname` so a `filename=` is not read as the part's name.
        Pattern {
            re: Regex::new(
                r#"(?i)(?P<head>content-disposition:[^\r\n]*\bname="?(?P<name>[^"\r\n;]*)"?[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*?\r?\n)(?s:.*?)(?P<end>\r?\n--|\z)"#,
            )
            .expect("redaction pattern"),
            with: "${head}[redacted]${end}",
            named: true,
        },
        // `name=value` with one of those names, prefixed or not: `access_token=`,
        // `client_secret=`, `api_key=`, `code=`. The character before the name is kept
        // and is what makes `code` a whole name.
        p(
            &format!(r#"(?i)(?P<pre>^|[^A-Za-z0-9_.-])(?P<name>{field})=[^&\s#"']+"#),
            "${pre}${name}=[redacted]",
        ),
    ]
});

/// Mask secrets recognised by name or format anywhere in free text.
pub(crate) fn redact_text(s: &str) -> String {
    let mut out = s.to_string();
    for p in PATTERNS.iter() {
        if !p.re.is_match(&out) {
            continue;
        }
        out = if p.named {
            p.re.replace_all(&out, |c: &regex::Captures| {
                let name = c.name("name").map_or("", |m| m.as_str());
                if sensitive_name(name) {
                    let mut to = String::new();
                    c.expand(p.with, &mut to);
                    to
                } else {
                    c[0].to_string()
                }
            })
            .into_owned()
        } else {
            p.re.replace_all(&out, p.with).into_owned()
        };
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

/// `%41` as `A` and `+` as a space, for reading a parameter's name. Bytes that do not
/// decode are kept as they are.
fn percent_decoded(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A request target as a request line carries it, `/path?query#fragment`. Query and
/// fragment parameters whose names [`sensitive_name`] passes lose their values, and
/// everything else keeps the bytes it was written with, so a path is shown as it was
/// sent rather than as a URL parser would tidy it. An absolute URL is masked as a URL.
pub(crate) fn redact_target(t: &str) -> String {
    if !t.starts_with('/') {
        return if t.contains("://") {
            redact_url(t)
        } else {
            redact_text(t)
        };
    }
    let (rest, fragment) = match t.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (t, None),
    };
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };
    let pairs = |q: &str| -> String {
        q.split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, _)) if sensitive_name(&percent_decoded(k)) => format!("{k}={MASK}"),
                _ => redact_text(pair),
            })
            .collect::<Vec<_>>()
            .join("&")
    };
    let mut out = redact_text(path);
    if let Some(q) = query {
        out.push('?');
        out.push_str(&pairs(q));
    }
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(&pairs(f));
    }
    out
}

/// `METHOD target [version]`, as a request line or a refusal's detail says it, with
/// the target masked by [`redact_target`]. Anything else is masked as free text.
pub(crate) fn redact_request_line(line: &str) -> String {
    let mut parts = line.splitn(3, ' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return redact_text(line);
    };
    if method.is_empty() || !(target.starts_with('/') || target.contains("://")) {
        return redact_text(line);
    }
    let mut out = format!("{} {}", redact_text(method), redact_target(target));
    if let Some(rest) = parts.next() {
        out.push(' ');
        out.push_str(&redact_text(rest));
    }
    out
}

/// Cookie attributes a server sets beside the cookie, which are kept as they are.
const COOKIE_ATTRIBUTES: [&str; 9] = [
    "path",
    "domain",
    "expires",
    "max-age",
    "samesite",
    "secure",
    "httponly",
    "partitioned",
    "priority",
];

/// `a=1; b=2` as `a=[redacted]; b=[redacted]`, so a reader can see which cookies a
/// request carried without seeing them. In a `Set-Cookie`, the attributes after the
/// first pair are kept unless they are not attributes at all.
fn mask_cookies(value: &str, set: bool) -> String {
    let mut out = Vec::new();
    for (i, part) in value.split(';').enumerate() {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, has_value) = match part.split_once('=') {
            Some((k, _)) => (k.trim(), true),
            None => (part, false),
        };
        let attribute =
            set && i > 0 && COOKIE_ATTRIBUTES.contains(&k.to_ascii_lowercase().as_str());
        out.push(if attribute {
            part.to_string()
        } else if has_value && !k.is_empty() {
            format!("{k}={MASK}")
        } else {
            MASK.to_string()
        });
    }
    if out.iter().all(|p| p == MASK) {
        return MASK.to_string();
    }
    out.join("; ")
}

/// One header value, masked by its name and then by format. A URL in a header is
/// masked as a URL, by parameter name. Cookies keep their names.
pub(crate) fn redact_header(name: &str, value: &str) -> String {
    let n = name.trim();
    if n.eq_ignore_ascii_case("cookie") {
        mask_cookies(value, false)
    } else if n.eq_ignore_ascii_case("set-cookie") {
        mask_cookies(value, true)
    } else if sensitive_name(name) {
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
        "workbench_replay" => {
            if let Some(e) = v.get_mut("edits").and_then(|e| e.as_object_mut()) {
                if let Some(h) = e.get_mut("headers").and_then(|h| h.as_object_mut()) {
                    for (k, x) in h.iter_mut() {
                        if let Some(s) = x.as_str() {
                            *x = json!(redact_header(k, s));
                        }
                    }
                }
                for field in ["query", "form", "json"] {
                    if let Some(m) = e.get_mut(field).and_then(|m| m.as_object_mut()) {
                        for (k, x) in m.iter_mut() {
                            if sensitive_name(k) && !x.is_null() {
                                *x = json!(MASK);
                            }
                        }
                    }
                }
                if let Some(path) = e.get("path").and_then(|p| p.as_str()) {
                    let shown = redact_url(&format!("http://h{path}"));
                    let shown = shown.strip_prefix("http://h").unwrap_or(&shown).to_string();
                    e.insert("path".into(), json!(shown));
                }
                if let Some(b) = e.get("body").filter(|b| !b.is_null()) {
                    let text = b
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| b.to_string());
                    let reduced = json!({
                        "body_bytes": text.len(),
                        "body_sha256": crate::scope_file::sha256_hex(text.as_bytes()),
                    });
                    e.insert("body".into(), reduced);
                }
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
    fn json_members_with_secret_names_are_masked() {
        let r = redact_text(
            r#"{"password":"hunter2","access_token":"AAA1","user":{"Session-Id" : "AAA2"},"q":"keep","note":"a \"quoted\" token"}"#,
        );
        for secret in ["hunter2", "AAA1", "AAA2"] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        assert!(r.contains(r#""password":"[redacted]""#), "{r}");
        assert!(r.contains(r#""q":"keep""#), "{r}");
        assert!(r.contains(r#""note":"a \"quoted\" token""#), "{r}");
        let r = redact_text(r#"{"api_key":"k\"EEE1\\"}"#);
        assert!(!r.contains("EEE1"), "{r}");
    }

    #[test]
    fn multipart_parts_with_secret_names_are_masked() {
        let body = "--XyZ\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n\
                    --XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\
                    Content-Type: text/plain\r\n\r\nhunter2\r\n\
                    --XyZ\r\ncontent-disposition: form-data; name=csrf_token\r\n\r\nBBB1\r\n--XyZ--\r\n";
        let r = redact_text(body);
        for secret in ["hunter2", "BBB1"] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        assert!(r.contains("alice"), "{r}");
        assert!(r.contains("name=\"password\""), "{r}");
        // A body cut off inside the part still loses the value.
        let r = redact_text("--b\nContent-Disposition: form-data; name=\"secret\"\n\nCCC1 and mo");
        assert!(!r.contains("CCC1"), "{r}");
    }

    #[test]
    fn cookie_headers_keep_their_names_and_lose_their_values() {
        assert_eq!(
            redact_header("Cookie", "sid=S1; theme=dark"),
            "sid=[redacted]; theme=[redacted]"
        );
        let r = redact_header("Set-Cookie", "sid=S2; Path=/; HttpOnly");
        assert_eq!(r, "sid=[redacted]; Path=/; HttpOnly");
        let r = redact_header("set-cookie", "__Host-a=S3=more; Secure");
        assert!(
            !r.contains("S3") && r.starts_with("__Host-a=[redacted]"),
            "{r}"
        );
        // Nothing that looks like a pair keeps nothing at all.
        assert_eq!(redact_header("Cookie", "S4"), MASK);
    }

    #[test]
    fn a_private_key_block_is_masked_whole() {
        let r = redact_text(
            "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\nabc\n-----END RSA PRIVATE KEY-----\nb",
        );
        assert!(!r.contains("MIIE"), "{r}");
        assert!(r.starts_with("a\n") && r.ends_with("\nb"));
    }

    /// Free text is masked by the names a header list or a URL is masked by. A raw
    /// request in a Repeater draft or a finding's evidence carries custom auth headers,
    /// and `code` and `*_key` values, that the old word list let through.
    #[test]
    fn free_text_is_masked_by_the_same_names_as_headers_and_urls() {
        let raw = "GET /cb?code=FT1&access_key=FT2&barcode=keep1 HTTP/1.1\r\n\
                   Host: h.test\r\nX-Auth-Token: FT3\r\nX-CSRF-Token: FT4\r\n\
                   Api-Key: FT5\r\nCode: FT6\r\nContent-Type: text/plain\r\n\r\n\
                   codex=keep2 next=/cb?token=FT7";
        let r = redact_text(raw);
        for secret in ["FT1", "FT2", "FT3", "FT4", "FT5", "FT6", "FT7"] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        for kept in [
            "barcode=keep1",
            "codex=keep2",
            "Host: h.test",
            "Content-Type: text/plain",
        ] {
            assert!(r.contains(kept), "{kept} was lost: {r}");
        }
        // Each masked header line keeps its name and its line ending.
        assert!(r.contains("X-Auth-Token: [redacted]\r\n"), "{r}");
        let r = redact_text(r#"{"code":"FJ1","api_key":"FJ2","codec":"keep"}"#);
        assert!(!r.contains("FJ1") && !r.contains("FJ2"), "{r}");
        assert!(r.contains(r#""codec":"keep""#), "{r}");
    }

    #[test]
    fn a_request_line_is_masked_by_its_parameters_and_keeps_its_path() {
        let r = redact_request_line("GET /a/../cb?code=RL1&access_key=RL2&q=1%202 HTTP/1.1");
        assert_eq!(
            r,
            "GET /a/../cb?code=[redacted]&access_key=[redacted]&q=1%202 HTTP/1.1"
        );
        let r = redact_request_line("POST /x?%74oken=RL3#id_token=RL4&s=1 HTTP/1.1");
        assert!(!r.contains("RL3") && !r.contains("RL4"), "{r}");
        assert!(r.ends_with("&s=1 HTTP/1.1"), "{r}");
        let r = redact_request_line("GET http://h.test/cb?code=RL5 HTTP/1.1");
        assert!(!r.contains("RL5"), "{r}");
        // Not a request line: masked as text.
        assert_eq!(
            redact_request_line("agent injection test"),
            "agent injection test"
        );
        assert_eq!(redact_request_line("token=RL6"), "token=[redacted]");
    }
}

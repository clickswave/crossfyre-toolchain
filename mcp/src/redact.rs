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
/// `session_id`, `api_key`, `PHPSESSID`, `X-Goog-Signature`.
const NAME_WORDS: [&str; 8] = [
    "token",
    "secret",
    "session",
    "sessid",
    "auth",
    "key",
    "passw",
    "signature",
];
/// Names masked only when they are the whole name. `code` is the OAuth authorization
/// code a login redirect carries, `sid` the session id phpBB and Engine.IO put in a
/// query, and `sig` an Azure shared access signature.
const NAMES: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "code",
    "sid",
    "sig",
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
        // does not end it early, and a value a body cap cut off before its closing
        // quote is masked to the end of what was captured.
        p(
            &format!(r#"(?i)"(?P<name>{member})"\s*:\s*"(?:[^"\\]|\\.)*(?:"|\\?\z)"#),
            r#""$name":"[redacted]""#,
        ),
        // The same with a number for a value: `"session_id": 123456`.
        p(
            &format!(r#"(?i)"(?P<name>{member})"\s*:\s*-?[0-9][0-9.eE+-]*"#),
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
    mask_nested_members(&out)
}

/// `"name":` with one of those names, followed by the start of an object or an array.
static NESTED_MEMBER: LazyLock<Regex> = LazyLock::new(|| {
    let member = sensitive_names(r#"^"\\"#);
    Regex::new(&format!(r#"(?i)"{member}"\s*:\s*[\[{{]"#)).expect("redaction pattern")
});

/// A JSON member with one of those names whose value is an object or an array, which
/// the member pattern does not reach, loses the whole value: `"session":{"id":"..."}`
/// becomes `"session":"[redacted]"`. A value a body cap cut off is masked to the end of
/// what was captured. Brackets inside strings are stepped over.
fn mask_nested_members(s: &str) -> String {
    if !NESTED_MEMBER.is_match(s) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut from = 0;
    while let Some(m) = NESTED_MEMBER.find_at(s, from) {
        let open = m.end() - 1;
        let (mut depth, mut in_str, mut esc) = (0usize, false, false);
        let mut end = s.len();
        for (i, c) in s[open..].char_indices() {
            if in_str {
                match (esc, c) {
                    (true, _) => esc = false,
                    (false, '\\') => esc = true,
                    (false, '"') => in_str = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                '{' | '[' => depth += 1,
                '}' | ']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push_str(&s[from..open]);
        out.push('"');
        out.push_str(MASK);
        out.push('"');
        from = end;
    }
    out.push_str(&s[from..]);
    out
}

/// Mask a URL and keep every byte it was written with outside what is masked, so the URL
/// as shown differs from the stored one only where a value was hidden: a search over the
/// shown URL finds what a search over the stored one would, short of the masked values.
///
/// Masked: a password in the authority, a user name standing alone (`https://<token>@`
/// is how a token rides in one) or holding a known format, the path a piece at a time
/// ([`redact_path`]), and query and fragment parameters by name. Text that does not parse
/// as a URL with an authority is masked as free text.
pub(crate) fn redact_url(s: &str) -> String {
    // A URL parser drops a tab or line break anywhere, so `tok\nen=` names `token`.
    let s = &s.replace(['\t', '\n', '\r'], "");
    let (Ok(_), Some(i)) = (transport::Url::parse(s), s.find("://")) else {
        return redact_text(s);
    };
    let scheme = &s[..i];
    if !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return redact_text(s);
    }
    let from = i + 3;
    let to = s[from..]
        .find(['/', '\\', '?', '#'])
        .map_or(s.len(), |j| from + j);
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..from]);
    match s[from..to].rsplit_once('@') {
        Some((userinfo, host)) => {
            match userinfo.split_once(':') {
                Some((user, _)) => {
                    out.push_str(&redact_text(user));
                    out.push(':');
                    out.push_str(MASK);
                }
                None if !userinfo.is_empty() => out.push_str(MASK),
                None => {}
            }
            out.push('@');
            out.push_str(host);
        }
        None => out.push_str(&s[from..to]),
    }
    out.push_str(&redact_after_authority(&s[to..]));
    out
}

/// `(S(...))`, an ASP.NET cookieless session in a path segment, and the `(A(...)F(...))`
/// forms of the same.
static COOKIELESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\((?:[A-Za-z]\([^()]*\))+\)$").expect("redaction pattern"));
static COOKIELESS_PART: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z])\([^()]*\)").expect("redaction pattern"));

/// A path masked a piece at a time, a piece being what lies between `/` and `;`. A
/// `name=value` piece with a secret name loses its value (`;jsessionid=`), an ASP.NET
/// cookieless segment loses what its parentheses hold, and any other piece is masked as
/// free text. The separators and every other piece keep their bytes, so the path after
/// a masked value is still shown.
pub(crate) fn redact_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for part in path.split_inclusive(['/', ';']) {
        let (piece, sep) = match part.strip_suffix(['/', ';']) {
            Some(p) => (p, &part[p.len()..]),
            None => (part, ""),
        };
        match piece.split_once('=') {
            _ if piece.is_empty() => {}
            Some((k, v)) if !v.is_empty() && sensitive_name(&percent_decoded(k)) => {
                out.push_str(k);
                out.push('=');
                out.push_str(MASK);
            }
            _ if COOKIELESS.is_match(piece) => {
                out.push_str(&COOKIELESS_PART.replace_all(piece, "$1([redacted])"));
            }
            _ => out.push_str(&redact_text(piece)),
        }
        out.push_str(sep);
    }
    out
}

/// What follows the authority of a URL, or a request target that starts with `/`:
/// `path?query#fragment`. The path is masked by [`redact_path`], query and fragment
/// parameters whose names [`sensitive_name`] passes lose their values, and everything
/// else keeps the bytes it was written with.
fn redact_after_authority(t: &str) -> String {
    let (rest, fragment) = match t.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (t, None),
    };
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };
    let pairs = |q: &str| -> String { q.split('&').map(redact_pair).collect::<Vec<_>>().join("&") };
    let mut out = redact_path(path);
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

/// One `name=value` query or fragment parameter. A sensitive name loses its value, and
/// any other value is masked as free text. A value whose decoded form holds a secret,
/// such as a URL carried encoded in it (`next=https%3A%2F%2F...%3Ftoken%3D...`), is
/// shown decoded, masked and encoded again.
fn redact_pair(pair: &str) -> String {
    let Some((k, v)) = pair.split_once('=') else {
        return redact_text(pair);
    };
    if sensitive_name(&percent_decoded(k)) {
        return format!("{k}={MASK}");
    }
    if v.contains(['%', '+']) {
        let decoded = percent_decoded(v);
        let masked = redact_text(&decoded);
        if masked != decoded {
            return format!("{}={}", redact_text(k), encoded(&masked));
        }
    }
    redact_text(pair)
}

/// A query value written back with `%XX` for the bytes that would end it or change what
/// it means, and everything else as it is, so it stays readable.
fn encoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:@,;=!$'()*[]?".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
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

/// A request target as a request line carries it, `/path?query#fragment`, masked by
/// [`redact_after_authority`], so a path is shown as it was sent rather than as a URL
/// parser would tidy it. An absolute URL is masked as a URL.
pub(crate) fn redact_target(t: &str) -> String {
    if !t.starts_with('/') {
        return if t.contains("://") {
            redact_url(t)
        } else {
            redact_text(t)
        };
    }
    redact_after_authority(t)
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
    /// Every member with a sensitive name, at any depth, loses its value.
    fn by_name(v: &mut Value) {
        match v {
            Value::Array(a) => a.iter_mut().for_each(by_name),
            Value::Object(o) => {
                for (k, x) in o.iter_mut() {
                    if sensitive_name(k) && !x.is_null() {
                        *x = json!(MASK);
                    } else {
                        by_name(x);
                    }
                }
            }
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
                // A JSON edit can set a member to an object, so its names are looked at
                // all the way down: `{"data":{"password":"..."}}`.
                for field in ["query", "form", "json"] {
                    if let Some(m) = e.get_mut(field).filter(|m| m.is_object()) {
                        by_name(m);
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
            "PHPSESSID",
            "sid",
            "sig",
            "signature",
            "X-Goog-Signature",
        ] {
            assert!(sensitive_name(n), "{n}");
        }
        for n in [
            "accept",
            "content-type",
            "q",
            "page",
            "side",
            "inside",
            "signal",
        ] {
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

    /// A session id rewritten into the path, the session and signature names PHP,
    /// phpBB, Engine.IO, Azure, Laravel and Google use, and a token in the user name.
    #[test]
    fn a_url_loses_session_ids_in_its_path_and_signatures_in_its_query() {
        let r = redact_url("https://portal.example.test/app/home;jsessionid=8F3APATH?x=1");
        assert!(!r.contains("8F3APATH"), "{r}");
        assert!(
            r.contains("/app/home;jsessionid=") && r.ends_with("?x=1"),
            "{r}"
        );
        let r = redact_url("http://h.test/a;PHPSESSID=PS1/b");
        assert!(!r.contains("PS1"), "{r}");
        let r = redact_url(
            "http://h.test/f?PHPSESSID=Q1&sid=Q2&sig=Q3&signature=Q4&X-Goog-Signature=Q5\
             &X-Amz-Signature=Q6&sessid=Q7&side=keep1&inside=keep2",
        );
        for secret in ["Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7"] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        assert!(
            r.contains("side=keep1") && r.contains("inside=keep2"),
            "{r}"
        );
        let r = redact_url("https://ghp_0123456789abcdefghijklmnopqrstuvwxyz@h.test/r");
        assert!(!r.contains("0123456789abcdef"), "{r}");
    }

    /// The member pattern reaches a string value only, so an object or array under a
    /// secret name is masked whole, and a body cut off inside one is masked to its end.
    #[test]
    fn json_members_with_secret_names_and_object_values_are_masked_whole() {
        let r = redact_text(
            r#"{"session": {"id": "NJ1", "exp": 5}, "tokens": ["NJ2", {"v": "NJ3"}], "q": {"keep": "k1"}, "n": "k2"}"#,
        );
        for secret in ["NJ1", "NJ2", "NJ3"] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        assert_eq!(
            r,
            r#"{"session": "[redacted]", "tokens": "[redacted]", "q": {"keep": "k1"}, "n": "k2"}"#
        );
        // A brace inside a string does not end the value early.
        let r = redact_text(r#"{"auth":{"note":"a } \" ]","key":"NJ4"},"after":1}"#);
        assert_eq!(r, r#"{"auth":"[redacted]","after":1}"#);
        // Nested under an ordinary name, and cut off by the body cap.
        let r = redact_text(r#"{"data":{"user":{"session":{"id":"NJ5","more"#);
        assert!(!r.contains("NJ5"), "{r}");
        assert!(
            r.starts_with(r#"{"data":{"user":{"session":"[redacted]""#),
            "{r}"
        );
    }

    /// The URL as shown keeps the bytes it was stored with outside a masked value, so a
    /// term searched for in it is found where it was written: `/`, `:`, `@`, `,`, `%20`
    /// in a query value are not re-encoded.
    #[test]
    fn a_url_keeps_its_bytes_outside_the_masked_values() {
        let u = "http://h.test/r?next=/admin/users&redirect=https://evil.test/a&q=a%20b+c\
                 &l=a,b@c&token=RB1#frag=/x";
        assert_eq!(
            redact_url(u),
            "http://h.test/r?next=/admin/users&redirect=https://evil.test/a&q=a%20b+c\
             &l=a,b@c&token=[redacted]#frag=/x"
        );
        assert_eq!(redact_url("HTTP://H.test:8080"), "HTTP://H.test:8080");
    }

    /// A value that carries a URL of its own, encoded, has that URL's secrets masked as
    /// well, and a tab or line break the URL parser would drop does not split a name.
    #[test]
    fn an_encoded_url_in_a_value_is_masked_inside() {
        let r = redact_url(
            "http://h.test/login?next=https%3A%2F%2Fapp.test%2Fcb%3Faccess_token%3DNX1%26x%3D1\
             &r=a+Bearer+NX2&q=1#s=%2Fcb%3Fcode%3DNX3",
        );
        for secret in ["NX1", "NX2", "NX3"] {
            assert!(!r.contains(secret), "{secret} survived: {r}");
        }
        assert!(
            r.contains("next=https://app.test/cb?access_token=[redacted]%26x=1&r="),
            "{r}"
        );
        assert!(r.contains("&q=1#"), "{r}");
        let r = redact_url("http://h.test/p?tok\nen=NX4&x=1");
        assert!(!r.contains("NX4"), "{r}");
    }

    /// A path keeps what follows a masked path parameter, an ASP.NET cookieless session
    /// is masked, and a user name with no password is masked whole.
    #[test]
    fn a_path_keeps_what_follows_a_masked_value() {
        assert_eq!(
            redact_url("https://h.test/a;jsessionid=PK1/b/c?y=2"),
            "https://h.test/a;jsessionid=[redacted]/b/c?y=2"
        );
        assert_eq!(
            redact_url("http://h.test/a;PHPSESSID=PK2;lang=en/b"),
            "http://h.test/a;PHPSESSID=[redacted];lang=en/b"
        );
        assert_eq!(
            redact_url("http://h.test/(S(pk3abcdef))/page.aspx?x=1"),
            "http://h.test/(S([redacted]))/page.aspx?x=1"
        );
        assert_eq!(
            redact_url("http://h.test/app/(A(PK4)F(PK5))/a"),
            "http://h.test/app/(A([redacted])F([redacted]))/a"
        );
        assert_eq!(
            redact_url("https://pk6opaque@h.test/r"),
            "https://[redacted]@h.test/r"
        );
        assert_eq!(
            redact_url("https://alice:PK7@h.test/r"),
            "https://alice:[redacted]@h.test/r"
        );
        assert_eq!(
            redact_request_line("GET /a;jsessionid=PK8/b?q=1 HTTP/1.1"),
            "GET /a;jsessionid=[redacted]/b?q=1 HTTP/1.1"
        );
        assert_eq!(redact_path("/a;sid=PK9/b"), "/a;sid=[redacted]/b");
    }

    #[test]
    fn json_members_with_secret_names_and_number_values_are_masked() {
        let r = redact_text(r#"{"session_id": 123456, "otp_token":-7.5e3, "page": 2}"#);
        assert_eq!(
            r,
            r#"{"session_id":"[redacted]", "otp_token":"[redacted]", "page": 2}"#
        );
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
    fn the_audit_masks_a_json_edit_by_name_at_every_depth() {
        let args = serde_json::json!({"exchange": "wx_0123456789_1", "edits": {
            "json": {"data": {"password": "AU1", "n": 2},
                     "list": [{"api_key": "AU2"}, "plain"],
                     "token": {"value": "AU3"},
                     "keep": "AU4"},
            "query": {"code": "AU5", "q": "AU6"}}});
        let shown = audit_args("workbench_replay", &args).to_string();
        for secret in ["AU1", "AU2", "AU3", "AU5"] {
            assert!(!shown.contains(secret), "{secret} survived: {shown}");
        }
        for kept in ["AU4", "AU6", "\"n\":2", "plain"] {
            assert!(shown.contains(kept), "{kept} was lost: {shown}");
        }
    }

    /// A body is cut at a byte cap, which can fall inside a secret. What was kept of it
    /// is masked, as the multipart pattern already did.
    #[test]
    fn a_json_secret_cut_off_by_the_body_cap_is_masked() {
        let r = redact_text(r#"{"user":"a","access_token":"TRUNC1abcdef"#);
        assert_eq!(r, r#"{"user":"a","access_token":"[redacted]""#);
        // Cut just after an escape character, and with nothing after the quote yet.
        let r = redact_text(r#"{"password":"TRUNC2\"#);
        assert!(!r.contains("TRUNC2"), "{r}");
        assert_eq!(redact_text(r#"{"secret":""#), r#"{"secret":"[redacted]""#);
        // A whole value is still masked only up to its own closing quote.
        let r = redact_text(r#"{"token":"T1","q":"keep"}"#);
        assert_eq!(r, r#"{"token":"[redacted]","q":"keep"}"#);
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

//! Privacy-safe reduction: turn a captured request/response into the redacted [`TraceEvent`] shape
//! the control plane ingests. This deliberately carries NO bodies, header values, or secrets - only
//! structural shape (method, redacted URL with query KEYS, body field NAMES, media type, and the
//! FACT that the request was authed). Shared by the desktop proxy and the mobile netstack so the
//! privacy invariant lives in exactly one place.

/// The privacy-safe event streamed to `/api/v1/web-trace/ingest`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct TraceEvent {
    pub method: String,
    /// Redacted absolute URL (userinfo/fragment stripped, query values blanked).
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i64>,
    /// Coarse tech fingerprint from the response `Server` banner, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tech: Option<String>,
    /// True when the request carried an Authorization header or session cookie. Only the FACT is
    /// sent (never the credential) so the graph can mark the endpoint auth-required.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub authed: bool,
    /// Request body media type (e.g. `application/json`), when the request carried a body.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content_type: Option<String>,
    /// Request-body field NAMES only (e.g. `["email", "role"]`), from a JSON or form body. The KEYS
    /// are the operation's request shape; the VALUES are secrets and are never captured.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub body_params: Vec<String>,

    // ── Full-capture fields (present ONLY when the workflow opted into full capture) ──────────────
    // These carry the real bytes for the Requests tab / Bench Repeater. Omitted entirely in the
    // default privacy-safe mode, so a shape-only event never contains a body, header value, or secret.
    /// The unredacted absolute URL (real query values), for the captured-requests store.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub full_url: Option<String>,
    /// Full request headers as ordered [name, value] pairs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub req_headers: Option<Vec<[String; 2]>>,
    /// Full request body (lossy UTF-8).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub req_body: Option<String>,
    /// Full response headers as ordered [name, value] pairs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resp_headers: Option<Vec<[String; 2]>>,
    /// Full response body (lossy UTF-8).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resp_body: Option<String>,
    /// Round-trip time to the origin, ms.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duration_ms: Option<u64>,
}

/// One captured exchange's real bytes, for full-capture mode.
///
/// Exists so "what a full-capture event must contain" is one type rather than
/// six optional fields each client remembers to set independently. The desktop
/// proxy forgot all six for the life of the feature, which is why the Requests
/// tab was empty for every PC capture while Assets worked fine.
#[derive(Debug, Clone, Default)]
pub struct FullExchange {
    /// Unredacted absolute URL, real query values included.
    pub url: String,
    pub req_headers: Vec<[String; 2]>,
    /// RAW body bytes, exactly as they went over the wire. Not a String: most
    /// bodies are compressed, and `from_utf8_lossy` on a gzip stream destroys
    /// it irreversibly. `attach_full` decodes these.
    pub req_body: Vec<u8>,
    pub resp_headers: Vec<[String; 2]>,
    /// RAW body bytes. See `req_body`.
    pub resp_body: Vec<u8>,
    pub duration_ms: Option<u64>,
}

impl TraceEvent {
    /// Attach the real bytes to an already-shaped event.
    ///
    /// Call this and only this when the session has full capture on. Setting the
    /// fields by hand is how they drift: the server stores whatever arrives and
    /// reports nothing when half of it is missing, so a partial event fails
    /// silently and looks like an empty tab rather than a bug.
    /// Bodies are decoded here, once, for every capture path. A body arrives
    /// compressed far more often than not, and the decode has to happen before
    /// the lossy UTF-8 conversion or the bytes are gone for good. Doing it in
    /// this one place is what keeps the mobile and desktop tracers agreeing.
    ///
    /// When a body IS decoded its headers are restated to match, so the stored
    /// exchange never claims an encoding its body no longer has.
    pub fn attach_full(&mut self, ex: FullExchange) {
        let FullExchange {
            url,
            mut req_headers,
            req_body,
            mut resp_headers,
            resp_body,
            duration_ms,
        } = ex;

        let (req_bytes, req_decoded) = crate::body::decode(&req_body, &req_headers);
        if req_decoded {
            crate::body::strip_encoding_headers(&mut req_headers, req_bytes.len());
        }
        let (resp_bytes, resp_decoded) = crate::body::decode(&resp_body, &resp_headers);
        if resp_decoded {
            crate::body::strip_encoding_headers(&mut resp_headers, resp_bytes.len());
        }

        self.full_url = Some(url);
        self.req_headers = Some(req_headers);
        self.req_body = Some(String::from_utf8_lossy(&req_bytes).into_owned());
        self.resp_headers = Some(resp_headers);
        self.resp_body = Some(String::from_utf8_lossy(&resp_bytes).into_owned());
        self.duration_ms = duration_ms;
    }

    /// Whether this event carries the real bytes.
    pub fn has_full_capture(&self) -> bool {
        self.full_url.is_some() && self.req_headers.is_some()
    }
}

/// Redact a URL down to a safe shape: strip `user:pass@` userinfo, drop the `#fragment`, and keep
/// query parameter KEYS while blanking their VALUES (`?a=secret&b=2` -> `?a=&b=`). Pure and robust to
/// malformed input.
/// Does a query or form part that carried no `=` look like a parameter NAME, rather than a
/// value somebody passed bare?
///
/// The default capture mode promises it records no values. A part with an `=` is
/// unambiguous: the key is a name and the value is blanked. A part WITHOUT one is
/// syntactically a name with no value, and that is how this was treated, so it was kept
/// verbatim. Measured: `?eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature`
/// came back unchanged, and `api_switch`'s asset graph then stores each query name as a
/// `param` asset, so the token was persisted and shown in the UI by the mode that promises
/// not to do that. A bare high-entropy part also mints a new `param` asset per request,
/// which pollutes the graph quite apart from the privacy of it.
///
/// So the question is answered conservatively, because the two cases cannot be told apart
/// with certainty and the costs are not symmetric: keeping a token is a privacy breach,
/// while dropping an unusually long flag name loses one piece of request shape.
///
/// What this does NOT catch, stated because a reader will otherwise assume it does: a
/// SHORT high-entropy value, say a sixteen-character bare token with mixed case, satisfies
/// every test here and is kept. Closing that would mean guessing at entropy, and a rule
/// that silently drops real parameter names is its own kind of wrong. Flags are short and
/// word-shaped, and that is what this recognises.
///
/// Note also that this only ever sees parts with no `=` at all. A bare token carrying
/// base64 padding, `?YWJjZA==`, splits into a key and a value and never reaches here, so
/// that case is handled at the call site instead.
fn looks_like_a_param_name(p: &str) -> bool {
    // Flags are short. The ones that actually occur are `debug`, `pretty`, `raw`, `force`,
    // `nocache`, `include_deleted`: under twenty characters with room to spare. The first
    // version of this allowed twenty-four and let through a measured
    // `eyJ0b2tlbiI6InNlY3JldCJ9`, which is exactly twenty-four, so the bound was doing
    // nothing for the one case it was written for. Past twenty, a part with no value is
    // far more likely to be data than a name.
    if p.is_empty() || p.len() > 20 {
        return false;
    }
    // Characters that belong to encodings and credentials, not to names.
    if p.bytes()
        .any(|b| matches!(b, b'%' | b'+' | b'/' | b'=' | b':' | b'@'))
    {
        return false;
    }
    if !p
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'[' | b']' | b'~'))
    {
        return false;
    }
    // A long run of hex is an id or a digest. `?deadbeef` is short enough to be a name and
    // is left alone; sixteen or more is not something anybody named a parameter.
    !(p.len() >= 16 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn redact_url(raw: &str) -> String {
    let no_frag = raw.split('#').next().unwrap_or(raw);
    let (base, query) = match no_frag.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (no_frag, None),
    };
    let base = strip_userinfo(base);
    match query {
        None => base,
        Some("") => base,
        Some(q) => {
            let blanked: Vec<String> = q
                .split('&')
                .filter(|p| !p.is_empty())
                .filter_map(|p| match p.split_once('=') {
                    // A "value" made only of `=` is base64 padding, which means the split
                    // landed inside a bare token and `k` is the token rather than a name.
                    // `?YWJjZA==` was coming back as `?YWJjZA=`.
                    Some((_, v)) if !v.is_empty() && v.bytes().all(|b| b == b'=') => None,
                    Some((k, _)) => Some(format!("{k}=")),
                    // No `=`, so there is no way to show this is a name. Dropped rather
                    // than carried, unless it looks like one.
                    None => looks_like_a_param_name(p).then(|| p.to_string()),
                })
                .collect();
            if blanked.is_empty() {
                base
            } else {
                format!("{base}?{}", blanked.join("&"))
            }
        }
    }
}

fn strip_userinfo(base: &str) -> String {
    let Some(scheme_end) = base.find("://") else {
        return base.to_string();
    };
    let authority_start = scheme_end + 3;
    let rest = &base[authority_start..];
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    match authority.rsplit_once('@') {
        Some((_userinfo, hostport)) => format!(
            "{}{}{}",
            &base[..authority_start],
            hostport,
            &rest[authority_end..]
        ),
        None => base.to_string(),
    }
}

/// Extract request-body field NAMES from a JSON object or a form-urlencoded body. Values are never
/// retained. Returns an empty vec for anything else (arrays, streams, opaque bodies).
pub fn body_field_names(content_type: Option<&str>, body: &[u8]) -> Vec<String> {
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    if ct.contains("application/json") {
        if let Ok(serde_json::Value::Object(map)) =
            serde_json::from_slice::<serde_json::Value>(body)
        {
            return map.keys().cloned().collect();
        }
    } else if ct.contains("application/x-www-form-urlencoded") {
        let s = String::from_utf8_lossy(body);
        return s
            .split('&')
            .filter(|p| !p.is_empty())
            .filter_map(|p| match p.split_once('=') {
                Some((_, v)) if !v.is_empty() && v.bytes().all(|b| b == b'=') => None,
                Some((k, _)) => Some(k.to_string()),
                // Same reasoning as the query string: a form part with no `=` is not
                // demonstrably a field name, and `["eyJ0b2tlbiI6InNlY3JldCJ9"]` was being
                // reported as one.
                None => looks_like_a_param_name(p).then(|| p.to_string()),
            })
            .collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_blanks_values_keeps_keys() {
        assert_eq!(
            redact_url("https://u:p@ex.com/a?token=secret&page=2#frag"),
            "https://ex.com/a?token=&page="
        );
        assert_eq!(redact_url("http://x/y"), "http://x/y");
    }

    #[test]
    fn body_names_json_and_form() {
        let j = body_field_names(Some("application/json"), br#"{"email":"a@b","role":"x"}"#);
        assert!(j.contains(&"email".to_string()) && j.contains(&"role".to_string()));
        let f = body_field_names(
            Some("application/x-www-form-urlencoded"),
            b"user=admin&pw=hunter2",
        );
        assert_eq!(f, vec!["user".to_string(), "pw".to_string()]);
        assert!(body_field_names(Some("text/plain"), b"whatever").is_empty());
    }

    /// The leak this rule exists for, in the exact form it was measured.
    const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature";

    #[test]
    fn a_bare_token_in_the_query_is_not_carried_as_a_name() {
        // Before the rule, this came back byte for byte, and the asset graph then stored
        // it as a `param` asset, so the credential was persisted by the mode whose whole
        // promise is that it records no values.
        let out = redact_url(&format!("https://ex.com/a?{JWT}"));
        assert_eq!(out, "https://ex.com/a");
        assert!(!out.contains("eyJ"), "no part of the token survives: {out}");
    }

    #[test]
    fn a_short_flag_with_no_value_is_still_kept() {
        // The cost of being conservative has to stay bounded: `?debug` is real request
        // shape and dropping it would make the rule worse than the leak for common URLs.
        for flag in [
            // Each of these is within the bound, which is itself part of the claim.
            "debug",
            "pretty",
            "verbose",
            "include_deleted",
            "a",
            "x-1.2",
            "deadbeef",
        ] {
            assert_eq!(
                redact_url(&format!("https://ex.com/a?{flag}")),
                format!("https://ex.com/a?{flag}"),
                "{flag} is name-shaped and should survive"
            );
        }
    }

    #[test]
    fn the_things_that_give_a_value_away() {
        for value in [
            // Long, which is the primary signal.
            "a-very-long-parameter-name-that-is-really-a-token",
            // Sixteen or more hex characters is an id or a digest.
            "0123456789abcdef",
            "d41d8cd98f00b204e9800998ecf8427e",
            // Characters that belong to encodings and credentials.
            "AbCdEf%2Bgh",
            "a+b",
            "a/b",
            "user@host",
            "a:b",
        ] {
            let out = redact_url(&format!("https://ex.com/a?{value}"));
            assert_eq!(
                out, "https://ex.com/a",
                "{value} should not be carried as a parameter name"
            );
        }
    }

    #[test]
    fn dropping_a_valueless_part_leaves_the_others_alone() {
        assert_eq!(
            redact_url(&format!("https://ex.com/a?page=2&{JWT}&debug")),
            "https://ex.com/a?page=&debug",
            "a keyed param keeps its key, the token goes, the flag stays"
        );
        // And when every part drops, the `?` goes with them rather than being left bare.
        assert_eq!(
            redact_url(&format!("https://ex.com/a?{JWT}")),
            "https://ex.com/a"
        );
    }

    #[test]
    fn a_keyed_parameter_is_unaffected_however_long_its_value() {
        // The rule applies ONLY to parts with no `=`. A keyed param was never the problem
        // and must not start being treated as one, or every signed CDN URL loses its shape.
        assert_eq!(
            redact_url(
                "https://cdn.ex.com/f.js?v=3&Expires=1699999999&Signature=AbCdEf%2Bgh%2F123%3D"
            ),
            "https://cdn.ex.com/f.js?v=&Expires=&Signature="
        );
        assert_eq!(
            redact_url(&format!("https://ex.com/a?Policy={JWT}")),
            "https://ex.com/a?Policy="
        );
    }

    #[test]
    fn a_form_body_with_no_equals_reports_no_field_names() {
        // Measured: this returned `["eyJ0b2tlbiI6InNlY3JldCJ9"]`, a token presented as a
        // field name, which the asset graph records as a body param.
        let got = body_field_names(
            Some("application/x-www-form-urlencoded"),
            b"eyJ0b2tlbiI6InNlY3JldCJ9",
        );
        assert!(got.is_empty(), "got: {got:?}");

        // A flag among real fields still comes through, and the real fields are untouched.
        let got = body_field_names(
            Some("application/x-www-form-urlencoded"),
            format!("user=admin&dry_run&pw=hunter2&{JWT}").as_bytes(),
        );
        assert_eq!(got, vec!["user", "dry_run", "pw"]);
    }

    #[test]
    fn full_capture_is_a_different_promise_and_keeps_the_real_url() {
        // Worth pinning so nobody reads the rule above as covering everything. Full
        // capture exists to record real bytes for the Requests tab, and `full_url` is
        // supposed to carry the token. The privacy guarantee there is the workflow opting
        // in, not redaction.
        let mut ev = TraceEvent::default();
        ev.attach_full(FullExchange {
            url: format!("https://ex.com/a?{JWT}"),
            ..Default::default()
        });
        assert_eq!(
            ev.full_url.as_deref(),
            Some(format!("https://ex.com/a?{JWT}").as_str())
        );
    }

    #[test]
    fn a_bare_token_with_base64_padding_is_dropped_rather_than_split() {
        // `?YWJjZA==` splits into key `YWJjZA` and value `=`, so the keyed branch used to
        // keep the token's own prefix as a parameter name and emit `?YWJjZA=`. A value
        // made only of `=` is padding, which is the signal that the split landed inside a
        // value rather than between a name and one.
        assert_eq!(redact_url("https://ex.com/a?YWJjZA=="), "https://ex.com/a");
        assert_eq!(
            redact_url("https://ex.com/a?page=2&YWJjZA==&debug"),
            "https://ex.com/a?page=&debug"
        );
        assert!(
            body_field_names(
                Some("application/x-www-form-urlencoded"),
                b"eyJ0b2tlbiI6InNlY3JldCJ9=="
            )
            .is_empty()
        );
        // An ordinary param with no value is NOT padding and keeps its name.
        assert_eq!(
            redact_url("https://ex.com/a?token="),
            "https://ex.com/a?token="
        );
    }
}

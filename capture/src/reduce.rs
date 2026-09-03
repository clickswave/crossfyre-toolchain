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
    pub req_body: String,
    pub resp_headers: Vec<[String; 2]>,
    pub resp_body: String,
    pub duration_ms: Option<u64>,
}

impl TraceEvent {
    /// Attach the real bytes to an already-shaped event.
    ///
    /// Call this and only this when the session has full capture on. Setting the
    /// fields by hand is how they drift: the server stores whatever arrives and
    /// reports nothing when half of it is missing, so a partial event fails
    /// silently and looks like an empty tab rather than a bug.
    pub fn attach_full(&mut self, ex: FullExchange) {
        self.full_url = Some(ex.url);
        self.req_headers = Some(ex.req_headers);
        self.req_body = Some(ex.req_body);
        self.resp_headers = Some(ex.resp_headers);
        self.resp_body = Some(ex.resp_body);
        self.duration_ms = ex.duration_ms;
    }

    /// Whether this event carries the real bytes.
    pub fn has_full_capture(&self) -> bool {
        self.full_url.is_some() && self.req_headers.is_some()
    }
}

/// Redact a URL down to a safe shape: strip `user:pass@` userinfo, drop the `#fragment`, and keep
/// query parameter KEYS while blanking their VALUES (`?a=secret&b=2` -> `?a=&b=`). Pure and robust to
/// malformed input.
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
                .map(|p| match p.split_once('=') {
                    Some((k, _)) => format!("{k}="),
                    None => p.to_string(),
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
            .map(|p| p.split_once('=').map(|(k, _)| k).unwrap_or(p).to_string())
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
}

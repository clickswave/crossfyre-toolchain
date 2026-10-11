//! Target-string normalization shared by the engines.
//!
//! Every engine takes a user-supplied target (`example.com`, `example.com:8443`,
//! `https://example.com/x`) and has to infer a scheme and port before it can
//! build a URL. plessor (`normalize_base`) and toolmark (`normalize_target`) carried
//! byte-identical copies of that inference, differing only in what they returned.
//! [`normalize_target`] does the inference once; [`Target`] exposes both shapes.

/// A target parsed from a user string, with scheme and port inferred.
pub struct Target {
    pub scheme: String,
    pub host: String,
    /// Resolved port: the explicit port if given, else the scheme default.
    pub port: u16,
    /// The fully parsed, normalized URL string.
    pub url: String,
    /// The port only when it was explicit in the input, so [`Target::base`] can
    /// omit a default port exactly as plessor's `normalize_base` did.
    explicit_port: Option<u16>,
}

impl Target {
    /// `scheme://host[:port]`, with the port shown only when it was explicit in
    /// the input (a default port is omitted). Suitable as a template `{{BaseURL}}`.
    pub fn base(&self) -> String {
        match self.explicit_port {
            Some(p) => format!("{}://{}:{}", self.scheme, self.host, p),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Infer scheme + port for a bare-host target, parse it, and return the
/// normalized [`Target`]. `None` for empty, oversized (>2048 bytes: only feeds a
/// pathological host into blocking DNS, which the request timeout does not
/// cover), or unparseable input.
///
/// Scheme inference: an explicit `http(s)://` is kept; a bare `host:PORT` becomes
/// `https` for 443/8443 and `http` otherwise; anything else defaults to `http`.
pub fn normalize_target(t: &str) -> Option<Target> {
    let t = t.trim();
    if t.is_empty() || t.len() > 2048 {
        return None;
    }
    let with_scheme = if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else if let Some((_, p)) = t.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let scheme = if p == "443" || p == "8443" {
                "https"
            } else {
                "http"
            };
            format!("{scheme}://{t}")
        } else {
            format!("http://{t}")
        }
    } else {
        format!("http://{t}")
    };
    let url = crate::Url::parse(&with_scheme).ok()?;
    let scheme = url.scheme().to_string();
    let host = url.host_str()?.to_string();
    let explicit_port = url.port();
    let port = url
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    Some(Target {
        scheme,
        host,
        port,
        url: url.to_string(),
        explicit_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_oversized() {
        assert!(normalize_target("").is_none());
        assert!(normalize_target("   ").is_none());
        assert!(normalize_target(&"a".repeat(2049)).is_none());
    }

    #[test]
    fn infers_scheme_and_port() {
        let t = normalize_target("example.com").unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.port, 80);
        // Default port is omitted from base() (matches plessor normalize_base).
        assert_eq!(t.base(), "http://example.com");

        let t = normalize_target("example.com:8443").unwrap();
        assert_eq!(t.scheme, "https");
        assert_eq!(t.port, 8443);
        // Explicit port is kept in base().
        assert_eq!(t.base(), "https://example.com:8443");

        let t = normalize_target("example.com:9000").unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.port, 9000);
        assert_eq!(t.base(), "http://example.com:9000");
    }

    #[test]
    fn keeps_explicit_scheme_and_resolves_default_port() {
        let t = normalize_target("https://example.com/some/path").unwrap();
        assert_eq!(t.scheme, "https");
        assert_eq!(t.port, 443);
        // No explicit port in the input -> base() omits it even though port=443.
        assert_eq!(t.base(), "https://example.com");
    }
}

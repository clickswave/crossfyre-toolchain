//! Backend-agnostic outbound HTTP transport for the Crossfyre engines.
//!
//! The open toolchain builds a plain `reqwest` client (rustls). Enabling the
//! `impersonate` feature swaps the client backend for `wreq` (BoringSSL) so the
//! Evasive path can present a real browser **TLS + HTTP/2 fingerprint**, which is
//! the signal a WAF checks before any HTTP is sent. reqwest only lets us fix the
//! User-Agent and headers; the handshake fingerprint needs this.
//!
//! ## Why this compiles cleanly for both backends
//!
//! reqwest and wreq both re-export the `http` and `url` crates, so `HeaderMap`,
//! `HeaderName`, `HeaderValue`, `Method`, `StatusCode` and `Url` are the *same
//! types* in both. Only `Client`, `ClientBuilder`, `RequestBuilder`, `Response`,
//! `Error` and `redirect::Policy` differ, so those are re-exported from whichever
//! backend is active and callers stay backend-agnostic. All backend-specific
//! construction (cert handling, emulation) is confined to [`build_client`].
//!
//! ## Open-core boundary
//!
//! The *choice* of which browser to present (the per-target UA) is a trade secret
//! and lives in the private `adaptive` drop-in (the profile catalogue). This crate
//! only maps a browser *family* (read from the UA) to a `wreq_util::Emulation`;
//! that mapping is not secret, the selection is.

use std::time::Duration;

// Backend-specific types (differ between reqwest and wreq).
#[cfg(not(feature = "impersonate"))]
pub use reqwest::{redirect, Client, ClientBuilder, Error, Proxy, RequestBuilder, Response};
#[cfg(feature = "impersonate")]
pub use wreq::{redirect, Client, ClientBuilder, Error, Proxy, RequestBuilder, Response};

// Shared http/url types (identical regardless of backend).
pub use reqwest::header;
pub use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
pub use reqwest::{Method, StatusCode, Url};

mod auth;
pub use auth::AuthSpec;

pub mod guard;

pub mod url;

/// Build a [`HeaderMap`] from `(name, value)` string pairs, skipping any that
/// fail to parse. Convenience for turning an identity's header list (from
/// `adaptive::identity`) into `ClientConfig::browser_headers`.
pub fn headers_from_pairs(pairs: &[(&'static str, String)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            m.insert(name, val);
        }
    }
    m
}

/// Redirect handling for a client.
#[derive(Clone, Copy, Debug)]
pub enum Redirect {
    /// Do not follow redirects (a 3xx reads as-is).
    None,
    /// Follow up to `n` redirects.
    Limited(usize),
}

/// Backend-agnostic client configuration. The engines fill this from the scan
/// params and the resolved identity; [`build_client`] applies it to whichever
/// backend is compiled in.
pub struct ClientConfig {
    /// Per-request timeout. `None` = no timeout (matches a bare reqwest client).
    pub timeout: Option<Duration>,
    pub redirect: Redirect,
    /// Trust invalid/self-signed certs (scanners deliberately hit such hosts).
    pub accept_invalid_certs: bool,
    pub cookie_store: bool,
    /// The identity's User-Agent. Sent when NOT emulating; when emulating, the
    /// emulation profile provides a coherent UA and this is used only to choose
    /// the browser family.
    pub user_agent: Option<String>,
    /// Browser fingerprint headers (sec-ch-ua, sec-fetch, accept-language, ...).
    /// Sent only when NOT emulating; when emulating, the profile owns these, so
    /// sending them too would duplicate or conflict with the emulated set.
    pub browser_headers: HeaderMap,
    /// Application headers (auth, attribution token, template headers). Always
    /// sent, in both the emulating and non-emulating paths.
    pub extra_headers: HeaderMap,
    /// Attempt browser emulation (Evasive / Identify posture). Honoured only when
    /// the `impersonate` backend is compiled in; a no-op for the reqwest backend.
    pub emulate: bool,
    /// Static DNS overrides: `(host, addr)` pairs. A request to `host` connects to
    /// `addr` while keeping `host` as the SNI + Host header. Origin discovery uses
    /// this to hit a candidate origin IP as if it were the fronted target host.
    pub resolve: Vec<(String, std::net::SocketAddr)>,
    /// Refuse to connect to private / reserved addresses.
    ///
    /// Off by default, because reaching a customer's own RFC1918 network from a
    /// node inside it is the product working. Turn it on for paths where the
    /// caller is anonymous and the egress is shared, which today means the free
    /// public tools: there, an unvetted stranger picks the destination and the
    /// hop is ours, so the node must not be usable as a pivot.
    ///
    /// Enforced at the RESOLVER, so it also covers redirect hops and DNS
    /// rebinding, neither of which a check at the call site can see. See
    /// [`guard`].
    pub block_internal: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            timeout: Some(Duration::from_secs(30)),
            redirect: Redirect::Limited(5),
            accept_invalid_certs: false,
            cookie_store: false,
            user_agent: None,
            browser_headers: HeaderMap::new(),
            extra_headers: HeaderMap::new(),
            emulate: false,
            resolve: Vec::new(),
            block_internal: false,
        }
    }
}

/// True when this build will actually emulate a browser fingerprint: the
/// `impersonate` backend is compiled in *and* emulation was requested.
fn will_emulate(cfg: &ClientConfig) -> bool {
    cfg!(feature = "impersonate") && cfg.emulate
}

/// Build a client from `cfg`. All backend differences are confined here.
pub fn build_client(cfg: ClientConfig) -> Result<Client, Error> {
    // App headers are always sent. Browser headers + UA are sent only when we are
    // NOT emulating (the emulation profile provides its own coherent set).
    let mut headers = cfg.extra_headers.clone();
    if !will_emulate(&cfg) {
        for (k, v) in cfg.browser_headers.iter() {
            // Never forward a browser Accept-Encoding here: reqwest only
            // auto-decompresses when IT set the header, so a manual `br`/`zstd`
            // would come back as undecoded bytes (breaking HTML/JS extraction on
            // any brotli/zstd server). Let reqwest advertise + decode via its
            // compression features instead.
            if k.as_str() == "accept-encoding" {
                continue;
            }
            headers.insert(k.clone(), v.clone());
        }
        if let Some(ua) = &cfg.user_agent {
            if let Ok(v) = HeaderValue::from_str(ua) {
                headers.insert(header::USER_AGENT, v);
            }
        }
    }

    let mut b = Client::builder().default_headers(headers);
    if cfg.block_internal {
        // Both backends expose the same `dns_resolver` hook and an identical
        // `Resolve` trait, so one value serves whichever is compiled.
        b = b.dns_resolver(std::sync::Arc::new(guard::PublicOnlyResolver));
    }
    if let Some(t) = cfg.timeout {
        b = b.timeout(t);
    }
    b = match cfg.redirect {
        Redirect::None => b.redirect(redirect::Policy::none()),
        Redirect::Limited(n) => b.redirect(redirect::Policy::limited(n)),
    };
    if cfg.cookie_store {
        b = b.cookie_store(true);
    }
    for (host, addr) in &cfg.resolve {
        b = b.resolve(host.as_str(), *addr);
    }

    // BYO residential / mobile egress. When the node exports
    // `CROSSFYRE_EGRESS_PROXY` (an `http(s)://` or `socks5://` gateway URL, with
    // optional `user:pass@`), every engine client routes through it. One env var
    // covers all engines with no per-engine plumbing, and a rotating-residential
    // provider is exactly one such gateway URL. Ignored (direct egress) when
    // unset or unparseable, so a bad value never silently drops to a worse path
    // than "no proxy".
    if let Ok(proxy_url) = std::env::var("CROSSFYRE_EGRESS_PROXY") {
        let proxy_url = proxy_url.trim();
        if !proxy_url.is_empty() {
            match Proxy::all(proxy_url) {
                Ok(p) => b = b.proxy(p),
                Err(e) => eprintln!("[transport] ignoring invalid CROSSFYRE_EGRESS_PROXY: {e}"),
            }
        }
    }

    // Cert handling differs by backend.
    #[cfg(not(feature = "impersonate"))]
    if cfg.accept_invalid_certs {
        b = b.danger_accept_invalid_certs(true);
    }
    #[cfg(feature = "impersonate")]
    {
        if cfg.accept_invalid_certs {
            b = b.cert_verification(false).verify_hostname(false);
        }
        if cfg.emulate {
            let ua = cfg.user_agent.as_deref();
            if let Some(em) = emulation_for_ua(ua) {
                // wreq's `emulation()` REPLACES the default header map wholesale
                // (`std::mem::swap`), which would wipe the app/auth headers we set
                // above (Authorization, Cookie, attribution token) -- silently
                // de-authenticating every scan run under the default evasive
                // posture. Merge them back: take the emulation profile's own
                // default headers (read off a throwaway client, since the profile's
                // header map is not otherwise accessible), overlay our extra
                // headers so auth wins, and apply that AFTER emulation. The TLS /
                // HTTP2 / header-order fingerprint from `emulation()` is carried in
                // separate config fields and is unaffected by this final
                // default_headers() call.
                let mut merged = Client::builder()
                    .emulation(em)
                    .build()
                    .map(|c| c.headers())
                    .unwrap_or_default();
                for (k, v) in cfg.extra_headers.iter() {
                    merged.insert(k.clone(), v.clone());
                }
                if let Some(em2) = emulation_for_ua(ua) {
                    b = b.emulation(em2).default_headers(merged);
                }
            }
        }
    }

    b.build()
}

/// A scan client described in terms an engine already has: a resolved browser
/// identity (headers + UA, from the private `adaptive` catalogue), optional
/// request auth, an optional attribution token, and the per-op transport policy.
///
/// [`build_scan_client`] turns this into a [`Client`], centralizing the ~15-line
/// "identity headers -> browser_headers, auth -> app headers, Identify token ->
/// `x-bug-bounty`" assembly that cortex (inject/authz), mach and scout each
/// reimplemented around [`build_client`]. The caller still resolves the identity,
/// so the `adaptive` dependency stays out of `transport`.
pub struct ScanClient<'a> {
    /// Resolved browser identity headers (`adaptive::identity::Identity::headers`).
    pub identity_headers: &'a [(&'static str, String)],
    /// The identity's User-Agent. Also selects the emulation browser family.
    pub user_agent: &'a str,
    /// Request auth applied as app headers (survives emulation). `None` or a
    /// non-meaningful spec means unauthenticated.
    pub auth: Option<&'a AuthSpec>,
    /// Attribution token for the Identify posture, sent as `x-bug-bounty`. An app
    /// header, so it too survives emulation.
    pub attribution_token: Option<&'a str>,
    pub emulate: bool,
    pub timeout: Option<Duration>,
    pub redirect: Redirect,
    pub accept_invalid_certs: bool,
    pub cookie_store: bool,
    pub resolve: Vec<(String, std::net::SocketAddr)>,
    /// Refuse private / reserved destinations. See [`ClientConfig::block_internal`].
    pub block_internal: bool,
}

impl<'a> Default for ScanClient<'a> {
    fn default() -> Self {
        ScanClient {
            identity_headers: &[],
            user_agent: "",
            auth: None,
            attribution_token: None,
            emulate: false,
            timeout: Some(Duration::from_secs(30)),
            redirect: Redirect::Limited(5),
            accept_invalid_certs: false,
            cookie_store: false,
            resolve: Vec::new(),
            block_internal: false,
        }
    }
}

/// Build a scan [`Client`] from a [`ScanClient`] description. Assembles the app
/// (auth + attribution) headers and the browser (identity) headers, then defers
/// to [`build_client`] for all backend-specific construction.
pub fn build_scan_client(spec: ScanClient) -> Result<Client, Error> {
    let mut extra_headers = HeaderMap::new();
    if let Some(a) = spec.auth.filter(|a| a.is_meaningful()) {
        for (k, v) in a.to_header_map().iter() {
            extra_headers.insert(k.clone(), v.clone());
        }
    }
    if let Some(tok) = spec.attribution_token {
        if let Ok(val) = HeaderValue::from_str(tok) {
            extra_headers.insert(HeaderName::from_static("x-bug-bounty"), val);
        }
    }
    build_client(ClientConfig {
        timeout: spec.timeout,
        redirect: spec.redirect,
        accept_invalid_certs: spec.accept_invalid_certs,
        cookie_store: spec.cookie_store,
        user_agent: Some(spec.user_agent.to_string()),
        browser_headers: headers_from_pairs(spec.identity_headers),
        extra_headers,
        emulate: spec.emulate,
        resolve: spec.resolve,
        block_internal: spec.block_internal,
    })
}

/// Map the identity's User-Agent to a `wreq_util` emulation profile by browser
/// family. The family variety across targets comes from the private catalogue's
/// per-target UA choice; only the family -> profile mapping is here (public).
#[cfg(feature = "impersonate")]
fn emulation_for_ua(ua: Option<&str>) -> Option<wreq_util::Emulation> {
    use wreq_util::Emulation::*;
    let ua = ua?;
    Some(if ua.contains("Firefox/") {
        Firefox139
    } else if ua.contains("Edg/") {
        Edge134
    } else if ua.contains("Version/") && ua.contains("Safari/") && !ua.contains("Chrome/") {
        Safari18_5
    } else if ua.contains("Chrome/") {
        Chrome137
    } else {
        return None;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ua(s: &str) -> ClientConfig {
        ClientConfig {
            user_agent: Some(s.into()),
            emulate: true,
            ..Default::default()
        }
    }

    #[test]
    fn builds_in_both_backends() {
        let c = build_client(ClientConfig {
            accept_invalid_certs: true,
            cookie_store: true,
            user_agent: Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
                    .into(),
            ),
            emulate: true,
            ..Default::default()
        });
        assert!(c.is_ok(), "build failed: {:?}", c.err());
    }

    #[test]
    fn will_emulate_tracks_feature_and_flag() {
        assert_eq!(will_emulate(&ua("x")), cfg!(feature = "impersonate"));
        assert!(!will_emulate(&ClientConfig {
            emulate: false,
            ..Default::default()
        }));
    }

    #[cfg(feature = "impersonate")]
    #[test]
    fn ua_maps_to_browser_family() {
        assert!(emulation_for_ua(Some("... Chrome/138.0.0.0 Safari/537.36")).is_some());
        assert!(emulation_for_ua(Some("... rv:139.0) Gecko/20100101 Firefox/139.0")).is_some());
        assert!(emulation_for_ua(Some("... Version/18.5 Safari/605.1.15")).is_some());
        assert!(emulation_for_ua(None).is_none());
    }
}

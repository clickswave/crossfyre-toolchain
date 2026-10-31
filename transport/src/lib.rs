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
//! only maps a browser *family* (read from the UA) to one of the emulation
//! profiles in `emulation`; those profiles and that mapping are not secret, the
//! selection is.

use std::time::Duration;

// Backend-specific types (differ between reqwest and wreq).
#[cfg(not(feature = "impersonate"))]
pub use reqwest::{Client, ClientBuilder, Error, Proxy, RequestBuilder, Response, redirect};
#[cfg(feature = "impersonate")]
pub use wreq::{Client, ClientBuilder, Error, Proxy, RequestBuilder, Response, redirect};

// Shared http/url types (identical regardless of backend).
pub use reqwest::header;
pub use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
pub use reqwest::{Method, StatusCode, Url};

mod auth;
pub use auth::AuthSpec;

#[cfg(feature = "impersonate")]
mod emulation;

pub mod guard;

pub mod url;

pub mod egress;
pub use egress::{
    BuildError, EGRESS_PROXY_VAR, Egress, EgressWire, Io, Tunnel, TunnelError, WIRE_VERSION, dial,
};

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
    /// the browser family. A User-Agent that names no family a profile covers,
    /// such as a scanner's own string, is not emulated: it is sent as it is.
    pub user_agent: Option<String>,
    /// Browser fingerprint headers (sec-ch-ua, sec-fetch, accept-language, ...).
    /// Sent only when NOT emulating; when emulating, the profile owns these, so
    /// sending them too would duplicate or conflict with the emulated set.
    pub browser_headers: HeaderMap,
    /// Application headers (auth, attribution token, template headers). Always
    /// sent, in both the emulating and non-emulating paths.
    pub extra_headers: HeaderMap,
    /// Attempt browser emulation (Evasive / Identify posture). Honoured only when
    /// the `impersonate` backend is compiled in and the User-Agent names a browser
    /// family it has a profile for; otherwise the client is built as if this were
    /// off.
    pub emulate: bool,
    /// Static DNS overrides: `(host, addr)` pairs. A request to `host` connects to
    /// `addr` while keeping `host` as the SNI + Host header. Origin discovery uses
    /// this to hit a candidate origin IP as if it were the fronted target host.
    /// A proxy would look the name up again, so a client with any pin uses no proxy
    /// from `HTTP_PROXY` and the like, and cannot be built to send through
    /// `CROSSFYRE_EGRESS_PROXY` or [`Egress::Proxy`].
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
    /// rebinding, neither of which a check at the call site can see, and in the
    /// redirect policy for a hop to an address written as one, which never reaches
    /// the resolver. See [`guard`]. A request the caller itself sends to an
    /// address is not filtered: that destination is the caller's to check.
    ///
    /// A proxy resolves names where this filter cannot see them. Under
    /// [`Egress::Inherit`] the client therefore uses no proxy from `HTTP_PROXY` and
    /// the like, and cannot be built while `CROSSFYRE_EGRESS_PROXY` is set. Under
    /// [`Egress::Proxy`] the filter is the proxy's job, which a node's gateway does.
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

/// The profile this build presents for `cfg`: emulation was requested and the
/// User-Agent names a browser family the `impersonate` backend has a profile for.
#[cfg(feature = "impersonate")]
fn profile(cfg: &ClientConfig) -> Option<emulation::Browser> {
    if !cfg.emulate {
        return None;
    }
    cfg.user_agent
        .as_deref()
        .and_then(emulation::Browser::from_user_agent)
}

/// True when this build will actually emulate a browser fingerprint: the
/// `impersonate` backend is compiled in, emulation was requested, and there is
/// a profile for the User-Agent's family.
#[cfg(feature = "impersonate")]
fn will_emulate(cfg: &ClientConfig) -> bool {
    profile(cfg).is_some()
}

#[cfg(not(feature = "impersonate"))]
fn will_emulate(_: &ClientConfig) -> bool {
    false
}

/// Build a client from `cfg` that sends the way `egress` says. All backend
/// differences are confined here.
///
/// | `egress` | the client |
/// |---|---|
/// | `Direct` | uses no proxy, whatever the environment says |
/// | `Inherit`, `CROSSFYRE_EGRESS_PROXY` unset | as before: `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` apply, unless the client pins names or refuses private addresses, which then uses none |
/// | `Inherit`, `CROSSFYRE_EGRESS_PROXY` set | sends through it; a value that is not a usable proxy URL, or a client that pins names or refuses private addresses, is an error |
/// | `Proxy(url)` | sends through `url`; an unusable URL or a pinned name is an error |
///
/// A proxy is never quietly dropped: anything that keeps one from being used is a
/// [`BuildError::Egress`], never a direct client. Names always go to the proxy
/// unresolved (see [`egress`]).
pub fn build_client(cfg: ClientConfig, egress: &Egress) -> Result<Client, BuildError> {
    let route = egress::route(
        egress,
        egress::Checks {
            block_internal: cfg.block_internal,
            pinned: !cfg.resolve.is_empty(),
        },
    )
    .map_err(BuildError::Egress)?;

    // App headers are always sent. Browser headers + UA are sent only when we are
    // NOT emulating (the emulation profile provides its own coherent set). That
    // includes a requested emulation with no profile for the User-Agent, so the
    // caller's own User-Agent still goes out.
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
    // Through a proxy no destination is resolved here, so the filter would only
    // ever be asked about the proxy itself.
    let proxied = matches!(route, egress::Route::Proxy { .. });
    if cfg.block_internal && !proxied {
        // Both backends expose the same `dns_resolver` hook and an identical
        // `Resolve` trait, so one value serves whichever is compiled.
        b = b.dns_resolver(std::sync::Arc::new(guard::PublicOnlyResolver));
    }
    if let Some(t) = cfg.timeout {
        b = b.timeout(t);
    }
    b = match cfg.redirect {
        Redirect::None => b.redirect(redirect::Policy::none()),
        // The resolver above is never asked about an address written into a URL, so
        // a hop to `http://127.0.0.1/` would get past it. Such a hop is refused here,
        // before it is dialled.
        Redirect::Limited(n) if cfg.block_internal => {
            let limit = redirect::Policy::limited(n);
            b.redirect(redirect::Policy::custom(move |attempt| {
                if attempt
                    .url()
                    .host_str()
                    .is_some_and(guard::is_internal_literal)
                {
                    attempt.error(guard::NOT_PERMITTED)
                } else {
                    limit.redirect(attempt)
                }
            }))
        }
        Redirect::Limited(n) => b.redirect(redirect::Policy::limited(n)),
    };
    if cfg.cookie_store {
        b = b.cookie_store(true);
    }
    for (host, addr) in &cfg.resolve {
        b = b.resolve(host.as_str(), *addr);
    }

    b = match route {
        // The backend reads HTTP_PROXY, HTTPS_PROXY and ALL_PROXY by itself.
        egress::Route::System => b,
        egress::Route::Direct => b.no_proxy(),
        egress::Route::Proxy { url, .. } => {
            // The backend's own error is not passed on: it can quote the URL, and the
            // URL can hold a password. The value has already parsed as a proxy URL,
            // so what is left is the backend refusing it, or not finding the address
            // of a SOCKS proxy's host, which one backend looks up here.
            let p = Proxy::all(url.as_str()).map_err(|_| {
                BuildError::Egress(
                    "the HTTP client cannot use the proxy URL, or could not find the \
                     proxy's address"
                        .into(),
                )
            })?;
            // An explicit proxy turns off the ones from the environment in both
            // backends; clearing them first does not depend on that.
            b.no_proxy().proxy(p)
        }
    };

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
        if let Some(browser) = profile(&cfg) {
            // The profile's own headers (its User-Agent and navigation set)
            // with the app headers laid over them, so Authorization, Cookie
            // and the attribution token win over anything the profile sends.
            // default_headers() replaces the map the builder holds, so the
            // merged map has to be the last one set. The TLS, HTTP/2 and
            // header-order settings travel separately in emulation().
            let mut headers = browser.default_headers();
            for (k, v) in cfg.extra_headers.iter() {
                headers.insert(k.clone(), v.clone());
            }
            b = b.emulation(browser.emulation()).default_headers(headers);
        }
    }

    Ok(b.build()?)
}

/// A scan client described in terms an engine already has: a resolved browser
/// identity (headers + UA, from the private `adaptive` catalogue), optional
/// request auth, an optional attribution token, and the per-op transport policy.
///
/// [`build_scan_client`] turns this into a [`Client`], centralizing the ~15-line
/// "identity headers -> browser_headers, auth -> app headers, Identify token ->
/// `x-bug-bounty`" assembly that plessor (inject/authz), ambulo and toolmark each
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
/// to [`build_client`] for all backend-specific construction, egress included.
pub fn build_scan_client(spec: ScanClient, egress: &Egress) -> Result<Client, BuildError> {
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
    build_client(
        ClientConfig {
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
        },
        egress,
    )
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
        let c = build_client(
            ClientConfig {
                accept_invalid_certs: true,
                cookie_store: true,
                user_agent: Some(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
                        .into(),
                ),
                emulate: true,
                ..Default::default()
            },
            &Egress::Direct,
        );
        assert!(c.is_ok(), "build failed: {:?}", c.err());
    }

    /// A listener on loopback that answers every request with `reply` and counts them.
    fn counting_listener(reply: String) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = std::sync::Arc::clone(&seen);
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { return };
                let mut buf = [0u8; 4096];
                if s.read(&mut buf).unwrap_or(0) > 0 {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = s.write_all(reply.as_bytes());
                }
            }
        });
        (port, seen)
    }

    #[tokio::test]
    async fn block_internal_stops_a_redirect_to_an_internal_address_literal() {
        // The resolver filter never sees an address written into a URL, so a hop to
        // one has to be stopped before it is dialled.
        let (inner, inner_seen) = counting_listener(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into(),
        );
        let (outer, _) = counting_listener(format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{inner}/admin\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        ));
        let client = |block_internal| {
            build_client(
                ClientConfig {
                    timeout: Some(Duration::from_secs(5)),
                    redirect: Redirect::Limited(3),
                    block_internal,
                    ..Default::default()
                },
                &Egress::Direct,
            )
            .unwrap()
        };
        let url = format!("http://127.0.0.1:{outer}/");
        let r = client(true).get(&url).send().await;
        assert!(
            r.is_err(),
            "the hop was followed: {:?}",
            r.map(|r| r.status())
        );
        assert_eq!(inner_seen.load(std::sync::atomic::Ordering::SeqCst), 0);
        // The same client without the flag follows it, so the fixture is sound.
        let r = client(false).get(&url).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(inner_seen.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn will_emulate_tracks_feature_flag_and_family() {
        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
        assert_eq!(will_emulate(&ua(firefox)), cfg!(feature = "impersonate"));
        // No profile covers a User-Agent that names no browser.
        assert!(!will_emulate(&ua("Crossfyre-Scanner/1.0")));
        assert!(!will_emulate(&ClientConfig {
            emulate: false,
            ..ua(firefox)
        }));
    }

    #[cfg(feature = "impersonate")]
    #[test]
    fn a_user_agent_no_profile_covers_is_sent_as_it_is() {
        // voyage's --active-user-agent takes any string, and with emulation on a
        // string that names no browser used to leave the client with no
        // User-Agent at all. It has to go out, with the browser headers, as it
        // does when emulation is off.
        let mut extra_headers = HeaderMap::new();
        extra_headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer t"));
        let client = build_client(
            ClientConfig {
                extra_headers,
                browser_headers: headers_from_pairs(&[("accept-language", "en-GB".into())]),
                ..ua("Crossfyre-Scanner/1.0")
            },
            &Egress::Direct,
        )
        .unwrap();
        let sent = client.headers();
        assert_eq!(sent[header::USER_AGENT], "Crossfyre-Scanner/1.0");
        assert_eq!(sent[header::ACCEPT_LANGUAGE], "en-GB");
        assert_eq!(sent[header::AUTHORIZATION], "Bearer t");
        assert!(sent.get("te").is_none(), "no profile header goes out");
    }

    #[cfg(feature = "impersonate")]
    #[test]
    fn emulating_client_sends_the_profile_headers_under_the_app_headers() {
        let mut extra_headers = HeaderMap::new();
        extra_headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer t"));
        // An app header the profile also sets: the app's value has to win.
        extra_headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let client = build_client(
            ClientConfig {
                extra_headers,
                browser_headers: headers_from_pairs(&[("sec-ch-ua", "from-identity".into())]),
                ..ua("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
            },
            &Egress::Direct,
        )
        .unwrap();
        let sent = client.headers();
        assert_eq!(sent[header::AUTHORIZATION], "Bearer t");
        assert_eq!(sent[header::ACCEPT], "application/json");
        // The profile owns the User-Agent and the browser headers; the
        // identity's are not sent alongside them.
        assert_eq!(
            sent[header::USER_AGENT],
            emulation::Browser::Firefox.user_agent()
        );
        assert_eq!(sent["te"], "trailers");
        assert!(sent.get("sec-ch-ua").is_none());
    }
}

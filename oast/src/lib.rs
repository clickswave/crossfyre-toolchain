//! Self-hosted OAST (out-of-band application security testing) interaction server.
//!
//! Three listeners share one in-memory, zero-knowledge interaction store:
//!   - HTTP(S) capture (public, *.OAST_DOMAIN): logs every inbound request.
//!   - DNS responder   (public, UDP :53):        answers A + the ACME challenge TXT.
//!   - Poll API         (on 443 with capture, or :8085 plaintext for dev/localhost):
//!     register a correlation + public key, drain sealed interactions.
//!
//! plessor embeds `<corr><rand>.OAST_DOMAIN` in an OOB payload and polls; any callback
//! confirms the blind vulnerability fired. Interactions are sealed to the scan's
//! public key, so the server never holds plaintext (see `crypto` + `store`).
//!
//! This is the same server that backs the managed pool; self-hosters run it via
//! `crossfyre oast serve` (in-process) or the standalone `oast` binary under systemd.

pub mod client_tui;
mod crypto;
mod dns;
mod http_capture;
mod poll;
pub mod store;
mod tls;

use std::sync::Arc;

#[derive(Clone)]
pub struct Config {
    /// Primary wildcard base domain (first in the pool); reported by /config.
    pub domain: String,
    /// Full pool of domains this box accepts callbacks on. One box can be
    /// authoritative for several delegated zones; a callback under any of them is
    /// matched to its correlation id and sealed the same way.
    pub domains: Vec<String>,
    pub http_addr: String,
    pub dns_addr: String,
    pub poll_addr: String,
    /// A-record returned by the DNS responder (this server's public IP).
    pub public_ip: [u8; 4],
    pub ttl_secs: u64,
    /// HTTPS capture listener; enabled only when tls_cert + tls_key are set.
    pub https_addr: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Optional per-domain cert pool: "dom=cert:key,dom2=cert:key" for SNI. Lets one
    /// box serve wildcard TLS for several delegated OAST domains on the same 443.
    pub tls_certs: Option<String>,
    /// File lego writes the ACME DNS-01 challenge value to; we answer it as a TXT
    /// record for `_acme-challenge.<domain>` since we are authoritative for the zone.
    pub acme_txt_file: Option<String>,
    /// Show the live interaction dashboard instead of log lines. Honoured only
    /// when stdout is a terminal; a service unit with piped output ignores it.
    pub tui: bool,
}

impl Config {
    /// Full config from environment (the standalone `oast` binary uses this).
    pub fn from_env() -> Self {
        // OAST_DOMAIN is a comma-separated pool; the first entry is the primary.
        let domains: Vec<String> = std::env::var("OAST_DOMAIN")
            .unwrap_or_else(|_| "oast.localhost".to_string())
            .split(',')
            .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        let public_ip = std::env::var("OAST_PUBLIC_IP")
            .ok()
            .and_then(|s| parse_ipv4(&s))
            .unwrap_or([127, 0, 0, 1]);
        let mut cfg = Self::new(domains, public_ip);
        if let Ok(v) = std::env::var("OAST_HTTP_ADDR") {
            cfg.http_addr = v;
        }
        if let Ok(v) = std::env::var("OAST_DNS_ADDR") {
            cfg.dns_addr = v;
        }
        if let Ok(v) = std::env::var("OAST_POLL_ADDR") {
            cfg.poll_addr = v;
        }
        if let Ok(v) = std::env::var("OAST_HTTPS_ADDR") {
            cfg.https_addr = v;
        }
        if let Some(v) = std::env::var("OAST_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
        {
            cfg.ttl_secs = v;
        }
        cfg.tls_cert = std::env::var("OAST_TLS_CERT")
            .ok()
            .filter(|s| !s.is_empty());
        cfg.tls_key = std::env::var("OAST_TLS_KEY").ok().filter(|s| !s.is_empty());
        cfg.tls_certs = std::env::var("OAST_TLS_CERTS")
            .ok()
            .filter(|s| !s.is_empty());
        cfg.acme_txt_file = std::env::var("OAST_ACME_TXT_FILE")
            .ok()
            .filter(|s| !s.is_empty());
        cfg
    }

    /// Programmatic constructor with sane defaults (the `crossfyre oast serve` path).
    pub fn new(domains: Vec<String>, public_ip: [u8; 4]) -> Self {
        let domain = domains
            .first()
            .cloned()
            .unwrap_or_else(|| "oast.localhost".to_string());
        Self {
            domain,
            domains,
            http_addr: "0.0.0.0:80".to_string(),
            dns_addr: "0.0.0.0:53".to_string(),
            poll_addr: "0.0.0.0:8085".to_string(),
            public_ip,
            ttl_secs: 3600,
            https_addr: "0.0.0.0:443".to_string(),
            tls_cert: None,
            tls_key: None,
            tls_certs: None,
            acme_txt_file: None,
            tui: false,
        }
    }

    /// Whether HTTPS (443) should be served: a single cert or an SNI cert pool.
    pub fn tls_enabled(&self) -> bool {
        (self.tls_cert.is_some() && self.tls_key.is_some()) || self.tls_certs.is_some()
    }
}

pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

/// Run the OAST server: install the crypto provider, then serve DNS + poll +
/// HTTP(S) capture until the process exits. Never returns under normal operation.
pub async fn run(cfg: Config) {
    // Best-effort logging init (no-op if the caller already set a subscriber).
    let _ = tracing_subscriber::fmt().with_target(false).try_init();
    // Install the ring crypto provider once so RustlsConfig has a process-wide
    // default (rustls 0.23 does not auto-select when TLS is enabled).
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing::info!(
        domain = %cfg.domain, http = %cfg.http_addr, dns = %cfg.dns_addr,
        poll = %cfg.poll_addr, tls = cfg.tls_enabled(), "oast starting"
    );

    let store = Arc::new(store::Store::new(cfg.ttl_secs));

    // Attach the live dashboard only when asked for and only with a real
    // terminal. Under a service unit stdout is piped, and drawing into it would
    // corrupt the log; there the server logs interactions as it always has.
    if cfg.tui && cfx_tui::available() {
        let (tx, rx) = std::sync::mpsc::channel();
        store.observe(tx);
        let listeners = format!(
            "dns {}  http {}  {}",
            cfg.dns_addr,
            cfg.http_addr,
            if cfg.tls_enabled() {
                "https on"
            } else {
                "https off"
            }
        );
        std::thread::spawn(move || {
            let _ = client_tui::run(listeners, rx);
            // The operator quit the dashboard. The servers keep running; exit
            // the process so a foreground `oast` stops when its UI is closed.
            std::process::exit(0);
        });
    }

    {
        let s = store.clone();
        tokio::spawn(async move { s.gc_loop().await });
    }
    {
        let s = store.clone();
        let c = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = dns::serve(c, s).await {
                tracing::error!("dns server error: {e}");
            }
        });
    }
    {
        let s = store.clone();
        let c = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = poll::serve(c, s).await {
                tracing::error!("poll server error: {e}");
            }
        });
    }
    if cfg.tls_enabled() {
        let s = store.clone();
        let c = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = http_capture::serve_https(c, s).await {
                tracing::error!("https capture server error: {e}");
            }
        });
    }

    if let Err(e) = http_capture::serve(cfg, store).await {
        tracing::error!("http capture server error: {e}");
    }
}

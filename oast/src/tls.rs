//! Multi-domain SNI cert resolution. One box can be authoritative for a *pool* of
//! delegated OAST domains (so callbacks are not all concentrated on a single domain
//! a WAF could blocklist), each with its own wildcard cert, served on one 443
//! listener. rustls picks the right cert per TLS SNI.

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

#[derive(Debug)]
struct SniResolver {
    /// (base_domain, cert). Matched when SNI == base or SNI ends with ".base".
    entries: Vec<(String, Arc<CertifiedKey>)>,
    default: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = hello.server_name() {
            let sni = sni.to_ascii_lowercase();
            for (dom, ck) in &self.entries {
                if sni == *dom || sni.ends_with(&format!(".{dom}")) {
                    return Some(ck.clone());
                }
            }
        }
        // No SNI match: fall back to the default cert, else the first pool cert.
        self.default
            .clone()
            .or_else(|| self.entries.first().map(|(_, ck)| ck.clone()))
    }
}

fn load_certified_key(cert_path: &str, key_path: &str) -> Option<Arc<CertifiedKey>> {
    let cert_pem = std::fs::read(cert_path).ok()?;
    let key_pem = std::fs::read(key_path).ok()?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .ok()?;
    if certs.is_empty() {
        return None;
    }
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_pem.as_slice()).ok()??;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).ok()?;
    Some(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Build a rustls ServerConfig from the single default cert (OAST_TLS_CERT/KEY) plus
/// an optional pool spec (OAST_TLS_CERTS = "dom=cert:key,dom2=cert:key"). Returns
/// None if no usable cert is found.
pub fn build_server_config(
    default_cert: Option<&str>,
    default_key: Option<&str>,
    certs_spec: Option<&str>,
) -> Option<Arc<ServerConfig>> {
    let mut entries: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
    if let Some(spec) = certs_spec {
        for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let Some((dom, paths)) = item.split_once('=') else {
                continue;
            };
            let Some((c, k)) = paths.split_once(':') else {
                continue;
            };
            match load_certified_key(c.trim(), k.trim()) {
                Some(ck) => entries.push((dom.trim().trim_matches('.').to_ascii_lowercase(), ck)),
                None => tracing::warn!("oast tls: failed to load pool cert for {dom}"),
            }
        }
    }
    let default = match (default_cert, default_key) {
        (Some(c), Some(k)) => load_certified_key(c, k),
        _ => None,
    };
    if entries.is_empty() && default.is_none() {
        return None;
    }
    let resolver = SniResolver { entries, default };
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Some(Arc::new(config))
}

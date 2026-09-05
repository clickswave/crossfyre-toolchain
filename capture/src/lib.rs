//! Shared traffic-capture core for the Web Tracer family (desktop proxy today, mobile VpnService
//! netstack next). The privacy-safe reduction (`shape` / `TraceEvent`) lives in `trace.rs`; this
//! module owns the parts a MITM capture front-end needs regardless of HOW it gets a client stream:
//!
//!   - the session CA + on-the-fly per-SNI leaf certs (`SessionCa`, `make_leaf`, `MitmResolver`),
//!   - a ready-to-use `TlsAcceptor` that terminates a client connection as any host (`mitm_acceptor`),
//!   - the `Egress` abstraction for reaching the origin: `Direct` now, a node tunnel later.
//!
//! The desktop proxy (`trace_proxy.rs`) accepts a browser CONNECT and hands the upgraded socket to
//! this acceptor; the mobile netstack will reassemble a TCP flow off the TUN fd and do the same. The
//! CA machinery is identical either way, which is the point: install one CA, trust every capture
//! surface, and never diverge the certificate behavior between desktop and mobile.

pub mod body;
pub mod config;
pub mod flow;
pub mod reduce;

pub use config::CaptureConfig;
pub use flow::{FlowOutcome, serve_mitm_flow};
pub use reduce::{FullExchange, TraceEvent, body_field_names, redact_url};

use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;

type BoxErr = Box<dyn Error + Send + Sync>;

// ---------------------------------------------------------------------------
// Session CA + on-the-fly per-host leaf certs
// ---------------------------------------------------------------------------

/// The Web Tracer CA. On desktop it is PERSISTED so the user installs `pem` once and it keeps working
/// across sessions (the signing key is stable). On mobile the app generates one on-device (the private
/// key never leaves the phone) and shows `pem` for the user to install. A fresh CA per session (same
/// name, new key) is exactly what makes an already-installed CA fail with SEC_ERROR_BAD_SIGNATURE,
/// because the leaf is signed by a key the installed CA does not match.
pub struct SessionCa {
    pub cert: rcgen::Certificate,
    pub key: rcgen::KeyPair,
    pub pem: String,
}

/// The CA's fixed parameters. Shared by generation and reload so a reloaded issuer has the same
/// subject and (with the persisted key) the same public key and identifier the installed CA carries.
pub fn ca_params() -> Result<rcgen::CertificateParams, BoxErr> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose};
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    // Path-length 0: this CA signs leaf certificates for the flows we intercept
    // and nothing else. It has no reason to be able to mint further CAs.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    // Bound the lifetime. rcgen's defaults are 1975 to 4096, so the certificate
    // the user installs in their OS trust store was, in effect, permanent. If
    // the key is ever recovered from the device, that is indefinite transparent
    // interception of every site for that user, long after they have stopped
    // using the tracer and forgotten the certificate is there. A short life
    // means a stale trust anchor expires on its own and becomes visible.
    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(30 * 24 * 60 * 60)).into();
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "Crossfyre Web Tracer CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Crossfyre");
    Ok(params)
}

/// Mint a brand-new CA (new keypair). Callers that want persistence write `pem` + the key themselves.
pub fn generate_ca() -> Result<SessionCa, BoxErr> {
    let key = rcgen::KeyPair::generate()?;
    let cert = ca_params()?.self_signed(&key)?;
    let pem = cert.pem();
    Ok(SessionCa { cert, key, pem })
}

/// Reconstruct a CA from a persisted cert PEM + key PEM. The issuer is re-derived from the fixed
/// [`ca_params`] and the given key, so it shares the installed CA's subject and public key.
pub fn load_ca(cert_pem: &str, key_pem: &str) -> Result<SessionCa, BoxErr> {
    let key = rcgen::KeyPair::from_pem(key_pem)?;
    let cert = ca_params()?.self_signed(&key)?;
    Ok(SessionCa {
        cert,
        key,
        pem: cert_pem.to_string(),
    })
}

/// Mint (unsigned-cached by the caller) a leaf cert for `host`, signed by the session CA. The chain is
/// `[leaf, ca]` so a client that trusts the CA validates the leaf.
pub fn make_leaf(ca: &SessionCa, host: &str) -> Result<Arc<CertifiedKey>, BoxErr> {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let leaf_key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![host.to_string()])?;
    params.distinguished_name.push(DnType::CommonName, host);
    let leaf = params.signed_by(&leaf_key, &ca.cert, &ca.key)?;

    let leaf_der: CertificateDer<'static> = leaf.der().clone();
    let ca_der: CertificateDer<'static> = ca.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der)?;
    Ok(Arc::new(CertifiedKey::new(
        vec![leaf_der, ca_der],
        signing_key,
    )))
}

/// Resolves (and caches) a leaf cert per SNI hostname, signed by the session CA.
pub struct MitmResolver {
    ca: Arc<SessionCa>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl MitmResolver {
    pub fn new(ca: Arc<SessionCa>) -> Self {
        Self {
            ca,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn leaf_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(k) = self.cache.lock().unwrap().get(host) {
            return Some(k.clone());
        }
        let ck = make_leaf(&self.ca, host).ok()?;
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), ck.clone());
        Some(ck)
    }
}

impl std::fmt::Debug for MitmResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MitmResolver")
    }
}

impl ResolvesServerCert for MitmResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Prefer SNI; fall back to a default so a no-SNI client still gets a cert.
        let host = hello
            .server_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "localhost".into());
        self.leaf_for(&host)
    }
}

/// Install aws-lc-rs as the process-wide rustls [`CryptoProvider`]. Idempotent: a second call (or a
/// lost install race) returns Err, which is ignored. This matters on any target whose dependency
/// graph also compiles in `ring` (e.g. the mobile app pulls it via quinn-proto / rcgen): with both
/// the `aws-lc-rs` and `ring` rustls features present, rustls cannot auto-select a provider and every
/// `ClientConfig`/`ServerConfig::builder()` panics. Calling this once at startup ends the ambiguity.
/// Desktop, with a single provider, does not need it but may call it harmlessly.
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A `TlsAcceptor` that terminates any client connection by minting a leaf for its SNI. ALPN is pinned
/// to HTTP/1.1: we do not MITM h2, so we force the client onto h1 (browsers and OkHttp both accept
/// this). Both the desktop proxy and the mobile netstack build their acceptor here so the TLS
/// behavior is identical.
pub fn mitm_acceptor(ca: Arc<SessionCa>) -> TlsAcceptor {
    let resolver = Arc::new(MitmResolver::new(ca));
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(server_config))
}

// ---------------------------------------------------------------------------
// Capture configuration: privacy-safe shapes (default) vs full capture + interception
// ---------------------------------------------------------------------------

/// An operator-edited request to forward instead of the original (Burp-style modify-and-forward). The
/// destination host/port is fixed by the already-open flow; only the request line, headers and body
/// can change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditedRequest {
    pub method: String,
    /// Path + query (origin-form), e.g. `/api/x?y=1`.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A manual-interception decision for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptDecision {
    /// Let the request proceed to the origin unchanged.
    Forward,
    /// Forward, but with an operator-edited request line/headers/body.
    ForwardModified(EditedRequest),
    /// Block it: the client gets a synthetic 403 and nothing is forwarded.
    Drop,
}

/// A hook the host (mobile app / desktop proxy) implements to gate a request in MANUAL intercept
/// mode. The capture core calls `decide` before forwarding; the implementation parks the request with
/// the control plane and blocks until a human forwards or drops it. Returning `Forward` on any error
/// keeps traffic flowing (fail-open) - implementors choose their own policy.
pub trait InterceptGate: Send + Sync {
    fn decide<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = InterceptDecision> + Send + 'a>>;
}

/// How a capture session behaves. Default = privacy-safe shapes only, no interception (the historic
/// behaviour). `full` also records complete request/response bytes; `gate` (when set) intercepts each
/// request for manual approval.
#[derive(Clone, Default)]
pub struct CaptureCfg {
    pub full: bool,
    pub gate: Option<Arc<dyn InterceptGate>>,
}

impl std::fmt::Debug for CaptureCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureCfg")
            .field("full", &self.full)
            .field("gate", &self.gate.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Egress: how an inspected flow reaches the origin
// ---------------------------------------------------------------------------

/// Where a captured flow egresses after inspection. `Direct` dials the origin from the local host
/// (the phone, on mobile) so the target sees the local IP. A future `NodeTunnel { .. }` variant will
/// dial a chosen crossfyre node and egress from THERE (the target sees the node IP) - the per-node
/// isolated-egress model applied to a device. Keeping this an enum behind one `connect` keeps the
/// data path identical; unlocking node routing is adding a variant, not re-plumbing.
#[derive(Clone, Debug)]
pub enum Egress {
    /// Dial the origin directly from this host.
    Direct,
    // NodeTunnel { node: std::net::SocketAddr, token: String },  // locked; ships with mobile routing.
}

impl Egress {
    /// Open a byte stream to `(host, port)` per the routing mode. Async, so a future node-tunnel
    /// variant can perform its own handshake here without any caller change.
    pub async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        match self {
            Egress::Direct => tokio::net::TcpStream::connect((host, port)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_signs_a_verifiable_leaf() {
        let ca = generate_ca().expect("ca");
        assert!(ca.pem.contains("BEGIN CERTIFICATE"));
        // A leaf mints and carries the [leaf, ca] chain (2 certs).
        let leaf = make_leaf(&ca, "example.com").expect("leaf");
        assert_eq!(leaf.cert.len(), 2);
    }

    #[test]
    fn reloaded_ca_shares_identity() {
        // Trust survives a reload because the SIGNING KEY is stable, not because the CA cert is
        // byte-identical (rcgen randomizes the serial, so `self_signed` twice differs in DER). The
        // installed CA keeps validating fresh leaves as long as the issuer name + key match, which is
        // the invariant here: the reloaded keypair round-trips to the same PEM.
        let ca = generate_ca().expect("ca");
        let key_pem = ca.key.serialize_pem();
        let reloaded = load_ca(&ca.pem, &key_pem).expect("reload");
        assert_eq!(key_pem, reloaded.key.serialize_pem(), "same signing key");
        assert_eq!(ca.pem, reloaded.pem, "serves the installed cert verbatim");
        // And the reloaded CA can still mint a leaf.
        assert!(make_leaf(&reloaded, "example.com").is_ok());
    }

    #[test]
    fn resolver_caches_per_host() {
        let ca = Arc::new(generate_ca().expect("ca"));
        let r = MitmResolver::new(ca);
        let a = r.leaf_for("a.example").expect("a");
        let a2 = r.leaf_for("a.example").expect("a2");
        assert!(Arc::ptr_eq(&a, &a2), "same host returns the cached leaf");
        let b = r.leaf_for("b.example").expect("b");
        assert!(!Arc::ptr_eq(&a, &b), "different host mints a new leaf");
    }
}

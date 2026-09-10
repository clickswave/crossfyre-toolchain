//! OAST client (out-of-band). Confirms blind vulnerabilities by making the target
//! call back to the Crossfyre OAST server and reading the (encrypted) interaction.
//!
//! Zero-knowledge: cortex generates an RSA keypair per scan and registers the
//! PUBLIC key with the OAST server; the server seals every interaction to it, so
//! neither the server nor Crossfyre can read the contents, only cortex, holding the
//! private key, decrypts on poll. Each template gets a fresh correlation id (bound
//! to the same scan keypair) so callbacks stay attributable per check.
//!
//! Enabled only when CORTEX_OAST_DOMAIN + CORTEX_OAST_API_URL are set.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::Engine as _;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};
use sha2::Sha256;
use std::time::Duration;
use transport::Client;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn b64d(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
}

fn rand_alnum(n: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// A per-scan OAST client: one RSA keypair, reused across the scan's correlations.
pub struct OastClient {
    /// Callback domain pool. Each payload picks one at random so a single scan's
    /// callbacks are spread across domains rather than concentrated on one that a
    /// WAF could blocklist. All are backed by the same OAST store + poll API.
    domains: Vec<String>,
    api_base: String,
    priv_key: RsaPrivateKey,
    pubkey_b64: String,
}

/// A registered correlation (per template): the id embedded in payloads and the
/// secret that authorizes polling it.
pub struct OastReg {
    corr_id: String,
    secret: String,
}

impl OastClient {
    /// Build a client (generating a fresh keypair) if OAST is configured.
    pub fn from_env() -> Option<OastClient> {
        // CORTEX_OAST_DOMAIN may be a comma-separated pool of callback domains.
        let domains: Vec<String> = std::env::var("CORTEX_OAST_DOMAIN")
            .ok()?
            .split(',')
            .map(String::from)
            .collect();
        let api_base = std::env::var("CORTEX_OAST_API_URL").ok()?;
        Self::from_spec(domains, &api_base)
    }

    /// Build a client from an explicit endpoint spec (the node resolves the
    /// workspace's selected OAST endpoint and hands it to cortex per scan). This
    /// takes precedence over the node's env fallback so a scan can target a BYO
    /// (self-hosted) OAST or the managed pool per the user's choice.
    pub fn from_spec(domains: Vec<String>, api_url: &str) -> Option<OastClient> {
        let domains: Vec<String> = domains
            .iter()
            .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        let api_base = api_url.trim().trim_end_matches('/');
        if domains.is_empty() || api_base.is_empty() {
            return None;
        }
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).ok()?;
        let pub_key = RsaPublicKey::from(&priv_key);
        let der = pub_key.to_pkcs1_der().ok()?;
        Some(OastClient {
            domains,
            api_base: api_base.to_string(),
            priv_key,
            pubkey_b64: b64(der.as_bytes()),
        })
    }

    /// Register a fresh correlation for one template. None if registration fails.
    pub async fn register(&self, http: &Client) -> Option<OastReg> {
        let corr_id = rand_alnum(crate::oast::CORR_LEN);
        let secret = rand_alnum(32);
        let resp = http
            .post(format!("{}/register", self.api_base))
            .json(&json!({ "corr_id": corr_id, "pubkey": self.pubkey_b64, "secret": secret }))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .ok()?;
        let body: Value = resp.json().await.ok()?;
        if body["ok"].as_bool().unwrap_or(false) {
            Some(OastReg { corr_id, secret })
        } else {
            None
        }
    }

    /// The callback host for a correlation: `<corr><rand>.<domain>`, with the domain
    /// drawn at random from the pool.
    pub fn host(&self, reg: &OastReg) -> String {
        use rand::Rng;
        let domain = if self.domains.len() == 1 {
            &self.domains[0]
        } else {
            &self.domains[rand::thread_rng().gen_range(0..self.domains.len())]
        };
        format!("{}{}.{}", reg.corr_id, rand_alnum(13), domain)
    }

    /// The callback host for a correlation, plus the marker that identifies THIS
    /// payload within it.
    ///
    /// One correlation can carry any number of payloads: the hostname already
    /// ends in thirteen random characters, and the server seals the full
    /// hostname it was asked for. That marker is what lets a single poll at the
    /// end of a scan say WHICH injection point called back, instead of every
    /// payload needing its own registration and its own blocking wait.
    pub fn host_marked(&self, reg: &OastReg) -> (String, String) {
        use rand::Rng;
        let domain = if self.domains.len() == 1 {
            &self.domains[0]
        } else {
            &self.domains[rand::thread_rng().gen_range(0..self.domains.len())]
        };
        let marker = rand_alnum(13);
        (format!("{}{}.{}", reg.corr_id, marker, domain), marker)
    }

    /// Poll once and return the hostnames that were actually called back.
    ///
    /// The sealed plaintext carries `full_host`, so a batched scan can match a
    /// callback to the payload that caused it. Only interactions we can decrypt
    /// count, which is what makes a callback proof: nobody else can produce one
    /// sealed to this scan's key.
    pub async fn poll_hosts(&self, http: &Client, reg: &OastReg) -> Vec<String> {
        let mut out = Vec::new();
        let url = format!(
            "{}/poll?corr_id={}&secret={}",
            self.api_base, reg.corr_id, reg.secret
        );
        let Ok(resp) = http.get(&url).timeout(Duration::from_secs(10)).send().await else {
            return out;
        };
        let Ok(body) = resp.json::<Value>().await else {
            return out;
        };
        if let Some(items) = body["interactions"].as_array() {
            for it in items {
                if let Some(enc) = it["enc"].as_str()
                    && let Some(plain) = self.decrypt(enc)
                    && let Ok(v) = serde_json::from_slice::<Value>(&plain)
                    && let Some(h) = v["full_host"].as_str()
                {
                    out.push(h.to_ascii_lowercase());
                }
            }
        }
        out
    }

    /// Poll for interactions on a correlation, returning how many we could decrypt
    /// (i.e. real callbacks sealed to our key).
    pub async fn poll(&self, http: &Client, reg: &OastReg) -> u64 {
        let url = format!(
            "{}/poll?corr_id={}&secret={}",
            self.api_base, reg.corr_id, reg.secret
        );
        let resp = match http.get(&url).timeout(Duration::from_secs(6)).send().await {
            Ok(r) => r,
            Err(_) => return 0,
        };
        let body: Value = match resp.json().await {
            Ok(b) => b,
            Err(_) => return 0,
        };
        let mut n = 0u64;
        if let Some(items) = body["interactions"].as_array() {
            for it in items {
                if let Some(enc) = it["enc"].as_str()
                    && self.decrypt(enc).is_some()
                {
                    n += 1;
                }
            }
        }
        n
    }

    /// Decrypt a sealed interaction blob {k,n,c} with our private key.
    fn decrypt(&self, enc: &str) -> Option<Vec<u8>> {
        let blob: Value = serde_json::from_str(enc).ok()?;
        let k = b64d(blob["k"].as_str()?)?;
        let n = b64d(blob["n"].as_str()?)?;
        let c = b64d(blob["c"].as_str()?)?;
        let aes_key = self.priv_key.decrypt(Oaep::new::<Sha256>(), &k).ok()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
        cipher.decrypt(Nonce::from_slice(&n), c.as_ref()).ok()
    }

    pub async fn deregister(&self, http: &Client, reg: &OastReg) {
        let _ = http
            .post(format!("{}/deregister", self.api_base))
            .json(&json!({ "corr_id": reg.corr_id, "secret": reg.secret }))
            .timeout(Duration::from_secs(5))
            .send()
            .await;
    }
}

/// Correlation id length, must match the OAST server's `store::CORR_LEN`.
pub const CORR_LEN: usize = 20;

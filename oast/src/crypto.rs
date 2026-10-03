//! Client-side encryption for OAST interactions (zero-knowledge store).
//!
//! Each interaction is sealed to the correlation's registered RSA public key: a
//! random AES-256-GCM data key encrypts the interaction, and that data key is
//! wrapped with RSA-OAEP(SHA-256) to the client's public key. The server stores
//! only ciphertext it cannot read; only the poller, holding the private key, can
//! decrypt. This is the same construction interactsh uses, and it is what makes a
//! shared managed OAST domain safe for sensitive out-of-band data.
//!
//! Wire format of a sealed interaction is a JSON object `{"k","n","c"}`:
//!   k = base64(RSA-OAEP(aes_key))   n = base64(nonce[12])   c = base64(AES-GCM ct)

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::Engine as _;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Seal `plaintext` to a base64 PKCS#1-DER RSA public key. Returns the JSON blob
/// string, or None if the key is malformed.
pub fn seal_to_pubkey(pubkey_der_b64: &str, plaintext: &[u8]) -> Option<String> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(pubkey_der_b64.trim())
        .ok()?;
    let pubkey = RsaPublicKey::from_pkcs1_der(&der).ok()?;

    // Random AES-256 data key + 96-bit nonce.
    let mut aes_key = [0u8; 32];
    OsRng.fill_bytes(&mut aes_key);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).ok()?;

    // Wrap the data key with RSA-OAEP(SHA-256).
    let enc_key = pubkey
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &aes_key)
        .ok()?;

    Some(
        serde_json::json!({
            "k": b64(&enc_key),
            "n": b64(&nonce),
            "c": b64(&ct),
        })
        .to_string(),
    )
}

/// Whether a base64 PKCS#1-DER string parses as an RSA public key (used to reject
/// junk registrations early).
pub fn valid_pubkey(pubkey_der_b64: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(pubkey_der_b64.trim())
        .ok()
        .and_then(|der| RsaPublicKey::from_pkcs1_der(&der).ok())
        .is_some()
}

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

use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine as _;
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
    let aes_key = Aes256Gcm::generate_key(OsRng);
    let nonce = Aes256Gcm::generate_nonce(OsRng);

    let cipher = Aes256Gcm::new(&aes_key);
    let ct = cipher.encrypt(&nonce, plaintext).ok()?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPublicKey;

    fn unb64(v: &serde_json::Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(v.as_str().expect("a string"))
            .expect("base64")
    }

    /// The poller opens a sealed interaction with its private key: a 32 byte data key
    /// under RSA-OAEP(SHA-256), a 12 byte nonce, and the AES-256-GCM ciphertext. Two
    /// seals of the same text share neither key nor nonce.
    #[test]
    fn a_sealed_interaction_opens_with_the_private_key() {
        let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("a key");
        let der = private.to_public_key().to_pkcs1_der().expect("der");
        let pubkey = b64(der.as_bytes());
        assert!(valid_pubkey(&pubkey));

        let seal = |text: &[u8]| -> serde_json::Value {
            serde_json::from_str(&seal_to_pubkey(&pubkey, text).expect("sealed")).unwrap()
        };
        let sealed = seal(b"GET /x HTTP/1.1");
        let key = private
            .decrypt(Oaep::new::<Sha256>(), &unb64(&sealed["k"]))
            .expect("the data key opens");
        assert_eq!(key.len(), 32);
        let nonce = unb64(&sealed["n"]);
        assert_eq!(nonce.len(), 12);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let plain = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                unb64(&sealed["c"]).as_slice(),
            )
            .expect("the interaction opens");
        assert_eq!(plain, b"GET /x HTTP/1.1");

        let again = seal(b"GET /x HTTP/1.1");
        assert_ne!(again["n"], sealed["n"]);
        let key_again = private
            .decrypt(Oaep::new::<Sha256>(), &unb64(&again["k"]))
            .unwrap();
        assert_ne!(key_again, key);
    }
}

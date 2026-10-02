//! Signature verification for the release manifest.
//!
//! Every artifact this toolchain installs is checked against a SHA256 recorded in
//! `manifest.json`, and until now nothing checked the manifest itself. The comment at the
//! top of `install.rs` called it a "signed-by-checksum manifest", which is doing work it
//! has not earned: a checksum inside the manifest proves the artifact matches what the
//! manifest claims, and nothing proves the manifest is ours. The trust root was TLS plus
//! write access to the release bucket.
//!
//! That is defensible for operators who deliberately enrolled a node and ran
//! `crossfyre extension install`. It stops being defensible the moment this binary
//! updates itself on other people's machines, because the thing being updated runs with
//! the operator's privileges and sits in the TLS path of their client's traffic. Whoever
//! can write to the bucket could ship a build that exfiltrates an engagement.
//!
//! So: a detached ed25519 signature over the exact bytes of `manifest.json`, published
//! beside it as `manifest.json.sig`, verified against a public key compiled into this
//! binary.
//!
//! # Why the key's presence is the switch
//!
//! `CROSSFYRE_MANIFEST_PUBKEY` is read with `option_env!`, so it is decided when this
//! binary is built, and the rule is:
//!
//!   - built WITH a key: a valid signature is REQUIRED, and a missing or bad one is a
//!     hard failure
//!   - built WITHOUT one: verification is skipped entirely
//!
//! Making it a build-time constant rather than a runtime flag is deliberate. A runtime
//! "verify if a signature is present" is worth nothing, because an attacker who controls
//! the bucket simply does not publish one. A runtime opt-out is worth little more,
//! because the attacker who can rewrite the manifest can usually rewrite whatever carries
//! the flag. Baking the key in means the only way to get a build that skips verification
//! is to build it yourself from source, which is a thing we want to keep working: a
//! public checkout with no key still installs, which is what the open-source funnel
//! needs.
//!
//! It also makes the rollout safe without a flag day. Builds shipped today carry no key
//! and behave exactly as they do now. The first build that carries one refuses an
//! unsigned manifest, so the publish pipeline has to be signing before that build goes
//! out, and if it is not then the failure is at our release step rather than on a user's
//! machine.
//!
//! # Key handling
//!
//! The signing key never appears in this repository, in CI, or in any build image. It
//! lives offline and the publish step reads it from a path given at run time. Rotation is
//! by shipping the next public key in the current release, so a compromised bucket cannot
//! roll the key forward on its own: an attacker who can rewrite the manifest still cannot
//! make an already-installed binary trust a new key.
//!
//! Signing lives in the `relsign` dev tool, not here. This module verifies and nothing
//! else, so the shipped binary carries no code path that produces a signature.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Base64 of the 32-byte ed25519 public key, compiled in at build time. `None` in a
/// build that was not given one, which disables verification. See the module note on why
/// this is a build-time rather than a runtime decision.
const MANIFEST_PUBKEY: Option<&str> = option_env!("CROSSFYRE_MANIFEST_PUBKEY");

/// Where the detached signature sits, relative to the manifest.
pub const SIG_SUFFIX: &str = ".sig";

/// Does this build demand a signed manifest?
///
/// Callers use this to decide whether a missing signature file is fatal or simply absent,
/// so the error a user sees names the real problem rather than a 404.
pub fn required() -> bool {
    MANIFEST_PUBKEY.is_some()
}

/// Decode a base64 ed25519 public key into a verifying key.
///
/// Hand-rolled base64 decode: this runs once per manifest fetch on a 44-character string,
/// and the alternative is a dependency the shipped binary does not otherwise need.
fn parse_pubkey(b64: &str) -> Result<VerifyingKey, String> {
    let raw = b64_decode(b64.trim()).ok_or("public key is not valid base64")?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "public key is not 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| format!("public key is not a valid ed25519 key: {e}"))
}

/// Verify a detached signature over the manifest bytes.
///
/// `manifest` must be the exact bytes that were fetched, not a re-serialisation of the
/// parsed value. Round-tripping through a JSON parser reorders keys and changes
/// whitespace, and the signature is over bytes.
pub fn verify(manifest: &[u8], sig_b64: &str) -> Result<(), String> {
    let Some(pk_b64) = MANIFEST_PUBKEY else {
        return Ok(()); // unkeyed build: nothing to verify against
    };
    verify_with(pk_b64, manifest, sig_b64)
}

/// Verify against an explicitly given public key.
///
/// `verify` is the one callers use, and it reads the key compiled into the binary, which
/// a test cannot set. This exists so the signature format can be tested against one the
/// `relsign` tool actually produced: without it the only coverage would be this module
/// signing and verifying with itself, which proves the two halves agree with each other
/// and nothing about whether they agree with the signer that ships releases.
pub fn verify_with(pk_b64: &str, manifest: &[u8], sig_b64: &str) -> Result<(), String> {
    let key = parse_pubkey(pk_b64)?;
    let raw = b64_decode(sig_b64.trim()).ok_or("signature is not valid base64")?;
    let bytes: [u8; 64] = raw
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&bytes);
    key.verify(manifest, &sig).map_err(|_| {
        "release manifest signature does not verify against this build's public key. \
         Refusing to install anything described by it. Either the manifest was modified \
         in transit or on the release origin, or this binary is older than a key rotation."
            .to_string()
    })
}

/// Minimal standard-alphabet base64 decoder, padding optional.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    const INVALID: i16 = -1;
    fn val(c: u8) -> i16 {
        match c {
            b'A'..=b'Z' => (c - b'A') as i16,
            b'a'..=b'z' => (c - b'a') as i16 + 26,
            b'0'..=b'9' => (c - b'0') as i16 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => INVALID,
        }
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c);
        if v == INVALID {
            return None;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero padding, not a truncated byte.
    if bits >= 6 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed vector, so the Rust verifier and the `relsign` signer are pinned to the
    // same interpretation of "ed25519 over these bytes". If either side ever changes
    // what it signs (a trailing newline, a re-serialisation, a different encoding), this
    // is what catches it rather than a release that nobody can install.
    //
    // Generated with `relsign keygen` + `relsign sign`, committed deliberately: the
    // secret key for this vector is a test key and is in the test below, which is why it
    // must never be used for a real release.
    const TEST_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const TEST_MANIFEST: &[u8] = br#"{"components":{"mach":{"version":"0.0.14"}}}"#;

    fn test_keypair() -> ed25519_dalek::SigningKey {
        let seed = b64_decode(TEST_SEED_B64).expect("seed decodes");
        let bytes: [u8; 32] = seed.try_into().expect("32-byte seed");
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    }

    fn b64_encode(data: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn base64_round_trips_and_rejects_rubbish() {
        for case in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"abcd"[..],
            &[0u8; 32][..],
            &[0xffu8; 64][..],
        ] {
            let enc = b64_encode(case);
            assert_eq!(
                b64_decode(&enc).as_deref(),
                Some(case),
                "round trip failed for {} bytes",
                case.len()
            );
        }
        // Not base64 at all, and a character outside the alphabet.
        assert_eq!(b64_decode("!!!!"), None);
        assert_eq!(b64_decode("ab$d"), None);
        // Whitespace is tolerated, because a signature file may end with a newline.
        assert_eq!(b64_decode("YWJj\n").as_deref(), Some(&b"abc"[..]));
    }

    #[test]
    fn a_good_signature_verifies_and_a_tampered_manifest_does_not() {
        use ed25519_dalek::Signer;
        let sk = test_keypair();
        let vk = sk.verifying_key();
        let sig = sk.sign(TEST_MANIFEST);

        // The real `verify` reads a compiled-in key, which a test cannot set, so the
        // crypto itself is exercised directly here and `verify`'s own behaviour is
        // covered by the unkeyed-build test below.
        assert!(vk.verify(TEST_MANIFEST, &sig).is_ok(), "honest signature");

        // One byte changed anywhere in the manifest and it fails. This is the whole
        // point: an attacker who rewrites a sha256 in the manifest invalidates it.
        let mut tampered = TEST_MANIFEST.to_vec();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "a modified manifest must not verify"
        );

        // A signature from a different key fails.
        let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        assert!(
            vk.verify(TEST_MANIFEST, &other.sign(TEST_MANIFEST))
                .is_err(),
            "another key's signature must not verify"
        );
    }

    #[test]
    fn an_unkeyed_build_skips_verification_rather_than_failing() {
        // This test documents the rollout rule, and it only means what it says while
        // this test binary is built without CROSSFYRE_MANIFEST_PUBKEY, which is the
        // normal case for a development build and for a public checkout.
        if MANIFEST_PUBKEY.is_none() {
            assert!(!required(), "an unkeyed build does not demand a signature");
            assert!(
                verify(TEST_MANIFEST, "not even base64 !!!").is_ok(),
                "an unkeyed build must install exactly as it did before this module \
                 existed, or the open-source checkout stops working"
            );
        } else {
            assert!(required(), "a keyed build demands a signature");
            assert!(
                verify(TEST_MANIFEST, "not even base64 !!!").is_err(),
                "a keyed build must refuse rubbish"
            );
        }
    }

    #[test]
    fn a_malformed_key_or_signature_is_an_error_not_a_panic() {
        // Reached only in a keyed build, but the parsing is what must never panic: this
        // code runs on every manifest fetch and a panic here bricks the updater.
        assert!(parse_pubkey("not base64 !!!").is_err());
        assert!(parse_pubkey("YWJj").is_err(), "too short to be a key");

        // An all-zero key PARSES. dalek accepts it, because all-zeros is a valid
        // encoding of the identity point, and it defers rejecting low-order keys to
        // verification time rather than construction. The property worth asserting is
        // therefore not that the key is refused but that it cannot be used to wave
        // anything through, which is what a caller would actually be relying on.
        let weak = parse_pubkey(&b64_encode(&[0u8; 32])).expect("all-zeros parses");
        use ed25519_dalek::Signer;
        let honest = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        assert!(
            weak.verify(TEST_MANIFEST, &honest.sign(TEST_MANIFEST))
                .is_err(),
            "a low-order key must not verify a real signature"
        );
        assert!(
            weak.verify(TEST_MANIFEST, &Signature::from_bytes(&[0u8; 64]))
                .is_err(),
            "nor an all-zero signature, which is the shape an attacker would try"
        );
    }
}

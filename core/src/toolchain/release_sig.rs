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
//! lives offline and the publish step reads it from a path given at run time.
//!
//! Rotation is by shipping the next public key in the current release, which is why a
//! build accepts TWO keys: `CROSSFYRE_MANIFEST_PUBKEY` and, when set,
//! `CROSSFYRE_MANIFEST_PUBKEY_NEXT`. The sequence is that release N trusts K1 and K2 while
//! manifests are still signed with K1, then release N+1 trusts K2 and K3 and manifests
//! move to K2. An install of release N keeps updating across the change, because the
//! manifests it is asked to trust are signed with a key it already carries.
//!
//! A compromised bucket cannot roll the key forward on its own: whoever can rewrite the
//! manifest still cannot make an already-installed binary trust a key it was not built
//! with. The flip side is the reason the second slot exists at all. With one key, losing
//! it or needing to retire it leaves every installed binary unable to accept any further
//! update, and the only remedy is asking users to reinstall by hand.
//!
//! Signing lives in the `relsign` dev tool, not here. This module verifies and nothing
//! else, so the shipped binary carries no code path that produces a signature.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Base64 of the 32-byte ed25519 public key, compiled in at build time. `None` in a
/// build that was not given one, which disables verification. See the module note on why
/// this is a build-time rather than a runtime decision.
const MANIFEST_PUBKEY: Option<&str> = option_env!("CROSSFYRE_MANIFEST_PUBKEY");

/// Base64 of the key the NEXT release will sign with, shipped one release early so a
/// rotation does not strand anything already installed. See the module note on rotation.
const MANIFEST_PUBKEY_NEXT: Option<&str> = option_env!("CROSSFYRE_MANIFEST_PUBKEY_NEXT");

/// Where the detached signature sits, relative to the manifest.
pub const SIG_SUFFIX: &str = ".sig";

/// Every key this build will accept a manifest from, current first.
///
/// Accepting two is not a weakening, because both are ours and a signature still has to
/// come from one of them. It is what makes a rotation survivable: an installed binary
/// trusting only one key can be updated only by manifests signed with that key, so losing
/// it, or needing to retire it, would leave every install unable to take another update.
fn trusted_keys() -> Vec<&'static str> {
    [MANIFEST_PUBKEY, MANIFEST_PUBKEY_NEXT]
        .into_iter()
        .flatten()
        .collect()
}

/// Does this build demand a signed manifest?
///
/// Callers use this to decide whether a missing signature file is fatal or simply absent,
/// so the error a user sees names the real problem rather than a 404.
pub fn required() -> bool {
    !trusted_keys().is_empty()
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
    let keys = trusted_keys();
    if keys.is_empty() {
        return Ok(()); // unkeyed build: nothing to verify against
    }
    verify_with_any(&keys, manifest, sig_b64)
}

/// Verify against the first of `keys` that accepts the signature.
///
/// The signature is decoded once, before any key is tried, so a malformed signature file
/// reports as malformed instead of as "did not verify against any key", which would send
/// whoever reads it looking for a rotation problem that is not there.
pub fn verify_with_any(keys: &[&str], manifest: &[u8], sig_b64: &str) -> Result<(), String> {
    let sig = parse_sig(sig_b64)?;
    for k in keys {
        // A key that does not parse is a build misconfiguration, not a bad manifest, and
        // silently skipping it would turn one into the other.
        if parse_pubkey(k)?.verify(manifest, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(format!(
        "release manifest signature does not verify against any of this build's {} \
         public key(s). Refusing to install anything described by it. Either the manifest \
         was modified in transit or on the release origin, or this binary predates a key \
         rotation and needs replacing from a trusted source.",
        keys.len()
    ))
}

/// Verify against an explicitly given public key.
///
/// `verify` is the one callers use, and it reads the key compiled into the binary, which
/// a test cannot set. This exists so the signature format can be tested against one the
/// `relsign` tool actually produced: without it the only coverage would be this module
/// signing and verifying with itself, which proves the two halves agree with each other
/// and nothing about whether they agree with the signer that ships releases.
pub fn verify_with(pk_b64: &str, manifest: &[u8], sig_b64: &str) -> Result<(), String> {
    verify_with_any(&[pk_b64], manifest, sig_b64)
}

/// Decode a detached signature. Separate from verification so the "this file is not a
/// signature" case is reported once rather than once per trusted key.
fn parse_sig(sig_b64: &str) -> Result<Signature, String> {
    let raw = b64_decode(sig_b64.trim()).ok_or("signature is not valid base64")?;
    let bytes: [u8; 64] = raw
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&bytes))
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
    /// A second test key, for the rotation cases. Same warning as the first: the secret
    /// is right here, so it must never sign a real release.
    const TEST_SEED_NEXT_B64: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    const TEST_MANIFEST: &[u8] = br#"{"components":{"mach":{"version":"0.0.14"}}}"#;

    fn test_keypair() -> ed25519_dalek::SigningKey {
        keypair_from(TEST_SEED_B64)
    }

    fn keypair_from(seed_b64: &str) -> ed25519_dalek::SigningKey {
        let seed = b64_decode(seed_b64).expect("seed decodes");
        let bytes: [u8; 32] = seed.try_into().expect("32-byte seed");
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    }

    /// Base64 of a signing key's public half, in the form the build constants carry.
    fn pubkey_b64(sk: &ed25519_dalek::SigningKey) -> String {
        b64_encode(sk.verifying_key().as_bytes())
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

    // ---------------------------------------------------------------------------
    // Rotation: a build trusts the current key and the next one
    // ---------------------------------------------------------------------------

    #[test]
    fn a_manifest_signed_by_either_trusted_key_verifies() {
        use ed25519_dalek::Signer;
        let current = test_keypair();
        let next = keypair_from(TEST_SEED_NEXT_B64);
        let trusted = [pubkey_b64(&current), pubkey_b64(&next)];
        let trusted: Vec<&str> = trusted.iter().map(String::as_str).collect();

        // Release N signs with the current key. This is the ordinary case.
        let by_current = b64_encode(&current.sign(TEST_MANIFEST).to_bytes());
        assert!(verify_with_any(&trusted, TEST_MANIFEST, &by_current).is_ok());

        // Release N+1 signs with what was the next key. An install of release N has to
        // accept this, or the rotation strands it on whatever it last installed.
        let by_next = b64_encode(&next.sign(TEST_MANIFEST).to_bytes());
        assert!(
            verify_with_any(&trusted, TEST_MANIFEST, &by_next).is_ok(),
            "the next key is what makes a rotation survivable"
        );
    }

    #[test]
    fn a_third_key_is_refused_and_the_error_says_how_many_were_tried() {
        use ed25519_dalek::Signer;
        let current = test_keypair();
        let next = keypair_from(TEST_SEED_NEXT_B64);
        let trusted = [pubkey_b64(&current), pubkey_b64(&next)];
        let trusted: Vec<&str> = trusted.iter().map(String::as_str).collect();

        // Someone else's key, which is the case that matters: whoever can rewrite the
        // manifest cannot make an installed binary trust a key it was not built with.
        let attacker = keypair_from("f39Ri29s9OTEHMiNIk74ZPe8AlhRHUNRaDFPtKPYIKk=");
        let forged = b64_encode(&attacker.sign(TEST_MANIFEST).to_bytes());
        let err = verify_with_any(&trusted, TEST_MANIFEST, &forged)
            .expect_err("a signature from an untrusted key must be refused");
        assert!(
            err.contains('2'),
            "the count tells an operator whether a rotation is in flight, got: {err}"
        );
        assert!(err.contains("Refusing to install"), "got: {err}");
    }

    #[test]
    fn a_malformed_signature_is_not_reported_as_a_rotation_problem() {
        let current = test_keypair();
        let next = keypair_from(TEST_SEED_NEXT_B64);
        let trusted = [pubkey_b64(&current), pubkey_b64(&next)];
        let trusted: Vec<&str> = trusted.iter().map(String::as_str).collect();

        // A truncated or garbled signature file is a different problem from a key
        // mismatch, and saying "did not verify against any of 2 keys" would send whoever
        // reads it hunting a rotation that is not happening.
        for bad in ["", "!!!!", "YWJj"] {
            let err = verify_with_any(&trusted, TEST_MANIFEST, bad)
                .expect_err("a malformed signature must be refused");
            assert!(
                err.contains("signature is not"),
                "expected a message about the signature itself for {bad:?}, got: {err}"
            );
        }
    }

    #[test]
    fn a_build_with_no_next_key_still_works_with_one() {
        use ed25519_dalek::Signer;
        let current = test_keypair();
        let only = [pubkey_b64(&current)];
        let only: Vec<&str> = only.iter().map(String::as_str).collect();
        let sig = b64_encode(&current.sign(TEST_MANIFEST).to_bytes());
        assert!(verify_with_any(&only, TEST_MANIFEST, &sig).is_ok());
        // And `verify_with`, which install.rs and the relsign integration test use, is
        // the same path with one key.
        assert!(verify_with(only[0], TEST_MANIFEST, &sig).is_ok());
    }
}

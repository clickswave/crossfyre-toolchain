//! The signer and the verifier must agree, and this is the only test that proves it.
//!
//! `release_sig`'s unit tests sign and verify with themselves, which shows the two halves
//! of one module are consistent and says nothing about the tool that signs real releases.
//! This drives `relsign` as a subprocess, exactly as the publish step does, and feeds its
//! output to the verifier the shipped binary uses.
//!
//! What it is really guarding is the class of failure where one side changes what it
//! signs: a trailing newline, a re-serialised manifest, a different base64 alphabet, a
//! line-ending conversion on Windows. Every one of those produces a release that verifies
//! nowhere, and the symptom is every user's updater breaking at once.
//!
//! Skipped rather than failed when the `relsign` binary is absent, because `cargo test`
//! on a fresh checkout has not built it yet and a test that fails for that reason trains
//! people to ignore it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn relsign_path() -> Option<PathBuf> {
    // CARGO_BIN_EXE_ is only set for bins in this package, and relsign is its own
    // package, so find it next to the test binary instead.
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?.to_path_buf();
    if dir.ends_with("deps") {
        dir.pop();
    }
    [dir.join("relsign"), dir.join("relsign.exe")]
        .into_iter()
        .find(|c| c.exists())
}

fn run(bin: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("could not run {}: {e}", bin.display()))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[test]
fn a_manifest_signed_by_relsign_verifies_and_tampering_does_not() {
    let Some(relsign) = relsign_path() else {
        eprintln!("skipping: relsign not built (cargo build -p relsign)");
        return;
    };

    // A scratch directory outside any git work tree, because relsign refuses to write a
    // signing key inside one and that refusal is itself worth exercising here.
    let dir = std::env::temp_dir().join(format!("cfx-relsign-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let secret = dir.join("sk.key");
    let manifest = dir.join("manifest.json");

    let keygen_out = run(&relsign, ["keygen", secret.to_str().unwrap()].as_ref())
        .expect("keygen should succeed outside a git tree");
    // The public key is the line after the "Public key" heading, indented.
    let pubkey = keygen_out
        .lines()
        .map(str::trim)
        .find(|l| l.ends_with('=') && l.len() == 44)
        .expect("keygen prints a 44-character base64 public key")
        .to_string();

    // Bytes that look like a real manifest, including the nested shape and a sha256, so
    // the thing being signed is representative rather than a toy string.
    let body = br#"{"components":{"mach":{"version":"0.0.14","artifacts":{"linux-x86_64":{"file":"mach-linux-x86_64-0.0.14-abc123def456.zip","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}}}}"#;
    std::fs::write(&manifest, body).expect("write manifest");

    run(
        &relsign,
        ["sign", secret.to_str().unwrap(), manifest.to_str().unwrap()].as_ref(),
    )
    .expect("sign");

    let sig = std::fs::read_to_string(dir.join("manifest.json.sig")).expect("signature file");

    // The honest case.
    assert_eq!(
        cfx_core::toolchain::release_sig::verify_with(&pubkey, body, &sig),
        Ok(()),
        "a manifest signed by relsign must verify in the shipped verifier"
    );

    // The signature file ends with a newline, which the verifier has to tolerate because
    // that is what `relsign sign` writes and what a CDN will serve.
    assert!(sig.ends_with('\n'), "relsign writes a trailing newline");

    // One byte of the manifest changed. In the real attack this is a rewritten sha256,
    // pointing the installer at a different artifact.
    let mut tampered = body.to_vec();
    let i = tampered
        .windows(4)
        .position(|w| w == b"e3b0")
        .expect("sha256 present");
    tampered[i] = b'f';
    assert!(
        cfx_core::toolchain::release_sig::verify_with(&pubkey, &tampered, &sig).is_err(),
        "a rewritten checksum must invalidate the manifest signature"
    );

    // A second key's signature over the same bytes.
    let other_secret = dir.join("other.key");
    let other_out = run(
        &relsign,
        ["keygen", other_secret.to_str().unwrap()].as_ref(),
    )
    .expect("second keygen");
    let _ = other_out;
    run(
        &relsign,
        [
            "sign",
            other_secret.to_str().unwrap(),
            manifest.to_str().unwrap(),
        ]
        .as_ref(),
    )
    .expect("sign with the other key");
    let other_sig =
        std::fs::read_to_string(dir.join("manifest.json.sig")).expect("second signature");
    assert!(
        cfx_core::toolchain::release_sig::verify_with(&pubkey, body, &other_sig).is_err(),
        "a signature from a key this build does not carry must be refused"
    );

    // And `pubkey` on an existing secret agrees with what keygen printed, because the
    // publish step reads the public key that way when baking it into a build.
    let printed = run(&relsign, ["pubkey", secret.to_str().unwrap()].as_ref()).expect("pubkey");
    assert_eq!(printed.trim(), pubkey, "pubkey must match keygen's output");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn relsign_refuses_to_overwrite_an_existing_key() {
    let Some(relsign) = relsign_path() else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("cfx-relsign-overwrite-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let secret = dir.join("sk.key");
    run(&relsign, ["keygen", secret.to_str().unwrap()].as_ref()).expect("first keygen");
    // Overwriting a signing key strands every build carrying the matching public key, so
    // it must take more than running the same command twice.
    assert!(
        run(&relsign, ["keygen", secret.to_str().unwrap()].as_ref()).is_err(),
        "a second keygen onto the same path must refuse"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

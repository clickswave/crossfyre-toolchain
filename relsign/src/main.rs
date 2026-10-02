//! Sign the release manifest. A build-host tool, not a shipped component.
//!
//! The counterpart to `cfx_core::toolchain::release_sig`, which verifies. They are split
//! so the binary that lands on a user's machine has no code path that produces a
//! signature: verification is what a client needs and signing is what a release needs,
//! and keeping them apart means a compromised client cannot be turned into a signing
//! oracle by a bug.
//!
//! Signing is in Rust rather than in the Python build script for two reasons. The build
//! tooling in `scripts/` is deliberately stdlib-only, so a Python signer would mean
//! adding a cryptography dependency to it and breaking that rule. And one ed25519
//! implementation across both sides removes the class of bug where the signer and the
//! verifier disagree about what was signed. `release_sig`'s test vector pins that
//! agreement.
//!
//! # Usage
//!
//!   relsign keygen <secret-out>        write a new secret key, print the public key
//!   relsign pubkey <secret>            print the public key for an existing secret
//!   relsign sign <secret> <file>       write <file>.sig, print the signature
//!
//! # The secret key
//!
//! It never belongs in this repository, in CI, or in a build image. Generate it on a
//! machine that does not publish, keep it offline, and pass its path at release time.
//! `keygen` refuses to write inside a git work tree as a cheap guard against the obvious
//! accident, which is not security but does catch the mistake people actually make.
//!
//! Rotation: ship the next public key in the current release, so an attacker who can
//! rewrite the manifest still cannot make an installed binary trust a new key.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use ed25519_dalek::{Signer, SigningKey};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn load_secret(path: &str) -> Result<SigningKey, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let raw = b64_decode(text.trim()).ok_or_else(|| format!("{path} is not base64"))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| format!("{path} is not a 32-byte key"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Refuse to write a secret inside a git work tree. Not a security control: a guard
/// against the specific accident of generating a key into the repo and committing it.
fn inside_git_tree(path: &Path) -> bool {
    let mut dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    if dir.as_os_str().is_empty() {
        dir = Path::new(".").to_path_buf();
    }
    let mut cur = dir.canonicalize().unwrap_or(dir);
    loop {
        if cur.join(".git").exists() {
            return true;
        }
        match cur.parent() {
            Some(p) => cur = p.to_path_buf(),
            None => return false,
        }
    }
}

fn keygen(out: &str) -> Result<(), String> {
    let path = Path::new(out);
    if path.exists() {
        return Err(format!(
            "{out} already exists. Refusing to overwrite a signing key, because doing so \
             would strand every build that carries the matching public key."
        ));
    }
    if inside_git_tree(path) {
        return Err(format!(
            "{out} is inside a git work tree. Generate the signing key somewhere that is \
             not a repository: the whole point of it is that it never gets committed."
        ));
    }
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    let mut f = fs::File::create(path).map_err(|e| format!("cannot write {out}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
    }
    writeln!(f, "{}", b64_encode(&sk.to_bytes()))
        .map_err(|e| format!("cannot write {out}: {e}"))?;
    println!("secret key written to {out} (mode 0600)");
    println!();
    println!("Public key, to pass as CROSSFYRE_MANIFEST_PUBKEY when building a release:");
    println!("  {}", b64_encode(sk.verifying_key().as_bytes()));
    println!();
    println!("Keep the secret offline. A build carrying this public key refuses any manifest");
    println!("it does not sign, so losing the secret means every such build stops updating.");
    Ok(())
}

fn pubkey(secret: &str) -> Result<(), String> {
    let sk = load_secret(secret)?;
    println!("{}", b64_encode(sk.verifying_key().as_bytes()));
    Ok(())
}

fn sign(secret: &str, file: &str) -> Result<(), String> {
    let sk = load_secret(secret)?;
    // Sign the bytes on disk exactly as they are. The verifier signs over what the CDN
    // served, so anything that rewrites the file between here and upload (a formatter, a
    // re-serialisation, a line-ending conversion) breaks the signature.
    let body = fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let sig = sk.sign(&body);
    let encoded = b64_encode(&sig.to_bytes());
    let out = format!("{file}.sig");
    fs::write(&out, format!("{encoded}\n")).map_err(|e| format!("cannot write {out}: {e}"))?;
    println!("{out}");
    println!("{encoded}");
    Ok(())
}

fn usage() -> ExitCode {
    eprintln!("relsign - sign the Crossfyre release manifest (build-host tool)");
    eprintln!();
    eprintln!("  relsign keygen <secret-out>     new signing key; prints the public key");
    eprintln!("  relsign pubkey <secret>         public key for an existing secret");
    eprintln!("  relsign sign <secret> <file>    writes <file>.sig");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [cmd, out] if cmd == "keygen" => keygen(out),
        [cmd, secret] if cmd == "pubkey" => pubkey(secret),
        [cmd, secret, file] if cmd == "sign" => sign(secret, file),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("relsign: {e}");
            ExitCode::FAILURE
        }
    }
}

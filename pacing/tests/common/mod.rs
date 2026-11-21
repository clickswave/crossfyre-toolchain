//! Test modules written as text, the keys that sign them, and a folder to put them in.
#![allow(dead_code)]

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use std::path::PathBuf;

/// The release key a test build trusts, and the data key it must not.
pub fn release_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}
pub fn data_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

pub fn public(key: &SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes())
}

pub fn sign(key: &SigningKey, bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.sign(bytes).to_bytes())
}

/// The parts of a test module that differ between tests.
pub struct Spec {
    pub interface: u32,
    pub answer: String,
    pub import: bool,
    pub spin: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
            interface: 1,
            answer: "{}".into(),
            import: false,
            spin: false,
        }
    }
}

/// A module of the interface: version "test 1", `answer` to every call.
pub fn module(spec: &Spec) -> Vec<u8> {
    let answer = spec
        .answer
        .replace('\\', "\\5c")
        .replace('"', "\\22")
        .replace('\n', "\\0a");
    let len = spec.answer.len();
    let import = if spec.import {
        r#"(import "env" "now" (func $now (result i64)))"#
    } else {
        ""
    };
    let spin = if spec.spin { "(loop $l (br $l))" } else { "" };
    let text = format!(
        r#"(module
          {import}
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 8192))
          (data (i32.const 16) "test 1")
          (data (i32.const 1024) "{answer}")
          (func (export "cfx_interface") (result i32) (i32.const {interface}))
          (func (export "cfx_version") (result i64)
            (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const 6)))
          (func (export "cfx_alloc") (param $n i32) (result i32) (local $at i32)
            (local.set $at (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $n)))
            (local.get $at))
          (func (export "cfx_call") (param i32 i32 i32 i32) (result i64)
            {spin}
            (global.set $next (i32.const 8192))
            (i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const {len}))))"#,
        interface = spec.interface,
    );
    wat::parse_str(text).expect("a test module")
}

/// A folder of its own, as the binaries' folder would be: writable by its owner only.
pub struct Folder(pub PathBuf);

impl Folder {
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("cfx-pacing-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Folder(dir)
    }

    /// `bytes` as the module, with `sig` beside it when given.
    pub fn put(&self, bytes: &[u8], sig: Option<&str>) -> PathBuf {
        let path = self.0.join(cfx_pacing::MODULE);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let sig_path = self
            .0
            .join(format!("{}{}", cfx_pacing::MODULE, cfx_pacing::SIG_SUFFIX));
        let _ = std::fs::remove_file(&sig_path);
        if let Some(sig) = sig {
            std::fs::write(sig_path, sig).unwrap();
        }
        path
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn exe() -> PathBuf {
    std::env::current_exe().unwrap()
}

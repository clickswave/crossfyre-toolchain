//! Selects the authorization-testing implementation at build time.
//!
//! With the `closed-authz` feature, which only plessor-authz's release build turns on,
//! the private drop-in `src/authz/private.rs` is compiled and `cfg(authz_private)` set,
//! and the build stops when the file is not there. Without it, `src/authz/baseline.rs`
//! is compiled whether or not the file is present, so plessor itself never carries the
//! drop-in. See `src/authz/mod.rs`.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(authz_private)");
    println!("cargo::rerun-if-changed=src/authz/private.rs");
    if std::env::var_os("CARGO_FEATURE_CLOSED_AUTHZ").is_none() {
        return;
    }
    if !std::path::Path::new("src/authz/private.rs").exists() {
        panic!(
            "the closed-authz feature compiles src/authz/private.rs, which this checkout \
             does not have"
        );
    }
    println!("cargo::rustc-cfg=authz_private");
}

//! Selects the authorization-oracle implementation at build time.
//!
//! If the private drop-in `src/authz/private.rs` is present (first-party builds),
//! compile it and set `cfg(authz_private)`. A public checkout has only
//! `src/authz/baseline.rs`, so the open build compiles the baseline (no oracle).
//! See `src/authz/mod.rs`. This mirrors `core/build.rs` (isolated egress).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(authz_private)");
    if std::path::Path::new("src/authz/private.rs").exists() {
        println!("cargo::rustc-cfg=authz_private");
    }
    println!("cargo::rerun-if-changed=src/authz/private.rs");
}

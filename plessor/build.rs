//! Selects the authorization-oracle implementation at build time.
//!
//! If the private drop-in `src/authz/private.rs` is present (first-party builds),
//! compile it and set `cfg(authz_private)`. A public checkout has only
//! `src/authz/baseline.rs`, so the open build compiles the baseline (no oracle).
//! See `src/authz/mod.rs`. This mirrors `core/build.rs` (isolated egress).
//!
//! It also compiles `templates/` into the binary as the starter pack. The pack
//! used to be reachable only through PLESSOR_TEMPLATES_DIR, which the daemon reads
//! from its own environment: a service nobody edits, on a machine where the
//! release archives never put the folder. So an installed `plessor scan` ran the
//! twelve built-in checks and none of the hundred templates beside them.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(authz_private)");
    if Path::new("src/authz/private.rs").exists() {
        println!("cargo::rustc-cfg=authz_private");
    }
    println!("cargo::rerun-if-changed=src/authz/private.rs");

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    println!("cargo::rerun-if-changed={}", root.display());
    let mut files = Vec::new();
    collect(&root, &mut files);
    // Sorted, so the same tree always makes the same binary.
    files.sort();
    let mut out = String::from("pub static PACK_YAML: &[(&str, &str)] = &[\n");
    for f in &files {
        println!("cargo::rerun-if-changed={}", f.display());
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        out.push_str(&format!(
            "    ({rel:?}, include_str!({:?})),\n",
            f.display().to_string()
        ));
    }
    out.push_str("];\n");
    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("pack.rs");
    std::fs::write(dest, out).unwrap();
}

/// Every .yaml and .yml under `dir`, skipping hidden directories the way
/// `template::load_dir` does at run time.
fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if !name.starts_with('.') {
                println!("cargo::rerun-if-changed={}", path.display());
                collect(&path, out);
            }
        } else if name.ends_with(".yaml") || name.ends_with(".yml") {
            out.push(path);
        }
    }
}

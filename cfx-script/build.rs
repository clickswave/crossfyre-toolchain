//! With the `bundled-python` feature, the Linux binary loads libpython from the python
//! folder beside it and from nowhere else (see `src/bundled.rs`).
//!
//! The library is named through DT_RPATH, which the dynamic loader searches before
//! LD_LIBRARY_PATH and before the system's directories, and not DT_RUNPATH, which it
//! searches after LD_LIBRARY_PATH. So a libpython of the same name that another Python
//! put on LD_LIBRARY_PATH is not the one loaded. `$ORIGIN` is the directory the binary
//! is in, wherever it was installed.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let bundled = std::env::var_os("CARGO_FEATURE_BUNDLED_PYTHON").is_some();
    let linux = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux");
    if bundled && linux {
        println!("cargo:rustc-link-arg-bins=-Wl,--disable-new-dtags");
        println!("cargo:rustc-link-arg-bins=-Wl,-rpath,$ORIGIN/python/lib");
    }
}

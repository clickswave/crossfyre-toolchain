// Built-in package manager and service lifecycle for the Crossfyre toolchain.
//
// Formerly the standalone `orion` CLI (OrionChain). Merged into the node
// binary so `crossfyre node init` can install extensions, provision the Postgres
// container, and register OS services without piping a remote install script
// into a shell. Extensions (mach, voyage, pulse) remain separate closed-source
// daemon binaries downloaded from bins.crossfyre.io.

// The traffic-capture core (session CA, per-SNI MITM leaves, egress) is its own crate so the mobile
// VpnService netstack can reuse it without pulling in the rest of cfx_core. Re-exported here so the
// desktop proxy keeps referring to it as `toolchain::capture`.
pub use cfx_capture as capture;
pub mod config;
pub mod db;
pub mod doctor;
pub mod install;
pub mod oast;
pub mod release_sig;
pub mod service;
pub mod status;
pub mod sudo_user;
pub mod trace;
pub mod trace_proxy;
pub mod ui;
pub mod uninstall;

/// Scan engines installable as node extensions.
pub const EXTENSIONS: &[&str] = &["mach", "voyage", "pulse", "scout", "cortex"];

/// Default daemon port per extension. These are fixed protocol constants -
/// the daemons listen on localhost and the node talks to them over TCP JSON.
pub const EXTENSION_PORTS: &[(&str, u16)] = &[
    ("mach", 4441),
    ("voyage", 4442),
    ("pulse", 4443),
    ("scout", 4444),
    ("cortex", 4445),
];

/// Expand an extension argument ("mach" | "all") into concrete extension names.
pub fn resolve_extensions(name: &str) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    if name == "all" {
        Ok(EXTENSIONS.to_vec())
    } else {
        match EXTENSIONS.iter().find(|&&e| e == name) {
            Some(e) => Ok(vec![e]),
            None => Err(format!(
                "Unknown extension: '{name}'. Use: mach, voyage, pulse, scout, cortex, or all"
            )
            .into()),
        }
    }
}

pub fn print_extension_usage(verb: &str) {
    use crate::toolchain::ui::*;

    let all_desc = if verb == "remove" {
        "Remove every extension"
    } else {
        "Install every extension"
    };
    let choices: [(&str, &str); 6] = [
        (
            "mach",
            "HTTP fuzzer, content-discovery and web-crawl engine",
        ),
        ("voyage", "Subdomain enumeration engine"),
        ("pulse", "Network host and port-scanning engine"),
        ("scout", "Service enumeration and web fingerprinting engine"),
        ("cortex", "Vulnerability detection engine"),
        ("all", all_desc),
    ];

    println!();
    println!("  {}", dim(&format!("Choose an extension to {verb}:")));
    for (name, desc) in choices {
        println!(
            "    {} crossfyre extension {} {}  {}",
            dot(),
            verb,
            bold(&format!("{name:<7}")),
            dim(desc)
        );
    }
    println!();
    section("Available extensions");
    for ext in EXTENSIONS {
        println!("{}", row(&dot(), ext, "", ""));
    }
    println!();
}

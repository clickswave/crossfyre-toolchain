// Built-in package manager and service lifecycle for the Crossfyre toolchain.
//
// Built into the CLI and the node, so `crossfyre node init` can install extensions,
// provision the Postgres container, and register OS services without piping a remote
// install script into a shell. Extensions (ambulo, voyage, doorward, toolmark, plessor)
// are separate daemon binaries downloaded from bins.crossfyre.io.

// The traffic-capture core (session CA, per-SNI MITM leaves, egress) is its own crate so the mobile
// VpnService netstack can reuse it without pulling in the rest of cfx_core. Re-exported here so the
// desktop proxy keeps referring to it as `toolchain::capture`.
pub use cfx_capture as capture;
pub mod config;
pub mod db;
pub mod doctor;
pub mod install;
#[cfg(target_os = "linux")]
pub mod linger;
pub mod node_config;
pub mod oast;
pub mod packaging;
pub mod release_http;
pub mod release_sig;
#[cfg(unix)]
pub mod root_fs;
pub mod service;
pub mod status;
pub mod sudo_user;
pub mod trace;
pub mod trace_proxy;
pub mod ui;
pub mod uninstall;
#[cfg(windows)]
pub mod win;

/// One scan engine installable as a node extension.
///
/// `name` is the engine's only name: its crate, binary, manifest key, service unit,
/// CLI argument and `config.toml` key, the key the node reports it under and takes
/// commands for, and the start of the `source` of every finding it makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine {
    pub name: &'static str,
    /// Default daemon port. A fixed protocol constant: the daemons listen on
    /// localhost and the node talks to them over TCP JSON.
    pub port: u16,
    pub about: &'static str,
}

/// Every engine, in the order they are listed to a person.
pub const ENGINES: &[Engine] = &[
    Engine {
        name: "ambulo",
        port: 4441,
        about: "HTTP fuzzer, content-discovery and web-crawl engine",
    },
    Engine {
        name: "voyage",
        port: 4442,
        about: "Subdomain enumeration engine",
    },
    Engine {
        name: "doorward",
        port: 4443,
        about: "Network host and port-scanning engine",
    },
    Engine {
        name: "toolmark",
        port: 4444,
        about: "Service enumeration and web fingerprinting engine",
    },
    Engine {
        name: "plessor",
        port: 4445,
        about: "Vulnerability detection engine",
    },
];

/// The engine called `name`.
pub fn engine(name: &str) -> Option<&'static Engine> {
    ENGINES.iter().find(|e| e.name == name)
}

/// Expand an extension argument (an engine's name, or "all") into engine names.
pub fn resolve_extensions(name: &str) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    if name == "all" {
        return Ok(ENGINES.iter().map(|e| e.name).collect());
    }
    match engine(name) {
        Some(e) => Ok(vec![e.name]),
        None => {
            let names: Vec<&str> = ENGINES.iter().map(|e| e.name).collect();
            Err(format!(
                "Unknown extension: '{name}'. Use: {}, or all",
                names.join(", ")
            )
            .into())
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
    let mut choices: Vec<(&str, &str)> = ENGINES.iter().map(|e| (e.name, e.about)).collect();
    choices.push(("all", all_desc));
    println!();
    println!("  {}", dim(&format!("Choose an extension to {verb}:")));
    for (name, desc) in choices {
        println!(
            "    {} crossfyre extension {} {}  {}",
            dot(),
            verb,
            bold(&format!("{name:<9}")),
            dim(desc)
        );
    }
    println!();
    section("Available extensions");
    for e in ENGINES {
        println!("{}", row(&dot(), e.name, "", ""));
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_extension_argument_is_an_engine_s_name_or_all() {
        assert_eq!(resolve_extensions("plessor").unwrap(), vec!["plessor"]);
        assert_eq!(
            resolve_extensions("all").unwrap(),
            vec!["ambulo", "voyage", "doorward", "toolmark", "plessor"]
        );
        let err = resolve_extensions("nope").unwrap_err().to_string();
        assert!(
            err.contains("Use: ambulo, voyage, doorward, toolmark, plessor, or all"),
            "{err}"
        );
    }
}

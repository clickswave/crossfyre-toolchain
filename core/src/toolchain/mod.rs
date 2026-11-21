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
pub mod data_manifest;
pub mod data_update;
pub mod db;
pub mod doctor;
pub mod install;
#[cfg(target_os = "linux")]
pub mod linger;
pub mod node_config;
pub mod node_engines;
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
/// `name` is the engine's only name: its binary, manifest key, service unit, CLI
/// argument and `config.toml` key, the key the node reports it under and takes commands
/// for, and the start of the `source` of every finding it makes. It is its crate's name
/// too, but for plessor-authz, a second binary of the plessor crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine {
    pub name: &'static str,
    /// Default daemon port. A fixed protocol constant, from dguard::ports, which every
    /// engine's client takes too: the daemons listen on localhost and the node talks to
    /// them over TCP JSON.
    pub port: u16,
    pub about: &'static str,
    /// It comes with a Crossfyre plan that includes it, after login, rather than with
    /// the release: `all` leaves it out, and where it is not installed it says so.
    pub closed: bool,
}

/// What is said of a closed engine that is not installed.
pub const NEEDS_A_PLAN: &str = "not installed (needs a plan that includes it)";

impl Engine {
    /// Why it is not installed or updated from the release: a closed engine comes with
    /// a plan that includes it, after login. None for every other.
    pub fn from_a_plan(&self) -> Option<String> {
        self.closed.then(|| {
            format!(
                "{} comes with a Crossfyre plan that includes it. Log in with `crossfyre \
                 login`, and it is installed with `crossfyre update`.",
                self.name
            )
        })
    }

    /// How it is said not to be installed.
    pub fn not_installed(&self) -> &'static str {
        if self.closed {
            NEEDS_A_PLAN
        } else {
            "not installed"
        }
    }
}

/// Every engine, in the order they are listed to a person.
pub const ENGINES: &[Engine] = &[
    Engine {
        name: "ambulo",
        port: dguard::ports::AMBULO,
        about: "HTTP fuzzer, content-discovery and web-crawl engine",
        closed: false,
    },
    Engine {
        name: "voyage",
        port: dguard::ports::VOYAGE,
        about: "Subdomain enumeration engine",
        closed: false,
    },
    Engine {
        name: "doorward",
        port: dguard::ports::DOORWARD,
        about: "Network host and port-scanning engine",
        closed: false,
    },
    Engine {
        name: "toolmark",
        port: dguard::ports::TOOLMARK,
        about: "Service enumeration and web fingerprinting engine",
        closed: false,
    },
    Engine {
        name: "plessor",
        port: dguard::ports::PLESSOR,
        about: "Vulnerability detection engine",
        closed: false,
    },
    Engine {
        name: "plessor-authz",
        port: dguard::ports::PLESSOR_AUTHZ,
        about: "Authorization testing engine (BOLA, BFLA, BOPLA)",
        closed: true,
    },
];

/// The engine called `name`.
pub fn engine(name: &str) -> Option<&'static Engine> {
    ENGINES.iter().find(|e| e.name == name)
}

/// Expand an extension argument (an engine's name, or "all") into engine names.
pub fn resolve_extensions(name: &str) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    if name == "all" {
        return Ok(ENGINES
            .iter()
            .filter(|e| !e.closed)
            .map(|e| e.name)
            .collect());
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
            resolve_extensions("plessor-authz").unwrap(),
            vec!["plessor-authz"]
        );
        // A closed engine comes with a plan, not with the release, so `all` leaves it out.
        assert_eq!(
            resolve_extensions("all").unwrap(),
            vec!["ambulo", "voyage", "doorward", "toolmark", "plessor"]
        );
        let authz = engine("plessor-authz").unwrap();
        assert_eq!(
            authz.not_installed(),
            "not installed (needs a plan that includes it)"
        );
        assert_eq!(engine("plessor").unwrap().not_installed(), "not installed");
        assert!(
            authz
                .from_a_plan()
                .unwrap()
                .starts_with("plessor-authz comes with a Crossfyre plan that includes it.")
        );
        assert_eq!(engine("plessor").unwrap().from_a_plan(), None);
        let err = resolve_extensions("nope").unwrap_err().to_string();
        assert!(
            err.contains("Use: ambulo, voyage, doorward, toolmark, plessor, plessor-authz, or all"),
            "{err}"
        );
    }
}

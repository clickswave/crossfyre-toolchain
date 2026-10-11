// Built-in package manager and service lifecycle for the Crossfyre toolchain.
//
// Formerly the standalone `orion` CLI (OrionChain). Merged into the node
// binary so `crossfyre node init` can install extensions, provision the Postgres
// container, and register OS services without piping a remote install script
// into a shell. Extensions (ambulo, voyage, doorward, toolmark, plessor) remain
// separate daemon binaries downloaded from bins.crossfyre.io.

// The traffic-capture core (session CA, per-SNI MITM leaves, egress) is its own crate so the mobile
// VpnService netstack can reuse it without pulling in the rest of cfx_core. Re-exported here so the
// desktop proxy keeps referring to it as `toolchain::capture`.
pub use cfx_capture as capture;
pub mod config;
pub mod db;
pub mod doctor;
pub mod install;
pub mod migrate;
pub mod oast;
pub mod release_sig;
pub mod service;
pub mod status;
pub mod sudo_user;
pub mod trace;
pub mod trace_proxy;
pub mod ui;
pub mod uninstall;

/// One scan engine installable as a node extension.
///
/// The ids are the engines' original names and are historical: they stay as they
/// are, whatever the engines are called.
///
/// Each engine has two names. `id` is the stored and wire identifier: the database,
/// the NATS commands, the ports map pushed to nodes, the heartbeat, `nodes.d` and a
/// finding's `source` all carry it, and it never changes. `name` is the engine's
/// public name: its crate, binary, manifest key, service unit and CLI argument, and
/// every label printed for a person. `legacy` is the binary, unit and manifest key an
/// engine had before it took its current name, kept for as long as installs that
/// predate the change can still be found on a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine {
    pub id: &'static str,
    pub name: &'static str,
    pub legacy: Option<&'static str>,
    /// Default daemon port. A fixed protocol constant: the daemons listen on
    /// localhost and the node talks to them over TCP JSON.
    pub port: u16,
    pub about: &'static str,
}

impl Engine {
    /// Does `key` name this engine: its id, its public name, or its legacy name?
    pub fn answers_to(&self, key: &str) -> bool {
        key == self.id || key == self.name || self.legacy == Some(key)
    }
}

/// Every engine, in the order they are listed to a person.
pub const ENGINES: &[Engine] = &[
    Engine {
        id: "mach",
        name: "ambulo",
        legacy: Some("mach"),
        port: 4441,
        about: "HTTP fuzzer, content-discovery and web-crawl engine",
    },
    Engine {
        id: "voyage",
        name: "voyage",
        legacy: None,
        port: 4442,
        about: "Subdomain enumeration engine",
    },
    Engine {
        id: "pulse",
        name: "doorward",
        legacy: Some("pulse"),
        port: 4443,
        about: "Network host and port-scanning engine",
    },
    Engine {
        id: "scout",
        name: "toolmark",
        legacy: Some("scout"),
        port: 4444,
        about: "Service enumeration and web fingerprinting engine",
    },
    Engine {
        id: "cortex",
        name: "plessor",
        legacy: Some("cortex"),
        port: 4445,
        about: "Vulnerability detection engine",
    },
];

/// The engine ids, in [`ENGINES`] order. Everything stored or sent over the wire uses
/// these.
pub const EXTENSIONS: &[&str] = &["mach", "voyage", "pulse", "scout", "cortex"];

/// The engine `key` names in `table`, by id, public name or legacy name.
pub fn find_engine<'t>(table: &'t [Engine], key: &str) -> Option<&'t Engine> {
    table.iter().find(|e| e.answers_to(key))
}

/// The engine `key` names, by id, public name or legacy name.
pub fn engine(key: &str) -> Option<&'static Engine> {
    find_engine(ENGINES, key)
}

/// The public name for `key`, which may be an id, a public name or a legacy name.
/// Anything that is not an engine (`crossfyre`, `node`, `cfx-script`) comes back as
/// it was, so this is safe on every component name.
pub fn public_name(key: &str) -> &str {
    engine(key).map(|e| e.name).unwrap_or(key)
}

/// Expand an extension argument (an id, a public name, or "all") into engine ids.
pub fn resolve_extensions(name: &str) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    resolve_in(ENGINES, name).map_err(Into::into)
}

/// [`resolve_extensions`] over any table. Ids come back, whichever name was given, and
/// the error lists only public names.
pub fn resolve_in<'t>(table: &'t [Engine], name: &str) -> Result<Vec<&'t str>, String> {
    if name == "all" {
        return Ok(table.iter().map(|e| e.id).collect());
    }
    match find_engine(table, name) {
        Some(e) => Ok(vec![e.id]),
        None => {
            let names: Vec<&str> = table.iter().map(|e| e.name).collect();
            Err(format!(
                "Unknown extension: '{name}'. Use: {}, or all",
                names.join(", ")
            ))
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

    /// One renamed engine and one that never was.
    const TABLE: &[Engine] = &[
        Engine {
            id: "cortex",
            name: "fresh",
            legacy: Some("cortex"),
            port: 4445,
            about: "",
        },
        Engine {
            id: "voyage",
            name: "voyage",
            legacy: None,
            port: 4442,
            about: "",
        },
    ];

    #[test]
    fn the_id_list_is_the_table_in_order() {
        let ids: Vec<&str> = ENGINES.iter().map(|e| e.id).collect();
        assert_eq!(ids, EXTENSIONS);
    }

    #[test]
    fn ids_and_names_are_unique_across_the_table() {
        // A name that is also another engine's id would make an argument ambiguous.
        let mut all: Vec<&str> = Vec::new();
        for e in ENGINES {
            all.push(e.id);
            if e.name != e.id {
                all.push(e.name);
            }
            if let Some(l) = e.legacy.filter(|l| *l != e.id) {
                all.push(l);
            }
        }
        let mut dedup = all.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), all.len(), "{all:?}");
    }

    #[test]
    fn any_name_of_an_engine_resolves_to_its_id() {
        for key in ["cortex", "fresh"] {
            assert_eq!(resolve_in(TABLE, key).unwrap(), vec!["cortex"], "{key}");
        }
        assert_eq!(resolve_in(TABLE, "voyage").unwrap(), vec!["voyage"]);
        assert_eq!(resolve_in(TABLE, "all").unwrap(), vec!["cortex", "voyage"]);
    }

    #[test]
    fn an_unknown_name_lists_only_public_names() {
        let err = resolve_in(TABLE, "nope").unwrap_err();
        assert!(err.contains("fresh, voyage, or all"), "{err}");
        assert!(!err.contains("cortex"), "ids are not offered: {err}");
    }

    /// Old name, new name, for every engine that was renamed.
    const RENAMES: [(&str, &str); 4] = [
        ("mach", "ambulo"),
        ("pulse", "doorward"),
        ("scout", "toolmark"),
        ("cortex", "plessor"),
    ];

    #[test]
    fn every_old_cli_argument_still_resolves_to_the_renamed_engine() {
        // `crossfyre extension install cortex`, and every other command taking an
        // engine, keeps working, and lands on the same engine as the new name.
        for (old, new) in RENAMES {
            assert_eq!(resolve_extensions(old).unwrap(), vec![old], "{old}");
            assert_eq!(resolve_extensions(new).unwrap(), vec![old], "{new}");
        }
        let err = resolve_extensions("nope").unwrap_err().to_string();
        assert!(
            err.contains("ambulo, voyage, doorward, toolmark, plessor, or all"),
            "{err}"
        );
        for (old, _) in RENAMES {
            assert!(!err.contains(old), "an old name is not offered: {err}");
        }
    }

    #[test]
    fn an_engine_is_printed_by_its_new_name_and_keeps_its_id() {
        for (old, new) in RENAMES {
            let e = engine(old).expect("known by its old name");
            assert_eq!((e.id, e.name, e.legacy), (old, new, Some(old)));
            assert_eq!(engine(new), Some(e));
            assert_eq!(public_name(old), new);
        }
        assert_eq!(public_name("voyage"), "voyage");
        assert_eq!(engine("voyage").unwrap().legacy, None);
    }

    #[test]
    fn a_component_that_is_not_an_engine_keeps_its_name() {
        for c in ["crossfyre", "node", "cfx-script"] {
            assert_eq!(public_name(c), c);
        }
    }
}

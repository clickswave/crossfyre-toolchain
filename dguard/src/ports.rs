//! The engines' daemon ports: the protocol's defaults, and config.toml's `[extensions]`,
//! which moves one. A client finds an engine's port the way the node's `engine_port` does:
//! the toolchain directory's config.toml first, the default when it names none.

use std::path::Path;

pub const AMBULO: u16 = 4441;
pub const VOYAGE: u16 = 4442;
pub const DOORWARD: u16 = 4443;
pub const TOOLMARK: u16 = 4444;
pub const PLESSOR: u16 = 4445;
/// plessor-authz: plessor's authorization testing, as a daemon of its own.
pub const PLESSOR_AUTHZ: u16 = 4446;

/// The ports a host's own database and engines listen on, which no test reaches: a test
/// build refuses them, and every test gives a port of its own.
pub const RESERVED: std::ops::RangeInclusive<u16> = 4440..=4446;

/// The protocol's port for `engine`, or None for a name that is not an engine.
pub fn default_of(engine: &str) -> Option<u16> {
    match engine {
        "ambulo" => Some(AMBULO),
        "voyage" => Some(VOYAGE),
        "doorward" => Some(DOORWARD),
        "toolmark" => Some(TOOLMARK),
        "plessor" => Some(PLESSOR),
        "plessor-authz" => Some(PLESSOR_AUTHZ),
        _ => None,
    }
}

/// `engine`'s port as config.toml in the toolchain directory sets it, or the protocol's.
pub fn engine_port(engine: &str) -> Option<u16> {
    engine_port_in(crate::toolchain_dir().as_deref(), engine)
}

/// [`engine_port`] for the toolchain directory `dir`. A file that cannot be read, or an
/// entry that is not a port, leaves the protocol's.
pub fn engine_port_in(dir: Option<&Path>, engine: &str) -> Option<u16> {
    let configured = dir
        .and_then(|d| std::fs::read_to_string(d.join("config.toml")).ok())
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|config| config.get("extensions")?.get(engine)?.as_integer())
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0);
    configured.or_else(|| default_of(engine))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every engine's port and the database's are reserved, and only those.
    #[test]
    fn the_reserved_ports_are_the_database_and_every_engine() {
        for port in [
            4440,
            AMBULO,
            VOYAGE,
            DOORWARD,
            TOOLMARK,
            PLESSOR,
            PLESSOR_AUTHZ,
        ] {
            assert!(RESERVED.contains(&port), "{port}");
        }
        assert!(!RESERVED.contains(&4439) && !RESERVED.contains(&4447));
    }

    /// config.toml's `[extensions]` moves an engine's port; with no entry, no file, or an
    /// entry that is not a port, the protocol's stands.
    #[test]
    fn config_toml_moves_an_engines_port() {
        let dir = std::env::temp_dir().join(format!("dguard-ports-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(engine_port_in(Some(&dir), "toolmark"), Some(TOOLMARK));
        std::fs::write(
            dir.join("config.toml"),
            "[postgres]\nport = 14440\n\n[extensions]\ntoolmark = 14444\nvoyage = 99999\n",
        )
        .unwrap();
        assert_eq!(engine_port_in(Some(&dir), "toolmark"), Some(14444));
        assert_eq!(engine_port_in(Some(&dir), "voyage"), Some(VOYAGE));
        assert_eq!(engine_port_in(Some(&dir), "plessor"), Some(PLESSOR));
        assert_eq!(
            engine_port_in(Some(&dir), "plessor-authz"),
            Some(PLESSOR_AUTHZ)
        );
        assert_eq!(engine_port_in(Some(&dir), "nothing"), None);
        assert_eq!(engine_port_in(None, "ambulo"), Some(AMBULO));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

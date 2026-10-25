// Toolchain configuration: where extension binaries live, and how the
// extensions reach the shared Postgres instance. Lives in the same
// `~/.config/crossfyre` root as the node configs (`nodes.d/`), in a
// `config.toml` the extension daemons also read.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolchainConfig {
    pub postgres: PostgresSection,
    pub container: ContainerSection,
    // Local TCP ports the extension daemons listen on. Host-level (all nodes on
    // this machine share one set of engine daemons + one Postgres), overridable
    // per install so an operator can dodge a port clash. Defaulted via serde so
    // an older config.toml still parses.
    #[serde(default)]
    pub extensions: ExtensionPorts,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostgresSection {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub db_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerSection {
    pub id: Option<String>,
}

/// Per-extension daemon ports, keyed by engine id.
///
/// In `config.toml` the `[extensions]` table is keyed by each engine's public name.
/// A key may also be an engine's id or its legacy name, so a file written before an
/// engine took its current name still loads with its ports intact; the public name
/// wins when a file carries both. A file that predates this section, or omits an
/// engine, gets the protocol default ([`super::Engine::port`]) for it, and an
/// unknown key is ignored. Written back, the table always uses public names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionPorts {
    ports: Vec<(&'static str, u16)>,
}

impl Default for ExtensionPorts {
    fn default() -> Self {
        Self::defaults_in(super::ENGINES)
    }
}

impl ExtensionPorts {
    fn defaults_in(table: &'static [super::Engine]) -> Self {
        Self {
            ports: table.iter().map(|e| (e.id, e.port)).collect(),
        }
    }

    /// Ports from `[extensions]` entries, read against `table`.
    fn from_entries_in<'a>(
        table: &'static [super::Engine],
        entries: impl IntoIterator<Item = (&'a str, u16)> + Clone,
    ) -> Self {
        let mut out = Self::defaults_in(table);
        // Two passes so a public-name key beats an id or legacy key for the same
        // engine whatever order the file lists them in.
        for public in [false, true] {
            for (key, port) in entries.clone() {
                if let Some(e) = super::find_engine(table, key)
                    && (key == e.name) == public
                {
                    out.set(e.id, port);
                }
            }
        }
        out
    }

    /// Configured port for `ext` (an id, public name or legacy name), or 0 if it
    /// isn't a known engine.
    pub fn get(&self, ext: &str) -> u16 {
        let id = super::engine(ext).map(|e| e.id).unwrap_or(ext);
        self.ports
            .iter()
            .find(|(k, _)| *k == id)
            .map(|(_, p)| *p)
            .unwrap_or(0)
    }

    /// Set `ext`'s port; no-op for an unknown engine name.
    pub fn set(&mut self, ext: &str, port: u16) {
        let id = super::engine(ext).map(|e| e.id).unwrap_or(ext);
        if let Some(slot) = self.ports.iter_mut().find(|(k, _)| *k == id) {
            slot.1 = port;
        }
    }
}

impl Serialize for ExtensionPorts {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(
            self.ports
                .iter()
                .map(|(id, port)| (super::public_name(id), *port)),
        )
    }
}

impl<'de> Deserialize<'de> for ExtensionPorts {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // A value that is not a port under a key that is not an engine is somebody
        // else's business, as it was when this was a plain struct.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Entry {
            Port(u16),
            Other(serde::de::IgnoredAny),
        }
        let raw: std::collections::BTreeMap<String, Entry> =
            std::collections::BTreeMap::deserialize(deserializer)?;
        let mut entries: Vec<(&str, u16)> = Vec::new();
        for (key, value) in &raw {
            match value {
                Entry::Port(p) => entries.push((key.as_str(), *p)),
                Entry::Other(_) if super::engine(key).is_some() => {
                    return Err(serde::de::Error::custom(format!(
                        "[extensions] {key} must be a port number"
                    )));
                }
                Entry::Other(_) => {}
            }
        }
        Ok(Self::from_entries_in(super::ENGINES, entries))
    }
}

impl Default for ToolchainConfig {
    fn default() -> Self {
        Self {
            postgres: PostgresSection {
                host: "localhost".to_string(),
                port: 4440,
                user: "postgres".to_string(),
                password: None,
                db_name: "crossfyre".to_string(),
            },
            container: ContainerSection { id: None },
            extensions: ExtensionPorts::default(),
        }
    }
}

/// `~/.config/crossfyre` of the *invoking* user (honors SUDO_USER), the same
/// root that holds `nodes.d/`.
/// Process-wide override for the toolchain directory, set once from `--data-dir`.
///
/// `--data-dir` is documented as "the directory that holds `nodes.d` and
/// `config.toml`" and exists so an operator can run an isolated set of nodes.
/// It used to reach only the auth and node files, because the config path was
/// resolved independently here and silently ignored it. Two "isolated" node
/// sets would then share one `config.toml`, which means one database and one
/// set of engine ports: exactly what the flag is meant to prevent.
static TOOLCHAIN_DIR_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Point every toolchain path at `dir`. Called once during CLI startup, before
/// any command runs. Later calls are ignored so a command cannot move the root
/// out from under itself half way through.
pub fn set_toolchain_dir(dir: PathBuf) {
    let _ = TOOLCHAIN_DIR_OVERRIDE.set(dir);
}

pub fn get_toolchain_dir() -> PathBuf {
    if let Some(dir) = TOOLCHAIN_DIR_OVERRIDE.get() {
        return dir.clone();
    }
    super::sudo_user::invoking_user_config_dir().join("crossfyre")
}

pub fn get_config_path() -> PathBuf {
    get_toolchain_dir().join("config.toml")
}

/// The variable that tells an engine daemon where the toolchain directory, and so its
/// `config.toml`, is. The engine host sets it on macOS and Windows; an engine without
/// it looks in the per-user default, as it always has on Linux.
pub const TOOLCHAIN_DIR_ENV: &str = "CROSSFYRE_TOOLCHAIN_DIR";

/// The file holding the egress-proxy variables the engine daemons start with. Linux
/// keeps the path its systemd units have always named; elsewhere it is in the
/// toolchain directory, which is where that path leads on Linux too unless
/// `--data-dir` moved the directory.
pub fn egress_env_path() -> PathBuf {
    if cfg!(target_os = "linux") {
        super::sudo_user::invoking_user_home().join(".config/crossfyre/egress.env")
    } else {
        get_toolchain_dir().join("egress.env")
    }
}

/// Where a file the node hands to an engine is written, such as a downloaded wordlist
/// the engine then reads by its path: `/tmp/<name>` on Unix, as it always has been. On
/// Windows the node runs as LocalSystem, whose temporary directory the operator, whom
/// the engines run as, cannot read, so it is the toolchain directory's `tmp`, in the
/// operator's profile, which both can.
pub fn handoff_path(name: &str) -> String {
    #[cfg(windows)]
    {
        let dir = get_toolchain_dir().join("tmp");
        let _ = fs::create_dir_all(&dir);
        dir.join(name).display().to_string()
    }
    #[cfg(not(windows))]
    {
        format!("/tmp/{name}")
    }
}

/// Where the services write their logs on macOS and Windows, which have no journal: the
/// toolchain directory's `logs`, beside the configs they describe and readable by the
/// same person. Linux services log to the journal instead.
pub fn logs_dir() -> PathBuf {
    get_toolchain_dir().join("logs")
}

pub fn get_bin_dir() -> PathBuf {
    // Where extension binaries (and the crossfyre binary itself) are
    // installed. Linux/macOS keep the conventional /opt prefix. Windows has
    // no /opt, so %ProgramFiles%\Crossfyre\bin: the node service runs from here
    // as LocalSystem, and Program Files is writable by administrators only.
    // %ProgramData% is not: every user may create files in its subdirectories,
    // which would let anyone plant a binary or a DLL the service then loads.
    // A package that keeps them somewhere else says where in its packaging.json.
    if let Some(dir) = super::packaging::bin_dir() {
        return dir.to_path_buf();
    }
    #[cfg(windows)]
    {
        let base =
            std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
        PathBuf::from(base).join("Crossfyre").join("bin")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/opt/crossfyre/bin")
    }
}

/// On-disk file name of an extension binary (adds `.exe` on Windows). `ext` may be an
/// engine id or any other component name; an engine is named by its public name.
pub fn ext_file_name(ext: &str) -> String {
    file_name(super::public_name(ext))
}

/// `name` as a file name on this OS.
pub(crate) fn file_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Full path to an installed extension binary, OS-correct extension included.
pub fn ext_bin_path(ext: &str) -> PathBuf {
    get_bin_dir().join(ext_file_name(ext))
}

/// Where the binary of an engine that has been renamed was installed under its legacy
/// name. `None` for an engine that has never had another name.
pub fn legacy_bin_path(ext: &str) -> Option<PathBuf> {
    let legacy = super::engine(ext)?.legacy?;
    Some(get_bin_dir().join(file_name(legacy)))
}

/// `path` exists and is a file in its own right, not a symlink to one.
pub fn is_regular_file(path: &std::path::Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// An engine counts as installed under its public name, or as a binary still sitting
/// under its legacy name on a machine the rename has not been carried to yet. A
/// legacy symlink does not count: that is what the migration in 0.1.31 and 0.1.32 left
/// behind, pointing at the binary under the public name, until the migration removes it.
pub fn is_extension_installed(ext: &str) -> bool {
    ext_bin_path(ext).exists() || legacy_bin_path(ext).is_some_and(|p| is_regular_file(&p))
}

pub fn load_config() -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    let path = get_config_path();
    let contents = fs::read_to_string(path)?;
    let config: ToolchainConfig = toml::from_str(&contents)?;
    Ok(config)
}

pub fn save_config(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    let dir = get_toolchain_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    let path = get_config_path();
    let toml_string = toml::to_string(config)?;
    fs::write(&path, toml_string)?;
    super::sudo_user::chown_to_invoking_user(&path);
    Ok(())
}

/// Resolve an extension daemon's port from `config.toml`, falling back to the
/// protocol default if the file is missing/unreadable or the engine is unknown.
/// This is the single lookup every op-client and the service installer use, so
/// changing a port in one place (config.toml) moves it everywhere consistently.
/// Reads the file each call - it's tiny, and this keeps the value fresh across
/// an install that rewrites config.toml mid-process.
pub fn engine_port(ext: &str) -> u16 {
    let configured = load_config()
        .ok()
        .map(|c| c.extensions.get(ext))
        .unwrap_or(0);
    if configured != 0 {
        return configured;
    }
    // Unknown to the config (old file, or a brand-new engine): protocol default.
    super::engine(ext).map(|e| e.port).unwrap_or(0)
}

/// `127.0.0.1:<port>` for an extension daemon, ready to hand to `TcpStream::connect`.
pub fn engine_addr(ext: &str) -> String {
    format!("127.0.0.1:{}", engine_port(ext))
}

/// Merge server-provided port overrides into the host `config.toml`. The JSON
/// is a flat map of service name to port, keyed by engine id (the ids are the
/// engines' original names), e.g.
/// `{ "postgres": 4440, "mach": 4441, "pulse": 4443 }` - "postgres" targets the
/// database, every other key an engine daemon. A public name is accepted in place
/// of an id. Missing/unknown keys keep their current value. Ensures `config.toml` exists first, and only writes when
/// something actually changed. Returns the list of services whose port moved
/// (so a live re-apply can restart exactly those), postgres included.
pub fn apply_ports_from_json(
    ports: &serde_json::Value,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut config = load_or_create_config()?;
    let obj = match ports.as_object() {
        Some(o) => o,
        None => return Ok(Vec::new()),
    };
    let mut changed: Vec<String> = Vec::new();

    if let Some(p) = obj.get("postgres").and_then(|v| v.as_u64()) {
        let p = p as u16;
        if p != 0 && config.postgres.port != p {
            config.postgres.port = p;
            changed.push("postgres".to_string());
        }
    }
    for e in super::ENGINES {
        let given = obj.get(e.id).or_else(|| obj.get(e.name));
        if let Some(p) = given.and_then(|v| v.as_u64()) {
            let p = p as u16;
            if p != 0 && config.extensions.get(e.id) != p {
                config.extensions.set(e.id, p);
                changed.push(e.id.to_string());
            }
        }
    }

    if !changed.is_empty() {
        save_config(&config)?;
    }
    Ok(changed)
}

/// Rewrite the `config.toml` at `path` so `[extensions]` is keyed by public names, if
/// it still names an engine by an id or legacy name that differs from its public name.
/// The file loads either way; this keeps what a person reads in it current. Returns
/// whether the file was written. A missing file is not an error.
pub fn rewrite_legacy_keys(path: &std::path::Path) -> Result<bool, Box<dyn std::error::Error>> {
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(false);
    };
    let value: toml::Value = toml::from_str(&text)?;
    let stale = value
        .get("extensions")
        .and_then(|v| v.as_table())
        .is_some_and(|t| {
            t.keys()
                .any(|k| super::engine(k).is_some_and(|e| e.name != k))
        });
    if !stale {
        return Ok(false);
    }
    let config: ToolchainConfig = toml::from_str(&text)?;
    fs::write(path, toml::to_string(&config)?)?;
    super::sudo_user::chown_to_invoking_user(path);
    Ok(true)
}

/// Load the toolchain config, writing the defaults first if none exists.
/// Defaults are sane for a single-host install; operators can edit
/// `config.toml` afterwards to point at an external Postgres.
pub fn load_or_create_config() -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    if !get_config_path().exists() {
        let config = ToolchainConfig::default();
        save_config(&config)?;
        println!(
            "[config] Wrote default toolchain config: {}",
            get_config_path().display()
        );
    }
    load_config()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::{ENGINES, Engine};

    fn ports(text: &str) -> ExtensionPorts {
        let cfg: ToolchainConfig = toml::from_str(&format!(
            "[postgres]\nhost = \"localhost\"\nport = 4440\nuser = \"postgres\"\n\
             db_name = \"crossfyre\"\n\n[container]\n\n{text}"
        ))
        .expect("config parses");
        cfg.extensions
    }

    #[test]
    fn a_config_without_the_section_gets_every_default() {
        let p = ports("");
        for e in ENGINES {
            assert_eq!(p.get(e.id), e.port, "{}", e.id);
        }
    }

    #[test]
    fn a_port_is_read_under_an_engine_id() {
        let p = ports("[extensions]\nmach = 5999\n");
        assert_eq!(p.get("mach"), 5999);
        assert_eq!(
            p.get("voyage"),
            4442,
            "an engine left out keeps its default"
        );
    }

    #[test]
    fn unknown_keys_are_ignored_and_a_bad_engine_port_is_not() {
        let p = ports("[extensions]\nsomething_else = \"x\"\nvoyage = 5000\n");
        assert_eq!(p.get("voyage"), 5000);
        let bad: Result<ToolchainConfig, _> = toml::from_str(
            "[postgres]\nhost = \"h\"\nport = 1\nuser = \"u\"\ndb_name = \"d\"\n\
             [container]\n[extensions]\nvoyage = \"x\"\n",
        );
        assert!(
            bad.is_err(),
            "a port that is not a number is an error, as it was"
        );
    }

    #[test]
    fn written_back_the_section_uses_public_names_in_table_order() {
        let text = toml::to_string(&ToolchainConfig::default()).expect("serialises");
        let section = text.split("[extensions]").nth(1).expect("section");
        let keys: Vec<&str> = section
            .lines()
            .filter_map(|l| l.split_once(" = ").map(|(k, _)| k))
            .collect();
        let names: Vec<&str> = ENGINES.iter().map(|e| e.name).collect();
        assert_eq!(keys, names);
    }

    #[test]
    fn a_config_written_before_the_rename_keeps_its_ports() {
        let p = ports("[extensions]\ncortex = 5001\nmach = 5002\npulse = 5003\nscout = 5004\n");
        assert_eq!(
            [
                p.get("cortex"),
                p.get("mach"),
                p.get("pulse"),
                p.get("scout")
            ],
            [5001, 5002, 5003, 5004]
        );
        // Reached by the new names as well, since a port is the engine's.
        assert_eq!(p.get("plessor"), 5001);
    }

    #[test]
    fn a_config_written_after_the_rename_uses_the_new_names() {
        let p = ports("[extensions]\nplessor = 5001\nambulo = 5002\n");
        assert_eq!((p.get("cortex"), p.get("mach")), (5001, 5002));
        let cfg = ToolchainConfig {
            extensions: p,
            ..ToolchainConfig::default()
        };
        let text = toml::to_string(&cfg).expect("serialises");
        assert!(
            text.contains("plessor = 5001") && text.contains("ambulo = 5002"),
            "{text}"
        );
        for old in ["cortex", "mach", "pulse", "scout"] {
            assert!(!text.contains(old), "{old} written back: {text}");
        }
    }

    #[test]
    fn the_migration_rewrites_old_keys_and_leaves_a_current_file_alone() {
        let dir = std::env::temp_dir().join(format!("cfx-config-rewrite-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "[postgres]\nhost = \"localhost\"\nport = 4440\nuser = \"postgres\"\n\
             db_name = \"crossfyre\"\n\n[container]\n\n[extensions]\ncortex = 5001\n",
        )
        .expect("old config");

        assert!(rewrite_legacy_keys(&path).expect("rewrites"));
        let text = fs::read_to_string(&path).expect("read");
        assert!(
            text.contains("plessor = 5001") && !text.contains("cortex"),
            "{text}"
        );
        assert!(
            !rewrite_legacy_keys(&path).expect("reads"),
            "a current file is not written"
        );
        assert!(!rewrite_legacy_keys(&dir.join("absent.toml")).expect("absent is fine"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// The alias reading against a table in which an engine was renamed.
    const RENAMED: &[Engine] = &[Engine {
        id: "cortex",
        name: "fresh",
        legacy: Some("cortex"),
        port: 4445,
        about: "",
    }];

    #[test]
    fn a_legacy_key_is_read_and_the_public_name_wins_over_it() {
        let p = ExtensionPorts::from_entries_in(RENAMED, vec![("cortex", 5001)]);
        assert_eq!(p.get("cortex"), 5001);
        for order in [
            vec![("fresh", 5002), ("cortex", 5001)],
            vec![("cortex", 5001), ("fresh", 5002)],
        ] {
            let p = ExtensionPorts::from_entries_in(RENAMED, order.clone());
            assert_eq!(p.get("cortex"), 5002, "{order:?}");
        }
    }
}

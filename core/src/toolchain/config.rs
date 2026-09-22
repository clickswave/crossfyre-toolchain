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

/// Per-extension daemon ports. Defaults are the protocol constants
/// ([`super::EXTENSION_PORTS`]); every field is `#[serde(default)]` so a config
/// that predates this section (or omits a newer engine) still loads.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtensionPorts {
    #[serde(default = "def_mach")]
    pub mach: u16,
    #[serde(default = "def_voyage")]
    pub voyage: u16,
    #[serde(default = "def_pulse")]
    pub pulse: u16,
    #[serde(default = "def_scout")]
    pub scout: u16,
    #[serde(default = "def_cortex")]
    pub cortex: u16,
}

fn def_mach() -> u16 {
    4441
}
fn def_voyage() -> u16 {
    4442
}
fn def_pulse() -> u16 {
    4443
}
fn def_scout() -> u16 {
    4444
}
fn def_cortex() -> u16 {
    4445
}

impl Default for ExtensionPorts {
    fn default() -> Self {
        Self {
            mach: def_mach(),
            voyage: def_voyage(),
            pulse: def_pulse(),
            scout: def_scout(),
            cortex: def_cortex(),
        }
    }
}

impl ExtensionPorts {
    /// Configured port for `ext`, or 0 if it isn't a known engine.
    pub fn get(&self, ext: &str) -> u16 {
        match ext {
            "mach" => self.mach,
            "voyage" => self.voyage,
            "pulse" => self.pulse,
            "scout" => self.scout,
            "cortex" => self.cortex,
            _ => 0,
        }
    }

    /// Set `ext`'s port; no-op for an unknown engine name.
    pub fn set(&mut self, ext: &str, port: u16) {
        match ext {
            "mach" => self.mach = port,
            "voyage" => self.voyage = port,
            "pulse" => self.pulse = port,
            "scout" => self.scout = port,
            "cortex" => self.cortex = port,
            _ => {}
        }
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

pub fn get_bin_dir() -> PathBuf {
    // Where extension binaries (and the crossfyre binary itself) are
    // installed. Linux/macOS keep the conventional /opt prefix; Windows has
    // no /opt so we use %ProgramData%\Crossfyre\bin.
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(base).join("Crossfyre").join("bin")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/opt/crossfyre/bin")
    }
}

/// On-disk file name of an extension binary (adds `.exe` on Windows).
pub fn ext_file_name(ext: &str) -> String {
    if cfg!(windows) {
        format!("{ext}.exe")
    } else {
        ext.to_string()
    }
}

/// Full path to an installed extension binary, OS-correct extension included.
pub fn ext_bin_path(ext: &str) -> PathBuf {
    get_bin_dir().join(ext_file_name(ext))
}

pub fn is_extension_installed(ext: &str) -> bool {
    ext_bin_path(ext).exists()
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
    super::EXTENSION_PORTS
        .iter()
        .find(|(name, _)| *name == ext)
        .map(|(_, p)| *p)
        .unwrap_or(0)
}

/// `127.0.0.1:<port>` for an extension daemon, ready to hand to `TcpStream::connect`.
pub fn engine_addr(ext: &str) -> String {
    format!("127.0.0.1:{}", engine_port(ext))
}

/// Merge server-provided port overrides into the host `config.toml`. The JSON
/// is a flat map of service name to port, e.g.
/// `{ "postgres": 4440, "mach": 4441, "pulse": 4443 }` - "postgres" targets the
/// database, every other key an engine daemon. Missing/unknown keys keep their
/// current value. Ensures `config.toml` exists first, and only writes when
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
    for ext in super::EXTENSIONS {
        if let Some(p) = obj.get(*ext).and_then(|v| v.as_u64()) {
            let p = p as u16;
            if p != 0 && config.extensions.get(ext) != p {
                config.extensions.set(ext, p);
                changed.push((*ext).to_string());
            }
        }
    }

    if !changed.is_empty() {
        save_config(&config)?;
    }
    Ok(changed)
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

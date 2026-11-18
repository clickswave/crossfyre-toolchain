// Toolchain configuration: where extension binaries live, and how the
// extensions reach the shared Postgres instance. Lives in the same
// `~/.config/crossfyre` root as the node configs (`nodes.d/`), in a
// `config.toml` the extension daemons also read.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolchainConfig {
    pub postgres: PostgresSection,
    pub container: ContainerSection,
    // Local TCP ports the extension daemons listen on. Host-level (all nodes on
    // this machine share one set of engine daemons + one Postgres), overridable
    // per install so an operator can dodge a port clash. Defaulted via serde, so
    // a file without the section gets the protocol defaults.
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
/// A file without the section, or one that leaves an engine out, gets the protocol
/// default ([`super::Engine::port`]) for it, and any other key is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionPorts {
    ports: Vec<(&'static str, u16)>,
}

impl Default for ExtensionPorts {
    fn default() -> Self {
        Self {
            ports: super::ENGINES.iter().map(|e| (e.id, e.port)).collect(),
        }
    }
}

/// The engine whose public name is `key`.
fn engine_named(key: &str) -> Option<&'static super::Engine> {
    super::ENGINES.iter().find(|e| e.name == key)
}

impl ExtensionPorts {
    /// Configured port for `ext` (an id or a public name), or 0 if it isn't a known
    /// engine.
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
        let mut ports = Self::default();
        for (key, value) in &raw {
            let Some(e) = engine_named(key) else {
                continue;
            };
            match value {
                Entry::Port(p) => ports.set(e.id, *p),
                Entry::Other(_) => {
                    return Err(serde::de::Error::custom(format!(
                        "[extensions] {key} must be a port number"
                    )));
                }
            }
        }
        Ok(ports)
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

/// An engine counts as installed when its binary is in the bin directory under its
/// public name.
pub fn is_extension_installed(ext: &str) -> bool {
    ext_bin_path(ext).exists()
}

pub fn load_config() -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    load_config_at(&get_config_path())
}

pub(crate) fn load_config_at(
    path: &std::path::Path,
) -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    // The node service reads this as root from the operator's home.
    let contents = super::sudo_user::read_to_string(path)?;
    let config: ToolchainConfig = toml::from_str(&contents)?;
    Ok(config)
}

pub fn save_config(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    save_config_at(&get_config_path(), config)
}

/// The file holds the database password, so it is written owner-only. The engine
/// daemons that read it run as the same account the file is handed back to.
pub(crate) fn save_config_at(
    path: &std::path::Path,
    config: &ToolchainConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(dir) = path.parent() {
        super::sudo_user::create_dir_all_for_invoking_user(dir)?;
    }
    let toml_string = toml::to_string(config)?;
    crate::write_secret_file(path, &toml_string)?;
    super::sudo_user::chown_to_invoking_user(path);
    Ok(())
}

/// A new random password for the toolchain database: 32 bytes as hex.
pub fn new_postgres_password() -> Result<String, Box<dyn std::error::Error>> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| format!("no randomness for a database password: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// The config at `path` with a database password, generating and saving one if the
/// file has none. The flag says whether one was generated, which means anything
/// that read the file earlier (the engine daemons) still holds the old settings.
pub(crate) fn ensure_postgres_password_at(
    path: &std::path::Path,
) -> Result<(ToolchainConfig, bool), Box<dyn std::error::Error>> {
    let mut config = load_config_at(path)?;
    if config
        .postgres
        .password
        .as_deref()
        .is_some_and(|p| !p.is_empty())
    {
        return Ok((config, false));
    }
    config.postgres.password = Some(new_postgres_password()?);
    save_config_at(path, &config)?;
    Ok((config, true))
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

/// Load the toolchain config, writing the defaults first if none exists.
/// Defaults are sane for a single-host install; operators can edit
/// `config.toml` afterwards to point at an external Postgres.
pub fn load_or_create_config() -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    load_or_create_config_at(&get_config_path())
}

/// A new file gets a generated database password, so the container `crossfyre db up`
/// makes from it, and the engines that read it, never run without one.
pub(crate) fn load_or_create_config_at(
    path: &std::path::Path,
) -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    if !path.exists() {
        let mut config = ToolchainConfig::default();
        config.postgres.password = Some(new_postgres_password()?);
        save_config_at(path, &config)?;
        println!(
            "[config] Wrote default toolchain config: {}",
            path.display()
        );
    }
    load_config_at(path)
}

#[cfg(all(test, unix))]
mod root_link_tests {
    use super::*;

    const A_CONFIG: &str = "[postgres]\nhost = \"localhost\"\nport = 4440\nuser = \"postgres\"\n\
                            db_name = \"crossfyre\"\n\n[container]\n";

    /// The node service reads the toolchain config as root from the operator's home.
    #[test]
    fn a_root_read_of_the_config_does_not_follow_a_link() {
        let t = tempfile::tempdir().unwrap();
        let elsewhere = t.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("config.toml"), A_CONFIG).unwrap();
        std::os::unix::fs::symlink(&elsewhere, t.path().join("crossfyre")).unwrap();

        let _root = crate::toolchain::sudo_user::act_as_root();
        assert!(load_config_at(&t.path().join("crossfyre/config.toml")).is_err());
    }

    /// Nor does a FIFO left at its name hang the service.
    #[test]
    fn a_root_read_of_the_config_does_not_wait_on_a_fifo() {
        let t = tempfile::tempdir().unwrap();
        let fifo = t.path().join("config.toml");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _root = crate::toolchain::sudo_user::act_as_root();
            let _ = tx.send(load_config_at(&fifo).is_err());
        });
        let refused = rx.recv_timeout(std::time::Duration::from_secs(3));
        assert_eq!(refused, Ok(true), "hung on a FIFO or read it");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::ENGINES;
    use std::fs;

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
    fn a_port_is_read_under_an_engine_s_public_name() {
        let p = ports("[extensions]\nambulo = 5999\n");
        assert_eq!((p.get("mach"), p.get("ambulo")), (5999, 5999));
        assert_eq!(
            p.get("voyage"),
            4442,
            "an engine left out keeps its default"
        );
    }

    #[test]
    fn unknown_keys_are_ignored_and_a_bad_engine_port_is_not() {
        let p = ports("[extensions]\nsomething_else = \"x\"\nvoyage = 5000\nmach = 5002\n");
        assert_eq!(p.get("voyage"), 5000);
        assert_eq!(p.get("mach"), 4441, "an id is not a key of the section");
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
    fn ports_are_written_back_under_public_names() {
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
        for id in ["cortex", "mach", "pulse", "scout"] {
            assert!(!text.contains(id), "{id} written back: {text}");
        }
    }

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_new_config_has_a_database_password_and_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = load_or_create_config_at(&path).unwrap();
        let pw = cfg.postgres.password.expect("a generated password");
        assert_eq!(pw.len(), 64);
        assert!(pw.chars().all(|c| c.is_ascii_hexdigit()));
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
        // The next load reads it back rather than making another.
        assert_eq!(
            load_or_create_config_at(&path).unwrap().postgres.password,
            Some(pw)
        );
    }

    #[test]
    fn a_config_without_a_password_gets_one_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[postgres]\nhost = \"localhost\"\nport = 4440\nuser = \"postgres\"\n\
             db_name = \"crossfyre\"\n\n[container]\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let (cfg, generated) = ensure_postgres_password_at(&path).unwrap();
        assert!(generated);
        let pw = cfg.postgres.password.expect("a password");
        assert_eq!(
            load_config_at(&path).unwrap().postgres.password,
            Some(pw.clone())
        );
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600, "tightened when the password went in");
        let (again, generated) = ensure_postgres_password_at(&path).unwrap();
        assert!(!generated);
        assert_eq!(again.postgres.password, Some(pw));
    }

    #[test]
    fn an_operator_password_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[postgres]\nhost = \"db.internal\"\nport = 5432\nuser = \"cfx\"\n\
             password = \"mine\"\ndb_name = \"crossfyre\"\n\n[container]\n",
        )
        .unwrap();
        let (cfg, generated) = ensure_postgres_password_at(&path).unwrap();
        assert!(!generated);
        assert_eq!(cfg.postgres.password.as_deref(), Some("mine"));
    }
}

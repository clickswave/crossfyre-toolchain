// Toolchain configuration: where extension binaries live, which database the
// extensions keep their state in, and the ports they listen on. Lives in the same
// `~/.config/crossfyre` root as the node configs (`nodes.d/`), in a `config.toml`
// the extension daemons also read.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ToolchainConfig {
    /// Which database the engines use, in the shape the engines read it.
    pub postgres: cfx_db::Settings,
    // Local TCP ports the extension daemons listen on. Host-level (all nodes on
    // this machine share one set of engine daemons + one Postgres), overridable
    // per install so an operator can dodge a port clash. Defaulted via serde, so
    // a file without the section gets the protocol defaults.
    #[serde(default)]
    pub extensions: ExtensionPorts,
}

/// Per-extension daemon ports, keyed by engine name, as the `[extensions]` table of
/// `config.toml` is. A file without the section, or one that leaves an engine out,
/// gets the protocol default ([`super::Engine::port`]) for it, and any other key is
/// ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionPorts {
    ports: Vec<(&'static str, u16)>,
}

impl Default for ExtensionPorts {
    fn default() -> Self {
        Self {
            ports: super::ENGINES.iter().map(|e| (e.name, e.port)).collect(),
        }
    }
}

impl ExtensionPorts {
    /// Configured port for engine `ext`, or 0 if it isn't a known engine.
    pub fn get(&self, ext: &str) -> u16 {
        self.ports
            .iter()
            .find(|(k, _)| *k == ext)
            .map(|(_, p)| *p)
            .unwrap_or(0)
    }

    /// Set `ext`'s port; no-op for an unknown engine name.
    pub fn set(&mut self, ext: &str, port: u16) {
        if let Some(slot) = self.ports.iter_mut().find(|(k, _)| *k == ext) {
            slot.1 = port;
        }
    }
}

impl Serialize for ExtensionPorts {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.ports.iter().copied())
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
            let Some(e) = super::engine(key) else {
                continue;
            };
            match value {
                Entry::Port(p) => ports.set(e.name, *p),
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
    #[cfg(test)]
    if let Some(dir) = TEST_TOOLCHAIN_DIR.with(|d| d.borrow().clone()) {
        return dir;
    }
    if let Some(dir) = TOOLCHAIN_DIR_OVERRIDE.get() {
        return dir.clone();
    }
    // A test build refuses the real one: what a test writes or reads there is the
    // operator's.
    #[cfg(test)]
    panic!(
        "a test asked for the real toolchain directory: a test gives it one of its own \
         (TestToolchainDir)"
    );
    #[cfg(not(test))]
    default_toolchain_dir().expect("Could not find the toolchain directory")
}

#[cfg(test)]
thread_local! {
    static TEST_TOOLCHAIN_DIR: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// A toolchain directory of a test's own, for the thread it runs on until it is dropped:
/// a config.toml in it gives each engine a port far from the real ones.
#[cfg(test)]
pub(crate) struct TestToolchainDir {
    _dir: tempfile::TempDir,
}

#[cfg(test)]
impl TestToolchainDir {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("a toolchain directory for the test");
        let ports: String = super::ENGINES
            .iter()
            .map(|e| format!("{} = {}\n", e.name, 20_000 + e.port))
            .collect();
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[postgres]\nbackend = \"local\"\nport = 24440\nuser = \"postgres\"\n\
                 db_name = \"crossfyre\"\n\n[extensions]\n{ports}"
            ),
        )
        .expect("its config.toml");
        TEST_TOOLCHAIN_DIR.with(|d| *d.borrow_mut() = Some(dir.path().to_path_buf()));
        Self { _dir: dir }
    }
}

#[cfg(test)]
impl TestToolchainDir {
    pub(crate) fn path(&self) -> &std::path::Path {
        self._dir.path()
    }
}

#[cfg(test)]
impl Drop for TestToolchainDir {
    fn drop(&mut self) {
        TEST_TOOLCHAIN_DIR.with(|d| *d.borrow_mut() = None);
    }
}

/// The toolchain directory, the same root that holds `nodes.d/`, when `--data-dir`
/// names none. As root it is the one of the user crossfyre was run for through sudo.
/// Otherwise it is the one the engines find (`dguard::toolchain_dir`), so the CLI and
/// the engines read one config.toml: `~/.config/crossfyre` on Linux whatever
/// XDG_CONFIG_HOME says.
pub fn default_toolchain_dir() -> Option<PathBuf> {
    if let Some((_, _, home, _)) = super::sudo_user::sudo_user_info() {
        return Some(super::sudo_user::config_root_in(&home).join("crossfyre"));
    }
    dguard::toolchain_dir()
}

pub fn get_config_path() -> PathBuf {
    get_toolchain_dir().join("config.toml")
}

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

/// The file name of the program called `name` on this OS: an engine, `crossfyre`,
/// `node` or `cfx-script`, with `.exe` on Windows.
pub fn file_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Full path to an installed extension binary, OS-correct extension included.
pub fn ext_bin_path(ext: &str) -> PathBuf {
    get_bin_dir().join(file_name(ext))
}

/// An engine counts as installed when its binary is in the bin directory.
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
    let config: ToolchainConfig =
        toml::from_str(&contents).map_err(|e| cfx_db::config_unreadable(&contents, path, &e))?;
    Ok(config)
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
    let port = if configured != 0 {
        configured
    } else {
        // Unknown to the config (old file, or a brand-new engine): protocol default.
        super::engine(ext).map(|e| e.port).unwrap_or(0)
    };
    // A test build refuses the engines' real ports: an engine of the operator's may be
    // listening on one.
    #[cfg(test)]
    if (4440..=4445).contains(&port) {
        panic!("a test asked for {ext}'s port {port}: a test reaches no engine of the host's");
    }
    port
}

/// `127.0.0.1:<port>` for an extension daemon, ready to hand to `TcpStream::connect`.
pub fn engine_addr(ext: &str) -> String {
    format!("127.0.0.1:{}", engine_port(ext))
}

/// Merge server-provided port overrides into the host `config.toml`. The JSON
/// is a flat map of service name to port, e.g.
/// `{ "postgres": 4440, "ambulo": 4441, "doorward": 4443 }`: "postgres" targets the
/// database, every other key an engine daemon by its name. Missing or unknown keys
/// keep their current value. Ensures `config.toml` exists first, and only writes when
/// something actually changed. Returns the services whose port moved (so a live
/// re-apply can restart exactly those), postgres included.
pub fn apply_ports_from_json(
    ports: &serde_json::Value,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    apply_ports_from_json_at(&get_config_path(), ports)
}

/// [`apply_ports_from_json`] for the config at `path`.
pub(crate) fn apply_ports_from_json_at(
    path: &std::path::Path,
    ports: &serde_json::Value,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut config = load_or_create_config_at(path)?;
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
        if let Some(p) = obj.get(e.name).and_then(|v| v.as_u64()) {
            let p = p as u16;
            if p != 0 && config.extensions.get(e.name) != p {
                config.extensions.set(e.name, p);
                changed.push(e.name.to_string());
            }
        }
    }

    if !changed.is_empty() {
        save_config_at(path, &config)?;
    }
    Ok(changed)
}

/// The toolchain config at `path`, written first when there is none. A new file is made
/// the way an engine makes one, under the same lock: for the local database, with a new
/// password, readable by the account the database belongs to.
pub(crate) fn load_or_create_config_at(
    path: &std::path::Path,
) -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    if !path.exists() {
        let dir = path.parent().ok_or("config.toml has no directory")?;
        let account = super::db::account()?;
        cfx_db::Toolchain::new(dir.to_path_buf(), account.as_ref()).settings()?;
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

    const A_CONFIG: &str = "[postgres]\nbackend = \"local\"\nport = 4440\nuser = \"postgres\"\n\
                            db_name = \"crossfyre\"\n";

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

    fn ports(text: &str) -> ExtensionPorts {
        let cfg: ToolchainConfig = toml::from_str(&format!(
            "[postgres]\nbackend = \"local\"\nport = 4440\nuser = \"postgres\"\n\
             db_name = \"crossfyre\"\n\n{text}"
        ))
        .expect("config parses");
        cfg.extensions
    }

    #[test]
    fn a_config_without_the_section_gets_every_default() {
        let p = ports("");
        for e in ENGINES {
            assert_eq!(p.get(e.name), e.port, "{}", e.name);
        }
    }

    #[test]
    fn a_port_is_read_under_the_engine_s_name() {
        let p = ports("[extensions]\nambulo = 5999\n");
        assert_eq!(p.get("ambulo"), 5999);
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
            "[postgres]\nbackend = \"local\"\nport = 1\nuser = \"u\"\ndb_name = \"d\"\n\
             [extensions]\nvoyage = \"x\"\n",
        );
        assert!(
            bad.is_err(),
            "a port that is not a number is an error, as it was"
        );
    }

    #[test]
    fn written_back_the_section_is_in_table_order() {
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
    fn ports_are_written_back_as_they_were_read() {
        let p = ports("[extensions]\nplessor = 5001\nambulo = 5002\n");
        assert_eq!((p.get("plessor"), p.get("ambulo")), (5001, 5002));
        let cfg = ToolchainConfig {
            extensions: p,
            ..ToolchainConfig::default()
        };
        let text = toml::to_string(&cfg).expect("serialises");
        assert!(
            text.contains("plessor = 5001") && text.contains("ambulo = 5002"),
            "{text}"
        );
    }

    /// The API sends the ports map keyed by engine name, and the node answers with the
    /// names of what moved.
    #[test]
    fn a_ports_map_moves_each_engine_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let ports = serde_json::json!({"postgres": 4999, "plessor": 5001, "voyage": 0, "nope": 7});
        assert_eq!(
            apply_ports_from_json_at(&path, &ports).unwrap(),
            ["postgres", "plessor"]
        );
        let cfg = load_config_at(&path).unwrap();
        assert_eq!(cfg.postgres.port, 4999);
        assert_eq!(cfg.extensions.get("plessor"), 5001);
        assert_eq!(
            cfg.extensions.get("voyage"),
            4442,
            "a port of 0 moves nothing"
        );
        assert!(
            apply_ports_from_json_at(&path, &ports).unwrap().is_empty(),
            "the same map again moves nothing"
        );
    }

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// With XDG_CONFIG_HOME pointing elsewhere, the CLI still finds the directory the
    /// engines read, which follows HOME on Linux. Run again in a child process, which
    /// has the environment this needs and prints what it found.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_cli_finds_the_directory_the_engines_read_whatever_xdg_config_home_says() {
        const NAME: &str = "toolchain::config::tests::the_cli_finds_the_directory_the_engines_read_whatever_xdg_config_home_says";
        const CHILD: &str = "CFX_TEST_PRINT_TOOLCHAIN_DIR";
        if std::env::var_os(CHILD).is_some() {
            println!("dir={}", crate::resolve_data_dir(None).unwrap().display());
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("elsewhere"))
            .env_remove(dguard::TOOLCHAIN_DIR_ENV)
            .env_remove("SUDO_USER")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        // libtest prints the test's name on the line the child's output starts.
        let dir = text
            .lines()
            .find_map(|l| l.split_once("dir=").map(|(_, d)| d.trim()))
            .unwrap_or_else(|| panic!("the child said: {text}"));
        assert_eq!(
            std::path::Path::new(dir),
            home.path().join(".config").join("crossfyre")
        );
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
}

#[cfg(test)]
mod test_guard_tests {
    use super::*;

    /// A test build refuses the real toolchain directory, and with it the engines' ports
    /// as this host's config gives them, until the test gives itself a directory; then
    /// both are its own, and an engine's port is far from the real ones.
    #[test]
    fn a_test_build_refuses_the_real_toolchain_directory_and_ports() {
        assert!(std::panic::catch_unwind(get_toolchain_dir).is_err());
        assert!(std::panic::catch_unwind(|| engine_port("toolmark")).is_err());
        let dir = TestToolchainDir::new();
        assert_eq!(get_toolchain_dir(), dir.path());
        assert_eq!(engine_port("toolmark"), 24444);
        drop(dir);
        assert!(std::panic::catch_unwind(get_toolchain_dir).is_err());
    }

    /// A test build refuses the bins origin: a test serves its own.
    #[test]
    fn a_test_build_refuses_the_bins_origin() {
        assert!(std::panic::catch_unwind(super::super::install::bins_origin).is_err());
    }
}

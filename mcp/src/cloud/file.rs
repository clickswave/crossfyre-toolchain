//! Where the Cloud key comes from: a file only its owner can read, or an environment
//! variable. Never a tool argument, and never anything a tool returns.
//!
//! The file is `<mcp dir>/cloud.toml`, next to the default scope file, or the path
//! given with `--cloud-file`. It is refused, and the server starts without Cloud,
//! when another user could read or replace it: a key in a file anyone on the machine
//! can read is a key anyone on the machine holds.
//!
//! The environment is read only when there is no file. The key and the API origin
//! always come from the same place, so a project's client config that sets a URL
//! cannot send a key from the file somewhere else.

use cfx_cloud_wire as wire;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The key, when it is not in a file.
pub(crate) const KEY_ENV: &str = "CROSSFYRE_MCP_CLOUD_KEY";
/// The API origin to use with [`KEY_ENV`]. Ignored when the key is in a file.
pub(crate) const URL_ENV: &str = "CROSSFYRE_MCP_CLOUD_URL";
/// The file's name in the MCP directory.
pub(crate) const FILE_NAME: &str = "cloud.toml";

/// A key that does not print itself.
#[derive(Clone)]
pub(crate) struct Key(String);

impl Key {
    pub(crate) fn new(key: &str) -> Self {
        Key(key.to_string())
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// `cfm_` and its first 8 hex characters.
    pub(crate) fn prefix(&self) -> String {
        wire::key_prefix(&self.0).unwrap_or_default()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({}...)", self.prefix())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    File(PathBuf),
    Env,
}

impl Source {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Source::File(_) => "file",
            Source::Env => "env",
        }
    }
}

/// What the last `whoami` said, kept in the file for display and for listing tools
/// when the Cloud cannot be reached at start.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cached {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// An origin: scheme, host and port, no path.
    pub api_url: String,
    pub key: Key,
    pub source: Source,
    pub cached: Cached,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileShape {
    api_url: String,
    key: String,
    #[serde(flatten)]
    cached: Cached,
}

/// What the server does about Cloud at start.
#[derive(Debug)]
pub(crate) enum Loaded {
    /// No file and no variable: the server is exactly the local one.
    None,
    /// Something was there and could not be used. The server starts without Cloud and
    /// `status` says this.
    Refused(String),
    Ready(Config),
}

/// Is the origin one a key may be sent to: https anywhere, or http to this machine.
/// Returns the origin with no path, or why not.
pub(crate) fn check_api_url(raw: &str) -> Result<String, String> {
    let url = transport::Url::parse(raw.trim())
        .map_err(|_| format!("api_url {:?} is not a URL", short(raw)))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("api_url must not carry a user name or password".into());
    }
    if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err("api_url must be an origin, such as https://crossfyre.io, with no path".into());
    }
    let host = url.host_str().unwrap_or("");
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => {
            return Err(format!(
                "api_url {:?} is plain http to another machine, which would send the key in \
                 the clear; use https",
                short(raw)
            ));
        }
        _ => return Err("api_url must be an https URL".into()),
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn short(s: &str) -> String {
    crate::untrusted::clean(s, 120)
}

/// Can someone other than the owner read the file, or replace it.
///
/// Owned by the effective user (root is accepted too, as for the scope file), with no
/// group or other permission bits at all, in a directory nobody else can write.
#[cfg(unix)]
fn unsafe_reason(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let m = std::fs::metadata(path).ok()?;
    if let Some(why) = mode_problem(m.mode(), m.uid(), me) {
        return Some(format!("{} {why}", path.display()));
    }
    let dir = path.parent()?;
    let d = std::fs::metadata(dir).ok()?;
    if d.mode() & 0o022 != 0 || (d.uid() != me && d.uid() != 0) {
        return Some(format!(
            "the directory {} can be written by other users or belongs to someone else, who \
             could put another key in its place",
            dir.display()
        ));
    }
    None
}

#[cfg(not(unix))]
fn unsafe_reason(_: &Path) -> Option<String> {
    None
}

/// The mode and owner rule on its own, so it can be tested without another user.
pub(crate) fn mode_problem(mode: u32, uid: u32, me: u32) -> Option<&'static str> {
    if uid != me && uid != 0 {
        return Some("belongs to another user");
    }
    if mode & 0o077 != 0 {
        return Some("can be read or written by other users; run chmod 600 on it");
    }
    None
}

/// Read the key, from the file when there is one and otherwise from the environment.
/// `explicit` is `--cloud-file`, which must exist.
pub(crate) fn load(default_path: &Path, explicit: Option<&Path>) -> Loaded {
    load_with(default_path, explicit, |k| std::env::var(k).ok())
}

pub(crate) fn load_with(
    default_path: &Path,
    explicit: Option<&Path>,
    env: impl Fn(&str) -> Option<String>,
) -> Loaded {
    let path = explicit.unwrap_or(default_path);
    match std::fs::read(path) {
        Ok(bytes) => from_file(path, &bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if explicit.is_some() {
                return Loaded::Refused(format!(
                    "--cloud-file {} does not exist; run `crossfyre mcp cloud login` to write it",
                    path.display()
                ));
            }
            from_env(env)
        }
        Err(e) => Loaded::Refused(format!("could not read {}: {e}", path.display())),
    }
}

fn from_file(path: &Path, bytes: &[u8]) -> Loaded {
    if let Some(why) = unsafe_reason(path) {
        return Loaded::Refused(format!("the Cloud key file {why}, so Cloud is off"));
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Loaded::Refused(format!("{} is not UTF-8 text", path.display()));
    };
    let shape: FileShape = match toml::from_str(text) {
        Ok(s) => s,
        // The parser's message can quote the line it failed on, which may be the key.
        Err(_) => {
            return Loaded::Refused(format!(
                "{} is not a valid Cloud key file; write it again with `crossfyre mcp cloud \
                 login`",
                path.display()
            ));
        }
    };
    let key = shape.key.trim();
    if !wire::valid_key(key) {
        return Loaded::Refused(format!(
            "the key in {} is not an MCP key (cfm_ and 32 hex characters); make one in Settings, \
             Agent access",
            path.display()
        ));
    }
    match check_api_url(&shape.api_url) {
        Ok(api_url) => Loaded::Ready(Config {
            api_url,
            key: Key(key.to_string()),
            source: Source::File(path.to_path_buf()),
            cached: shape.cached,
        }),
        Err(e) => Loaded::Refused(format!("{}: {e}", path.display())),
    }
}

fn from_env(env: impl Fn(&str) -> Option<String>) -> Loaded {
    let Some(raw) = env(KEY_ENV).filter(|v| !v.trim().is_empty()) else {
        return Loaded::None;
    };
    let key = raw.trim();
    if !wire::valid_key(key) {
        return Loaded::Refused(format!(
            "{KEY_ENV} is not an MCP key (cfm_ and 32 hex characters)"
        ));
    }
    let url = env(URL_ENV)
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());
    match check_api_url(&url) {
        Ok(api_url) => Loaded::Ready(Config {
            api_url,
            key: Key(key.to_string()),
            source: Source::Env,
            cached: Cached::default(),
        }),
        Err(e) => Loaded::Refused(format!("{URL_ENV}: {e}")),
    }
}

/// Where a key from the environment goes when nothing says otherwise: the origin this
/// build was made for, as for `crossfyre login`.
pub(crate) const DEFAULT_API_URL: &str = match option_env!("CROSSFYRE_API_URL") {
    Some(u) => u,
    None => "https://crossfyre.io",
};

/// Write the file: mode 0600 from the moment it exists, under a temporary name, then
/// renamed over the old one, so a reader never sees half a key.
pub(crate) fn save(path: &Path, api_url: &str, key: &str, cached: &Cached) -> std::io::Result<()> {
    let shape = FileShape {
        api_url: api_url.to_string(),
        key: key.to_string(),
        cached: cached.clone(),
    };
    let body = toml::to_string(&shape).map_err(std::io::Error::other)?;
    let text = format!(
        "# Written by `crossfyre mcp cloud login`. It holds a secret: keep it private.\n{body}"
    );
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".{FILE_NAME}.{}.tmp", std::process::id()));
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        let written = f.write_all(text.as_bytes()).and_then(|_| f.sync_all());
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

#[cfg(test)]
mod unit {
    use super::*;
    use crate::tests::support::{TempDir, write_private};

    const KEY: &str = "cfm_0123456789abcdef0123456789abcdef";

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn origins_are_https_or_this_machine() {
        assert_eq!(
            check_api_url("https://crossfyre.io").as_deref(),
            Ok("https://crossfyre.io")
        );
        assert_eq!(
            check_api_url("https://crossfyre.io/").as_deref(),
            Ok("https://crossfyre.io")
        );
        assert!(check_api_url("http://127.0.0.1:12004").is_ok());
        assert!(check_api_url("http://localhost:12004").is_ok());
        assert!(check_api_url("http://[::1]:12004").is_ok());
        for bad in [
            "http://crossfyre.io",
            "http://10.0.0.5:12004",
            "ftp://crossfyre.io",
            "https://user:pw@crossfyre.io",
            "https://crossfyre.io/api",
            "https://crossfyre.io/?x=1",
            "crossfyre.io",
        ] {
            assert!(check_api_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_mode_rule_wants_the_owner_alone() {
        assert_eq!(mode_problem(0o100600, 1000, 1000), None);
        assert_eq!(mode_problem(0o100400, 1000, 1000), None);
        assert_eq!(mode_problem(0o100600, 0, 1000), None);
        assert!(mode_problem(0o100644, 1000, 1000).is_some());
        assert!(mode_problem(0o100640, 1000, 1000).is_some());
        assert!(mode_problem(0o100604, 1000, 1000).is_some());
        assert!(mode_problem(0o100600, 1001, 1000).is_some());
    }

    #[test]
    fn a_saved_file_loads_back_and_is_private() {
        let d = TempDir::new();
        let p = d.path().join(FILE_NAME);
        let cached = Cached {
            workspace_name: Some("Acme staging".into()),
            permission: Some("launch".into()),
            ..Default::default()
        };
        save(&p, "https://crossfyre.io", KEY, &cached).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        match load_with(&p, None, no_env) {
            Loaded::Ready(c) => {
                assert_eq!(c.key.expose(), KEY);
                assert_eq!(c.cached, cached);
                assert_eq!(c.source, Source::File(p.clone()));
                assert!(!format!("{c:?}").contains(KEY), "Debug shows the key");
            }
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = TempDir::new();
        let p = d.path().join(FILE_NAME);
        write_private(
            &p,
            &format!("api_url = \"https://crossfyre.io\"\nkey = \"{KEY}\"\n"),
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        match load_with(&p, None, no_env) {
            Loaded::Refused(why) => {
                assert!(why.contains("chmod 600"), "{why}");
                assert!(!why.contains(KEY));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_bad_file_never_quotes_its_key() {
        let d = TempDir::new();
        let p = d.path().join(FILE_NAME);
        write_private(
            &p,
            &format!("api_url = \"https://crossfyre.io\"\nkey = {KEY}\n"),
        );
        match load_with(&p, None, no_env) {
            Loaded::Refused(why) => assert!(!why.contains("0123456789abcdef"), "{why}"),
            other => panic!("{other:?}"),
        }
        write_private(
            &p,
            &format!("api_url = \"http://crossfyre.io\"\nkey = \"{KEY}\"\n"),
        );
        assert!(matches!(load_with(&p, None, no_env), Loaded::Refused(_)));
        write_private(
            &p,
            "api_url = \"https://crossfyre.io\"\nkey = \"cfk_0123456789abcdef0123456789abcdef\"\n",
        );
        assert!(matches!(load_with(&p, None, no_env), Loaded::Refused(_)));
    }

    #[test]
    fn the_environment_is_read_only_without_a_file() {
        let d = TempDir::new();
        let p = d.path().join(FILE_NAME);
        let other = "cfm_ffffffffffffffffffffffffffffffff";
        let env = |k: &str| match k {
            KEY_ENV => Some(other.to_string()),
            URL_ENV => Some("https://attacker.example".to_string()),
            _ => None,
        };
        match load_with(&p, None, env) {
            Loaded::Ready(c) => {
                assert_eq!(c.key.expose(), other);
                assert_eq!(c.source, Source::Env);
                assert_eq!(c.api_url, "https://attacker.example");
            }
            other => panic!("{other:?}"),
        }
        // With a file, neither the key nor the URL from the environment is used.
        write_private(
            &p,
            &format!("api_url = \"https://crossfyre.io\"\nkey = \"{KEY}\"\n"),
        );
        match load_with(&p, None, env) {
            Loaded::Ready(c) => {
                assert_eq!(c.key.expose(), KEY);
                assert_eq!(c.api_url, "https://crossfyre.io");
            }
            other => panic!("{other:?}"),
        }
        let none = d.path().join("absent.toml");
        assert!(matches!(load_with(&none, None, no_env), Loaded::None));
        assert!(matches!(
            load_with(&none, Some(&none), env),
            Loaded::Refused(_)
        ));
    }
}

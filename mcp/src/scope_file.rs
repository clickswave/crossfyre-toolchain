//! The scope file: the one place traffic permission comes from.
//!
//! A person writes it, the server reads it once at start, and nothing the server does
//! writes it back. A model can ask what is in it (`get_scope`, `check_scope`) and
//! nothing else. So an instruction smuggled into a scanned page can at most get the
//! model to ask for a destination the file does not list, which the guard refuses.
//!
//! Parsing is strict on purpose. An unknown key is an error rather than a key
//! ignored, because `allow_privte = true` silently doing nothing is how a person ends
//! up believing a setting is in force when it is not. An entry the scope crate does
//! not understand stops the server, because running with four of five rules is
//! running with a fence the person did not write.

use cfx_scope::{Guard, Policy, Scope};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Written into `get_scope` when there is no file yet, so the person reading the
/// model's answer has something to copy.
pub(crate) const EXAMPLE: &str = r#"# Written by a person. crossfyre mcp reads this file when it starts and never writes it.
entries = ["app.example.com", "api.example.com:8443", "*.staging.example.com", "10.20.0.0/24"]
allow_writes = false                  # test_writes, and non-GET/HEAD/OPTIONS methods in send_http_request
allow_private = false                 # names that resolve to private, loopback or link-local addresses
max_concurrent_scans = 3              # 1..=10
max_scan_starts_per_hour = 20         # 1..=200
requests_per_second_per_host = 2      # 1..=20, for send_http_request and fingerprint
"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeFile {
    #[serde(default)]
    entries: Option<Vec<String>>,
    #[serde(default)]
    allow_writes: bool,
    #[serde(default)]
    allow_private: bool,
    #[serde(default = "d_concurrent")]
    max_concurrent_scans: u32,
    #[serde(default = "d_starts")]
    max_scan_starts_per_hour: u32,
    #[serde(default = "d_rate")]
    requests_per_second_per_host: u32,
}
fn d_concurrent() -> u32 {
    3
}
fn d_starts() -> u32 {
    20
}
fn d_rate() -> u32 {
    2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeState {
    /// No file at the path. The server runs, and every traffic tool refuses.
    Missing,
    /// A file with no entries, or only blank ones. Same as missing.
    Empty,
    /// At least one entry, every one of which parsed.
    Loaded,
}

impl ScopeState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ScopeState::Missing => "missing",
            ScopeState::Empty => "empty",
            ScopeState::Loaded => "loaded",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedScope {
    pub path: PathBuf,
    pub state: ScopeState,
    /// Of the raw bytes. `None` when there was no file.
    pub sha256: Option<String>,
    /// The non-blank entries, trimmed, as the person wrote them.
    pub entries: Vec<String>,
    pub scope: Scope,
    /// Each entry parsed on its own, so `check_scope` can say which rule matched.
    pub per_entry: Vec<(String, Scope)>,
    pub allow_writes: bool,
    pub allow_private: bool,
    pub max_concurrent_scans: u32,
    pub max_scan_starts_per_hour: u32,
    pub requests_per_second_per_host: u32,
    pub loaded_at: String,
}

impl LoadedScope {
    pub(crate) fn has_entries(&self) -> bool {
        self.state == ScopeState::Loaded
    }

    /// The guard every traffic tool goes through.
    ///
    /// Always `Restricted`. `Policy::from_entries` turns an empty list into
    /// `Unrestricted`, which is right for a proxy nobody has fenced yet and exactly
    /// wrong here, so it is never called: no entries means a guard that admits
    /// nothing, behind the `no_scope` refusal that comes first anyway.
    pub(crate) fn guard(&self) -> Arc<Guard> {
        Guard::new(Policy::Restricted(self.scope.clone()))
    }

    /// The hash the file on disk has now, or `None` if it is gone.
    pub(crate) fn current_sha256(&self) -> Option<String> {
        std::fs::read(&self.path).ok().map(|b| sha256_hex(&b))
    }

    pub(crate) fn short_sha(&self) -> String {
        self.sha256
            .as_deref()
            .map(|s| s[..12.min(s.len())].to_string())
            .unwrap_or_else(|| "none".into())
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn bounded(name: &str, v: u32, lo: u32, hi: u32) -> Result<u32, String> {
    if (lo..=hi).contains(&v) {
        Ok(v)
    } else {
        Err(format!("{name} = {v} is outside {lo}..={hi}"))
    }
}

/// Another local user able to write the file, or its directory, can widen the scope:
/// through the group or everyone write bit, or by owning it. Root is the one other
/// owner accepted, since root can write anything anyway.
#[cfg(unix)]
fn others_can_write(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    std::fs::metadata(path)
        .map(|m| m.mode() & 0o022 != 0 || (m.uid() != me && m.uid() != 0))
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn others_can_write(_: &Path) -> bool {
    false
}

/// Read and check the scope file. Every error names the file and what is wrong with
/// it, and is a reason not to start.
pub(crate) fn load(path: &Path) -> Result<LoadedScope, String> {
    let shown = path.display();
    // The directory the path is in, and the one the file really lives in when the
    // path is a link: whoever can write either can put another file in its place.
    let real = std::fs::canonicalize(path).ok();
    for dir in [path.parent(), real.as_deref().and_then(Path::parent)]
        .into_iter()
        .flatten()
    {
        if others_can_write(dir) {
            return Err(format!(
                "the directory holding the scope file, {}, is writable by other users or \
                 belongs to someone else, who could widen the scope; make it yours and remove \
                 that permission (chmod go-w)",
                dir.display()
            ));
        }
    }
    let loaded_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let base = |state| LoadedScope {
        path: path.to_path_buf(),
        state,
        sha256: None,
        entries: Vec::new(),
        scope: Scope::default(),
        per_entry: Vec::new(),
        allow_writes: false,
        allow_private: false,
        max_concurrent_scans: d_concurrent(),
        max_scan_starts_per_hour: d_starts(),
        requests_per_second_per_host: d_rate(),
        loaded_at: loaded_at.clone(),
    };
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(base(ScopeState::Missing));
        }
        Err(e) => return Err(format!("could not read the scope file {shown}: {e}")),
    };
    if others_can_write(path) {
        return Err(format!(
            "the scope file {shown} is writable by other users or belongs to someone else, who \
             could widen the scope; make it yours and remove that permission (chmod go-w)"
        ));
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| format!("the scope file {shown} is not UTF-8 text"))?;
    let file: ScopeFile =
        toml::from_str(text).map_err(|e| format!("the scope file {shown} is not valid: {e}"))?;

    let mut out = base(ScopeState::Empty);
    out.sha256 = Some(sha256_hex(&raw));
    out.allow_writes = file.allow_writes;
    out.allow_private = file.allow_private;
    let check = |r: Result<u32, String>| r.map_err(|e| format!("the scope file {shown}: {e}"));
    out.max_concurrent_scans = check(bounded(
        "max_concurrent_scans",
        file.max_concurrent_scans,
        1,
        10,
    ))?;
    out.max_scan_starts_per_hour = check(bounded(
        "max_scan_starts_per_hour",
        file.max_scan_starts_per_hour,
        1,
        200,
    ))?;
    out.requests_per_second_per_host = check(bounded(
        "requests_per_second_per_host",
        file.requests_per_second_per_host,
        1,
        20,
    ))?;

    let entries: Vec<String> = file
        .entries
        .unwrap_or_default()
        .iter()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect();
    if entries.is_empty() {
        return Ok(out);
    }
    let (scope, refused) = cfx_scope::parse(&entries);
    if !refused.is_empty() {
        let named: Vec<String> = refused.iter().map(|e| format!("{e:?}")).collect();
        return Err(format!(
            "the scope file {shown} has entries that are not destinations: {}. An entry is a \
             host, host:port, *.domain or an address range such as 10.0.0.0/24; nothing was \
             started, so fix or remove these and start again",
            named.join(", ")
        ));
    }
    out.per_entry = entries
        .iter()
        .map(|e| (e.clone(), cfx_scope::parse(std::slice::from_ref(e)).0))
        .collect();
    out.scope = scope;
    out.entries = entries;
    out.state = ScopeState::Loaded;
    Ok(out)
}

#[cfg(test)]
mod unit {
    use super::*;
    use crate::tests::support::TempDir;

    fn write(dir: &TempDir, text: &str) -> PathBuf {
        let p = dir.path().join("scope.toml");
        crate::tests::support::write_private(&p, text);
        p
    }

    #[test]
    fn a_full_file_parses() {
        let d = TempDir::new();
        let p = write(&d, EXAMPLE);
        let s = load(&p).unwrap();
        assert_eq!(s.state, ScopeState::Loaded);
        assert_eq!(s.entries.len(), 4);
        assert_eq!(s.per_entry.len(), 4);
        assert_eq!(s.max_concurrent_scans, 3);
        assert!(!s.allow_writes && !s.allow_private);
        assert_eq!(
            s.sha256.as_deref(),
            Some(sha256_hex(EXAMPLE.as_bytes()).as_str())
        );
        assert!(s.guard().is_restricted());
    }

    #[test]
    fn an_unknown_key_is_an_error() {
        let d = TempDir::new();
        let p = write(&d, "entries = [\"a.test\"]\nallow_privte = true\n");
        let e = load(&p).unwrap_err();
        assert!(e.contains("allow_privte"), "{e}");
    }

    #[test]
    fn an_entry_that_does_not_parse_is_named_and_stops_the_start() {
        let d = TempDir::new();
        let p = write(
            &d,
            "entries = [\"a.test\", \"not a host\", \"https://b.test/x\"]\n",
        );
        let e = load(&p).unwrap_err();
        assert!(e.contains("\"not a host\""), "{e}");
        assert!(e.contains("\"https://b.test/x\""), "{e}");
    }

    #[test]
    fn blank_or_absent_entries_are_empty_and_missing_is_missing() {
        let d = TempDir::new();
        let p = write(&d, "entries = [\"\", \"  \"]\n");
        let s = load(&p).unwrap();
        assert_eq!(s.state, ScopeState::Empty);
        assert!(s.guard().is_restricted());
        assert!(
            !s.guard()
                .admit("anything.test", 80, cfx_scope::Point::Request, None)
        );

        let p = write(&d, "allow_writes = true\n");
        assert_eq!(load(&p).unwrap().state, ScopeState::Empty);

        let s = load(&d.path().join("absent.toml")).unwrap();
        assert_eq!(s.state, ScopeState::Missing);
        assert!(s.guard().is_restricted());
        assert!(s.sha256.is_none());
    }

    #[test]
    fn bounds_are_enforced() {
        let d = TempDir::new();
        for bad in [
            "max_concurrent_scans = 0",
            "max_concurrent_scans = 11",
            "max_scan_starts_per_hour = 201",
            "requests_per_second_per_host = 0",
            "requests_per_second_per_host = 21",
        ] {
            let p = write(&d, &format!("entries = [\"a.test\"]\n{bad}\n"));
            assert!(load(&p).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn bad_toml_is_an_error() {
        let d = TempDir::new();
        let p = write(&d, "entries = [\"a.test\"\n");
        assert!(load(&p).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_file_or_directory_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = TempDir::new();
        let p = write(&d, "entries = [\"a.test\"]\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load(&p).unwrap_err().contains("writable by other users"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&p).is_ok());
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = load(&p).unwrap_err();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(e.contains("directory"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_or_directory_the_group_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = TempDir::new();
        let p = write(&d, "entries = [\"a.test\"]\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(load(&p).unwrap_err().contains("other users"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&p).is_ok());
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let e = load(&p).unwrap_err();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(e.contains("directory"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn a_link_into_a_directory_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let shared = TempDir::new();
        let real = write(&shared, "entries = [\"a.test\"]\n");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let mine = TempDir::new();
        let link = mine.path().join("scope.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let r = load(&link);
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.unwrap_err().contains("other users"));
        assert!(load(&link).is_ok());
    }
}

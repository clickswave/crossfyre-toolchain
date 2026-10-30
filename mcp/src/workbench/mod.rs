//! Finding the running Workbenches and keeping a connection to each.
//!
//! A Workbench with Agent access on listens on a Unix socket in its data directory and
//! writes an endpoint file beside it saying where, with a token. This module reads those
//! files, refuses any that another user could have written or that point outside the
//! two directories a Workbench uses, and keeps one connection to each live instance, up
//! to four. Which tools are listed follows from what those connections advertise.
//!
//! The data directory comes from the CLI, never from a tool argument.

mod conn;

pub(crate) use conn::Instance;

use crate::core::Mcp;
use crate::guard::BoxFut;
use crate::untrusted;
use cfx_bridge::{Call, ClientInfo, Endpoint, Method, StatusResult};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Connections kept at once.
pub(crate) const MAX_INSTANCES: usize = 4;

/// The directory under `$XDG_RUNTIME_DIR` a Workbench puts its socket in when the path in
/// its data directory would be too long for a socket.
pub(crate) const RUNTIME_SUBDIR: &str = "io.crossfyre.workbench";

/// How long a request waits for its answer.
pub(crate) const REQUEST_WAIT: Duration = Duration::from_secs(10);

/// How often the control directory is looked at again: often while nothing is
/// connected, so a Workbench that starts is found quickly, and now and then otherwise,
/// to find a second one.
const LOOK_IDLE: Duration = Duration::from_secs(2);
const LOOK_CONNECTED: Duration = Duration::from_secs(10);

/// The client is told the tool list changed at most this often.
const NOTIFY_GAP: Duration = Duration::from_secs(2);

/// The bridge methods each tool needs. A tool is listed only while some instance
/// advertises all of them.
pub(crate) fn needs(tool: &str) -> &'static [Method] {
    match tool {
        "workbench_list_history" => &[Method::History],
        "workbench_get_exchange" => &[Method::Exchange],
        "workbench_get_selection" => &[Method::Selection, Method::Exchange],
        "workbench_get_site_map" => &[Method::SiteMap],
        "workbench_get_scope" => &[Method::Scope, Method::Check],
        "workbench_replay" => &[Method::Exchange, Method::Replay],
        "workbench_test_injection" => &[Method::ScanSource, Method::Check, Method::Scope],
        _ => &[],
    }
}

/// An endpoint file that was not used, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ignored {
    pub file: String,
    pub why: String,
}

/// A Workbench that is running but cannot be connected to: Agent access is off, its
/// bridge did not start, or it speaks another protocol.
#[derive(Debug, Clone)]
pub(crate) struct Idle {
    pub pid: u32,
    pub app_version: String,
    pub why: String,
}

/// What the last look at the control directory found besides the connections.
#[derive(Debug, Clone, Default)]
struct Seen {
    idle: Vec<Idle>,
    ignored: Vec<Ignored>,
}

pub(crate) struct Registry {
    dir: Option<PathBuf>,
    version: String,
    /// What the MCP client said it was, passed on in the handshake once it is known.
    label: Mutex<Option<String>>,
    instances: Mutex<BTreeMap<u32, Arc<Instance>>>,
    seen: Mutex<Seen>,
    /// Bumped whenever an instance comes or goes.
    changed: watch::Sender<u64>,
    refreshing: tokio::sync::Mutex<()>,
    /// Set by the first look, so the first `tools/list` can wait for it.
    looked: AtomicBool,
    me: Weak<Registry>,
}

impl Registry {
    pub(crate) fn new(dir: Option<PathBuf>, version: String) -> Arc<Registry> {
        Arc::new_cyclic(|me| Registry {
            dir,
            version,
            label: Mutex::new(None),
            instances: Mutex::new(BTreeMap::new()),
            seen: Mutex::new(Seen::default()),
            changed: watch::channel(0).0,
            refreshing: tokio::sync::Mutex::new(()),
            looked: AtomicBool::new(false),
            me: me.clone(),
        })
    }

    pub(crate) fn set_label(&self, label: &str) {
        if let Ok(mut l) = self.label.lock() {
            *l = Some(untrusted::clean(label, 64));
        }
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn bump(&self) {
        self.changed.send_modify(|n| *n += 1);
    }

    /// Every connection that is still open.
    pub(crate) fn instances(&self) -> Vec<Arc<Instance>> {
        self.instances
            .lock()
            .map(|m| m.values().filter(|i| !i.is_closed()).cloned().collect())
            .unwrap_or_default()
    }

    fn idle(&self) -> Vec<Idle> {
        self.seen.lock().map(|s| s.idle.clone()).unwrap_or_default()
    }

    pub(crate) fn ignored(&self) -> Vec<Ignored> {
        self.seen
            .lock()
            .map(|s| s.ignored.clone())
            .unwrap_or_default()
    }

    /// The Workbench tools some connected instance can answer, in listing order.
    pub(crate) fn listed(&self) -> Vec<&'static str> {
        let all = self.instances();
        crate::tools::WORKBENCH_NAMES
            .into_iter()
            .filter(|t| {
                all.iter()
                    .any(|i| needs(t).iter().all(|m| i.welcome.supports(*m)))
            })
            .collect()
    }

    pub(crate) fn forget(&self, pid: u32) {
        let removed = self
            .instances
            .lock()
            .map(|mut m| m.remove(&pid).is_some())
            .unwrap_or(false);
        if removed {
            self.bump();
        }
    }

    /// Look once if nobody has looked yet, so the first tool list a client reads
    /// already holds a Workbench that was running when the server started.
    pub(crate) async fn first_look(&self) {
        if !self.looked.load(Ordering::SeqCst) {
            self.refresh().await;
        }
    }

    /// Look at the control directory again: connect to new instances, and note the files
    /// that were not used. Several callers at once wait for one look.
    pub(crate) async fn refresh(&self) {
        let _one = self.refreshing.lock().await;
        let Some(dir) = self.dir.clone() else {
            self.looked.store(true, Ordering::SeqCst);
            return;
        };
        let mut seen = Seen::default();
        let found = discover(&dir, &mut seen);
        let mut added = false;
        for (file, e) in found {
            let connected = self
                .instances
                .lock()
                .map(|m| m.get(&e.pid).is_some_and(|i| !i.is_closed()))
                .unwrap_or(false);
            if connected {
                continue;
            }
            if self.instances().len() >= MAX_INSTANCES {
                seen.ignored.push(Ignored {
                    file,
                    why: format!("{MAX_INSTANCES} Workbenches are connected already"),
                });
                continue;
            }
            let client = ClientInfo {
                name: "crossfyre mcp".into(),
                version: self.version.clone(),
                pid: std::process::id(),
                label: self.label.lock().ok().and_then(|l| l.clone()),
            };
            match conn::connect(&e, client, self.me.clone()).await {
                Ok(inst) => {
                    if let Ok(mut m) = self.instances.lock() {
                        m.insert(e.pid, inst);
                        added = true;
                    }
                }
                Err(why) => seen.ignored.push(Ignored { file, why }),
            }
        }
        if let Ok(mut s) = self.seen.lock() {
            *s = seen;
        }
        self.looked.store(true, Ordering::SeqCst);
        if added {
            self.bump();
        }
    }

    /// The `instances` and `ignored` of the `workbench` object in `status`, and the hints
    /// that go with them. Each connected instance is asked how it stands now.
    pub(crate) async fn status(&self, hints: &mut Vec<String>) -> Value {
        self.refresh().await;
        let mut instances = Vec::new();
        for i in self.instances() {
            let asked = i.request::<StatusResult>(&Call::Status, REQUEST_WAIT).await;
            let unanswered = asked.as_ref().err().map(|e| e.describe());
            let now = asked.ok();
            let p = now
                .as_ref()
                .map_or_else(|| i.project(), |s| s.project.clone());
            if p.is_none() {
                hints.push(format!(
                    "the Workbench with pid {} has no project open; the workbench_* tools \
                     need one",
                    i.pid
                ));
            }
            instances.push(json!({
                "pid": i.pid,
                "app_version": untrusted::clean(&i.welcome.app_version, 40),
                "agent_access": true,
                "project": p.as_ref().map(|p| untrusted::clean(&p.name, 200)),
                "project_uid": p.as_ref().map(|p| p.uid.clone()),
                "exchanges": p.as_ref().map(|p| p.exchanges),
                "project_scope": now.as_ref().map(|s| json!({
                    "restricted": s.scope.restricted,
                    "rules": s.scope.rules,
                })),
                "status_error": unanswered,
                "capabilities": i.welcome.capabilities.iter()
                    .map(|c| untrusted::clean(c, 40))
                    .collect::<Vec<_>>(),
            }));
        }
        for i in self.idle() {
            hints.push(format!(
                "a Workbench (pid {}) is running but cannot be reached: {}",
                i.pid, i.why
            ));
            instances.push(json!({
                "pid": i.pid,
                "app_version": i.app_version,
                "agent_access": false,
                "project": null,
                "project_uid": null,
                "exchanges": null,
                "why": i.why,
            }));
        }
        let ignored: Vec<Value> = self
            .ignored()
            .into_iter()
            .map(|g| json!({"file": g.file, "why": g.why}))
            .collect();
        if !ignored.is_empty() {
            hints.push(format!(
                "{} Workbench endpoint file(s) were not used; workbench.ignored says why",
                ignored.len()
            ));
        }
        json!({
            "dir": self.dir.as_ref().map(|d| d.display().to_string()),
            "instances": instances,
            "ignored": ignored,
        })
    }
}

/// Keep the tool list in step with the Workbenches that answer, for as long as the
/// session runs: look for new ones, and tell the client when the set of listed tools
/// changes, at most once every two seconds.
pub(crate) async fn watch<F>(mcp: Arc<Mcp>, notify: F)
where
    F: Fn() -> BoxFut<'static, ()> + Send + Sync,
{
    let reg = Arc::clone(&mcp.workbench);
    let mut changed = reg.subscribe();
    reg.first_look().await;
    let mut told = mcp.backends();
    let mut last_told: Option<Instant> = None;
    loop {
        let wait = if reg.instances().is_empty() {
            LOOK_IDLE
        } else {
            LOOK_CONNECTED
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => reg.refresh().await,
            r = changed.changed() => {
                if r.is_err() {
                    return;
                }
            }
        }
        if mcp.backends() == told {
            continue;
        }
        if let Some(gap) = last_told.map(|t| NOTIFY_GAP.saturating_sub(t.elapsed())) {
            tokio::time::sleep(gap).await;
        }
        // What is listed after the wait, which can be back where it was.
        let now = mcp.backends();
        if now != told {
            notify().await;
            told = now;
            last_told = Some(Instant::now());
        }
    }
}

// ---------------------------------------------------------------------------
// The control directory

/// The endpoints in `<dir>/control` that may be connected to, by file name. Files that
/// fail a check go to `seen.ignored`, and running Workbenches that cannot be reached to
/// `seen.idle`. A file whose process is gone is left out silently: it is what a crash
/// leaves behind, and the next Workbench start removes it.
fn discover(dir: &Path, seen: &mut Seen) -> Vec<(String, Endpoint)> {
    let control = dir.join("control");
    let Ok(rd) = std::fs::read_dir(&control) else {
        return Vec::new();
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let path = control.join(&name);
        let shown = untrusted::clean(&name, 100);
        let e = match read_endpoint(&path, &name) {
            Ok(Some(e)) => e,
            Ok(None) => continue,
            Err(why) => {
                seen.ignored.push(Ignored { file: shown, why });
                continue;
            }
        };
        if e.protocol != cfx_bridge::PROTOCOL {
            seen.idle.push(Idle {
                pid: e.pid,
                app_version: untrusted::clean(&e.app_version, 40),
                why: format!(
                    "it speaks bridge protocol {} and this crossfyre speaks {}; update \
                     whichever is older",
                    e.protocol,
                    cfx_bridge::PROTOCOL
                ),
            });
            continue;
        }
        let Some((socket, _)) = e.connectable() else {
            seen.idle.push(Idle {
                pid: e.pid,
                app_version: untrusted::clean(&e.app_version, 40),
                why: match &e.why {
                    Some(w) => format!("its bridge did not start: {}", untrusted::clean(w, 200)),
                    None => "Agent access is off; turn it on with the Agents chip in the \
                             Workbench's status bar"
                        .into(),
                },
            });
            continue;
        };
        if let Err(why) = socket_allowed(Path::new(socket), &control) {
            seen.ignored.push(Ignored { file: shown, why });
            continue;
        }
        out.push((shown, e));
    }
    out
}

/// Read one endpoint file, or `None` when its process is gone.
fn read_endpoint(path: &Path, name: &str) -> Result<Option<Endpoint>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("not a regular file".into());
    }
    private_to_me(&meta, false)?;
    if meta.len() > cfx_bridge::MAX_ENDPOINT_FILE as u64 {
        return Err(format!(
            "larger than {} bytes",
            cfx_bridge::MAX_ENDPOINT_FILE
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let e = Endpoint::parse(&bytes)?;
    if e.app != cfx_bridge::ENDPOINT_APP {
        return Err("not a Workbench endpoint file".into());
    }
    if name.strip_suffix(".json") != Some(e.pid.to_string().as_str()) {
        return Err("the file name is not the pid it holds".into());
    }
    if !alive(e.pid) {
        return Ok(None);
    }
    Ok(Some(e))
}

/// The socket has to be in the control directory or the runtime directory a Workbench
/// uses, and that directory has to be this user's alone.
fn socket_allowed(socket: &Path, control: &Path) -> Result<(), String> {
    // Read as written: `Path` would quietly drop a `.` and compare equal anyway.
    let raw = socket.as_os_str().to_string_lossy();
    if !socket.is_absolute()
        || raw.split('/').any(|seg| seg == "." || seg == "..")
        || socket
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("the socket path is not a plain absolute path".into());
    }
    let parent = socket.parent().ok_or("the socket path has no directory")?;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(|r| PathBuf::from(r).join(RUNTIME_SUBDIR));
    if parent != control && runtime.as_deref() != Some(parent) {
        return Err("the socket is outside the Workbench's control and runtime directories".into());
    }
    let meta = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !meta.file_type().is_dir() {
        return Err("the socket's directory is not a directory".into());
    }
    private_to_me(&meta, true).map_err(|why| format!("the socket's directory {why}"))?;
    Ok(())
}

/// Owned by this user, and nobody else can read or write it.
#[cfg(unix)]
fn private_to_me(meta: &std::fs::Metadata, dir: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != euid() {
        return Err("belongs to another user".into());
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "can be read or written by other users (mode {:o}, needs {})",
            meta.mode() & 0o777,
            if dir { "0700" } else { "0600" }
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_to_me(_: &std::fs::Metadata, _: bool) -> Result<(), String> {
    Err("the Workbench bridge is not available on this platform".into())
}

#[cfg(unix)]
pub(crate) fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Whether a process exists. A process of another user counts: the check is only there
/// to pass over what a crash left behind.
#[cfg(unix)]
fn alive(pid: u32) -> bool {
    let Ok(p) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if p <= 0 {
        return false;
    }
    // SAFETY: signal 0 sends nothing; it only asks whether the process exists.
    let r = unsafe { libc::kill(p, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(not(unix))]
fn alive(_: u32) -> bool {
    false
}

/// The connection's peer has to be this user. A Workbench drops anyone else, and a
/// client drops a server that is not its own user's, so `sudo crossfyre mcp` never
/// reaches somebody's Workbench.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn peer_allowed(peer_uid: Option<u32>, own: u32) -> bool {
    peer_uid == Some(own)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn only_this_user_is_a_peer() {
        assert!(peer_allowed(Some(1000), 1000));
        assert!(!peer_allowed(Some(0), 1000));
        assert!(!peer_allowed(Some(1001), 1000));
        assert!(!peer_allowed(None, 1000));
        // Root talking to root is still one user.
        assert!(peer_allowed(Some(0), 0));
    }

    #[test]
    fn a_socket_path_has_one_meaning() {
        let control = Path::new("/home/u/.local/share/io.crossfyre.workbench/control");
        for bad in [
            "relative/1.sock",
            "/home/u/.local/share/io.crossfyre.workbench/control/../1.sock",
            "/home/u/.local/share/io.crossfyre.workbench/control/./1.sock",
            "/tmp/1.sock",
            "/home/u/.local/share/io.crossfyre.workbench/control/sub/1.sock",
        ] {
            assert!(socket_allowed(Path::new(bad), control).is_err(), "{bad}");
        }
    }
}

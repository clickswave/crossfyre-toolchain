//! `crossfyre mcp`: the locally installed engines as tools for an MCP client, over
//! stdio, with no account.
//!
//! What it may reach is decided by a scope file a person writes and the server only
//! reads. Every destination a tool would send to is checked against that file when
//! the call arrives, its addresses are checked before anything is sent, and each
//! redirect hop that `send_http_request` follows is checked again. The engines are
//! given the addresses that were checked and told not to follow redirects; what they
//! still do on their own is listed under MCP.md's known limits. What comes back from
//! a target is returned as untrusted data, stripped and capped, and every call leaves
//! one line in an audit log next to the scope file.
//!
//! The engines are reached the way the CLI and the node reach them: their daemon
//! protocol on loopback. Nothing here links an engine.

mod audit;
mod confirm;
mod core;
mod engine;
mod findings;
mod guard;
mod jobs;
mod limits;
mod peer;
mod redact;
mod scope_file;
mod server;
mod tools;
mod untrusted;
mod workbench;

#[cfg(test)]
mod tests;

use rmcp::ServiceExt;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// One engine as the CLI knows it.
#[derive(Debug, Clone)]
pub struct EngineInfo {
    /// The public name: `toolmark`, `plessor`, ...
    pub name: String,
    /// The daemon's port on 127.0.0.1, from `config.toml`.
    pub port: u16,
    pub installed: bool,
}

/// Whether the Workbench tools are offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkbenchMode {
    /// Listed while at least one Workbench with Agent access on answers. The client is
    /// told when that changes.
    #[default]
    Auto,
    /// Always listed, for a client that ignores a changed tool list. With no Workbench
    /// answering, a call is refused with `workbench_unavailable`.
    Always,
    /// Never listed, and no Workbench is looked for.
    Off,
}

impl WorkbenchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkbenchMode::Auto => "auto",
            WorkbenchMode::Always => "always",
            WorkbenchMode::Off => "off",
        }
    }
}

/// Everything `serve` needs from the CLI.
#[derive(Debug, Clone)]
pub struct Options {
    /// `--scope-file`. `None` means `<default_dir>/scope.toml`.
    pub scope_file: Option<PathBuf>,
    /// `<data-dir>/mcp`.
    pub default_dir: PathBuf,
    pub engines: Vec<EngineInfo>,
    /// Only to report whether the database is up; nothing here uses it.
    pub postgres_port: Option<u16>,
    pub version: String,
    /// False with `--no-redact`.
    pub redact: bool,
    /// A running Workbench's data directory, where it says how to reach it. Never taken
    /// from a tool argument.
    pub workbench_dir: Option<PathBuf>,
    pub workbench: WorkbenchMode,
}

/// A reason the server did not start. Its text is printed and the process exits 2.
#[derive(Debug)]
pub struct StartError(String);

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StartError {}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Where the scope file is, made absolute. The directory holding it is where the audit
/// log and the jobs live, so the record of what was done sits with the permission it
/// was done under.
fn scope_path(opts: &Options) -> Result<(PathBuf, PathBuf), StartError> {
    match &opts.scope_file {
        Some(p) => {
            let name = p.file_name().ok_or_else(|| {
                StartError(format!("--scope-file {} does not name a file", p.display()))
            })?;
            let parent = match p.parent() {
                Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let dir = std::fs::canonicalize(&parent).map_err(|e| {
                StartError(format!(
                    "the directory of --scope-file, {}, is not usable: {e}",
                    parent.display()
                ))
            })?;
            Ok((dir.join(name), dir))
        }
        None => {
            create_private_dir(&opts.default_dir).map_err(|e| {
                StartError(format!(
                    "could not create {}: {e}",
                    opts.default_dir.display()
                ))
            })?;
            let dir = std::fs::canonicalize(&opts.default_dir).map_err(|e| {
                StartError(format!("{} is not usable: {e}", opts.default_dir.display()))
            })?;
            Ok((dir.join("scope.toml"), dir))
        }
    }
}

/// Build the server state: scope, audit and job store, in that order, each a reason
/// not to start if it fails.
fn build(opts: Options, resolver: Arc<dyn guard::Resolver>) -> Result<core::Mcp, StartError> {
    let (path, dir) = scope_path(&opts)?;
    let scope = scope_file::load(&path).map_err(StartError)?;
    let audit_path = dir.join("audit.jsonl");
    let audit = audit::Audit::open(&audit_path).map_err(|e| {
        StartError(format!(
            "could not open the audit log {}: {e}",
            audit_path.display()
        ))
    })?;
    let store = jobs::JobStore::open(&dir.join("jobs"))
        .map_err(|e| StartError(format!("could not open the job store: {e}")))?;
    let settings = core::Settings {
        version: opts.version,
        redact: opts.redact,
        engines: opts.engines,
        postgres_port: opts.postgres_port,
        workbench: opts.workbench,
        workbench_dir: opts.workbench_dir,
        call_burst: 10,
        calls_per_minute: 60,
    };
    let mcp = core::Mcp::new(settings, dir, scope, audit, store, resolver);
    mcp.jobs.recover(&mcp.session, jobs::now_ms());
    mcp.jobs.prune(jobs::KEEP_FINISHED);
    Ok(mcp)
}

/// SIGTERM or SIGHUP. A client that is done with the server closes its stdin and,
/// when the server has not gone after a moment, sends SIGTERM; a closed terminal
/// sends SIGHUP. Either way the running scans are stopped and the log closed, as on
/// Ctrl-C.
#[cfg(unix)]
async fn terminated() {
    use tokio::signal::unix::{SignalKind, signal};
    match (
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
    ) {
        (Ok(mut term), Ok(mut hup)) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = hup.recv() => {}
            }
        }
        _ => std::future::pending().await,
    }
}

#[cfg(not(unix))]
async fn terminated() {
    std::future::pending().await
}

/// Serve MCP on stdin and stdout until the client goes away or the process is
/// interrupted. Diagnostics go to stderr; stdout carries the protocol and nothing else.
pub async fn serve(opts: Options) -> Result<(), StartError> {
    let mcp = Arc::new(build(opts, Arc::new(guard::SystemResolver))?);
    mcp.audit_event(
        "start",
        json!({
            "entries": mcp.scope.entries.len(),
            "allow_writes": mcp.scope.allow_writes,
            "allow_private": mcp.scope.allow_private,
            "redaction": mcp.settings.redact,
        }),
    );
    eprintln!(
        "crossfyre mcp: scope {} ({} entries, sha256 {}), audit {}",
        mcp.scope.path.display(),
        mcp.scope.entries.len(),
        mcp.scope.short_sha(),
        mcp.audit.path().display()
    );

    let handler = server::Server {
        mcp: Arc::clone(&mcp),
    };
    let ct = tokio_util::sync::CancellationToken::new();
    match handler
        .serve_with_ct(rmcp::transport::stdio(), ct.clone())
        .await
    {
        Ok(running) => {
            let watcher = (mcp.settings.workbench != WorkbenchMode::Off).then(|| {
                let peer = running.peer().clone();
                if let Some(info) = peer.peer_info() {
                    mcp.workbench.set_label(&format!(
                        "{} {}",
                        info.client_info.name, info.client_info.version
                    ));
                }
                let notify = move || -> guard::BoxFut<'static, ()> {
                    let peer = peer.clone();
                    Box::pin(async move {
                        let _ = peer.notify_tool_list_changed().await;
                    })
                };
                tokio::spawn(workbench::watch(Arc::clone(&mcp), notify))
            });
            tokio::select! {
                _ = running.waiting() => {}
                _ = tokio::signal::ctrl_c() => ct.cancel(),
                _ = terminated() => ct.cancel(),
            }
            if let Some(w) = watcher {
                w.abort();
            }
        }
        Err(e) => eprintln!("crossfyre mcp: the client did not start a session: {e}"),
    }
    mcp.shutdown().await;
    mcp.audit_event("stop", json!({}));
    Ok(())
}

//! The egress helper: a separate program that applies isolated egress for this node.
//! It is installed beside the binaries, and is run only when it passes the rule
//! `packaging.json` is believed under, since the node runs it with its own rights.
//!
//! Each call is one process: `cfx-egress <action>`, a JSON request on its stdin carrying
//! the interface it is written for, and one JSON line in answer on its stdout. What it
//! has to say on the way goes to its stderr, which is the node's. An answer carries the
//! helper's version, or an `error`.
//!
//! - `config` takes a node's network config as the platform sends it and answers with
//!   the config the node keeps (`network`).
//! - `up` applies egress for that config and answers once it has (`up`), then keeps
//!   running for as long as egress is to stay up. Closing its stdin takes egress down,
//!   which happens when the [`Up`] is dropped and when the node ends, however it ends.
//!   After its answer it writes nothing more to its stdout. When egress cannot come
//!   up it answers `up: false` with `why`, and ends.
//!
//! Every error here is a whole reason, as the node says it: `helper not installed`,
//! `helper did not answer within 30 s`, `egress not up: <why>`.

use crate::NetworkConfig;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

/// The helper's file name beside the binaries.
pub const HELPER: &str = "cfx-egress";

/// The interface a request is written for.
pub const INTERFACE: u32 = 1;

/// How long each call may take.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub config: Duration,
    pub up: Duration,
    /// From closing an `up` helper's stdin to killing it.
    pub down: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            config: Duration::from_secs(30),
            up: Duration::from_secs(180),
            down: Duration::from_secs(30),
        }
    }
}

/// The longest answer read.
const ANSWER_BYTES: u64 = 1 << 20;

/// The helper beside the executable at `exe`, when it is there and passes the rule.
pub fn find(exe: &Path) -> Result<PathBuf, String> {
    let dir = exe.parent().ok_or("the executable has no folder")?;
    let path = dir.join(format!("{HELPER}{}", std::env::consts::EXE_SUFFIX));
    if !path.exists() {
        return Err("helper not installed".into());
    }
    crate::toolchain::packaging::trust(&path, exe)
        .map_err(|why| format!("helper not run: {why}"))?;
    Ok(path)
}

/// `config`: the network config the node keeps for `raw`.
pub fn config(
    helper: &Path,
    raw: &Value,
    net_dir: &Path,
    tunnel_hooks: bool,
    limits: Limits,
) -> Result<(String, Option<NetworkConfig>), String> {
    let request = json!({
        "interface": INTERFACE,
        "raw": raw,
        "net_dir": net_dir,
        "tunnel_hooks": tunnel_hooks,
    });
    let asked = || -> Result<(String, Option<NetworkConfig>), String> {
        let mut child = spawn(helper, "config")?;
        let mut stdin = child.stdin.take().ok_or("its stdin was not opened")?;
        let written = writeln!(stdin, "{request}");
        drop(stdin);
        let answer = written
            .map_err(|e| format!("could not be asked: {e}"))
            .and_then(|()| answer_within(&mut child, limits.config));
        end(&mut child, limits.down.min(Duration::from_secs(5)));
        let answer = answer?;
        let version = version_of(&answer)?;
        let network = match &answer["network"] {
            Value::Null => None,
            n => Some(
                serde_json::from_value(n.clone())
                    .map_err(|_| "answered with a config that does not read".to_string())?,
            ),
        };
        Ok((version, network))
    };
    asked().map_err(|why| format!("helper {why}"))
}

/// An `up` helper, holding egress up until it is dropped.
pub struct Up {
    child: Child,
    stdin: Option<ChildStdin>,
    down: Duration,
    /// The helper's version, as it answered.
    pub version: String,
}

impl Up {
    /// Whether the helper is still running, and with it egress.
    pub fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Up {
    fn drop(&mut self) {
        drop(self.stdin.take());
        end(&mut self.child, self.down);
    }
}

/// `up`: egress applied for `net`, held by the returned [`Up`].
pub fn up(
    helper: &Path,
    net: &NetworkConfig,
    net_dir: &Path,
    node_id: &str,
    tunnel_hooks: bool,
    limits: Limits,
) -> Result<Up, String> {
    let request = json!({
        "interface": INTERFACE,
        "net": net,
        "net_dir": net_dir,
        "node_id": node_id,
        "tunnel_hooks": tunnel_hooks,
    });
    let mut child = spawn(helper, "up").map_err(|why| format!("helper {why}"))?;
    let mut stdin = child.stdin.take().ok_or("helper's stdin was not opened")?;
    let answered = writeln!(stdin, "{request}")
        .and_then(|()| stdin.flush())
        .map_err(|e| format!("could not be asked: {e}"))
        .and_then(|()| answer_within(&mut child, limits.up))
        .map_err(|why| format!("helper {why}"))
        .and_then(|a| {
            let version = version_of(&a).map_err(|why| format!("helper {why}"))?;
            match a["up"].as_bool() {
                Some(true) => Ok(version),
                Some(false) => Err(format!(
                    "egress not up: {}",
                    a["why"]
                        .as_str()
                        .map(|w| clean(w, 200))
                        .unwrap_or_else(|| "no reason given".into())
                )),
                None => Err("helper answered without saying whether egress is up".into()),
            }
        });
    match answered {
        Ok(version) => Ok(Up {
            child,
            stdin: Some(stdin),
            down: limits.down,
            version,
        }),
        Err(why) => {
            drop(stdin);
            end(&mut child, limits.down);
            Err(why)
        }
    }
}

fn spawn(helper: &Path, action: &str) -> Result<Child, String> {
    Command::new(helper)
        .arg(action)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("could not be started: {e}"))
}

/// The helper's one answer line, read within `limit`: its JSON, or why there is none.
fn answer_within(child: &mut Child, limit: Duration) -> Result<Value, String> {
    let stdout = child.stdout.take().ok_or("its stdout was not opened")?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let read = BufReader::new(stdout.take(ANSWER_BYTES)).read_line(&mut line);
        let _ = tx.send(read.map(|_| line));
    });
    let line = match rx.recv_timeout(limit) {
        Ok(Ok(line)) => line,
        Ok(Err(e)) => return Err(format!("could not be read: {e}")),
        Err(_) => return Err(format!("did not answer within {}", span(limit))),
    };
    if line.trim().is_empty() {
        return Err(match child.wait() {
            Ok(status) => format!("ended without an answer ({status})"),
            Err(e) => format!("ended without an answer: {e}"),
        });
    }
    let answer: Value =
        serde_json::from_str(line.trim()).map_err(|_| "answered something unreadable")?;
    if let Some(e) = answer["error"].as_str() {
        return Err(format!("said: {}", clean(e, 200)));
    }
    Ok(answer)
}

/// The version an answer carries: one short printable line.
fn version_of(answer: &Value) -> Result<String, String> {
    answer["version"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| (b' '..=b'~').contains(&b)))
        .map(str::to_string)
        .ok_or_else(|| "answered without a version".into())
}

/// `d` as a person reads it: whole seconds, or milliseconds under one.
fn span(d: Duration) -> String {
    if d.as_millis() % 1000 == 0 {
        format!("{} s", d.as_secs())
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// `s` as one printable line of at most `max` bytes.
fn clean(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    out.truncate(max);
    out
}

/// Wait up to `grace` for the helper to end, then end it.
fn end(child: &mut Child, grace: Duration) {
    let until = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

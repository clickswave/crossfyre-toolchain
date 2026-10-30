//! One line per tool call, next to the scope file it was made under.
//!
//! The question this answers comes later and from somebody else: what did the agent
//! do, under which scope, and what was refused. So every call writes a line, refusals
//! and malformed calls included, and each line carries the hash of the scope file the
//! server loaded. A refusal that left no trace would make the log useless for the one
//! thing it is for.
//!
//! If a line cannot be written, traffic stops: the traffic tools refuse with
//! `audit_unavailable` from then on, while the read tools keep working. An agent
//! that can act without a record is the thing this file exists to prevent.

use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Lines longer than this lose their arguments and are flagged.
const LINE_MAX: usize = 16 * 1024;
/// Over this at start, the log moves to `audit.jsonl.1` and a new one begins.
const ROTATE_AT: u64 = 50 * 1024 * 1024;

pub(crate) struct Audit {
    path: PathBuf,
    file: Mutex<File>,
    healthy: AtomicBool,
}

impl Audit {
    pub(crate) fn open(path: &Path) -> std::io::Result<Self> {
        if std::fs::metadata(path).is_ok_and(|m| m.len() > ROTATE_AT) {
            let mut old = path.as_os_str().to_owned();
            old.push(".1");
            std::fs::rename(path, PathBuf::from(old))?;
        }
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let file = o.open(path)?;
        Ok(Self::from_file(file, path))
    }

    /// Over an already open file. The tests hand it one that cannot be written.
    pub(crate) fn from_file(file: File, path: &Path) -> Self {
        Audit {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            healthy: AtomicBool::new(true),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    /// Append one line. A failure is remembered, not returned: the caller has already
    /// decided what happened, and what changes is whether the next call may send.
    pub(crate) fn write(&self, mut line: Value) {
        let mut text = line.to_string();
        if text.len() > LINE_MAX {
            if let Some(o) = line.as_object_mut() {
                o.insert("args".into(), json!({"omitted": "over the line limit"}));
                o.insert("truncated".into(), json!(true));
                if let Some(m) = o.get("message").and_then(|m| m.as_str()) {
                    let short: String = m.chars().take(500).collect();
                    o.insert("message".into(), json!(short));
                }
            }
            text = line.to_string();
            if text.len() > LINE_MAX {
                text = json!({
                    "ts": line.get("ts"),
                    "event": line.get("event"),
                    "seq": line.get("seq"),
                    "tool": line.get("tool"),
                    "decision": line.get("decision"),
                    "reason": line.get("reason"),
                    "truncated": true,
                })
                .to_string();
            }
        }
        text.push('\n');
        // One write_all under the lock, so concurrent calls never interleave a line.
        let ok = match self.file.lock() {
            Ok(mut f) => f.write_all(text.as_bytes()).and_then(|_| f.flush()).is_ok(),
            Err(_) => false,
        };
        if !ok {
            self.healthy.store(false, Ordering::SeqCst);
        }
    }
}

pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

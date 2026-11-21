//! A scan as this server shows it, and its ids. What a scan found, said and how far it
//! got is kept by its engine, in the tables every engine has, and read back through its
//! daemon (see `kept`); this server keeps nothing of it on disk. The record here is the
//! one a scan this server is running holds in memory, and the shape a kept scan is shown
//! in.
//!
//! Ids are checked against a fixed pattern before they are used. They arrive from a model,
//! and `../` is a string like any other.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::LazyLock;

pub(crate) const RUNNING: &str = "running";
pub(crate) const COMPLETED: &str = "completed";
pub(crate) const FAILED: &str = "failed";
pub(crate) const CANCELLED: &str = "cancelled";
pub(crate) const INTERRUPTED: &str = "interrupted";

static SCAN_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^s_(plessor|toolmark|voyage|doorward|ambulo)_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    )
    .expect("scan id pattern")
});
static FINDING_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^f_(plessor|toolmark|voyage|doorward|ambulo)_[0-9]{1,18}$")
        .expect("finding id pattern")
});
static SCAN_CURSOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([0-9]{1,16})-(s_(plessor|toolmark|voyage|doorward|ambulo)_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12})$",
    )
    .expect("cursor pattern")
});

pub(crate) fn is_terminal(status: &str) -> bool {
    status != RUNNING
}

pub(crate) fn valid_scan_id(id: &str) -> bool {
    SCAN_ID.is_match(id)
}

pub(crate) fn valid_finding_id(id: &str) -> bool {
    FINDING_ID.is_match(id)
}

pub(crate) fn new_id(prefix: &str) -> String {
    let hex = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}_{}", &hex[..10])
}

pub(crate) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub(crate) fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Owner {
    pub session: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Progress {
    pub done: u64,
    pub total: u64,
    pub phase: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Counts {
    pub findings: u64,
    pub by_severity: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JobMeta {
    pub id: String,
    pub tool: String,
    pub engine: String,
    pub target: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub status: String,
    /// `stopped` when the engine confirmed it stopped, `requested` when it could not.
    #[serde(default)]
    pub cancel: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub owner: Owner,
    #[serde(default)]
    pub progress: Progress,
    #[serde(default)]
    pub counts: Counts,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub scope_sha256: Option<String>,
    #[serde(default)]
    pub cancellable: bool,
    #[serde(default)]
    pub test_writes: bool,
    /// Where the scan's request came from, when it was not typed by the client:
    /// `{"workbench": {"pid", "project_uid", "exchange"}}`. Absent in files written
    /// before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
}

/// The tools whose scans count toward `max_scan_starts_per_hour`.
pub(crate) const SCAN_TOOLS: [&str; 3] = [
    "test_injection",
    "workbench_test_injection",
    "scan_templates",
];

pub(crate) struct NewJob<'a> {
    /// The id the engine kept the scan as, here (see `kept::scan_id`).
    pub id: String,
    pub tool: &'a str,
    pub engine: &'a str,
    pub target: &'a str,
    pub endpoints: Vec<String>,
    pub scope_sha256: Option<String>,
    pub cancellable: bool,
    pub test_writes: bool,
}

impl JobMeta {
    pub(crate) fn new(session: &str, n: NewJob<'_>) -> Self {
        let now = now_ms();
        JobMeta {
            id: n.id,
            tool: n.tool.into(),
            engine: n.engine.into(),
            target: n.target.into(),
            endpoints: n.endpoints,
            status: RUNNING.into(),
            cancel: None,
            created_at: rfc3339(now),
            updated_at: rfc3339(now),
            finished_at: None,
            created_ms: now,
            updated_ms: now,
            owner: Owner {
                session: session.into(),
                pid: std::process::id(),
            },
            progress: Progress::default(),
            counts: Counts::default(),
            error: None,
            notes: Vec::new(),
            scope_sha256: n.scope_sha256,
            cancellable: n.cancellable,
            test_writes: n.test_writes,
            source: None,
        }
    }

    pub(crate) fn touch(&mut self) {
        let now = now_ms();
        self.updated_ms = now;
        self.updated_at = rfc3339(now);
    }

    pub(crate) fn finish(&mut self, status: &str) {
        self.status = status.into();
        self.touch();
        self.finished_at = Some(self.updated_at.clone());
    }

    pub(crate) fn note(&mut self, n: String) {
        self.notes.push(n);
        let excess = self
            .notes
            .len()
            .saturating_sub(crate::untrusted::NOTES_KEPT);
        if excess > 0 {
            self.notes.drain(..excess);
        }
    }

    pub(crate) fn count(&mut self, severity: &str) {
        self.counts.findings += 1;
        *self
            .counts
            .by_severity
            .entry(severity.to_string())
            .or_insert(0) += 1;
    }
}

/// Newest first for scans, so a page boundary is (created, id) and the next page is
/// everything strictly older.
pub(crate) fn scan_cursor(m: &JobMeta) -> String {
    format!("{}-{}", m.created_ms, m.id)
}

pub(crate) fn parse_scan_cursor(c: &str) -> Option<(i64, String)> {
    let m = SCAN_CURSOR.captures(c)?;
    Some((m[1].parse().ok()?, m[2].to_string()))
}

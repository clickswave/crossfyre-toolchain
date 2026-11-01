//! Scans the server started, on disk, so a handle outlives the call that made it.
//!
//! Each job is a metadata file written whole (temp file, then rename) and a findings
//! file appended one line per finding. Several server processes using the same scope
//! file share the directory, and each job is written only by the process that owns
//! it, so there is nothing to lock across processes.
//!
//! Ids are checked against a fixed pattern before they are used to build a path.
//! They arrive from a model, and `../` is a string like any other.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub(crate) const RUNNING: &str = "running";
pub(crate) const COMPLETED: &str = "completed";
pub(crate) const FAILED: &str = "failed";
pub(crate) const CANCELLED: &str = "cancelled";
pub(crate) const INTERRUPTED: &str = "interrupted";

/// A running job whose owner has not written for this long is taken to be gone. The
/// owner rewrites it every 30 s, so this is four missed beats.
pub(crate) const STALE_MS: i64 = 120_000;
/// Finished jobs kept; older ones are removed at start.
pub(crate) const KEEP_FINISHED: usize = 200;
/// Findings stored per job.
pub(crate) const FINDINGS_PER_JOB: u64 = 2000;

static SCAN_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^s_[0-9a-f]{10}$").expect("scan id pattern"));
static FINDING_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^f_[0-9a-f]{10}$").expect("finding id pattern"));
static FINDING_CURSOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([0-9]{1,16})-(s_[0-9a-f]{10})-([0-9]{1,9})$").expect("cursor pattern")
});
static SCAN_CURSOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9]{1,16})-(s_[0-9a-f]{10})$").expect("cursor pattern"));

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
pub(crate) const INJECTION_TOOLS: [&str; 2] = ["test_injection", "workbench_test_injection"];

pub(crate) struct NewJob<'a> {
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
            id: new_id("s"),
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

/// Where a finding sits in the shared feed: when it was recorded, then the scan and
/// its place in it, so equal timestamps still order the same way every time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FindingKey {
    pub recorded_ms: i64,
    pub scan_id: String,
    pub seq: u64,
}

impl FindingKey {
    pub(crate) fn start() -> Self {
        FindingKey {
            recorded_ms: 0,
            scan_id: "s_0000000000".into(),
            seq: 0,
        }
    }

    pub(crate) fn of(f: &Value) -> Option<Self> {
        Some(FindingKey {
            recorded_ms: f.get("recorded_ms")?.as_i64()?,
            scan_id: f.get("scan_id")?.as_str()?.to_string(),
            seq: f.get("seq")?.as_u64()?,
        })
    }

    pub(crate) fn cursor(&self) -> String {
        format!("{}-{}-{}", self.recorded_ms, self.scan_id, self.seq)
    }

    pub(crate) fn parse(c: &str) -> Option<Self> {
        let m = FINDING_CURSOR.captures(c)?;
        Some(FindingKey {
            recorded_ms: m[1].parse().ok()?,
            scan_id: m[2].to_string(),
            seq: m[3].parse().ok()?,
        })
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

pub(crate) struct JobStore {
    dir: PathBuf,
}

impl JobStore {
    pub(crate) fn open(dir: &Path) -> std::io::Result<Self> {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(dir)?;
        Ok(JobStore {
            dir: dir.to_path_buf(),
        })
    }

    fn meta_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn findings_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.findings.ndjson"))
    }

    /// Written to a temp file and renamed over the old one, so a reader never sees half.
    pub(crate) fn write_meta(&self, m: &JobMeta) -> std::io::Result<()> {
        if !valid_scan_id(&m.id) {
            return Err(std::io::Error::other("bad job id"));
        }
        let tmp = self.dir.join(format!(
            "{}.json.tmp-{}-{}",
            m.id,
            std::process::id(),
            new_id("t")
        ));
        let body = serde_json::to_vec_pretty(m).map_err(std::io::Error::other)?;
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, self.meta_path(&m.id)).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    }

    pub(crate) fn read_meta(&self, id: &str) -> Option<JobMeta> {
        if !valid_scan_id(id) {
            return None;
        }
        let b = std::fs::read(self.meta_path(id)).ok()?;
        serde_json::from_slice(&b).ok()
    }

    pub(crate) fn list(&self) -> Vec<JobMeta> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        rd.filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let id = name.strip_suffix(".json")?;
                self.read_meta(id)
            })
            .collect()
    }

    pub(crate) fn append_findings(&self, id: &str, findings: &[Value]) -> std::io::Result<()> {
        if !valid_scan_id(id) {
            return Err(std::io::Error::other("bad job id"));
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.findings_path(id))?;
        let mut buf = Vec::new();
        for v in findings {
            buf.extend_from_slice(v.to_string().as_bytes());
            buf.push(b'\n');
        }
        f.write_all(&buf)
    }

    /// Every finding of one scan, read line by line.
    pub(crate) fn read_findings(&self, id: &str) -> Vec<Value> {
        if !valid_scan_id(id) {
            return Vec::new();
        }
        let Ok(f) = std::fs::File::open(self.findings_path(id)) else {
            return Vec::new();
        };
        BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .filter_map(|l| serde_json::from_str(&l).ok())
            .collect()
    }

    pub(crate) fn find_finding(&self, finding_id: &str) -> Option<Value> {
        if !valid_finding_id(finding_id) {
            return None;
        }
        let mut jobs = self.list();
        jobs.sort_by(|a, b| b.created_ms.cmp(&a.created_ms));
        for j in jobs {
            let Ok(f) = std::fs::File::open(self.findings_path(&j.id)) else {
                continue;
            };
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                // Cheap test first: most lines are not the one.
                if !line.contains(finding_id) {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(&line)
                    && v.get("id").and_then(|i| i.as_str()) == Some(finding_id)
                {
                    return Some(v);
                }
            }
        }
        None
    }

    /// Mark running jobs whose owner has gone quiet as interrupted. Run at start, when
    /// every running job belongs to some earlier process. Works the same on every
    /// system because it reads only the heartbeat, never the process table.
    pub(crate) fn recover(&self, session: &str, now: i64) -> usize {
        let mut n = 0;
        for mut m in self.list() {
            if m.status == RUNNING && m.owner.session != session && now - m.updated_ms > STALE_MS {
                m.finish(INTERRUPTED);
                m.note("the server that owned this scan stopped before it finished".into());
                if self.write_meta(&m).is_ok() {
                    n += 1;
                }
            }
        }
        n
    }

    /// Keep the newest `keep` finished jobs.
    pub(crate) fn prune(&self, keep: usize) {
        let mut done: Vec<JobMeta> = self
            .list()
            .into_iter()
            .filter(|m| is_terminal(&m.status))
            .collect();
        done.sort_by(|a, b| b.created_ms.cmp(&a.created_ms));
        for m in done.into_iter().skip(keep) {
            let _ = std::fs::remove_file(self.findings_path(&m.id));
            let _ = std::fs::remove_file(self.meta_path(&m.id));
        }
    }

    /// Running jobs with a heartbeat recent enough to be alive, from any process.
    pub(crate) fn running_fresh(&self, now: i64) -> usize {
        self.list()
            .iter()
            .filter(|m| m.status == RUNNING && now - m.updated_ms <= STALE_MS)
            .count()
    }

    pub(crate) fn starts_since(&self, tools: &[&str], since: i64) -> usize {
        self.list()
            .iter()
            .filter(|m| tools.contains(&m.tool.as_str()) && m.created_ms >= since)
            .count()
    }
}

//! What the engines kept, read back through their daemons: the scans and what they found,
//! wherever they were started from (this server, another one, the command line or the
//! Workbench). The server keeps no file of its own about them.
//!
//! Only what is inside the loaded scope file is ever shown. A session works under one
//! engagement's scope, and a scan of a target outside it is another engagement's: it is
//! not listed, and an id of one is answered as if there were none.

use crate::core::Mcp;
use crate::jobs::{self, Counts, JobMeta, Owner, Progress};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The engines whose daemons keep scans, as MCP reads them.
pub(crate) const ENGINES: [&str; 5] = ["plessor", "toolmark", "voyage", "doorward", "ambulo"];

/// What `engine`'s daemon answers `op` with, or None when it is not running or does not
/// answer it.
async fn ask(mcp: &Mcp, engine: &str, op: Value) -> Option<Value> {
    let port = mcp
        .settings
        .engines
        .iter()
        .find(|e| e.name == engine && e.installed)?
        .port;
    let conn = crate::engine::connect(port).await.ok()?;
    let answer = conn.read(&op).await.ok()?;
    (answer["status"] == "completed").then_some(answer)
}

/// Whether `target`, a scan's as its engine kept it, is inside the loaded scope file: each
/// of the hosts it names is admitted by an entry.
pub(crate) fn in_scope(mcp: &Mcp, target: &str) -> bool {
    let hosts: Vec<(String, Option<u16>)> = target
        .split([',', ' '])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|t| {
            if t.contains("://") {
                crate::guard::parse_target(t)
                    .ok()
                    .map(|d| (d.host, Some(d.port)))
            } else {
                match t.rsplit_once(':') {
                    Some((h, p)) if p.parse::<u16>().is_ok() && !h.contains(':') => {
                        Some((h.to_ascii_lowercase(), p.parse().ok()))
                    }
                    _ => Some((t.trim_matches(['[', ']']).to_ascii_lowercase(), None)),
                }
            }
        })
        .collect();
    !hosts.is_empty()
        && hosts.iter().all(|(host, port)| {
            mcp.scope
                .per_entry
                .iter()
                .any(|(_, s)| s.admits(host, *port))
        })
}

/// A scan's id here, from its engine and the engine's own id.
pub(crate) fn scan_id(engine: &str, id: &str) -> String {
    format!("s_{engine}_{id}")
}

/// A finding's id here, from its engine and the engine's own id.
pub(crate) fn finding_id(engine: &str, id: i64) -> String {
    format!("f_{engine}_{id}")
}

/// The engine and the engine's own id an id here names, when it is one.
pub(crate) fn parse_scan_id(id: &str) -> Option<(&'static str, &str)> {
    if !jobs::valid_scan_id(id) {
        return None;
    }
    let rest = id.strip_prefix("s_")?;
    let (engine, own) = rest.split_once('_')?;
    Some((ENGINES.iter().find(|e| **e == engine)?, own))
}

fn parse_finding_id(id: &str) -> Option<(&'static str, i64)> {
    if !jobs::valid_finding_id(id) {
        return None;
    }
    let rest = id.strip_prefix("f_")?;
    let (engine, own) = rest.split_once('_')?;
    Some((ENGINES.iter().find(|e| **e == engine)?, own.parse().ok()?))
}

fn millis(at: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(at)
        .map(|d| d.timestamp_millis())
        .unwrap_or(0)
}

/// The words a scan's state is said in here. A scan its engine stopped is cancelled when
/// this server stopped it, and interrupted otherwise: its daemon went away, or a client
/// gone with its connection took it with it.
fn status(mcp: &Mcp, id: &str, engine_status: &str) -> String {
    match engine_status {
        "queued" | "running" => jobs::RUNNING,
        "completed" => jobs::COMPLETED,
        "failed" => jobs::FAILED,
        _ if mcp.was_cancelled(id) => jobs::CANCELLED,
        _ => jobs::INTERRUPTED,
    }
    .to_string()
}

/// A scan as its engine keeps it, in the shape this server shows one: what this server
/// said of it when it started it is under the `mcp` of its settings.
fn meta_of(mcp: &Mcp, engine: &str, row: &Value) -> JobMeta {
    let own = row["id"].as_str().unwrap_or_default();
    let id = scan_id(engine, own);
    let settings = &row["settings"];
    let said = &settings["mcp"];
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let created_at = text(&row["created_at"]);
    let updated_at = text(&row["updated_at"]);
    let status = status(mcp, &id, row["status"].as_str().unwrap_or_default());
    let by_severity: BTreeMap<String, u64> = row["by_severity"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();
    let progress = &row["progress"];
    JobMeta {
        tool: said["tool"].as_str().map_or_else(
            || {
                format!(
                    "{engine} {}",
                    settings["operation"].as_str().unwrap_or("scan")
                )
            },
            str::to_string,
        ),
        engine: engine.to_string(),
        target: text(&row["target"]),
        endpoints: said["endpoints"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        finished_at: jobs::is_terminal(&status).then(|| updated_at.clone()),
        status,
        cancel: None,
        created_ms: millis(&created_at),
        updated_ms: millis(&updated_at),
        created_at,
        updated_at,
        owner: Owner {
            session: text(&said["process"]),
            pid: said["pid"].as_u64().unwrap_or(0) as u32,
        },
        progress: Progress {
            done: progress["processed"].as_u64().unwrap_or(0),
            total: progress["total"].as_u64().unwrap_or(0),
            phase: text(&progress["phase"]),
        },
        counts: Counts {
            findings: row["findings"].as_u64().unwrap_or(0),
            by_severity,
        },
        error: None,
        notes: Vec::new(),
        scope_sha256: said["scope_sha256"].as_str().map(str::to_string),
        cancellable: said["cancellable"].as_bool().unwrap_or(false),
        test_writes: said["test_writes"].as_bool().unwrap_or(false),
        source: said.get("source").filter(|s| !s.is_null()).cloned(),
        id,
    }
}

/// Every scan the engines keep whose target is in scope, newest first.
pub(crate) async fn scans(mcp: &Mcp) -> Vec<JobMeta> {
    let mut all = Vec::new();
    for engine in ENGINES {
        let Some(answer) = ask(
            mcp,
            engine,
            json!({"operation": "scans", "response": "instant"}),
        )
        .await
        else {
            continue;
        };
        for row in answer["scans"].as_array().into_iter().flatten() {
            if in_scope(mcp, row["target"].as_str().unwrap_or_default()) {
                all.push(meta_of(mcp, engine, row));
            }
        }
    }
    all.sort_by(|x, y| (y.created_ms, &y.id).cmp(&(x.created_ms, &x.id)));
    all
}

/// Scan `id` as its engine keeps it, with what it said, or None when there is none in
/// scope by that id.
pub(crate) async fn scan(mcp: &Mcp, id: &str) -> Option<JobMeta> {
    let (engine, own) = parse_scan_id(id)?;
    let answer = ask(
        mcp,
        engine,
        json!({"operation": "scan_info", "response": "instant", "id": own}),
    )
    .await?;
    let row = &answer["scan"];
    if !in_scope(mcp, row["target"].as_str().unwrap_or_default()) {
        return None;
    }
    let mut meta = meta_of(mcp, engine, row);
    if let Some(said) = mcp.cancelled(&meta.id) {
        meta.cancel = said.how.map(str::to_string);
        if let Some(why) = said.why {
            meta.note(why);
        }
    }
    for note in row["notes"].as_array().into_iter().flatten() {
        let message = note["message"].as_str().unwrap_or_default().to_string();
        if note["level"] == "error" {
            meta.error = Some(message);
        } else {
            meta.note(message);
        }
    }
    Some(meta)
}

/// A finding as its engine kept it, in the shape this server shows one, marked as what
/// the target said, or None for a kind that is no finding here.
fn shown(engine: &str, row: &Value) -> Option<Value> {
    let own = row["id"].as_i64()?;
    let scan = scan_id(engine, row["scan"].as_str()?);
    let id = finding_id(engine, own);
    let stamp = crate::findings::Stamp {
        id,
        scan_id: &scan,
        seq: own as u64,
        recorded_ms: millis(row["found"].as_str().unwrap_or_default()),
    };
    let data = &row["data"];
    match engine {
        "plessor" => Some(crate::findings::from_plessor(data, stamp)),
        "toolmark" => crate::findings::from_toolmark(data, stamp),
        _ => Some(crate::findings::from_result(engine, data, stamp)),
    }
}

/// `f`, a finding of scan `of`, masked when `of` tested a request captured somewhere
/// else: it was the captured URL and session that were tested, which the model never saw
/// unmasked, whatever `--no-redact` says about results.
fn captured(of: &JobMeta, mut f: Value) -> Value {
    if of.source.is_some() {
        crate::findings::redact_finding(&mut f);
    }
    f
}

/// Where a list of findings stands in each engine's: the last finding read of each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FindingsCursor(pub BTreeMap<&'static str, i64>);

impl FindingsCursor {
    pub(crate) fn text(&self) -> String {
        let mut s = String::from("k");
        for (engine, id) in &self.0 {
            s.push_str(&format!("_{engine}-{id}"));
        }
        s
    }

    pub(crate) fn parse(c: &str) -> Option<Self> {
        let rest = c.strip_prefix('k')?;
        if rest.len() > 200 {
            return None;
        }
        let mut at = BTreeMap::new();
        for part in rest.split('_').skip(1) {
            let (engine, id) = part.split_once('-')?;
            let engine = ENGINES.iter().find(|e| **e == engine)?;
            at.insert(*engine, id.parse::<i64>().ok().filter(|n| *n >= 0)?);
        }
        Some(Self(at))
    }
}

/// The findings of scan `scan`, or of every scan in scope, oldest first, after `after`, at
/// most `limit`, each as this server shows it, with where the list stands after them and
/// whether there are more.
pub(crate) async fn findings(
    mcp: &Mcp,
    scan: Option<&str>,
    after: &FindingsCursor,
    limit: usize,
) -> (Vec<Value>, FindingsCursor, bool) {
    let engines: Vec<(&'static str, Option<&str>)> = match scan.and_then(parse_scan_id) {
        Some((engine, own)) => vec![(engine, Some(own))],
        None if scan.is_some() => Vec::new(),
        None => ENGINES.iter().map(|e| (*e, None)).collect(),
    };
    // The scans in scope, so a finding of one out of it is never shown, and those of a
    // request captured somewhere else, whose findings stay masked (see [`captured`]).
    let in_scope: Vec<JobMeta> = scans(mcp).await;
    let mut found: Vec<(i64, &'static str, i64, Value)> = Vec::new();
    let mut more = false;
    for (engine, own) in engines {
        let mut from = after.0.get(engine).copied().unwrap_or(0);
        // How many to ask for at once: fewer when an answer was too long to read, as one
        // of findings this large can be.
        let mut batch = limit + 1;
        // Read on past findings out of scope until enough are in.
        loop {
            let mut op = json!({"operation": "findings", "response": "instant",
                                "after": from, "limit": batch});
            if let Some(own) = own {
                op["scan"] = json!(own);
            }
            let Some(answer) = ask(mcp, engine, op).await else {
                if batch > 1 {
                    batch /= 2;
                    continue;
                }
                break;
            };
            let rows = answer["findings"].as_array().cloned().unwrap_or_default();
            let got = rows.len();
            for row in rows {
                let Some(id) = row["id"].as_i64() else {
                    continue;
                };
                from = id;
                let scan = scan_id(engine, row["scan"].as_str().unwrap_or_default());
                let Some(of) = in_scope.iter().find(|m| m.id == scan) else {
                    continue;
                };
                if let Some(f) = shown(engine, &row).map(|f| captured(of, f)) {
                    let ms = f["recorded_ms"].as_i64().unwrap_or(0);
                    found.push((ms, engine, id, f));
                }
            }
            if got < batch || found.len() > limit {
                break;
            }
        }
    }
    found.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
    if found.len() > limit {
        more = true;
        found.truncate(limit);
    }
    let mut next = after.clone();
    for (_, engine, id, _) in &found {
        next.0.insert(engine, *id);
    }
    (found.into_iter().map(|(.., f)| f).collect(), next, more)
}

/// Finding `id`, as this server shows it, or None when there is none in scope by that id.
pub(crate) async fn finding(mcp: &Mcp, id: &str) -> Option<Value> {
    let (engine, own) = parse_finding_id(id)?;
    let answer = ask(
        mcp,
        engine,
        json!({"operation": "finding", "response": "instant", "id": own}),
    )
    .await?;
    let row = &answer["finding"];
    let of = scan(
        mcp,
        &scan_id(engine, row["scan"].as_str().unwrap_or_default()),
    )
    .await?;
    shown(engine, row).map(|f| captured(&of, f))
}

/// How many scans this scope file's servers started that are running now.
pub(crate) async fn running(mcp: &Mcp) -> usize {
    scans(mcp)
        .await
        .iter()
        .filter(|m| m.status == jobs::RUNNING && m.scope_sha256 == mcp.scope.sha256)
        .count()
}

/// How many scans of `tools` this scope file's servers started since `since_ms`.
pub(crate) async fn starts_since(mcp: &Mcp, tools: &[&str], since_ms: i64) -> usize {
    scans(mcp)
        .await
        .iter()
        .filter(|m| {
            tools.contains(&m.tool.as_str())
                && m.created_ms >= since_ms
                && m.scope_sha256 == mcp.scope.sha256
        })
        .count()
}

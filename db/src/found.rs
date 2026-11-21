//! What each engine's scans found, said and how far they got, kept in the tables every
//! engine has, and read back the same way from each: by the `scan_info` and `findings`
//! operations of its daemon, which the MCP server and the dashboards ask. Nothing reads
//! another engine's tables, and nothing outside an engine opens them.
//!
//! A daemon keeps a scan's events through a [`Keeper`] as it relays them: a finding (an
//! engine's `finding`, or its `result` or `takeover`) as a row of `findings`, a log line
//! as one of `logs`, the error that ended it as one too, and progress on the scan's row, at
//! most about once a second.

use crate::scans::{safe_stream, safe_text};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::time::{Duration, Instant};

/// How often a scan's progress is written at most.
const PROGRESS_EVERY: Duration = Duration::from_secs(1);

/// The most findings one `findings` request is answered with.
pub const FINDINGS_AT_MOST: i64 = 500;

/// Keeps what one scan's events say, as its daemon relays them.
pub struct Keeper {
    pool: PgPool,
    scan: Option<String>,
    /// When progress was last written, and the progress said since and not written.
    written: Option<Instant>,
    pending: Option<Value>,
}

impl Keeper {
    /// For scan `scan` on `pool`, or for nothing when the scan could not be kept.
    pub fn new(pool: &PgPool, scan: Option<&str>) -> Self {
        Self {
            pool: pool.clone(),
            scan: scan.map(str::to_string),
            written: None,
            pending: None,
        }
    }

    /// Keep what `event` says. A failure is only said: a scan goes on whether or not what
    /// it found could be kept.
    pub async fn event(&mut self, event: &Value) {
        let Some(scan) = self.scan.clone() else {
            return;
        };
        let kept = match event["type"].as_str().unwrap_or_default() {
            "finding" => self.found(&scan, &event["data"]).await,
            "result" | "takeover" => {
                let mut data = event.clone();
                if let Some(o) = data.as_object_mut() {
                    o.remove("operation_id");
                }
                self.found(&scan, &data).await
            }
            "log" => match event["message"].as_str() {
                Some(message) => {
                    let level = event["level"]
                        .as_str()
                        .or(event["log_level"].as_str())
                        .unwrap_or("info");
                    crate::scans::log(&self.pool, Some(&scan), level, message).await
                }
                None => Ok(()),
            },
            "progress" => {
                let mut progress = event.clone();
                if let Some(o) = progress.as_object_mut() {
                    o.remove("type");
                    o.remove("operation_id");
                }
                self.pending = Some(progress);
                if self.written.is_none_or(|at| at.elapsed() >= PROGRESS_EVERY) {
                    self.flush().await
                } else {
                    Ok(())
                }
            }
            "done" => self.flush().await,
            // What ended it is said with its notes.
            "error" => {
                let said = match event["message"].as_str() {
                    Some(message) => {
                        crate::scans::log(&self.pool, Some(&scan), "error", message).await
                    }
                    None => Ok(()),
                };
                said.and(self.flush().await)
            }
            _ => Ok(()),
        };
        if let Err(e) = kept {
            eprintln!("[db] could not keep what scan {scan} said: {e}");
        }
    }

    /// Write the progress said and not yet written, as a scan's end does.
    pub async fn flush(&mut self) -> Result<(), sqlx::Error> {
        let (Some(scan), Some(progress)) = (self.scan.as_deref(), self.pending.take()) else {
            return Ok(());
        };
        self.written = Some(Instant::now());
        sqlx::query("UPDATE scans SET progress = $2::jsonb, updated_at = now() WHERE id = $1")
            .bind(scan)
            .bind(progress.to_string())
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Keep `data`, a finding of scan `scan`, with no credential in it, once: made safe as
    /// a line an engine sends is (see [`safe_stream`]), so a header said in its text keeps
    /// its name and not its value.
    async fn found(&self, scan: &str, data: &Value) -> Result<(), sqlx::Error> {
        let kept = safe_stream(data);
        let kind = kept["type"].as_str().unwrap_or_default().to_string();
        let check = kept["template"]
            .as_str()
            .or(kept["template_id"].as_str())
            .map(str::to_string);
        sqlx::query(
            "INSERT INTO findings (scan_id, kind, check_id, data, digest) \
             VALUES ($1, $2, $3, $4::jsonb, md5(($4::jsonb - 'proof')::text)) \
             ON CONFLICT (scan_id, digest) DO NOTHING",
        )
        .bind(scan)
        .bind(kind)
        .bind(check)
        .bind(kept.to_string())
        .execute(&self.pool)
        .await
        .map(|_| ())
    }
}

/// A kept finding: its id, scan, kind, check and what was kept of it.
pub async fn finding(pool: &PgPool, id: i64) -> Result<Option<Value>, sqlx::Error> {
    let row: Option<FindingRow> = sqlx::query_as(&format!("{FINDING_COLUMNS} WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(finding_json))
}

const FINDING_COLUMNS: &str = "SELECT id, scan_id, kind, coalesce(check_id, ''), data, \
     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM findings";

type FindingRow = (i64, String, String, String, Value, String);

fn finding_json((id, scan, kind, check, data, found): FindingRow) -> Value {
    json!({"id": id, "scan": scan, "kind": kind, "check": check, "data": data, "found": found})
}

/// What a daemon answers a `findings` request with: what its scans found, oldest first,
/// of scan `scan` when one is named, after finding `after` when one is, at most `limit`
/// of them and never more than [`FINDINGS_AT_MOST`].
pub async fn answer_findings(
    pool: &PgPool,
    scan: Option<&str>,
    after: Option<i64>,
    limit: i64,
) -> Value {
    let rows: Result<Vec<FindingRow>, _> = sqlx::query_as(&format!(
        "{FINDING_COLUMNS} WHERE ($1::text IS NULL OR scan_id = $1) AND id > $2 \
         ORDER BY id LIMIT $3"
    ))
    .bind(scan)
    .bind(after.unwrap_or(0))
    .bind(limit.clamp(1, FINDINGS_AT_MOST))
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => json!({
            "status": "completed",
            "findings": rows.into_iter().map(finding_json).collect::<Vec<_>>(),
        }),
        Err(e) => json!({
            "status": "error",
            "message": format!("could not read the findings: {e}"),
        }),
    }
}

/// What a daemon answers a `scan_info` request with: scan `id` as it was kept, with how far it
/// got, what it said, and how many findings it kept, by severity. An id nothing was kept
/// under is said to be none.
pub async fn answer_scan(pool: &PgPool, id: &str) -> Value {
    match scan(pool, id).await {
        Ok(Some(scan)) => json!({"status": "completed", "scan": scan}),
        Ok(None) => json!({"status": "error", "message": format!("no scan {id} is kept here")}),
        Err(e) => json!({"status": "error", "message": format!("could not read scan {id}: {e}")}),
    }
}

/// The most of a scan's log lines a `scan_info` answer holds, the latest.
const NOTES_AT_MOST: i64 = 50;

async fn scan(pool: &PgPool, id: &str) -> Result<Option<Value>, sqlx::Error> {
    let row: Option<(String, String, String, String, String, Value, Value)> = sqlx::query_as(
        "SELECT id, target, status, \
         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
         to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
         params, progress FROM scans WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some((id, target, status, created_at, updated_at, settings, progress)) = row else {
        return Ok(None);
    };
    let mut notes: Vec<(String, String)> = sqlx::query_as(
        "SELECT level, message FROM logs WHERE scan_id = $1 ORDER BY id DESC LIMIT $2",
    )
    .bind(&id)
    .bind(NOTES_AT_MOST)
    .fetch_all(pool)
    .await?;
    notes.reverse();
    let counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT coalesce(data->>'severity', ''), count(*) FROM findings WHERE scan_id = $1 \
         GROUP BY 1 ORDER BY 1",
    )
    .bind(&id)
    .fetch_all(pool)
    .await?;
    let total: i64 = counts.iter().map(|(_, n)| n).sum();
    let by_severity: serde_json::Map<String, Value> = counts
        .into_iter()
        .filter(|(sev, _)| !sev.is_empty())
        .map(|(sev, n)| (sev, json!(n)))
        .collect();
    Ok(Some(json!({
        "id": id,
        "target": target,
        "status": status,
        "created_at": created_at,
        "updated_at": updated_at,
        "settings": settings,
        "progress": progress,
        "notes": notes
            .into_iter()
            .map(|(level, message)| json!({"level": level, "message": safe_text(&message)}))
            .collect::<Vec<_>>(),
        "findings": total,
        "by_severity": by_severity,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scans::{Asked, Key, Status};

    /// An engine of the tests' own, with only the tables every engine has.
    const ENGINE: crate::Engine = crate::Engine {
        name: "found_test",
        version: "0.0.1",
        migrations: &[],
    };

    async fn started(pool: &PgPool) -> crate::scans::Running {
        crate::scans::start(
            pool,
            Asked::new("https://app.test", r#"{"target":"https://app.test"}"#),
            Key::Settings("k"),
            true,
        )
        .await
        .expect("started")
    }

    /// A scan's findings are kept once each, with no credential, under their kind and
    /// check; its log lines are its notes; its progress is on its row, its last said
    /// written at its end; and each is read back by the `scan_info` and `findings` answers.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_scan_is_kept_as_it_goes_and_read_back() {
        let scratch = crate::testing::Scratch::new(&ENGINE).await;
        let pool = scratch.pool.clone();
        let running = started(&pool).await;
        let mut keeper = Keeper::new(&pool, Some(&running.id));
        let found = |token: &str, hash: &str| {
            json!({"type": "finding", "data": {
                "type": "vulnerability", "template": "t1", "severity": "high", "name": "n",
                "matched_at": format!("https://app.test/x?token={token}"),
                "proof": {"response_sha256": hash},
            }})
        };
        keeper.event(&found("first", "aa")).await;
        keeper.event(&found("rotated", "bb")).await;
        keeper
            .event(
                &json!({"type": "result", "operation_id": "op", "host": "app.test",
                           "port": 443, "status": "open", "banner": "Set-Cookie: s=c-secret"}),
            )
            .await;
        keeper
            .event(&json!({"type": "log", "message": "fetch of https://app.test/?token=l-secret"}))
            .await;
        keeper
            .event(&json!({"type": "progress", "processed": 1, "total": 9}))
            .await;
        keeper
            .event(&json!({"type": "progress", "processed": 5, "total": 9}))
            .await;
        keeper
            .event(&json!({"type": "error", "message": "the target went away"}))
            .await;
        crate::scans::finish(running, Status::Failed).await.unwrap();

        let all = answer_findings(&pool, None, None, 100).await;
        let rows = all["findings"].as_array().expect("rows");
        assert_eq!(rows.len(), 2, "{all}");
        assert_eq!(rows[0]["kind"], "vulnerability");
        assert_eq!(rows[0]["check"], "t1");
        assert_eq!(rows[0]["data"]["matched_at"], "https://app.test/x?token=");
        assert_eq!(rows[1]["kind"], "result");
        assert!(rows[1]["data"].get("operation_id").is_none());
        let text = all.to_string();
        assert!(
            !text.contains("c-secret") && !text.contains("first"),
            "{text}"
        );
        let after = answer_findings(&pool, None, rows[0]["id"].as_i64(), 100).await;
        assert_eq!(after["findings"].as_array().unwrap().len(), 1);
        let id = rows[0]["scan"].as_str().unwrap();
        assert_eq!(
            answer_findings(&pool, Some("another"), None, 100).await["findings"],
            json!([])
        );

        let scan = answer_scan(&pool, id).await;
        assert_eq!(scan["status"], "completed", "{scan}");
        let scan = &scan["scan"];
        assert_eq!(scan["status"], "failed");
        assert_eq!(scan["progress"], json!({"processed": 5, "total": 9}));
        assert_eq!(scan["findings"], 2);
        assert_eq!(scan["by_severity"], json!({"high": 1}));
        assert_eq!(
            scan["notes"],
            json!([
                {"level": "info", "message": "fetch of https://app.test/?token="},
                {"level": "error", "message": "the target went away"},
            ])
        );
        let first = finding(&pool, rows[0]["id"].as_i64().unwrap())
            .await
            .unwrap();
        assert_eq!(first.unwrap()["data"]["proof"]["response_sha256"], "aa");
        assert_eq!(
            answer_scan(&pool, "nothing").await["message"],
            "no scan nothing is kept here"
        );
        scratch.done().await;
    }

    /// Progress said more often than once a second is written at most once a second, and
    /// what is said last is never lost.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn progress_is_written_about_once_a_second() {
        let scratch = crate::testing::Scratch::new(&ENGINE).await;
        let pool = scratch.pool.clone();
        let running = started(&pool).await;
        let mut keeper = Keeper::new(&pool, Some(&running.id));
        let progress = |n: u64| json!({"type": "progress", "processed": n});
        keeper.event(&progress(1)).await;
        for n in 2..50 {
            keeper.event(&progress(n)).await;
        }
        let read = || async {
            sqlx::query_scalar::<_, Value>("SELECT progress FROM scans")
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        assert_eq!(
            read().await,
            json!({"processed": 1}),
            "written at once, then held"
        );
        keeper.flush().await.unwrap();
        assert_eq!(read().await, json!({"processed": 49}));
        crate::scans::finish(running, Status::Completed)
            .await
            .unwrap();
        scratch.done().await;
    }
}

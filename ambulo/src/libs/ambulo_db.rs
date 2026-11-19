use crate::libs::wordlist_source::{ListDigest, WordSource};
use crate::scanner::{ScanResult, ScanResults};
use crate::store::{Outcome, Store, Work};
use sqlx::QueryBuilder;

/// ambulo's part of the database: its schema, and the files that make its tables.
pub const ENGINE: cfx_db::Engine = cfx_db::Engine {
    name: "ambulo",
    version: env!("CARGO_PKG_VERSION"),
    migrations: &[include_str!("../../migrations/0001_entries.sql")],
};

/// A word list as it is kept: by id, and known by the digest of its words.
pub struct Wordlist {
    pub id: i64,
    pub hash: String,
}

#[derive(Clone)]
pub struct AmbuloDb {
    pool: sqlx::PgPool,
}

impl AmbuloDb {
    /// ambulo's tables on `pool`, a pool [`cfx_db::ensure_ready`] gave for [`ENGINE`].
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// A handle that has never connected and connects only if it is used, for tests
    /// of daemon paths that do not touch the database.
    #[cfg(test)]
    pub fn unconnected() -> Self {
        let opts = sqlx::postgres::PgConnectOptions::new()
            .host("127.0.0.1")
            .port(1)
            .username("none")
            .database("none");
        Self {
            pool: sqlx::PgPool::connect_lazy_with(opts),
        }
    }

    /// The pool, for the tables every engine has.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }

    // Column-for-column mirror of the table it writes; splitting it into a struct
    // would add a type whose only job is to be destructured immediately.
    #[allow(clippy::too_many_arguments)]
    pub async fn save_probe_result(
        &self,
        operation_id: &str,
        url: &str,
        status: &str,
        code: i32,
        body_length: i64,
        headers_length: i64,
        volatility_hours: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO probe_results (operation_id, url, status, code, body_length, headers_length, delete_after) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW() + ($7 || ' hours')::INTERVAL)",
        )
        .bind(operation_id)
        .bind(url)
        .bind(status)
        .bind(code)
        .bind(body_length)
        .bind(headers_length)
        .bind(volatility_hours)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_expired_probe_results(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM probe_results WHERE delete_after < NOW()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Store the words `source` gives as the wordlist `name`, and say which wordlist
    /// holds them. A list is known by its [`ListDigest`], so one stored before is used
    /// again rather than stored twice. The words go in a chunk at a time inside one
    /// transaction, which is undone when the source fails or the list was already
    /// here, and only one chunk is ever held in memory.
    pub(crate) async fn store_wordlist(
        &self,
        name: &str,
        source: &mut impl WordSource,
    ) -> Result<Wordlist, String> {
        let db = |e: sqlx::Error| format!("DB: {e}");
        let mut tx = self.pool.begin().await.map_err(db)?;
        let id: i64 =
            sqlx::query_scalar("INSERT INTO wordlists (name, hash) VALUES ($1, $2) RETURNING id")
                .bind(name)
                .bind(format!("pending {}", uuid::Uuid::new_v4()))
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        let mut digest = ListDigest::default();
        while let Some(chunk) = source.next_chunk().await? {
            digest.update(&chunk);
            let mut qb: QueryBuilder<sqlx::Postgres> =
                QueryBuilder::new("INSERT INTO words (word, wordlist_id) ");
            qb.push_values(chunk.iter(), |mut b, word| {
                b.push_bind(word).push_bind(id);
            });
            qb.build().execute(&mut *tx).await.map_err(db)?;
        }
        let hash = digest.finish();
        let stored = sqlx::query("UPDATE wordlists SET hash = $1 WHERE id = $2")
            .bind(&hash)
            .bind(id)
            .execute(&mut *tx)
            .await;
        match stored {
            Ok(_) => tx.commit().await.map_err(db)?,
            // Stored before, or by another scan meanwhile: that copy is the one used.
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505") => {
                tx.rollback().await.map_err(db)?;
                let id = sqlx::query_scalar("SELECT id FROM wordlists WHERE hash = $1")
                    .bind(&hash)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(db)?;
                return Ok(Wordlist { id, hash });
            }
            Err(e) => return Err(db(e)),
        }
        Ok(Wordlist { id, hash })
    }

    /// Request each of `urls` with every word of wordlist `wordlist_id`, as scan
    /// `scan_id`: the URLs are kept, and an entry made for each URL and word. The
    /// database makes the entries from the words it holds, so none is read here.
    pub async fn queue_scan(
        &self,
        scan_id: &str,
        urls: &[String],
        wordlist_id: i64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        for url in urls {
            let url_id: i64 =
                sqlx::query_scalar("INSERT INTO urls (url, scan_id) VALUES ($1, $2) RETURNING id")
                    .bind(url)
                    .bind(scan_id)
                    .fetch_one(&mut *tx)
                    .await?;
            sqlx::query(
                "INSERT INTO scan_entries (word_id, scan_id, url_id) \
                 SELECT id, $1, $2 FROM words WHERE wordlist_id = $3 ORDER BY id",
            )
            .bind(scan_id)
            .bind(url_id)
            .bind(wordlist_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }

    /// Queue again the entries of scan `scan_id` that were being requested when it
    /// stopped, so that the scan taken up again requests them.
    pub async fn requeue_unfinished(&self, scan_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE scan_entries SET status = 'queued' WHERE scan_id = $1 AND status = 'scanning'",
        )
        .bind(scan_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// How many requests scan `scan_id` makes in all.
    pub async fn entries(&self, scan_id: &str) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_one(&self.pool)
            .await
    }

    /// End scan `scan_id`: completed when it sent every request, stopped when some were
    /// left unsent, failed when it failed.
    pub async fn end_scan(&self, scan_id: &str, failed: bool) -> Result<(), sqlx::Error> {
        let left: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM scan_entries \
             WHERE scan_id = $1 AND status IN ('queued', 'scanning'))",
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;
        let status = match (failed, left) {
            (true, _) => cfx_db::scans::Status::Failed,
            (false, true) => cfx_db::scans::Status::Stopped,
            (false, false) => cfx_db::scans::Status::Completed,
        };
        cfx_db::scans::finish(&self.pool, scan_id, status).await
    }

    /// Delete the scans made more than `retention_hours` ago, with everything kept for
    /// them, and say how many. Word lists are kept: scans share them.
    pub async fn delete_old_scans(&self, retention_hours: i64) -> Result<u64, sqlx::Error> {
        let deleted =
            sqlx::query("DELETE FROM scans WHERE created_at < now() - make_interval(hours => $1)")
                .bind(retention_hours as i32)
                .execute(&self.pool)
                .await?;
        Ok(deleted.rows_affected())
    }
}

/// The levels of a scan's log, least important first.
const LOG_LEVELS: [&str; 4] = ["debug", "info", "warn", "error"];

/// One scan's [`Store`]: its entries and its log, in ambulo's tables.
pub struct ScanStore {
    pool: sqlx::PgPool,
    scan_id: String,
    /// What a request is made from: the scan's URL with the word in place of its marker.
    fuzz_marker: String,
    method: String,
    /// Log lines below this level are not kept.
    min_level: usize,
}

impl AmbuloDb {
    /// The store for scan `scan_id`, run with `config`.
    pub fn scan_store(&self, scan_id: String, config: &crate::libs::cli_args::Args) -> ScanStore {
        let level = config.log_level.to_string();
        ScanStore {
            pool: self.pool.clone(),
            scan_id,
            fuzz_marker: config.fuzz_marker.clone(),
            method: config.http_method.to_string(),
            min_level: LOG_LEVELS.iter().position(|l| *l == level).unwrap_or(0),
        }
    }
}

impl Store for ScanStore {
    /// Taken with FOR UPDATE SKIP LOCKED, so two workers never take the same entry.
    async fn claim(&self) -> Result<Option<Work>, String> {
        let entry: Option<(i64, String, String)> = sqlx::query_as(
            r#"
            WITH taken AS (
                UPDATE scan_entries
                SET status = 'scanning'
                WHERE id = (
                    SELECT id FROM scan_entries
                    WHERE scan_id = $1 AND status = 'queued'
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, url_id, word_id
            )
            SELECT taken.id, urls.url, words.word
            FROM taken JOIN urls ON urls.id = taken.url_id JOIN words ON words.id = taken.word_id
            "#,
        )
        .bind(&self.scan_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(entry.map(|(entry_id, url, word)| Work {
            url: url.replace(&self.fuzz_marker, &word),
            entry_id,
            method: self.method.clone(),
        }))
    }

    async fn record(&self, entry: i64, outcome: Outcome<'_>) -> Result<(), String> {
        sqlx::query(
            "UPDATE scan_entries SET status = $1, request_status = $2, headers_length = $3, \
             body_length = $4 WHERE id = $5",
        )
        .bind(outcome.status)
        .bind(outcome.code.parse::<i32>().unwrap_or(0))
        .bind(outcome.headers_length)
        .bind(outcome.body_length)
        .bind(entry)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn release(&self, entry: i64) -> Result<(), String> {
        sqlx::query("UPDATE scan_entries SET status = 'queued' WHERE id = $1")
            .bind(entry)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn results(&self) -> Result<ScanResults, String> {
        results(&self.pool, &self.fuzz_marker, &self.scan_id)
            .await
            .map_err(|e| e.to_string())
    }

    /// A line that cannot be kept is dropped: a scan does not stop over its log.
    async fn log(&self, level: &str, message: &str) {
        if LOG_LEVELS.iter().position(|l| *l == level).unwrap_or(0) < self.min_level {
            return;
        }
        let _ = sqlx::query("INSERT INTO logs (scan_id, level, message) VALUES ($1, $2, $3)")
            .bind(&self.scan_id)
            .bind(level)
            .bind(message)
            .execute(&self.pool)
            .await;
    }
}

/// What scan `scan_id` found, in the order its entries were made, with its totals.
async fn results(
    pool: &sqlx::PgPool,
    fuzz_marker: &str,
    scan_id: &str,
) -> Result<ScanResults, sqlx::Error> {
    let found: Vec<(String, String, i32, i64, i64)> = sqlx::query_as(
        "SELECT u.url, w.word, e.request_status, e.body_length, e.headers_length \
         FROM scan_entries e JOIN urls u ON u.id = e.url_id JOIN words w ON w.id = e.word_id \
         WHERE e.scan_id = $1 AND e.status = 'found' ORDER BY e.id",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;
    let (not_found, error, entries): (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE status = 'not_found'), \
         COUNT(*) FILTER (WHERE status = 'error'), COUNT(*) FROM scan_entries WHERE scan_id = $1",
    )
    .bind(scan_id)
    .fetch_one(pool)
    .await?;
    Ok(ScanResults {
        totals: crate::scanner::ScanResultTotals {
            found: found.len(),
            not_found: not_found as usize,
            error: error as usize,
            entries: entries as usize,
        },
        found: found
            .into_iter()
            .map(
                |(url, word, code, body_length, headers_length)| ScanResult {
                    url: url.replace(fuzz_marker, &word),
                    scan_status: "found".to_string(),
                    request_status: code.to_string(),
                    body_length,
                    headers_length,
                },
            )
            .collect(),
    })
}

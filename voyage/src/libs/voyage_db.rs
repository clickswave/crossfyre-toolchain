use crate::store::{PassiveResult, Store, Work};
use sqlx::QueryBuilder;

/// voyage's part of the database: its schema, and the files that make its tables.
pub const ENGINE: cfx_db::Engine = cfx_db::Engine {
    name: "voyage",
    version: env!("CARGO_PKG_VERSION"),
    migrations: &[include_str!("../../migrations/0001_entries.sql")],
};

#[derive(Clone)]
pub struct VoyageDb {
    pool: sqlx::PgPool,
}

impl VoyageDb {
    /// voyage's tables on `pool`, a pool [`cfx_db::ensure_ready`] gave for [`ENGINE`].
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

    /// Start a scan of `domain` asked for with `params`, whose names are keyed by
    /// `config_hash`: a stopped scan with the same key is taken up again, with the names
    /// it had tried, unless `fresh` asks for a new one.
    pub async fn start_scan(
        &self,
        domain: &str,
        config_hash: &str,
        params: &str,
        fresh: bool,
    ) -> Result<String, sqlx::Error> {
        Ok(
            cfx_db::scans::start(&self.pool, domain, config_hash, params, fresh)
                .await?
                .id,
        )
    }

    /// End scan `scan`: completed when it tried every name, stopped when some were left
    /// untried, failed when it failed.
    pub async fn end_scan(&self, scan: &str, failed: bool) -> Result<(), sqlx::Error> {
        let left: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM scan_entries \
             WHERE scan_id = $1 AND status IN ('queued', 'scanning'))",
        )
        .bind(scan)
        .fetch_one(&self.pool)
        .await?;
        let status = match (failed, left) {
            (true, _) => cfx_db::scans::Status::Failed,
            (false, true) => cfx_db::scans::Status::Stopped,
            (false, false) => cfx_db::scans::Status::Completed,
        };
        cfx_db::scans::finish(&self.pool, scan, status).await
    }

    // --- Entries ---

    /// Batch-insert subdomain entries; silently skips duplicates (UNIQUE constraint).
    pub async fn insert_entries_batch(
        &self,
        scan_id: &str,
        entries: &[(String, String, String, String)], // (full_subdomain, method, source, status)
    ) -> Result<(), sqlx::Error> {
        if entries.is_empty() {
            return Ok(());
        }

        const BATCH_SIZE: usize = 1000;
        for chunk in entries.chunks(BATCH_SIZE) {
            let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
                "INSERT INTO scan_entries (scan_id, full_subdomain, method, source, status) ",
            );
            qb.push_values(
                chunk.iter(),
                |mut b, (subdomain, method, source, status)| {
                    b.push_bind(scan_id)
                        .push_bind(subdomain)
                        .push_bind(method)
                        .push_bind(source)
                        .push_bind(status);
                },
            );
            qb.push(" ON CONFLICT (scan_id, full_subdomain) DO NOTHING");
            qb.build().execute(&self.pool).await?;
        }

        Ok(())
    }

    /// Reset any 'scanning' entries back to 'queued' (for crash recovery).
    pub async fn reset_halted_entries(&self, scan_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE scan_entries SET status = 'queued' WHERE scan_id = $1 AND status = 'scanning'",
        )
        .bind(scan_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_scan_entry_total(&self, scan_id: &str) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_found_subdomains(&self, scan_id: &str) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT full_subdomain FROM scan_entries WHERE scan_id = $1 AND status = 'found' ORDER BY id",
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await
    }

    // --- Probe results ---

    pub async fn save_probe_result(
        &self,
        operation_id: &str,
        domain: &str,
        found: bool,
        technique: &str,
        volatility_hours: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO probe_results (operation_id, domain, found, technique, delete_after) \
             VALUES ($1, $2, $3, $4, NOW() + ($5 || ' hours')::INTERVAL)",
        )
        .bind(operation_id)
        .bind(domain)
        .bind(found)
        .bind(technique)
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
}

/// The scanner's view of a scan, kept in voyage's tables.
impl Store for VoyageDb {
    async fn passive_results(&self, scan: &str) -> Result<Vec<PassiveResult>, String> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT full_subdomain, source FROM scan_entries \
             WHERE scan_id = $1 AND method = 'passive' ORDER BY id",
        )
        .bind(scan)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .map(|(full_subdomain, source)| PassiveResult {
                full_subdomain,
                source,
            })
            .collect())
    }

    /// Taken with FOR UPDATE SKIP LOCKED, so two workers never take the same name.
    async fn claim(&self, scan: &str) -> Result<Option<Work>, String> {
        let entry: Option<(i64, String)> = sqlx::query_as(
            r#"
            UPDATE scan_entries
            SET status = 'scanning', updated_at = now()
            WHERE id = (
                SELECT id FROM scan_entries
                WHERE scan_id = $1 AND status = 'queued'
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id, full_subdomain
            "#,
        )
        .bind(scan)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(entry.map(|(entry_id, full_subdomain)| Work {
            entry_id,
            full_subdomain,
        }))
    }

    async fn trying(&self, scan: &str) -> Result<bool, String> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1 AND status = 'scanning'",
        )
        .bind(scan)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(count > 0)
    }

    async fn record(&self, entry: i64, status: &str, source: &str) -> Result<(), String> {
        sqlx::query(
            "UPDATE scan_entries SET status = $1, source = $2, updated_at = now() \
             WHERE id = $3",
        )
        .bind(status)
        .bind(source)
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

    async fn totals(&self, scan: &str) -> Result<(i64, i64), String> {
        sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE status = 'found'), \
             COUNT(*) FILTER (WHERE status = 'not_found') FROM scan_entries WHERE scan_id = $1",
        )
        .bind(scan)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| e.to_string())
    }
}

use sqlx::postgres::PgConnectOptions;
use sqlx::{FromRow, QueryBuilder};

pub struct Work {
    pub entry_id: i64,
    pub full_subdomain: String,
}

#[derive(Clone)]
pub struct VoyageDb {
    pool: sqlx::PgPool,
}

#[derive(Debug, Clone, FromRow)]
pub struct PassiveResult {
    pub full_subdomain: String,
    pub source: String,
}

impl VoyageDb {
    /// Bootstrap: connect to `postgres` maintenance DB, create `voyage` DB if missing,
    /// then return a pool connected to `voyage`.
    pub async fn init(
        host: &str,
        port: u16,
        user: &str,
        password: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        let mut admin_opts = PgConnectOptions::new()
            .host(host)
            .port(port)
            .username(user)
            .database("postgres");
        if let Some(pwd) = password {
            admin_opts = admin_opts.password(pwd);
        }

        let admin_pool = sqlx::PgPool::connect_with(admin_opts).await?;

        let db_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'voyage')")
                .fetch_one(&admin_pool)
                .await?;

        if !db_exists {
            sqlx::query("CREATE DATABASE voyage")
                .execute(&admin_pool)
                .await?;
        }
        drop(admin_pool);

        let mut voyage_opts = PgConnectOptions::new()
            .host(host)
            .port(port)
            .username(user)
            .database("voyage");
        if let Some(pwd) = password {
            voyage_opts = voyage_opts.password(pwd);
        }

        let pool = sqlx::PgPool::connect_with(voyage_opts).await?;

        Ok(Self { pool })
    }

    /// A handle that has never connected and connects only if it is used, for tests
    /// of daemon paths that do not touch the database.
    #[cfg(test)]
    pub fn unconnected() -> Self {
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(1)
            .username("none")
            .database("voyage");
        Self {
            pool: sqlx::PgPool::connect_lazy_with(opts),
        }
    }

    pub async fn create_tables(&self) -> Result<(), sqlx::Error> {
        // scans table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                config_hash TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                wordlist_path TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'created',
                created_at TEXT NOT NULL DEFAULT NOW()::TEXT,
                updated_at TEXT NOT NULL DEFAULT NOW()::TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // scan_entries table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scan_entries (
                id BIGSERIAL PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES scans(id),
                full_subdomain TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                method TEXT NOT NULL DEFAULT 'active',
                source TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT NOW()::TEXT,
                updated_at TEXT NOT NULL DEFAULT NOW()::TEXT,
                UNIQUE (scan_id, full_subdomain)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // logs table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS logs (
                id BIGSERIAL PRIMARY KEY,
                scan_id TEXT,
                level TEXT NOT NULL DEFAULT 'info',
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT NOW()::TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // operations table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS operations (
                id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                params TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'queued',
                result TEXT,
                created_at TEXT NOT NULL DEFAULT NOW()::TEXT,
                updated_at TEXT NOT NULL DEFAULT NOW()::TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // probe_results table (for enum-exec with volatility > 0)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS probe_results (
                id BIGSERIAL PRIMARY KEY,
                operation_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                found BOOLEAN NOT NULL DEFAULT false,
                technique TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                delete_after TIMESTAMPTZ NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn truncate_tables(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "TRUNCATE TABLE probe_results, operations, logs, scan_entries, scans RESTART IDENTITY CASCADE",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // --- Scan lifecycle ---

    pub async fn get_or_create_scan(
        &self,
        config_hash: &str,
        domain: &str,
        wordlist_path: &str,
    ) -> Result<String, sqlx::Error> {
        let existing: Option<String> =
            sqlx::query_scalar("SELECT id FROM scans WHERE config_hash = $1")
                .bind(config_hash)
                .fetch_optional(&self.pool)
                .await?;

        if let Some(id) = existing {
            return Ok(id);
        }

        let new_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO scans (id, config_hash, domain, wordlist_path, status) VALUES ($1, $2, $3, $4, 'created')",
        )
        .bind(&new_id)
        .bind(config_hash)
        .bind(domain)
        .bind(wordlist_path)
        .execute(&self.pool)
        .await?;

        Ok(new_id)
    }

    pub async fn fresh_start_scan(&self, scan_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM scan_entries WHERE scan_id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM logs WHERE scan_id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("UPDATE scans SET status = 'created' WHERE id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_scan_status(&self, scan_id: &str, status: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE scans SET status = $1 WHERE id = $2")
            .bind(status)
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        Ok(())
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

    /// Atomically claim one queued entry for scanning (FOR UPDATE SKIP LOCKED).
    pub async fn get_work_one(&self, scan_id: &str) -> Result<Work, sqlx::Error> {
        #[derive(FromRow)]
        struct Entry {
            id: i64,
            full_subdomain: String,
        }

        let entry = sqlx::query_as::<_, Entry>(
            r#"
            UPDATE scan_entries
            SET status = 'scanning', updated_at = NOW()::TEXT
            WHERE id = (
                SELECT id FROM scan_entries
                WHERE scan_id = $1 AND status = 'queued'
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id, full_subdomain
            "#,
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(Work {
            entry_id: entry.id,
            full_subdomain: entry.full_subdomain,
        })
    }

    pub async fn update_work_status(
        &self,
        entry_id: i64,
        status: &str,
        source: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE scan_entries SET status = $1, source = $2, updated_at = NOW()::TEXT WHERE id = $3",
        )
        .bind(status)
        .bind(source)
        .bind(entry_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn reset_entry_to_queued(&self, entry_id: i64) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE scan_entries SET status = 'queued' WHERE id = $1")
            .bind(entry_id)
            .execute(&self.pool)
            .await?;
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

    pub async fn is_scanning_active(&self, scan_id: &str) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1 AND status = 'scanning'",
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    pub async fn get_scan_entry_total(&self, scan_id: &str) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_scan_totals(&self, scan_id: &str) -> Result<(i64, i64), sqlx::Error> {
        let found: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1 AND status = 'found'",
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        let not_found: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1 AND status = 'not_found'",
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        Ok((found, not_found))
    }

    pub async fn get_passive_results(
        &self,
        scan_id: &str,
    ) -> Result<Vec<PassiveResult>, sqlx::Error> {
        sqlx::query_as::<_, PassiveResult>(
            "SELECT full_subdomain, source FROM scan_entries WHERE scan_id = $1 AND method = 'passive' ORDER BY id",
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
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

    // --- Operations ---

    pub async fn create_operation(
        &self,
        id: &str,
        operation: &str,
        params: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO operations (id, operation, params, status) VALUES ($1, $2, $3, 'queued')",
        )
        .bind(id)
        .bind(operation)
        .bind(params)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_operation_status(
        &self,
        id: &str,
        status: &str,
        result: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE operations SET status = $1, result = $2, updated_at = NOW()::TEXT WHERE id = $3",
        )
        .bind(status)
        .bind(result)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
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

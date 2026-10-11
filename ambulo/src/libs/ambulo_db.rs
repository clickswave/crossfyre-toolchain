use crate::libs;
use crate::libs::wordlist_config::WordlistConfig;
use crate::scanner::{LogTotals, Logs, ScanResult, ScanResults};
use sqlx::postgres::PgConnectOptions;
use sqlx::{FromRow, QueryBuilder};
use std::fmt::Display;

pub struct Work {
    pub url: String,
    pub entry_id: i64,
    pub method: String,
}

impl Display for Work {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Work {{ url: {}, entry_id: {}, method: {} }}",
            self.url, self.entry_id, self.method
        )
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct ScanEntry {
    pub id: i64,
    pub scan_id: i64,
    pub url_id: i64,
    pub word_id: i64,
    pub status: String,
    pub request_status: i32,
    pub headers: Option<String>,
    pub headers_length: i64,
    pub body: Option<Vec<u8>>,
    pub body_length: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct Scan {
    pub id: i64,
    pub config_hash: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub notifications: String,
    pub wordlist_id: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct Log {
    pub id: i64,
    pub scan_id: i64,
    pub message: String,
    pub level: String,
    pub created_at: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct Wordlist {
    pub id: i64,
    pub name: String,
    pub hash: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct Url {
    pub id: i64,
    pub url: String,
    pub scan_id: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct Word {
    pub id: i64,
    pub word: String,
    pub wordlist_id: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct Operation {
    pub id: String,
    pub operation: String,
    pub params: String,
    pub status: String,
    pub result: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct AmbuloDb {
    pool: sqlx::PgPool,
    config: crate::libs::cli_args::Args,
}

#[derive(Clone)]
pub struct Logger {
    pool: sqlx::PgPool,
    scan_id: i64,
    min_log_level: String,
    log_levels: Vec<&'static str>,
}

impl Logger {
    fn accept_log_level(&self, log_level: &str) -> bool {
        let min_log_level_index = self
            .log_levels
            .iter()
            .position(|&x| x == self.min_log_level)
            .unwrap_or(0);
        let current_log_level_index = self
            .log_levels
            .iter()
            .position(|&x| x == log_level)
            .unwrap_or(0);
        current_log_level_index >= min_log_level_index
    }

    async fn insert_log(&self, level: &str, description: &str) -> Result<(), sqlx::Error> {
        if !self.accept_log_level(level) {
            return Ok(());
        }

        sqlx::query("INSERT INTO logs (scan_id, level, description) VALUES ($1, $2, $3)")
            .bind(self.scan_id)
            .bind(level)
            .bind(description)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn error(&self, message: &str) -> Result<(), sqlx::Error> {
        self.insert_log("error", message).await
    }
    pub async fn info(&self, message: &str) -> Result<(), sqlx::Error> {
        self.insert_log("info", message).await
    }
    pub async fn debug(&self, message: &str) -> Result<(), sqlx::Error> {
        self.insert_log("debug", message).await
    }
    pub async fn warn(&self, message: &str) -> Result<(), sqlx::Error> {
        self.insert_log("warn", message).await
    }
}

impl AmbuloDb {
    /// Bootstrap: connect to the `postgres` maintenance DB, create the `mach` DB if
    /// missing, then return a pool connected to it.
    ///
    /// The database keeps the engine's original name, `mach`. It holds resumable scan
    /// state, and renaming it would drop every run an operator could still resume.
    pub async fn init(
        host: &str,
        port: u16,
        user: &str,
        password: Option<&str>,
        config: &crate::libs::cli_args::Args,
    ) -> Result<Self, sqlx::Error> {
        // Build admin connection options (connect to postgres maintenance DB)
        let mut admin_opts = PgConnectOptions::new()
            .host(host)
            .port(port)
            .username(user)
            .database("postgres");
        if let Some(pwd) = password {
            admin_opts = admin_opts.password(pwd);
        }

        let admin_pool = sqlx::PgPool::connect_with(admin_opts).await?;

        // Create the `mach` database if it doesn't exist
        let db_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'mach')")
                .fetch_one(&admin_pool)
                .await?;

        if !db_exists {
            // CREATE DATABASE cannot run inside a transaction
            sqlx::query("CREATE DATABASE mach")
                .execute(&admin_pool)
                .await?;
        }
        drop(admin_pool);

        // Connect to the `mach` database
        let mut ambulo_opts = PgConnectOptions::new()
            .host(host)
            .port(port)
            .username(user)
            .database("mach");
        if let Some(pwd) = password {
            ambulo_opts = ambulo_opts.password(pwd);
        }

        let pool = sqlx::PgPool::connect_with(ambulo_opts).await?;

        Ok(Self {
            pool,
            config: config.clone(),
        })
    }

    pub async fn spawn_logger(
        &self,
        scan_id: &i64,
        log_level: &str,
    ) -> Result<Logger, sqlx::Error> {
        Ok(Logger {
            pool: self.pool.clone(),
            scan_id: *scan_id,
            min_log_level: log_level.to_string(),
            log_levels: vec!["debug", "info", "warn", "error"],
        })
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

    pub async fn truncate_tables(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "TRUNCATE TABLE probe_results, operations, scan_entries, logs, urls, scans, words, wordlists RESTART IDENTITY CASCADE"
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_tables(&self) -> Result<(), sqlx::Error> {
        // wordlists table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS wordlists (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                hash TEXT UNIQUE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // words table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS words (
                id BIGSERIAL PRIMARY KEY,
                word TEXT NOT NULL,
                wordlist_id BIGINT NOT NULL,
                FOREIGN KEY (wordlist_id) REFERENCES wordlists(id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // scans table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scans (
                id BIGSERIAL PRIMARY KEY,
                config_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT NOW()::TEXT,
                updated_at TEXT NOT NULL DEFAULT NOW()::TEXT,
                notifications TEXT NOT NULL DEFAULT '{}',
                wordlist_id BIGINT,
                method TEXT NOT NULL,
                FOREIGN KEY (wordlist_id) REFERENCES wordlists(id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // urls table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS urls (
                id BIGSERIAL PRIMARY KEY,
                url TEXT NOT NULL,
                scan_id BIGINT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
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
                scan_id BIGINT,
                url_id BIGINT,
                word_id BIGINT,
                status TEXT,
                request_status INTEGER NOT NULL DEFAULT 0,
                headers TEXT,
                headers_length BIGINT NOT NULL,
                body BYTEA,
                body_length BIGINT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (url_id) REFERENCES urls(id),
                FOREIGN KEY (word_id) REFERENCES words(id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Every hot scan_entries query filters by (scan_id, status): the per-probe
        // work-claim (status='queued'), the result fetches (found/not_found/error),
        // the counts, and the processing->queued reset. Without this index those
        // are sequential scans that grow with the whole table, so a large scan
        // slows as its own rows accumulate and any orphaned rows make it worse.
        // Verified: turns the claim from a ~7ms seq scan (200k rows) into a
        // ~0.08ms index scan, size-independent.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS scan_entries_scan_status_idx \
             ON scan_entries(scan_id, status)",
        )
        .execute(&self.pool)
        .await?;

        // logs table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS logs (
                id BIGSERIAL PRIMARY KEY,
                scan_id BIGINT NOT NULL,
                level TEXT NOT NULL DEFAULT 'debug',
                description TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT NOW()::TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // operations table (for daemon mode)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS operations (
                id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                params TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                result TEXT,
                created_at TEXT NOT NULL DEFAULT NOW()::TEXT,
                updated_at TEXT NOT NULL DEFAULT NOW()::TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // probe_results table (for fuzz-exec with volatility > 0)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS probe_results (
                id BIGSERIAL PRIMARY KEY,
                operation_id TEXT NOT NULL,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                code INTEGER NOT NULL DEFAULT 0,
                body_length BIGINT NOT NULL DEFAULT 0,
                headers_length BIGINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                delete_after TIMESTAMPTZ NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_wordlist(&self, wordlist_hash: &str) -> Result<Wordlist, sqlx::Error> {
        sqlx::query_as::<_, Wordlist>("SELECT * FROM wordlists WHERE hash = $1")
            .bind(wordlist_hash)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn create_words(
        &self,
        wordlist_id: &i64,
        words: &[String],
    ) -> Result<Vec<Word>, sqlx::Error> {
        const BATCH_SIZE: usize = 1000;
        for chunk in words.chunks(BATCH_SIZE) {
            let mut qb: QueryBuilder<sqlx::Postgres> =
                QueryBuilder::new("INSERT INTO words (word, wordlist_id) ");
            qb.push_values(chunk.iter(), |mut b, word| {
                b.push_bind(word.clone()).push_bind(*wordlist_id);
            });
            qb.build().execute(&self.pool).await?;
        }

        sqlx::query_as::<_, Word>("SELECT * FROM words WHERE wordlist_id = $1")
            .bind(wordlist_id)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn create_wordlist(
        &self,
        wordlist_config: &WordlistConfig,
    ) -> Result<Wordlist, sqlx::Error> {
        let wordlist = sqlx::query_as::<_, Wordlist>(
            "INSERT INTO wordlists (name, hash) VALUES ($1, $2) RETURNING *",
        )
        .bind(&wordlist_config.name)
        .bind(&wordlist_config.hash)
        .fetch_one(&self.pool)
        .await?;

        let words = libs::utils::read_lines(&wordlist_config.path).await?;
        self.create_words(&wordlist.id, &words).await?;

        Ok(wordlist)
    }

    pub async fn fetch_words(&self, wordlist_id: &i64) -> Result<Vec<Word>, sqlx::Error> {
        sqlx::query_as::<_, Word>("SELECT * FROM words WHERE wordlist_id = $1")
            .bind(wordlist_id)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn find_scan(&self, scan_hash: &str) -> Result<Scan, sqlx::Error> {
        sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE config_hash = $1")
            .bind(scan_hash)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn fetch_found_scan_entries(
        &self,
        scan_id: i64,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ScanResult>, sqlx::Error> {
        let found_entries = if limit == 0 {
            sqlx::query_as::<_, ScanEntry>(
                "SELECT * FROM scan_entries WHERE scan_id = $1 AND status = 'found'",
            )
            .bind(scan_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, ScanEntry>(
                "SELECT * FROM scan_entries WHERE scan_id = $1 AND status = 'found' LIMIT $2 OFFSET $3",
            )
            .bind(scan_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        };

        let mut found_urls = Vec::new();
        for entry in found_entries {
            let mut url = sqlx::query_scalar::<_, String>("SELECT url FROM urls WHERE id = $1")
                .bind(entry.url_id)
                .fetch_one(&self.pool)
                .await?;
            let word = sqlx::query_scalar::<_, String>("SELECT word FROM words WHERE id = $1")
                .bind(entry.word_id)
                .fetch_one(&self.pool)
                .await?;
            url = url.replace(&self.config.fuzz_marker, &word);

            found_urls.push(ScanResult {
                url,
                scan_status: entry.status.clone(),
                request_status: entry.request_status.to_string(),
                body_length: entry.body_length,
                headers_length: entry.headers_length,
            });
        }
        Ok(found_urls)
    }

    pub async fn fetch_not_found_scan_entries(
        &self,
        scan_id: i64,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ScanResult>, sqlx::Error> {
        let not_found_entries = if limit == 0 {
            sqlx::query_as::<_, ScanEntry>(
                "SELECT * FROM scan_entries WHERE scan_id = $1 AND status = 'not_found'",
            )
            .bind(scan_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, ScanEntry>(
                "SELECT * FROM scan_entries WHERE scan_id = $1 AND status = 'not_found' LIMIT $2 OFFSET $3",
            )
            .bind(scan_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        };

        let mut not_found_urls = Vec::new();
        for entry in not_found_entries {
            let mut url = sqlx::query_scalar::<_, String>("SELECT url FROM urls WHERE id = $1")
                .bind(entry.url_id)
                .fetch_one(&self.pool)
                .await?;
            let word = sqlx::query_scalar::<_, String>("SELECT word FROM words WHERE id = $1")
                .bind(entry.word_id)
                .fetch_one(&self.pool)
                .await?;
            url = url.replace(&self.config.fuzz_marker, &word);

            not_found_urls.push(ScanResult {
                url,
                scan_status: entry.status.clone(),
                request_status: entry.request_status.to_string(),
                body_length: entry.body_length,
                headers_length: entry.headers_length,
            });
        }
        Ok(not_found_urls)
    }

    pub async fn fetch_error_scan_entries(
        &self,
        scan_id: i64,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ScanResult>, sqlx::Error> {
        let error_entries = if limit == 0 {
            sqlx::query_as::<_, ScanEntry>(
                "SELECT * FROM scan_entries WHERE scan_id = $1 AND status = 'error'",
            )
            .bind(scan_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, ScanEntry>(
                "SELECT * FROM scan_entries WHERE scan_id = $1 AND status = 'error' LIMIT $2 OFFSET $3",
            )
            .bind(scan_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        };

        let mut error_urls = Vec::new();
        for entry in error_entries {
            let mut url = sqlx::query_scalar::<_, String>("SELECT url FROM urls WHERE id = $1")
                .bind(entry.url_id)
                .fetch_one(&self.pool)
                .await?;
            let word = sqlx::query_scalar::<_, String>("SELECT word FROM words WHERE id = $1")
                .bind(entry.word_id)
                .fetch_one(&self.pool)
                .await?;
            url = url.replace(&self.config.fuzz_marker, &word);

            error_urls.push(ScanResult {
                url,
                scan_status: entry.status.clone(),
                request_status: entry.request_status.to_string(),
                body_length: entry.body_length,
                headers_length: entry.headers_length,
            });
        }
        Ok(error_urls)
    }

    pub async fn fetch_total_scan_entries(
        &self,
        scan_id: i64,
    ) -> Result<(usize, usize, usize, usize), sqlx::Error> {
        let found = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1 AND status = 'found'",
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        let not_found = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1 AND status = 'not_found'",
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        let error = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1 AND status = 'error'",
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        let total =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scan_entries WHERE scan_id = $1")
                .bind(scan_id)
                .fetch_one(&self.pool)
                .await?;

        Ok((
            found as usize,
            not_found as usize,
            error as usize,
            total as usize,
        ))
    }

    pub async fn get_scan_results(
        &self,
        scan_id: i64,
        limit: usize,
        offset: usize,
    ) -> Result<ScanResults, sqlx::Error> {
        let found = self
            .fetch_found_scan_entries(scan_id, limit, offset)
            .await?;
        let not_found = self
            .fetch_not_found_scan_entries(scan_id, limit, offset)
            .await?;
        let error = self
            .fetch_error_scan_entries(scan_id, limit, offset)
            .await?;
        let (found_total, not_found_total, error_total, entries_total) =
            self.fetch_total_scan_entries(scan_id).await?;

        Ok(ScanResults {
            found,
            not_found,
            error,
            totals: crate::scanner::ScanResultTotals {
                found: found_total,
                not_found: not_found_total,
                error: error_total,
                entries: entries_total,
            },
        })
    }

    pub async fn get_log_totals(&self) -> Result<LogTotals, sqlx::Error> {
        let debug_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM logs WHERE level = 'debug'")
                .fetch_one(&self.pool)
                .await?;
        let info_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM logs WHERE level = 'info'")
                .fetch_one(&self.pool)
                .await?;
        let warn_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM logs WHERE level = 'warn'")
                .fetch_one(&self.pool)
                .await?;
        let error_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM logs WHERE level = 'error'")
                .fetch_one(&self.pool)
                .await?;

        Ok(LogTotals {
            debug: debug_count as usize,
            info: info_count as usize,
            warn: warn_count as usize,
            error: error_count as usize,
            entries: (debug_count + info_count + warn_count + error_count) as usize,
        })
    }

    pub async fn get_logs(
        &self,
        scan_id: &i64,
        limit: usize,
        offset: usize,
    ) -> Result<Logs, sqlx::Error> {
        let logs = if limit == 0 {
            sqlx::query_as::<_, crate::scanner::Log>(
                "SELECT * FROM logs WHERE scan_id = $1 ORDER BY created_at DESC",
            )
            .bind(scan_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, crate::scanner::Log>(
                "SELECT * FROM logs WHERE scan_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(scan_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        };

        let log_totals = self.get_log_totals().await?;

        Ok(Logs {
            logs,
            totals: log_totals,
        })
    }

    // Column-for-column mirror of the table it writes; splitting it into a struct
    // would add a type whose only job is to be destructured immediately.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_work_status(
        &self,
        entry_id: i64,
        status: &str,
        response_status: &str,
        body: Option<Vec<u8>>,
        headers: Option<Vec<String>>,
        headers_length: i64,
        body_length: i64,
    ) -> Result<(), sqlx::Error> {
        let response_status_int: i32 = response_status.parse().unwrap_or(0);
        sqlx::query(
            "UPDATE scan_entries SET status = $1, request_status = $2, body = $3, headers = $4, headers_length = $5, body_length = $6 WHERE id = $7",
        )
        .bind(status)
        .bind(response_status_int)
        .bind(body)
        .bind(headers.map(|h| serde_json::to_string(&h).unwrap()))
        .bind(headers_length)
        .bind(body_length)
        .bind(entry_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_scan(
        &self,
        scan_config_hash: &str,
        wordlist_id: &i64,
        http_method: &str,
    ) -> Result<Scan, sqlx::Error> {
        sqlx::query_as::<_, Scan>(
            "INSERT INTO scans (config_hash, status, wordlist_id, method) VALUES ($1, 'created', $2, $3) RETURNING *",
        )
        .bind(scan_config_hash)
        .bind(wordlist_id)
        .bind(http_method)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn create_urls(
        &self,
        scan_id: &i64,
        urls: &[String],
    ) -> Result<Vec<Url>, sqlx::Error> {
        let mut qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("INSERT INTO urls (url, scan_id) ");
        qb.push_values(urls.iter(), |mut b, url| {
            b.push_bind(url.clone()).push_bind(*scan_id);
        });
        qb.build().execute(&self.pool).await?;

        sqlx::query_as::<_, Url>("SELECT * FROM urls WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn find_urls(&self, scan_id: &i64) -> Result<Vec<Url>, sqlx::Error> {
        let urls = sqlx::query_as::<_, Url>("SELECT * FROM urls WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_all(&self.pool)
            .await?;

        if urls.is_empty() {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(urls)
    }

    pub async fn fresh_start_scan(&self, scan_id: &i64) -> Result<Scan, sqlx::Error> {
        sqlx::query("UPDATE scans SET status = 'created' WHERE id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM logs WHERE scan_id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM scan_entries WHERE scan_id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;

        sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = $1")
            .bind(scan_id)
            .fetch_one(&self.pool)
            .await
    }

    /// Remove an isolated stream scan and its dependent rows once it has
    /// finished streaming. Stream scans are unique per connection (see the
    /// `isolate` arg to prepare_scan), so nothing else references them; deleting
    /// keeps the ambulo DB from growing unbounded now that concurrent scans no
    /// longer share (and reuse) one cached scan record. Words/wordlists are
    /// content-deduped and shared across scans, so they are intentionally kept.
    pub async fn delete_scan(&self, scan_id: i64) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM scan_entries WHERE scan_id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM logs WHERE scan_id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM urls WHERE scan_id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM scans WHERE id = $1")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Age-based garbage collection. Stream scans self-clean on completion
    /// (daemon `delete_scan`), but scans abandoned mid-run (node disconnect /
    /// daemon crash) and instant/CLI scans leave their rows behind and grow the
    /// table unbounded. This deletes everything for scans created before the
    /// retention cutoff - old enough that no real scan is still running, so it is
    /// safe even for a scan that still has queued rows (i.e. was abandoned). Words
    /// and wordlists are content-deduped and shared across scans, so kept.
    /// Returns the number of scan_entries rows reclaimed.
    pub async fn gc_old_scans(&self, retention_hours: i64) -> Result<u64, sqlx::Error> {
        // created_at is stored as NOW()::TEXT; cast back to compare by age.
        let old_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM scans \
             WHERE created_at::timestamptz < NOW() - make_interval(hours => $1)",
        )
        .bind(retention_hours as i32)
        .fetch_all(&self.pool)
        .await?;
        if old_ids.is_empty() {
            return Ok(0);
        }
        // Children before parents (scan_entries + urls FK scans).
        let reclaimed = sqlx::query("DELETE FROM scan_entries WHERE scan_id = ANY($1)")
            .bind(&old_ids)
            .execute(&self.pool)
            .await?
            .rows_affected();
        let _ = sqlx::query("DELETE FROM logs WHERE scan_id = ANY($1)")
            .bind(&old_ids)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM urls WHERE scan_id = ANY($1)")
            .bind(&old_ids)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM scans WHERE id = ANY($1)")
            .bind(&old_ids)
            .execute(&self.pool)
            .await;
        Ok(reclaimed)
    }

    pub async fn create_scan_entries(
        &self,
        urls: &Vec<Url>,
        scan: &Scan,
        words: &[Word],
    ) -> Result<(), sqlx::Error> {
        const BATCH_SIZE: usize = 1000;
        for url in urls {
            for chunk in words.chunks(BATCH_SIZE) {
                let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
                    "INSERT INTO scan_entries (word_id, scan_id, url_id, status, headers_length, body_length, headers, body) ",
                );
                qb.push_values(chunk.iter(), |mut b, word| {
                    b.push_bind(word.id)
                        .push_bind(scan.id)
                        .push_bind(url.id)
                        .push_bind("queued")
                        .push_bind(0i64)
                        .push_bind(0i64)
                        .push_bind(Option::<String>::None)
                        .push_bind(Option::<Vec<u8>>::None);
                });
                if let Err(e) = qb.build().execute(&self.pool).await {
                    eprintln!("Error inserting scan entries: {e:?}");
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub async fn set_scan_status(
        &self,
        scan_id: &i64,
        status: &str,
    ) -> Result<String, sqlx::Error> {
        sqlx::query("UPDATE scans SET status = $1 WHERE id = $2")
            .bind(status)
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        Ok(status.to_string())
    }

    pub async fn reset_halted_scan_entries(&self, scan_id: &i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE scan_entries SET status = 'queued' WHERE status = 'processing' AND scan_id = $1",
        )
        .bind(scan_id)
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

    pub async fn get_work_one(&self, scan_id: &i64) -> Result<Work, sqlx::Error> {
        let scan_entry = sqlx::query_as::<_, ScanEntry>(
            r#"
            UPDATE scan_entries
            SET status = 'scanning'
            WHERE id = (
                SELECT id FROM scan_entries
                WHERE scan_id = $1 AND status = 'queued'
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING *
            "#,
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        let url_string = sqlx::query_scalar::<_, String>("SELECT url FROM urls WHERE id = $1")
            .bind(scan_entry.url_id)
            .fetch_one(&self.pool)
            .await?;

        let word_string = sqlx::query_scalar::<_, String>("SELECT word FROM words WHERE id = $1")
            .bind(scan_entry.word_id)
            .fetch_one(&self.pool)
            .await?;

        let full_url = url_string.replace(&self.config.fuzz_marker, &word_string);

        Ok(Work {
            url: full_url,
            entry_id: scan_entry.id,
            method: self.config.http_method.to_string(),
        })
    }

    /// Drop all ambulo tables (used by --recreate-db in CLI mode).
    pub async fn drop_tables(&self) -> Result<(), sqlx::Error> {
        for table in &[
            "operations",
            "logs",
            "scan_entries",
            "urls",
            "scans",
            "words",
            "wordlists",
        ] {
            sqlx::query(&format!("DROP TABLE IF EXISTS {table} CASCADE"))
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Return a clone of this AmbuloDb but with a different config (used by daemon per-scan).
    pub fn clone_with_config(&self, config: crate::libs::cli_args::Args) -> Self {
        Self {
            pool: self.pool.clone(),
            config,
        }
    }

    // --- Operations (daemon mode) ---

    pub async fn create_operation(
        &self,
        id: &str,
        operation: &str,
        params: &str,
    ) -> Result<Operation, sqlx::Error> {
        sqlx::query_as::<_, Operation>(
            "INSERT INTO operations (id, operation, params, status) VALUES ($1, $2, $3, 'queued') RETURNING *",
        )
        .bind(id)
        .bind(operation)
        .bind(params)
        .fetch_one(&self.pool)
        .await
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
}

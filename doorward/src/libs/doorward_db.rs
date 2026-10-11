use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};

pub struct DoorwardDb {
    pub pool: Pool<Postgres>,
}

impl DoorwardDb {
    pub async fn init(
        host: &str,
        port: u16,
        user: &str,
        password: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let admin_url = match password {
            Some(pw) => format!("postgresql://{user}:{pw}@{host}:{port}/postgres"),
            None => format!("postgresql://{user}@{host}:{port}/postgres"),
        };

        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;

        // Create the `pulse` database if it doesn't exist. It keeps the engine's
        // original name: it holds resumable scan state, and renaming it would drop
        // every run an operator could still resume.
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'pulse')")
                .fetch_one(&admin_pool)
                .await?;

        if !exists {
            sqlx::query("CREATE DATABASE pulse")
                .execute(&admin_pool)
                .await?;
            println!("Created database: pulse");
        }

        admin_pool.close().await;

        // Connect to the `pulse` database
        let db_url = match password {
            Some(pw) => format!("postgresql://{user}:{pw}@{host}:{port}/pulse"),
            None => format!("postgresql://{user}@{host}:{port}/pulse"),
        };

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn create_tables(&self) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS scans (
                id              TEXT PRIMARY KEY,
                config_hash     TEXT NOT NULL,
                targets         TEXT NOT NULL,
                ports           TEXT NOT NULL,
                technique       TEXT NOT NULL DEFAULT 'connect',
                status          TEXT NOT NULL DEFAULT 'pending',
                created_at      TEXT DEFAULT NOW()::TEXT,
                updated_at      TEXT DEFAULT NOW()::TEXT
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS scan_entries (
                id              BIGSERIAL PRIMARY KEY,
                scan_id         TEXT NOT NULL REFERENCES scans(id),
                host            TEXT NOT NULL,
                port            INTEGER NOT NULL,
                status          TEXT NOT NULL DEFAULT 'queued',
                service         TEXT,
                banner          TEXT,
                latency_ms      BIGINT DEFAULT 0,
                created_at      TEXT DEFAULT NOW()::TEXT,
                updated_at      TEXT DEFAULT NOW()::TEXT,
                UNIQUE (scan_id, host, port)
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS logs (
                id              BIGSERIAL PRIMARY KEY,
                scan_id         TEXT,
                level           TEXT DEFAULT 'info',
                message         TEXT NOT NULL,
                created_at      TEXT DEFAULT NOW()::TEXT
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS operations (
                id              TEXT PRIMARY KEY,
                operation       TEXT NOT NULL,
                params          TEXT DEFAULT '{}',
                status          TEXT DEFAULT 'queued',
                result          TEXT,
                created_at      TEXT DEFAULT NOW()::TEXT,
                updated_at      TEXT DEFAULT NOW()::TEXT
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS probe_results (
                id              BIGSERIAL PRIMARY KEY,
                operation_id    TEXT NOT NULL,
                host            TEXT NOT NULL,
                port            INTEGER NOT NULL,
                status          TEXT NOT NULL,
                service         TEXT,
                banner          TEXT,
                latency_ms      BIGINT DEFAULT 0,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                delete_after    TIMESTAMPTZ NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_operation(
        &self,
        id: &str,
        operation: &str,
        params: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(
            "INSERT INTO operations (id, operation, params) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET params = $3, status = 'queued', updated_at = NOW()::TEXT",
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(
            "UPDATE operations SET status = $2, result = $3, updated_at = NOW()::TEXT WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(result)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn truncate_tables(&self) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query("TRUNCATE probe_results, logs, scan_entries, operations, scans CASCADE")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_expired_probe_results(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let result = sqlx::query("DELETE FROM probe_results WHERE delete_after < NOW()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

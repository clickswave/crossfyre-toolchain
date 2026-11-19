//! What toolmark keeps: the hosts it looked at, what it saw on each, the products and
//! services it found there, and when they changed. Other engines read it through the
//! `inventory` view.

use crate::observe::{Observation, Observer};
use cfx_db::scans::{Key, Running, Status};
use serde_json::Value;
use std::io::Write;

/// toolmark's part of the database: its schema, and the files that make its tables.
pub const ENGINE: cfx_db::Engine = cfx_db::Engine {
    name: "toolmark",
    version: env!("CARGO_PKG_VERSION"),
    migrations: &[include_str!("../../migrations/0001_inventory.sql")],
};

#[derive(Clone)]
pub struct ToolmarkDb {
    pool: sqlx::PgPool,
}

impl ToolmarkDb {
    /// toolmark's tables on `pool`, a pool [`cfx_db::ensure_ready`] gave for [`ENGINE`].
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// A handle that has never connected and gives up at once when used, for tests of
    /// daemon paths that run without a database: their scans are not kept.
    #[cfg(test)]
    pub fn unconnected() -> Self {
        let opts = sqlx::postgres::PgConnectOptions::new()
            .host("127.0.0.1")
            .port(1)
            .username("none")
            .database("none");
        Self {
            pool: sqlx::postgres::PgPoolOptions::new()
                .acquire_timeout(std::time::Duration::from_millis(100))
                .connect_lazy_with(opts),
        }
    }

    /// The pool, for the tables every engine has.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }

    /// Start keeping a scan, an `operation` of `target` asked for with `params`. A scan
    /// with credentials is known by its id alone; one without, by its settings. Every
    /// scan is a new one, as toolmark keeps nothing a stopped scan could carry on from. A
    /// scan runs whether or not it could be kept, so a failure is only said.
    pub async fn start(&self, operation: &str, target: &str, params: &Value) -> Option<Running> {
        let asked = params.to_string();
        let hash = format!("{operation} {}", cfx_db::scans::without_secrets(&asked));
        let key = if cfx_db::scans::carries_credentials(&asked) {
            Key::Authenticated
        } else {
            Key::Settings(&hash)
        };
        match cfx_db::scans::start(&self.pool, target, key, &asked, true).await {
            Ok(scan) => Some(scan),
            Err(e) => {
                eprintln!("[toolmark] could not keep a record of the scan: {e}");
                None
            }
        }
    }

    /// Say that scan `scan`, if it was kept, has ended.
    pub async fn finish(&self, scan: Option<Running>, status: Status) {
        if let Some(scan) = scan {
            let _ = cfx_db::scans::finish(scan, status).await;
        }
    }

    /// What scan `scan` should keep of `event`: a product it found on a web host, or a
    /// service it found listening.
    pub async fn event(&self, scan: Option<&str>, event: &Value) {
        if scan.is_none() {
            return;
        }
        let kept = match (event["type"].as_str(), event["data"]["type"].as_str()) {
            (Some("finding"), Some("technology")) => self.fingerprint(&event["data"]).await,
            (Some("service"), _) => self.service(event).await,
            _ => Ok(()),
        };
        if let Err(e) = kept {
            eprintln!("[toolmark] could not keep a finding: {e}");
        }
    }

    /// The host `host`:`port`, made when it is new and marked seen now.
    async fn host(
        &self,
        tx: &mut sqlx::PgConnection,
        host: &str,
        port: i64,
        scheme: &str,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "INSERT INTO hosts (host, port, scheme) VALUES ($1, $2, $3) \
             ON CONFLICT (host, port) DO UPDATE SET last_seen = now(), \
             scheme = CASE WHEN $3 = '' THEN hosts.scheme ELSE $3 END RETURNING id",
        )
        .bind(host)
        .bind(port as i32)
        .bind(scheme)
        .fetch_one(&mut *tx)
        .await
    }

    /// A product found on a host: kept, with a change row when it is new there or its
    /// version is not the one it had.
    async fn fingerprint(&self, data: &Value) -> Result<(), sqlx::Error> {
        let product = data["name"].as_str().unwrap_or_default();
        if product.is_empty() {
            return Ok(());
        }
        let version = data["version"].as_str().unwrap_or_default();
        let cpe = data["cpe"].as_str().unwrap_or_default();
        // cpe:2.3:a:<vendor>:<product>:...
        let vendor = cpe.split(':').nth(3).unwrap_or_default();
        let mut tx = self.pool.begin().await?;
        let host = self
            .host(
                &mut tx,
                data["host"].as_str().unwrap_or_default(),
                data["port"].as_i64().unwrap_or_default(),
                data["scheme"].as_str().unwrap_or_default(),
            )
            .await?;
        let had: Option<String> = sqlx::query_scalar(
            "SELECT version FROM fingerprints WHERE host_id = $1 AND product = $2",
        )
        .bind(host)
        .bind(product)
        .fetch_optional(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO fingerprints \
             (host_id, product, vendor, version, cpe, confidence, evidence, signature_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $2) \
             ON CONFLICT (host_id, product) DO UPDATE SET vendor = $3, version = $4, cpe = $5, \
             confidence = $6, evidence = $7::jsonb, last_seen = now()",
        )
        .bind(host)
        .bind(product)
        .bind(vendor)
        .bind(version)
        .bind(cpe)
        .bind(data["confidence"].as_i64().unwrap_or_default() as i32)
        .bind(data["evidence"].to_string())
        .execute(&mut *tx)
        .await?;
        if had.as_deref() != Some(version) {
            sqlx::query(
                "INSERT INTO changes (host_id, product, old_version, new_version) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(host)
            .bind(product)
            .bind(had)
            .bind(version)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }

    /// A service found listening on a host's port, and whether it lets anyone in.
    async fn service(&self, data: &Value) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let host = self
            .host(
                &mut tx,
                data["host"].as_str().unwrap_or_default(),
                data["port"].as_i64().unwrap_or_default(),
                "",
            )
            .await?;
        let text = |v: &Value| match v {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        sqlx::query(
            "INSERT INTO services (host_id, service, version, banner, access) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (host_id, service) DO UPDATE SET \
             version = $3, banner = $4, access = $5, last_seen = now()",
        )
        .bind(host)
        .bind(text(&data["service"]))
        .bind(text(&data["version"]))
        .bind(cfx_db::scans::safe_text(&text(&data["banner"])))
        .bind(text(&data["auth"]))
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }

    /// What scan `scan`, asked for with `params`, sees, kept as it is seen.
    pub fn observer(&self, scan: Option<&Running>, params: &Value) -> ScanObserver {
        ScanObserver {
            db: self.clone(),
            scan: scan.map(|s| s.id.clone()),
            keep_body: !cfx_db::scans::carries_credentials(&params.to_string()),
        }
    }
}

/// One scan's [`Observer`], which keeps what it saw in toolmark's tables.
pub struct ScanObserver {
    db: ToolmarkDb,
    scan: Option<String>,
    /// Whether the pages it sees are kept whole. A scan with credentials sees them as
    /// the user they belong to, so it keeps none.
    keep_body: bool,
}

/// `body` gzipped.
fn gzipped(body: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = gz.write_all(body);
    gz.finish().unwrap_or_default()
}

impl Observer for ScanObserver {
    /// The headers are kept with no value for one that carries a credential, as an
    /// Authorization header does, except that a Set-Cookie keeps the cookie's name, which
    /// signatures match. The body is kept as read, gzipped.
    async fn observed(&self, o: Observation<'_>) {
        let Some(scan) = &self.scan else {
            return;
        };
        let headers: Vec<Value> = o
            .headers
            .iter()
            .map(|(name, value)| {
                let kept = if name == "set-cookie" {
                    let cookie = value.split(['=', ';']).next().unwrap_or_default();
                    Value::String(format!("{}=", cookie.trim()))
                } else if cfx_db::scans::secret_name(name) {
                    Value::Null
                } else {
                    Value::String(value.clone())
                };
                serde_json::json!([name, kept])
            })
            .collect();
        let body = self.keep_body.then(|| gzipped(o.body));
        let kept = async {
            let mut tx = self.db.pool.begin().await?;
            let host = self
                .db
                .host(&mut tx, o.host, i64::from(o.port), o.scheme)
                .await?;
            sqlx::query(
                "INSERT INTO observations (scan_id, host_id, url, status, headers, body, body_length) \
                 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)",
            )
            .bind(scan)
            .bind(host)
            .bind(cfx_db::scans::safe_url(o.url))
            .bind(i32::from(o.status))
            .bind(Value::Array(headers).to_string())
            .bind(body)
            .bind(o.body.len() as i64)
            .execute(&mut *tx)
            .await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = kept {
            eprintln!("[toolmark] could not keep what the scan saw: {e}");
        }
    }
}

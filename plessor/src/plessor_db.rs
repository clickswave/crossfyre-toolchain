//! What plessor keeps: its scans, the plan of each template scan with the state of every
//! template in it, and what each scan found.

use crate::ledger::{Ledger, Planned, Planning, State};
use cfx_db::scans::{Key, Running, Status};
use serde_json::Value;

/// plessor's part of the database: its schema, and the files that make its tables.
pub const ENGINE: cfx_db::Engine = cfx_db::Engine {
    name: "plessor",
    version: env!("CARGO_PKG_VERSION"),
    migrations: &[include_str!("../migrations/0001_plans_findings.sql")],
};

#[derive(Clone)]
pub struct PlessorDb {
    pool: sqlx::PgPool,
}

impl PlessorDb {
    /// plessor's tables on `pool`, a pool [`cfx_db::ensure_ready`] gave for [`ENGINE`].
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

    /// Start keeping an `operation` asked for with `params`. One with credentials is known
    /// by its id alone; one without, by its settings. A template scan with the same
    /// settings as a stopped one takes it up again and carries on with what it had not
    /// run. Any other operation keeps nothing it could carry on from, so it is a new scan
    /// every time. An operation runs whether or not it could be kept, so a failure is
    /// only said.
    pub async fn start(&self, operation: &str, params: &Value) -> Option<Running> {
        let asked = params.to_string();
        let hash = format!("{operation} {}", cfx_db::scans::without_secrets(&asked));
        let key = if cfx_db::scans::carries_credentials(&asked) {
            Key::Authenticated
        } else {
            Key::Settings(&hash)
        };
        let target = ["target", "url", "endpoint"]
            .iter()
            .find_map(|k| params[*k].as_str().map(str::to_string))
            .or_else(|| {
                params["urls"].as_array().map(|urls| {
                    urls.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
            })
            .unwrap_or_else(|| operation.to_string());
        let fresh = operation != "scan";
        match cfx_db::scans::start(&self.pool, &target, key, &asked, fresh).await {
            Ok(scan) => Some(scan),
            Err(e) => {
                eprintln!("[plessor] could not keep a record of the {operation}: {e}");
                None
            }
        }
    }

    /// Say where scan `scan`, if it was kept, ended.
    pub async fn finish(&self, scan: Option<Running>, status: Status) {
        if let Some(scan) = scan {
            let _ = cfx_db::scans::finish(scan, status).await;
        }
    }

    /// Keep what scan `scan` found in `event`, when it is a finding, with no credential
    /// in it. A finding the scan has kept already is not kept again.
    pub async fn event(&self, scan: Option<&str>, event: &Value) {
        let (Some(scan), "finding") = (scan, event["type"].as_str().unwrap_or_default()) else {
            return;
        };
        let kept = sqlx::query(
            "INSERT INTO findings (scan_id, template_id, data, digest) \
             VALUES ($1, $2, $3::jsonb, md5($3::jsonb::text)) \
             ON CONFLICT (scan_id, digest) DO NOTHING",
        )
        .bind(scan)
        .bind(event["data"]["template"].as_str())
        .bind(cfx_db::scans::safe_json(&event["data"]).to_string())
        .execute(&self.pool)
        .await;
        if let Err(e) = kept {
            eprintln!("[plessor] could not keep a finding: {e}");
        }
    }

    /// The [`Ledger`] of template scan `scan`.
    pub fn ledger(&self, scan: Option<String>) -> ScanLedger {
        ScanLedger {
            db: self.clone(),
            scan,
        }
    }
}

/// One template scan's [`Ledger`], kept in plessor's tables.
pub struct ScanLedger {
    db: PlessorDb,
    scan: Option<String>,
}

impl ScanLedger {
    async fn make_plan(
        &self,
        scan: &str,
        pack: &str,
        templates: &[Planned],
    ) -> Result<Planning, sqlx::Error> {
        let mut tx = self.db.pool.begin().await?;
        let had: Option<String> = sqlx::query_scalar("SELECT pack FROM plans WHERE scan_id = $1")
            .bind(scan)
            .fetch_optional(&mut *tx)
            .await?;
        if had.as_deref() == Some(pack) {
            let done: Vec<String> = sqlx::query_scalar(
                "SELECT template_id FROM template_states \
                 WHERE scan_id = $1 AND state IN ('sent', 'confirmed')",
            )
            .bind(scan)
            .fetch_all(&mut *tx)
            .await?;
            let found: Vec<Value> = sqlx::query_scalar(
                "SELECT f.data FROM findings f JOIN template_states s \
                 ON s.scan_id = f.scan_id AND s.template_id = f.template_id \
                 WHERE f.scan_id = $1 AND s.state = 'confirmed' ORDER BY f.id",
            )
            .bind(scan)
            .fetch_all(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(Planning {
                done: done.into_iter().collect(),
                found,
                replanned: false,
            });
        }
        // Starting over: what the templates of the old plan found goes with it.
        sqlx::query(
            "DELETE FROM findings WHERE scan_id = $1 AND template_id IN \
             (SELECT template_id FROM template_states WHERE scan_id = $1)",
        )
        .bind(scan)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM template_states WHERE scan_id = $1")
            .bind(scan)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO plans (scan_id, pack) VALUES ($1, $2) \
             ON CONFLICT (scan_id) DO UPDATE SET pack = $2",
        )
        .bind(scan)
        .bind(pack)
        .execute(&mut *tx)
        .await?;
        let mut rows: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
            "INSERT INTO template_states (scan_id, position, template_id, state, reason) ",
        );
        rows.push_values(templates.iter().enumerate(), |mut row, (i, t)| {
            row.push_bind(scan)
                .push_bind(i as i32)
                .push_bind(&t.id)
                .push_bind(t.state.as_str())
                .push_bind(t.reason);
        });
        rows.push(" ON CONFLICT (scan_id, template_id) DO NOTHING");
        if !templates.is_empty() {
            rows.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(Planning {
            replanned: had.is_some(),
            ..Planning::default()
        })
    }
}

impl Ledger for ScanLedger {
    async fn plan(&self, pack: &str, templates: &[Planned]) -> Planning {
        let Some(scan) = &self.scan else {
            return Planning::default();
        };
        match self.make_plan(scan, pack, templates).await {
            Ok(planning) => planning,
            Err(e) => {
                eprintln!("[plessor] could not keep the scan's plan: {e}");
                Planning::default()
            }
        }
    }

    async fn state(&self, id: &str, state: State) {
        let Some(scan) = &self.scan else {
            return;
        };
        let _ = sqlx::query(
            "UPDATE template_states SET state = $3, updated_at = now() \
             WHERE scan_id = $1 AND template_id = $2",
        )
        .bind(scan)
        .bind(id)
        .bind(state.as_str())
        .execute(&self.db.pool)
        .await;
    }
}

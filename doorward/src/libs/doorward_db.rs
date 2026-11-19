use sqlx::{Pool, Postgres};

/// doorward's part of the database. It keeps nothing of its own: its scans and the
/// operations it was sent are in the tables every engine has.
pub const ENGINE: cfx_db::Engine = cfx_db::Engine {
    name: "doorward",
    version: env!("CARGO_PKG_VERSION"),
    migrations: &[],
};

pub struct DoorwardDb {
    pub pool: Pool<Postgres>,
}

impl DoorwardDb {
    /// doorward's tables on `pool`, a pool [`cfx_db::ensure_ready`] gave for [`ENGINE`].
    pub fn new(pool: Pool<Postgres>) -> Self {
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

    /// Start keeping a scan of `targets`, asked for with `params`: a stopped one with the
    /// same settings is run again from the start, as a port scan keeps nothing to resume
    /// from. The settings, without credentials, are the key. A scan runs whether or not
    /// it could be kept, so a failure is only said.
    pub async fn start_scan(
        &self,
        targets: &[String],
        params: &serde_json::Value,
    ) -> Option<String> {
        let params = cfx_db::scans::without_secrets(&params.to_string());
        match cfx_db::scans::start(&self.pool, &targets.join(", "), &params, &params, false).await {
            Ok(scan) => Some(scan.id),
            Err(e) => {
                eprintln!("[doorward] could not keep a record of the scan: {e}");
                None
            }
        }
    }

    /// Say that scan `scan`, if it was kept, has ended.
    pub async fn finish_scan(&self, scan: Option<&str>) {
        if let Some(id) = scan {
            let _ = cfx_db::scans::finish(&self.pool, id, cfx_db::scans::Status::Completed).await;
        }
    }
}

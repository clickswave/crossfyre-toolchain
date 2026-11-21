//! What toolmark keeps: the hosts it looked at, what it saw on each, the products and
//! services it found there, and when they changed. Other engines read it through the
//! `inventory` view.

use crate::observe::{Asked, Observation, Observer};
use cfx_db::scans::{Key, Running, Status};
use serde_json::Value;
use std::io::Write;

/// Why no toolmark scan is taken up again.
pub const NOTHING_TO_TAKE_UP: &str =
    "toolmark keeps nothing to carry on from, so a scan is run again rather than taken up";

/// toolmark's part of the database: its schema, and the files that make its tables.
pub const ENGINE: cfx_db::Engine = cfx_db::Engine {
    name: "toolmark",
    schema: "toolmark",
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
        let asked = cfx_db::scans::Asked::new(target, &asked);
        match cfx_db::scans::start(&self.pool, asked, key, true).await {
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

    /// What scan `scan` should keep of `event`: a product it found on a web host, a CVE
    /// lead it reported, or a service it found listening.
    pub async fn event(&self, scan: Option<&str>, event: &Value) {
        if scan.is_none() {
            return;
        }
        let kept = match (event["type"].as_str(), event["data"]["type"].as_str()) {
            (Some("finding"), Some("technology")) => self.fingerprint(&event["data"]).await,
            (Some("finding"), Some("vulnerability"))
                if event["data"]["source"] == "toolmark-cve" =>
            {
                self.lead(&event["data"]).await
            }
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
        let distro = data["distro"].as_str().unwrap_or_default();
        let cpe_names = data["cpe_names"].to_string();
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
             (host_id, product, vendor, version, cpe, cpe_names, distro, confidence, evidence, \
             signature_id) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9::jsonb, $2) \
             ON CONFLICT (host_id, product) DO UPDATE SET vendor = $3, version = $4, cpe = $5, \
             cpe_names = $6::jsonb, distro = $7, confidence = $8, evidence = $9::jsonb, \
             last_seen = now()",
        )
        .bind(host)
        .bind(product)
        .bind(vendor)
        .bind(version)
        .bind(cpe)
        .bind(if data["cpe_names"].is_array() {
            cpe_names
        } else {
            "[]".to_string()
        })
        .bind(distro)
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
            // What a scan said of the product's leads was about the version before.
            sqlx::query(
                "UPDATE leads SET answer = NULL, answer_template = '', answer_reason = '', \
                 answered_at = NULL, answer_scan = '' WHERE host_id = $1 AND product = $2",
            )
            .bind(host)
            .bind(product)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }

    /// What plessor scan `scan` said of the leads of `host`:`port`, as the client that gave
    /// it the leads writes back, kept with each lead, and a lead not kept yet kept with its
    /// answer. Nothing is written for a host toolmark never looked at. The number kept.
    pub async fn answer_leads(
        &self,
        host: &str,
        port: u16,
        scan: &str,
        answers: &[cfx_cve::inventory::LeadAnswer],
    ) -> Result<usize, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let host_id: Option<i64> =
            sqlx::query_scalar("SELECT id FROM hosts WHERE lower(host) = lower($1) AND port = $2")
                .bind(host)
                .bind(i32::from(port))
                .fetch_optional(&mut *tx)
                .await?;
        let Some(host_id) = host_id else {
            return Ok(0);
        };
        for a in answers {
            sqlx::query(
                "INSERT INTO leads (host_id, product, cve, answer, answer_template, \
                 answer_reason, answered_at, answer_scan) \
                 VALUES ($1, $2, $3, $4, $5, $6, now(), $7) \
                 ON CONFLICT (host_id, product, cve) DO UPDATE SET answer = $4, \
                 answer_template = $5, answer_reason = $6, answered_at = now(), answer_scan = $7",
            )
            .bind(host_id)
            .bind(&a.product)
            .bind(&a.cve)
            .bind(a.answer.as_str())
            .bind(a.template.as_deref().unwrap_or_default())
            .bind(a.reason.as_deref().unwrap_or_default())
            .bind(scan)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(answers.len())
    }

    /// Every lead a scan has answered, with where, for the inventory to show.
    pub async fn answered(&self) -> Vec<Answered> {
        let rows: Result<Vec<AnsweredRow>, _> = sqlx::query_as(
            "SELECT h.host, h.port, l.product, l.cve, l.answer, l.answer_template, \
                 l.answer_reason, \
                 to_char(l.answered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                 l.answer_scan \
             FROM leads l JOIN hosts h ON h.id = l.host_id WHERE l.answer IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await;
        match rows {
            Ok(rows) => rows
                .into_iter()
                .map(
                    |(host, port, product, cve, answer, template, reason, at, scan)| Answered {
                        host,
                        port: u16::try_from(port).unwrap_or_default(),
                        product,
                        cve,
                        answer,
                        template,
                        reason,
                        at,
                        scan,
                    },
                )
                .collect(),
            Err(e) => {
                eprintln!("[toolmark] could not read the answered leads: {e}");
                Vec::new()
            }
        }
    }

    /// A CVE lead reported for a product on a host, kept once.
    async fn lead(&self, data: &Value) -> Result<(), sqlx::Error> {
        let (Some(product), Some(cve)) = (data["product"].as_str(), data["cve"].as_str()) else {
            return Ok(());
        };
        let mut tx = self.pool.begin().await?;
        let host = self
            .host(
                &mut tx,
                data["host"].as_str().unwrap_or_default(),
                data["port"].as_i64().unwrap_or_default(),
                data["scheme"].as_str().unwrap_or_default(),
            )
            .await?;
        sqlx::query(
            "INSERT INTO leads (host_id, product, cve) VALUES ($1, $2, $3) \
             ON CONFLICT (host_id, product, cve) DO NOTHING",
        )
        .bind(host)
        .bind(product)
        .bind(cve)
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }

    /// Each product the inventory holds at a version, with what is needed to look up its
    /// CVE leads and the leads already reported for it.
    pub async fn stored(&self) -> Result<Vec<Stored>, sqlx::Error> {
        let rows: Vec<StoredRow> = sqlx::query_as(
            "SELECT h.host, h.port, h.scheme, f.product, f.version, f.cpe_names::text, f.distro, \
                 COALESCE(array_agg(l.cve) FILTER (WHERE l.cve IS NOT NULL), '{}') \
             FROM fingerprints f JOIN hosts h ON h.id = f.host_id \
             LEFT JOIN leads l ON l.host_id = f.host_id AND l.product = f.product \
             WHERE f.version <> '' \
             GROUP BY h.host, h.port, h.scheme, f.product, f.version, f.cpe_names::text, f.distro \
             ORDER BY h.host, h.port, f.product",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(host, port, scheme, product, version, names, distro, reported)| Stored {
                    host,
                    port: u16::try_from(port).unwrap_or_default(),
                    scheme,
                    product,
                    version,
                    cpes: serde_json::from_str::<Vec<String>>(&names)
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|n| cfx_cve::Cpe::parse(n))
                        .collect(),
                    distro: (!distro.is_empty()).then_some(distro),
                    reported: reported.into_iter().collect(),
                },
            )
            .collect())
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

    /// What this daemon answers an `inventory` request with: each product toolmark found,
    /// on its host and port, with its version, by host.
    pub async fn inventory(&self) -> Value {
        let rows: Result<Vec<InventoryRow>, _> = sqlx::query_as(
            "SELECT host, port, vendor, product, version, cpe, cpe_names::text, distro, \
                 to_char(last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
                 FROM inventory ORDER BY host, port, product",
        )
        .fetch_all(&self.pool)
        .await;
        match rows {
            Ok(rows) => serde_json::json!({
                "status": "completed",
                "inventory": rows
                    .into_iter()
                    .map(|(host, port, vendor, product, version, cpe, names, distro, last_seen)| {
                        let names: Value = serde_json::from_str(&names).unwrap_or_default();
                        serde_json::json!({
                            "host": host, "port": port, "vendor": vendor, "product": product,
                            "version": version, "cpe": cpe, "cpe_names": names,
                            "distro": distro, "last_seen": last_seen,
                        })
                    })
                    .collect::<Vec<_>>(),
            }),
            Err(e) => serde_json::json!({
                "status": "error",
                "message": format!("could not read the inventory: {e}"),
            }),
        }
    }

    /// What toolmark kept of each host it has fetched a landing page of: the pages of the
    /// latest scan that did, and what it has found there.
    pub async fn kept(&self) -> Result<Vec<KeptHost>, sqlx::Error> {
        let latest: Vec<(i64, String, String, i32, String)> = sqlx::query_as(
            "SELECT DISTINCT ON (o.host_id) o.host_id, o.scan_id, h.host, h.port, h.scheme \
             FROM observations o JOIN hosts h ON h.id = o.host_id WHERE o.asked = 'landing' \
             ORDER BY o.host_id, o.observed_at DESC, o.id DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::new();
        for (host_id, scan, host, port, scheme) in latest {
            let rows: Vec<KeptRow> = sqlx::query_as(
                "SELECT asked, url, status, moved, headers::text, body, certificate \
                 FROM observations WHERE scan_id = $1 AND host_id = $2 ORDER BY id",
            )
            .bind(&scan)
            .bind(host_id)
            .fetch_all(&self.pool)
            .await?;
            let pages = rows
                .into_iter()
                .filter_map(|(asked, url, status, moved, headers, body, certificate)| {
                    let headers: Vec<(String, Option<String>)> =
                        serde_json::from_str(&headers).unwrap_or_default();
                    Some(Kept {
                        asked: Asked::from_str(&asked)?,
                        url,
                        status: u16::try_from(status).ok()?,
                        moved,
                        headers: headers
                            .into_iter()
                            .filter_map(|(name, value)| Some((name, value?)))
                            .collect(),
                        body: body.as_deref().map(gunzipped).unwrap_or_default(),
                        certificate,
                    })
                })
                .collect();
            let found =
                sqlx::query_as("SELECT product, version FROM fingerprints WHERE host_id = $1")
                    .bind(host_id)
                    .fetch_all(&self.pool)
                    .await?
                    .into_iter()
                    .collect();
            out.push(KeptHost {
                host,
                port: u16::try_from(port).unwrap_or_default(),
                scheme,
                pages,
                found,
            });
        }
        Ok(out)
    }

    /// What this daemon answers a `scans` request with: its scans, none of which can be
    /// taken up again.
    pub async fn scans(&self) -> Value {
        cfx_db::scans::answer_scans(&self.pool, |_| Some(NOTHING_TO_TAKE_UP.to_string())).await
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

/// A lead a plessor scan answered: where, what it said, by which template or why none,
/// when, and which scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered {
    pub host: String,
    pub port: u16,
    pub product: String,
    pub cve: String,
    pub answer: String,
    pub template: String,
    pub reason: String,
    pub at: String,
    pub scan: String,
}

type AnsweredRow = (
    String,
    i32,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// A product the inventory holds at a version, where, and the leads reported for it.
pub struct Stored {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub product: String,
    pub version: String,
    /// The products it may be, by their CPEs.
    pub cpes: Vec<cfx_cve::Cpe>,
    pub distro: Option<String>,
    /// The CVEs already reported for it there.
    pub reported: std::collections::HashSet<String>,
}

type StoredRow = (
    String,
    i32,
    String,
    String,
    String,
    String,
    String,
    Vec<String>,
);

/// A page a scan kept: what it was asked for, where, and what came back.
pub struct Kept {
    pub asked: Asked,
    pub url: String,
    pub status: u16,
    pub moved: bool,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The certificate a landing page came with, when it came over TLS.
    pub certificate: Option<Vec<u8>>,
}

/// What toolmark kept of one host: the pages of the latest scan that fetched its landing
/// page, and the version of each product it has found there, empty for none.
pub struct KeptHost {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub pages: Vec<Kept>,
    pub found: std::collections::BTreeMap<String, String>,
}

/// One kept page as the observations table holds it: what it was asked for, its URL,
/// status, whether it moved, its headers as JSON text, its gzipped body, and the
/// certificate it came with.
type KeptRow = (
    String,
    String,
    i32,
    bool,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// `body` as it was before it was gzipped, read no further than a fingerprint reads.
fn gunzipped(body: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    let _ = flate2::read::GzDecoder::new(body)
        .take(8 * 1024 * 1024)
        .read_to_end(&mut out);
    out
}

/// One row of the inventory view: host, port, vendor, product, version, CPE and when it
/// was last seen.
type InventoryRow = (
    String,
    i32,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

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

/// `headers` as an observation keeps them, each as [name, value] in the order they came:
/// a Set-Cookie with only the cookie's name, which signatures match, no value for a header
/// that carries a credential, as an Authorization header does, and every other value with
/// the URLs in it made safe, as a Location carrying an authorization code needs.
fn kept_headers(headers: &[(String, String)]) -> Vec<Value> {
    headers
        .iter()
        .map(|(name, value)| {
            let kept = if name == "set-cookie" {
                let cookie = value.split(['=', ';']).next().unwrap_or_default();
                Value::String(format!("{}=", cookie.trim()))
            } else if cfx_db::scans::secret_name(name) {
                Value::Null
            } else {
                Value::String(cfx_db::scans::safe_text(value))
            };
            serde_json::json!([name, kept])
        })
        .collect()
}

impl Observer for ScanObserver {
    /// The headers are kept as [`kept_headers`] keeps them, and the body as read, gzipped.
    async fn observed(&self, o: Observation<'_>) {
        let Some(scan) = &self.scan else {
            return;
        };
        let headers = kept_headers(o.headers);
        let body = self.keep_body.then(|| gzipped(o.body));
        let kept = async {
            let mut tx = self.db.pool.begin().await?;
            let host = self
                .db
                .host(&mut tx, o.host, i64::from(o.port), o.scheme)
                .await?;
            sqlx::query(
                "INSERT INTO observations \
                 (scan_id, host_id, asked, url, status, moved, headers, body, body_length, \
                 certificate) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)",
            )
            .bind(scan)
            .bind(host)
            .bind(o.asked.as_str())
            .bind(cfx_db::scans::safe_url(o.url))
            .bind(i32::from(o.status))
            .bind(o.moved)
            .bind(Value::Array(headers).to_string())
            .bind(body)
            .bind(o.body.len() as i64)
            .bind(o.certificate)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A product toolmark found on `host`, as a fingerprint reports it.
    fn found(host: &str, product: &str, version: &str, cpe: &str) -> Value {
        serde_json::json!({"type": "finding", "data": {
            "type": "technology", "host": host, "port": 443, "scheme": "https",
            "name": product, "category": "Web Server", "version": version, "cpe": cpe,
            "confidence": 50, "evidence": ["header server: x"],
        }})
    }

    /// A host whose version of a product changed between two scans is in the inventory
    /// once, at the newer version, seen at the second scan.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn the_inventory_holds_each_product_once_at_its_newest_version() {
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let mut seen = Vec::new();
        for (version, cpe) in [
            ("1.24.0", "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"),
            ("1.25.3", "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"),
        ] {
            let params = serde_json::json!({"target": "https://app.test/"});
            let scan = db.start("fingerprint", "https://app.test/", &params).await;
            db.event(
                scan.as_ref().map(|s| s.id.as_str()),
                &found("app.test", "Nginx", version, cpe),
            )
            .await;
            db.finish(scan, Status::Completed).await;
            seen.push(database_now(&db).await);
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }
        let inventory = db.inventory().await;
        assert_eq!(inventory["status"], "completed", "{inventory}");
        let rows = inventory["inventory"].as_array().expect("rows");
        assert_eq!(rows.len(), 1, "{inventory}");
        let row = &rows[0];
        assert_eq!(
            (
                &row["host"],
                &row["port"],
                &row["product"],
                &row["vendor"],
                &row["version"]
            ),
            (
                &serde_json::json!("app.test"),
                &serde_json::json!(443),
                &serde_json::json!("Nginx"),
                &serde_json::json!("f5"),
                &serde_json::json!("1.25.3")
            ),
            "{inventory}"
        );
        assert_eq!(
            (&row["cpe_names"], &row["distro"]),
            (&serde_json::json!([]), &serde_json::json!(""))
        );
        let last_seen = row["last_seen"].as_str().expect("last seen");
        assert!(
            seen[0].as_str() < last_seen && last_seen <= seen[1].as_str(),
            "seen at the second scan: {last_seen}, scans at {seen:?}"
        );
        scratch.done().await;
    }

    /// What a plessor scan said of a host's leads is kept with each lead, and a new
    /// version of the product there clears it; a host toolmark never looked at keeps
    /// nothing.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn an_answer_is_kept_until_the_version_changes() {
        use cfx_cve::inventory::{Answer, LeadAnswer};
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let scan_of = async |version: &str| {
            let params = serde_json::json!({"target": "https://app.test/"});
            let scan = db.start("fingerprint", "https://app.test/", &params).await;
            let cpe = format!("cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*");
            db.event(
                scan.as_ref().map(|s| s.id.as_str()),
                &found("app.test", "Apache HTTP Server", version, &cpe),
            )
            .await;
            db.finish(scan, Status::Completed).await;
        };
        scan_of("2.4.49").await;
        let answer = |cve: &str, answer: Answer, template: Option<&str>| LeadAnswer {
            cve: cve.into(),
            product: "Apache HTTP Server".into(),
            answer,
            template: template.map(str::to_string),
            reason: None,
        };
        let kept = db
            .answer_leads(
                "app.test",
                443,
                "s1",
                &[
                    answer("CVE-2021-41773", Answer::Confirmed, Some("CVE-2021-41773")),
                    answer("CVE-2021-42013", Answer::NotFound, Some("CVE-2021-42013")),
                ],
            )
            .await
            .unwrap();
        assert_eq!(kept, 2);
        let said: Vec<(String, String, String, String)> = db
            .answered()
            .await
            .into_iter()
            .map(|a| (a.cve, a.answer, a.template, a.scan))
            .collect();
        assert_eq!(
            said,
            [
                (
                    "CVE-2021-41773".into(),
                    "confirmed".into(),
                    "CVE-2021-41773".into(),
                    "s1".into()
                ),
                (
                    "CVE-2021-42013".into(),
                    "checked, not found".into(),
                    "CVE-2021-42013".into(),
                    "s1".into()
                ),
            ]
        );
        assert_eq!(
            db.answer_leads(
                "unseen.test",
                443,
                "s1",
                &[answer("CVE-2021-41773", Answer::Confirmed, None)]
            )
            .await
            .unwrap(),
            0
        );
        scan_of("2.4.49").await;
        assert_eq!(db.answered().await.len(), 2, "the same version keeps them");
        scan_of("2.4.50").await;
        assert_eq!(db.answered().await, [], "a new version clears them");
        scratch.done().await;
    }

    /// The page a browser built is kept as a fetched body is: gzipped, and not at all for
    /// a scan that carried a credential.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_rendered_page_is_kept_as_a_body_is() {
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let built = b"<html><body><app-root ng-version=\"17.3.0\"></app-root></body></html>";
        for params in [
            serde_json::json!({"target": "https://app.test/"}),
            serde_json::json!({"target": "https://app.test/",
                "headers": {"Authorization": "Bearer not-kept"}}),
        ] {
            let scan = db.start("fingerprint", "https://app.test/", &params).await;
            db.observer(scan.as_ref(), &params)
                .observed(Observation {
                    asked: Asked::Rendered,
                    url: "https://app.test/",
                    host: "app.test",
                    port: 443,
                    scheme: "https",
                    status: 200,
                    headers: &[],
                    body: built,
                    moved: false,
                    certificate: None,
                })
                .await;
            db.finish(scan, Status::Completed).await;
        }
        let kept: Vec<(Option<Vec<u8>>, i64)> = sqlx::query_as(
            "SELECT body, body_length FROM observations WHERE asked = 'rendered' ORDER BY id",
        )
        .fetch_all(db.pool())
        .await
        .expect("kept");
        let length = built.len() as i64;
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert_eq!(
            kept[0].0.as_deref().map(gunzipped).as_deref(),
            Some(&built[..])
        );
        assert_eq!(kept[0].1, length);
        assert_eq!(
            kept[1],
            (None, length),
            "a scan with a credential keeps no body"
        );
        scratch.done().await;
    }

    /// The database's clock now, as the inventory writes a time.
    async fn database_now(db: &ToolmarkDb) -> String {
        sqlx::query_scalar(
            "SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
        )
        .fetch_one(db.pool())
        .await
        .expect("now")
    }

    #[test]
    fn a_header_keeps_no_credential_and_no_url_that_carried_one() {
        let seen = [
            ("location", "https://app.example/callback?code=c-1&state=s"),
            ("refresh", "0; url=https://app.example/?token=t-1"),
            ("link", "<https://app.example/next?sig=g-1>; rel=\"next\""),
            ("content-location", "https://u:p-1@app.example/a"),
            ("set-cookie", "sid=k-1; Path=/; HttpOnly"),
            ("authorization", "Bearer b-1"),
            ("server", "Apache/2.4.49 (Debian)"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));
        assert_eq!(
            Value::Array(kept_headers(&seen)),
            serde_json::json!([
                ["location", "https://app.example/callback?code=&state=s"],
                ["refresh", "0; url=https://app.example/?token="],
                ["link", "<https://app.example/next?sig=>; rel=\"next\""],
                ["content-location", "https://app.example/a"],
                ["set-cookie", "sid="],
                ["authorization", null],
                ["server", "Apache/2.4.49 (Debian)"],
            ])
        );
    }
}

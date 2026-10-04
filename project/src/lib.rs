//! The local project store.
//!
//! One project is one SQLite database plus a content-addressed blob directory beside it.
//! It exists so the workbench can hold a capture session with no control plane and no
//! network: a pentester on a client site with no outbound route, or under an NDA that
//! forbids sending a client's traffic to a vendor, is the normal case rather than the
//! awkward one.
//!
//! # Shape
//!
//! ```text
//! my-engagement.cfxproj/
//!   project.db          SQLite, WAL
//!   blobs/ab/abcdef...  bodies over INLINE_MAX, named by sha256, reference counted
//! ```
//!
//! A directory rather than a single file, because a 200 MB download has no business in a
//! database row and because a blob directory can be pruned, inspected and backed up with
//! ordinary tools.
//!
//! # What is indexed
//!
//! Full-text search covers the URL, the headers, and the first [`FTS_BODY_MAX`] bytes of a
//! body that looks like text. Not the whole body, deliberately. FTS5 can index without
//! storing a copy, but deleting from such a table needs either the original values or a
//! SQLite newer than this crate wants to require, and eviction has to be able to delete.
//! Indexing a bounded prefix keeps the index proportional to the number of exchanges
//! rather than to their size, and a binary body is not a thing anybody full-text searches.
//! Searching whole bodies is the upgrade path, not a regression to fix.

use std::path::{Path, PathBuf};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

/// How many refusals are kept.
///
/// Bounded because the exchange cap counts BYTES, and `size_bytes` is the whole file:
/// a browser whose telemetry hosts are out of scope writes a refusal per request, and an
/// unbounded log would push a capped project over its limit, at which point eviction
/// deletes every unpinned exchange and the project is still over. The traffic that is
/// refused is exactly the traffic nobody asked for, so it is also the traffic most likely
/// to be voluminous.
///
/// Fifty thousand rows is a few megabytes and is far more than an engagement produces.
/// The count of what was dropped is kept, so the audit answer stays true: "this is all
/// of them" and "these are the most recent of more" are different statements and the
/// file has to be able to make the second one.
pub const REFUSAL_MAX: i64 = 50_000;

/// How many refusals have been trimmed, in `setting`.
pub const REFUSALS_DROPPED: &str = "refusals_dropped";

/// Where the scope lives in `setting`.
pub const SCOPE_SETTING: &str = "scope";

pub mod blob;
pub mod schema;
pub mod sink;

pub use sink::ProjectSink;

/// Bodies at or below this stay in the row; above it they go to the blob directory.
///
/// 64 KiB because that is comfortably above an API response and comfortably below an
/// asset. A row holding a megabyte makes every listing query drag the megabyte along.
pub const INLINE_MAX: usize = 64 * 1024;

/// How much of a textual body reaches the full-text index. See the module note.
pub const FTS_BODY_MAX: usize = 32 * 1024;

#[derive(Debug)]
pub enum Error {
    Db(sqlx::Error),
    Io(std::io::Error),
    /// The file was written by a build with a newer schema. Refused rather than opened,
    /// because the alternative is a half-understood document being written back.
    NewerSchema {
        found: i64,
        supported: i64,
    },
    /// A row points at a blob the directory does not have.
    MissingBlob {
        hash: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Db(e) => write!(f, "project database: {e}"),
            Error::Io(e) => write!(f, "project directory: {e}"),
            Error::NewerSchema { found, supported } => write!(
                f,
                "this project was written by a newer version of Crossfyre (file schema {found}, \
                 this build understands {supported}). Refusing to open it, because writing to it \
                 could lose what the newer version recorded."
            ),
            Error::MissingBlob { hash } => write!(
                f,
                "a body is recorded for this exchange but blobs/{}/{} is missing from the project \
                 directory. Nothing is reported as empty: the file is gone, which is a different \
                 thing from the server having sent nothing.",
                &hash[..2.min(hash.len())],
                hash
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::Db(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// One captured exchange, as handed to the store.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Exchange {
    /// Unix milliseconds. Taken from the caller rather than the clock so a test and a
    /// replayed capture can both place an exchange in time.
    pub at_ms: i64,
    pub method: String,
    /// The full URL, values included. This store is the full-capture surface; the redacted
    /// shape is a separate thing that goes to the control plane.
    pub url: String,
    pub host: String,
    pub status: Option<i64>,
    pub duration_ms: Option<i64>,
    pub req_headers: Vec<[String; 2]>,
    pub resp_headers: Vec<[String; 2]>,
    pub req_body: Vec<u8>,
    /// As much of the response body as was kept.
    pub resp_body: Vec<u8>,
    /// The response's real length when `resp_body` is only a prefix. `None` means whole.
    pub resp_len: Option<usize>,
}

/// An exchange read back out, with its bodies wherever they were kept.
#[derive(Debug, Clone)]
pub struct Stored {
    pub id: i64,
    pub pinned: bool,
    pub exchange: Exchange,
}

/// A row as a listing shows it: no bodies, so a thousand of these cost nothing.
#[derive(Debug, Clone)]
pub struct Summary {
    pub id: i64,
    pub at_ms: i64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub status: Option<i64>,
    pub req_len: i64,
    pub resp_len: i64,
    pub pinned: bool,
}

/// What a project is allowed to grow to.
///
/// Present from the first version on purpose. Burp projects reach tens of gigabytes and
/// users are surprised every time, which is a thing to design against rather than
/// document later.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cap {
    pub max_bytes: Option<i64>,
    pub max_exchanges: Option<i64>,
}

/// What an eviction pass did, so a caller can say so rather than guessing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Evicted {
    pub exchanges: usize,
    /// Exchanges that were over the cap but pinned, so they stayed.
    pub kept_pinned: usize,
}

pub struct Project {
    pool: SqlitePool,
    root: PathBuf,
    blobs: PathBuf,
    cap: Cap,
    /// The capture session everything inserted right now belongs to, or 0 for none.
    ///
    /// Carried on the project rather than passed to `insert`, because every caller in
    /// the path would otherwise have to thread it through and the one that forgot would
    /// write an exchange belonging to no run, which is indistinguishable from an
    /// exchange written before runs existed.
    run: std::sync::atomic::AtomicI64,
}

/// Hand-written rather than derived: a pool prints as its internal state, which is noise,
/// and what a reader of a panic message wants is which project this was.
impl std::fmt::Debug for Project {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Project")
            .field("path", &self.root)
            .field("cap", &self.cap)
            .finish()
    }
}

impl Project {
    /// Open `root`, creating it and its database if absent.
    pub async fn open(root: impl AsRef<Path>, cap: Cap) -> Result<Self, Error> {
        let root = root.as_ref().to_path_buf();
        let blobs = root.join("blobs");
        tokio::fs::create_dir_all(&blobs).await?;

        let opts = SqliteConnectOptions::new()
            .filename(root.join("project.db"))
            .create_if_missing(true)
            // The proxy writes while the GUI reads. Without WAL they block each other and
            // the UI stutters on every captured request.
            .journal_mode(SqliteJournalMode::Wal)
            // WAL plus NORMAL loses at most the last commits to a power cut and never
            // corrupts the file. FULL costs an fsync per commit, which a proxy taking a
            // few hundred requests a second feels. A lost tail is survivable; a corrupt
            // project file is a lost engagement.
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            // A writer holding the file for a moment is normal here, so wait rather than
            // handing SQLITE_BUSY to the caller.
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            // One writer, several readers. SQLite serialises writes anyway, and a larger
            // pool only moves the contention.
            .max_connections(5)
            .connect_with(opts)
            .await?;

        schema::migrate(&pool).await?;
        Ok(Self {
            pool,
            root,
            blobs,
            cap,
            run: std::sync::atomic::AtomicI64::new(0),
        })
    }

    /// Open a capture session. Everything inserted afterwards belongs to it.
    ///
    /// `started_ms` comes from the caller for the same reason `Exchange::at_ms` does:
    /// the layer that knows when the capture actually began is the one that should say,
    /// and a test needs to be able to say too.
    pub async fn begin_run(&self, started_ms: i64, label: Option<&str>) -> Result<i64, Error> {
        let id: i64 =
            sqlx::query("INSERT INTO run (started_ms, label) VALUES (?1, ?2) RETURNING id")
                .bind(started_ms)
                .bind(label)
                .fetch_one(&self.pool)
                .await?
                .try_get(0)?;
        self.run.store(id, std::sync::atomic::Ordering::Relaxed);
        Ok(id)
    }

    /// Close the current session. Inserts after this belong to no run again.
    pub async fn end_run(&self, ended_ms: i64) -> Result<(), Error> {
        let id = self.run.swap(0, std::sync::atomic::Ordering::Relaxed);
        if id == 0 {
            return Ok(());
        }
        sqlx::query("UPDATE run SET ended_ms = ?1 WHERE id = ?2")
            .bind(ended_ms)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The pool, for tests that need to assert on a column this crate has no reader for
    /// yet. Not for callers: everything a front end needs has a method.
    #[doc(hidden)]
    pub fn pool_for_test(&self) -> &SqlitePool {
        &self.pool
    }

    /// The session inserts are currently attributed to, if any.
    pub fn current_run(&self) -> Option<i64> {
        match self.run.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            id => Some(id),
        }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn cap(&self) -> Cap {
        self.cap
    }

    /// Flush and close. Called so a caller can be sure the WAL has been folded back
    /// before the directory is copied or archived.
    pub async fn close(self) {
        let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await;
        self.pool.close().await;
    }

    /// Record one exchange, and return its id.
    ///
    /// The row, its blob references and its index entry go in together. A reader that saw
    /// a row whose blob was not yet referenced, or an index entry for a row that is not
    /// there, would be looking at an exchange that half exists, which is worse than one
    /// that does not exist yet.
    pub async fn insert(&self, ex: &Exchange) -> Result<i64, Error> {
        let mut tx = self.pool.begin().await?;

        let (req_inline, req_hash) = if ex.req_body.len() > INLINE_MAX {
            (
                None,
                Some(blob::put(&mut tx, &self.blobs, &ex.req_body).await?),
            )
        } else {
            (Some(ex.req_body.clone()), None)
        };
        let (resp_inline, resp_hash) = if ex.resp_body.len() > INLINE_MAX {
            (
                None,
                Some(blob::put(&mut tx, &self.blobs, &ex.resp_body).await?),
            )
        } else {
            (Some(ex.resp_body.clone()), None)
        };

        let req_headers = serde_json::to_string(&ex.req_headers).unwrap_or_else(|_| "[]".into());
        let resp_headers = serde_json::to_string(&ex.resp_headers).unwrap_or_else(|_| "[]".into());

        let id: i64 = sqlx::query(
            "INSERT INTO exchange
               (at_ms, method, url, host, status, duration_ms,
                req_headers, resp_headers, req_body, resp_body,
                req_blob, resp_blob, req_len, resp_len, run_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             RETURNING id",
        )
        .bind(ex.at_ms)
        .bind(&ex.method)
        .bind(&ex.url)
        .bind(&ex.host)
        .bind(ex.status)
        .bind(ex.duration_ms)
        .bind(&req_headers)
        .bind(&resp_headers)
        .bind(req_inline)
        .bind(resp_inline)
        .bind(&req_hash)
        .bind(&resp_hash)
        .bind(ex.req_body.len() as i64)
        .bind(ex.resp_len.unwrap_or(ex.resp_body.len()) as i64)
        .bind(self.current_run())
        .fetch_one(&mut *tx)
        .await?
        .try_get(0)?;

        let indexed_body = format!(
            "{} {}",
            searchable_text(&ex.req_body),
            searchable_text(&ex.resp_body)
        );
        sqlx::query("INSERT INTO exchange_fts (rowid, url, headers, body) VALUES (?1,?2,?3,?4)")
            .bind(id)
            .bind(&ex.url)
            .bind(format!("{req_headers} {resp_headers}"))
            .bind(indexed_body)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(id)
    }

    /// Read one exchange back, bodies and all.
    pub async fn get(&self, id: i64) -> Result<Option<Stored>, Error> {
        let Some(row) = sqlx::query(
            "SELECT id, at_ms, method, url, host, status, duration_ms, req_headers,
                    resp_headers, req_body, resp_body, req_blob, resp_blob, resp_len, pinned
             FROM exchange WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };

        let req_blob: Option<String> = row.try_get("req_blob")?;
        let resp_blob: Option<String> = row.try_get("resp_blob")?;
        let req_body = match req_blob {
            Some(h) => blob::get(&self.blobs, &h).await?,
            None => row
                .try_get::<Option<Vec<u8>>, _>("req_body")?
                .unwrap_or_default(),
        };
        let resp_body = match resp_blob {
            Some(h) => blob::get(&self.blobs, &h).await?,
            None => row
                .try_get::<Option<Vec<u8>>, _>("resp_body")?
                .unwrap_or_default(),
        };

        Ok(Some(Stored {
            id: row.try_get("id")?,
            pinned: row.try_get::<i64, _>("pinned")? != 0,
            exchange: Exchange {
                at_ms: row.try_get("at_ms")?,
                method: row.try_get("method")?,
                url: row.try_get("url")?,
                host: row.try_get("host")?,
                status: row.try_get("status")?,
                duration_ms: row.try_get("duration_ms")?,
                req_headers: headers_from(row.try_get("req_headers")?),
                resp_headers: headers_from(row.try_get("resp_headers")?),
                req_body,
                resp_body,
                // Read back, the stored `resp_len` is already the true length and the
                // body is whatever was kept. Saying `None` here would claim a prefix is
                // whole, which is the lie this field exists to stop.
                resp_len: Some(row.try_get::<i64, _>("resp_len")? as usize),
            },
        }))
    }

    /// Newest first.
    pub async fn recent(&self, limit: i64) -> Result<Vec<Summary>, Error> {
        let rows = sqlx::query(
            "SELECT id, at_ms, method, url, host, status, req_len, resp_len, pinned
             FROM exchange ORDER BY at_ms DESC, id DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(summary_from).collect()
    }

    /// Full-text search, newest first.
    ///
    /// `query` is what a person typed, not FTS5 syntax. Every whitespace-separated term
    /// has to appear. Passing the text through unchanged does not work and does not fail
    /// cleanly: FTS5 reads `WIDGET-7` as a column reference and answers
    /// `no such column: 7`, so a search box would surface a parser error for an ordinary
    /// SKU. [`fts_query`] quotes each term instead.
    pub async fn search(&self, query: &str, limit: i64) -> Result<Vec<Summary>, Error> {
        let Some(query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        self.search_fts(&query, limit).await
    }

    /// Search with an FTS5 expression, for a caller that genuinely wants the operators.
    pub async fn search_fts(&self, query: &str, limit: i64) -> Result<Vec<Summary>, Error> {
        let rows = sqlx::query(
            "SELECT e.id, e.at_ms, e.method, e.url, e.host, e.status, e.req_len, e.resp_len,
                    e.pinned
             FROM exchange_fts f JOIN exchange e ON e.id = f.rowid
             WHERE exchange_fts MATCH ?1
             ORDER BY e.at_ms DESC, e.id DESC LIMIT ?2",
        )
        .bind(query)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(summary_from).collect()
    }

    /// Pin or unpin. A pinned exchange is exempt from cap eviction.
    pub async fn set_pinned(&self, id: i64, pinned: bool) -> Result<(), Error> {
        sqlx::query("UPDATE exchange SET pinned = ?2 WHERE id = ?1")
            .bind(id)
            .bind(i64::from(pinned))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete one exchange, releasing whatever it was the last holder of.
    pub async fn delete(&self, id: i64) -> Result<bool, Error> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query("SELECT req_blob, resp_blob FROM exchange WHERE id = ?1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
        else {
            return Ok(false);
        };
        let req_blob: Option<String> = row.try_get(0)?;
        let resp_blob: Option<String> = row.try_get(1)?;

        sqlx::query("DELETE FROM exchange WHERE id = ?1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM exchange_fts WHERE rowid = ?1")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        // After the row is gone, so a failure here cannot leave a row pointing at a
        // released blob. The reverse order would.
        for h in [req_blob, resp_blob].into_iter().flatten() {
            blob::release(&mut tx, &self.blobs, &h).await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Bytes the project occupies: the database plus the blobs, counting each distinct
    /// body once because that is what the directory holds.
    pub async fn size_bytes(&self) -> Result<i64, Error> {
        let mut conn = self.pool.acquire().await?;
        let pages: i64 = sqlx::query("PRAGMA page_count")
            .fetch_one(&mut *conn)
            .await?
            .try_get(0)?;
        let page_size: i64 = sqlx::query("PRAGMA page_size")
            .fetch_one(&mut *conn)
            .await?
            .try_get(0)?;
        let blobs = blob::bytes_on_disk(&mut conn).await?;
        Ok(pages * page_size + blobs)
    }

    /// What SQLite makes of the file: `"ok"`, or the first problems it found.
    ///
    /// Worth having on the API rather than only in a test. A project that has been through
    /// a crash, a full disk or a sync client is exactly when somebody wants to ask, and
    /// the answer should not require a sqlite3 binary the operator may not have.
    pub async fn integrity_check(&self) -> Result<String, Error> {
        let rows = sqlx::query("PRAGMA integrity_check")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::new();
        for r in &rows {
            out.push(r.try_get::<String, _>(0)?);
        }
        Ok(out.join("; "))
    }

    // -----------------------------------------------------------------
    // Settings and the scope
    // -----------------------------------------------------------------

    /// One value that belongs to the project rather than to a launch.
    pub async fn setting(&self, key: &str) -> Result<Option<String>, Error> {
        let row = sqlx::query("SELECT value FROM setting WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("value")))
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        sqlx::query("INSERT INTO setting(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The scope, as the lines an operator typed.
    ///
    /// Newline-joined in one value rather than a table, which is lossless because the
    /// parser refuses any entry containing whitespace. A table would buy ordering and
    /// per-entry metadata, and neither is wanted: the list IS the thing the operator
    /// reads and edits, and it round trips exactly.
    pub async fn scope_entries(&self) -> Result<Vec<String>, Error> {
        Ok(self
            .setting(SCOPE_SETTING)
            .await?
            .map(|v| v.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default())
    }

    pub async fn set_scope_entries(&self, entries: &[String]) -> Result<(), Error> {
        self.set_setting(SCOPE_SETTING, &entries.join("\n")).await
    }

    /// A destination that was not reached, against the capture session it happened in.
    ///
    /// Durable on purpose. The guard keeps a ring for the window; this is the answer
    /// months later, from the file alone, to whether this tool ever touched something it
    /// should not have.
    pub async fn record_refusal(&self, r: &cfx_scope::Refusal) -> Result<i64, Error> {
        let res = sqlx::query(
            "INSERT INTO refusal(at_ms, run_id, host, port, point, detail) VALUES(?,?,?,?,?,?)",
        )
        .bind(r.at_ms)
        // The capture session it happened in, or none when the proxy is stopped: a
        // Repeater send is still an egress and still gets a row.
        .bind(self.current_run())
        .bind(&r.host)
        .bind(r.port as i64)
        .bind(r.point.as_str())
        .bind(r.detail.as_deref())
        .execute(&self.pool)
        .await?;

        // Trimmed on the way past rather than on a timer, so there is one place this can
        // grow and one place it is bounded.
        self.trim_refusals(REFUSAL_MAX).await?;
        Ok(res.last_insert_rowid())
    }

    /// Keep the newest `max` refusals and count what went.
    ///
    /// The oldest go, because the recent ones are what somebody is looking at when a
    /// target stops working. Takes the bound as an argument so a test can drive it at a
    /// size it can actually write: at the real bound the only thing a test measures is
    /// how long fifty thousand inserts take.
    pub async fn trim_refusals(&self, max: i64) -> Result<i64, Error> {
        let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM refusal")
            .fetch_one(&self.pool)
            .await?
            .get("n");
        if n <= max {
            return Ok(0);
        }
        let over = n - max;
        sqlx::query(
            "DELETE FROM refusal WHERE id IN (SELECT id FROM refusal ORDER BY id ASC LIMIT ?)",
        )
        .bind(over)
        .execute(&self.pool)
        .await?;
        let dropped = self.refusals_dropped().await? + over;
        self.set_setting(REFUSALS_DROPPED, &dropped.to_string())
            .await?;
        Ok(over)
    }

    /// How many refusals were trimmed away, so a report can say the log is partial.
    pub async fn refusals_dropped(&self) -> Result<i64, Error> {
        Ok(self
            .setting(REFUSALS_DROPPED)
            .await?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0))
    }

    /// Newest first, which is the order somebody reads them in.
    pub async fn refusals(&self, limit: i64) -> Result<Vec<cfx_scope::Refusal>, Error> {
        let rows = sqlx::query(
            "SELECT at_ms, host, port, point, detail FROM refusal ORDER BY id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| cfx_scope::Refusal {
                at_ms: r.get("at_ms"),
                host: r.get("host"),
                port: r.get::<i64, _>("port") as u16,
                // A row this crate wrote, so an unknown value means the file was edited
                // by something else. Named as a request rather than dropped: a refusal
                // that vanished from the audit trail is the one failure this table has.
                point: cfx_scope::Point::parse(r.get::<String, _>("point").as_str())
                    .unwrap_or(cfx_scope::Point::Request),
                detail: r.get("detail"),
            })
            .collect())
    }

    pub async fn refusal_count(&self) -> Result<i64, Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM refusal")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("n"))
    }

    pub async fn count(&self) -> Result<i64, Error> {
        Ok(sqlx::query("SELECT COUNT(*) FROM exchange")
            .fetch_one(&self.pool)
            .await?
            .try_get(0)?)
    }

    /// Bring the project back under its cap by deleting the oldest unpinned exchanges.
    ///
    /// Oldest first, and pinned never. A cap that could evict something the operator
    /// deliberately kept would make pinning worthless, so a project held over its cap
    /// entirely by pinned rows stays over it and says so through [`Evicted::kept_pinned`]
    /// rather than quietly breaking the promise.
    pub async fn enforce_cap(&self) -> Result<Evicted, Error> {
        let mut out = Evicted::default();
        if self.cap.max_bytes.is_none() && self.cap.max_exchanges.is_none() {
            return Ok(out);
        }

        loop {
            let over_count = match self.cap.max_exchanges {
                Some(max) => self.count().await? > max,
                None => false,
            };
            let over_bytes = match self.cap.max_bytes {
                Some(max) => self.size_bytes().await? > max,
                None => false,
            };
            if !over_count && !over_bytes {
                return Ok(out);
            }

            let victim: Option<i64> = sqlx::query(
                "SELECT id FROM exchange WHERE pinned = 0 ORDER BY at_ms ASC, id ASC LIMIT 1",
            )
            .fetch_optional(&self.pool)
            .await?
            .map(|r| r.try_get(0))
            .transpose()?;

            let Some(victim) = victim else {
                // Everything left is pinned. Stop rather than spin, and report it.
                out.kept_pinned = self.count().await? as usize;
                return Ok(out);
            };
            self.delete(victim).await?;
            out.exchanges += 1;
        }
    }
}

fn headers_from(json: String) -> Vec<[String; 2]> {
    serde_json::from_str(&json).unwrap_or_default()
}

fn summary_from(row: sqlx::sqlite::SqliteRow) -> Result<Summary, Error> {
    Ok(Summary {
        id: row.try_get("id")?,
        at_ms: row.try_get("at_ms")?,
        method: row.try_get("method")?,
        url: row.try_get("url")?,
        host: row.try_get("host")?,
        status: row.try_get("status")?,
        req_len: row.try_get("req_len")?,
        resp_len: row.try_get("resp_len")?,
        pinned: row.try_get::<i64, _>("pinned")? != 0,
    })
}

/// The part of a body worth putting in a text index.
///
/// Empty for anything that is not text, which is most of a real capture by volume. A NUL
/// byte is the test: it does not occur in text and it is the thing that has already broken
/// this family of code once, when captured bodies containing NULs were rejected outright
/// by the ingest layer and the Requests tab stayed empty with nothing logged.
///
/// Truncated at a character boundary, so a body cut mid-sequence does not produce a
/// replacement character where a term used to be.
pub fn searchable_text(body: &[u8]) -> String {
    if body.is_empty() || body.contains(&0) {
        return String::new();
    }
    let head = &body[..body.len().min(FTS_BODY_MAX)];
    match std::str::from_utf8(head) {
        Ok(s) => s.to_string(),
        Err(e) => String::from_utf8_lossy(&head[..e.valid_up_to()]).into_owned(),
    }
}

/// Turn what somebody typed into an FTS5 MATCH expression.
///
/// Each whitespace-separated term becomes a quoted phrase and they are ANDed, which is
/// what a search box is expected to do. Quoting is what makes punctuation safe: a bare
/// `WIDGET-7` is a column reference to FTS5, a bare `a:b` filters on a column named `a`,
/// and `"` ends a phrase, so an embedded quote is doubled the way SQL does it.
///
/// `None` when there is nothing to search for, so an empty box returns no rows rather than
/// every row or a syntax error.
pub fn fts_query(user: &str) -> Option<String> {
    let terms: Vec<String> = user
        .split_whitespace()
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect();
    if terms.is_empty() {
        return None;
    }
    Some(terms.join(" AND "))
}

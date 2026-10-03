//! The project database's shape, and the one function that brings a file up to it.
//!
//! Applied with `user_version`, not a migrations table, because a project file is a
//! document a user owns rather than a service's database: it gets copied, renamed, put on
//! a USB stick and opened by a different build. `user_version` is a single integer in the
//! file header, costs no table, and makes "which version is this file" answerable without
//! parsing anything.

use sqlx::{Row, SqlitePool};

/// Bumped whenever the statements below change. An older build opening a newer file
/// refuses rather than guessing, which is the whole reason this is checked.
pub const SCHEMA_VERSION: i64 = 1;

/// Exchanges, their out-of-line bodies, and a full-text index over the parts a human
/// searches.
///
/// `body` columns hold the bytes inline when they are small and are NULL when the body
/// went out of line, in which case `blob` carries its content hash. Keeping both shapes in
/// one row means a reader does not have to know which it is until it wants the bytes.
const DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS exchange (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        at_ms        INTEGER NOT NULL,
        method       TEXT    NOT NULL,
        url          TEXT    NOT NULL,
        host         TEXT    NOT NULL,
        status       INTEGER,
        duration_ms  INTEGER,
        req_headers  TEXT    NOT NULL DEFAULT '[]',
        resp_headers TEXT    NOT NULL DEFAULT '[]',
        req_body     BLOB,
        resp_body    BLOB,
        req_blob     TEXT,
        resp_blob    TEXT,
        req_len      INTEGER NOT NULL DEFAULT 0,
        resp_len     INTEGER NOT NULL DEFAULT 0,
        pinned       INTEGER NOT NULL DEFAULT 0
    )",
    // Newest-first listing and cap eviction both walk this.
    "CREATE INDEX IF NOT EXISTS exchange_at ON exchange(at_ms)",
    // Eviction skips pinned rows, so it wants them out of the way rather than filtered.
    "CREATE INDEX IF NOT EXISTS exchange_evictable ON exchange(pinned, at_ms)",
    "CREATE INDEX IF NOT EXISTS exchange_host ON exchange(host)",
    // Content-addressed bodies, with a reference count.
    //
    // The count is the part that is easy to get wrong. Two exchanges carrying the same
    // body share one file, so deleting one of them must not take the file with it. An
    // eviction pass that unlinked by hash alone would silently empty the other exchange,
    // and the symptom would be a response body that is there until some unrelated row
    // ages out.
    "CREATE TABLE IF NOT EXISTS blob (
        hash TEXT PRIMARY KEY,
        len  INTEGER NOT NULL,
        refs INTEGER NOT NULL
    )",
    // FTS5 over what somebody actually types into a search box.
    //
    // NOT contentless. A `content=''` table indexes without storing a copy, which is
    // tempting when the thing being indexed is response bodies, but it cannot be deleted
    // from on the SQLite versions this crate wants to support, and cap eviction has to be
    // able to delete. The copy is bounded instead: only `FTS_BODY_MAX` of a body that
    // looks like text reaches this table, so the index grows with the NUMBER of exchanges
    // rather than with their size.
    "CREATE VIRTUAL TABLE IF NOT EXISTS exchange_fts USING fts5(url, headers, body)",
];

/// Create the tables if they are absent, and refuse a file from a newer build.
pub async fn migrate(pool: &SqlitePool) -> Result<(), super::Error> {
    let found: i64 = sqlx::query("PRAGMA user_version")
        .fetch_one(pool)
        .await?
        .try_get(0)?;

    if found > SCHEMA_VERSION {
        return Err(super::Error::NewerSchema {
            found,
            supported: SCHEMA_VERSION,
        });
    }

    for stmt in DDL {
        sqlx::query(stmt).execute(pool).await?;
    }

    if found != SCHEMA_VERSION {
        // Interpolated because PRAGMA does not take a bind parameter. The value is a
        // constant in this file and never comes from a caller.
        sqlx::query(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
            .execute(pool)
            .await?;
    }
    Ok(())
}

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

/// One version's worth of change, applied as a unit.
pub struct Step {
    pub version: i64,
    pub statements: &'static [&'static str],
}

/// Every version in order. A new version appends a step; it never edits an old one,
/// because an old step is the only description of what a file in the wild already has.
///
/// Step 1 is `CREATE ... IF NOT EXISTS` because it is also the create path for a file
/// that does not exist yet. Later steps will be `ALTER TABLE` and must not be, since a
/// step that silently does nothing is the bug this runner was written to stop.
const STEPS: &[Step] = &[Step {
    version: 1,
    statements: DDL,
}];

/// Bring a file up to date, applying only the steps it has not seen.
///
/// The previous version of this ran the whole DDL array unconditionally and then stamped
/// `user_version`. Because the array is all `CREATE TABLE IF NOT EXISTS`, that worked for
/// exactly one version and no more: adding a column at version 2 would run a create that
/// no-ops against the existing table, add nothing, and then stamp the file as version 2.
/// The file would claim a shape it did not have, and every query touching the new column
/// would fail at runtime against a file that looked migrated. Nothing caught it because
/// the only test covered the refusal direction.
pub async fn migrate(pool: &SqlitePool) -> Result<(), super::Error> {
    apply(pool, STEPS).await
}

/// The version a step table ends at. Exposed so the invariant below is checkable.
pub fn target_version(steps: &[Step]) -> i64 {
    steps.last().map(|s| s.version).unwrap_or(0)
}

/// The runner, taking its steps as an argument so a test can drive a second version
/// without this crate having to have one yet.
pub async fn apply(pool: &SqlitePool, steps: &[Step]) -> Result<(), super::Error> {
    let found: i64 = sqlx::query("PRAGMA user_version")
        .fetch_one(pool)
        .await?
        .try_get(0)?;

    let target = target_version(steps);
    if found > target {
        return Err(super::Error::NewerSchema {
            found,
            supported: target,
        });
    }

    // One transaction for the whole upgrade. A file half way between two versions is a
    // file nobody can reason about, and this one is a document the user owns: there is
    // no operator to go and repair it.
    let mut tx = pool.begin().await?;
    for step in steps.iter().filter(|s| s.version > found) {
        for stmt in step.statements {
            sqlx::query(stmt).execute(&mut *tx).await?;
        }
        // Interpolated because PRAGMA does not take a bind parameter. The value comes
        // from this file's own step table and never from a caller.
        sqlx::query(&format!("PRAGMA user_version = {}", step.version))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declared_version_matches_the_steps() {
        // Adding a step and forgetting to bump the constant would mean a file is written
        // with the new shape and stamped with the old number, which is the same class of
        // lie the runner was rewritten to stop, arriving by a different door.
        assert_eq!(
            SCHEMA_VERSION,
            target_version(STEPS),
            "SCHEMA_VERSION and the last step disagree"
        );
    }

    #[test]
    fn the_steps_are_in_order_and_start_at_one() {
        let mut expected = 1;
        for step in STEPS {
            assert_eq!(step.version, expected, "steps must be consecutive from 1");
            expected += 1;
        }
    }
}

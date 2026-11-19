//! Each engine's tables, in a schema of its own in the one database, made and brought up
//! to date by numbered SQL files compiled into the engine.
//!
//! The database config.toml names has a schema per engine, named after it, and `meta`,
//! whose `migrations` table records the files each schema has had: what each said, and
//! which version of the engine applied it. The tables every engine has are made by this
//! crate's own files, the same in every schema and before the engine's.
//!
//! A file may still be rewritten, as long as nobody depends on the scans an engine
//! keeps: a schema whose files changed after they were applied is dropped and made again
//! from all of them, empty. A schema that a newer version of the engine brought up to
//! date is left as it is, and the engine is told to update.

use crate::ready::NotReady;
use sqlx::{Connection, Executor, PgConnection};

/// One engine's part of the database.
#[derive(Debug, Clone, Copy)]
pub struct Engine {
    /// The engine's name, which its schema has too.
    pub name: &'static str,
    /// The engine's version, recorded with each file it applies.
    pub version: &'static str,
    /// The engine's own SQL files, in order: the first is number 1.
    pub migrations: &'static [&'static str],
}

/// This crate's files, which make the tables every engine has.
const SHARED: &[&str] = &[include_str!("../migrations/0001_scans_logs_operations.sql")];

/// What this crate's files are recorded under, where an engine's are under its name.
const SHARED_SOURCE: &str = "shared";

/// Held while a schema is checked and brought up to date, so that engines starting at
/// once take turns, the first making `meta` and the others finding it.
const MIGRATING: i64 = 0x0063_6678_5f6d_6967;

/// The record of what every schema has had.
///
/// Its shape is frozen. Engines are installed one at a time, each with its own copy of
/// this crate, so engines built against different versions of it share this table: no
/// version may change its columns, or an engine built before the change breaks. What a
/// later version needs to record about a schema goes in a table of its own in `meta`,
/// which earlier engines do not read.
const META: &str = "CREATE SCHEMA IF NOT EXISTS meta;
CREATE TABLE IF NOT EXISTS meta.migrations (
    schema_name TEXT NOT NULL,
    source      TEXT NOT NULL,
    number      INTEGER NOT NULL,
    body        TEXT NOT NULL,
    version     TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (schema_name, source, number)
);";

/// What bringing a schema up to date did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migrated {
    /// Nothing: it had every file.
    Current,
    /// It had been made by fewer files, and got this many more.
    Applied(usize),
    /// A file it had changed afterwards, so it was dropped and made again, empty.
    Remade,
}

/// Bring `engine`'s schema up to date on `conn`, a connection to the engine's database,
/// in one transaction: all of it happens, or none of it does.
pub(crate) async fn migrate(
    conn: &mut PgConnection,
    engine: &Engine,
) -> Result<Migrated, NotReady> {
    let name = engine.name;
    let mut tx = conn.begin().await.map_err(|e| failed(name, e))?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(MIGRATING)
        .execute(&mut *tx)
        .await
        .map_err(|e| failed(name, e))?;
    tx.execute(META).await.map_err(|e| failed(name, e))?;
    let had: Vec<(String, i32, String, String)> = sqlx::query_as(
        "SELECT source, number, body, version FROM meta.migrations WHERE schema_name = $1",
    )
    .bind(name)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| failed(name, e))?;

    if had.iter().any(|(source, number, _, version)| {
        newer(version, engine.version) || file(engine, source, *number).is_none()
    }) {
        return Err(NotReady::new(
            format!("this database was upgraded by a newer {}", engine.name),
            Some("crossfyre update"),
        ));
    }
    let changed = had
        .iter()
        .any(|(source, number, body, _)| file(engine, source, *number) != Some(body.as_str()));

    let schema = format!("\"{}\"", engine.name.replace('"', "\"\""));
    if changed {
        tx.execute(format!("DROP SCHEMA IF EXISTS {schema} CASCADE").as_str())
            .await
            .map_err(|e| failed(name, e))?;
        sqlx::query("DELETE FROM meta.migrations WHERE schema_name = $1")
            .bind(engine.name)
            .execute(&mut *tx)
            .await
            .map_err(|e| failed(name, e))?;
    }
    tx.execute(
        format!("CREATE SCHEMA IF NOT EXISTS {schema}; SET LOCAL search_path TO {schema}").as_str(),
    )
    .await
    .map_err(|e| failed(name, e))?;

    let mut applied = 0;
    for (source, files) in [(SHARED_SOURCE, SHARED), (engine.name, engine.migrations)] {
        for (number, body) in (1..).zip(files.iter().copied()) {
            let had_it = !changed && had.iter().any(|(s, n, _, _)| s == source && *n == number);
            if had_it {
                continue;
            }
            tx.execute(body).await.map_err(|e| {
                NotReady::new(
                    format!("{}'s file {source} {number} failed: {e}", engine.name),
                    None,
                )
            })?;
            sqlx::query(
                "INSERT INTO meta.migrations (schema_name, source, number, body, version) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(engine.name)
            .bind(source)
            .bind(number)
            .bind(body)
            .bind(engine.version)
            .execute(&mut *tx)
            .await
            .map_err(|e| failed(name, e))?;
            applied += 1;
        }
    }
    if changed {
        // Never cleared silently: the engine's own log says so, as does its stderr.
        sqlx::query("INSERT INTO logs (level, message) VALUES ('warn', $1)")
            .bind(cleared(name))
            .execute(&mut *tx)
            .await
            .map_err(|e| failed(name, e))?;
    }
    tx.commit().await.map_err(|e| failed(name, e))?;
    Ok(match (changed, applied) {
        (true, _) => Migrated::Remade,
        (false, 0) => Migrated::Current,
        (false, n) => Migrated::Applied(n),
    })
}

/// What an engine says when it made its schema again.
pub(crate) fn cleared(engine: &str) -> String {
    format!("{engine}'s stored scans were cleared because this version keeps them differently")
}

/// The file `number` from `source` that `engine` knows, if it knows one.
fn file(engine: &Engine, source: &str, number: i32) -> Option<&'static str> {
    let files = match source {
        SHARED_SOURCE => SHARED,
        _ if source == engine.name => engine.migrations,
        _ => return None,
    };
    usize::try_from(number - 1)
        .ok()
        .and_then(|i| files.get(i).copied())
}

fn failed(engine: &str, e: sqlx::Error) -> NotReady {
    NotReady::new(
        format!("could not bring {engine}'s tables up to date: {e}"),
        None,
    )
}

/// Whether version `a` is newer than `b`, comparing their numbers in order: 0.10.0 is
/// newer than 0.9.2. A part that is not a number counts as 0.
fn newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parts(a) > parts(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_is_newer_by_its_numbers_not_its_spelling() {
        assert!(newer("0.10.0", "0.9.2"));
        assert!(newer("0.0.18", "0.0.17"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.0.17", "0.0.17"));
        assert!(!newer("0.0.9", "0.0.10"));
    }
}

//! What every engine keeps in the database, seen from outside the engines: for
//! `crossfyre db status` and `crossfyre db purge`, which need no daemon running.

use crate::ready::NotReady;
use crate::scans::{Purge, purge};
use crate::settings::Settings;
use sqlx::{Connection, PgConnection};
use std::time::Duration;

/// What one engine keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub engine: String,
    pub scans: i64,
    /// The space its tables take, indexes included.
    pub bytes: i64,
}

/// A connection to the engines' database, or None while it has not been made.
async fn connect(settings: &Settings) -> Result<Option<PgConnection>, NotReady> {
    let tried = tokio::time::timeout(
        Duration::from_secs(10),
        PgConnection::connect_with(&settings.options(&settings.db_name)),
    )
    .await
    .map_err(|_| {
        NotReady::new(
            format!("the database on {} did not answer", settings.address()),
            None,
        )
    })?;
    match tried {
        Ok(conn) => Ok(Some(conn)),
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("3D000") => Ok(None),
        Err(e) => Err(NotReady::new(
            format!(
                "could not reach the database on {}: {e}",
                settings.address()
            ),
            None,
        )),
    }
}

/// The engines that have a schema in the database, by name.
async fn engines(conn: &mut PgConnection) -> Result<Vec<String>, sqlx::Error> {
    let made: bool = sqlx::query_scalar("SELECT to_regclass('meta.migrations') IS NOT NULL")
        .fetch_one(&mut *conn)
        .await?;
    if !made {
        return Ok(Vec::new());
    }
    sqlx::query_scalar("SELECT DISTINCT schema_name FROM meta.migrations ORDER BY schema_name")
        .fetch_all(&mut *conn)
        .await
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// What each engine keeps in the database `settings` names, by engine. None of it while
/// the database has not been made.
pub async fn held(settings: &Settings) -> Result<Vec<Held>, NotReady> {
    let Some(mut conn) = connect(settings).await? else {
        return Ok(Vec::new());
    };
    let failed = |e: sqlx::Error| NotReady::new(format!("could not read the database: {e}"), None);
    let mut out = Vec::new();
    for engine in engines(&mut conn).await.map_err(failed)? {
        let scans: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {}.scans", quoted(&engine)))
                .fetch_one(&mut conn)
                .await
                .map_err(failed)?;
        let bytes: i64 = sqlx::query_scalar(
            "SELECT coalesce(sum(pg_total_relation_size(c.oid)), 0)::bigint FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = $1 AND c.relkind = 'r'",
        )
        .bind(&engine)
        .fetch_one(&mut conn)
        .await
        .map_err(failed)?;
        out.push(Held {
            engine,
            scans,
            bytes,
        });
    }
    let _ = conn.close().await;
    Ok(out)
}

/// Delete the scans `which` names in every engine's schema of the database `settings`
/// names, and say how many went from each engine. A running scan is left alone.
pub async fn purge_all(
    settings: &Settings,
    which: Purge<'_>,
) -> Result<Vec<(String, u64)>, NotReady> {
    let Some(mut conn) = connect(settings).await? else {
        return Ok(Vec::new());
    };
    let failed = |e: sqlx::Error| NotReady::new(format!("could not purge: {e}"), None);
    let mut out = Vec::new();
    for engine in engines(&mut conn).await.map_err(failed)? {
        sqlx::query(&format!("SET search_path TO {}", quoted(&engine)))
            .execute(&mut conn)
            .await
            .map_err(failed)?;
        let deleted = purge(&mut conn, which).await.map_err(failed)?;
        out.push((engine, deleted));
    }
    let _ = conn.close().await;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ready::ready_in;
    use crate::ready::tests::{free_port, local_on, toolchain_with};
    use crate::scans::{Key, Status, finish, start};
    use crate::{Engine, Stop, ThisAccount, Toolchain};

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn every_engine_is_counted_and_purged_in_its_own_schema() {
        let settings = local_on(free_port());
        let (_dir, toolchain) = toolchain_with(&settings);
        assert_eq!(
            held(&settings).await.unwrap_err().fix(),
            None,
            "not started yet"
        );
        for name in ["one", "two"] {
            let pool = ready_in(
                toolchain.clone(),
                &Engine {
                    name,
                    version: "0.0.1",
                    migrations: &[],
                },
            )
            .await
            .unwrap();
            for target in ["a", "b"] {
                let scan = start(&pool, target, Key::Settings(target), "{}", false)
                    .await
                    .unwrap();
                finish(scan, Status::Completed).await.unwrap();
            }
            pool.close().await;
        }
        let counted = held(&settings).await.unwrap();
        assert_eq!(
            counted
                .iter()
                .map(|h| (h.engine.as_str(), h.scans))
                .collect::<Vec<_>>(),
            [("one", 2), ("two", 2)]
        );
        assert!(counted.iter().all(|h| h.bytes > 0));

        assert_eq!(
            purge_all(&settings, Purge::OlderThanDays(0)).await.unwrap(),
            [("one".to_string(), 2), ("two".to_string(), 2)]
        );
        assert!(held(&settings).await.unwrap().iter().all(|h| h.scans == 0));
        let account = ThisAccount::new().unwrap();
        assert_eq!(
            Toolchain::new(toolchain, &account).stop().unwrap(),
            Stop::Stopped
        );
    }
}
